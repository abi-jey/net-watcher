// Package ingest forwards collector observations to and accepts observations from
// a central Net Watcher instance.
package ingest

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	batchPath     = "/api/ingest/v1/batch"
	maxEvents     = 250
	maxBatchBytes = 5 << 20
	// Keep INSERTs within SQLite's 999-bind-variable compatibility limit:
	// events have about 60 columns, resolutions 20, and ingest keys 4.
	eventInsertSize      = 15
	resolutionInsertSize = 40
	keyInsertSize        = 200
)

// Batch is an authenticated, idempotent request from one collector. A batch
// without events is a heartbeat that only carries Health.
type Batch struct {
	CollectorID string                   `json:"collectorId"`
	Events      []database.NetworkEvent  `json:"events"`
	Resolutions []database.DNSResolution `json:"resolutions"`
	Health      *Health                  `json:"health,omitempty"`
}

// Health is a collector's self-reported state, sent with every request.
type Health struct {
	Version             string    `json:"version"`
	ReportedAt          time.Time `json:"reportedAt"`
	PendingEvents       int64     `json:"pendingEvents"`
	OldestPendingAt     time.Time `json:"oldestPendingAt"`
	LastAcknowledgedAt  time.Time `json:"lastAcknowledgedAt"`
	ConsecutiveFailures int64     `json:"consecutiveFailures"`
	LastError           string    `json:"lastError"`
	StorageBytes        int64     `json:"storageBytes"`
	StorageLimitBytes   int64     `json:"storageLimitBytes"`
	DiscardedEvents     int64     `json:"discardedEvents"`
	MissingEvidence     int64     `json:"missingEvidence"`
	CaptureDrops        int64     `json:"captureDrops"`
	InventoryAgeSeconds int64     `json:"inventoryAgeSeconds"`
	PodWatch            bool      `json:"podWatch"`
}

// LocalStats supplies capture-side counters to a Forwarder's health report.
type LocalStats struct {
	DiscardedEvents     int64
	CaptureDrops        int64
	InventoryAgeSeconds int64
	PodWatch            bool
}

// rejectHeader marks a 400 response as a permanent rejection of the batch
// content, as opposed to a proxy or version mismatch that may be transient.
const rejectHeader = "X-Net-Watcher-Reject"

// Receiver accepts collector batches into a central database.
type Receiver struct {
	DB    *database.DB
	Token string
	Queue *Queue

	receivedMu sync.Mutex
	received   map[string]time.Time
}

func (r *Receiver) markReceived(collector string, at time.Time) {
	r.receivedMu.Lock()
	defer r.receivedMu.Unlock()
	if r.received == nil {
		r.received = make(map[string]time.Time)
	}
	r.received[collector] = at
}

func (r *Receiver) receivedAt(collector string) time.Time {
	r.receivedMu.Lock()
	defer r.receivedMu.Unlock()
	if at, ok := r.received[collector]; ok {
		return at
	}
	return time.Now().UTC()
}

// Handler returns the authenticated ingestion handler.
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(batchPath, r.handleBatch)
	return mux
}

// Serve runs the ingestion-only listener. Keep the map UI on a separate,
// localhost-bound listener because it does not currently provide authentication.
func (r *Receiver) Serve(ctx context.Context, address string) error {
	server := &http.Server{Addr: address, Handler: r.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (r *Receiver) handleBatch(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !validToken(request.Header.Get("Authorization"), r.Token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var batch Batch
	decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, maxBatchBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		http.Error(w, "invalid ingest batch", http.StatusBadRequest)
		return
	}
	if !validBatch(batch) {
		w.Header().Set(rejectHeader, "content")
		http.Error(w, "invalid ingest batch", http.StatusBadRequest)
		return
	}
	if batch.Health != nil {
		// Server time, so a collector with a skewed clock still looks fresh or stale correctly.
		batch.Health.ReportedAt = batch.Health.ReportedAt.UTC()
		r.markReceived(batch.CollectorID, time.Now().UTC())
	}
	if r.Queue != nil {
		if err := r.Queue.enqueue(request.Context(), batch); err != nil {
			log.Warn("Could not queue ingest batch", "collector_id", batch.CollectorID, "error", err)
			w.Header().Set("Retry-After", "2")
			http.Error(w, "ingestion queue unavailable; retry later", http.StatusServiceUnavailable)
			return
		}
	} else if err := r.store(request.Context(), batch); err != nil {
		log.Error("Could not store ingest batch", "collector_id", batch.CollectorID, "error", err)
		http.Error(w, "could not store ingest batch", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validToken(header, token string) bool {
	if token == "" || !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	provided := strings.TrimPrefix(header, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

func validBatch(batch Batch) bool {
	if len(batch.CollectorID) == 0 || len(batch.CollectorID) > 253 || len(batch.Events) > maxEvents || len(batch.Resolutions) > maxEvents*4 {
		return false
	}
	eventIDs, resolutionIDs := make(map[uint]bool), make(map[uint]bool)
	for _, event := range batch.Events {
		if event.ID == 0 || uint64(event.ID) > math.MaxInt64 || event.Timestamp.IsZero() || event.EventType == "" || eventIDs[event.ID] {
			return false
		}
		eventIDs[event.ID] = true
	}
	for _, resolution := range batch.Resolutions {
		if resolution.ID == 0 || uint64(resolution.ID) > math.MaxInt64 || resolution.ResponseTime.IsZero() || resolution.Name == "" || resolution.IP == "" || resolutionIDs[resolution.ID] {
			return false
		}
		resolutionIDs[resolution.ID] = true
	}
	// Reject permanently invalid evidence before acknowledging it into the spool.
	for _, event := range batch.Events {
		var ids []uint
		if event.DNSResolutionIDs != "" && json.Unmarshal([]byte(event.DNSResolutionIDs), &ids) != nil {
			return false
		}
		for _, id := range ids {
			if !resolutionIDs[id] {
				return false
			}
		}
	}
	return true
}

func (r *Receiver) store(ctx context.Context, batch Batch) error {
	return r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// The outer transaction already rolls back the whole batch, including
		// evidence and ingest keys; avoid per-table savepoints for GORM batches.
		tx = tx.Session(&gorm.Session{SkipDefaultTransaction: true})
		resolutionIDs := make(map[uint]uint, len(batch.Resolutions))
		for start := 0; start < len(batch.Resolutions); start += 500 {
			end := min(start+500, len(batch.Resolutions))
			ids := make([]uint, 0, end-start)
			for _, resolution := range batch.Resolutions[start:end] {
				ids = append(ids, resolution.ID)
			}
			var existing []database.IngestedResolution
			if err := tx.Where("collector_id = ? AND source_id IN ?", batch.CollectorID, ids).Find(&existing).Error; err != nil {
				return err
			}
			for _, mapping := range existing {
				resolutionIDs[mapping.SourceID] = mapping.ResolutionID
			}
		}
		newResolutions := make([]database.DNSResolution, 0, len(batch.Resolutions))
		newResolutionIDs := make([]uint, 0, len(batch.Resolutions))
		for _, resolution := range batch.Resolutions {
			if resolutionIDs[resolution.ID] != 0 {
				continue
			}
			newResolutionIDs = append(newResolutionIDs, resolution.ID)
			resolution.ID, resolution.CollectorID = 0, batch.CollectorID
			newResolutions = append(newResolutions, resolution)
		}
		if len(newResolutions) > 0 {
			if err := tx.CreateInBatches(&newResolutions, resolutionInsertSize).Error; err != nil {
				return err
			}
			mappings := make([]database.IngestedResolution, len(newResolutions))
			for index, resolution := range newResolutions {
				resolutionIDs[newResolutionIDs[index]] = resolution.ID
				mappings[index] = database.IngestedResolution{CollectorID: batch.CollectorID, SourceID: newResolutionIDs[index], ResolutionID: resolution.ID}
			}
			if err := tx.CreateInBatches(&mappings, keyInsertSize).Error; err != nil {
				return err
			}
		}
		ids := make([]uint, 0, len(batch.Events))
		for _, event := range batch.Events {
			ids = append(ids, event.ID)
		}
		existingEvents := map[uint]bool{}
		if len(ids) > 0 {
			var mappings []database.IngestedEvent
			if err := tx.Where("collector_id = ? AND source_id IN ?", batch.CollectorID, ids).Find(&mappings).Error; err != nil {
				return err
			}
			for _, mapping := range mappings {
				existingEvents[mapping.SourceID] = true
			}
		}
		newEvents := make([]database.NetworkEvent, 0, len(batch.Events))
		newEventIDs := make([]uint, 0, len(batch.Events))
		for _, event := range batch.Events {
			sourceID := event.ID
			if existingEvents[sourceID] {
				continue
			}
			var sourceEvidence []uint
			if event.DNSResolutionIDs != "" && json.Unmarshal([]byte(event.DNSResolutionIDs), &sourceEvidence) != nil {
				return fmt.Errorf("invalid DNS resolution IDs for event %d", sourceID)
			}
			mappedEvidence := make([]uint, 0, len(sourceEvidence))
			for _, id := range sourceEvidence {
				mapped, ok := resolutionIDs[id]
				if !ok {
					return fmt.Errorf("event %d references unbundled DNS evidence %d", sourceID, id)
				}
				mappedEvidence = append(mappedEvidence, mapped)
			}
			if len(sourceEvidence) > 0 {
				encoded, _ := json.Marshal(mappedEvidence)
				event.DNSResolutionIDs = string(encoded)
			}
			event.ID, event.CollectorID = 0, batch.CollectorID
			newEventIDs = append(newEventIDs, sourceID)
			newEvents = append(newEvents, event)
		}
		if len(newEvents) > 0 {
			if err := tx.CreateInBatches(&newEvents, eventInsertSize).Error; err != nil {
				return err
			}
			mappings := make([]database.IngestedEvent, len(newEvents))
			for index, event := range newEvents {
				mappings[index] = database.IngestedEvent{CollectorID: batch.CollectorID, SourceID: newEventIDs[index], EventID: event.ID}
			}
			if err := tx.CreateInBatches(&mappings, keyInsertSize).Error; err != nil {
				return err
			}
		}
		if err := database.ApplyEventSummaries(tx, newEvents, 1); err != nil {
			return err
		}
		return r.storeHealth(tx, batch)
	})
}

func (r *Receiver) storeHealth(tx *gorm.DB, batch Batch) error {
	h := batch.Health
	if h == nil {
		return nil
	}
	status := database.CollectorStatus{
		CollectorID: batch.CollectorID, Version: h.Version, ReportedAt: h.ReportedAt, ReceivedAt: r.receivedAt(batch.CollectorID),
		PendingEvents: h.PendingEvents, OldestPendingAt: h.OldestPendingAt, LastAcknowledgedAt: h.LastAcknowledgedAt,
		ConsecutiveFailures: h.ConsecutiveFailures, LastError: truncate(h.LastError, 512), StorageBytes: h.StorageBytes,
		StorageLimitBytes: h.StorageLimitBytes, DiscardedEvents: h.DiscardedEvents, MissingEvidence: h.MissingEvidence,
		CaptureDrops: h.CaptureDrops, InventoryAgeSeconds: h.InventoryAgeSeconds, PodWatch: h.PodWatch,
	}
	// Queued batches may drain out of order after a restart; never let an older
	// report overwrite a newer one.
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "collector_id"}},
		Where:     clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: "excluded.reported_at >= collector_statuses.reported_at"}}},
		UpdateAll: true,
	}).Create(&status).Error
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// Forwarder uploads locally persisted events. A cursor advances only after the
// receiver acknowledges the whole batch, so restarts and retries are safe.
//
// Delivery never blocks permanently on one event: references to DNS evidence
// that no longer exists are forwarded as missing, and an event the ingester
// explicitly rejects on its own is skipped and recorded as a GAP.
type Forwarder struct {
	DB          *database.DB
	URL         string
	Token       string
	CollectorID string
	Version     string
	// StorageLimit is reported in health; enforcement happens in maintenance.
	StorageLimit int64
	Stats        func() LocalStats
	Logger       *log.Logger
	client       *http.Client

	limit               int
	consecutiveFailures int64
	lastError           string
	lastAcknowledged    time.Time
	lastHeartbeat       time.Time
	missingEvidence     int64
}

// heartbeatInterval keeps the central view of an idle collector fresh.
const heartbeatInterval = 30 * time.Second

func (f *Forwarder) Run(ctx context.Context) {
	if f.client == nil {
		f.client = &http.Client{Timeout: 15 * time.Second}
	}
	for {
		sent, err := f.send(ctx)
		if err != nil {
			f.consecutiveFailures++
			f.lastError = err.Error()
			f.Logger.Warn("Ingest delivery failed; will retry", "error", err, "consecutive_failures", f.consecutiveFailures)
		}
		if sent && err == nil {
			// Acknowledged batches can be drained without an artificial backlog delay.
			continue
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (f *Forwarder) health() *Health {
	h := &Health{Version: f.Version, ReportedAt: time.Now().UTC(), LastAcknowledgedAt: f.lastAcknowledged,
		ConsecutiveFailures: f.consecutiveFailures, LastError: f.lastError, StorageLimitBytes: f.StorageLimit,
		MissingEvidence: f.missingEvidence, InventoryAgeSeconds: -1}
	var cursor database.IngestCursor
	_ = f.DB.Where("endpoint = ?", f.URL).First(&cursor).Error
	var next database.NetworkEvent
	if err := f.DB.Select("id, timestamp").Where("id > ?", cursor.EventID).Order("id ASC").Limit(1).Find(&next).Error; err == nil && next.ID != 0 {
		h.OldestPendingAt = next.Timestamp
		var last uint
		// IDs are allocated sequentially, so this approximates the backlog without a full count.
		_ = f.DB.Raw("SELECT COALESCE(MAX(id), 0) FROM network_events").Scan(&last).Error
		h.PendingEvents = int64(last) - int64(cursor.EventID)
	}
	h.StorageBytes, _ = f.DB.StorageBytes()
	if f.Stats != nil {
		stats := f.Stats()
		h.DiscardedEvents, h.CaptureDrops, h.InventoryAgeSeconds, h.PodWatch = stats.DiscardedEvents, stats.CaptureDrops, stats.InventoryAgeSeconds, stats.PodWatch
	}
	return h
}

func (f *Forwarder) send(ctx context.Context) (bool, error) {
	if f.URL == "" || f.Token == "" || f.CollectorID == "" {
		return false, nil
	}
	if f.client == nil {
		f.client = &http.Client{Timeout: 15 * time.Second}
	}
	if f.limit <= 0 || f.limit > maxEvents {
		f.limit = maxEvents
	}
	var cursor database.IngestCursor
	if err := f.DB.Where("endpoint = ?", f.URL).First(&cursor).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return false, err
	}
	var events []database.NetworkEvent
	if err := f.DB.Where("id > ?", cursor.EventID).Order("id ASC").Limit(f.limit).Find(&events).Error; err != nil {
		return false, err
	}
	if len(events) == 0 {
		if time.Since(f.lastHeartbeat) < heartbeatInterval {
			return false, nil
		}
		_, err := f.post(ctx, Batch{CollectorID: f.CollectorID, Events: []database.NetworkEvent{}, Resolutions: []database.DNSResolution{}, Health: f.health()})
		if err == nil {
			f.lastHeartbeat = time.Now()
			f.consecutiveFailures, f.lastError = 0, ""
		}
		return false, err
	}
	var body []byte
	var missing int64
	for {
		var resolutionCount int
		var err error
		body, resolutionCount, missing, err = f.marshalBatch(events)
		if err != nil {
			return false, err
		}
		if len(body) <= maxBatchBytes && resolutionCount <= maxEvents*4 {
			break
		}
		if len(events) == 1 {
			return f.skip(events[0], "event and its DNS evidence exceed ingestion batch limits")
		}
		events = events[:len(events)/2]
	}
	rejected, err := f.postBody(ctx, body)
	if rejected {
		// Narrow down to the offending event instead of retrying the same batch forever.
		if len(events) == 1 {
			return f.skip(events[0], err.Error())
		}
		f.limit = max(1, len(events)/2)
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if err := f.DB.RecordAcknowledgment(f.URL, events[len(events)-1].ID); err != nil {
		return false, err
	}
	f.missingEvidence += missing
	f.lastAcknowledged, f.lastHeartbeat = time.Now().UTC(), time.Now()
	f.consecutiveFailures, f.lastError = 0, ""
	f.limit = min(maxEvents, f.limit*2)
	return true, nil
}

// skip permanently passes over one event the ingester cannot accept, replacing
// it with a GAP event so the omission is itself forwarded and auditable.
func (f *Forwarder) skip(event database.NetworkEvent, reason string) (bool, error) {
	f.Logger.Error("Skipping event rejected by ingester", "event_id", event.ID, "type", event.EventType, "reason", reason)
	gap := database.NewGapEvent(database.GapRejectedByIngest, 1, event.Timestamp, event.Timestamp, event.Interface)
	if err := f.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&gap).Error; err != nil {
			return err
		}
		return (&database.DB{DB: tx}).RecordAcknowledgment(f.URL, event.ID)
	}); err != nil {
		return false, err
	}
	f.limit = maxEvents
	return true, nil
}

func (f *Forwarder) post(ctx context.Context, batch Batch) (bool, error) {
	body, err := json.Marshal(batch)
	if err != nil {
		return false, err
	}
	return f.postBody(ctx, body)
}

// postBody returns rejected=true only when the ingester explicitly marks the
// content as permanently invalid. Other failures, including a 400 from an older
// ingester or a proxy, are retried without skipping data.
func (f *Forwarder) postBody(ctx context.Context, body []byte) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(f.URL, "/")+batchPath, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+f.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(request)
	if err != nil {
		return false, err
	}
	response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return false, nil
	}
	err = fmt.Errorf("ingest endpoint returned HTTP %d", response.StatusCode)
	return response.StatusCode == http.StatusBadRequest && response.Header.Get(rejectHeader) != "", err
}

// marshalBatch bundles the DNS evidence referenced by events. References to
// evidence that no longer exists locally are removed from the forwarded event
// and counted in DNSEvidenceMissing instead of blocking delivery.
func (f *Forwarder) marshalBatch(events []database.NetworkEvent) ([]byte, int, int64, error) {
	resolutionIDs := make(map[uint]bool)
	references := make([][]uint, len(events))
	for index, event := range events {
		var ids []uint
		if event.DNSResolutionIDs != "" && json.Unmarshal([]byte(event.DNSResolutionIDs), &ids) != nil {
			// Undecodable references cannot be verified; forward the event without them.
			events[index].DNSResolutionIDs = ""
			events[index].DNSEvidenceMissing++
			continue
		}
		references[index] = ids
		for _, id := range ids {
			resolutionIDs[id] = true
		}
	}
	resolutions := make([]database.DNSResolution, 0, len(resolutionIDs))
	found := make(map[uint]bool, len(resolutionIDs))
	if len(resolutionIDs) > 0 {
		ids := make([]uint, 0, len(resolutionIDs))
		for id := range resolutionIDs {
			ids = append(ids, id)
		}
		for start := 0; start < len(ids); start += 500 {
			var rows []database.DNSResolution
			if err := f.DB.Where("id IN ?", ids[start:min(start+500, len(ids))]).Find(&rows).Error; err != nil {
				return nil, 0, 0, err
			}
			for _, row := range rows {
				found[row.ID] = true
			}
			resolutions = append(resolutions, rows...)
		}
	}
	var missing int64
	if len(found) != len(resolutionIDs) {
		for index, ids := range references {
			kept := ids[:0:0]
			for _, id := range ids {
				if found[id] {
					kept = append(kept, id)
				} else {
					events[index].DNSEvidenceMissing++
					missing++
				}
			}
			if len(kept) != len(ids) {
				encoded, _ := json.Marshal(kept)
				events[index].DNSResolutionIDs = string(encoded)
			}
		}
		f.Logger.Warn("Forwarding events with missing DNS evidence", "missing_references", missing)
	}
	body, err := json.Marshal(Batch{CollectorID: f.CollectorID, Events: events, Resolutions: resolutions, Health: f.health()})
	if err != nil {
		return nil, 0, 0, err
	}
	return body, len(resolutions), missing, nil
}
