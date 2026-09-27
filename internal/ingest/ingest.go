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
	"net/http"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
	"gorm.io/gorm"
)

const (
	batchPath     = "/api/ingest/v1/batch"
	maxEvents     = 250
	maxBatchBytes = 5 << 20
	// Keep INSERTs within SQLite's 999-bind-variable compatibility limit:
	// events have 41 columns, resolutions 20, and ingest keys 4.
	eventInsertSize      = 20
	resolutionInsertSize = 40
	keyInsertSize        = 200
)

// Batch is an authenticated, idempotent request from one collector.
type Batch struct {
	CollectorID string                   `json:"collectorId"`
	Events      []database.NetworkEvent  `json:"events"`
	Resolutions []database.DNSResolution `json:"resolutions"`
}

// Receiver accepts collector batches into a central database.
type Receiver struct {
	DB    *database.DB
	Token string
}

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
	if err := decoder.Decode(&batch); err != nil || !validBatch(batch) {
		http.Error(w, "invalid ingest batch", http.StatusBadRequest)
		return
	}
	if err := r.store(request.Context(), batch); err != nil {
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
		if event.ID == 0 || event.Timestamp.IsZero() || event.EventType == "" || eventIDs[event.ID] {
			return false
		}
		eventIDs[event.ID] = true
	}
	for _, resolution := range batch.Resolutions {
		if resolution.ID == 0 || resolution.ResponseTime.IsZero() || resolution.Name == "" || resolution.IP == "" || resolutionIDs[resolution.ID] {
			return false
		}
		resolutionIDs[resolution.ID] = true
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
		return nil
	})
}

// Forwarder uploads locally persisted events. A cursor advances only after the
// receiver acknowledges the whole batch, so restarts and retries are safe.
type Forwarder struct {
	DB          *database.DB
	URL         string
	Token       string
	CollectorID string
	Logger      *log.Logger
	client      *http.Client
}

func (f *Forwarder) Run(ctx context.Context) {
	if f.client == nil {
		f.client = &http.Client{Timeout: 15 * time.Second}
	}
	for {
		sent, err := f.send(ctx)
		if err != nil {
			f.Logger.Warn("Ingest delivery failed; will retry", "error", err)
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

func (f *Forwarder) send(ctx context.Context) (bool, error) {
	if f.URL == "" || f.Token == "" || f.CollectorID == "" {
		return false, nil
	}
	if f.client == nil {
		f.client = &http.Client{Timeout: 15 * time.Second}
	}
	var cursor database.IngestCursor
	if err := f.DB.Where("endpoint = ?", f.URL).First(&cursor).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return false, err
	}
	var events []database.NetworkEvent
	if err := f.DB.Where("id > ?", cursor.EventID).Order("id ASC").Limit(maxEvents).Find(&events).Error; err != nil || len(events) == 0 {
		return false, err
	}
	var body []byte
	for {
		var resolutionCount int
		var err error
		body, resolutionCount, err = f.marshalBatch(events)
		if err != nil {
			return false, err
		}
		if len(body) <= maxBatchBytes && resolutionCount <= maxEvents*4 {
			break
		}
		if len(events) == 1 {
			return false, fmt.Errorf("event %d and its DNS evidence exceed ingestion batch limits", events[0].ID)
		}
		events = events[:len(events)/2]
	}
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
	if response.StatusCode != http.StatusNoContent {
		return false, fmt.Errorf("ingest endpoint returned HTTP %d", response.StatusCode)
	}
	if err := f.DB.RecordAcknowledgment(f.URL, events[len(events)-1].ID); err != nil {
		return false, err
	}
	return true, nil
}

func (f *Forwarder) marshalBatch(events []database.NetworkEvent) ([]byte, int, error) {
	resolutionIDs := make(map[uint]bool)
	for _, event := range events {
		var ids []uint
		if event.DNSResolutionIDs != "" && json.Unmarshal([]byte(event.DNSResolutionIDs), &ids) != nil {
			return nil, 0, fmt.Errorf("decode local DNS evidence for event %d", event.ID)
		}
		for _, id := range ids {
			resolutionIDs[id] = true
		}
	}
	resolutions := make([]database.DNSResolution, 0, len(resolutionIDs))
	if len(resolutionIDs) > 0 {
		ids := make([]uint, 0, len(resolutionIDs))
		for id := range resolutionIDs {
			ids = append(ids, id)
		}
		for start := 0; start < len(ids); start += 500 {
			var rows []database.DNSResolution
			if err := f.DB.Where("id IN ?", ids[start:min(start+500, len(ids))]).Find(&rows).Error; err != nil {
				return nil, 0, err
			}
			resolutions = append(resolutions, rows...)
		}
		if len(resolutions) != len(resolutionIDs) {
			return nil, 0, fmt.Errorf("%d of %d referenced DNS resolutions are unavailable", len(resolutionIDs)-len(resolutions), len(resolutionIDs))
		}
	}
	body, err := json.Marshal(Batch{CollectorID: f.CollectorID, Events: events, Resolutions: resolutions})
	if err != nil {
		return nil, 0, err
	}
	return body, len(resolutions), nil
}
