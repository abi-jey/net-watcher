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
	"gorm.io/gorm/clause"
)

const (
	batchPath     = "/api/ingest/v1/batch"
	maxEvents     = 100
	maxBatchBytes = 5 << 20
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
	for _, event := range batch.Events {
		if event.ID == 0 || event.Timestamp.IsZero() || event.EventType == "" {
			return false
		}
	}
	for _, resolution := range batch.Resolutions {
		if resolution.ID == 0 || resolution.ResponseTime.IsZero() || resolution.Name == "" || resolution.IP == "" {
			return false
		}
	}
	return true
}

func (r *Receiver) store(ctx context.Context, batch Batch) error {
	return r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		resolutionIDs := make(map[uint]uint, len(batch.Resolutions))
		for _, resolution := range batch.Resolutions {
			sourceID := resolution.ID
			var existing database.IngestedResolution
			err := tx.Where("collector_id = ? AND source_id = ?", batch.CollectorID, sourceID).First(&existing).Error
			if err == nil {
				resolutionIDs[sourceID] = existing.ResolutionID
				continue
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			resolution.ID, resolution.CollectorID = 0, batch.CollectorID
			if err := tx.Create(&resolution).Error; err != nil {
				return err
			}
			mapping := database.IngestedResolution{CollectorID: batch.CollectorID, SourceID: sourceID, ResolutionID: resolution.ID}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&mapping).Error; err != nil {
				return err
			}
			if mapping.ID == 0 {
				if err := tx.Where("collector_id = ? AND source_id = ?", batch.CollectorID, sourceID).First(&mapping).Error; err != nil {
					return err
				}
			}
			resolutionIDs[sourceID] = mapping.ResolutionID
		}
		for _, event := range batch.Events {
			sourceID := event.ID
			var existing database.IngestedEvent
			if err := tx.Where("collector_id = ? AND source_id = ?", batch.CollectorID, sourceID).First(&existing).Error; err == nil {
				continue
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
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
			if err := tx.Create(&event).Error; err != nil {
				return err
			}
			mapping := database.IngestedEvent{CollectorID: batch.CollectorID, SourceID: sourceID, EventID: event.ID}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&mapping).Error; err != nil {
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
	resolutionIDs := make(map[uint]bool)
	for _, event := range events {
		var ids []uint
		if event.DNSResolutionIDs != "" && json.Unmarshal([]byte(event.DNSResolutionIDs), &ids) != nil {
			return false, fmt.Errorf("decode local DNS evidence for event %d", event.ID)
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
		if err := f.DB.Where("id IN ?", ids).Find(&resolutions).Error; err != nil {
			return false, err
		}
	}
	body, err := json.Marshal(Batch{CollectorID: f.CollectorID, Events: events, Resolutions: resolutions})
	if err != nil {
		return false, err
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
