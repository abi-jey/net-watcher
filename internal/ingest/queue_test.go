package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
)

func postBatch(t *testing.T, handler http.Handler, batch Batch) int {
	t.Helper()
	payload, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, batchPath, bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func TestQueueAcceptsDuringMaintenanceAndSurvivesRestart(t *testing.T) {
	db := testDB(t, "central.db")
	path := filepath.Join(t.TempDir(), "queue.db")
	queue, err := OpenQueue(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = queue.Close() }()
	receiver := &Receiver{DB: db, Token: "token", Queue: queue}
	// Occupy the only central connection as maintenance does, without preventing
	// the HTTP path from durably acknowledging more than one collector batch.
	sqlDB, err := db.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := sqlDB.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		queue.Run(ctx, receiver)
	}()
	defer func() { cancel(); <-done }()
	batch := sampleBatch()
	for range 2 {
		if code := postBatch(t, receiver.Handler(), batch); code != http.StatusNoContent {
			t.Fatalf("acknowledgment during maintenance: %d", code)
		}
	}
	batch.CollectorID = "node-b"
	if code := postBatch(t, receiver.Handler(), batch); code != http.StatusNoContent {
		t.Fatalf("second collector acknowledgment during maintenance: %d", code)
	}
	var count int
	if err := queue.db.QueryRow("SELECT COUNT(*) FROM pending_batches").Scan(&count); err != nil || count != 2 {
		t.Fatalf("pending batches = %d, error = %v", count, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop while maintenance held the writer")
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	queue, err = OpenQueue(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	receiver.Queue = queue
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after a central commit but before deleting its queue row.
	if err := receiver.store(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if sent, err := queue.drainOne(t.Context(), receiver); err != nil || !sent {
			t.Fatalf("recovered batch: sent=%v, error=%v", sent, err)
		}
	}
	if sent, err := queue.drainOne(t.Context(), receiver); err != nil || sent {
		t.Fatalf("queue not empty: sent=%v, error=%v", sent, err)
	}
	for _, model := range []interface{}{&database.NetworkEvent{}, &database.DNSResolution{}} {
		var stored int64
		if err := db.Model(model).Count(&stored).Error; err != nil || stored != 2 {
			t.Fatalf("%T: recovered %d rows, error=%v", model, stored, err)
		}
	}
}

func TestQueueBoundsConcurrentAdmissionAndReusesCapacity(t *testing.T) {
	batch := sampleBatch()
	payload, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "queue.db"), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidate := batch
			candidate.CollectorID = string(rune('a'+i)) + "ode-a"
			if err := queue.enqueue(t.Context(), candidate); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, errQueueFull) {
				t.Errorf("unexpected enqueue error: %v", err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d batches into one-batch capacity", accepted.Load())
	}
	receiver := &Receiver{DB: testDB(t, "central.db"), Token: "token", Queue: queue}
	if code := postBatch(t, receiver.Handler(), batch); code != http.StatusServiceUnavailable {
		t.Fatalf("full queue status = %d", code)
	}
	if sent, err := queue.drainOne(t.Context(), receiver); err != nil || !sent {
		t.Fatalf("drain: sent=%v, error=%v", sent, err)
	}
	for range 2 {
		if code := postBatch(t, receiver.Handler(), batch); code != http.StatusNoContent {
			t.Fatalf("retry/reused capacity status = %d", code)
		}
	}
}

func TestQueueRejectsInvalidEvidenceBeforeAcknowledgment(t *testing.T) {
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "queue.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	receiver := &Receiver{Token: "token", Queue: queue}
	for _, ids := range []string{"[99]", "invalid", "[-1]"} {
		batch := sampleBatch()
		batch.Events[0].DNSResolutionIDs = ids
		if code := postBatch(t, receiver.Handler(), batch); code != http.StatusBadRequest {
			t.Fatalf("invalid evidence %q status = %d", ids, code)
		}
	}
	var count int
	if err := queue.db.QueryRow("SELECT COUNT(*) FROM pending_batches").Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid batches queued: %d, error=%v", count, err)
	}
}
