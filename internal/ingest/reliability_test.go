package ingest

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

// Reproduces the 2026-11-22 stall: an event references DNS evidence that the
// collector already deleted. Delivery must continue and record the omission.
func TestForwarderDeliversEventsWhoseDNSEvidenceIsMissing(t *testing.T) {
	central := testDB(t, "central.db")
	server := httptest.NewServer((&Receiver{DB: central, Token: "token"}).Handler())
	defer server.Close()
	local := testDB(t, "local.db")
	at := time.Now().UTC().Truncate(time.Millisecond)
	kept := database.DNSResolution{QueryTime: at, ResponseTime: at, ExpiresAt: at.Add(time.Minute), ClientIP: "10.0.0.2", Name: "kept.test", IP: "203.0.113.10"}
	if err := local.Create(&kept).Error; err != nil {
		t.Fatal(err)
	}
	broken := database.NetworkEvent{Timestamp: at, EventType: database.EventTCPStart, SrcIP: "10.0.0.2", DstIP: "203.0.113.10", DNSResolutionIDs: "[654798, 1]"}
	healthy := database.NetworkEvent{Timestamp: at.Add(time.Second), EventType: database.EventTCPStart, SrcIP: "10.0.0.3", DstIP: "203.0.113.11"}
	for _, event := range []*database.NetworkEvent{&broken, &healthy} {
		if err := local.Create(event).Error; err != nil {
			t.Fatal(err)
		}
	}
	forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "node-a", Logger: log.Default()}
	if sent, err := forwarder.send(t.Context()); err != nil || !sent {
		t.Fatalf("sent = %t, error = %v", sent, err)
	}
	var events []database.NetworkEvent
	if err := central.Order("id").Find(&events).Error; err != nil || len(events) != 2 {
		t.Fatalf("central events = %d, %v", len(events), err)
	}
	if events[0].DNSEvidenceMissing != 1 || events[0].DNSResolutionIDs != "[1]" {
		t.Fatalf("missing evidence not recorded: %#v", events[0])
	}
	if forwarder.missingEvidence != 1 {
		t.Fatalf("missing evidence counter = %d", forwarder.missingEvidence)
	}
}

// One event the ingester permanently rejects is isolated and replaced by a GAP;
// the events around it are still delivered.
func TestForwarderIsolatesAndSkipsRejectedEvent(t *testing.T) {
	central := testDB(t, "central.db")
	server := httptest.NewServer((&Receiver{DB: central, Token: "token"}).Handler())
	defer server.Close()
	local := testDB(t, "local.db")
	at := time.Now().UTC()
	for i := 0; i < 9; i++ {
		event := database.NetworkEvent{Timestamp: at.Add(time.Duration(i) * time.Second), EventType: database.EventTCPStart}
		if i == 4 {
			event.EventType = "" // Rejected by validBatch.
		}
		if err := local.Create(&event).Error; err != nil {
			t.Fatal(err)
		}
	}
	forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "node-a", Logger: log.Default()}
	for range 40 {
		if _, err := forwarder.send(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var stored []database.NetworkEvent
	if err := central.Order("timestamp, id").Find(&stored).Error; err != nil {
		t.Fatal(err)
	}
	var tcp, gaps int
	for _, event := range stored {
		switch event.EventType {
		case database.EventTCPStart:
			tcp++
		case database.EventGap:
			gaps++
			if event.Reason != database.GapRejectedByIngest || event.EventCount != 1 {
				t.Fatalf("unexpected gap %#v", event)
			}
		}
	}
	if tcp != 8 || gaps != 1 {
		t.Fatalf("tcp = %d, gaps = %d", tcp, gaps)
	}
}

// A 400 without the rejection marker (an older ingester, a proxy) must never
// cause data to be skipped.
func TestForwarderDoesNotSkipOnUnmarkedBadRequest(t *testing.T) {
	local := testDB(t, "local.db")
	event := database.NetworkEvent{Timestamp: time.Now().UTC(), EventType: database.EventTCPStart}
	if err := local.Create(&event).Error; err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unknown field", http.StatusBadRequest)
	}))
	defer server.Close()
	forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "node-a", Logger: log.Default()}
	for range 5 {
		if _, err := forwarder.send(t.Context()); err == nil {
			t.Fatal("expected delivery failure")
		}
	}
	var cursor database.IngestCursor
	if err := local.Where("endpoint = ?", server.URL).First(&cursor).Error; err == nil && cursor.EventID != 0 {
		t.Fatalf("cursor advanced to %d", cursor.EventID)
	}
	var gaps int64
	local.Model(&database.NetworkEvent{}).Where("event_type = ?", database.EventGap).Count(&gaps)
	if gaps != 0 {
		t.Fatal("event skipped on unmarked 400")
	}
}

// An idle collector still reports health so a stalled one is distinguishable.
func TestHeartbeatStoresCollectorHealthAndIgnoresOlderReports(t *testing.T) {
	central := testDB(t, "central.db")
	receiver := &Receiver{DB: central, Token: "token"}
	server := httptest.NewServer(receiver.Handler())
	defer server.Close()
	local := testDB(t, "local.db")
	forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "node-a", Version: "test", StorageLimit: 1 << 30, Logger: log.Default(),
		Stats: func() LocalStats { return LocalStats{DiscardedEvents: 3, CaptureDrops: 7, InventoryAgeSeconds: 12} }}
	if _, err := forwarder.send(t.Context()); err != nil {
		t.Fatal(err)
	}
	var status database.CollectorStatus
	if err := central.First(&status, "collector_id = ?", "node-a").Error; err != nil {
		t.Fatal(err)
	}
	if status.Version != "test" || status.DiscardedEvents != 3 || status.CaptureDrops != 7 || status.InventoryAgeSeconds != 12 || status.StorageLimitBytes != 1<<30 {
		t.Fatalf("unexpected status %#v", status)
	}
	older := Batch{CollectorID: "node-a", Events: []database.NetworkEvent{}, Resolutions: []database.DNSResolution{},
		Health: &Health{Version: "old", ReportedAt: status.ReportedAt.Add(-time.Hour)}}
	if code := postBatch(t, receiver.Handler(), older); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	if err := central.First(&status, "collector_id = ?", "node-a").Error; err != nil || status.Version != "test" {
		t.Fatalf("older report overwrote newer: %#v, %v", status, err)
	}
}


// A batch that keeps failing is set aside after the attempt and time budget;
// the next batch drains, and the set-aside batch is recovered later.
func TestQueueDeadLettersPoisonBatchAndRecoversIt(t *testing.T) {
	db := testDB(t, "central.db")
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "queue.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = queue.Close() }()
	clock := time.Now()
	queue.now = func() time.Time { return clock }
	receiver := &Receiver{DB: db, Token: "token", Queue: queue}
	poison := sampleBatch()
	poison.CollectorID = "poison"
	good := sampleBatch()
	good.CollectorID = "good"
	for _, batch := range []Batch{poison, good} {
		if err := queue.enqueue(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	// Make storing fail by removing a table, as a schema or disk problem would.
	if err := db.Exec("ALTER TABLE ingested_events RENAME TO ingested_events_hidden").Error; err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < deadLetterAttempts; attempt++ {
		if _, err := queue.drainOne(t.Context(), receiver); err == nil {
			t.Fatal("expected store failure")
		}
		clock = clock.Add(deadLetterAfter / deadLetterAttempts)
	}
	clock = clock.Add(time.Second)
	if sent, err := queue.drainOne(t.Context(), receiver); err != nil || !sent {
		t.Fatalf("poison batch not set aside: sent=%t err=%v", sent, err)
	}
	if count, _ := queue.DeadLetters(t.Context()); count != 1 {
		t.Fatalf("dead letters = %d", count)
	}
	if err := db.Exec("ALTER TABLE ingested_events_hidden RENAME TO ingested_events").Error; err != nil {
		t.Fatal(err)
	}
	if sent, err := queue.drainOne(t.Context(), receiver); err != nil || !sent {
		t.Fatalf("following batch blocked: sent=%t err=%v", sent, err)
	}
	queue.retryDeadLetters(t.Context(), receiver)
	if count, _ := queue.DeadLetters(t.Context()); count != 0 {
		t.Fatalf("dead letters after recovery = %d", count)
	}
	var collectors []string
	db.Model(&database.NetworkEvent{}).Distinct().Order("collector_id").Pluck("collector_id", &collectors)
	if len(collectors) != 2 {
		t.Fatalf("collectors stored = %v", collectors)
	}
}

func TestQueueDeadLettersUndecodablePayloadImmediately(t *testing.T) {
	db := testDB(t, "central.db")
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "queue.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = queue.Close() }()
	if _, err := queue.db.Exec("INSERT INTO pending_batches(digest, payload, created_at) VALUES (x'00', 'not json', 0)"); err != nil {
		t.Fatal(err)
	}
	if sent, err := queue.drainOne(t.Context(), &Receiver{DB: db}); err != nil || !sent {
		t.Fatalf("sent=%t err=%v", sent, err)
	}
	if count, _ := queue.DeadLetters(t.Context()); count != 1 {
		t.Fatalf("dead letters = %d", count)
	}
	var decoded Batch
	if json.Unmarshal([]byte("not json"), &decoded) == nil {
		t.Fatal(errors.New("fixture unexpectedly decodes"))
	}
}
