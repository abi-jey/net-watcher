package ingest

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

func testDB(t *testing.T, name string) *database.DB {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func sampleBatch() Batch {
	at := time.Now().UTC().Truncate(time.Millisecond)
	return Batch{
		CollectorID: "node-a",
		Resolutions: []database.DNSResolution{{ID: 11, QueryTime: at, ResponseTime: at, ExpiresAt: at.Add(time.Minute), ClientIP: "10.0.0.2", Name: "api.test", IP: "203.0.113.10"}},
		Events:      []database.NetworkEvent{{ID: 7, Timestamp: at, EventType: database.EventTCPStart, SrcIP: "10.0.0.2", DstIP: "203.0.113.10", DstPort: 443, DNSResolutionIDs: "[11]"}},
	}
}

func TestReceiverStoresIdempotentBatchAndRemapsEvidence(t *testing.T) {
	db := testDB(t, "central.db")
	receiver := Receiver{DB: db, Token: "token"}
	batch := sampleBatch()
	if err := receiver.store(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if err := receiver.store(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	var events []database.NetworkEvent
	if err := db.Find(&events).Error; err != nil || len(events) != 1 {
		t.Fatalf("events: %d, %v", len(events), err)
	}
	if events[0].CollectorID != "node-a" || events[0].DNSResolutionIDs != "[1]" {
		t.Fatalf("unexpected central event: %#v", events[0])
	}
	var resolutions []database.DNSResolution
	if err := db.Find(&resolutions).Error; err != nil || len(resolutions) != 1 || resolutions[0].CollectorID != "node-a" {
		t.Fatalf("resolutions: %#v, %v", resolutions, err)
	}
}

func TestReceiverRequiresBearerToken(t *testing.T) {
	receiver := Receiver{DB: testDB(t, "central.db"), Token: "token"}
	server := httptest.NewServer(receiver.Handler())
	defer server.Close()
	response, err := http.Post(server.URL+batchPath, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestForwarderAdvancesOnlyAfterAcknowledgedBatch(t *testing.T) {
	central := testDB(t, "central.db")
	server := httptest.NewServer((&Receiver{DB: central, Token: "token"}).Handler())
	defer server.Close()
	local := testDB(t, "local.db")
	at := time.Now().UTC().Truncate(time.Millisecond)
	resolution := database.DNSResolution{QueryTime: at, ResponseTime: at, ExpiresAt: at.Add(time.Minute), ClientIP: "10.0.0.2", Name: "api.test", IP: "203.0.113.10"}
	if err := local.Create(&resolution).Error; err != nil {
		t.Fatal(err)
	}
	event := database.NetworkEvent{Timestamp: at, EventType: database.EventTCPStart, SrcIP: "10.0.0.2", DstIP: "203.0.113.10", DstPort: 443, DNSResolutionIDs: "[1]"}
	if err := local.Create(&event).Error; err != nil {
		t.Fatal(err)
	}
	forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "node-a", Logger: log.Default()}
	if err := forwarder.send(t.Context()); err != nil {
		t.Fatal(err)
	}
	var cursor database.IngestCursor
	if err := local.Where("endpoint = ?", server.URL).First(&cursor).Error; err != nil || cursor.EventID != event.ID {
		t.Fatalf("cursor = %#v, err = %v", cursor, err)
	}
	var received int64
	central.Model(&database.NetworkEvent{}).Count(&received)
	if received != 1 {
		t.Fatalf("received = %d", received)
	}
	var localCount int64
	if err := local.Model(&database.NetworkEvent{}).Count(&localCount).Error; err != nil || localCount != 1 {
		t.Fatalf("collector must retain event until scheduled cleanup: %d, %v", localCount, err)
	}
	removed, err := local.ReclaimCollectorSpace(server.URL)
	if err != nil || removed != 1 {
		t.Fatalf("reclaimed = %d, error = %v", removed, err)
	}
	newEvent := database.NetworkEvent{Timestamp: at.Add(time.Second), EventType: database.EventTCPStart, SrcIP: "10.0.0.2", DstIP: "203.0.113.20", DstPort: 443}
	if err := local.Create(&newEvent).Error; err != nil || newEvent.ID <= event.ID {
		t.Fatalf("collector reused an acknowledged source ID: %d <= %d, %v", newEvent.ID, event.ID, err)
	}
	if err := forwarder.send(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := central.Model(&database.NetworkEvent{}).Count(&received).Error; err != nil || received != 2 {
		t.Fatalf("received after cleanup = %d, %v", received, err)
	}
}

func TestForwarderRetainsEventsWhenIngestionFails(t *testing.T) {
	local := testDB(t, "pending.db")
	event := database.NetworkEvent{Timestamp: time.Now().UTC(), EventType: database.EventTCPStart}
	if err := local.Create(&event).Error; err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "node-a", Logger: log.Default()}
	if err := forwarder.send(t.Context()); err == nil {
		t.Fatal("expected failed batch")
	}
	removed, err := local.ReclaimCollectorSpace(server.URL)
	if err != nil || removed != 0 {
		t.Fatalf("reclaimed = %d, error = %v", removed, err)
	}
	var count int64
	if err := local.Model(&database.NetworkEvent{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("unacknowledged event count = %d, error = %v", count, err)
	}
}
