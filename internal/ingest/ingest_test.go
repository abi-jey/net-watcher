package ingest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func TestReceiverBatchesAndDeduplicatesManyEventsAndResolutions(t *testing.T) {
	db := testDB(t, "large-central.db")
	batch := Batch{CollectorID: "node-a"}
	at := time.Now().UTC()
	for i := range maxEvents {
		id := uint(i + 1)
		batch.Resolutions = append(batch.Resolutions, database.DNSResolution{ID: id, ResponseTime: at, ExpiresAt: at.Add(time.Minute), Name: "api.test", IP: "203.0.113.10"})
		batch.Events = append(batch.Events, database.NetworkEvent{ID: id, Timestamp: at, EventType: database.EventTCPStart, DstPort: uint16(i + 1), DNSResolutionIDs: fmt.Sprintf("[%d]", id)})
	}
	// Also exercise the chunked lookup for more than 500 referenced resolutions.
	for i := maxEvents; i < maxEvents*3; i++ {
		batch.Resolutions = append(batch.Resolutions, database.DNSResolution{ID: uint(i + 1), ResponseTime: at, ExpiresAt: at.Add(time.Minute), Name: "extra.test", IP: "203.0.113.11"})
	}
	receiver := Receiver{DB: db, Token: "token"}
	for range 2 {
		if err := receiver.store(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	for _, check := range []struct {
		model interface{}
		want  int64
	}{{&database.NetworkEvent{}, int64(maxEvents)}, {&database.IngestedEvent{}, int64(maxEvents)}, {&database.DNSResolution{}, int64(maxEvents * 3)}, {&database.IngestedResolution{}, int64(maxEvents * 3)}} {
		var count int64
		if err := db.Model(check.model).Count(&count).Error; err != nil || count != check.want {
			t.Fatalf("%T count = %d, want %d, error = %v", check.model, count, check.want, err)
		}
	}
	var first database.NetworkEvent
	if err := db.Where("dst_port = ?", 1).First(&first).Error; err != nil || first.DNSResolutionIDs != "[1]" {
		t.Fatalf("first event evidence mapping = %q, error = %v", first.DNSResolutionIDs, err)
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
	if sent, err := forwarder.send(t.Context()); err != nil || !sent {
		t.Fatalf("sent = %t, error = %v", sent, err)
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
	if sent, err := forwarder.send(t.Context()); err != nil || !sent {
		t.Fatalf("sent = %t, error = %v", sent, err)
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
	if sent, err := forwarder.send(t.Context()); err == nil || sent {
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

func TestForwarderDrainsBacklogWithoutWaitingBetweenBatches(t *testing.T) {
	central := testDB(t, "central.db")
	server := httptest.NewServer((&Receiver{DB: central, Token: "token"}).Handler())
	defer server.Close()
	local := testDB(t, "local.db")
	events := make([]database.NetworkEvent, maxEvents*2+5)
	for i := range events {
		events[i] = database.NetworkEvent{Timestamp: time.Now().UTC(), EventType: database.EventDNS}
	}
	if err := local.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "node-a", Logger: log.Default()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		forwarder.Run(ctx)
	}()
	defer func() { cancel(); <-done }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var received int64
		if err := central.Model(&database.NetworkEvent{}).Count(&received).Error; err != nil {
			t.Fatal(err)
		}
		if received == int64(len(events)) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("only %d of %d events arrived before the next 2s polling cycle", received, len(events))
		case <-ticker.C:
		}
	}
}

func TestForwarderSplitsOversizedBatchWithoutSkippingEvents(t *testing.T) {
	central := testDB(t, "central.db")
	server := httptest.NewServer((&Receiver{DB: central, Token: "token"}).Handler())
	defer server.Close()
	local := testDB(t, "local.db")
	for range 2 {
		if err := local.InsertEvent(&database.NetworkEvent{Timestamp: time.Now().UTC(), EventType: database.EventTCPStart, SourceContext: strings.Repeat("x", 3<<20)}); err != nil {
			t.Fatal(err)
		}
	}
	forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "node-a", Logger: log.Default()}
	for n := int64(1); n <= 2; n++ {
		if sent, err := forwarder.send(t.Context()); err != nil || !sent {
			t.Fatalf("batch %d: sent = %t, error = %v", n, sent, err)
		}
		var count int64
		if err := central.Model(&database.NetworkEvent{}).Count(&count).Error; err != nil || count != n {
			t.Fatalf("after batch %d, stored %d events: %v", n, count, err)
		}
	}
}
