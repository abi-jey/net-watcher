package web

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

func TestAssessCollectorStates(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name   string
		status database.CollectorStatus
		want   string
	}{
		{"ok", database.CollectorStatus{ReceivedAt: now, ReportedAt: now, InventoryAgeSeconds: 5, PodWatch: true}, "ok"},
		{"no watch", database.CollectorStatus{ReceivedAt: now, ReportedAt: now, InventoryAgeSeconds: 5}, "degraded"},
		{"no kubernetes", database.CollectorStatus{ReceivedAt: now, ReportedAt: now, InventoryAgeSeconds: -1}, "ok"},
		{"stale", database.CollectorStatus{ReceivedAt: now.Add(-10 * time.Minute), ConsecutiveFailures: 3}, "stale"},
		{"failing", database.CollectorStatus{ReceivedAt: now, ReportedAt: now, ConsecutiveFailures: 2, LastError: "HTTP 503"}, "failing"},
		{"backlog", database.CollectorStatus{ReceivedAt: now, ReportedAt: now, OldestPendingAt: now.Add(-time.Hour)}, "backlog"},
		{"degraded", database.CollectorStatus{ReceivedAt: now, ReportedAt: now, CaptureDrops: 10}, "degraded"},
		{"inventory", database.CollectorStatus{ReceivedAt: now, ReportedAt: now, InventoryAgeSeconds: 600}, "degraded"},
	}
	for _, c := range cases {
		if got := assessCollector(c.status, now); got.State != c.want {
			t.Errorf("%s: state %q, want %q (%v)", c.name, got.State, c.want, got.Problems)
		}
	}
}

func TestCollectorsEndpointReportsStatusAndGaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "central.db")
	writer, err := database.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	now := time.Now().UTC().Truncate(time.Second)
	if err := writer.Create(&database.CollectorStatus{CollectorID: "node-a", ReceivedAt: now, ReportedAt: now, InventoryAgeSeconds: -1}).Error; err != nil {
		t.Fatal(err)
	}
	gaps := []database.NetworkEvent{
		database.NewGapEvent(database.GapCaptureDrops, 10, now.Add(-time.Hour), now.Add(-59*time.Minute), "eth0"),
		database.NewGapEvent(database.GapCaptureDrops, 5, now.Add(-10*time.Minute), now.Add(-9*time.Minute), "eth0"),
	}
	for i := range gaps {
		gaps[i].CollectorID = "node-a"
	}
	if err := writer.InsertBatch(gaps); err != nil {
		t.Fatal(err)
	}
	reader, err := database.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	server := &Server{db: reader, logger: log.Default()}
	recorder := httptest.NewRecorder()
	server.handleCollectors(recorder, httptest.NewRequest("GET", "/api/collectors", nil))
	if recorder.Code != 200 {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response HealthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Collectors) != 1 || response.Collectors[0].State != "ok" {
		t.Fatalf("collectors = %+v", response.Collectors)
	}
	if len(response.Gaps) != 1 {
		t.Fatalf("gaps = %+v", response.Gaps)
	}
	g := response.Gaps[0]
	if g.Events != 2 || g.Lost != 15 || !g.First.Equal(now.Add(-time.Hour)) || !g.Last.Equal(now.Add(-9*time.Minute)) {
		t.Fatalf("gap summary = %+v", g)
	}
}
