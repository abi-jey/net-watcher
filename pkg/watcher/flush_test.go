package watcher

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

// A failed write must not lose events; once writes recover everything is stored.
// Beyond the retention bound, discarded events are summarised as one GAP.
func TestFlushRetainsEventsOnWriteFailureAndRecordsOverflowGap(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sm := NewSessionManager(log.Default(), db, "", "", "")
	defer sm.Stop()
	sm.maxRetained = 5
	at := time.Now().UTC().Truncate(time.Second)
	if err := db.Exec("ALTER TABLE network_events RENAME TO network_events_hidden").Error; err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		sm.eventBufferMux.Lock()
		sm.eventBuffer = append(sm.eventBuffer, database.NetworkEvent{Timestamp: at.Add(time.Duration(i) * time.Second), EventType: database.EventTCPStart})
		sm.eventBufferMux.Unlock()
		sm.flushEvents()
	}
	if stats := sm.Stats(); stats.DiscardedEvents != 3 || stats.BufferedEvents != 5 {
		t.Fatalf("stats = %+v", stats)
	}
	if err := db.Exec("ALTER TABLE network_events_hidden RENAME TO network_events").Error; err != nil {
		t.Fatal(err)
	}
	sm.flushEvents()
	var stored []database.NetworkEvent
	if err := db.Order("id").Find(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if len(stored) != 6 {
		t.Fatalf("stored %d events, want 5 retained + 1 gap", len(stored))
	}
	gap := stored[len(stored)-1]
	if gap.EventType != database.EventGap || gap.Reason != database.GapWriteFailure || gap.EventCount != 3 ||
		!gap.Timestamp.Equal(at) || !gap.EndTime.Equal(at.Add(2*time.Second)) {
		t.Fatalf("gap = %+v", gap)
	}
	if !stored[0].Timestamp.Equal(at.Add(3 * time.Second)) {
		t.Fatalf("oldest retained %v; newest events must be kept", stored[0].Timestamp)
	}
	sm.flushEvents()
	var count int64
	db.Model(&database.NetworkEvent{}).Where("event_type = ?", database.EventGap).Count(&count)
	if count != 1 {
		t.Fatalf("gap recorded %d times", count)
	}
}

func TestCaptureDropsBecomeGapEvents(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sm := NewSessionManager(log.Default(), db, "", "", "")
	defer sm.Stop()
	from := time.Now().UTC().Add(-30 * time.Second)
	sm.RecordCaptureDrops("eth0", 42, from, from.Add(30*time.Second))
	sm.flushEvents()
	var gap database.NetworkEvent
	if err := db.Where("event_type = ?", database.EventGap).First(&gap).Error; err != nil {
		t.Fatal(err)
	}
	if gap.Reason != database.GapCaptureDrops || gap.EventCount != 42 || gap.Interface != "eth0" || sm.Stats().CaptureDrops != 42 {
		t.Fatalf("gap = %+v", gap)
	}
}
