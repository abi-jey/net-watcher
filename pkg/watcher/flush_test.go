package watcher

import (
	"context"
	"fmt"
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
	defer func() { _ = db.Close() }()
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
	defer func() { _ = db.Close() }()
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

// Packet handlers must never wait for the database: a write under the
// session mutex stalls every capture goroutine and the kernel drops packets.
func TestPacketTrackingDoesNotWaitForDatabaseWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.db")
	db, err := database.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sm := NewSessionManager(log.Default(), db, "", "", "")

	// Hold the database write lock from another connection, as a slow
	// checkpoint or the forwarder's delete would.
	other, err := database.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	sqlDB, err := other.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}

	const connections = 350 // Several batches of 100.
	started := time.Now()
	for i := range connections {
		src := fmt.Sprintf("[10.0.%d.%d]:40000", i/250, i%250+1)
		sm.TrackTCP("eth0", src, "[192.0.2.1]:443", true, false, false, 60, false)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("tracking %d SYNs took %v while the database was locked", connections, elapsed)
	}

	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	sm.Stop()
	var stored int64
	if err := db.Model(&database.NetworkEvent{}).Where("event_type = ?", database.EventTCPStart).Count(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored != connections {
		t.Fatalf("stored %d TCP_START events, want %d", stored, connections)
	}
}

func TestRingSizeByInterfaceRole(t *testing.T) {
	for name, blocks := range map[string]int{"lxc1234abcd": 8, "veth0": 8, "lxc_health": 64, "enp0s25": 64, "tailscale0": 64, "cilium_vxlan": 64} {
		if got := ringBlocks(name); got != blocks {
			t.Errorf("%s: %d blocks, want %d", name, got, blocks)
		}
	}
}
