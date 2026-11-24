package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func rawTime(t *testing.T, db *DB, column string, id uint) string {
	t.Helper()
	var text string
	if err := db.Raw("SELECT CAST("+column+" AS TEXT) FROM network_events WHERE id = ?", id).Scan(&text).Error; err != nil {
		t.Fatal(err)
	}
	return text
}

// A host in a local zone must store and query UTC text, or rows sort and
// match an offset away from rows written in UTC.
func TestTimesAreStoredAndQueriedInUTC(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "utc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	cet := time.FixedZone("CET", 3600)
	at := time.Date(2026, 11, 24, 2, 30, 0, 123456789, cet) // 01:30 UTC
	events := []NetworkEvent{
		{Timestamp: at, EventType: EventTCPStart, SrcIP: "10.0.0.1", DstIP: "10.0.0.2"},
		{Timestamp: time.Date(2026, 11, 24, 1, 45, 0, 0, time.UTC), EventType: EventTCPStart, SrcIP: "10.0.0.3", DstIP: "10.0.0.4"},
	}
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	if got := rawTime(t, db, "timestamp", events[0].ID); got != "2026-11-24 01:30:00.123456789+00:00" {
		t.Fatalf("stored %q", got)
	}
	// 02:40 CET is 01:40 UTC: only the first event is earlier.
	var ids []uint
	if err := db.Model(&NetworkEvent{}).Where("timestamp < ?", time.Date(2026, 11, 24, 2, 40, 0, 0, cet)).Order("timestamp").Pluck("id", &ids).Error; err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != events[0].ID {
		t.Fatalf("events before 01:40 UTC: %v", ids)
	}
	var read NetworkEvent
	if err := db.First(&read, events[0].ID).Error; err != nil || !read.Timestamp.Equal(at) {
		t.Fatalf("read back %v (%v), want %v", read.Timestamp, err, at)
	}
}

func TestNormalizeStoredTimesRewritesOffsetsOnce(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	events := []NetworkEvent{
		{Timestamp: time.Now(), EventType: EventTCPStart, SrcIP: "10.0.0.1", DstIP: "10.0.0.2"},
		{Timestamp: time.Now(), EventType: EventTCPEnd, SrcIP: "10.0.0.1", DstIP: "10.0.0.2"},
		{Timestamp: time.Now(), EventType: EventDNS, SrcIP: "10.0.0.1", DstIP: "10.0.0.53"},
	}
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	// As written by earlier versions on hosts in a local zone. Strings are
	// bound as given.
	legacy := map[uint][2]string{
		events[0].ID: {"2026-03-26 20:48:50.948046449+01:00", "2026-03-26 19:48:50.948046449+00:00"},
		events[1].ID: {"2026-07-01 00:30:00+02:00", "2026-06-30 22:30:00+00:00"},
		events[2].ID: {"2026-01-01 23:59:59.5-05:00", "2026-01-02 04:59:59.5+00:00"},
	}
	for id, times := range legacy {
		if err := db.Exec("UPDATE network_events SET timestamp = ?, end_time = ? WHERE id = ?", times[0], times[0], id).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("UPDATE network_events SET dns_query_time = '0001-01-01 00:00:00+00:00' WHERE id = ?", events[2].ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.NormalizeStoredTimes(context.Background()); err != nil {
		t.Fatal(err)
	}
	for id, times := range legacy {
		if got := rawTime(t, db, "timestamp", id); got != times[1] {
			t.Errorf("timestamp %q: got %q, want %q", times[0], got, times[1])
		}
		if got := rawTime(t, db, "end_time", id); got != times[1] {
			t.Errorf("end_time %q: got %q, want %q", times[0], got, times[1])
		}
	}
	if got := rawTime(t, db, "dns_query_time", events[2].ID); got != "0001-01-01 00:00:00+00:00" {
		t.Errorf("zero time changed: %q", got)
	}
	// Recorded as done: later offset rows (impossible with the UTC driver)
	// are left alone.
	if err := db.Exec("UPDATE network_events SET timestamp = '2026-03-26 20:00:00+01:00' WHERE id = ?", events[0].ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.NormalizeStoredTimes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := rawTime(t, db, "timestamp", events[0].ID); got != "2026-03-26 20:00:00+01:00" {
		t.Errorf("migration ran twice: %q", got)
	}
}
