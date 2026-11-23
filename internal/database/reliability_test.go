package database

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Evidence that just expired may still be referenced by an event waiting in
// the capture buffer; it must survive maintenance for EvidenceGrace.
func TestRecentlyExpiredEvidenceSurvivesMaintenance(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "collector.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	now := time.Now().UTC()
	recent := DNSResolution{ResponseTime: now.Add(-3 * time.Minute), ExpiresAt: now.Add(-2 * time.Minute), Name: "recent.test", IP: "203.0.113.1"}
	old := DNSResolution{ResponseTime: now.Add(-time.Hour), ExpiresAt: now.Add(-EvidenceGrace - time.Minute), Name: "old.test", IP: "203.0.113.2"}
	live := DNSResolution{ResponseTime: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Name: "live.test", IP: "203.0.113.3"}
	for _, r := range []*DNSResolution{&recent, &old, &live} {
		if err := db.Create(r).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.removeUnusedEvidence(now); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		id   uint
		want int64
	}{{recent.ID, 1}, {old.ID, 0}, {live.ID, 1}} {
		var count int64
		db.Model(&DNSResolution{}).Where("id = ?", check.id).Count(&count)
		if count != check.want {
			t.Fatalf("resolution %d: count %d, want %d", check.id, count, check.want)
		}
	}
}

func TestEnforceCollectorLimitDiscardsOldestPendingAndRecordsGap(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "collector.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	events := make([]NetworkEvent, 4000)
	padding := strings.Repeat("x", 512)
	for i := range events {
		events[i] = NetworkEvent{Timestamp: start.Add(time.Duration(i) * time.Second), EventType: EventTCPStart, SourceContext: padding}
	}
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAcknowledgment("http://central", 0); err != nil {
		t.Fatal(err)
	}
	size, err := db.StorageBytes()
	if err != nil {
		t.Fatal(err)
	}
	limit := size / 2
	removed, err := db.EnforceCollectorLimit("http://central", limit)
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 || removed >= int64(len(events)) {
		t.Fatalf("removed = %d", removed)
	}
	if size, _ = db.StorageBytes(); size > limit {
		t.Fatalf("size %d still above limit %d", size, limit)
	}
	var gap NetworkEvent
	if err := db.Where("event_type = ?", EventGap).First(&gap).Error; err != nil {
		t.Fatal(err)
	}
	if gap.Reason != GapCollectorLimit || gap.EventCount != removed || !gap.Timestamp.Equal(start) || !gap.EndTime.Equal(start.Add(time.Duration(removed-1)*time.Second)) {
		t.Fatalf("gap = %+v", gap)
	}
	var oldest NetworkEvent
	if err := db.Where("event_type = ?", EventTCPStart).Order("id").First(&oldest).Error; err != nil {
		t.Fatal(err)
	}
	if want := start.Add(time.Duration(removed) * time.Second); !oldest.Timestamp.Equal(want) {
		t.Fatalf("oldest retained %v, want %v (newest events must be kept)", oldest.Timestamp, want)
	}
	if again, err := db.EnforceCollectorLimit("http://central", limit); err != nil || again != 0 {
		t.Fatalf("second enforcement removed %d, %v", again, err)
	}
	_ = fmt.Sprint()
}
