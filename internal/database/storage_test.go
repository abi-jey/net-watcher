package database

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPruneToSizeRemovesOldestAndPreservesReferencedEvidence(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	at := time.Now().UTC().Add(-2 * time.Hour)
	referenced := DNSResolution{ResponseTime: at, ExpiresAt: at.Add(time.Hour), Name: "kept.test", IP: "203.0.113.1"}
	orphan := DNSResolution{ResponseTime: at, ExpiresAt: at.Add(time.Hour), Name: "orphan.test", IP: "203.0.113.2"}
	for _, resolution := range []*DNSResolution{&referenced, &orphan} {
		if err := db.Create(resolution).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&IngestedResolution{CollectorID: "node-a", SourceID: resolution.ID, ResolutionID: resolution.ID}).Error; err != nil {
			t.Fatal(err)
		}
	}

	var firstID, newestID uint
	for i := range 120 {
		event := NetworkEvent{
			Timestamp: at.Add(time.Duration(i) * time.Second),
			EventType: EventTCPStart,
			Hostname:  strings.Repeat("x", 8192),
		}
		if i == 119 {
			event.DNSResolutionIDs = fmt.Sprintf("[%d]", referenced.ID)
		}
		if err := db.Create(&event).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&IngestedEvent{CollectorID: "node-a", SourceID: uint(i + 1), EventID: event.ID}).Error; err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstID = event.ID
		}
		newestID = event.ID
	}
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BackfillSummaries(t.Context(), 1000); err != nil {
		t.Fatal(err)
	}
	if err := db.checkpoint(); err != nil {
		t.Fatal(err)
	}
	size, err := db.StorageBytes()
	if err != nil {
		t.Fatal(err)
	}
	limit := size * 3 / 4
	removed, err := db.PruneToSize(limit)
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 || removed >= 120 {
		t.Fatalf("removed = %d", removed)
	}
	assertSummaryMatchesRaw(t, db)
	size, err = db.StorageBytes()
	if err != nil || size > limit {
		t.Fatalf("size = %d, limit = %d, error = %v", size, limit, err)
	}
	for _, check := range []struct {
		id   uint
		want int64
	}{{firstID, 0}, {newestID, 1}} {
		var count, mappings int64
		if err := db.Model(&NetworkEvent{}).Where("id = ?", check.id).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Model(&IngestedEvent{}).Where("event_id = ?", check.id).Count(&mappings).Error; err != nil {
			t.Fatal(err)
		}
		if count != check.want || mappings != check.want {
			t.Fatalf("event %d: records = %d, ingest keys = %d, want %d", check.id, count, mappings, check.want)
		}
	}
	var count int64
	db.Model(&DNSResolution{}).Where("id = ?", referenced.ID).Count(&count)
	if count != 1 {
		t.Fatal("referenced DNS evidence was pruned")
	}
	db.Model(&DNSResolution{}).Where("id = ?", orphan.ID).Count(&count)
	if count != 0 {
		t.Fatal("unreferenced DNS evidence was retained")
	}
	db.Model(&IngestedResolution{}).Where("resolution_id = ?", orphan.ID).Count(&count)
	if count != 0 {
		t.Fatal("orphaned DNS ingest key was retained")
	}
}

func TestCollectorReclaimKeepsPendingEventsAndEvidence(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "collector.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Add(-2 * time.Hour)
	referenced := DNSResolution{ResponseTime: at, ExpiresAt: at.Add(time.Minute), Name: "pending.test", IP: "203.0.113.1"}
	orphan := DNSResolution{ResponseTime: at, ExpiresAt: at.Add(time.Minute), Name: "orphan.test", IP: "203.0.113.2"}
	for _, resolution := range []*DNSResolution{&referenced, &orphan} {
		if err := db.Create(resolution).Error; err != nil {
			t.Fatal(err)
		}
	}
	old := NetworkEvent{Timestamp: at, EventType: EventDNS}
	pending := NetworkEvent{Timestamp: at.Add(time.Second), EventType: EventTCPStart, DNSResolutionIDs: fmt.Sprintf("[%d]", referenced.ID)}
	for _, event := range []*NetworkEvent{&old, &pending} {
		if err := db.Create(event).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RecordAcknowledgment("http://central", old.ID); err != nil {
		t.Fatal(err)
	}
	removed, err := db.ReclaimCollectorSpace("http://central")
	if err != nil || removed != 1 {
		t.Fatalf("reclaimed = %d, error = %v", removed, err)
	}
	for _, check := range []struct {
		model interface{}
		id    uint
		want  int64
	}{{&NetworkEvent{}, old.ID, 0}, {&NetworkEvent{}, pending.ID, 1}, {&DNSResolution{}, referenced.ID, 1}, {&DNSResolution{}, orphan.ID, 0}} {
		var count int64
		if err := db.Model(check.model).Where("id = ?", check.id).Count(&count).Error; err != nil || count != check.want {
			t.Fatalf("id %d: count = %d, want %d, error = %v", check.id, count, check.want, err)
		}
	}
}
