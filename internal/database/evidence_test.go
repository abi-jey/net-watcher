package database

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCompactionKeepsVersionedDNSAndConnectionEvidence(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().Add(-time.Hour)
	resolution := DNSResolution{Name: "api.test", IP: "203.0.113.20", ClientIP: "10.2.0.8", QueryTime: at, ResponseTime: at.Add(time.Millisecond), ExpiresAt: at.Add(time.Minute), TTL: 60}
	if err := db.Create(&resolution).Error; err != nil {
		t.Fatal(err)
	}
	rows := []NetworkEvent{
		{Timestamp: at, EventType: EventDNS, DNSVersion: 1, DNSType: "QUERY", DNSQuery: "api.test", SrcIP: "10.2.0.8"},
		{Timestamp: at.Add(time.Millisecond), EventType: EventDNS, DNSVersion: 1, DNSType: "RESPONSE", DNSQuery: "api.test", DNSMatched: true},
		{Timestamp: at, EventType: EventTCPStart, SrcIP: "10.2.0.8", SrcPort: 1234, DstIP: "203.0.113.20", DstPort: 443, DNSResolutionIDs: "[1]", SourceContext: `{"UID":"pod-at-capture"}`},
		{Timestamp: at.Add(time.Second), EventType: EventTCPEnd, SrcIP: "10.2.0.8", SrcPort: 1234, DstIP: "203.0.113.20", DstPort: 443, ByteCount: 500},
	}
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertBatch(rows); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Compact(time.Now(), time.Second); err != nil {
		t.Fatal(err)
	}
	finishBackfill(t, db)
	assertSummaryMatchesRaw(t, db)
	var count int64
	db.Model(&NetworkEvent{}).Where("dns_version = 1").Count(&count)
	if count != 2 {
		t.Fatal("versioned DNS observations were heuristically combined")
	}
	var compacted NetworkEvent
	if err := db.Where("event_type = ?", EventTCP).First(&compacted).Error; err != nil {
		t.Fatal(err)
	}
	if compacted.DNSResolutionIDs != "[1]" || compacted.SourceContext != rows[2].SourceContext {
		t.Fatal("connection compaction lost historical attribution")
	}
	db.Model(&DNSResolution{}).Count(&count)
	if count != 1 {
		t.Fatal("historical evidence was deleted")
	}
}
