package database

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"
)

func summaryDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(filepath.Join(t.TempDir(), "summary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func finishBackfill(t *testing.T, db *DB) {
	t.Helper()
	for range 100 {
		done, err := db.BackfillSummaries(t.Context(), 3)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			return
		}
	}
	t.Fatal("backfill did not finish")
}

func assertSummaryMatchesRaw(t *testing.T, db *DB) {
	t.Helper()
	var events []NetworkEvent
	if err := db.Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	counts, total, err := EventCounts(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts := map[string]int64{}
	for _, event := range events {
		wantCounts[string(event.EventType)]++
	}
	if total != int64(len(events)) || !reflect.DeepEqual(counts, wantCounts) {
		t.Fatalf("counts=%v total=%d, want %v total=%d", counts, total, wantCounts, len(events))
	}
	for _, kind := range []string{"srcIP", "dstIP", "hostname"} {
		rows, _, err := TopHosts(db.DB, kind, time.Time{}, time.Time{}, 100, true)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string][2]int64{}
		for _, row := range rows {
			got[row.Host] = [2]int64{row.EventCount, row.ByteCount}
		}
		want := map[string][2]int64{}
		for _, event := range events {
			host := event.Hostname
			if kind == "srcIP" {
				host = event.SrcIP
			} else if kind == "dstIP" {
				host = event.DstIP
			}
			if host == "" {
				continue
			}
			value := want[host]
			value[0]++
			value[1] += event.ByteCount
			want[host] = value
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s totals=%v, want %v", kind, got, want)
		}
	}
}

func TestSparseSummariesCoalesceBatchAndRollback(t *testing.T) {
	db := summaryDB(t)
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var events []NetworkEvent
	for i := range 120 {
		events = append(events, NetworkEvent{Timestamp: at.Add(time.Duration(i/60) * 2 * time.Hour), EventType: EventTCPEnd, SrcIP: "10.0.0.1", DstIP: "203.0.113.1", Hostname: "api.test", ByteCount: 100})
	}
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	var hours, hosts int64
	if err := db.Model(&HourlyEvent{}).Count(&hours).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&HourlyHost{}).Count(&hosts).Error; err != nil {
		t.Fatal(err)
	}
	if hours != 2 || hosts != 6 {
		t.Fatalf("expected only populated buckets, got %d event rows, %d host rows", hours, hosts)
	}
	sentinel := errors.New("abort")
	err := db.Transaction(func(tx *gorm.DB) error {
		event := NetworkEvent{Timestamp: at, EventType: EventDNS, SrcIP: "10.0.0.2", ByteCount: 999}
		if err := tx.Create(&event).Error; err != nil {
			return err
		}
		if err := ApplyEventSummaries(tx, []NetworkEvent{event}, 1); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	assertSummaryMatchesRaw(t, db)
}

func TestBackfillResumesWithLiveIngestionAndPartialCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.db")
	db, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	at := time.Now().UTC().Truncate(time.Hour)
	var events []NetworkEvent
	for i := range 6 {
		events = append(events, NetworkEvent{Timestamp: at.Add(time.Duration(i) * time.Minute), EventType: EventTCPEnd, SrcIP: "10.0.0.1", DstIP: "203.0.113.1", ByteCount: int64(i + 1)})
	}
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	if done, err := db.BackfillSummaries(t.Context(), 2); err != nil || done {
		t.Fatalf("first chunk: done=%v err=%v", done, err)
	}
	if ready, err := SummariesReady(db.DB); err != nil || ready {
		t.Fatalf("incomplete summaries marked ready: %v %v", ready, err)
	}
	// A late-arriving observation in the same historical hour is summarized live.
	if err := db.InsertEvent(&NetworkEvent{Timestamp: at, EventType: EventDNS, SrcIP: "10.0.0.2", ByteCount: 40}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAcknowledgment("test", events[2].ID); err != nil {
		t.Fatal(err)
	}
	if removed, err := db.ReclaimCollectorSpace("test"); err != nil || removed != 3 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	assertSummaryMatchesRaw(t, db)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := db.BackfillSummaries(ctx, 2); err == nil {
		t.Fatal("canceled backfill succeeded")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	finishBackfill(t, db)
	assertSummaryMatchesRaw(t, db)
	if err := db.RecordAcknowledgment("test", 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReclaimCollectorSpace("test"); err != nil {
		t.Fatal(err)
	}
	for _, model := range []interface{}{&HourlyHost{}, &HourlyEvent{}} {
		var count int64
		if err := db.Model(model).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("empty summary rows retained: %d %v", count, err)
		}
	}
}

func TestSummaryAnalyticsMatchesRawIncludingHourBoundaries(t *testing.T) {
	db := summaryDB(t)
	at := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	var events []NetworkEvent
	for i, minute := range []int{50, 70, 80, 120, 239, 250, 270} {
		events = append(events, NetworkEvent{Timestamp: at.Add(time.Duration(minute) * time.Minute), EventType: EventTCPEnd, SrcIP: "172.20.0.1", DstIP: "fd00::1", Hostname: "api.test", ByteCount: int64(i+1) * 100})
	}
	events[3].SrcIP = "203.0.113.1"
	events[4].Hostname = "other.test"
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	start, end := at.Add(75*time.Minute), at.Add(270*time.Minute)
	local := func(value string) bool { address, _ := netip.ParseAddr(value); return address.IsPrivate() }
	before := map[int64]map[int64]*TrafficBucket{}
	for _, size := range []int64{300, 3600, 7200, 604800} {
		rows, err := TrafficTotals(db.DB, start, end, size, local)
		if err != nil {
			t.Fatal(err)
		}
		before[size] = rows
	}
	hosts, unique, err := TopHosts(db.DB, "hostname", start, end, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if unique != 2 || len(hosts) != 1 || hosts[0].EventCount != 3 {
		t.Fatalf("raw ranking: %+v, unique=%d", hosts, unique)
	}
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BackfillSummaries(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	// Partial historical coverage must never leak into API totals.
	assertSummaryMatchesRaw(t, db)
	finishBackfill(t, db)
	for size, expected := range before {
		actual, err := TrafficTotals(db.DB, start, end, size, local)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("bucket=%d: got %+v, want %+v", size, actual, expected)
		}
		var total int64
		for _, row := range actual {
			total += row.EventCount
		}
		if total != 4 {
			t.Fatalf("range boundary count=%d, want 4", total)
		}
	}
	after, total, err := TopHosts(db.DB, "hostname", start, end, 1, true)
	if err != nil || total != unique || !reflect.DeepEqual(after, hosts) {
		t.Fatalf("summary ranking: %+v %d %v, want %+v %d", after, total, err, hosts, unique)
	}
	assertSummaryMatchesRaw(t, db)
}

func TestHybridAnalyticsAtEveryBackfillCursor(t *testing.T) {
	db := summaryDB(t)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var events []NetworkEvent
	for i := range 12 {
		events = append(events, NetworkEvent{Timestamp: at.Add(time.Duration(i) * time.Hour), EventType: EventTCPEnd, SrcIP: fmt.Sprintf("10.0.0.%d", i%3), DstIP: "203.0.113.1", Hostname: "api.test", ByteCount: int64(i + 1)})
	}
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, hour := range []int{4, 20} {
		if err := db.InsertEvent(&NetworkEvent{Timestamp: at.Add(time.Duration(hour)*time.Hour + time.Minute), EventType: EventDNS, SrcIP: "10.0.0.8", DstIP: "203.0.113.2", Hostname: "live.test", ByteCount: 100}); err != nil {
			t.Fatal(err)
		}
	}
	start, end := at.Add(90*time.Minute), at.Add(570*time.Minute)
	local := func(string) bool { return true }
	var wantHosts []HostTotal
	var wantUnique int64
	var wantTraffic map[int64]*TrafficBucket
	// The paused path is the raw-data oracle; toggling it here affects no worker.
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&AggregateState{}).Where("id=1").Update("paused", true).Error; err != nil {
			return err
		}
		var err error
		wantHosts, wantUnique, err = TopHosts(tx, "srcIP", start, end, 100, true)
		if err != nil {
			return err
		}
		wantTraffic, err = TrafficTotals(tx, start, end, 3600, local)
		if err != nil {
			return err
		}
		return tx.Model(&AggregateState{}).Where("id=1").Update("paused", false).Error
	}); err != nil {
		t.Fatal(err)
	}
	for step := 0; step <= 4; step++ {
		assertSummaryMatchesRaw(t, db)
		hosts, unique, err := TopHosts(db.DB, "srcIP", start, end, 100, true)
		if err != nil || unique != wantUnique || !reflect.DeepEqual(hosts, wantHosts) {
			t.Fatalf("step=%d hybrid hosts=%+v, want %+v: %v", step, hosts, wantHosts, err)
		}
		traffic, err := TrafficTotals(db.DB, start, end, 3600, local)
		if err != nil || !reflect.DeepEqual(traffic, wantTraffic) {
			t.Fatalf("step=%d hybrid traffic differs: %v", step, err)
		}
		if _, err := db.BackfillSummaries(t.Context(), 3); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkBatchWithHourlySummaries(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprintf("summaries=%v", enabled), func(b *testing.B) {
			db, err := New(filepath.Join(b.TempDir(), "bench.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			if enabled {
				if err := db.EnableSummaries(b.Context()); err != nil {
					b.Fatal(err)
				}
			}
			at := time.Now().UTC()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				events := make([]NetworkEvent, 250)
				for j := range events {
					events[j] = NetworkEvent{Timestamp: at, EventType: EventTCPEnd, SrcIP: fmt.Sprintf("10.0.0.%d", j%16), DstIP: "203.0.113.1", Hostname: "api.test", ByteCount: 1000}
				}
				if err := db.InsertBatch(events); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDashboardSummaryQueries(b *testing.B) {
	db, err := New(filepath.Join(b.TempDir(), "queries.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	events := make([]NetworkEvent, 20000)
	for i := range events {
		events[i] = NetworkEvent{Timestamp: at.Add(time.Duration(i%1440) * time.Minute), EventType: EventTCPEnd, SrcIP: fmt.Sprintf("10.0.0.%d", i%16), DstIP: "203.0.113.1", Hostname: "api.test", ByteCount: 1000}
	}
	if err := db.InsertBatch(events); err != nil {
		b.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		if enabled {
			if err := db.EnableSummaries(b.Context()); err != nil {
				b.Fatal(err)
			}
			for {
				done, err := db.BackfillSummaries(b.Context(), 1000)
				if err != nil {
					b.Fatal(err)
				}
				if done {
					break
				}
			}
		}
		b.Run(fmt.Sprintf("summaries=%v", enabled), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if err := db.Transaction(func(tx *gorm.DB) error {
					if _, _, err := EventCounts(tx); err != nil {
						return err
					}
					if _, _, err := TopHosts(tx, "srcIP", at, at.Add(24*time.Hour), 10, true); err != nil {
						return err
					}
					_, err := TrafficTotals(tx, at, at.Add(24*time.Hour), 3600, func(string) bool { return true })
					return err
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
