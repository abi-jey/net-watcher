package database

import (
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"
)

func podSummaryEvent(at time.Time, uid, attribution string) NetworkEvent {
	return NetworkEvent{Timestamp: at, EventType: EventTCPStart, SrcIP: "10.0.0.7", DstIP: "10.0.0.9",
		SrcKind: "pod", SrcNamespace: "demo", SrcName: "api-" + uid, SrcUID: uid, SrcWorkload: "Deployment/api", SrcAttribution: attribution,
		DstKind: "pod", DstNamespace: "demo", DstName: "db-0", DstUID: "db", DstWorkload: "StatefulSet/db", DstAttribution: "exact"}
}

func assertPodSummaryMatchesRaw(t *testing.T, db *DB) {
	t.Helper()
	type total struct {
		Side, UID         string
		Events, Uncertain int64
	}
	var raw, summary []total
	err := db.Raw(`SELECT side, uid, COUNT(*) AS events, SUM(uncertain) AS uncertain FROM (
		SELECT 'src' AS side, src_uid AS uid, src_attribution IN ('ambiguous','stale') AS uncertain FROM network_events WHERE src_kind = 'pod'
		UNION ALL SELECT 'dst', dst_uid, dst_attribution IN ('ambiguous','stale') FROM network_events WHERE dst_kind = 'pod')
		GROUP BY side, uid ORDER BY side, uid`).Scan(&raw).Error
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Raw("SELECT side, uid, SUM(event_count) AS events, SUM(uncertain) AS uncertain FROM hourly_pods GROUP BY side, uid ORDER BY side, uid").Scan(&summary).Error; err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(raw) != fmt.Sprint(summary) {
		t.Fatalf("summary %v, raw %v", summary, raw)
	}
}

// Enabling on an existing database starts at the first attributed event, the
// backfill and live inserts never double-count, and removal keeps the summary
// exact and drops emptied hours.
func TestPodSummaryBackfillLiveInsertAndRemoval(t *testing.T) {
	db := summaryDB(t)
	at := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	var legacy []NetworkEvent
	for i := range 5 {
		legacy = append(legacy, NetworkEvent{Timestamp: at.Add(time.Duration(i) * time.Minute), EventType: EventTCPStart, SrcIP: "10.0.0.1", DstIP: "10.0.0.2"})
	}
	var attributed []NetworkEvent
	for i := range 7 {
		attribution := "exact"
		if i%2 == 0 {
			attribution = "ambiguous"
		}
		attributed = append(attributed, podSummaryEvent(at.Add(time.Duration(i)*20*time.Minute), "a", attribution))
	}
	if err := db.InsertBatch(legacy); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertBatch(attributed); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	var state AggregateState
	if err := db.First(&state, podSummaryState).Error; err != nil || state.Cursor != 5 || state.Target != 12 {
		t.Fatalf("pod coverage should start after the legacy rows: %+v %v", state, err)
	}
	if done, err := db.BackfillPodSummaries(t.Context(), 3); err != nil || done {
		t.Fatalf("first chunk: %v %v", done, err)
	}
	if err := db.InsertBatch([]NetworkEvent{podSummaryEvent(at.Add(3*time.Hour), "b", "exact")}); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		done, err := db.BackfillPodSummaries(t.Context(), 3)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	if status, err := PodSummaryStatus(db.DB); err != nil || !status.Ready {
		t.Fatalf("not ready: %+v %v", status, err)
	}
	assertPodSummaryMatchesRaw(t, db)

	// Remove the first hour of attributed events the way retention does.
	err := db.Transaction(func(tx *gorm.DB) error {
		var events []NetworkEvent
		if err := tx.Select(summaryColumns).Where("src_kind = 'pod' AND timestamp < ?", at.Add(time.Hour)).Find(&events).Error; err != nil {
			return err
		}
		if len(events) != 3 {
			return fmt.Errorf("expected 3 events in the first hour, got %d", len(events))
		}
		if err := ApplyEventSummaries(tx, events, -1); err != nil {
			return err
		}
		ids := make([]uint, len(events))
		for i, event := range events {
			ids[i] = event.ID
		}
		return tx.Delete(&NetworkEvent{}, ids).Error
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPodSummaryMatchesRaw(t, db)
	var emptied int64
	if err := db.Model(&HourlyPod{}).Where("hour = ?", at.Unix()).Count(&emptied).Error; err != nil || emptied != 0 {
		t.Fatalf("emptied hour kept %d rows: %v", emptied, err)
	}
}
