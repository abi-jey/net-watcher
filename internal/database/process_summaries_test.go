package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func processEvent(at time.Time, eventType EventType, collector, side, pod, container, command string, bytes int64) NetworkEvent {
	return NetworkEvent{Timestamp: at, EventType: eventType, SrcIP: "10.0.0.7", DstIP: "10.0.0.9", ByteCount: bytes, CollectorID: collector,
		ProcessPID: 42, ProcessCommand: command, ProcessSide: side, ProcessPod: pod, ProcessContainer: container}
}

func assertProcessSummaryMatchesRaw(t *testing.T, db *DB) {
	t.Helper()
	type total struct {
		Collector, Side, Pod, Container, Command    string
		Events, Connections, PeerConnections, Bytes int64
	}
	var raw, summary []total
	// Each event counts for its process and, when recorded, the peer process
	// at the other end.
	err := db.Raw(`SELECT collector, side, pod, container, command, COUNT(*) AS events, SUM(event_type IN ('TCP_START','UDP_START')) AS connections,
		SUM(peer AND event_type IN ('TCP_START','UDP_START')) AS peer_connections, SUM(COALESCE(byte_count, 0)) AS bytes FROM (
			SELECT collector_id AS collector, process_side AS side, process_pod AS pod, process_container AS container, process_command AS command, event_type, byte_count, 0 AS peer
			FROM network_events WHERE process_side > ''
			UNION ALL
			SELECT collector_id, CASE process_side WHEN 'src' THEN 'dst' ELSE 'src' END, peer_process_pod, peer_process_container, peer_process_command, event_type, byte_count, 1
			FROM network_events WHERE peer_process_command > ''
		) GROUP BY 1, 2, 3, 4, 5 ORDER BY 1, 2, 3, 4, 5`).Scan(&raw).Error
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Raw(`SELECT collector_id AS collector, side, pod, container, command, SUM(event_count) AS events, SUM(connections) AS connections,
		SUM(peer_connections) AS peer_connections, SUM(byte_count) AS bytes
		FROM hourly_processes GROUP BY 1, 2, 3, 4, 5 ORDER BY 1, 2, 3, 4, 5`).Scan(&summary).Error; err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(raw) != fmt.Sprint(summary) {
		t.Fatalf("summary %v\nraw %v", summary, raw)
	}
}

// withPeer adds the process that accepted the connection.
func withPeer(event NetworkEvent, pod, container, command string) NetworkEvent {
	event.PeerProcessPID, event.PeerProcessPod, event.PeerProcessContainer, event.PeerProcessCommand = 43, pod, container, command
	return event
}

// The process summary starts at the end of existing history (older rows have
// no process side), stays exact under live inserts and retention removal, and
// a compaction reset rebuilds it from the first attributed event.
func TestProcessSummaryLiveInsertRemovalAndReset(t *testing.T) {
	db := summaryDB(t)
	at := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	if err := db.InsertBatch([]NetworkEvent{{Timestamp: at, EventType: EventTCPStart, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", ProcessCommand: "legacy"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status, err := ProcessSummaryStatus(db.DB); err != nil || !status.Ready || status.Cursor != 1 {
		t.Fatalf("process summary should start ready after existing rows: %+v %v", status, err)
	}
	var events []NetworkEvent
	for i := range 9 {
		when := at.Add(time.Duration(i) * 25 * time.Minute)
		events = append(events,
			processEvent(when, EventTCPStart, "node-a", "src", "demo/api-1", "api", "python3", 0),
			processEvent(when.Add(time.Second), EventTCPEnd, "node-a", "src", "demo/api-1", "api", "python3", int64(1000+i)),
			processEvent(when, EventUDPStart, "node-b", "src", "", "", "tailscaled", 0),
			processEvent(when, EventTCPStart, "node-a", "dst", "demo/db-0", "postgres", "postgres", 0),
			// A kubelet health check of the API pod: the pod's server is the peer.
			withPeer(processEvent(when, EventTCPStart, "node-a", "src", "", "", "kubelet", 0), "demo/api-1", "api", "python3"),
			withPeer(processEvent(when.Add(time.Millisecond), EventTCPEnd, "node-a", "src", "", "", "kubelet", 900), "demo/api-1", "api", "python3"),
			NetworkEvent{Timestamp: when, EventType: EventTCPStart, SrcIP: "10.0.0.3", DstIP: "10.0.0.4"}, // Unattributed.
		)
	}
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	assertProcessSummaryMatchesRaw(t, db)

	// Remove the first hour the way retention does.
	err := db.Transaction(func(tx *gorm.DB) error {
		var old []NetworkEvent
		if err := tx.Select(summaryColumns).Where("timestamp < ?", at.Add(time.Hour)).Find(&old).Error; err != nil {
			return err
		}
		if err := ApplyEventSummaries(tx, old, -1); err != nil {
			return err
		}
		ids := make([]uint, len(old))
		for i, event := range old {
			ids[i] = event.ID
		}
		return tx.Delete(&NetworkEvent{}, ids).Error
	})
	if err != nil {
		t.Fatal(err)
	}
	assertProcessSummaryMatchesRaw(t, db)
	var emptied int64
	if err := db.Model(&HourlyProcess{}).Where("hour = ?", at.Unix()).Count(&emptied).Error; err != nil || emptied != 0 {
		t.Fatalf("emptied hour kept %d rows: %v", emptied, err)
	}

	// After a reset (as compaction does), the backfill rebuilds the same totals.
	if err := db.Transaction(resetProcessSummaries); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		done, err := db.backfillSummary(t.Context(), processSummaryState, 7, aggregateProcesses)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	if status, err := ProcessSummaryStatus(db.DB); err != nil || !status.Ready {
		t.Fatalf("not ready after rebuild: %+v %v", status, err)
	}
	assertProcessSummaryMatchesRaw(t, db)
}

// The events drill-down by process uses the partial index, not a time scan.
func TestProcessFilterUsesPartialIndex(t *testing.T) {
	db := summaryDB(t)
	var plan []struct{ Detail string }
	err := db.Raw(`EXPLAIN QUERY PLAN SELECT * FROM network_events WHERE process_command = ? AND process_pod = ? AND process_container = ? AND process_side > ''
		AND timestamp >= ? AND timestamp < ? ORDER BY timestamp DESC, id DESC LIMIT 50`, "python3", "demo/api-1", "api", time.Now().Add(-time.Hour), time.Now()).Scan(&plan).Error
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(plan) == "" || !strings.Contains(fmt.Sprint(plan), "idx_process_time") {
		t.Fatalf("plan does not use idx_process_time: %v", plan)
	}
}
