package database

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// processSummaryState is the AggregateState row tracking HourlyProcess.
const processSummaryState = 3

// HourlyProcess totals one process identity's events on one side of
// connections in one UTC hour on one collector. A process is identified by
// what stays stable across restarts: node, pod, container and command name;
// PIDs are not part of the key.
type HourlyProcess struct {
	Hour        int64  `gorm:"primaryKey;autoIncrement:false"`
	CollectorID string `gorm:"primaryKey"`
	Side        string `gorm:"primaryKey"` // "src" (the process opened it) or "dst" (it accepted it)
	Pod         string `gorm:"primaryKey"` // namespace/name; empty for host processes
	Container   string `gorm:"primaryKey"`
	Command     string `gorm:"primaryKey"`
	Namespace   string `gorm:"index"`
	EventCount  int64
	// Connections counts flows the process was attributed at their start.
	Connections int64
	// PeerConnections counts those of Connections where the process was the
	// event's peer process (the flow's other end was attributed too), so
	// attributed flows are Connections - PeerConnections summed over all rows.
	PeerConnections int64
	// ByteCount totals both directions of attributed flows, recorded at flow end.
	ByteCount int64
	FirstSeen int64
	LastSeen  int64
}

// ProcessSummaryStatus reports whether HourlyProcess covers all retained
// attributed events.
func ProcessSummaryStatus(tx *gorm.DB) (AggregationStatus, error) {
	var state AggregateState
	err := tx.First(&state, processSummaryState).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AggregationStatus{}, nil
	}
	if err != nil {
		return AggregationStatus{}, err
	}
	return AggregationStatus{Enabled: true, Ready: !state.Paused && state.Cursor >= state.Target, Cursor: state.Cursor, Target: state.Target, Paused: state.Paused}, nil
}

// enableProcessSummaries starts coverage at the current end of the table the
// first time: events stored before this version carry no process side, so
// there is nothing to backfill and no reason to scan the history.
func enableProcessSummaries(tx *gorm.DB) error {
	var state AggregateState
	err := tx.First(&state, processSummaryState).Error
	if err == nil && !state.Paused {
		return nil
	}
	if err == nil {
		return resetProcessSummaries(tx)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	var target uint
	if err := tx.Raw("SELECT COALESCE(MAX(id), 0) FROM network_events").Scan(&target).Error; err != nil {
		return err
	}
	return tx.Create(&AggregateState{ID: processSummaryState, Cursor: target, Target: target}).Error
}

// resetProcessSummaries rebuilds from the first attributed event, after
// compaction rewrote history.
func resetProcessSummaries(tx *gorm.DB) error {
	if err := tx.Exec("DELETE FROM hourly_processes").Error; err != nil {
		return err
	}
	var target, first uint
	if err := tx.Raw("SELECT COALESCE(MAX(id), 0) FROM network_events").Scan(&target).Error; err != nil {
		return err
	}
	if err := tx.Raw("SELECT COALESCE(MIN(id), 0) FROM network_events WHERE process_side > ''").Scan(&first).Error; err != nil {
		return err
	}
	cursor := target
	if first > 0 {
		cursor = first - 1
	}
	return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&AggregateState{ID: processSummaryState, Cursor: cursor, Target: target}).Error
}

func isFlowStart(eventType EventType) bool {
	return eventType == EventTCPStart || eventType == EventUDPStart
}

func aggregateProcesses(tx *gorm.DB, events []NetworkEvent, delta int64) error {
	if delta != 1 && delta != -1 {
		return fmt.Errorf("invalid summary delta %d", delta)
	}
	type key struct {
		hour                                     int64
		collector, side, pod, container, command string
	}
	rows := map[key]*HourlyProcess{}
	hours := map[int64]bool{}
	add := func(event NetworkEvent, side, pod, container, command string, peer bool) {
		hour := event.Timestamp.UTC().Truncate(time.Hour).Unix()
		at := event.Timestamp.UnixNano()
		hours[hour] = true
		k := key{hour, event.CollectorID, side, pod, container, command}
		row := rows[k]
		if row == nil {
			namespace, _, _ := strings.Cut(pod, "/")
			row = &HourlyProcess{Hour: hour, CollectorID: event.CollectorID, Side: side, Pod: pod,
				Container: container, Command: command, Namespace: namespace, FirstSeen: at, LastSeen: at}
			rows[k] = row
		}
		row.EventCount += delta
		row.ByteCount += delta * event.ByteCount
		if isFlowStart(event.EventType) {
			row.Connections += delta
			if peer {
				row.PeerConnections += delta
			}
		}
		row.FirstSeen = min(row.FirstSeen, at)
		row.LastSeen = max(row.LastSeen, at)
	}
	for _, event := range events {
		if event.ProcessSide == "" {
			continue
		}
		add(event, event.ProcessSide, event.ProcessPod, event.ProcessContainer, event.ProcessCommand, false)
		if event.PeerProcessCommand != "" {
			add(event, otherSide(event.ProcessSide), event.PeerProcessPod, event.PeerProcessContainer, event.PeerProcessCommand, true)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	list := make([]HourlyProcess, 0, len(rows))
	for _, row := range rows {
		list = append(list, *row)
	}
	// A fixed order keeps concurrent writers from deadlocking on row locks.
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		return fmt.Sprint(a.Hour, a.CollectorID, a.Side, a.Pod, a.Container, a.Command) < fmt.Sprint(b.Hour, b.CollectorID, b.Side, b.Pod, b.Container, b.Command)
	})
	counts := map[string]interface{}{
		"event_count":      gorm.Expr("event_count + excluded.event_count"),
		"connections":      gorm.Expr("connections + excluded.connections"),
		// Rows from before the column existed hold NULL.
		"peer_connections": gorm.Expr("COALESCE(peer_connections, 0) + excluded.peer_connections"),
		"byte_count":       gorm.Expr("byte_count + excluded.byte_count"),
	}
	updates := clause.Assignments(counts)
	if delta > 0 {
		counts["first_seen"] = gorm.Expr("MIN(first_seen, excluded.first_seen)")
		counts["last_seen"] = gorm.Expr("MAX(last_seen, excluded.last_seen)")
		updates = clause.Assignments(counts)
	}
	columns := []clause.Column{{Name: "hour"}, {Name: "collector_id"}, {Name: "side"}, {Name: "pod"}, {Name: "container"}, {Name: "command"}}
	tx = tx.Session(&gorm.Session{SkipDefaultTransaction: true})
	if err := tx.Clauses(clause.OnConflict{Columns: columns, DoUpdates: updates}).CreateInBatches(&list, 50).Error; err != nil {
		return err
	}
	if delta < 0 {
		for hour := range hours {
			if err := tx.Where("hour = ? AND event_count <= 0", hour).Delete(&HourlyProcess{}).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// otherSide is the end opposite side ("src" or "dst").
func otherSide(side string) string {
	if side == "src" {
		return "dst"
	}
	return "src"
}
