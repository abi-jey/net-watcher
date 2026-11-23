package database

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// podSummaryState is the AggregateState row tracking HourlyPod coverage. It is
// separate from the event/host summaries (row 1) so enabling it on an existing
// database only backfills rows that carry pod attribution.
const podSummaryState = 2

// HourlyPod totals one pod's events on one side of connections in one UTC
// hour. Listing pods over a day reads at most 24 rows per pod instead of
// millions of events. FirstSeen/LastSeen are UnixNano bounds of the counted
// events; retention lowers counts but cannot narrow the bounds, so they may be
// wider than the remaining events until the hour expires entirely.
type HourlyPod struct {
	Hour       int64  `gorm:"primaryKey;autoIncrement:false"`
	Side       string `gorm:"primaryKey"` // "src" (egress) or "dst" (ingress)
	UID        string `gorm:"primaryKey"`
	Namespace  string `gorm:"index"`
	Name       string
	Workload   string
	EventCount int64
	// ByteCount totals the connections on this side: bytes in both directions
	// of each flow, recorded when the flow ends.
	ByteCount int64
	Uncertain int64
	FirstSeen int64
	LastSeen  int64
}

// PodSummaryStatus reports whether HourlyPod covers all retained pod events.
func PodSummaryStatus(tx *gorm.DB) (AggregationStatus, error) {
	var state AggregateState
	err := tx.First(&state, podSummaryState).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AggregationStatus{}, nil
	}
	if err != nil {
		return AggregationStatus{}, err
	}
	return AggregationStatus{Enabled: true, Ready: !state.Paused && state.Cursor >= state.Target, Cursor: state.Cursor, Target: state.Target, Paused: state.Paused}, nil
}

func enablePodSummaries(tx *gorm.DB) error {
	var state AggregateState
	err := tx.First(&state, podSummaryState).Error
	if err == nil && !state.Paused {
		return nil
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return resetPodSummaries(tx)
}

// resetPodSummaries starts coverage at the first attributed event. Events
// before pod attribution existed carry no pod columns, so skipping them loses
// nothing and avoids rescanning the whole history. Both lookups use indexes.
func resetPodSummaries(tx *gorm.DB) error {
	if err := tx.Exec("DELETE FROM hourly_pods").Error; err != nil {
		return err
	}
	var target, first uint
	if err := tx.Raw("SELECT COALESCE(MAX(id), 0) FROM network_events").Scan(&target).Error; err != nil {
		return err
	}
	if err := tx.Raw(`SELECT COALESCE(MIN(id), 0) FROM (
		SELECT MIN(id) AS id FROM network_events INDEXED BY idx_src_uid_time WHERE src_uid > ''
		UNION ALL SELECT MIN(id) FROM network_events INDEXED BY idx_dst_uid_time WHERE dst_uid > '')
		WHERE id IS NOT NULL`).Scan(&first).Error; err != nil {
		return err
	}
	cursor := target
	if first > 0 {
		cursor = first - 1
	}
	return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&AggregateState{ID: podSummaryState, Cursor: cursor, Target: target}).Error
}

func applyPodSummaries(tx *gorm.DB, events []NetworkEvent, delta int64) error {
	var state AggregateState
	err := tx.First(&state, podSummaryState).Error
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && state.Paused) {
		return nil
	}
	if err != nil {
		return err
	}
	covered := make([]NetworkEvent, 0, len(events))
	for _, event := range events {
		if event.ID <= state.Cursor || event.ID > state.Target {
			covered = append(covered, event)
		}
	}
	return aggregatePods(tx, covered, delta)
}

func aggregatePods(tx *gorm.DB, events []NetworkEvent, delta int64) error {
	if delta != 1 && delta != -1 {
		return fmt.Errorf("invalid summary delta %d", delta)
	}
	type key struct {
		hour      int64
		side, uid string
	}
	rows := map[key]*HourlyPod{}
	hours := map[int64]bool{}
	for _, event := range events {
		hour := event.Timestamp.UTC().Truncate(time.Hour).Unix()
		at := event.Timestamp.UnixNano()
		for _, side := range []struct {
			name, kind, uid, namespace, pod, workload, attribution string
		}{
			{"src", event.SrcKind, event.SrcUID, event.SrcNamespace, event.SrcName, event.SrcWorkload, event.SrcAttribution},
			{"dst", event.DstKind, event.DstUID, event.DstNamespace, event.DstName, event.DstWorkload, event.DstAttribution},
		} {
			if side.kind != "pod" || side.uid == "" {
				continue
			}
			hours[hour] = true
			k := key{hour, side.name, side.uid}
			row := rows[k]
			if row == nil {
				row = &HourlyPod{Hour: hour, Side: side.name, UID: side.uid, Namespace: side.namespace, Name: side.pod, Workload: side.workload, FirstSeen: at, LastSeen: at}
				rows[k] = row
			}
			row.EventCount += delta
			row.ByteCount += delta * event.ByteCount
			if side.attribution == "ambiguous" || side.attribution == "stale" {
				row.Uncertain += delta
			}
			row.FirstSeen = min(row.FirstSeen, at)
			row.LastSeen = max(row.LastSeen, at)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	list := make([]HourlyPod, 0, len(rows))
	for _, row := range rows {
		list = append(list, *row)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Hour != b.Hour {
			return a.Hour < b.Hour
		}
		if a.Side != b.Side {
			return a.Side < b.Side
		}
		return a.UID < b.UID
	})
	updates := clause.Assignments(map[string]interface{}{
		"event_count": gorm.Expr("event_count + excluded.event_count"),
		"byte_count":  gorm.Expr("byte_count + excluded.byte_count"),
		"uncertain":   gorm.Expr("uncertain + excluded.uncertain"),
		"first_seen":  gorm.Expr("MIN(first_seen, excluded.first_seen)"),
		"last_seen":   gorm.Expr("MAX(last_seen, excluded.last_seen)"),
		"workload":    gorm.Expr("CASE WHEN excluded.workload > '' THEN excluded.workload ELSE workload END"),
	})
	if delta < 0 {
		// Removal must not widen bounds or relabel; only counts change.
		updates = clause.Assignments(map[string]interface{}{
			"event_count": gorm.Expr("event_count + excluded.event_count"),
			"byte_count":  gorm.Expr("byte_count + excluded.byte_count"),
			"uncertain":   gorm.Expr("uncertain + excluded.uncertain"),
		})
	}
	tx = tx.Session(&gorm.Session{SkipDefaultTransaction: true})
	if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "hour"}, {Name: "side"}, {Name: "uid"}}, DoUpdates: updates}).CreateInBatches(&list, 50).Error; err != nil {
		return err
	}
	if delta < 0 {
		for hour := range hours {
			if err := tx.Where("hour = ? AND event_count <= 0", hour).Delete(&HourlyPod{}).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// BackfillPodSummaries covers at most limit historical events in one
// transaction, like BackfillSummaries.
func (db *DB) BackfillPodSummaries(ctx context.Context, limit int) (bool, error) {
	if limit < 1 || limit > 10000 {
		return false, fmt.Errorf("summary batch size must be between 1 and 10000")
	}
	var done bool
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var state AggregateState
		if err := tx.First(&state, podSummaryState).Error; err != nil {
			return err
		}
		if state.Paused {
			return nil
		}
		if state.Cursor >= state.Target {
			done = true
			return nil
		}
		var events []NetworkEvent
		if err := tx.Select(summaryColumns).Where("id > ? AND id <= ?", state.Cursor, state.Target).Order("id").Limit(limit).Find(&events).Error; err != nil {
			return err
		}
		if err := aggregatePods(tx, events, 1); err != nil {
			return err
		}
		cursor := state.Target
		if len(events) == limit {
			cursor = events[len(events)-1].ID
		}
		done = cursor >= state.Target
		return tx.Model(&state).Update("cursor", cursor).Error
	})
	return done, err
}
