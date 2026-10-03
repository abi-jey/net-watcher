package database

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/charmbracelet/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// HourlyEvent contains totals for one observed event type in one UTC hour.
type HourlyEvent struct {
	Hour       int64     `gorm:"primaryKey;autoIncrement:false"`
	EventType  EventType `gorm:"primaryKey"`
	EventCount int64
	ByteCount  int64
}

// HourlyHost keeps independent source, destination, and hostname totals. Ports
// and source/destination pairs are deliberately excluded to bound cardinality.
type HourlyHost struct {
	Hour       int64  `gorm:"primaryKey;autoIncrement:false;index:idx_hourly_host_kind_hour,priority:2"`
	Kind       string `gorm:"primaryKey;index:idx_hourly_host_kind_hour,priority:1"`
	Host       string `gorm:"primaryKey"`
	EventCount int64
	ByteCount  int64
}

// AggregateState separates historical rows awaiting backfill from live inserts.
// A transaction advances Cursor only after all its summary updates commit.
type AggregateState struct {
	ID     uint `gorm:"primaryKey;autoIncrement:false"`
	Cursor uint
	Target uint
	Paused bool
}

const summaryColumns = "id, timestamp, event_type, src_ip, dst_ip, hostname, byte_count"

// EnableSummaries snapshots the historical high-water mark without scanning or
// rewriting events. Collector-only databases do not enable summary maintenance.
func (db *DB) EnableSummaries(ctx context.Context) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var state AggregateState
		err := tx.First(&state, 1).Error
		if err == nil && !state.Paused {
			return nil
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return resetSummaries(tx)
	})
}

func resetSummaries(tx *gorm.DB) error {
	for _, table := range []string{"hourly_events", "hourly_hosts"} {
		if err := tx.Exec("DELETE FROM " + table).Error; err != nil {
			return err
		}
	}
	var target uint
	if err := tx.Raw("SELECT COALESCE(MAX(id), 0) FROM network_events").Scan(&target).Error; err != nil {
		return err
	}
	return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&AggregateState{ID: 1, Target: target}).Error
}

// SummariesReady reports whether all retained historical rows have been covered.
// Call it inside the same read transaction as queries using the summaries.
func SummariesReady(tx *gorm.DB) (bool, error) {
	var state AggregateState
	err := tx.First(&state, 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return err == nil && !state.Paused && state.Cursor >= state.Target, err
}

// ApplyEventSummaries updates only already-covered rows, within the transaction
// inserting or removing them. delta must be 1 for insertion or -1 for removal.
func ApplyEventSummaries(tx *gorm.DB, events []NetworkEvent, delta int64) error {
	if len(events) == 0 {
		return nil
	}
	var state AggregateState
	err := tx.First(&state, 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) || state.Paused {
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
	return aggregateEvents(tx, covered, delta)
}

func aggregateEvents(tx *gorm.DB, events []NetworkEvent, delta int64) error {
	if delta != 1 && delta != -1 {
		return fmt.Errorf("invalid summary delta %d", delta)
	}
	type eventKey struct {
		hour int64
		kind EventType
	}
	type hostKey struct {
		hour       int64
		kind, host string
	}
	counts := make(map[eventKey]*HourlyEvent)
	hosts := make(map[hostKey]*HourlyHost)
	hours := make(map[int64]bool)
	for _, event := range events {
		hour := event.Timestamp.UTC().Truncate(time.Hour).Unix()
		hours[hour] = true
		key := eventKey{hour, event.EventType}
		if counts[key] == nil {
			counts[key] = &HourlyEvent{Hour: hour, EventType: event.EventType}
		}
		counts[key].EventCount += delta
		counts[key].ByteCount += delta * event.ByteCount
		for _, dimension := range []struct{ kind, host string }{{"srcIP", event.SrcIP}, {"dstIP", event.DstIP}, {"hostname", event.Hostname}} {
			if dimension.host == "" {
				continue
			}
			key := hostKey{hour, dimension.kind, dimension.host}
			if hosts[key] == nil {
				hosts[key] = &HourlyHost{Hour: hour, Kind: dimension.kind, Host: dimension.host}
			}
			hosts[key].EventCount += delta
			hosts[key].ByteCount += delta * event.ByteCount
		}
	}
	eventRows := make([]HourlyEvent, 0, len(counts))
	for _, row := range counts {
		eventRows = append(eventRows, *row)
	}
	hostRows := make([]HourlyHost, 0, len(hosts))
	for _, row := range hosts {
		hostRows = append(hostRows, *row)
	}
	// Sorted keys improve locality in the summary indexes and deterministic tests.
	sort.Slice(eventRows, func(i, j int) bool {
		if eventRows[i].Hour != eventRows[j].Hour {
			return eventRows[i].Hour < eventRows[j].Hour
		}
		return eventRows[i].EventType < eventRows[j].EventType
	})
	sort.Slice(hostRows, func(i, j int) bool {
		a, b := hostRows[i], hostRows[j]
		if a.Hour != b.Hour {
			return a.Hour < b.Hour
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Host < b.Host
	})
	updates := clause.Assignments(map[string]interface{}{
		"event_count": gorm.Expr("event_count + excluded.event_count"),
		"byte_count":  gorm.Expr("byte_count + excluded.byte_count"),
	})
	tx = tx.Session(&gorm.Session{SkipDefaultTransaction: true})
	if len(eventRows) > 0 {
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "hour"}, {Name: "event_type"}}, DoUpdates: updates}).CreateInBatches(&eventRows, 100).Error; err != nil {
			return err
		}
	}
	if len(hostRows) > 0 {
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "hour"}, {Name: "kind"}, {Name: "host"}}, DoUpdates: updates}).CreateInBatches(&hostRows, 100).Error; err != nil {
			return err
		}
	}
	if delta < 0 {
		for hour := range hours {
			for _, model := range []interface{}{&HourlyEvent{}, &HourlyHost{}} {
				if err := tx.Where("hour = ? AND event_count = 0", hour).Delete(model).Error; err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// BackfillSummaries processes at most limit historical events in one transaction.
// New ingestion, retention, and the cursor share the single SQLite writer, so
// retrying a chunk or pruning rows during backfill cannot double-count them.
func (db *DB) BackfillSummaries(ctx context.Context, limit int) (bool, error) {
	if limit < 1 || limit > 10000 {
		return false, fmt.Errorf("summary batch size must be between 1 and 10000")
	}
	var done bool
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var state AggregateState
		if err := tx.First(&state, 1).Error; err != nil {
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
		if err := aggregateEvents(tx, events, 1); err != nil {
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

// RunSummaryBackfill runs one low-duty-cycle worker. Each chunk yields for at
// least nine times its runtime (and 100ms), prioritizing capture and ingestion.
func (db *DB) RunSummaryBackfill(ctx context.Context) {
	lastReport := time.Time{}
	wasDone := false
	for ctx.Err() == nil {
		start := time.Now()
		done, err := db.BackfillSummaries(ctx, 1000)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Warn("Summary backfill paused; will retry", "error", err)
		} else if time.Since(lastReport) >= time.Minute || done != wasDone {
			var state AggregateState
			if db.WithContext(ctx).First(&state, 1).Error == nil {
				log.Info("Hourly summary backfill", "cursor", state.Cursor, "target", state.Target, "complete", done)
			}
			lastReport = time.Now()
		}
		wasDone = done
		pause := max(100*time.Millisecond, time.Since(start)*9)
		if done || err != nil {
			pause = time.Minute
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
