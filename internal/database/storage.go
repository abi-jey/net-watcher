package database

import (
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// StorageBytes reports the SQLite database and its write-ahead log on disk.
func (db *DB) StorageBytes() (int64, error) {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(db.path + suffix)
		if errors.Is(err, os.ErrNotExist) && suffix != "" {
			continue
		}
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

func (db *DB) checkpoint() error {
	var result struct {
		Busy int
	}
	if err := db.Raw("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&result).Error; err != nil {
		return err
	}
	if result.Busy != 0 {
		return fmt.Errorf("SQLite WAL checkpoint is busy")
	}
	return nil
}

// PruneToSize removes the oldest observations when the database exceeds maxBytes.
// It targets 80% of the limit to avoid vacuuming again at the next check.
func (db *DB) PruneToSize(maxBytes int64) (int64, error) {
	if maxBytes <= 0 {
		return 0, fmt.Errorf("maximum database size must be positive")
	}
	size, err := db.StorageBytes()
	if err != nil || size <= maxBytes {
		return 0, err
	}
	if err := db.checkpoint(); err != nil {
		return 0, err
	}
	size, err = db.StorageBytes()
	if err != nil || size <= maxBytes {
		return 0, err
	}
	var count int64
	if err := db.Model(&NetworkEvent{}).Count(&count).Error; err != nil {
		return 0, err
	}
	var removed int64
	if count > 0 {
		target := maxBytes - maxBytes/5
		toRemove := int64(math.Ceil(float64(count) * float64(size-target) / float64(size)))
		if toRemove < 1 {
			toRemove = 1
		}
		for toRemove > 0 {
			batch := min(toRemove, 10000)
			var deleted int64
			err := db.Transaction(func(tx *gorm.DB) error {
				var events []NetworkEvent
				if err := tx.Select(summaryColumns).Order("timestamp ASC, id ASC").Limit(int(batch)).Find(&events).Error; err != nil {
					return err
				}
				if err := ApplyEventSummaries(tx, events, -1); err != nil {
					return err
				}
				oldest := "SELECT id FROM network_events ORDER BY timestamp ASC, id ASC LIMIT ?"
				if err := tx.Exec("DELETE FROM ingested_events WHERE event_id IN ("+oldest+")", batch).Error; err != nil {
					return err
				}
				result := tx.Exec("DELETE FROM network_events WHERE id IN ("+oldest+")", batch)
				deleted = result.RowsAffected
				return result.Error
			})
			if err != nil {
				return removed, err
			}
			if deleted == 0 {
				break
			}
			removed += deleted
			toRemove -= deleted
		}
	}
	if err := db.removeUnusedEvidence(time.Now()); err != nil {
		return removed, err
	}
	if err := db.Exec("VACUUM").Error; err != nil {
		return removed, err
	}
	if err := db.checkpoint(); err != nil {
		return removed, err
	}
	size, err = db.StorageBytes()
	if err != nil {
		return removed, err
	}
	if size > maxBytes {
		return removed, fmt.Errorf("database still uses %d bytes (limit %d)", size, maxBytes)
	}
	return removed, nil
}

// ReclaimCollectorSpace drops acknowledged events and returns freed pages to disk.
// A collector retains only unacknowledged observations between maintenance runs.
func (db *DB) ReclaimCollectorSpace(endpoint string) (int64, error) {
	var cursor IngestCursor
	if err := db.Where("endpoint = ?", endpoint).First(&cursor).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, err
	}
	var summaryState AggregateState
	summaryErr := db.First(&summaryState, 1).Error
	if summaryErr != nil && !errors.Is(summaryErr, gorm.ErrRecordNotFound) {
		return 0, summaryErr
	}
	// Avoid loading event details on collector-only databases. A database that
	// previously served a standalone UI still needs consistent summary cleanup.
	var removed int64
	if errors.Is(summaryErr, gorm.ErrRecordNotFound) {
		result := db.Where("id <= ?", cursor.EventID).Delete(&NetworkEvent{})
		if result.Error != nil {
			return 0, result.Error
		}
		removed = result.RowsAffected
	}
	if summaryErr == nil {
		for {
			var count int64
			err := db.Transaction(func(tx *gorm.DB) error {
				var events []NetworkEvent
				if err := tx.Select(summaryColumns).Where("id <= ?", cursor.EventID).Order("id").Limit(1000).Find(&events).Error; err != nil {
					return err
				}
				if len(events) == 0 {
					return nil
				}
				if err := ApplyEventSummaries(tx, events, -1); err != nil {
					return err
				}
				result := tx.Where("id <= ?", events[len(events)-1].ID).Delete(&NetworkEvent{})
				count = result.RowsAffected
				return result.Error
			})
			if err != nil {
				return removed, err
			}
			removed += count
			if count == 0 {
				break
			}
		}
	}
	if err := db.removeUnusedEvidence(time.Now()); err != nil {
		return removed, err
	}
	if err := db.checkpoint(); err != nil {
		return removed, err
	}
	var pages, free int64
	if err := db.Raw("PRAGMA page_count").Scan(&pages).Error; err != nil {
		return removed, err
	}
	if err := db.Raw("PRAGMA freelist_count").Scan(&free).Error; err != nil {
		return removed, err
	}
	size, err := db.StorageBytes()
	if err != nil {
		return removed, err
	}
	if size >= 32<<20 && pages > 0 && free > 0 && free >= pages/4 {
		if err := db.Exec("VACUUM").Error; err != nil {
			return removed, err
		}
		return removed, db.checkpoint()
	}
	return removed, nil
}

// RecordAcknowledgment persists the cursor without running cleanup per batch.
func (db *DB) RecordAcknowledgment(endpoint string, eventID uint) error {
	cursor := IngestCursor{Endpoint: endpoint, EventID: eventID}
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "endpoint"}},
		DoUpdates: clause.AssignmentColumns([]string{"event_id"}),
	}).Create(&cursor).Error
}

// EvidenceGrace is how long expired DNS evidence is kept after expiry. Capture
// buffers events in memory before writing them, so a connection can reference
// an answer that is about to expire; deleting it immediately would leave the
// event pointing at evidence that no longer exists.
const EvidenceGrace = 15 * time.Minute

// removeUnusedEvidence deletes DNS evidence that has expired for longer than
// EvidenceGrace and is not referenced by any retained event. Unexpired evidence
// is always kept: capture may still attach it to new connections.
func (db *DB) removeUnusedEvidence(now time.Time) error {
	cutoff := now.Add(-EvidenceGrace)
	condition := "response_time < ? AND expires_at < ?"
	query := "SELECT id FROM dns_resolutions WHERE " + condition + ` AND id NOT IN (
		SELECT CAST(reference.value AS INTEGER) FROM network_events AS event,
		json_each(CASE WHEN json_valid(event.dns_resolution_ids) THEN event.dns_resolution_ids ELSE '[]' END) AS reference
	)`
	args := []interface{}{cutoff, cutoff}
	var candidates bool
	if err := db.Raw("SELECT EXISTS(SELECT 1 FROM dns_resolutions WHERE "+condition+" LIMIT 1)", args...).Scan(&candidates).Error; err != nil || !candidates {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("DELETE FROM ingested_resolutions WHERE resolution_id IN ("+query+")", args...).Error; err != nil {
			return err
		}
		return tx.Exec("DELETE FROM dns_resolutions WHERE id IN ("+query+")", args...).Error
	})
}

// EnforceCollectorLimit discards the oldest unforwarded events when a collector
// database exceeds maxBytes, for example while the ingester is unreachable.
// Discarded events are replaced by a single GAP event that is forwarded like any
// other observation, so the loss is visible centrally instead of silent.
func (db *DB) EnforceCollectorLimit(endpoint string, maxBytes int64) (int64, error) {
	if maxBytes <= 0 {
		return 0, fmt.Errorf("maximum collector size must be positive")
	}
	size, err := db.StorageBytes()
	if err != nil || size <= maxBytes {
		return 0, err
	}
	if err := db.checkpoint(); err != nil {
		return 0, err
	}
	if size, err = db.StorageBytes(); err != nil || size <= maxBytes {
		return 0, err
	}
	var cursor IngestCursor
	if err := db.Where("endpoint = ?", endpoint).First(&cursor).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, err
	}
	var count int64
	if err := db.Model(&NetworkEvent{}).Where("id > ?", cursor.EventID).Count(&count).Error; err != nil {
		return 0, err
	}
	var removed int64
	var first, last time.Time
	if count > 0 {
		target := maxBytes - maxBytes/5
		toRemove := max(int64(math.Ceil(float64(count)*float64(size-target)/float64(size))), 1)
		for toRemove > 0 {
			batch := min(toRemove, 10000)
			var events []NetworkEvent
			err := db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Select(summaryColumns).Where("id > ?", cursor.EventID).Order("id ASC").Limit(int(batch)).Find(&events).Error; err != nil {
					return err
				}
				if len(events) == 0 {
					return nil
				}
				if err := ApplyEventSummaries(tx, events, -1); err != nil {
					return err
				}
				return tx.Where("id > ? AND id <= ?", cursor.EventID, events[len(events)-1].ID).Delete(&NetworkEvent{}).Error
			})
			if err != nil {
				return removed, err
			}
			if len(events) == 0 {
				break
			}
			for _, event := range events {
				if first.IsZero() || event.Timestamp.Before(first) {
					first = event.Timestamp
				}
				if event.Timestamp.After(last) {
					last = event.Timestamp
				}
			}
			removed += int64(len(events))
			toRemove -= int64(len(events))
		}
	}
	if removed > 0 {
		if err := db.InsertBatch([]NetworkEvent{NewGapEvent(GapCollectorLimit, removed, first, last, "")}); err != nil {
			return removed, err
		}
	}
	if err := db.removeUnusedEvidence(time.Now()); err != nil {
		return removed, err
	}
	if err := db.Exec("VACUUM").Error; err != nil {
		return removed, err
	}
	return removed, db.checkpoint()
}
