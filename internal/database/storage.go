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
	if err := db.removeUnusedEvidence(time.Now(), false); err != nil {
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
	result := db.Where("id <= ?", cursor.EventID).Delete(&NetworkEvent{})
	if result.Error != nil {
		return 0, result.Error
	}
	removed := result.RowsAffected
	if err := db.removeUnusedEvidence(time.Now(), true); err != nil {
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

// removeUnusedEvidence keeps evidence referenced by retained events. Collectors
// also keep unexpired DNS answers for connections that have not occurred yet.
func (db *DB) removeUnusedEvidence(now time.Time, collector bool) error {
	cutoff := now.Add(-time.Minute)
	condition := "response_time < ?"
	if collector {
		condition += " AND expires_at < ?"
	}
	query := "SELECT id FROM dns_resolutions WHERE " + condition + ` AND id NOT IN (
		SELECT CAST(reference.value AS INTEGER) FROM network_events AS event,
		json_each(CASE WHEN json_valid(event.dns_resolution_ids) THEN event.dns_resolution_ids ELSE '[]' END) AS reference
	)`
	args := []interface{}{cutoff}
	if collector {
		args = append(args, now)
	}
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
