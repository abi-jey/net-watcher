package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	sqlite3 "github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// SQLite stores times as text and compares them as text, so every stored
// time must use one zone. The driver formats a bound time.Time in the zone it
// carries: on a host in a local zone, time.Now() would be stored as
// "...+01:00" and sort an hour away from UTC rows. This driver binds every
// time as UTC, covering inserts, updates and query arguments alike.
const utcDriverName = "sqlite3-utc"

var registerUTCDriver sync.Once

type utcDriver struct{ sqlite3.SQLiteDriver }

func (d *utcDriver) Open(dsn string) (driver.Conn, error) {
	conn, err := d.SQLiteDriver.Open(dsn)
	if err != nil {
		return nil, err
	}
	return &utcConn{conn.(*sqlite3.SQLiteConn)}, nil
}

type utcConn struct{ *sqlite3.SQLiteConn }

// CheckNamedValue binds times as UTC and leaves every other value to the
// default conversion.
func (c *utcConn) CheckNamedValue(value *driver.NamedValue) error {
	switch v := value.Value.(type) {
	case time.Time:
		value.Value = v.UTC()
		return nil
	case *time.Time:
		if v != nil {
			value.Value = v.UTC()
			return nil
		}
	case sql.NullTime:
		if v.Valid {
			value.Value = v.Time.UTC()
		} else {
			value.Value = nil
		}
		return nil
	}
	return driver.ErrSkip
}

func dialector(dsn string) gorm.Dialector {
	registerUTCDriver.Do(func() { sql.Register(utcDriverName, &utcDriver{}) })
	return sqlite.New(sqlite.Config{DriverName: utcDriverName, DSN: dsn})
}

// storedModels are the tables AutoMigrate maintains.
func storedModels() []any {
	return []any{&NetworkEvent{}, &DNSResolution{}, &IngestedEvent{}, &IngestedResolution{}, &IngestCursor{}, &HourlyEvent{}, &HourlyHost{}, &AggregateState{}, &HourlyPod{}, &HourlyProcess{}, &CollectorStatus{}, &NodeAddress{}}
}

// Migration records one-time data migrations that have completed.
type Migration struct {
	Name        string `gorm:"primaryKey"`
	CompletedAt time.Time
}

const utcMigration = "stored-times-utc"

// Rows per statement of the UTC migration: short write transactions, so
// ingestion interleaves with it.
const utcMigrationChunk = 20000

// NormalizeStoredTimes rewrites times stored with a non-UTC offset (by
// versions before the UTC driver, on hosts in a local zone) to UTC, keeping
// their full precision. It runs once per database, in chunks, and resumes
// from the start after an interruption: converted rows no longer match.
func (db *DB) NormalizeStoredTimes(ctx context.Context) error {
	if err := db.AutoMigrate(&Migration{}); err != nil {
		return err
	}
	var done int64
	if err := db.Model(&Migration{}).Where("name = ?", utcMigration).Count(&done).Error; err != nil || done > 0 {
		return err
	}
	timeType := reflect.TypeOf(time.Time{})
	var converted int64
	for _, model := range storedModels() {
		statement := &gorm.Statement{DB: db.DB}
		if err := statement.Parse(model); err != nil {
			return err
		}
		var columns []string
		for _, field := range statement.Schema.Fields {
			if field.DBName != "" && field.FieldType == timeType {
				columns = append(columns, field.DBName)
			}
		}
		if len(columns) == 0 {
			continue
		}
		n, err := db.normalizeTable(ctx, statement.Schema.Table, columns)
		converted += n
		if err != nil {
			return fmt.Errorf("%s: %w", statement.Schema.Table, err)
		}
	}
	if converted > 0 {
		log.Info("Stored times converted to UTC", "rows", converted)
	}
	return db.Create(&Migration{Name: utcMigration, CompletedAt: time.Now()}).Error
}

// offsetTime matches a time stored by the driver with a zone offset.
const offsetTime = "'[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]*[+-][0-9][0-9]:[0-9][0-9]'"

func nonUTC(column string) string {
	return fmt.Sprintf("(typeof(%[1]s) = 'text' AND %[1]s GLOB %[2]s AND substr(%[1]s, -6) <> '+00:00')", column, offsetTime)
}

// toUTC converts "YYYY-MM-DD HH:MM:SS[.fraction]±HH:MM" in SQL: datetime()
// applies the offset to the seconds, and the fraction is carried over as is.
func toUTC(column string) string {
	return fmt.Sprintf("datetime(substr(%[1]s, 1, 19) || substr(%[1]s, -6)) || substr(%[1]s, 20, length(%[1]s) - 25) || '+00:00'", column)
}

func (db *DB) normalizeTable(ctx context.Context, table string, columns []string) (int64, error) {
	var last sql.NullInt64
	if err := db.Raw("SELECT max(rowid) FROM " + table).Scan(&last).Error; err != nil || !last.Valid {
		return 0, err
	}
	sets := make([]string, len(columns))
	matches := make([]string, len(columns))
	for i, column := range columns {
		column = `"` + column + `"`
		sets[i] = fmt.Sprintf("%s = CASE WHEN %s THEN %s ELSE %s END", column, nonUTC(column), toUTC(column), column)
		matches[i] = nonUTC(column)
	}
	update := fmt.Sprintf("UPDATE %s SET %s WHERE rowid > ? AND rowid <= ? AND (%s)", table, strings.Join(sets, ", "), strings.Join(matches, " OR "))
	var converted int64
	for from := int64(0); from < last.Int64; from += utcMigrationChunk {
		if err := ctx.Err(); err != nil {
			return converted, err
		}
		result := db.Exec(update, from, from+utcMigrationChunk)
		if result.Error != nil {
			return converted, result.Error
		}
		converted += result.RowsAffected
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond): // Let ingestion take the writer.
		}
	}
	return converted, nil
}
