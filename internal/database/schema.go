package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

// Database represents the SQLite database connection
type Database struct {
	db *sql.DB
}

// NewDatabase creates a new database connection with proper configuration
func NewDatabase(dbPath string) (*Database, error) {
	// Open database with connection pooling
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	database := &Database{db: db}

	// Initialize schema
	if err := database.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return database, nil
}

// initSchema creates the database schema with proper indexes
func (d *Database) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS dns_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		source_ip TEXT NOT NULL,
		dest_ip TEXT NOT NULL,
		domain_name TEXT NOT NULL,
		record_type TEXT NOT NULL,
		interface TEXT NOT NULL,
		packet_size INTEGER DEFAULT 0
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_domain ON dns_events(domain_name);
	CREATE INDEX IF NOT EXISTS idx_source_ip ON dns_events(source_ip);
	CREATE INDEX IF NOT EXISTS idx_dest_ip ON dns_events(dest_ip);
	CREATE INDEX IF NOT EXISTS idx_interface ON dns_events(interface);
	CREATE INDEX IF NOT EXISTS idx_record_type ON dns_events(record_type);

	-- Composite index for common queries
	CREATE INDEX IF NOT EXISTS idx_timestamp_domain ON dns_events(timestamp, domain_name);
	`

	if _, err := d.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Configure SQLite for performance and concurrency
	configs := []string{
		"PRAGMA journal_mode=WAL",    // Enable WAL mode for concurrent access
		"PRAGMA synchronous=NORMAL",  // Balance between safety and performance
		"PRAGMA cache_size=2000",     // Set cache size to ~2MB
		"PRAGMA temp_store=MEMORY",   // Store temporary tables in memory
		"PRAGMA mmap_size=268435456", // Enable memory-mapped I/O (256MB)
		"PRAGMA foreign_keys=ON",     // Enable foreign key constraints
		"PRAGMA query_only=OFF",      // Allow writes
	}

	for _, config := range configs {
		if _, err := d.db.Exec(config); err != nil {
			log.Printf("Warning: failed to set %s: %v", config, err)
		}
	}

	return nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// InsertDNSEvent inserts a DNS event into the database
func (d *Database) InsertDNSEvent(event DNSEvent) error {
	query := `
	INSERT INTO dns_events (timestamp, source_ip, dest_ip, domain_name, record_type, interface, packet_size)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.Exec(query,
		event.Timestamp,
		event.SourceIP,
		event.DestIP,
		event.DomainName,
		event.RecordType,
		event.Interface,
		event.PacketSize,
	)

	return err
}

// InsertDNSEventBatch inserts multiple DNS events in a single transaction
func (d *Database) InsertDNSEventBatch(events []DNSEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
	INSERT INTO dns_events (timestamp, source_ip, dest_ip, domain_name, record_type, interface, packet_size)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, event := range events {
		if _, err := stmt.Exec(
			event.Timestamp,
			event.SourceIP,
			event.DestIP,
			event.DomainName,
			event.RecordType,
			event.Interface,
			event.PacketSize,
		); err != nil {
			return fmt.Errorf("failed to insert event: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetDNSEvents retrieves DNS events with optional filtering
func (d *Database) GetDNSEvents(filter EventFilter) ([]DNSEvent, error) {
	query := `
	SELECT id, timestamp, source_ip, dest_ip, domain_name, record_type, interface, packet_size
	FROM dns_events
	WHERE 1=1
	`
	args := []interface{}{}

	// Build WHERE clause
	if filter.Since != "" {
		query += " AND timestamp >= ?"
		args = append(args, filter.Since)
	}

	if filter.IP != "" {
		query += " AND (source_ip = ? OR dest_ip = ?)"
		args = append(args, filter.IP, filter.IP)
	}

	if filter.Domain != "" {
		query += " AND domain_name LIKE ?"
		args = append(args, "%"+filter.Domain+"%")
	}

	if filter.Interface != "" {
		query += " AND interface = ?"
		args = append(args, filter.Interface)
	}

	// Add ordering and limit
	query += " ORDER BY timestamp DESC"
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []DNSEvent
	for rows.Next() {
		var event DNSEvent
		if err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.SourceIP,
			&event.DestIP,
			&event.DomainName,
			&event.RecordType,
			&event.Interface,
			&event.PacketSize,
		); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return events, nil
}

// CleanupOldEvents removes events older than the specified retention period
func (d *Database) CleanupOldEvents(retentionDays int) error {
	if retentionDays <= 0 {
		return fmt.Errorf("retention days must be positive")
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	query := "DELETE FROM dns_events WHERE timestamp < ?"

	result, err := d.db.Exec(query, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup old events: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Cleaned up %d old DNS events", rowsAffected)
	}

	// Optimize database after cleanup
	if _, err := d.db.Exec("VACUUM"); err != nil {
		log.Printf("Warning: failed to vacuum database: %v", err)
	}

	return nil
}

// GetStats returns database statistics
func (d *Database) GetStats() (DatabaseStats, error) {
	stats := DatabaseStats{}

	// Total events
	if err := d.db.QueryRow("SELECT COUNT(*) FROM dns_events").Scan(&stats.TotalEvents); err != nil {
		return stats, fmt.Errorf("failed to count total events: %w", err)
	}

	// Oldest event
	if err := d.db.QueryRow("SELECT MIN(timestamp) FROM dns_events").Scan(&stats.OldestEvent); err != nil {
		if err != sql.ErrNoRows {
			return stats, fmt.Errorf("failed to get oldest event: %w", err)
		}
	}

	// Newest event
	if err := d.db.QueryRow("SELECT MAX(timestamp) FROM dns_events").Scan(&stats.NewestEvent); err != nil {
		if err != sql.ErrNoRows {
			return stats, fmt.Errorf("failed to get newest event: %w", err)
		}
	}

	// Database size
	if err := d.db.QueryRow("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()").Scan(&stats.DatabaseSize); err != nil {
		// Fallback if pragma query fails
		stats.DatabaseSize = 0
	}

	return stats, nil
}
