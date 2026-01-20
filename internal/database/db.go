package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/charmbracelet/log"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB wraps the gorm database
type DB struct {
	*gorm.DB
}

// New creates a new database connection
func New(dbPath string) (*DB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.Exec("PRAGMA journal_mode=WAL")
	sqlDB.Exec("PRAGMA synchronous=NORMAL")
	sqlDB.Exec("PRAGMA cache_size=2000")

	if err := db.AutoMigrate(&NetworkEvent{}); err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// InsertEvent inserts a single network event
func (db *DB) InsertEvent(event *NetworkEvent) error {
	return db.Create(event).Error
}

// InsertBatch inserts multiple events in batches
func (db *DB) InsertBatch(events []NetworkEvent) error {
	if len(events) == 0 {
		return nil
	}
	return db.CreateInBatches(events, 100).Error
}

// CompactStats holds statistics about compaction operations
type CompactStats struct {
	TCPPairsCompacted   int64
	UDPPairsCompacted   int64
	DNSPairsCompacted   int64
	DuplicatesRemoved   int64
	HourlySummaries     int64
	OrphanedEndsRemoved int64
	TotalEventsRemoved  int64
	TotalEventsCreated  int64
	TotalBytesInDB      int64
	TCPBytes            int64
	UDPBytes            int64
}

// Compact performs database compaction with various strategies
func (db *DB) Compact(olderThan time.Time, dedupeWindow time.Duration) (*CompactStats, error) {
	stats := &CompactStats{}

	// 1. Compact TCP: Merge TCP_START + TCP_END pairs
	if err := db.compactTCP(olderThan, stats); err != nil {
		return stats, fmt.Errorf("TCP compaction failed: %w", err)
	}

	// 2. Compact UDP: Merge UDP_START + UDP_END pairs
	if err := db.compactUDP(olderThan, stats); err != nil {
		return stats, fmt.Errorf("UDP compaction failed: %w", err)
	}

	// 3. Compact DNS: Merge QUERY + RESPONSE pairs
	if err := db.compactDNS(olderThan, stats); err != nil {
		return stats, fmt.Errorf("DNS compaction failed: %w", err)
	}

	// 4. Remove duplicate DNS queries within window
	if dedupeWindow > 0 {
		if err := db.deduplicateDNS(olderThan, dedupeWindow, stats); err != nil {
			return stats, fmt.Errorf("DNS deduplication failed: %w", err)
		}
	}

	// 5. Remove orphaned END events (no matching START)
	if err := db.removeOrphanedEnds(olderThan, stats); err != nil {
		return stats, fmt.Errorf("orphan removal failed: %w", err)
	}

	// 6. Calculate data transfer statistics
	db.calculateTransferStats(stats)

	// 7. Vacuum the database
	db.Exec("VACUUM")

	return stats, nil
}

// compactTCP merges TCP_START and TCP_END pairs into single TCP records
func (db *DB) compactTCP(olderThan time.Time, stats *CompactStats) error {
	// Find TCP_START events that have matching TCP_END
	var startEvents []NetworkEvent
	db.Where("event_type = ? AND timestamp < ? AND (compacted = ? OR compacted IS NULL)", EventTCPStart, olderThan, false).
		Find(&startEvents)

	total := len(startEvents)
	log.Info("Processing TCP events", "total", total)

	for i, start := range startEvents {
		if (i+1)%1000 == 0 || i+1 == total {
			log.Info("TCP progress", "processed", i+1, "total", total, "pairs_found", stats.TCPPairsCompacted)
		}
		// Find matching END event (same src/dst within reasonable time)
		var endEvent NetworkEvent
		result := db.Where(
			"event_type IN (?, ?) AND src_ip = ? AND src_port = ? AND dst_ip = ? AND dst_port = ? AND timestamp > ? AND timestamp < ?",
			EventTCPEnd, EventTimeout,
			start.SrcIP, start.SrcPort, start.DstIP, start.DstPort,
			start.Timestamp, start.Timestamp.Add(24*time.Hour),
		).Order("timestamp ASC").First(&endEvent)

		if result.Error == nil {
			// Create compacted record
			compacted := NetworkEvent{
				Timestamp:   start.Timestamp,
				EndTime:     endEvent.Timestamp,
				EventType:   EventTCP,
				Interface:   start.Interface,
				IPVersion:   start.IPVersion,
				SrcIP:       start.SrcIP,
				SrcPort:     start.SrcPort,
				DstIP:       start.DstIP,
				DstPort:     start.DstPort,
				Hostname:    start.Hostname,
				DNSAge:      start.DNSAge,
				Duration:    endEvent.Duration,
				ByteCount:   endEvent.ByteCount,
				Reason:      endEvent.Reason,
				Compacted:   true,
				OriginalIDs: fmt.Sprintf("%d,%d", start.ID, endEvent.ID),
			}

			if err := db.Create(&compacted).Error; err != nil {
				continue
			}

			// Delete original events
			db.Delete(&start)
			db.Delete(&endEvent)
			stats.TCPPairsCompacted++
			stats.TotalEventsRemoved += 2
			stats.TotalEventsCreated++
		}
	}

	return nil
}

// compactUDP merges UDP_START and UDP_END pairs into single UDP records
func (db *DB) compactUDP(olderThan time.Time, stats *CompactStats) error {
	var startEvents []NetworkEvent
	db.Where("event_type = ? AND timestamp < ? AND (compacted = ? OR compacted IS NULL)", EventUDPStart, olderThan, false).
		Find(&startEvents)

	total := len(startEvents)
	log.Info("Processing UDP events", "total", total)

	for i, start := range startEvents {
		if (i+1)%1000 == 0 || i+1 == total {
			log.Info("UDP progress", "processed", i+1, "total", total, "pairs_found", stats.UDPPairsCompacted)
		}
		var endEvent NetworkEvent
		result := db.Where(
			"event_type = ? AND src_ip = ? AND src_port = ? AND dst_ip = ? AND dst_port = ? AND timestamp > ? AND timestamp < ?",
			EventUDPEnd,
			start.SrcIP, start.SrcPort, start.DstIP, start.DstPort,
			start.Timestamp, start.Timestamp.Add(24*time.Hour),
		).Order("timestamp ASC").First(&endEvent)

		if result.Error == nil {
			compacted := NetworkEvent{
				Timestamp:   start.Timestamp,
				EndTime:     endEvent.Timestamp,
				EventType:   EventUDP,
				Interface:   start.Interface,
				IPVersion:   start.IPVersion,
				SrcIP:       start.SrcIP,
				SrcPort:     start.SrcPort,
				DstIP:       start.DstIP,
				DstPort:     start.DstPort,
				Protocol:    start.Protocol,
				Duration:    endEvent.Duration,
				ByteCount:   endEvent.ByteCount,
				Compacted:   true,
				OriginalIDs: fmt.Sprintf("%d,%d", start.ID, endEvent.ID),
			}

			if err := db.Create(&compacted).Error; err != nil {
				continue
			}

			db.Delete(&start)
			db.Delete(&endEvent)
			stats.UDPPairsCompacted++
			stats.TotalEventsRemoved += 2
			stats.TotalEventsCreated++
		}
	}

	return nil
}

// compactDNS merges DNS QUERY and RESPONSE pairs
func (db *DB) compactDNS(olderThan time.Time, stats *CompactStats) error {
	var queryEvents []NetworkEvent
	db.Where("event_type = ? AND dns_type = ? AND timestamp < ? AND (compacted = ? OR compacted IS NULL)",
		EventDNS, "QUERY", olderThan, false).
		Find(&queryEvents)

	total := len(queryEvents)
	log.Info("Processing DNS events", "total", total)

	for i, query := range queryEvents {
		if (i+1)%1000 == 0 || i+1 == total {
			log.Info("DNS progress", "processed", i+1, "total", total, "pairs_found", stats.DNSPairsCompacted)
		}
		var response NetworkEvent
		result := db.Where(
			"event_type = ? AND dns_type = ? AND dns_query = ? AND timestamp > ? AND timestamp < ?",
			EventDNS, "RESPONSE", query.DNSQuery,
			query.Timestamp, query.Timestamp.Add(5*time.Second),
		).Order("timestamp ASC").First(&response)

		if result.Error == nil {
			compacted := NetworkEvent{
				Timestamp:   query.Timestamp,
				EndTime:     response.Timestamp,
				EventType:   EventDNS,
				Interface:   query.Interface,
				IPVersion:   query.IPVersion,
				SrcIP:       query.SrcIP,
				SrcPort:     query.SrcPort,
				DstIP:       query.DstIP,
				DstPort:     query.DstPort,
				DNSType:     "COMPLETE",
				DNSQuery:    query.DNSQuery,
				DNSAnswers:  response.DNSAnswers,
				DNSCNAMEs:   response.DNSCNAMEs,
				Duration:    response.Timestamp.Sub(query.Timestamp).Milliseconds(),
				Compacted:   true,
				OriginalIDs: fmt.Sprintf("%d,%d", query.ID, response.ID),
			}

			if err := db.Create(&compacted).Error; err != nil {
				continue
			}

			db.Delete(&query)
			db.Delete(&response)
			stats.DNSPairsCompacted++
			stats.TotalEventsRemoved += 2
			stats.TotalEventsCreated++
		}
	}

	return nil
}

// deduplicateDNS removes duplicate DNS queries within a time window
func (db *DB) deduplicateDNS(olderThan time.Time, window time.Duration, stats *CompactStats) error {
	var events []NetworkEvent
	db.Where("event_type = ? AND timestamp < ?", EventDNS, olderThan).
		Order("dns_query, timestamp").
		Find(&events)

	var toDelete []uint
	lastQuery := ""
	var lastTime time.Time

	for _, e := range events {
		if e.DNSQuery == lastQuery && e.Timestamp.Sub(lastTime) < window {
			toDelete = append(toDelete, e.ID)
		} else {
			lastQuery = e.DNSQuery
			lastTime = e.Timestamp
		}
	}

	if len(toDelete) > 0 {
		db.Where("id IN ?", toDelete).Delete(&NetworkEvent{})
		stats.DuplicatesRemoved = int64(len(toDelete))
		stats.TotalEventsRemoved += int64(len(toDelete))
	}

	return nil
}

// removeOrphanedEnds removes END events without matching START
func (db *DB) removeOrphanedEnds(olderThan time.Time, stats *CompactStats) error {
	// Find TCP_END without TCP_START
	result := db.Exec(`
		DELETE FROM network_events 
		WHERE event_type = 'TCP_END' 
		AND timestamp < ?
		AND NOT EXISTS (
			SELECT 1 FROM network_events AS starts 
			WHERE starts.event_type = 'TCP_START'
			AND starts.src_ip = network_events.src_ip
			AND starts.src_port = network_events.src_port
			AND starts.dst_ip = network_events.dst_ip
			AND starts.dst_port = network_events.dst_port
			AND starts.timestamp < network_events.timestamp
		)
	`, olderThan)
	stats.OrphanedEndsRemoved += result.RowsAffected
	stats.TotalEventsRemoved += result.RowsAffected

	// Find UDP_END without UDP_START
	result = db.Exec(`
		DELETE FROM network_events 
		WHERE event_type = 'UDP_END' 
		AND timestamp < ?
		AND NOT EXISTS (
			SELECT 1 FROM network_events AS starts 
			WHERE starts.event_type = 'UDP_START'
			AND starts.src_ip = network_events.src_ip
			AND starts.src_port = network_events.src_port
			AND starts.dst_ip = network_events.dst_ip
			AND starts.dst_port = network_events.dst_port
			AND starts.timestamp < network_events.timestamp
		)
	`, olderThan)
	stats.OrphanedEndsRemoved += result.RowsAffected
	stats.TotalEventsRemoved += result.RowsAffected

	return nil
}

// CreateHourlySummary creates hourly aggregated summaries for old data
func (db *DB) CreateHourlySummary(olderThan time.Time) (int64, error) {
	var count int64

	// Get distinct hours with events
	var hours []struct {
		Hour      string
		Interface string
		IPVersion uint8
	}
	db.Model(&NetworkEvent{}).
		Select("strftime('%Y-%m-%d %H:00:00', timestamp) as hour, interface, ip_version").
		Where("timestamp < ? AND event_type NOT IN (?, ?)", olderThan, EventHourlySummary, EventTCP).
		Group("hour, interface, ip_version").
		Scan(&hours)

	for _, h := range hours {
		hourTime, _ := time.Parse("2006-01-02 15:04:05", h.Hour)

		// Get counts per event type
		var tcpCount, udpCount, dnsCount, tlsCount, icmpCount int64
		db.Model(&NetworkEvent{}).
			Where("strftime('%Y-%m-%d %H:00:00', timestamp) = ? AND interface = ? AND ip_version = ? AND event_type LIKE 'TCP%'",
				h.Hour, h.Interface, h.IPVersion).
			Count(&tcpCount)
		db.Model(&NetworkEvent{}).
			Where("strftime('%Y-%m-%d %H:00:00', timestamp) = ? AND interface = ? AND ip_version = ? AND event_type LIKE 'UDP%'",
				h.Hour, h.Interface, h.IPVersion).
			Count(&udpCount)
		db.Model(&NetworkEvent{}).
			Where("strftime('%Y-%m-%d %H:00:00', timestamp) = ? AND interface = ? AND ip_version = ? AND event_type = ?",
				h.Hour, h.Interface, h.IPVersion, EventDNS).
			Count(&dnsCount)
		db.Model(&NetworkEvent{}).
			Where("strftime('%Y-%m-%d %H:00:00', timestamp) = ? AND interface = ? AND ip_version = ? AND event_type = ?",
				h.Hour, h.Interface, h.IPVersion, EventTLSSNI).
			Count(&tlsCount)
		db.Model(&NetworkEvent{}).
			Where("strftime('%Y-%m-%d %H:00:00', timestamp) = ? AND interface = ? AND ip_version = ? AND event_type = ?",
				h.Hour, h.Interface, h.IPVersion, EventICMP).
			Count(&icmpCount)

		totalCount := tcpCount + udpCount + dnsCount + tlsCount + icmpCount
		if totalCount == 0 {
			continue
		}

		// Create summary record
		summary := NetworkEvent{
			Timestamp:  hourTime,
			EventType:  EventHourlySummary,
			Interface:  h.Interface,
			IPVersion:  h.IPVersion,
			EventCount: totalCount,
			Protocol:   fmt.Sprintf("TCP:%d,UDP:%d,DNS:%d,TLS:%d,ICMP:%d", tcpCount, udpCount, dnsCount, tlsCount, icmpCount),
			Compacted:  true,
		}

		if err := db.Create(&summary).Error; err != nil {
			continue
		}

		// Delete original events for this hour
		db.Where("strftime('%Y-%m-%d %H:00:00', timestamp) = ? AND interface = ? AND ip_version = ? AND event_type != ?",
			h.Hour, h.Interface, h.IPVersion, EventHourlySummary).
			Delete(&NetworkEvent{})

		count++
	}

	return count, nil
}

// calculateTransferStats calculates total data transfer statistics in the database
func (db *DB) calculateTransferStats(stats *CompactStats) {
	// Total bytes across all events
	var totalBytes sql.NullInt64
	db.Model(&NetworkEvent{}).Select("COALESCE(SUM(byte_count), 0)").Scan(&totalBytes)
	stats.TotalBytesInDB = totalBytes.Int64

	// TCP bytes (includes TCP, TCP_START, TCP_END)
	var tcpBytes sql.NullInt64
	db.Model(&NetworkEvent{}).
		Select("COALESCE(SUM(byte_count), 0)").
		Where("event_type IN ?", []string{string(EventTCP), string(EventTCPStart), string(EventTCPEnd)}).
		Scan(&tcpBytes)
	stats.TCPBytes = tcpBytes.Int64

	// UDP bytes (includes UDP, UDP_START, UDP_END)
	var udpBytes sql.NullInt64
	db.Model(&NetworkEvent{}).
		Select("COALESCE(SUM(byte_count), 0)").
		Where("event_type IN ?", []string{string(EventUDP), string(EventUDPStart), string(EventUDPEnd)}).
		Scan(&udpBytes)
	stats.UDPBytes = udpBytes.Int64

	log.Info("Data transfer statistics",
		"total", FormatBytes(stats.TotalBytesInDB),
		"tcp", FormatBytes(stats.TCPBytes),
		"udp", FormatBytes(stats.UDPBytes))
}

// FormatBytes converts bytes to human-readable format
func FormatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
