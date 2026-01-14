package cli

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abja/net-watcher/internal/capture"
	"github.com/abja/net-watcher/internal/database"
)

// Serve starts the DNS monitoring daemon
func Serve(iface, dbPath string, retentionDays, batchSize int, debug bool) error {
	// Validate interface
	if err := capture.ValidateInterface(iface); err != nil {
		return fmt.Errorf("interface validation failed: %w", err)
	}

	// Initialize database
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}
	defer db.Close()

	// Initialize DNS sniffer
	sniffer, err := capture.NewDNSSniffer(iface, batchSize, debug)
	if err != nil {
		return fmt.Errorf("failed to create DNS sniffer: %w", err)
	}
	defer sniffer.Stop()

	// Start packet capture
	if err := sniffer.Start(); err != nil {
		return fmt.Errorf("failed to start packet capture: %w", err)
	}

	log.Printf("Net-watcher started on interface %s", iface)
	log.Printf("Database: %s", dbPath)
	log.Printf("Data retention: %d days", retentionDays)
	log.Printf("Batch size: %d", batchSize)

	// Start cleanup routine
	cleanupTicker := time.NewTicker(time.Hour)
	defer cleanupTicker.Stop()

	// Start batch insert routine
	eventChan := sniffer.GetEventChannel()
	batchTicker := time.NewTicker(time.Second)
	defer batchTicker.Stop()

	var batch []database.DNSEvent

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Main event loop
	for {
		select {
		case event, ok := <-eventChan:
			if !ok {
				// Event channel closed, insert remaining batch and exit
				if len(batch) > 0 {
					if err := db.InsertDNSEventBatch(batch); err != nil && debug {
						log.Printf("Failed to insert final batch: %v", err)
					}
				}
				log.Println("Event channel closed, shutting down...")
				return nil
			}

			batch = append(batch, event)

			// Insert batch if it reaches the configured size
			if len(batch) >= batchSize {
				if err := db.InsertDNSEventBatch(batch); err != nil {
					log.Printf("Failed to insert batch: %v", err)
				} else if debug {
					log.Printf("Inserted batch of %d events", len(batch))
				}
				batch = batch[:0] // Clear batch
			}

		case <-batchTicker.C:
			// Insert any remaining events every second
			if len(batch) > 0 {
				if err := db.InsertDNSEventBatch(batch); err != nil {
					log.Printf("Failed to insert batch: %v", err)
				} else if debug {
					log.Printf("Inserted batch of %d events", len(batch))
				}
				batch = batch[:0] // Clear batch
			}

		case <-cleanupTicker.C:
			// Run cleanup routine every hour
			if err := db.CleanupOldEvents(retentionDays); err != nil && debug {
				log.Printf("Cleanup failed: %v", err)
			}

		case sig := <-sigChan:
			log.Printf("Received signal %v, shutting down gracefully...", sig)
			// Insert remaining batch before exit
			if len(batch) > 0 {
				if err := db.InsertDNSEventBatch(batch); err != nil && debug {
					log.Printf("Failed to insert final batch: %v", err)
				}
			}
			return nil
		}
	}
}

// Inspect displays DNS traffic data from the database
func Inspect(dbPath string, limit int, ip, domain, since, ifaceFilter string) error {
	// Open database (read-only)
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Build filter
	filter := database.EventFilter{
		Limit:     limit,
		IP:        ip,
		Domain:    domain,
		Interface: ifaceFilter,
	}

	// Parse time duration for "since" filter
	if since != "" {
		duration, err := time.ParseDuration(since)
		if err != nil {
			return fmt.Errorf("invalid time format for --since: %w", err)
		}
		sinceTime := time.Now().Add(-duration)
		filter.Since = sinceTime.Format(time.RFC3339)
	}

	// Query events
	events, err := db.GetDNSEvents(filter)
	if err != nil {
		return fmt.Errorf("failed to query events: %w", err)
	}

	// Display results
	if len(events) == 0 {
		fmt.Println("No DNS events found matching the criteria.")
		return nil
	}

	// Create simple table output without tablewriter for now
	fmt.Println("Timestamp           Source IP      Dest IP        Domain                           Type    Interface    Size")
	fmt.Println("-------------------- -------------- -------------- ---------------------------------- ------- ------------ -------")

	// Add rows
	for _, event := range events {
		timestamp := event.Timestamp.Format("2006-01-02 15:04:05")
		domain := truncateString(event.DomainName, 32)

		fmt.Printf("%-20s %-14s %-14s %-32s %-7s %-12s %s\n",
			timestamp,
			event.SourceIP,
			event.DestIP,
			domain,
			event.RecordType,
			event.Interface,
			fmt.Sprintf("%dB", event.PacketSize),
		)
	}

	// Show summary
	fmt.Printf("\nShowing %d of %d total events", len(events), getTotalEvents(db))
	if filter.IP != "" || filter.Domain != "" || filter.Since != "" || filter.Interface != "" {
		fmt.Printf(" (filtered)")
	}
	fmt.Println()

	return nil
}

// Install sets up the net-watcher as a systemd service
func Install(user, dataDir, serviceName string) error {
	// This function will be implemented with the systemd service creation
	// and user setup logic
	log.Printf("Installation feature not yet implemented")
	log.Printf("User: %s, DataDir: %s, ServiceName: %s", user, dataDir, serviceName)
	return nil
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// getTotalEvents gets the total number of events in the database
func getTotalEvents(db *database.Database) int {
	stats, err := db.GetStats()
	if err != nil {
		return 0
	}
	return stats.TotalEvents
}
