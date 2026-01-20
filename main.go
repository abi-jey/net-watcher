package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/abja/net-watcher/internal/web"
	"github.com/abja/net-watcher/pkg/watcher"
	"github.com/charmbracelet/log"
)

// Build information (will be overridden by build flags)
var (
	version   = "1.0.0-dev"
	buildTime = "unknown"
	commitSHA = "unknown"
	goVersion = runtime.Version()
	builder   = "unknown"
)

func printUsage() {
	fmt.Printf(`Net Watcher - Secure Network Traffic Recorder v%s

USAGE:
    net-watcher <command> [options]

COMMANDS:
    start        Start the daemon service for monitor traffic
    serve        Start the web UI server to view events
    compact      Compact the database by merging event pairs

`, version)
}

func main() {
	logger := log.NewWithOptions(os.Stdout, log.Options{
		ReportTimestamp: true,
	})
	log.SetDefault(logger)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start":
		startCmd := flag.NewFlagSet("start", flag.ExitOnError)
		interfaceName := startCmd.String("interface", "", "Network interface to monitor")
		debug := startCmd.Bool("debug", false, "Enable debug logs")
		onlyFilter := startCmd.String("only", "", "Comma-separated list of events to log (tcp,udp,icmp,dns,tls)")
		excludeFilter := startCmd.String("exclude", "", "Comma-separated list of traffic to exclude (multicast,broadcast,linklocal,bittorrent,mdns,ssdp,metadata,ndp,unreachable)")
		excludePorts := startCmd.String("exclude-ports", "", "Comma-separated list of ports to exclude")
		startCmd.Parse(os.Args[2:])

		if *debug {
			logger.SetLevel(log.DebugLevel)
		}
		var interfacesToMonitor []net.Interface
		var err error

		// Load specified interfaces if provided
		interfacesToMonitor, err = getInterfacesByName(*interfaceName)
		if err != nil {
			log.Error("Failed to get interfaces by name", "error", err)
			os.Exit(1)
		}

		// Attempt best-effort detection
		if *interfaceName == "" {
			log.Info("Interface name not provided, using best-effort detection")
			interfacesToMonitor, err = getUsableInterfaces()
			if err != nil {
				log.Error("Failed to get usable interfaces", "error", err)
				os.Exit(1)
			}
			if len(interfacesToMonitor) == 0 {
				log.Error("No usable network interfaces found")
				os.Exit(1)
			}
			var names []string
			for _, iface := range interfacesToMonitor {
				names = append(names, iface.Name)
			}
			*interfaceName = strings.Join(names, ",")
		}
		log.Info("Starting net-watcher", "version", version, "interface", *interfaceName, "debug", *debug, "only", *onlyFilter, "exclude", *excludeFilter, "exclude-ports", *excludePorts)
		w, err := watcher.New("netwatcher.db", interfacesToMonitor, logger, *onlyFilter, *excludeFilter, *excludePorts)
		if err != nil {
			log.Error("Failed to create watcher", "error", err)
			os.Exit(1)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := w.Run(ctx); err != nil {
			log.Error("Watcher stopped with error", "error", err)
			os.Exit(1)
		}
	case "serve":
		serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
		dbPath := serveCmd.String("db", "netwatcher.db", "Path to the database file")
		port := serveCmd.Int("port", 8080, "Port to serve the web UI on")
		serveCmd.Parse(os.Args[2:])

		log.Info("Starting web server", "db", *dbPath, "port", *port)

		db, err := database.New(*dbPath)
		if err != nil {
			log.Error("Failed to open database", "error", err)
			os.Exit(1)
		}
		defer db.Close()

		server := web.NewServer(db, *port, logger, version)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Handle shutdown signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigChan
			log.Info("Shutting down web server...")
			cancel()
		}()

		if err := server.Start(ctx); err != nil {
			log.Error("Web server error", "error", err)
			os.Exit(1)
		}
	case "compact":
		compactCmd := flag.NewFlagSet("compact", flag.ExitOnError)
		dbPath := compactCmd.String("db", "netwatcher.db", "Path to the database file")
		olderThan := compactCmd.String("older-than", "24h", "Compact events older than this (e.g., 1h, 24h, 7d)")
		dedupeWindow := compactCmd.String("dedupe-window", "5s", "Window for DNS deduplication (0 to disable)")
		hourlySummary := compactCmd.Bool("hourly-summary", false, "Also create hourly summaries (destructive)")
		dryRun := compactCmd.Bool("dry-run", false, "Show what would be compacted without making changes")
		compactCmd.Parse(os.Args[2:])

		if err := runCompact(*dbPath, *olderThan, *dedupeWindow, *hourlySummary, *dryRun); err != nil {
			log.Error("Compaction failed", "error", err)
			os.Exit(1)
		}
	case "-h", "--help":
		printUsage()

	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func getInterfacesByName(names string) ([]net.Interface, error) {
	var interfaces []net.Interface
	interfaceNames := strings.Split(names, ",")
	for _, ifaceName := range interfaceNames {
		ifaceName = strings.TrimSpace(ifaceName)
		if ifaceName == "" {
			continue
		}
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
		}
		if iface.Flags&net.FlagUp == 0 {
			return nil, fmt.Errorf("interface %s is down", ifaceName)
		}
		interfaces = append(interfaces, *iface)
	}
	return interfaces, nil
}

func getUsableInterfaces() ([]net.Interface, error) {
	var usableInterfaces []net.Interface
	interfaces, err := net.Interfaces()
	log.Info("Getting usable interfaces")
	if err != nil || len(interfaces) == 0 {
		log.Error("Failed to list network interfaces", "error", err)
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	for _, i := range interfaces {
		if (i.Flags&net.FlagUp == 0) || (i.Flags&net.FlagLoopback != 0) {
			continue
		}
		candidateInterfaceName := i.Name
		addrs, err := i.Addrs()
		if err != nil || len(addrs) == 0 {
			log.Info("Skipping interface", "interface", candidateInterfaceName, "addrs", addrs, "error", err)
			continue
		}
		addr := addrs[0].String()
		log.Info("Checking interface", "candidateInterfaceName", candidateInterfaceName, "addr", addr)
		if strings.HasPrefix(candidateInterfaceName, "docker") ||
			strings.HasPrefix(candidateInterfaceName, "br-") ||
			strings.HasPrefix(candidateInterfaceName, "veth") {
			continue
		}
		log.Info("Usable interface found", "candidateInterfaceName", candidateInterfaceName)
		usableInterfaces = append(usableInterfaces, i)
	}
	return usableInterfaces, nil
}

func runCompact(dbPath, olderThanStr, dedupeWindowStr string, hourlySummary, dryRun bool) error {
	// Parse durations
	olderThan, err := parseDuration(olderThanStr)
	if err != nil {
		return fmt.Errorf("invalid older-than duration: %w", err)
	}

	var dedupeWindow time.Duration
	if dedupeWindowStr != "0" && dedupeWindowStr != "" {
		dedupeWindow, err = time.ParseDuration(dedupeWindowStr)
		if err != nil {
			return fmt.Errorf("invalid dedupe-window duration: %w", err)
		}
	}

	olderThanTime := time.Now().Add(-olderThan)

	log.Info("Starting database compaction",
		"db", dbPath,
		"older_than", olderThanTime.Format("2006-01-02 15:04:05"),
		"dedupe_window", dedupeWindow,
		"hourly_summary", hourlySummary,
		"dry_run", dryRun,
	)

	// Open database
	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	if dryRun {
		// Show what would be compacted
		return showCompactionPreview(db, olderThanTime, dedupeWindow, hourlySummary)
	}

	// Run compaction
	stats, err := db.Compact(olderThanTime, dedupeWindow)
	if err != nil {
		return err
	}

	log.Info("Compaction complete",
		"tcp_pairs", stats.TCPPairsCompacted,
		"udp_pairs", stats.UDPPairsCompacted,
		"dns_pairs", stats.DNSPairsCompacted,
		"duplicates_removed", stats.DuplicatesRemoved,
		"orphans_removed", stats.OrphanedEndsRemoved,
		"total_removed", stats.TotalEventsRemoved,
		"total_created", stats.TotalEventsCreated,
	)

	// Optionally create hourly summaries
	if hourlySummary {
		summaryCount, err := db.CreateHourlySummary(olderThanTime)
		if err != nil {
			log.Warn("Hourly summary creation had errors", "error", err)
		}
		log.Info("Created hourly summaries", "count", summaryCount)
	}

	return nil
}

func showCompactionPreview(db *database.DB, olderThan time.Time, dedupeWindow time.Duration, hourlySummary bool) error {
	// Count potential TCP pairs
	var tcpStarts, tcpEnds int64
	db.Model(&database.NetworkEvent{}).Where("event_type = ? AND timestamp < ?", database.EventTCPStart, olderThan).Count(&tcpStarts)
	db.Model(&database.NetworkEvent{}).Where("event_type IN (?, ?) AND timestamp < ?", database.EventTCPEnd, database.EventTimeout, olderThan).Count(&tcpEnds)

	// Count potential UDP pairs
	var udpStarts, udpEnds int64
	db.Model(&database.NetworkEvent{}).Where("event_type = ? AND timestamp < ?", database.EventUDPStart, olderThan).Count(&udpStarts)
	db.Model(&database.NetworkEvent{}).Where("event_type = ? AND timestamp < ?", database.EventUDPEnd, olderThan).Count(&udpEnds)

	// Count DNS events
	var dnsQueries, dnsResponses int64
	db.Model(&database.NetworkEvent{}).Where("event_type = ? AND dns_type = ? AND timestamp < ?", database.EventDNS, "QUERY", olderThan).Count(&dnsQueries)
	db.Model(&database.NetworkEvent{}).Where("event_type = ? AND dns_type = ? AND timestamp < ?", database.EventDNS, "RESPONSE", olderThan).Count(&dnsResponses)

	// Estimate deduplication
	var duplicateEstimate int64
	if dedupeWindow > 0 {
		// Rough estimate: count DNS with same query in window
		db.Raw(`
			SELECT COUNT(*) FROM network_events e1
			WHERE event_type = 'DNS' AND timestamp < ?
			AND EXISTS (
				SELECT 1 FROM network_events e2
				WHERE e2.dns_query = e1.dns_query
				AND e2.id < e1.id
				AND e2.timestamp > datetime(e1.timestamp, '-' || ? || ' seconds')
			)
		`, olderThan, int(dedupeWindow.Seconds())).Scan(&duplicateEstimate)
	}

	fmt.Println("\n📊 Compaction Preview (Dry Run)")
	fmt.Println("================================")
	fmt.Printf("Events older than: %s\n\n", olderThan.Format("2006-01-02 15:04:05"))

	fmt.Println("TCP Compaction:")
	fmt.Printf("  - TCP_START events: %d\n", tcpStarts)
	fmt.Printf("  - TCP_END/TIMEOUT events: %d\n", tcpEnds)
	fmt.Printf("  - Potential pairs: ~%d\n", min(tcpStarts, tcpEnds))

	fmt.Println("\nUDP Compaction:")
	fmt.Printf("  - UDP_START events: %d\n", udpStarts)
	fmt.Printf("  - UDP_END events: %d\n", udpEnds)
	fmt.Printf("  - Potential pairs: ~%d\n", min(udpStarts, udpEnds))

	fmt.Println("\nDNS Compaction:")
	fmt.Printf("  - DNS QUERY events: %d\n", dnsQueries)
	fmt.Printf("  - DNS RESPONSE events: %d\n", dnsResponses)
	fmt.Printf("  - Potential pairs: ~%d\n", min(dnsQueries, dnsResponses))

	if dedupeWindow > 0 {
		fmt.Printf("\nDNS Deduplication (window: %s):\n", dedupeWindow)
		fmt.Printf("  - Estimated duplicates: ~%d\n", duplicateEstimate)
	}

	if hourlySummary {
		var distinctHours int64
		db.Model(&database.NetworkEvent{}).
			Select("COUNT(DISTINCT strftime('%Y-%m-%d %H', timestamp))").
			Where("timestamp < ?", olderThan).
			Scan(&distinctHours)
		fmt.Printf("\nHourly Summaries:\n")
		fmt.Printf("  - Distinct hours: %d\n", distinctHours)
		fmt.Printf("  - ⚠️  This will aggregate all events into hourly summaries\n")
	}

	fmt.Println("\n✋ No changes made (dry run)")
	fmt.Println("   Remove --dry-run to apply compaction")

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := 0
		fmt.Sscanf(s, "%dd", &days)
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
