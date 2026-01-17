package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
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
    report       Generate an HTML report from the database
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
	case "report":
		reportCmd := flag.NewFlagSet("report", flag.ExitOnError)
		dbPath := reportCmd.String("db", "netwatcher.db", "Path to the database file")
		outputPath := reportCmd.String("output", "report.html", "Path to the output HTML file")
		since := reportCmd.String("since", "24h", "Time range for the report (e.g., 1h, 24h, 7d)")
		reportCmd.Parse(os.Args[2:])

		if err := generateReport(*dbPath, *outputPath, *since); err != nil {
			log.Error("Failed to generate report", "error", err)
			os.Exit(1)
		}
		log.Info("Report generated successfully", "output", *outputPath)
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

// Generated by Copilot
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

// Generated by Copilot
func generateReport(dbPath, outputPath, sinceStr string) error {
	// Parse the "since" duration
	var since time.Duration
	if strings.HasSuffix(sinceStr, "d") {
		days := 0
		fmt.Sscanf(sinceStr, "%dd", &days)
		since = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		since, err = time.ParseDuration(sinceStr)
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
	}

	sinceTime := time.Now().Add(-since)

	// Open database
	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Get stats
	stats, err := db.GetStats(sinceTime)
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	// Get all events
	events, err := db.GetEvents(database.EventFilter{Since: sinceTime})
	if err != nil {
		return fmt.Errorf("failed to get events: %w", err)
	}

	// Get timeline data
	timeline, err := db.GetTimelineData(sinceTime)
	if err != nil {
		return fmt.Errorf("failed to get timeline: %w", err)
	}

	// Prepare template data
	data := struct {
		GeneratedAt   string
		Since         string
		Stats         *database.Stats
		Events        []database.NetworkEvent
		Timeline      []database.TimelinePoint
		TimelineJSON  string
	}{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Since:       sinceStr,
		Stats:       stats,
		Events:      events,
		Timeline:    timeline,
	}

	// Build timeline JSON for chart
	var timelinePoints []string
	for _, tp := range timeline {
		timelinePoints = append(timelinePoints, fmt.Sprintf(`{x:"%s",y:%d}`, tp.Hour, tp.Count))
	}
	data.TimelineJSON = "[" + strings.Join(timelinePoints, ",") + "]"

	// Create output file
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	// Parse and execute template
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl.Execute(f, data)
}

const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Net Watcher Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f0f; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #00ff88; margin-bottom: 10px; }
        h2 { color: #00ccff; margin: 30px 0 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .meta { color: #888; margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; }
        .stat-card h3 { color: #888; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }
        .stat-card .value { font-size: 32px; font-weight: bold; color: #00ff88; }
        .chart-container { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; margin-bottom: 30px; height: 300px; }
        .top-lists { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .top-list { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; }
        .top-list h3 { color: #00ccff; margin-bottom: 15px; }
        .top-list ol { padding-left: 20px; }
        .top-list li { margin-bottom: 8px; font-family: monospace; }
        .top-list .count { color: #00ff88; margin-left: 10px; }
        table { width: 100%; border-collapse: collapse; background: #1a1a1a; border-radius: 8px; overflow: hidden; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #252525; color: #00ccff; font-weight: 600; position: sticky; top: 0; }
        tr:hover { background: #252525; }
        .event-type { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .event-TCP_START { background: #006633; color: #00ff88; }
        .event-TCP_END { background: #663300; color: #ffaa00; }
        .event-UDP_START { background: #003366; color: #00aaff; }
        .event-UDP_END { background: #333366; color: #aaaaff; }
        .event-DNS { background: #660066; color: #ff88ff; }
        .event-TLS_SNI { background: #666600; color: #ffff88; }
        .event-ICMP { background: #660000; color: #ff8888; }
        .event-TIMEOUT { background: #444; color: #aaa; }
        .event-TCP { background: #005533; color: #00ff99; }
        .event-UDP { background: #004466; color: #00ccff; }
        .event-HOURLY { background: #553300; color: #ffcc66; }
        tr.compacted { border-left: 3px solid #00ff88; }
        .table-container { max-height: 600px; overflow-y: auto; border: 1px solid #333; border-radius: 8px; }
        .filter-bar { background: #1a1a1a; padding: 15px; border-radius: 8px; margin-bottom: 20px; display: flex; gap: 15px; flex-wrap: wrap; align-items: center; }
        .filter-bar input, .filter-bar select { background: #252525; border: 1px solid #444; color: #e0e0e0; padding: 8px 12px; border-radius: 4px; }
        .filter-bar input:focus, .filter-bar select:focus { outline: none; border-color: #00ccff; }
        .filter-bar label { color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Net Watcher Report</h1>
        <p class="meta">Generated: {{.GeneratedAt}} | Period: Last {{.Since}}</p>

        <h2>📊 Overview</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Events</h3>
                <div class="value">{{.Stats.TotalEvents}}</div>
            </div>
            <div class="stat-card">
                <h3>TCP Connections</h3>
                <div class="value">{{.Stats.TCPCount}}</div>
            </div>
            <div class="stat-card">
                <h3>UDP Sessions</h3>
                <div class="value">{{.Stats.UDPCount}}</div>
            </div>
            <div class="stat-card">
                <h3>DNS Queries</h3>
                <div class="value">{{.Stats.DNSCount}}</div>
            </div>
            <div class="stat-card">
                <h3>TLS Handshakes</h3>
                <div class="value">{{.Stats.TLSCount}}</div>
            </div>
            <div class="stat-card">
                <h3>Unique Hosts</h3>
                <div class="value">{{.Stats.UniqueHosts}}</div>
            </div>
            <div class="stat-card">
                <h3>Unique Domains</h3>
                <div class="value">{{.Stats.UniqueDomains}}</div>
            </div>
        </div>

        <h2>📈 Activity Timeline</h2>
        <div class="chart-container">
            <canvas id="timelineChart"></canvas>
        </div>

        <h2>🔝 Top Activity</h2>
        <div class="top-lists">
            <div class="top-list">
                <h3>Top Domains (DNS)</h3>
                <ol>
                {{range .Stats.TopDomains}}
                    <li>{{.Name}}<span class="count">({{.Count}})</span></li>
                {{else}}
                    <li>No data</li>
                {{end}}
                </ol>
            </div>
            <div class="top-list">
                <h3>Top Destinations (IP)</h3>
                <ol>
                {{range .Stats.TopDestinations}}
                    <li>{{.Name}}<span class="count">({{.Count}})</span></li>
                {{else}}
                    <li>No data</li>
                {{end}}
                </ol>
            </div>
            <div class="top-list">
                <h3>Top SNI (TLS)</h3>
                <ol>
                {{range .Stats.TopSNIs}}
                    <li>{{.Name}}<span class="count">({{.Count}})</span></li>
                {{else}}
                    <li>No data</li>
                {{end}}
                </ol>
            </div>
        </div>

        <h2>📋 All Events</h2>
        <div class="filter-bar">
            <label>Filter: <input type="text" id="filterInput" placeholder="Search..." oninput="filterTable()"></label>
            <label>Type: 
                <select id="typeFilter" onchange="filterTable()">
                    <option value="">All</option>
                    <option value="TCP_START">TCP_START</option>
                    <option value="TCP_END">TCP_END</option>
                    <option value="TCP">TCP (compacted)</option>
                    <option value="UDP_START">UDP_START</option>
                    <option value="UDP_END">UDP_END</option>
                    <option value="UDP">UDP (compacted)</option>
                    <option value="DNS">DNS</option>
                    <option value="TLS_SNI">TLS_SNI</option>
                    <option value="ICMP">ICMP</option>
                    <option value="TIMEOUT">TIMEOUT</option>
                    <option value="HOURLY">HOURLY</option>
                </select>
            </label>
        </div>
        <div class="table-container">
            <table id="eventsTable">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>IP</th>
                        <th>Interface</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                {{range .Events}}
                    <tr data-type="{{.EventType}}"{{if .Compacted}} class="compacted"{{end}}>
                        <td>{{.Timestamp.Format "15:04:05"}}</td>
                        <td><span class="event-type event-{{.EventType}}">{{.EventType}}</span></td>
                        <td>{{if eq .IPVersion 6}}v6{{else}}v4{{end}}</td>
                        <td>{{.Interface}}</td>
                        <td>{{.SrcIP}}{{if .SrcPort}}:{{.SrcPort}}{{end}}</td>
                        <td>{{.DstIP}}{{if .DstPort}}:{{.DstPort}}{{end}}</td>
                        <td>
                            {{if .DNSQuery}}Domain: {{.DNSQuery}}{{end}}
                            {{if .DNSCNAMEs}} (CNAME: {{.DNSCNAMEs}}){{end}}
                            {{if .DNSAnswers}} → {{.DNSAnswers}}{{end}}
                            {{if .TLSSNI}}SNI: {{.TLSSNI}}{{end}}
                            {{if .Hostname}}Host: {{.Hostname}}{{end}}
                            {{if .ICMPDesc}}{{.ICMPDesc}}{{end}}
                            {{if gt .Duration 0}}Duration: {{.Duration}}ms{{end}}
                            {{if gt .ByteCount 0}} | Bytes: {{.ByteCount}}{{end}}
                            {{if .Compacted}}📦{{end}}
                        </td>
                    </tr>
                {{end}}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Timeline Chart
        const ctx = document.getElementById('timelineChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                datasets: [{
                    label: 'Events per Hour',
                    data: {{.TimelineJSON}},
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { type: 'category', grid: { color: '#333' }, ticks: { color: '#888' } },
                    y: { beginAtZero: true, grid: { color: '#333' }, ticks: { color: '#888' } }
                },
                plugins: { legend: { labels: { color: '#e0e0e0' } } }
            }
        });

        // Table filtering
        function filterTable() {
            const filter = document.getElementById('filterInput').value.toLowerCase();
            const typeFilter = document.getElementById('typeFilter').value;
            const rows = document.querySelectorAll('#eventsTable tbody tr');
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                const type = row.dataset.type;
                const matchesText = text.includes(filter);
                const matchesType = !typeFilter || type === typeFilter;
                row.style.display = matchesText && matchesType ? '' : 'none';
            });
        }
    </script>
</body>
</html>
`