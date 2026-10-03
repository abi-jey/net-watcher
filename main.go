package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/abja/net-watcher/internal/ingest"
	"github.com/abja/net-watcher/internal/kube"
	"github.com/abja/net-watcher/internal/web"
	"github.com/abja/net-watcher/pkg/watcher"
	"github.com/charmbracelet/log"
)

// Build information (will be overridden by build flags)
var (
	version   = "1.0.0-dev"
	buildTime = "unknown"         //nolint:unused // Set by ldflags
	commitSHA = "unknown"         //nolint:unused // Set by ldflags
	goVersion = runtime.Version() //nolint:unused // Set by ldflags
	builder   = "unknown"         //nolint:unused // Set by ldflags
)

func printUsage() {
	fmt.Printf(`Net Watcher - Secure Network Traffic Recorder v%s

USAGE:
    net-watcher <command> [options]

COMMANDS:
    start        Start the daemon service (includes web UI by default)

FLAGS:
    --interface          Network interface(s) to monitor (comma-separated)
    --interface-exclude  Network interface(s) to exclude (comma-separated, e.g., vpn,tun0)
    --debug              Enable debug logging
    --web                Enable web UI (default: true)
    --web-port           Web UI port (default: 8920)
    --only               Only log specific events (tcp,udp,icmp,dns,tls)
    --traffic-exclude    Exclude traffic types (multicast,broadcast,etc)
    --kubernetes         Enrich with read-only Kubernetes inventory; include pod interfaces
    --kube-context       Explicit kubectl context (otherwise use in-cluster identity)
    --owned-cidrs        Comma-separated operator-owned IP ranges for map labels
    --process-attribution  Best-effort host TLS PID/name using read-only procfs
    --process-proc-root    Host procfs mount (default: /host/proc)
    --include-virtual    Include bridge/veth interfaces during automatic discovery
    --db                 SQLite database path (default: netwatcher.db)
    --max-db-size-gb     Maximum central/standalone SQLite size in GiB (default: 10)
    --storage-check-interval  Storage maintenance interval (minimum/default: 10m)
    --capture=false      View stored data without starting packet capture
    --web-host           Web bind address (default: all interfaces)
    --ingest-url         Central ingest base URL for a collector
    --ingest-token       Required bearer token for ingest send/receive
    --ingest-port        Run the central ingest listener on this port
    --ingest-queue-size-mb  Maximum pending ingestion payload in MiB (default: 256)
    --collector-id       Stable collector identity (defaults to hostname)

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
		interfaceExclude := startCmd.String("interface-exclude", "", "Comma-separated list of interfaces to exclude (e.g., vpn,tun0)")
		debug := startCmd.Bool("debug", false, "Enable debug logs")
		onlyFilter := startCmd.String("only", "", "Comma-separated list of events to log (tcp,udp,icmp,dns,tls)")
		trafficExclude := startCmd.String("traffic-exclude", "", "Comma-separated list of traffic to exclude (multicast,broadcast,linklocal,bittorrent,mdns,ssdp,metadata,ndp,unreachable)")
		excludePorts := startCmd.String("exclude-ports", "", "Comma-separated list of ports to exclude")
		enableWeb := startCmd.Bool("web", true, "Enable web UI server")
		webPort := startCmd.Int("web-port", 8920, "Port for web UI server")
		webHost := startCmd.String("web-host", "", "Web bind address")
		dbPath := startCmd.String("db", "netwatcher.db", "SQLite database path")
		maxDBSizeGB := startCmd.Int64("max-db-size-gb", 10, "Maximum central/standalone SQLite size in GiB")
		storageCheckInterval := startCmd.Duration("storage-check-interval", 10*time.Minute, "Storage maintenance interval")
		capture := startCmd.Bool("capture", true, "Capture packets; disable to view stored data")
		kubernetes := startCmd.Bool("kubernetes", false, "Enable read-only Kubernetes inventory")
		kubeContext := startCmd.String("kube-context", "", "Explicit kubectl context for inventory")
		ownedCIDRs := startCmd.String("owned-cidrs", "", "Comma-separated operator-owned CIDRs for network map classification")
		processAttribution := startCmd.Bool("process-attribution", false, "Best-effort host TLS process attribution from read-only procfs")
		processProcRoot := startCmd.String("process-proc-root", "/host/proc", "Read-only host procfs mount for process attribution")
		includeVirtual := startCmd.Bool("include-virtual", false, "Include bridge/veth interfaces")
		ingestURL := startCmd.String("ingest-url", "", "Authenticated central ingestion base URL for this collector")
		ingestToken := startCmd.String("ingest-token", "", "Bearer token for central ingestion")
		ingestPort := startCmd.Int("ingest-port", 0, "Run authenticated central ingestion listener on this port")
		ingestQueueMB := startCmd.Int64("ingest-queue-size-mb", 256, "Maximum pending ingestion payload in MiB; stored beside --db")
		collectorID := startCmd.String("collector-id", "", "Stable collector identity for central ingestion")
		_ = startCmd.Parse(os.Args[2:])
		if *ingestQueueMB <= 0 || *ingestQueueMB > (1<<63-1)/(1<<20) {
			log.Error("--ingest-queue-size-mb must be a positive number of MiB")
			os.Exit(1)
		}
		if *maxDBSizeGB <= 0 || *maxDBSizeGB > (1<<63-1)/(1<<30) {
			log.Error("--max-db-size-gb must be a positive number of GiB")
			os.Exit(1)
		}
		if *storageCheckInterval < 10*time.Minute {
			log.Error("--storage-check-interval must be at least 10m")
			os.Exit(1)
		}
		ownedPrefixes, err := web.ParseOwnedCIDRs(*ownedCIDRs)
		if err != nil {
			log.Error("Invalid --owned-cidrs", "error", err)
			os.Exit(1)
		}
		*kubernetes = *kubernetes || *kubeContext != ""

		if *debug {
			logger.SetLevel(log.DebugLevel)
		}
		var interfacesToMonitor []net.Interface

		// Load specified interfaces if provided
		if *capture {
			interfacesToMonitor, err = getInterfacesByName(*interfaceName)
		}
		if err != nil {
			log.Error("Failed to get interfaces by name", "error", err)
			os.Exit(1)
		}

		// Attempt best-effort detection
		autoInterfaces := *interfaceName == ""
		if *capture && autoInterfaces {
			log.Info("Interface name not provided, using best-effort detection")
			interfacesToMonitor, err = getUsableInterfaces(*interfaceExclude, *includeVirtual || *kubernetes)
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
		log.Info("Starting net-watcher", "version", version, "interface", *interfaceName, "interface_exclude", *interfaceExclude, "debug", *debug, "web", *enableWeb, "web_port", *webPort, "only", *onlyFilter, "traffic_exclude", *trafficExclude, "exclude_ports", *excludePorts)

		// Open database
		db, err := database.New(*dbPath)
		if err != nil {
			log.Error("Failed to open database", "error", err)
			os.Exit(1)
		}
		defer db.Close()
		if *collectorID == "" {
			*collectorID, _ = os.Hostname()
		}
		if *ingestURL != "" && *ingestToken == "" {
			log.Error("--ingest-token is required with --ingest-url")
			os.Exit(1)
		}
		if *ingestPort < 0 || *ingestPort > 65535 {
			log.Error("--ingest-port must be 0..65535")
			os.Exit(1)
		}
		if *ingestPort > 0 && *ingestToken == "" {
			log.Error("--ingest-token is required with --ingest-port")
			os.Exit(1)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if *ingestURL == "" {
			if err := db.EnableSummaries(ctx); err != nil {
				log.Error("Could not initialize hourly summaries", "error", err)
				return
			}
			backfillDone := make(chan struct{})
			go func() { defer close(backfillDone); db.RunSummaryBackfill(ctx) }()
			defer func() { cancel(); <-backfillDone }()
		}
		go maintainStorage(ctx, db, *ingestURL, *maxDBSizeGB*(1<<30), *storageCheckInterval)

		// Handle shutdown signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigChan
			log.Info("Shutting down...")
			cancel()
		}()
		if *ingestURL != "" {
			forwarder := &ingest.Forwarder{DB: db, URL: *ingestURL, Token: *ingestToken, CollectorID: *collectorID, Logger: logger}
			go forwarder.Run(ctx)
		}
		if *ingestPort > 0 {
			// A central commit must survive power loss before its durable queue
			// entry is deleted; NORMAL synchronization cannot guarantee that handoff.
			if err := db.Exec("PRAGMA synchronous=FULL").Error; err != nil {
				log.Error("Failed to enable durable central ingestion", "error", err)
				return
			}
			queue, err := ingest.OpenQueue(*dbPath+".ingest-queue.db", *ingestQueueMB*(1<<20))
			if err != nil {
				log.Error("Failed to open ingestion queue", "error", err)
				return
			}
			receiver := &ingest.Receiver{DB: db, Token: *ingestToken, Queue: queue}
			workerDone := make(chan struct{})
			go func() {
				defer close(workerDone)
				queue.Run(ctx, receiver)
			}()
			defer func() {
				cancel()
				<-workerDone
				_ = queue.Close()
			}()
			go func() {
				if err := receiver.Serve(ctx, net.JoinHostPort("", strconv.Itoa(*ingestPort))); err != nil {
					log.Error("Ingest server error", "error", err)
					cancel()
				}
			}()
		}
		inventory := kube.New(nil)
		if *kubernetes {
			var source kube.Source
			if *kubeContext != "" {
				source = kube.KubectlSource{Context: *kubeContext}
			} else {
				source, err = kube.InClusterSource()
			}
			if err != nil {
				log.Error("Kubernetes configuration failed", "error", err)
				return
			}
			inventory = kube.New(source)
			refreshCtx, stop := context.WithTimeout(ctx, 20*time.Second)
			if err := inventory.Refresh(refreshCtx); err != nil {
				log.Warn("Kubernetes inventory unavailable; capture continues without attribution", "error", err)
			}
			stop()
			go inventory.Run(ctx)
		}

		// Start web server if enabled
		if *enableWeb {
			reader, err := database.OpenReadOnly(*dbPath)
			if err != nil {
				log.Error("Failed to open read-only web database", "error", err)
				return
			}
			defer reader.Close()
			server := web.NewServer(reader, *webPort, logger, version)
			server.Host = *webHost
			server.Kubernetes = inventory
			server.OwnedCIDRs = ownedPrefixes
			go func() {
				if err := server.Start(ctx); err != nil {
					log.Error("Web server error", "error", err)
					cancel()
				}
			}()
		}

		if !*capture {
			<-ctx.Done()
			return
		}
		w, err := watcher.NewWithDB(db, interfacesToMonitor, logger, *onlyFilter, *trafficExclude, *excludePorts)
		if err != nil {
			log.Error("Failed to create watcher", "error", err)
			return
		}
		w.SetContextLookup(inventory.Lookup)
		if *processAttribution {
			if err := w.EnableProcessAttribution(*processProcRoot); err != nil {
				log.Warn("Process attribution unavailable; continuing packet capture", "error", err)
			}
		}
		if autoInterfaces {
			w.Discover = func() ([]net.Interface, error) {
				return getUsableInterfaces(*interfaceExclude, *includeVirtual || *kubernetes)
			}
		}
		if err := w.Run(ctx); err != nil {
			log.Error("Watcher stopped with error", "error", err)
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

func maintainStorage(ctx context.Context, db *database.DB, ingestURL string, maxBytes int64, interval time.Duration) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if ingestURL != "" {
			removed, err := db.ReclaimCollectorSpace(ingestURL)
			if err != nil {
				log.Error("Could not reclaim collector storage", "error", err)
			} else if removed > 0 {
				log.Info("Discarded acknowledged collector events", "removed", removed)
			}
		} else {
			removed, err := db.PruneToSize(maxBytes)
			if err != nil {
				log.Error("Could not enforce database size limit", "error", err)
			} else if removed > 0 {
				size, sizeErr := db.StorageBytes()
				log.Info("Pruned old network events", "removed", removed, "bytes", size, "error", sizeErr)
			}
		}
		timer.Reset(interval)
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

// getUsableInterfaces returns all usable network interfaces, excluding those specified
func getUsableInterfaces(excludePattern string, includeVirtual bool) ([]net.Interface, error) {
	var usableInterfaces []net.Interface
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		log.Error("Failed to list network interfaces", "error", err)
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	// Build exclusion set from pattern
	excludeSet := make(map[string]bool)
	for _, name := range strings.Split(excludePattern, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			excludeSet[name] = true
		}
	}

	for _, i := range interfaces {
		if (i.Flags&net.FlagUp == 0) || (i.Flags&net.FlagLoopback != 0) {
			continue
		}
		candidateInterfaceName := i.Name

		// Check explicit exclusion list
		if excludeSet[candidateInterfaceName] {
			continue
		}

		if !includeVirtual {
			addrs, err := i.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}
		}
		if !includeVirtual && (strings.HasPrefix(candidateInterfaceName, "docker") ||
			strings.HasPrefix(candidateInterfaceName, "br-") ||
			strings.HasPrefix(candidateInterfaceName, "veth")) {
			continue
		}
		usableInterfaces = append(usableInterfaces, i)
	}
	return usableInterfaces, nil
}
