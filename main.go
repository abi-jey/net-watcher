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
    start        Start the daemon service (includes web UI by default)

FLAGS:
    --interface          Network interface(s) to monitor (comma-separated)
    --interface-exclude  Network interface(s) to exclude (comma-separated, e.g., vpn,tun0)
    --debug              Enable debug logging
    --web                Enable web UI (default: true)
    --web-port           Web UI port (default: 8920)
    --only               Only log specific events (tcp,udp,icmp,dns,tls)
    --traffic-exclude    Exclude traffic types (multicast,broadcast,etc)

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
			interfacesToMonitor, err = getUsableInterfaces(*interfaceExclude)
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
		db, err := database.New("netwatcher.db")
		if err != nil {
			log.Error("Failed to open database", "error", err)
			os.Exit(1)
		}
		defer db.Close()

		w, err := watcher.NewWithDB(db, interfacesToMonitor, logger, *onlyFilter, *trafficExclude, *excludePorts)
		if err != nil {
			log.Error("Failed to create watcher", "error", err)
			os.Exit(1)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Handle shutdown signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigChan
			log.Info("Shutting down...")
			cancel()
		}()

		// Start web server if enabled
		if *enableWeb {
			server := web.NewServer(db, *webPort, logger, version)
			go func() {
				if err := server.Start(ctx); err != nil {
					log.Error("Web server error", "error", err)
				}
			}()
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
func getUsableInterfaces(excludePattern string) ([]net.Interface, error) {
	var usableInterfaces []net.Interface
	interfaces, err := net.Interfaces()
	log.Info("Getting usable interfaces")
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
			log.Info("Excluding interface (user specified)", "interface", candidateInterfaceName)
			continue
		}

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


