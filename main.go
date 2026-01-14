package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/abja/net-watcher/pkg/cli"
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
    serve        Start the daemon service for packet capture
    inspect      Display captured DNS traffic data
    install      Install the service with proper permissions
    version      Show version information
    build-info   Show build information in JSON format

EXAMPLES:
    net-watcher serve --interface eth0
    net-watcher serve --interface tailscale0 --retention 30
    net-watcher inspect --limit 100
    net-watcher inspect --ip 192.168.1.100
    net-watcher inspect --domain example.com
    
    # Development commands
    net-watcher version --verbose
    net-watcher build-info
    make dev-release

For detailed help on any command:
    net-watcher <command> --help

`, version)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
		iface := serveCmd.String("interface", "", "Network interface to monitor (required)")
		dbPath := serveCmd.String("db", "/var/lib/net-watcher/dns.sqlite", "Database path")
		retention := serveCmd.Int("retention", 90, "Data retention in days")
		batchSize := serveCmd.Int("batch-size", 100, "Batch insert size")
		debug := serveCmd.Bool("debug", false, "Enable debug logging")

		serveCmd.Usage = func() {
			fmt.Printf(`USAGE: net-watcher serve [options]

OPTIONS:
`)
			serveCmd.PrintDefaults()
			fmt.Printf(`
DESCRIPTION:
    Start the network monitoring daemon. Captures DNS traffic on the specified
    interface and stores it in the SQLite database.

REQUIRES:
    -interface: Network interface to monitor (e.g., tailscale0, eth0)

SECURITY:
    This service requires CAP_NET_RAW capability to capture packets.
    When installed via 'net-watcher install', it runs as a dedicated
    unprivileged user with minimal permissions.

EXAMPLES:
    net-watcher serve --interface tailscale0
    net-watcher serve --interface eth0 --retention 30 --debug
`)
		}

		if err := serveCmd.Parse(os.Args[2:]); err != nil {
			serveCmd.Usage()
			os.Exit(1)
		}

		if *iface == "" {
			fmt.Println("Error: --interface is required")
			serveCmd.Usage()
			os.Exit(1)
		}

		// Validate database path
		if err := validatePath(*dbPath); err != nil {
			log.Fatalf("Invalid database path: %v", err)
		}

		if err := cli.Serve(*iface, *dbPath, *retention, *batchSize, *debug); err != nil {
			log.Fatalf("Serve command failed: %v", err)
		}

	case "inspect":
		inspectCmd := flag.NewFlagSet("inspect", flag.ExitOnError)
		dbPath := inspectCmd.String("db", "/var/lib/net-watcher/dns.sqlite", "Database path")
		limit := inspectCmd.Int("limit", 50, "Number of records to show")
		ip := inspectCmd.String("ip", "", "Filter by IP address")
		domain := inspectCmd.String("domain", "", "Filter by domain")
		since := inspectCmd.String("since", "", "Show records since (e.g., '1h', '24h', '7d')")
		ifaceFilter := inspectCmd.String("interface", "", "Filter by interface")

		inspectCmd.Usage = func() {
			fmt.Printf(`USAGE: net-watcher inspect [options]

OPTIONS:
`)
			inspectCmd.PrintDefaults()
			fmt.Printf(`
DESCRIPTION:
    Display captured DNS traffic data from the database in a formatted table.

FILTERS:
    -ip: Filter by source or destination IP address
    -domain: Filter by domain name (partial match)
    -since: Show records since specified duration (1h, 24h, 7d, etc.)
    -interface: Filter by network interface

EXAMPLES:
    net-watcher inspect
    net-watcher inspect --limit 100
    net-watcher inspect --ip 192.168.1.100
    net-watcher inspect --domain example.com --since 24h
    net-watcher inspect --interface tailscale0
`)
		}

		if err := inspectCmd.Parse(os.Args[2:]); err != nil {
			inspectCmd.Usage()
			os.Exit(1)
		}

		// Validate database path
		if err := validatePath(*dbPath); err != nil {
			log.Fatalf("Invalid database path: %v", err)
		}

		if err := cli.Inspect(*dbPath, *limit, *ip, *domain, *since, *ifaceFilter); err != nil {
			log.Fatalf("Inspect command failed: %v", err)
		}

	case "install":
		installCmd := flag.NewFlagSet("install", flag.ExitOnError)
		user := installCmd.String("user", "netmon", "System user to run as")
		dataDir := installCmd.String("data-dir", "/var/lib/net-watcher", "Data directory path")
		serviceName := installCmd.String("service-name", "net-watcher", "Systemd service name")

		installCmd.Usage = func() {
			fmt.Printf(`USAGE: net-watcher install [options]

OPTIONS:
`)
			installCmd.PrintDefaults()
			fmt.Printf(`
DESCRIPTION:
    Install net-watcher as a systemd service with proper security permissions.
    Creates a dedicated system user, sets up data directory, and installs
    the systemd service file.

SECURITY:
    - Creates dedicated 'netmon' user with no shell access
    - Grants only CAP_NET_RAW capability for packet capture
    - Restricts file system access to data directory only
    - Enables systemd sandboxing features

REQUIRES:
    Root privileges for installation

EXAMPLES:
    sudo net-watcher install
    sudo net-watcher install --user customuser --data-dir /opt/net-watcher
`)
		}

		if err := installCmd.Parse(os.Args[2:]); err != nil {
			installCmd.Usage()
			os.Exit(1)
		}

		// Check if running as root for installation
		if os.Geteuid() != 0 {
			log.Fatal("Installation requires root privileges. Use 'sudo net-watcher install'")
		}

		if err := cli.Install(*user, *dataDir, *serviceName); err != nil {
			log.Fatalf("Install command failed: %v", err)
		}

	case "version":
		fmt.Printf("net-watcher v%s\n", version)
		fmt.Printf("Built: %s\n", buildTime)
		fmt.Printf("Commit: %s\n", commitSHA)
		fmt.Printf("Go Version: %s\n", goVersion)
		fmt.Printf("Builder: %s\n", builder)

		// Extended version info for debugging
		if len(os.Args) > 2 && os.Args[2] == "--verbose" {
			fmt.Printf("\nBuild Information:\n")
			fmt.Printf("  Go Version: %s\n", goVersion)
			fmt.Printf("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			fmt.Printf("  Compiler: %s\n", runtime.Compiler)
			fmt.Printf("  CGO Enabled: %v\n", os.Getenv("CGO_ENABLED") != "")
			fmt.Printf("\nVersion Details:\n")
			fmt.Printf("  Version: %s\n", version)
			fmt.Printf("  Build Time: %s\n", buildTime)
			fmt.Printf("  Commit SHA: %s\n", commitSHA)
			fmt.Printf("  Build Environment: %s\n", builder)
		}

	case "build-info":
		fmt.Printf("{\"version\":\"%s\",\"buildTime\":\"%s\",\"commitSha\":\"%s\",\"goVersion\":\"%s\",\"builder\":\"%s\",\"os\":\"%s\",\"arch\":\"%s\"}\n",
			version, buildTime, commitSHA, goVersion, builder, runtime.GOOS, runtime.GOARCH)

	case "-h", "--help":
		printUsage()

	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// validatePath performs security checks on file paths
func validatePath(path string) error {
	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}

	// Check for path traversal attempts
	if filepath.Clean(path) != path {
		return fmt.Errorf("path contains traversal components")
	}

	// For database files, ensure parent directory exists
	dir := filepath.Dir(absPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", dir)
	}

	return nil
}
