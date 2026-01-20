# Net Watcher

A secure Go-based network traffic recorder that captures DNS queries and stores them in an SQLite database. Designed with security hardening and minimal dependencies in mind.

## 🚀 Quick Start

### One-Liner Installation
```bash
curl -L https://github.com/abja/net-watcher/releases/latest/download/net-watcher-linux-amd64 -o net-watcher && \
chmod +x net-watcher && \
sudo ./net-watcher install
```

### Source Installation
```bash
git clone https://github.com/abja/net-watcher.git && cd net-watcher && \
sudo ./install.sh
```

## 📋 Usage

### Service Management
```bash
# Start service
sudo systemctl start net-watcher

# Check status
sudo systemctl status net-watcher

# View logs
sudo journalctl -u net-watcher -f

# Stop service
sudo systemctl stop net-watcher
```

### CLI Commands

#### Start Daemon Mode
```bash
# Monitor specific interface
sudo net-watcher serve --interface eth0

# With custom settings
sudo net-watcher serve --interface tailscale0 --retention 30 --batch-size 50 --debug
```

#### Inspect Captured Data
```bash
# Show last 50 records
net-watcher inspect

# Show more records
net-watcher inspect --limit 100

# Filter by IP
net-watcher inspect --ip 192.168.1.100

# Filter by domain
net-watcher inspect --domain example.com

# Show recent records
net-watcher inspect --since 24h

# Filter by interface
net-watcher inspect --interface tailscale0

# Combined filters
net-watcher inspect --ip 10.0.0.5 --since 1h --limit 20
```

#### Utility Commands
```bash
# Show version
net-watcher version

# Show available interfaces
net-watcher list-interfaces

# Validate interface
net-watcher validate-interface eth0

# Show help
net-watcher --help
```

## 🏗️ Architecture

### Security-First Design
- **Minimal Privileges**: Runs as dedicated `netmon` user with CAP_NET_RAW only
- **Sandboxed**: Systemd service with strict filesystem restrictions
- **Pure Go**: Static binaries with no external dependencies
- **Input Validation**: Comprehensive packet validation and bounds checking

### Linux-Only, Pure Go
- **AF_PACKET**: Direct kernel packet capture via raw sockets
- **No CGO**: Pure Go implementation with zero C dependencies
- **Static Binary**: Single binary deployment with no external libraries

## 🔧 Installation

### System Requirements
- **Linux only** (uses AF_PACKET raw sockets)
- **Go 1.25+** for building from source
- **CAP_NET_RAW** capability for packet capture

### Automated Installation
```bash
# Install latest release (recommended)
curl -L https://github.com/abja/net-watcher/releases/latest/download/net-watcher-linux-amd64 -o net-watcher && \
chmod +x net-watcher && \
sudo ./net-watcher install
```

### Manual Installation
```bash
# From source
git clone https://github.com/abja/net-watcher.git
cd net-watcher
sudo ./install.sh

# Development build
git clone https://github.com/abja/net-watcher.git
cd net-watcher
make dev-release
sudo ./net-watcher install
```

## 🔧 Development

### Prerequisites
- Go 1.25+ for development builds
- Linux only (uses AF_PACKET raw sockets)

### Build Commands
```bash
# Debug build
make build-debug

# Release build (pure Go)
CGO_ENABLED=0 make build-all

# Development release
make dev-release

# Generate version info
make build-info

# Run tests
make test

# Format code
make fmt

# Security scan
make lint
```

### Versioning & Release

Net-Watcher uses **Semantic Release** with conventional commits:

- `feat:` → Minor version bump (1.1.0 → 1.2.0)
- `fix:` → Patch version bump (1.2.0 → 1.2.1)
- `BREAKING CHANGE:` → Major version bump (1.2.0 → 2.0.0)

### Release Types
- **Stable**: `v1.2.0` (from tags on main)
- **Development**: `v1.2.1-dev` (from develop branch)
- **Pre-release**: `v1.2.1-alpha.1` (from alpha/beta branches)

### Release Workflow
```bash
# Create stable release
git tag v1.2.0 && git push origin v1.2.0

# Create development release
git push origin develop  # Auto creates v1.2.1-dev

# Manual release with version
make release VERSION=1.3.0-beta.1
```

## 🔒 Security Architecture

### Principle of Least Privilege
- **Dedicated User**: Runs as `netmon` (no shell, no password)
- **Capability Scoping**: Only CAP_NET_RAW for packet capture
- **File System Restrictions**: Limited to `/var/lib/net-watcher` only
- **Network Restrictions**: AF_PACKET socket access only

### Systemd Hardening
```ini
[Service]
Type=simple
User=netmon
Group=netmon

# Security capabilities
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

# File system sandboxing
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/net-watcher

# Additional restrictions
PrivateTmp=true
ProtectKernelTunables=true
NoNewPrivileges=true
```

### Security Benefits
- **Exploit Containment**: Attacker limited to unprivileged user context
- **Minimal Attack Surface**: Only packet capture capability required
- **Audit Trail**: Systemd journaling of all activities
- **No Root Required**: Eliminates entire class of vulnerabilities

## 📊 Database

### Schema
```sql
CREATE TABLE dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    source_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    domain_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    interface TEXT NOT NULL,
    packet_size INTEGER DEFAULT 0
);

-- Performance indexes
CREATE INDEX idx_timestamp ON dns_events(timestamp);
CREATE INDEX idx_domain ON dns_events(domain_name);
CREATE INDEX idx_source_ip ON dns_events(source_ip);
```

### Configuration
- **WAL Mode**: Concurrent read/write access
- **Batch Inserts**: Efficient bulk operations
- **Retention Policy**: Automatic cleanup of old records (default: 90 days)
- **Connection Pooling**: Optimized database connections

## 🐳 Development

### Project Structure
```
net-watcher/
├── main.go                 # Entry point with CLI routing
├── internal/
│   ├── database/
│   │   ├── schema.go       # Database operations
│   │   └── models.go       # Data models
│   └── capture/
│       └── sniffer.go      # AF_PACKET DNS capture (Linux)
├── pkg/cli/
│   └── commands.go         # CLI command implementations
├── scripts/
│   └── release-helper.sh   # Release automation
├── Makefile                # Build system
├── install.sh              # Installation script
├── net-watcher.service     # Systemd service file
├── go.mod                  # Go modules
└── README.md               # This file
```

## 🔍 Monitoring & Troubleshooting

### Health Checks
```bash
# Service health
sudo systemctl is-active net-watcher

# Database status
sqlite3 /var/lib/net-watcher/dns.sqlite "SELECT COUNT(*) FROM dns_events;"

# Interface status
ip link show eth0
```

### Debug Mode
```bash
# Enable debug logging
sudo net-watcher serve --interface eth0 --debug

# Verbose version info
net-watcher version --verbose
```

### Common Issues

#### Permission Denied
```bash
# Check capabilities
getcap /usr/local/bin/net-watcher
# Should show: /usr/local/bin/net-watcher = cap_net_raw+ep

# Check service status
sudo systemctl status net-watcher
```

#### Service Won't Start
```bash
# Check logs
sudo journalctl -u net-watcher -n 50

# Validate interface
sudo net-watcher validate-interface eth0

# Check capabilities
sudo setcap -v cap_net_raw+ep /usr/local/bin/net-watcher
```

## 📦 CI/CD Pipeline

### Automated Workflows
- **Go Version**: Go 1.25
- **Cross-Platform Builds**: Linux, macOS, Windows (amd64/arm64)
- **Security Scanning**: Gosec, Trivy, Snyk, CodeQL
- **Release Automation**: Semantic versioning with changelog generation

### Build Process
```yaml
# Pure Go builds (CGO_ENABLED=0)
- Automatic version injection
- Checksum generation (SHA256/SHA512)
- Multi-architecture support
- GitHub release creation
```

## 📝 Performance

### Optimization Features
- **Zero-Copy Packet Processing**: Minimize memory allocations
- **BPF Filtering**: Kernel-level packet filtering
- **Batch Database Operations**: Bulk inserts for throughput
- **WAL Mode**: Concurrent access without blocking
- **Connection Pooling**: Reuse database connections

### Benchmarks
- **Packet Processing**: >100k packets/second on modern hardware
- **Database Throughput**: >10k DNS queries/second batch insert
- **Memory Usage**: <50MB steady state
- **CPU Overhead**: <5% on single core for packet capture

## 📚 Documentation

### API Reference
```bash
# Complete CLI help
net-watcher --help

# Command-specific help
net-watcher serve --help
net-watcher inspect --help
```

### Configuration
```bash
# Configuration file location
/etc/net-watcher/config.env

# Environment variables
NETWATCHER_DB="/var/lib/net-watcher/dns.sqlite"
NETWATCHER_RETENTION="90"
NETWATCHER_BATCH_SIZE="100"
NETWATCHER_DEBUG="false"
```

## 🗺️ Roadmap

### Phase 1: Stability & Enrichment (v1.x)
Goal: A stable, standalone service with rich data context and streamlined operations.
- **One-Command Service**: Robust `install.sh` for systemd integration and immediate UI serving.
- **Traffic Enrichment**: 
  - **GeoIP**: Automatic resolution of country/city for remote IPs.
  - **IP Ownership**: Fetch ASN/ISP data (Whois/RDAP) to identify traffic sources (e.g., "Google LLC", "AWS").
- **TCP Diagnostics**: 
  - **Health Metrics**: Monitor retransmissions, jitter (time variation), and ghost connections.
  - **Quality Analysis**: Detect unstable or high-latency TCP flows.
- **Release Pipeline**: Strict semantic versioning and automated releases.
- **Traffic Monitoring**: Reliable packet capture with zero-copy optimizations.

### Phase 2: Distributed Architecture (Future)
Goal: Centralized observability for multiple nodes.
- **Ingest Mode**: Lightweight agents that forward traffic instead of storing it locally.
- **Command Center**: Centralized server for aggregating data from multiple ingestion nodes.
- **Stateless Operation**: Option for nodes to run without a local SQLite database.
- **Alerting System**: Configurable triggers for specific network events or anomalies.

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes with conventional commits
4. Run tests: `make test`
5. Submit pull request

### Commit Format
```bash
feat: add IPv6 support
fix: resolve memory leak in packet processing
security: update dependencies due to CVE-2024-1234
docs: update installation instructions
chore: update dependencies
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Repository**: https://github.com/abja/net-watcher
- **Releases**: https://github.com/abja/net-watcher/releases
- **Issues**: https://github.com/abja/net-watcher/issues
- **Documentation**: https://github.com/abja/net-watcher/wiki

---

## 🚀 Quick Reference

| Command | Purpose | Example |
|---------|---------|---------|
| `serve` | Start daemon | `net-watcher serve --interface eth0` |
| `inspect` | View data | `net-watcher inspect --limit 100` |
| `version` | Show version | `net-watcher version --verbose` |
| `install` | Setup service | `sudo ./install.sh` |

Net-Watcher provides robust network monitoring with minimal dependencies and maximum security.
