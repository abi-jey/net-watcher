# Release Template

## 🚀 What's Changed

### 🆕 New Features
- **Pure Go Packet Capture**: Replaced libpcap dependency with AF_PACKET for Linux systems
- **Cross-Platform Support**: Added fallback to libpcap for non-Linux systems
- **Static Binary Generation**: Eliminated CGO requirements for Linux builds
- **GitHub Actions**: Added comprehensive CI/CD pipeline with security scanning
- **Enhanced Installation**: Smart source detection and release download support

### 🛡️ Security Improvements
- **Capability Scoping**: Maintains CAP_NET_RAW only requirement
- **Sandboxing**: Systemd service with strict security policies
- **Dependency Scanning**: Automated vulnerability scanning with Snyk, Trivy, and Gosec
- **Code Quality**: Added golangci-lint and automated formatting checks

### 🐛 Bug Fixes
- **Memory Safety**: Improved bounds checking and error handling
- **Packet Processing**: Better filtering to reduce CPU overhead
- **Database Operations**: Optimized batch inserts with WAL mode

### ⚡ Performance
- **Reduced CPU Usage**: AF_PACKET with BPF filtering at kernel level
- **Memory Efficiency**: Zero-copy packet processing where possible
- **Database Performance**: Connection pooling and query optimization

### 🛠️ Developer Experience
- **VS Code Debugging**: Complete debugging configuration with launch profiles
- **Build System**: Multi-architecture builds (amd64, arm64)
- **Testing**: Automated testing across multiple Go versions

### 📦 Installation
- **One-Command Install**: `curl ... | bash` installation option
- **Architecture Detection**: Automatic detection of system architecture
- **Checksum Verification**: SHA256/SHA512 verification for all releases
- **Docker Support**: Multi-architecture Docker images

## 🔧 Installation

### Quick Install (Linux/macOS)
```bash
curl -L https://github.com/abja/net-watcher/releases/download/v{{VERSION}}/net-watcher-linux-amd64 -o net-watcher
chmod +x net-watcher
sudo ./net-watcher install
```

### Docker
```bash
docker run --privileged --network=host abja/net-watcher:{{VERSION}}
```

### From Source
```bash
git clone https://github.com/abja/net-watcher.git
cd net-watcher
sudo ./install.sh
```

## 🔐 Security Notes

- **Minimal Privileges**: Runs with CAP_NET_RAW only
- **User Isolation**: Dedicated unprivileged `netmon` user
- **Sandboxed**: Systemd service with strict filesystem restrictions
- **Auditable**: All dependencies and code scanned for vulnerabilities

## 📋 Checksums

| Binary | SHA256 | SHA512 |
|---------|----------|----------|
| Linux AMD64 | `[CHECKSUM]` | `[CHECKSUM]` |
| Linux ARM64 | `[CHECKSUM]` | `[CHECKSUM]` |
| macOS AMD64 | `[CHECKSUM]` | `[CHECKSUM]` |
| macOS ARM64 | `[CHECKSUM]` | `[CHECKSUM]` |
| Windows | `[CHECKSUM]` | `[CHECKSUM]` |

---

📖 For detailed documentation, visit: [https://github.com/abja/net-watcher](https://github.com/abja/net-watcher)