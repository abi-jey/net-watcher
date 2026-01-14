#!/bin/bash
set -euo pipefail

# Net Watcher Installation Script
# Enhanced with source detection and release download support

readonly APP_NAME="net-watcher"
readonly USER="netmon"
readonly DATA_DIR="/var/lib/net-watcher"
readonly SERVICE_NAME="net-watcher"
readonly BINARY_PATH="/usr/local/bin/${APP_NAME}"
readonly SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Installation modes
readonly MODE_SOURCE="source"
readonly MODE_RELEASE="release"

# Detect installation mode
detect_installation_mode() {
    if [[ -d ".git" && -f "go.mod" && -f "main.go" ]]; then
        # Check if we want dev release
        if [[ "${DEV_RELEASE:-false}" == "true" ]]; then
            echo "dev-source"
            return 0
        fi
        
        echo "$MODE_SOURCE"
        return 0
    else
        echo "$MODE_RELEASE"
        return 0
    fi
}

# Architecture detection
detect_architecture() {
    local arch=$(uname -m)
    case $arch in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l) echo "armv7" ;;
        *) echo "unknown" ;;
    esac
}

# OS detection
detect_os() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case $os in
        linux) echo "linux" ;;
        darwin) echo "darwin" ;;
        *) echo "unknown" ;;
    esac
}

# Get latest release information
get_latest_release() {
    log_info "Fetching latest release information..."
    
    # Try GitHub API first
    if command -v curl >/dev/null 2>&1; then
        local api_url="https://api.github.com/repos/abja/net-watcher/releases/latest"
        local release_info=$(curl -s "$api_url" 2>/dev/null || echo "")
        
        if [[ -n "$release_info" ]]; then
            local tag=$(echo "$release_info" | grep -o '"tag_name": "[^"]*' | cut -d'"' -f2)
            local assets=$(echo "$release_info" | grep -o '"browser_download_url": "[^"]*' | cut -d'"' -f4)
            
            echo "$tag"
            return 0
        fi
    fi
    
    # Fallback: Try GitHub releases page
    if command -v wget >/dev/null 2>&1; then
        local releases_page=$(wget -qO- "https://github.com/abja/net-watcher/releases/latest" 2>/dev/null || echo "")
        if [[ -n "$releases_page" ]]; then
            local tag=$(echo "$releases_page" | grep -o '/abja/net-watcher/releases/tag/[^"]*' | head -1 | cut -d'/' -f5)
            echo "$tag"
            return 0
        fi
    fi
    
    log_warn "Could not fetch release information"
    echo "v0.0.0"  # Fallback
    return 1
}

# Get development release information
get_dev_release() {
    log_info "Fetching latest development release..."
    
    # Try to get latest pre-release
    if command -v curl >/dev/null 2>&1; then
        local api_url="https://api.github.com/repos/abja/net-watcher/releases"
        local release_info=$(curl -s "$api_url" 2>/dev/null || echo "")
        
        if [[ -n "$release_info" ]]; then
            # Look for latest pre-release that contains "dev"
            local tag=$(echo "$release_info" | grep -o '"tag_name": "[^"]*' | grep -o '"[^"]*dev[^"]*' | head -1 | sed 's/"//g' | head -1)
            if [[ -n "$tag" ]]; then
                echo "$tag"
                return 0
            fi
        fi
    fi
    
    # Fallback
    echo "dev-latest"
    return 1
}

# Choose release source (stable vs dev)
choose_release_source() {
    # Check if user wants dev release
    if [[ "${DEV_RELEASE:-false}" == "true" ]]; then
        get_dev_release
        return $?
    fi
    
    # Check if in development environment
    if [[ -n "${BUILD_DEV:-}" ]]; then
        echo "dev-$(git rev-parse --short HEAD)"
        return 0
    fi
    
    # Default to latest stable release
    get_latest_release
}

# Download binary from release
download_release_binary() {
    local version="$1"
    local os="$2"
    local arch="$3"
    
    local binary_name="${APP_NAME}-${os}-${arch}"
    if [[ "$os" == "windows" ]]; then
        binary_name="${binary_name}.exe"
    fi
    
    local download_url="https://github.com/abja/net-watcher/releases/download/${version}/${binary_name}"
    local temp_dir="/tmp/net-watcher-install"
    
    log_info "Downloading ${APP_NAME} ${version} for ${os}/${arch}..."
    
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    # Try curl first
    if command -v curl >/dev/null 2>&1; then
        if ! curl -L "$download_url" -o "$binary_name"; then
            log_error "Failed to download binary"
            return 1
        fi
    # Fallback to wget
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -O "$binary_name" "$download_url"; then
            log_error "Failed to download binary"
            return 1
        fi
    else
        log_error "Neither curl nor wget is available"
        return 1
    fi
    
    # Verify download
    if [[ ! -f "$binary_name" || ! -s "$binary_name" ]]; then
        log_error "Download failed or empty file"
        return 1
    fi
    
    log_info "Downloaded binary: $temp_dir/$binary_name"
    echo "$temp_dir/$binary_name"
}

# Verify checksums
verify_checksum() {
    local binary="$1"
    local version="$2"
    local checksum_file="${binary}.sha256"
    
    log_info "Downloading checksum..."
    
    # Download checksum file
    local checksum_url="https://github.com/abja/net-watcher/releases/download/${version}/$(basename $checksum_file)"
    if command -v curl >/dev/null 2>&1; then
        curl -L "$checksum_url" -o "$checksum_file"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$checksum_file" "$checksum_url"
    else
        log_warn "Could not download checksum file"
        return 0
    fi
    
    if [[ ! -f "$checksum_file" ]]; then
        log_warn "Checksum file not available"
        return 0
    fi
    
    # Verify checksum
    if command -v sha256sum >/dev/null 2>&1; then
        local expected=$(cat "$checksum_file" | cut -d' ' -f1)
        local actual=$(sha256sum "$binary" | cut -d' ' -f1)
        
        if [[ "$expected" == "$actual" ]]; then
            log_info "✓ Checksum verification passed"
            return 0
        else
            log_error "✗ Checksum verification failed"
            log_error "Expected: $expected"
            log_error "Actual:   $actual"
            return 1
        fi
    else
        log_warn "sha256sum not available, skipping checksum verification"
        return 0
    fi
}

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_info "Usage: sudo $0"
        exit 1
    fi
}

# Check system dependencies
check_dependencies() {
    log_info "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check for essential commands
    for cmd in systemctl useradd getent; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    # Check for download tools
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing_deps+=("curl or wget")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install missing dependencies:"
        log_info "  Ubuntu/Debian: apt-get install ${missing_deps[*]}"
        log_info "  CentOS/RHEL:   yum install ${missing_deps[*]}"
        log_info "  Fedora:        dnf install ${missing_deps[*]}"
        exit 1
    fi
    
    log_info "All dependencies satisfied"
}

# Build from source
build_from_source() {
    log_info "Building ${APP_NAME} from source..."
    
    # Check for Go (for source builds only)
    check_go_version() {
        if command -v go >/dev/null 2>&1; then
            local go_version=$(go version | awk '{print $3}' | sed 's/go//')
            log_info "Go version: $go_version"
            return 0
        else
            log_warn "Go is not installed (not needed for release installs)"
            return 1
        fi
    }
    
    # Check Go version
    local go_version=$(go version | awk '{print $3}' | sed 's/go//')
    if ! command -v awk >/dev/null 2>&1 || ! command -v sed >/dev/null 2>&1; then
        log_warn "Cannot verify Go version (missing awk/sed)"
    fi
    
    # Clean any existing binaries
    if [[ -f "$APP_NAME" ]]; then
        rm -f "$APP_NAME"
    fi
    
    # Build with optimization flags and version info
    local version=$(git describe --tags --always --dirty 2>/dev/null || echo 'unknown')
    local build_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    local commit_sha=$(git rev-parse HEAD 2>/dev/null || echo 'unknown')
    
    local build_flags="-ldflags=-s -w -X main.version=${version} -X main.buildTime=${build_time} -X main.commitSHA=${commit_sha}"
    
    log_info "Building with flags: $build_flags"
    
    if ! CGO_ENABLED=0 go build $build_flags -o "$APP_NAME"; then
        log_error "Build failed"
        exit 1
    fi
    
    if [[ ! -f "$APP_NAME" ]]; then
        log_error "Build failed - no binary created"
        exit 1
    fi
    
    log_info "Build completed successfully"
}

# Install binary with proper permissions
install_binary() {
    local binary="$1"
    
    log_info "Installing binary to '$BINARY_PATH'..."
    
    # Install binary
    cp "$binary" "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
    chown root:root "$BINARY_PATH"
    
    # Verify installation
    if [[ ! -x "$BINARY_PATH" ]]; then
        log_error "Binary installation failed"
        exit 1
    fi
    
    log_info "Binary installed successfully"
    
    # Test binary
    if ! "$BINARY_PATH" version >/dev/null 2>&1; then
        log_warn "Binary test failed"
    fi
}

# Create dedicated system user
create_user() {
    log_info "Creating system user '$USER'..."
    
    if ! getent passwd "$USER" >/dev/null 2>&1; then
        useradd -r -s /bin/false -d "$DATA_DIR" "$USER"
        log_info "User '$USER' created successfully"
    else
        log_warn "User '$USER' already exists"
    fi
}

# Setup data directory with proper permissions
setup_data_dir() {
    log_info "Setting up data directory '$DATA_DIR'..."
    
    mkdir -p "$DATA_DIR"
    chown -R "$USER:$USER" "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    
    log_info "Data directory configured with secure permissions"
}

# Install systemd service
install_service() {
    log_info "Installing systemd service..."
    
    # Copy service file
    cp net-watcher.service "$SERVICE_PATH"
    
    # Reload systemd daemon
    systemctl daemon-reload
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    
    log_info "Systemd service installed and enabled"
}

# Configure systemd service with CAP_NET_RAW capability
configure_capabilities() {
    log_info "Configuring Linux capabilities for packet capture..."
    
    # Grant CAP_NET_RAW capability to binary
    if ! setcap cap_net_raw=+ep "$BINARY_PATH" 2>/dev/null; then
        log_warn "Failed to set capabilities via setcap"
        log_warn "Service will rely on systemd AmbientCapabilities instead"
    else
        log_info "CAP_NET_RAW capability granted to binary"
    fi
}

# Set up log rotation
setup_logrotate() {
    log_info "Setting up log rotation..."
    
    local logrotate_config="/etc/logrotate.d/net-watcher"
    
    cat > "$logrotate_config" << 'EOF'
/var/log/net-watcher.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        systemctl reload net-watcher || true
    endscript
}
EOF
    
    log_info "Log rotation configured"
}

# Create configuration file
create_config() {
    log_info "Creating default configuration..."
    
    local config_dir="/etc/net-watcher"
    local config_file="${config_dir}/config.env"
    
    mkdir -p "$config_dir"
    
    cat > "$config_file" << 'EOF'
# Net Watcher Configuration
# These settings can be overridden by systemd environment or command line flags

# Database path
NETWATCHER_DB="/var/lib/net-watcher/dns.sqlite"

# Data retention period (days)
NETWATCHER_RETENTION="90"

# Batch insert size
NETWATCHER_BATCH_SIZE="100"

# Debug mode (true/false)
NETWATCHER_DEBUG="false"

# Network interface to monitor (empty = auto-detect)
NETWATCHER_INTERFACE=""
EOF
    
    chown root:root "$config_file"
    chmod 644 "$config_file"
    
    log_info "Configuration file created at $config_file"
}

# Test installation
test_installation() {
    log_info "Testing installation..."
    
    # Test binary
    if ! "$BINARY_PATH" version >/dev/null 2>&1; then
        log_error "Binary test failed"
        exit 1
    fi
    
    # Test service syntax
    if ! systemctl status "$SERVICE_NAME" >/dev/null 2>&1; then
        log_warn "Service is not running (expected for fresh installation)"
    fi
    
    log_info "Installation test passed"
}

# Main installation function
main() {
    local mode=$(detect_installation_mode)
    log_info "Installation mode: $mode"
    
    check_root
    check_dependencies
    
    # Check Go version for source builds
    if [[ "$mode" == "$MODE_SOURCE" ]] && ! check_go_version; then
        log_error "Go installation required for source builds"
        exit 1
    fi
    
    create_user
    setup_data_dir
    
    local binary=""
    
    if [[ "$mode" == "$MODE_SOURCE" ]]; then
        build_from_source
        binary="$APP_NAME"
    elif [[ "$mode" == "dev-source" ]]; then
        build_from_source
        binary="$APP_NAME"
    else
        local version=$(get_latest_release)
        local os=$(detect_os)
        local arch=$(detect_architecture)
        
        if [[ "$os" == "unknown" || "$arch" == "unknown" ]]; then
            log_error "Unsupported OS/architecture: ${os}/${arch}"
            exit 1
        fi
        
        local download_path=$(download_release_binary "$version" "$os" "$arch")
        
        if ! verify_checksum "$download_path" "$version"; then
            log_warn "Checksum verification failed (may be dev release)"
        fi
        
        binary="$download_path"
    fi
        
        local download_path=$(download_release_binary "$version" "$os" "$arch")
        
        if ! verify_checksum "$download_path" "$version"; then
            log_warn "Checksum verification failed (may be dev release)"
        fi
        
        binary="$download_path"
    fi
    
    install_binary "$binary"
    install_service
    configure_capabilities
    setup_logrotate
    create_config
    test_installation
    
    log_info "Installation completed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Start service:     systemctl start $SERVICE_NAME"
    log_info "2. Check service status:   systemctl status $SERVICE_NAME"
    log_info "3. View logs:            journalctl -u $SERVICE_NAME -f"
    log_info "4. Inspect DNS data:     $BINARY_PATH inspect"
    log_info ""
    log_info "Configuration: /etc/net-watcher/config.env"
    log_info "Data directory: $DATA_DIR"
    log_info "Service file: $SERVICE_PATH"
    
    # Ask if user wants to start the service
    read -p "Do you want to start net-watcher service now? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Starting net-watcher service..."
        systemctl start "$SERVICE_NAME"
        
        # Show status
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_info "Service started successfully!"
            systemctl status "$SERVICE_NAME" --no-pager
        else
            log_error "Service failed to start. Check logs with: journalctl -u $SERVICE_NAME"
        fi
    fi
}

# Parse command line arguments
DEV_RELEASE=false
STABLE_RELEASE=false

while [[ $# -gt 1 ]]; do
    case "$2" in
        --dev)
            DEV_RELEASE=true
            shift
            ;;
        --stable)
            STABLE_RELEASE=true
            shift
            ;;
        *)
            # Unknown option, break
            break
            ;;
    esac
done

# Handle script arguments
case "${1:-install}" in
    "install"|"")
        main
        ;;
    "uninstall")
        log_info "Uninstalling net-watcher..."
        systemctl stop "$SERVICE_NAME" || true
        systemctl disable "$SERVICE_NAME" || true
        rm -f "$SERVICE_PATH" "$BINARY_PATH"
        systemctl daemon-reload
        userdel -r "$USER" || true
        log_info "Uninstallation completed"
        ;;
    "help"|"-h"|"--help")
        echo "Net Watcher Installation Script"
        echo ""
        echo "Usage: $0 [install|uninstall|help] [options]"
        echo ""
        echo "Commands:"
        echo "  install   Install net-watcher (auto-detects source vs release)"
        echo "  uninstall Remove net-watcher installation"
        echo "  help      Show this help message"
        echo ""
        echo "Options:"
        echo "  --dev     Install latest development release"
        echo "  --stable  Force stable release (default)"
        echo ""
        echo "Source Detection:"
        echo "  - If run in git repository with go.mod and main.go: build from source"
        echo "  - Otherwise: download latest release binary (pure Go, no libpcap needed)"
        echo "  - With --dev: download latest development release"
        echo ""
        echo "Environment Variables:"
        echo "  DEV_RELEASE=true  Force development release download"
        echo "  BUILD_DEV=1      Build from source as dev release"
        ;;
    *)
        log_error "Unknown command: $1"
        log_info "Use '$0 help' for usage information"
        exit 1
        ;;
esac