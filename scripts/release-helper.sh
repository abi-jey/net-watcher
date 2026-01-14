#!/usr/bin/env sh

# Semantic Release helper script for net-watcher
set -e

# Configuration
REPO_URL="https://github.com/abja/net-watcher.git"
BUILD_DIR="dist"
CHANGELOG_FILE="CHANGELOG.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Ensure we're on a clean state
prepare_release() {
    echo_info "Preparing for semantic release..."
    
    # Clean previous builds
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
    
    mkdir -p "$BUILD_DIR"
    
    # Ensure git is clean
    if [ -n "$(git status --porcelain)" ]; then
        echo_error "Working directory is not clean. Commit or stash changes first."
        exit 1
    fi
    
    # Fetch latest tags
    git fetch --tags
}

# Generate version info
generate_version_info() {
    echo_info "Generating version information..."
    
    # Get current version from package.json
    VERSION=$(node -p "require('./package.json').version")
    
    # Get build info
    BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    COMMIT_SHA=$(git rev-parse HEAD)
    GO_VERSION=$(go version | awk '{print $3}')
    
    echo "VERSION=$VERSION"
    echo "BUILD_TIME=$BUILD_TIME"
    echo "COMMIT_SHA=$COMMIT_SHA"
    echo "GO_VERSION=$GO_VERSION"
    
    # Export for build
    export VERSION
    export BUILD_TIME
    export COMMIT_SHA
    export GO_VERSION
}

# Build release artifacts
build_release() {
    echo_info "Building release artifacts..."
    
    # Build for Linux only (uses AF_PACKET raw sockets)
    platforms=(
        "linux/amd64:net-watcher-linux-amd64"
        "linux/arm64:net-watcher-linux-arm64"
    )
    
    for platform in "${platforms[@]}"; do
        IFS=':/' read -r GOOS GOARCH BINARY_NAME <<< "$platform"
        
        echo_info "Building for $GOOS/$GOARCH..."
        
        CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
            go build \
                -ldflags="-s -w -X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.commitSHA=$COMMIT_SHA -X main.builder=GitHub-Actions" \
                -a -installsuffix cgo \
                -o "$BUILD_DIR/$BINARY_NAME" \
                .
        
        if [ $? -ne 0 ]; then
            echo_error "Failed to build $BINARY_NAME"
            exit 1
        fi
    done
}

# Generate checksums
generate_checksums() {
    echo_info "Generating checksums..."
    
    cd "$BUILD_DIR"
    
    # Generate checksums
    for binary in net-watcher-*; do
        if [ -f "$binary" ]; then
            echo_info "Generating checksum for $binary"
            
            # SHA256
            sha256sum "$binary" > "${binary}.sha256"
            
            # SHA512
            sha512sum "$binary" > "${binary}.sha512"
        fi
    done
    
    # Create checksums.txt
    {
        echo "# Checksums for Net Watcher v$VERSION"
        echo ""
        
        for binary in net-watcher-*; do
            if [ -f "$binary" ]; then
                echo "## $binary"
                echo "### SHA256"
                cat "${binary}.sha256" | cut -d' ' -f1
                echo ""
                echo "### SHA512"
                cat "${binary}.sha512" | cut -d' ' -f1
                echo ""
            fi
        done
    } > checksums.txt
}

# Generate release notes
generate_release_notes() {
    echo_info "Generating release notes..."
    
    # Get last tag
    LAST_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || echo "")
    
    # Generate notes based on commits since last tag
    if [ -n "$LAST_TAG" ]; then
        echo_info "Generating notes since tag $LAST_TAG"
        git log --pretty=format:"- %s" "$LAST_TAG..HEAD" > release-notes.tmp
    else
        echo_info "Generating notes for initial release"
        git log --pretty=format:"- %s" HEAD > release-notes.tmp
    fi
    
    # Categorize commits
    echo "# Release Notes v$VERSION" > release-notes.md
    echo "" >> release-notes.md
    echo "## 🚀 New Features" >> release-notes.md
    
    if grep -E "^(feat|feature)" release-notes.tmp >/dev/null 2>&1; then
        grep -E "^(feat|feature)" release-notes.tmp | sed 's/^/- /' >> release-notes.md
    else
        echo "No new features" >> release-notes.md
    fi
    
    echo "" >> release-notes.md
    echo "## 🐛 Bug Fixes" >> release-notes.md
    
    if grep -E "^fix" release-notes.tmp >/dev/null 2>&1; then
        grep -E "^fix" release-notes.tmp | sed 's/^/- /' >> release-notes.md
    else
        echo "No bug fixes" >> release-notes.md
    fi
    
    echo "" >> release-notes.md
    echo "## 🛡️ Security Improvements" >> release-notes.md
    
    if grep -E "^(security|chore\(security\)" release-notes.tmp >/dev/null 2>&1; then
        grep -E "^(security|chore\(security\)" release-notes.tmp | sed 's/^/- /' >> release-notes.md
    else
        echo "No security changes" >> release-notes.md
    fi
    
    echo "" >> release-notes.md
    echo "## 📦 Build Information" >> release-notes.md
    echo "- **Version**: $VERSION" >> release-notes.md
    echo "- **Build Time**: $BUILD_TIME" >> release-notes.md
    echo "- **Go Version**: $GO_VERSION" >> release-notes.md
    echo "- **Commit**: $COMMIT_SHA" >> release-notes.md
    
    # Clean up
    rm -f release-notes.tmp
}

# Main function
main() {
    case "${1:-}" in
        "prepare")
            prepare_release
            ;;
        "build")
            prepare_release
            generate_version_info
            build_release
            ;;
        "checksums")
            generate_checksums
            ;;
        "notes")
            generate_release_notes
            ;;
        "all")
            prepare_release
            generate_version_info
            build_release
            generate_checksums
            generate_release_notes
            
            echo_info "Release artifacts created in $BUILD_DIR/"
            echo_info "Generated files:"
            ls -la "$BUILD_DIR/"
            ;;
        "clean")
            rm -rf "$BUILD_DIR"
            echo_info "Cleaned build directory"
            ;;
        *)
            echo "Usage: $0 {prepare|build|checksums|notes|all|clean}"
            echo ""
            echo "  prepare    - Prepare environment for release"
            echo "  build      - Build release artifacts"
            echo "  checksums  - Generate checksums"
            echo "  notes      - Generate release notes"
            echo "  all        - Complete release process"
            echo "  clean      - Clean build directory"
            exit 1
            ;;
    esac
}

main "$@"