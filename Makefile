# Net Watcher Makefile

# Variables
BINARY_NAME=net-watcher
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT_SHA=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS=-ldflags="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.commitSHA=${COMMIT_SHA}"
CGO_FLAGS=CGO_ENABLED=0

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@echo "Building ${BINARY_NAME} ${VERSION}..."
	go build ${LDFLAGS} -o ${BINARY_NAME} .

# Build for Linux
.PHONY: build-linux
build-linux:
	@echo "Building ${BINARY_NAME} ${VERSION} for Linux..."
	${CGO_FLAGS} GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-amd64 .

# Build for macOS
.PHONY: build-darwin
build-darwin:
	@echo "Building ${BINARY_NAME} ${VERSION} for macOS..."
	${CGO_FLAGS} GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-amd64 .

# Build for Windows
.PHONY: build-windows
build-windows:
	@echo "Building ${BINARY_NAME} ${VERSION} for Windows..."
	${CGO_FLAGS} GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-windows-amd64.exe .

# Build all platforms
.PHONY: build-all
build-all: build-linux build-darwin build-windows

# Debug build
.PHONY: build-debug
build-debug:
	@echo "Building ${BINARY_NAME} ${VERSION} (debug)..."
	go build -gcflags="all=-N -l" ${LDFLAGS} -o ${BINARY_NAME}-debug .

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f ${BINARY_NAME} ${BINARY_NAME}-* ${BINARY_NAME}-debug

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

# Run benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Run linting
.PHONY: lint
lint:
	@echo "Running linters..."
	golangci-lint run

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet code
.PHONY: vet
vet:
	@echo "Vetting code..."
	go vet ./...

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod verify

# Update dependencies
.PHONY: update
update:
	@echo "Updating dependencies..."
	go get -u ./...

# Generate checksums
.PHONY: checksums
checksums:
	@echo "Generating checksums..."
	sha256sum ${BINARY_NAME}-* > checksums.txt
	sha512sum ${BINARY_NAME}-* >> checksums.txt

# Create release artifacts
.PHONY: release
release:
	@echo "Creating release..."
	./scripts/release-helper.sh all
	@echo "Release artifacts created:"
	@ls -la dist/

# Development release
.PHONY: dev-release
dev-release:
	@echo "Creating development release..."
	VERSION=dev-latest ./scripts/release-helper.sh build
	@echo "Development artifacts created:"
	@ls -la dist/net-watcher-*

# Clean release artifacts
.PHONY: clean-release
clean-release:
	@echo "Cleaning release artifacts..."
	rm -rf dist/

# Prepare for release
.PHONY: prepare-release
prepare-release:
	@echo "Preparing for release..."
	./scripts/release-helper.sh prepare

# Generate release notes only
.PHONY: release-notes
release-notes:
	@echo "Generating release notes..."
	./scripts/release-helper.sh notes
	@echo "Release notes:"
	@cat release-notes.md

# Install locally (for testing)
.PHONY: install-local
install-local: build
	@echo "Installing ${BINARY_NAME} locally..."
	sudo cp ${BINARY_NAME} /usr/local/bin/
	sudo chmod +x /usr/local/bin/${BINARY_NAME}

# Run with debug
.PHONY: run-debug
run-debug: build-debug
	@echo "Running ${BINARY_NAME} in debug mode..."
	sudo ./${BINARY_NAME}-debug serve --debug

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t abja/net-watcher:${VERSION} .
	docker tag abja/net-watcher:${VERSION} abja/net-watcher:latest

# Docker run
.PHONY: docker-run
docker-run:
	@echo "Running ${BINARY_NAME} in Docker..."
	docker run --rm --privileged --network=host abja/net-watcher

# Show version info
.PHONY: version
version:
	@echo "Net Watcher"
	@echo "Version: ${VERSION}"
	@echo "Build Time: ${BUILD_TIME}"
	@echo "Commit SHA: ${COMMIT_SHA}"

# Help
.PHONY: help
help:
	@echo "Net Watcher Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build binary for current platform"
	@echo "  build-linux    Build binary for Linux (amd64)"
	@echo "  build-darwin   Build binary for macOS (amd64)"
	@echo "  build-windows  Build binary for Windows (amd64)"
	@echo "  build-all      Build binaries for all platforms"
	@echo "  build-debug     Build debug binary"
	@echo "  clean          Clean build artifacts"
	@echo "  test           Run tests"
	@echo "  bench          Run benchmarks"
	@echo "  lint           Run linters"
	@echo "  fmt            Format code"
	@echo "  vet            Vet code"
	@echo "  deps           Install dependencies"
	@echo "  update         Update dependencies"
	@echo "  checksums      Generate checksums"
	@echo "  release        Create release artifacts"
	@echo "  install-local  Install binary locally"
	@echo "  run-debug      Run debug version"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-run     Run in Docker container"
	@echo "  version        Show version info"
	@echo "  help           Show this help"