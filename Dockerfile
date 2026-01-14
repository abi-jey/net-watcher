# Multi-stage Docker build for net-watcher
FROM golang:1.25-alpine AS builder

# Install dependencies for building (if needed)
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary
ARG VERSION=dev
ARG BINARY=net-watcher
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -a -installsuffix cgo \
    -o ${BINARY} .

# Final lightweight image
FROM alpine:latest

# Install necessary runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    iptables \
    iproute2 && \
    adduser -D -s /bin/false netmon

# Create data directory
RUN mkdir -p /var/lib/net-watcher && \
    chown netmon:netmon /var/lib/net-watcher && \
    chmod 700 /var/lib/net-watcher

# Copy binary from builder
ARG BINARY=net-watcher
COPY --from=builder /app/${BINARY} /usr/local/bin/net-watcher

# Set permissions
RUN chmod +x /usr/local/bin/net-watcher && \
    chown root:root /usr/local/bin/net-watcher

# Set capabilities
RUN setcap cap_net_raw=+ep /usr/local/bin/net-watcher || echo "Warning: Could not set capabilities (not critical in container)"

# Switch to non-root user (for data directory access)
USER netmon

# Set working directory
WORKDIR /var/lib/net-watcher

# Expose data directory as volume
VOLUME ["/var/lib/net-watcher"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD pgrep -x net-watcher > /dev/null || exit 1

# Entry point
ENTRYPOINT ["/usr/local/bin/net-watcher"]
CMD ["serve"]

# Labels
LABEL maintainer="Abbas Jafari <abbas@example.com>" \
      description="Net Watcher - Secure Network Traffic Recorder" \
      version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/abja/net-watcher" \
      org.opencontainers.image.licenses="MIT"