# Base images float: every build pulls the latest Node, Go and distroless patches.
FROM node:slim AS ui

WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# Writes ../internal/web/ui/dist, which go build embeds.
RUN npm run build

FROM golang:bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/web/ui/dist ./internal/web/ui/dist
ARG VERSION=dev
ARG COMMIT_SHA=unknown
RUN make build VERSION="$VERSION" COMMIT_SHA="$COMMIT_SHA"

# glibc (required by cgo SQLite and AF_PACKET capture) and CA certificates,
# without OpenSSL: Go uses its own TLS implementation.
FROM gcr.io/distroless/base-nossl-debian12:nonroot

# Links the GHCR package to this repository, so its workflows can publish it.
LABEL org.opencontainers.image.source="https://github.com/abi-jey/net-watcher" \
      org.opencontainers.image.description="Network event capture and audit log for hosts and Kubernetes nodes" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /src/net-watcher /net-watcher
USER nonroot:nonroot
ENTRYPOINT ["/net-watcher"]
