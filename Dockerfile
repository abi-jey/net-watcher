# Base images float: every build pulls the latest Go and distroless patches.
FROM golang:bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT_SHA=unknown
RUN make build VERSION="$VERSION" COMMIT_SHA="$COMMIT_SHA"

# glibc (required by cgo SQLite and AF_PACKET capture) and CA certificates,
# without OpenSSL: Go uses its own TLS implementation.
FROM gcr.io/distroless/base-nossl-debian12:nonroot

COPY --from=build /src/net-watcher /net-watcher
USER nonroot:nonroot
ENTRYPOINT ["/net-watcher"]
