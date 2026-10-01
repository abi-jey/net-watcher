FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT_SHA=unknown
RUN make build VERSION="$VERSION" COMMIT_SHA="$COMMIT_SHA"

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=build /src/net-watcher /net-watcher
USER nonroot:nonroot
ENTRYPOINT ["/net-watcher"]
