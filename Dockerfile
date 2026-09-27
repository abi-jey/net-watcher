FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags='-s -w' -o /out/net-watcher .

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=build /out/net-watcher /net-watcher
USER nonroot:nonroot
ENTRYPOINT ["/net-watcher"]
