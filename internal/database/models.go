package database

import (
	"time"
)

// EventType represents the type of network event
type EventType string

const (
	EventTCPStart EventType = "TCP_START"
	EventTCPEnd   EventType = "TCP_END"
	EventUDPStart EventType = "UDP_START"
	EventUDPEnd   EventType = "UDP_END"
	EventDNS      EventType = "DNS"
	EventTLSSNI   EventType = "TLS_SNI"
	EventICMP     EventType = "ICMP"
	EventTimeout  EventType = "TIMEOUT"

	// Compacted event types
	EventTCP           EventType = "TCP"    // Merged TCP_START + TCP_END
	EventUDP           EventType = "UDP"    // Merged UDP_START + UDP_END
	EventHourlySummary EventType = "HOURLY" // Hourly aggregation
)

// NetworkEvent represents a captured network event
type NetworkEvent struct {
	ID        uint      `gorm:"primaryKey"`
	Timestamp time.Time `gorm:"index;not null"`
	EventType EventType `gorm:"index;not null"`
	Interface string    `gorm:"index"`
	IPVersion uint8     `gorm:"index"` // 4 or 6

	// Connection info
	SrcIP   string `gorm:"index"`
	SrcPort uint16
	DstIP   string `gorm:"index"`
	DstPort uint16

	// DNS specific
	DNSType          string // QUERY or RESPONSE
	DNSQuery         string `gorm:"index"` // Domain name
	DNSAnswers       string // Comma-separated IPs
	DNSCNAMEs        string // Comma-separated CNAME chain
	DNSVersion       uint8  // Version 1 retains wire transaction metadata; legacy rows are not evidence.
	DNSID            uint16
	DNSQuestionType  string
	DNSResponseCode  string
	DNSMatched       bool
	DNSTruncated     bool
	DNSQueryTime     time.Time
	DNSRecords       string // JSON answer records including owner names and TTLs.
	DNSResolutionIDs string // JSON IDs of client-scoped, TTL-valid evidence at capture time.

	// TLS specific
	TLSSNI string `gorm:"index"`

	// Connection lifecycle
	Hostname  string // Resolved hostname from DNS cache
	DNSAge    int64  // Milliseconds since DNS resolution
	Duration  int64  // Milliseconds (for END events or compacted)
	ByteCount int64
	Reason    string    // FIN, RST, TIMEOUT
	EndTime   time.Time // End timestamp for compacted events

	// ICMP specific
	ICMPType uint8
	ICMPCode uint8
	ICMPDesc string

	// Protocol for timeout events
	Protocol           string
	SourceContext      string // JSON Kubernetes inventory snapshot at capture time.
	DestinationContext string
	ProcessPID         int    // Host PID observed through read-only procfs; zero when unavailable.
	ProcessCommand     string // Kernel comm name; never full command-line arguments.

	// Compaction metadata
	Compacted   bool   // Whether this is a compacted record
	OriginalIDs string // Comma-separated original event IDs (for audit)
	EventCount  int64  // Count of events (for hourly summaries)
	CollectorID string `gorm:"index"` // Empty for standalone/local observations.
}

// DNSResolution is immutable historical evidence from an observed query/response pair.
// It demonstrates that a resolver returned an address, not that an application used a hostname.
type DNSResolution struct {
	ID             uint `gorm:"primaryKey"`
	QueryTime      time.Time
	ResponseTime   time.Time `gorm:"index"`
	ExpiresAt      time.Time `gorm:"index"`
	Interface      string
	Transport      string
	TransactionID  uint16
	ClientIP       string `gorm:"index"`
	ClientPort     uint16
	ResolverIP     string
	ResolverPort   uint16
	Name           string `gorm:"index"`
	QueryType      string
	IP             string `gorm:"index"`
	TTL            uint32
	CNAMEChain     string // JSON records followed from the queried name to this address.
	AnswerRecords  string // JSON records exactly as observed in the response answer section.
	ClientContext  string
	AddressContext string
	CollectorID    string `gorm:"index"` // Empty for standalone/local observations.
}

// IngestedEvent records an idempotency key for a collector event stored centrally.
type IngestedEvent struct {
	ID          uint   `gorm:"primaryKey"`
	CollectorID string `gorm:"uniqueIndex:idx_ingested_event_source"`
	SourceID    uint   `gorm:"uniqueIndex:idx_ingested_event_source"`
	EventID     uint   `gorm:"index"`
}

// IngestedResolution records an idempotency key for DNS evidence stored centrally.
type IngestedResolution struct {
	ID           uint   `gorm:"primaryKey"`
	CollectorID  string `gorm:"uniqueIndex:idx_ingested_resolution_source"`
	SourceID     uint   `gorm:"uniqueIndex:idx_ingested_resolution_source"`
	ResolutionID uint   `gorm:"index"`
}

// IngestCursor persists a collector's acknowledged remote event position.
type IngestCursor struct {
	ID       uint   `gorm:"primaryKey"`
	Endpoint string `gorm:"uniqueIndex"`
	EventID  uint
}
