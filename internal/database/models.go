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
	DNSType    string // QUERY or RESPONSE
	DNSQuery   string `gorm:"index"` // Domain name
	DNSAnswers string // Comma-separated IPs
	DNSCNAMEs  string // Comma-separated CNAME chain

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
	Protocol string

	// Compaction metadata
	Compacted   bool   // Whether this is a compacted record
	OriginalIDs string // Comma-separated original event IDs (for audit)
	EventCount  int64  // Count of events (for hourly summaries)
}
