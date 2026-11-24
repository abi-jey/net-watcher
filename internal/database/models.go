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
	// EventGap records observations that were knowingly lost or withheld, so an
	// audit can distinguish "nothing happened" from "nothing was recorded".
	EventGap EventType = "GAP"

	// Compacted event types
	EventTCP           EventType = "TCP"    // Merged TCP_START + TCP_END
	EventUDP           EventType = "UDP"    // Merged UDP_START + UDP_END
	EventHourlySummary EventType = "HOURLY" // Hourly aggregation
)

// NetworkEvent represents a captured network event
type NetworkEvent struct {
	ID        uint      `gorm:"primaryKey"`
	Timestamp time.Time `gorm:"index;not null;index:idx_src_uid_time,priority:2;index:idx_dst_uid_time,priority:2;index:idx_src_workload_time,priority:3;index:idx_dst_workload_time,priority:3;index:idx_src_namespace_time,priority:2;index:idx_dst_namespace_time,priority:2"`
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
	// DNSEvidenceMissing counts referenced resolutions that were unavailable when
	// the event was forwarded; the remaining references stay verifiable.
	DNSEvidenceMissing int

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
	// Indexed capture-time Kubernetes identity. Kind is pod, node, service or
	// endpoint; Workload is "Kind/name" of the top-level owner; Attribution is
	// the confidence (exact, ambiguous, stale, node, service) or empty when the
	// address was not a known cluster address. Events captured before these
	// columns existed have them empty and only the JSON context.
	SrcKind        string
	SrcNamespace   string `gorm:"index:idx_src_namespace_time,priority:1;index:idx_src_workload_time,priority:1"`
	SrcName        string
	SrcUID         string `gorm:"index:idx_src_uid_time,priority:1"`
	SrcWorkload    string `gorm:"index:idx_src_workload_time,priority:2"`
	SrcAttribution string
	DstKind        string
	DstNamespace   string `gorm:"index:idx_dst_namespace_time,priority:1;index:idx_dst_workload_time,priority:1"`
	DstName        string
	DstUID         string `gorm:"index:idx_dst_uid_time,priority:1"`
	DstWorkload    string `gorm:"index:idx_dst_workload_time,priority:2"`
	DstAttribution string
	ProcessPID     int    // Host PID observed through read-only procfs; zero when unavailable.
	ProcessCommand string // Kernel comm name; never full command-line arguments.
	// ProcessSide is "src" or "dst": the endpoint whose socket the process
	// owns. Empty when no process was attributed.
	ProcessSide string
	// ProcessPod is namespace/name of the pod the process runs in, including
	// host-network pods; empty for host processes outside pods.
	ProcessPod       string
	ProcessContainer string // Container name from the pod's status.

	// Route marks traffic on a Tailscale interface that is not between two
	// tailnet devices: "exit-node" (this node forwarded a tailnet device's
	// traffic to the internet), "subnet-router" (to a private network), or
	// "via-tailnet" (this node's own traffic sent into the tailnet, toward
	// another device's exit node or subnet route). Empty otherwise.
	Route           string
	TailnetPeer     string // Address of the tailnet device this node forwarded for.
	TailnetPeerName string // Its MagicDNS name at capture time, when resolvable.

	// Compaction metadata
	Compacted   bool   // Whether this is a compacted record
	OriginalIDs string // Comma-separated original event IDs (for audit)
	EventCount  int64  // Count of events (for hourly summaries)
	CollectorID string `gorm:"index"` // Empty for standalone/local observations.
}

// Gap reasons describe why observations are absent for an interval.
const (
	GapCaptureDrops     = "capture-drops"         // Kernel ring dropped packets before decoding.
	GapWriteFailure     = "write-buffer-overflow" // Local writes failed long enough to overflow the retry buffer.
	GapCollectorLimit   = "collector-size-limit"  // Pending events were discarded to respect the collector size limit.
	GapRejectedByIngest = "rejected-by-ingester"  // The ingester permanently rejected a single event.
)

// NewGapEvent describes a span of lost observations. EventCount holds the number
// of lost events or packets, Reason the cause and Timestamp/EndTime the span.
func NewGapEvent(reason string, count int64, from, to time.Time, iface string) NetworkEvent {
	if to.Before(from) {
		from, to = to, from
	}
	return NetworkEvent{Timestamp: from, EndTime: to, EventType: EventGap, Reason: reason, EventCount: count, Interface: iface}
}

// CollectorStatus is the latest health report from a collector, kept centrally so
// a silent collector is visible instead of indistinguishable from a quiet one.
type CollectorStatus struct {
	CollectorID         string `gorm:"primaryKey"`
	Version             string
	ReportedAt          time.Time
	ReceivedAt          time.Time `gorm:"index"`
	PendingEvents       int64
	OldestPendingAt     time.Time
	LastAcknowledgedAt  time.Time
	ConsecutiveFailures int64
	LastError           string
	StorageBytes        int64
	StorageLimitBytes   int64
	DiscardedEvents     int64 // Cumulative events knowingly lost by this collector process.
	MissingEvidence     int64 // Cumulative DNS references forwarded as missing.
	CaptureDrops        int64 // Cumulative kernel packet drops.
	InventoryAgeSeconds int64 // -1 when Kubernetes attribution is disabled.
	PodWatch            bool  // A pod watch stream is connected.
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
