package database

import "time"

// DNSEvent represents a captured DNS query/response
type DNSEvent struct {
	ID         int       `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	DestIP     string    `json:"dest_ip"`
	DomainName string    `json:"domain_name"`
	RecordType string    `json:"record_type"`
	Interface  string    `json:"interface"`
	PacketSize int       `json:"packet_size"`
}

// EventFilter represents filtering options for DNS events
type EventFilter struct {
	Limit     int    `json:"limit"`
	Since     string `json:"since"`     // Time duration like "1h", "24h", "7d"
	IP        string `json:"ip"`        // Filter by IP address
	Domain    string `json:"domain"`    // Filter by domain name
	Interface string `json:"interface"` // Filter by interface
}

// DatabaseStats represents database statistics
type DatabaseStats struct {
	TotalEvents  int       `json:"total_events"`
	OldestEvent  time.Time `json:"oldest_event"`
	NewestEvent  time.Time `json:"newest_event"`
	DatabaseSize int64     `json:"database_size"` // in bytes
}
