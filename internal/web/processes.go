package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
)

// ProcessSummary is one process identity (node, pod, container, command) and
// the flows it opened and accepted in a window. PIDs change across restarts
// and are not part of the identity.
type ProcessSummary struct {
	Collector string `json:"collector"`
	Pod       string `json:"pod"` // namespace/name; empty for host processes
	Namespace string `json:"namespace"`
	Container string `json:"container"`
	Command   string `json:"command"`
	Opened    int64  `json:"opened"`   // Flows it started (it held the source socket).
	Accepted  int64  `json:"accepted"` // Flows it received (it held the destination socket).
	// Bytes total both directions of the flows it opened or accepted.
	OpenedBytes   int64     `json:"openedBytes"`
	AcceptedBytes int64     `json:"acceptedBytes"`
	Events        int64     `json:"events"`
	FirstSeen     time.Time `json:"firstSeen"`
	LastSeen      time.Time `json:"lastSeen"`
}

// ProcessCoverage compares attributed flow starts with all flow starts since
// the first attributed one in the window, so time before attribution was
// enabled does not count. In hourly mode that start is rounded down to the
// hour. Without a namespace filter only.
type ProcessCoverage struct {
	Since           *time.Time `json:"since,omitempty"`
	FlowStarts      int64      `json:"flowStarts"`
	AttributedFlows int64      `json:"attributedFlows"`
}

const processListMaxRows = 2000

var flowStartTypes = []database.EventType{database.EventTCPStart, database.EventUDPStart}

func firstAttributed(rows []processRow) *time.Time {
	var first *time.Time
	for _, row := range rows {
		at := time.Unix(0, row.First).UTC()
		if first == nil || at.Before(*first) {
			first = &at
		}
	}
	return first
}

type processRow struct {
	Collector, Side, Pod, Namespace, Container, Command string
	First, Last                                         int64
	Events, Connections, Bytes                          int64
	// PeerConnections: of Connections, those where the process was the
	// event's peer, whose flows are already counted for the other end.
	PeerConnections int64
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	from, to, err := timeWindow(r, 24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	namespace := r.URL.Query().Get("namespace")
	db := s.db.WithContext(r.Context())
	status, err := database.ProcessSummaryStatus(db)
	if err != nil {
		http.Error(w, "could not read summary state", http.StatusInternalServerError)
		return
	}
	var rows []processRow
	var coverage ProcessCoverage
	granularity := "hour"
	switch {
	case status.Ready:
		from, to = from.Truncate(time.Hour), to.Add(time.Hour-time.Nanosecond).Truncate(time.Hour)
		query := `SELECT collector_id AS collector, side, pod, MAX(namespace) AS namespace, container, command,
			MIN(first_seen) AS first, MAX(last_seen) AS last, SUM(event_count) AS events, SUM(connections) AS connections,
			SUM(peer_connections) AS peer_connections, SUM(byte_count) AS bytes
			FROM hourly_processes WHERE hour >= ? AND hour < ?`
		args := []interface{}{from.Unix(), to.Unix()}
		if namespace != "" {
			query += " AND namespace = ?"
			args = append(args, namespace)
		}
		query += " GROUP BY collector_id, side, pod, container, command LIMIT ?"
		args = append(args, 2*processListMaxRows+1)
		err = db.Raw(query, args...).Scan(&rows).Error
		if since := firstAttributed(rows); err == nil && since != nil && namespace == "" {
			coverage.Since = since
			err = db.Raw(`SELECT COALESCE(SUM(event_count), 0) FROM hourly_events WHERE hour >= ? AND hour < ? AND event_type IN ?`,
				since.Truncate(time.Hour).Unix(), to.Unix(), flowStartTypes).Scan(&coverage.FlowStarts).Error
		}
	case to.Sub(from) <= podRawMaxWindow:
		granularity = "event"
		// Each event counts for its process and, when recorded, the peer
		// process at the other end, as the hourly summary does.
		podFilter, args := "", []interface{}{from, to, from, to}
		if namespace != "" {
			podFilter, args = " AND pod LIKE ?", append(args, namespace+"/%")
		}
		query := `SELECT collector, side, pod, container, command, MIN(timestamp) AS first_text, MAX(timestamp) AS last_text, COUNT(*) AS events,
			SUM(event_type IN ('TCP_START', 'UDP_START')) AS connections, SUM(peer AND event_type IN ('TCP_START', 'UDP_START')) AS peer_connections,
			SUM(COALESCE(byte_count, 0)) AS bytes FROM (
				SELECT collector_id AS collector, process_side AS side, process_pod AS pod, process_container AS container, process_command AS command,
					timestamp, event_type, byte_count, 0 AS peer
				FROM network_events WHERE process_side > '' AND timestamp >= ? AND timestamp < ?
				UNION ALL
				SELECT collector_id, CASE process_side WHEN 'src' THEN 'dst' ELSE 'src' END, peer_process_pod, peer_process_container, peer_process_command,
					timestamp, event_type, byte_count, 1
				FROM network_events WHERE peer_process_command > '' AND process_side > '' AND timestamp >= ? AND timestamp < ?
			) WHERE 1` + podFilter + " GROUP BY collector, side, pod, container, command LIMIT ?"
		args = append(args, 2*processListMaxRows+1)
		var raw []struct {
			Collector, Side, Pod, Container, Command string
			FirstText, LastText                      string
			Events, Connections, PeerConnections     int64
			Bytes                                    int64
		}
		if err = db.Raw(query, args...).Scan(&raw).Error; err == nil {
			for _, item := range raw {
				rows = append(rows, processRow{Collector: item.Collector, Side: item.Side, Pod: item.Pod, Container: item.Container, Command: item.Command,
					First: parseSQLiteTime(item.FirstText).UnixNano(), Last: parseSQLiteTime(item.LastText).UnixNano(),
					Events: item.Events, Connections: item.Connections, PeerConnections: item.PeerConnections, Bytes: item.Bytes})
			}
			if since := firstAttributed(rows); since != nil && namespace == "" {
				coverage.Since = since
				err = db.Raw(`SELECT COUNT(*) FROM network_events WHERE timestamp >= ? AND timestamp < ? AND event_type IN ?`,
					*since, to, flowStartTypes).Scan(&coverage.FlowStarts).Error
			}
		}
	default:
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "process summary is still being built; use a window of at most 1h meanwhile", "aggregation": status})
		return
	}
	if err != nil {
		http.Error(w, "could not list processes", http.StatusInternalServerError)
		return
	}
	processes, attributed := mergeProcessRows(rows)
	coverage.AttributedFlows = attributed
	truncated := len(processes) > processListMaxRows
	if truncated {
		processes = processes[:processListMaxRows]
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"from": from, "to": to, "granularity": granularity, "truncated": truncated,
		"coverage": coverage, "processes": processes})
}

// mergeProcessRows folds the per-side rows of each identity into one summary,
// busiest first, and counts attributed flow starts.
func mergeProcessRows(rows []processRow) ([]ProcessSummary, int64) {
	type key struct{ collector, pod, container, command string }
	merged := map[key]*ProcessSummary{}
	var attributed int64
	for _, row := range rows {
		k := key{row.Collector, row.Pod, row.Container, row.Command}
		p := merged[k]
		first, last := time.Unix(0, row.First).UTC(), time.Unix(0, row.Last).UTC()
		if p == nil {
			namespace, _, _ := strings.Cut(row.Pod, "/")
			p = &ProcessSummary{Collector: row.Collector, Pod: row.Pod, Namespace: namespace, Container: row.Container, Command: row.Command, FirstSeen: first, LastSeen: last}
			merged[k] = p
		}
		if first.Before(p.FirstSeen) {
			p.FirstSeen = first
		}
		if last.After(p.LastSeen) {
			p.LastSeen = last
		}
		p.Events += row.Events
		attributed += row.Connections - row.PeerConnections
		if row.Side == "src" {
			p.Opened += row.Connections
			p.OpenedBytes += row.Bytes
		} else {
			p.Accepted += row.Connections
			p.AcceptedBytes += row.Bytes
		}
	}
	list := make([]ProcessSummary, 0, len(merged))
	for _, p := range merged {
		list = append(list, *p)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Opened+a.Accepted != b.Opened+b.Accepted {
			return a.Opened+a.Accepted > b.Opened+b.Accepted
		}
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.Collector+a.Pod+a.Container+a.Command < b.Collector+b.Pod+b.Container+b.Command
	})
	return list, attributed
}
