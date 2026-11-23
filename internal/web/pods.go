package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
)

const (
	podConnectionsDefaultLimit = 200
	podConnectionsMaxLimit     = 1000
	podQueryMaxWindow          = 7 * 24 * time.Hour
	podListMaxRows             = 2000
)

// sqliteTimeLayouts covers how the SQLite driver stores time values; aggregate
// results lose the column type and arrive as text.
var sqliteTimeLayouts = []string{"2006-01-02 15:04:05.999999999-07:00", "2006-01-02T15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999", time.RFC3339Nano}

func parseSQLiteTime(value string) time.Time {
	for _, layout := range sqliteTimeLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// timeWindow reads from/to (RFC3339) with a default of the last hour and a
// maximum span, so a single request cannot scan unbounded history.
func timeWindow(r *http.Request, fallback time.Duration) (time.Time, time.Time, error) {
	to := time.Now().UTC()
	from := to.Add(-fallback)
	var err error
	if value := r.URL.Query().Get("to"); value != "" {
		if to, err = time.Parse(time.RFC3339Nano, value); err != nil {
			return from, to, fmt.Errorf("invalid to")
		}
	}
	if value := r.URL.Query().Get("from"); value != "" {
		if from, err = time.Parse(time.RFC3339Nano, value); err != nil {
			return from, to, fmt.Errorf("invalid from")
		}
	} else {
		from = to.Add(-fallback)
	}
	if !from.Before(to) {
		return from, to, fmt.Errorf("from must be before to")
	}
	if to.Sub(from) > podQueryMaxWindow {
		return from, to, fmt.Errorf("window exceeds %s", podQueryMaxWindow)
	}
	return from.UTC(), to.UTC(), nil
}

// PodSummary is a pod observed during the window.
type PodSummary struct {
	Namespace    string    `json:"namespace"`
	Name         string    `json:"name"`
	UID          string    `json:"uid"`
	Workload     string    `json:"workload"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	Egress       int64     `json:"egress"`       // Events where the pod was the source.
	Ingress      int64     `json:"ingress"`      // Events where the pod was the destination.
	EgressBytes  int64     `json:"egressBytes"`  // Bytes (both directions) of connections the pod opened.
	IngressBytes int64     `json:"ingressBytes"` // Bytes (both directions) of connections to the pod.
	Uncertain    int64     `json:"uncertain"`    // Events whose attribution was ambiguous or stale.
	Replacement  bool      `json:"replacement"`  // Another pod with the same name was seen in the window.
}

type podRow struct {
	Namespace, Name, UID, Workload string
	First, Last                    string
	Events, Bytes, Uncertain       int64
}

// podRawMaxWindow bounds the fallback that aggregates raw events while the
// hourly pod summary is still being built; longer windows wait for it.
const podRawMaxWindow = time.Hour

type sidePodRow struct {
	side        string
	row         podRow
	first, last time.Time
}

// handlePods lists pods seen in the window. It reads the hourly pod summary,
// so the window is widened to whole UTC hours and reported back.
func (s *Server) handlePods(w http.ResponseWriter, r *http.Request) {
	from, to, err := timeWindow(r, 24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	namespace := r.URL.Query().Get("namespace")
	status, err := database.PodSummaryStatus(s.db.WithContext(r.Context()))
	if err != nil {
		http.Error(w, "could not read summary state", http.StatusInternalServerError)
		return
	}
	var rows []sidePodRow
	granularity := "hour"
	switch {
	case status.Ready:
		from, to = from.Truncate(time.Hour), to.Add(time.Hour-time.Nanosecond).Truncate(time.Hour)
		rows, err = s.podRowsFromSummary(r, from, to, namespace)
	case to.Sub(from) <= podRawMaxWindow:
		granularity = "event"
		rows, err = s.podRowsFromEvents(r, from, to, namespace)
	default:
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "pod summary is still being built; use a window of at most 1h meanwhile", "aggregation": status})
		return
	}
	if err != nil {
		http.Error(w, "could not list pods", http.StatusInternalServerError)
		return
	}
	pods := map[string]*PodSummary{}
	for _, entry := range rows {
		row := entry.row
		pod := pods[row.UID]
		if pod == nil {
			pod = &PodSummary{Namespace: row.Namespace, Name: row.Name, UID: row.UID, Workload: row.Workload}
			pods[row.UID] = pod
		}
		if pod.Workload == "" {
			pod.Workload = row.Workload
		}
		if pod.FirstSeen.IsZero() || entry.first.Before(pod.FirstSeen) {
			pod.FirstSeen = entry.first
		}
		if entry.last.After(pod.LastSeen) {
			pod.LastSeen = entry.last
		}
		if entry.side == "src" {
			pod.Egress += row.Events
			pod.EgressBytes += row.Bytes
		} else {
			pod.Ingress += row.Events
			pod.IngressBytes += row.Bytes
		}
		pod.Uncertain += row.Uncertain
	}
	names := map[string]int{}
	for _, pod := range pods {
		names[pod.Namespace+"/"+pod.Name]++
	}
	result := make([]PodSummary, 0, len(pods))
	for _, pod := range pods {
		pod.Replacement = names[pod.Namespace+"/"+pod.Name] > 1
		result = append(result, *pod)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Namespace != result[j].Namespace {
			return result[i].Namespace < result[j].Namespace
		}
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].FirstSeen.Before(result[j].FirstSeen)
	})
	truncated := len(result) > podListMaxRows
	if truncated {
		result = result[:podListMaxRows]
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"from": from, "to": to, "granularity": granularity, "truncated": truncated, "pods": result})
}

func (s *Server) podRowsFromSummary(r *http.Request, from, to time.Time, namespace string) ([]sidePodRow, error) {
	query := `SELECT side, uid, MAX(namespace) AS namespace, MAX(name) AS name, MAX(workload) AS workload,
		MIN(first_seen) AS first, MAX(last_seen) AS last, SUM(event_count) AS events, SUM(byte_count) AS bytes, SUM(uncertain) AS uncertain
		FROM hourly_pods WHERE hour >= ? AND hour < ?`
	args := []interface{}{from.Unix(), to.Unix()}
	if namespace != "" {
		query += " AND namespace = ?"
		args = append(args, namespace)
	}
	query += " GROUP BY side, uid LIMIT ?"
	args = append(args, 2*podListMaxRows+1)
	var raw []struct {
		Side, UID, Namespace, Name, Workload  string
		First, Last, Events, Bytes, Uncertain int64
	}
	if err := s.db.WithContext(r.Context()).Raw(query, args...).Scan(&raw).Error; err != nil {
		return nil, err
	}
	rows := make([]sidePodRow, 0, len(raw))
	for _, item := range raw {
		rows = append(rows, sidePodRow{
			side:  item.Side,
			row:   podRow{Namespace: item.Namespace, Name: item.Name, UID: item.UID, Workload: item.Workload, Events: item.Events, Bytes: item.Bytes, Uncertain: item.Uncertain},
			first: time.Unix(0, item.First).UTC(),
			last:  time.Unix(0, item.Last).UTC(),
		})
	}
	return rows, nil
}

func (s *Server) podRowsFromEvents(r *http.Request, from, to time.Time, namespace string) ([]sidePodRow, error) {
	var rows []sidePodRow
	for _, side := range []string{"src", "dst"} {
		query := fmt.Sprintf(`SELECT %[1]s_namespace AS namespace, %[1]s_name AS name, %[1]s_uid AS uid, MAX(%[1]s_workload) AS workload,
			MIN(timestamp) AS first, MAX(timestamp) AS last, COUNT(*) AS events, SUM(COALESCE(byte_count, 0)) AS bytes,
			SUM(CASE WHEN %[1]s_attribution IN ('ambiguous', 'stale') THEN 1 ELSE 0 END) AS uncertain
			FROM network_events WHERE %[1]s_kind = 'pod' AND timestamp >= ? AND timestamp < ?`, side)
		args := []interface{}{from, to}
		if namespace != "" {
			query += " AND " + side + "_namespace = ?"
			args = append(args, namespace)
		}
		query += " GROUP BY " + side + "_uid LIMIT ?"
		args = append(args, podListMaxRows+1)
		var raw []podRow
		if err := s.db.WithContext(r.Context()).Raw(query, args...).Scan(&raw).Error; err != nil {
			return nil, err
		}
		for _, row := range raw {
			rows = append(rows, sidePodRow{side: side, row: row, first: parseSQLiteTime(row.First), last: parseSQLiteTime(row.Last)})
		}
	}
	return rows, nil
}

// Endpoint side of a connection row.
type ConnectionEnd struct {
	IP          string `json:"ip"`
	Port        uint16 `json:"port"`
	Kind        string `json:"kind,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name,omitempty"`
	UID         string `json:"uid,omitempty"`
	Workload    string `json:"workload,omitempty"`
	Attribution string `json:"attribution"` // exact, ambiguous, stale, node, service, legacy or none.
}

// DNSEvidenceRef is a DNS answer that matched the connection at capture time.
type DNSEvidenceRef struct {
	ID           uint      `json:"id"`
	Name         string    `json:"name"`
	TTL          uint32    `json:"ttl"`
	ResponseTime time.Time `json:"responseTime"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Resolver     string    `json:"resolver"`
}

// PodConnection is one observation involving the selected pod or workload.
type PodConnection struct {
	ID          uint             `json:"id"`
	Timestamp   time.Time        `json:"timestamp"`
	Direction   string           `json:"direction"` // egress: the pod is the source; ingress: the destination.
	EventType   string           `json:"eventType"`
	Protocol    string           `json:"protocol"`
	Pod         ConnectionEnd    `json:"pod"`
	Peer        ConnectionEnd    `json:"peer"`
	Hostname    string           `json:"hostname,omitempty"`
	TLSSNI      string           `json:"tlsSni,omitempty"`
	DNSQuery    string           `json:"dnsQuery,omitempty"`
	DNSEvidence []DNSEvidenceRef `json:"dnsEvidence"`
	// DNSEvidenceMissing counts references that could not be forwarded.
	DNSEvidenceMissing int    `json:"dnsEvidenceMissing,omitempty"`
	ByteCount          int64  `json:"byteCount,omitempty"`
	CollectorID        string `json:"collectorId"`
	Interface          string `json:"interface"`
	ProcessCommand     string `json:"processCommand,omitempty"`
	// Verdict is always "unknown": a captured packet is an observation, not
	// proof that a policy allowed or denied it.
	Verdict string `json:"verdict"`
}

// PodConnectionsResponse is served by /api/pod-connections.
type PodConnectionsResponse struct {
	From        time.Time       `json:"from"`
	To          time.Time       `json:"to"`
	Connections []PodConnection `json:"connections"`
	NextCursor  string          `json:"nextCursor,omitempty"`
	Gaps        []GapSummary    `json:"gaps"`
	Notes       []string        `json:"notes"`
}

type cursor struct {
	at time.Time
	id uint
}

func parseCursor(value string) (*cursor, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.SplitN(value, "_", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid cursor")
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	return &cursor{at: time.Unix(0, nanos).UTC(), id: uint(id)}, nil
}

func (s *Server) handlePodConnections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uid, namespace, workload := q.Get("uid"), q.Get("namespace"), q.Get("workload")
	if uid == "" && (namespace == "" || workload == "") {
		http.Error(w, "uid, or namespace and workload, required", http.StatusBadRequest)
		return
	}
	direction := q.Get("direction")
	if direction == "" {
		direction = "both"
	}
	if direction != "both" && direction != "egress" && direction != "ingress" {
		http.Error(w, "direction must be egress, ingress or both", http.StatusBadRequest)
		return
	}
	from, to, err := timeWindow(r, time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limit := podConnectionsDefaultLimit
	if value := q.Get("limit"); value != "" {
		if limit, err = strconv.Atoi(value); err != nil || limit < 1 || limit > podConnectionsMaxLimit {
			http.Error(w, fmt.Sprintf("limit must be 1..%d", podConnectionsMaxLimit), http.StatusBadRequest)
			return
		}
	}
	after, err := parseCursor(q.Get("cursor"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sides := []string{"src", "dst"}
	switch direction {
	case "egress":
		sides = sides[:1]
	case "ingress":
		sides = sides[1:]
	}
	// Each side uses its own (uid, timestamp) or workload index; merging in Go
	// avoids an OR that SQLite would answer with a full scan.
	var events []database.NetworkEvent
	seen := map[uint]bool{}
	for _, side := range sides {
		query := s.db.Where("timestamp >= ? AND timestamp < ? AND event_type <> ?", from, to, database.EventGap)
		if uid != "" {
			query = query.Where(side+"_uid = ?", uid)
		} else {
			query = query.Where(side+"_namespace = ? AND "+side+"_workload = ?", namespace, workload)
		}
		if after != nil {
			query = query.Where("(timestamp, id) < (?, ?)", after.at, after.id)
		}
		var rows []database.NetworkEvent
		if err := query.Order("timestamp DESC, id DESC").Limit(limit + 1).Find(&rows).Error; err != nil {
			http.Error(w, "could not query connections", http.StatusInternalServerError)
			return
		}
		for _, row := range rows {
			if !seen[row.ID] {
				seen[row.ID] = true
				events = append(events, row)
			}
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Timestamp.After(events[j].Timestamp)
		}
		return events[i].ID > events[j].ID
	})
	response := PodConnectionsResponse{From: from, To: to, Connections: []PodConnection{}, Gaps: []GapSummary{}, Notes: []string{
		"Rows are packet observations; verdict is unknown without an enforcement-point source.",
		"A flow captured on several interfaces or nodes appears once per observation.",
		"Attribution is the pod that held the address at capture time; ambiguous rows list alternatives in the raw event context.",
	}}
	if len(events) > limit {
		last := events[limit-1]
		response.NextCursor = fmt.Sprintf("%d_%d", last.Timestamp.UnixNano(), last.ID)
		events = events[:limit]
	}
	evidence, err := s.loadEvidence(events)
	if err != nil {
		http.Error(w, "could not load DNS evidence", http.StatusInternalServerError)
		return
	}
	for _, event := range events {
		egress := (uid != "" && event.SrcUID == uid) || (uid == "" && event.SrcNamespace == namespace && event.SrcWorkload == workload)
		if direction == "ingress" {
			egress = false
		}
		row := PodConnection{ID: event.ID, Timestamp: event.Timestamp, EventType: string(event.EventType), Protocol: eventProtocol(event),
			Hostname: event.Hostname, TLSSNI: event.TLSSNI, DNSQuery: event.DNSQuery, DNSEvidence: []DNSEvidenceRef{},
			DNSEvidenceMissing: event.DNSEvidenceMissing, ByteCount: event.ByteCount, CollectorID: event.CollectorID,
			Interface: event.Interface, ProcessCommand: event.ProcessCommand, Verdict: "unknown"}
		src := ConnectionEnd{IP: event.SrcIP, Port: event.SrcPort, Kind: event.SrcKind, Namespace: event.SrcNamespace, Name: event.SrcName, UID: event.SrcUID, Workload: event.SrcWorkload, Attribution: attributionLabel(event.SrcAttribution, event.SrcKind)}
		dst := ConnectionEnd{IP: event.DstIP, Port: event.DstPort, Kind: event.DstKind, Namespace: event.DstNamespace, Name: event.DstName, UID: event.DstUID, Workload: event.DstWorkload, Attribution: attributionLabel(event.DstAttribution, event.DstKind)}
		if egress {
			row.Direction, row.Pod, row.Peer = "egress", src, dst
		} else {
			row.Direction, row.Pod, row.Peer = "ingress", dst, src
		}
		var ids []uint
		_ = json.Unmarshal([]byte(event.DNSResolutionIDs), &ids)
		for _, id := range ids {
			if e, ok := evidence[id]; ok {
				row.DNSEvidence = append(row.DNSEvidence, e)
			}
		}
		response.Connections = append(response.Connections, row)
	}
	var gaps []database.NetworkEvent
	if err := s.db.Select("collector_id, reason, event_count, timestamp, end_time").
		Where("event_type = ? AND timestamp < ? AND (end_time >= ? OR timestamp >= ?)", database.EventGap, to, from, from).
		Limit(100000).Find(&gaps).Error; err != nil {
		http.Error(w, "could not read gap events", http.StatusInternalServerError)
		return
	}
	response.Gaps = summarizeGaps(gaps)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func attributionLabel(confidence, kind string) string {
	if confidence != "" {
		return confidence
	}
	if kind == "" {
		return "none"
	}
	return "legacy"
}

func eventProtocol(event database.NetworkEvent) string {
	switch {
	case strings.HasPrefix(string(event.EventType), "TCP") || event.EventType == database.EventTLSSNI:
		return "TCP"
	case strings.HasPrefix(string(event.EventType), "UDP"):
		return "UDP"
	case event.EventType == database.EventICMP:
		return "ICMP"
	}
	return event.Protocol
}

func (s *Server) loadEvidence(events []database.NetworkEvent) (map[uint]DNSEvidenceRef, error) {
	ids := map[uint]bool{}
	for _, event := range events {
		var refs []uint
		_ = json.Unmarshal([]byte(event.DNSResolutionIDs), &refs)
		for _, id := range refs {
			ids[id] = true
		}
	}
	result := map[uint]DNSEvidenceRef{}
	if len(ids) == 0 {
		return result, nil
	}
	list := make([]uint, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	for start := 0; start < len(list); start += 500 {
		var rows []database.DNSResolution
		if err := s.db.Where("id IN ?", list[start:min(start+500, len(list))]).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			result[row.ID] = DNSEvidenceRef{ID: row.ID, Name: row.Name, TTL: row.TTL, ResponseTime: row.ResponseTime, ExpiresAt: row.ExpiresAt, Resolver: row.ResolverIP}
		}
	}
	return result, nil
}
