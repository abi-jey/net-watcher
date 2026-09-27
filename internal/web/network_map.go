package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/abja/net-watcher/internal/kube"
)

type MapNode struct {
	ID, Label, IP, Kind, Scope string
	Context                    kube.Endpoint
}
type MapLink struct {
	ID, Source, Target, Kind, Protocol, Interface, CollectorID string
	Port                                                       uint16
	Events                                                     int
	Bytes                                                      int64
	FirstSeen, LastSeen                                        time.Time
	EvidenceIDs                                                []uint
	SNI                                                        []string
}
type NetworkMap struct {
	Nodes        []MapNode
	Links        []MapLink
	Evidence     []database.DNSResolution
	Namespaces   []string
	Kubernetes   kube.Status
	Since        time.Time
	Truncated    bool
	Observations int
}

func endpointContext(raw string) kube.Endpoint {
	var result kube.Endpoint
	_ = json.Unmarshal([]byte(raw), &result)
	return result
}

func networkNode(ip, context string) MapNode {
	info := endpointContext(context)
	result := MapNode{ID: "ip:" + ip, IP: ip, Label: ip, Kind: "ip", Scope: "external", Context: info}
	if address, err := netip.ParseAddr(ip); err == nil {
		if address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(address) {
			result.Scope = "internal"
		}
	}
	if info.Kind != "" {
		result.Kind, result.Scope = info.Kind, "cluster"
		if info.Name != "" {
			result.Label = info.Name
			if info.Namespace != "" {
				result.Label = info.Namespace + "/" + info.Name
			}
		}
		// Keep historical pod incarnations distinct even when an IP is reused.
		if info.UID != "" {
			result.ID = info.Kind + ":" + info.UID + ":" + ip
		}
	}
	return result
}

func addID(ids []uint, id uint) []uint {
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}

func (s *Server) handleNetworkMap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	window := time.Hour
	if value := r.URL.Query().Get("since"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 || parsed > 24*time.Hour {
			http.Error(w, "since must be between 1ns and 24h", http.StatusBadRequest)
			return
		}
		window = parsed
	}
	limit := 2000
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 5000 {
			http.Error(w, "limit must be 1..5000", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	namespace, ipFilter := r.URL.Query().Get("namespace"), r.URL.Query().Get("ip")
	if ipFilter != "" {
		address, err := netip.ParseAddr(ipFilter)
		if err != nil {
			http.Error(w, "ip must be an IP address", http.StatusBadRequest)
			return
		}
		ipFilter = address.Unmap().String()
	}
	response := NetworkMap{Nodes: []MapNode{}, Links: []MapLink{}, Evidence: []database.DNSResolution{}, Namespaces: []string{}, Since: time.Now().Add(-window)}
	if s.Kubernetes != nil {
		response.Kubernetes = s.Kubernetes.Status()
	}
	var events []database.NetworkEvent
	query := s.db.WithContext(r.Context()).Where("timestamp >= ? AND event_type != ? AND event_type != ?", response.Since, database.EventDNS, database.EventHourlySummary)
	if ipFilter != "" {
		query = query.Where("src_ip = ? OR dst_ip = ?", ipFilter, ipFilter)
	}
	if namespace != "" {
		query = query.Where("(CASE WHEN json_valid(source_context) THEN json_extract(source_context, '$.Namespace') END = ?) OR (CASE WHEN json_valid(destination_context) THEN json_extract(destination_context, '$.Namespace') END = ?)", namespace, namespace)
	}
	if err := query.Order("timestamp DESC").Limit(limit + 1).Find(&events).Error; err != nil {
		http.Error(w, "could not read network observations", http.StatusInternalServerError)
		return
	}
	if len(events) > limit {
		response.Truncated = true
		events = events[:limit]
	}
	var evidence []database.DNSResolution
	evidenceQuery := s.db.WithContext(r.Context()).Where("response_time >= ?", response.Since)
	if ipFilter != "" {
		evidenceQuery = evidenceQuery.Where("client_ip = ? OR ip = ?", ipFilter, ipFilter)
	}
	if namespace != "" {
		evidenceQuery = evidenceQuery.Where("CASE WHEN json_valid(client_context) THEN json_extract(client_context, '$.Namespace') END = ?", namespace)
	}
	if err := evidenceQuery.Order("response_time DESC").Limit(limit + 1).Find(&evidence).Error; err != nil {
		http.Error(w, "could not read DNS evidence", http.StatusInternalServerError)
		return
	}
	if len(evidence) > limit {
		response.Truncated = true
		evidence = evidence[:limit]
	}
	nodes, links := map[string]MapNode{}, map[string]*MapLink{}
	namespaces := map[string]bool{}
	addNodes := func(a, b MapNode) bool {
		needed := 0
		if _, ok := nodes[a.ID]; !ok {
			needed++
		}
		if _, ok := nodes[b.ID]; !ok && a.ID != b.ID {
			needed++
		}
		if len(nodes)+needed > 250 {
			response.Truncated = true
			return false
		}
		nodes[a.ID], nodes[b.ID] = a, b
		return true
	}
	for _, event := range events {
		if event.SrcIP == "" || event.DstIP == "" {
			continue
		}
		src, dst := networkNode(event.SrcIP, event.SourceContext), networkNode(event.DstIP, event.DestinationContext)
		if src.Context.Namespace != "" {
			namespaces[src.Context.Namespace] = true
		}
		if dst.Context.Namespace != "" {
			namespaces[dst.Context.Namespace] = true
		}
		if namespace != "" && src.Context.Namespace != namespace && dst.Context.Namespace != namespace {
			continue
		}
		if !addNodes(src, dst) {
			continue
		}
		protocol := event.Protocol
		switch {
		case strings.HasPrefix(string(event.EventType), "TCP"), event.EventType == database.EventTLSSNI:
			protocol = "TCP"
		case strings.HasPrefix(string(event.EventType), "UDP"):
			protocol = "UDP"
		case event.EventType == database.EventICMP:
			protocol = "ICMP"
		}
		id := fmt.Sprintf("%s>%s/%s/%d/%s/%s", src.ID, dst.ID, protocol, event.DstPort, event.Interface, event.CollectorID)
		link := links[id]
		if link == nil {
			link = &MapLink{ID: id, Source: src.ID, Target: dst.ID, Kind: "connection", Protocol: protocol, Port: event.DstPort, Interface: event.Interface, CollectorID: event.CollectorID, FirstSeen: event.Timestamp, LastSeen: event.Timestamp, EvidenceIDs: []uint{}, SNI: []string{}}
			links[id] = link
		}
		link.Events++
		link.Bytes += event.ByteCount
		if event.Timestamp.Before(link.FirstSeen) {
			link.FirstSeen = event.Timestamp
		}
		if event.Timestamp.After(link.LastSeen) {
			link.LastSeen = event.Timestamp
		}
		var ids []uint
		if json.Unmarshal([]byte(event.DNSResolutionIDs), &ids) == nil {
			for _, id := range ids {
				link.EvidenceIDs = addID(link.EvidenceIDs, id)
			}
		}
		if event.TLSSNI != "" {
			found := false
			for _, name := range link.SNI {
				found = found || name == event.TLSSNI
			}
			if !found {
				link.SNI = append(link.SNI, event.TLSSNI)
			}
		}
		response.Observations++
	}
	for _, record := range evidence {
		client := networkNode(record.ClientIP, record.ClientContext)
		if client.Context.Namespace != "" {
			namespaces[client.Context.Namespace] = true
		}
		if namespace != "" && client.Context.Namespace != namespace {
			continue
		}
		domain := MapNode{ID: "dns:" + client.ID + ":" + record.ResolverIP + ":" + record.Name, Label: record.Name, Kind: "dns", Scope: "dns"}
		address := networkNode(record.IP, record.AddressContext)
		// Reuse an observed destination only if its incarnation is unambiguous.
		var candidates []MapNode
		for _, node := range nodes {
			if node.IP == record.IP {
				candidates = append(candidates, node)
			}
		}
		if len(candidates) == 1 && address.Context.UID == "" {
			address = candidates[0]
		}
		if !addNodes(client, domain) || !addNodes(domain, address) {
			continue
		}
		for _, pair := range []struct{ from, to, kind string }{{client.ID, domain.ID, "dns_query"}, {domain.ID, address.ID, "dns_answer"}} {
			id := pair.kind + ":" + pair.from + ">" + pair.to
			link := links[id]
			if link == nil {
				link = &MapLink{ID: id, Source: pair.from, Target: pair.to, Kind: pair.kind, Protocol: record.Transport, Port: record.ResolverPort, FirstSeen: record.QueryTime, LastSeen: record.ResponseTime, EvidenceIDs: []uint{}, SNI: []string{}}
				links[id] = link
			}
			link.Events++
			link.EvidenceIDs = addID(link.EvidenceIDs, record.ID)
			if record.QueryTime.Before(link.FirstSeen) {
				link.FirstSeen = record.QueryTime
			}
			if record.ResponseTime.After(link.LastSeen) {
				link.LastSeen = record.ResponseTime
			}
		}
		response.Evidence = append(response.Evidence, record)
	}
	for _, node := range nodes {
		response.Nodes = append(response.Nodes, node)
	}
	for _, link := range links {
		response.Links = append(response.Links, *link)
	}
	for name := range namespaces {
		response.Namespaces = append(response.Namespaces, name)
	}
	sort.Slice(response.Nodes, func(i, j int) bool { return response.Nodes[i].ID < response.Nodes[j].ID })
	sort.Slice(response.Links, func(i, j int) bool { return response.Links[i].ID < response.Links[j].ID })
	sort.Strings(response.Namespaces)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDNSEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(r.URL.Query().Get("ids"), ",")
	if len(parts) > 100 {
		http.Error(w, "at most 100 evidence IDs", http.StatusBadRequest)
		return
	}
	ids := make([]uint64, 0, len(parts))
	for _, value := range parts {
		id, err := strconv.ParseUint(value, 10, 64)
		if err != nil || id == 0 {
			http.Error(w, "positive evidence IDs required", http.StatusBadRequest)
			return
		}
		ids = append(ids, id)
	}
	rows := []database.DNSResolution{}
	if err := s.db.WithContext(r.Context()).Where("id IN ?", ids).Order("response_time DESC").Find(&rows).Error; err != nil {
		http.Error(w, "could not read DNS evidence", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(rows)
}
