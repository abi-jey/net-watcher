package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"gorm.io/gorm"
)

const (
	eventsDefaultLimit  = 50
	eventsMaxLimit      = 200
	eventsDefaultWindow = 24 * time.Hour
	// eventsScanBudget bounds the database time one request may spend. A
	// substring search cannot use an index, so it walks the timestamp index
	// newest first in slices and stops at the budget, returning where it got to.
	eventsScanBudget = 3 * time.Second
	eventsFirstSlice = 15 * time.Minute
	eventsMaxSlice   = 2 * time.Hour
)

// EventsResponse is one page of events, newest first. When Complete is false,
// NextCursor continues the search; SearchedFrom is the oldest time fully
// searched so far, so partial results are never mistaken for "no matches".
type EventsResponse struct {
	Events       []database.NetworkEvent `json:"events"`
	From         time.Time               `json:"from"`
	To           time.Time               `json:"to"`
	SearchedFrom time.Time               `json:"searchedFrom"`
	Complete     bool                    `json:"complete"`
	NextCursor   string                  `json:"nextCursor,omitempty"`
}

// handleEvents pages through events in a bounded time window (default 24 h,
// at most 7 days) with keyset pagination. Filters: eventType (comma list),
// srcIP, dstIP and q (substrings of addresses, names, Kubernetes identity or
// process); collector, iface, ifaceRole, ipVersion, withProcess, srcKind,
// dstKind, namespace, port and route (exact; route "any" for every Tailscale
// route); an exact process identity; from, to, limit and cursor.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	from, to, err := timeWindow(r, eventsDefaultWindow)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limit := eventsDefaultLimit
	if value := query.Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > eventsMaxLimit {
			http.Error(w, fmt.Sprintf("limit must be 1..%d", eventsMaxLimit), http.StatusBadRequest)
			return
		}
	}
	if err := validateEventFilters(query); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	position := cursor{at: to}
	if after, err := parseCursor(query.Get("cursor")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if after != nil {
		if after.at.After(to) || after.at.Before(from) {
			http.Error(w, "cursor outside window", http.StatusBadRequest)
			return
		}
		position = *after
	}
	response := EventsResponse{Events: []database.NetworkEvent{}, From: from, To: to}
	started := time.Now()
	slice := eventsFirstSlice
	for first := true; ; first = false {
		sliceStart := position.at.Add(-slice)
		if sliceStart.Before(from) {
			sliceStart = from
		}
		ctx := r.Context()
		if !first {
			// Later slices are cut off at the budget; the first always runs so
			// every request makes progress.
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, started.Add(eventsScanBudget+time.Second))
			defer cancel()
		}
		var rows []database.NetworkEvent
		err := eventsSlice(s.db.WithContext(ctx), query, sliceStart, position, limit-len(response.Events)).Find(&rows).Error
		if err != nil {
			if r.Context().Err() == nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
				break // Budget spent inside this slice; resume from the last full slice.
			}
			http.Error(w, "could not read events", http.StatusServiceUnavailable)
			return
		}
		response.Events = append(response.Events, rows...)
		if len(response.Events) == limit {
			last := response.Events[len(response.Events)-1]
			position = cursor{at: last.Timestamp.UTC(), id: last.ID}
			break
		}
		position = cursor{at: sliceStart}
		if !sliceStart.After(from) {
			response.Complete = true
			break
		}
		if time.Since(started) >= eventsScanBudget {
			break
		}
		if len(rows) == 0 && slice < eventsMaxSlice {
			slice = min(slice*2, eventsMaxSlice)
		}
	}
	response.SearchedFrom = position.at
	if !response.Complete {
		response.NextCursor = fmt.Sprintf("%d_%d", position.at.UnixNano(), position.id)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// eventsFilter applies the request's filters to an events query.
func eventsFilter(query url.Values, db *gorm.DB) *gorm.DB {
	if value := query.Get("eventType"); value != "" {
		db = db.Where("event_type IN ?", strings.Split(value, ","))
	}
	if value := query.Get("srcIP"); value != "" {
		db = db.Where("src_ip LIKE ?", "%"+value+"%")
	}
	if value := query.Get("dstIP"); value != "" {
		db = db.Where("dst_ip LIKE ?", "%"+value+"%")
	}
	// Exact process identity, as listed by /api/processes. An empty pod
	// selects host processes once a command is given.
	if value := query.Get("process"); value != "" {
		db = db.Where("process_command = ? AND process_pod = ? AND process_container = ? AND process_side > ''", value, query.Get("processPod"), query.Get("processContainer"))
	}
	if value := query.Get("collector"); value != "" {
		db = db.Where("collector_id = ?", value)
	}
	if value := query.Get("iface"); value != "" {
		db = db.Where("interface = ?", value)
	}
	if role, ok := interfaceRoles[query.Get("ifaceRole")]; ok {
		db = db.Where(globClause(role.match, " OR "), globArgs(role.match)...)
		if len(role.except) > 0 {
			db = db.Where("NOT "+globClause(role.except, " OR "), globArgs(role.except)...)
		}
	}
	if value := query.Get("ipVersion"); value != "" {
		db = db.Where("ip_version = ?", value)
	}
	switch query.Get("withProcess") {
	case "yes":
		db = db.Where("process_side > ''")
	case "no":
		db = db.Where("COALESCE(process_side, '') = ''")
	}
	for _, side := range []string{"src", "dst"} {
		switch value := query.Get(side + "Kind"); value {
		case "":
		case "none":
			db = db.Where("COALESCE(" + side + "_kind, '') = ''")
		default:
			db = db.Where(side+"_kind = ?", value)
		}
	}
	if value := query.Get("namespace"); value != "" {
		db = db.Where("(src_namespace = ? OR dst_namespace = ?)", value, value)
	}
	if value := query.Get("port"); value != "" {
		db = db.Where("(src_port = ? OR dst_port = ?)", value, value)
	}
	switch value := query.Get("route"); value {
	case "":
	case "any":
		db = db.Where("route > ''")
	default:
		db = db.Where("route = ? AND route > ''", value) // The second term lets SQLite use the partial index.
	}
	if value := query.Get("q"); value != "" {
		like := "%" + value + "%"
		columns := []string{"src_ip", "dst_ip", "hostname", "dns_query", "tls_sni", "src_name", "dst_name", "src_namespace", "dst_namespace", "src_workload", "dst_workload", "process_command", "process_pod", "process_container", "tailnet_peer", "tailnet_peer_name"}
		clauses := make([]string, len(columns))
		args := make([]interface{}, len(columns))
		for i, column := range columns {
			clauses[i], args[i] = column+" LIKE ?", like
		}
		db = db.Where("("+strings.Join(clauses, " OR ")+")", args...)
	}
	return db
}

// eventsIndex is the index a page walks, newest first. A process drill-down
// or one Tailscale route walks a partial index holding only those rows in
// time order; other filters walk all events by time.
func eventsIndex(query url.Values) string {
	if query.Get("process") != "" {
		return "idx_process_time"
	}
	if route := query.Get("route"); route != "" && route != "any" {
		return "idx_route_time"
	}
	return "idx_network_events_timestamp"
}

// eventsSlice selects one time slice of a page, newest first, before position.
func eventsSlice(db *gorm.DB, query url.Values, sliceStart time.Time, position cursor, limit int) *gorm.DB {
	return eventsFilter(query, db.Table("network_events INDEXED BY "+eventsIndex(query))).
		// A row value, not "t < ? OR (t = ? AND id < ?)": SQLite plans the OR
		// as a multi-index union and sorts the whole slice before LIMIT.
		Where("timestamp >= ? AND (timestamp, id) < (?, ?)", sliceStart, position.at, position.id).
		Order("timestamp DESC, id DESC").Limit(limit)
}

// interfaceRoles groups interface names by what they connect, as the UI
// labels them (web/src/lib/network.ts): GLOB patterns, minus exceptions.
var interfaceRoles = map[string]struct{ match, except []string }{
	"pod":          {match: []string{"lxc*", "veth*", "cali*", "azv*", "eni*"}},
	"overlay":      {match: []string{"cilium_vxlan*", "cilium_geneve*", "flannel.*", "vxlan*", "genev*"}},
	"cluster-host": {match: []string{"cilium_host*", "cilium_net*"}},
	"tailscale":    {match: []string{"tailscale*", "ts[0-9]*"}},
	"wireguard":    {match: []string{"wg*"}},
	"bridge":       {match: []string{"docker*", "br-*", "cni*", "virbr*", "kube-bridge*"}},
	"wifi":         {match: []string{"wl*"}},
	"uplink":       {match: []string{"en*", "eth*", "bond*"}, except: []string{"eni*"}},
	"tunnel":       {match: []string{"tun*", "tap*"}},
	"loopback":     {match: []string{"lo"}},
}

func globClause(patterns []string, join string) string {
	clauses := make([]string, len(patterns))
	for i := range patterns {
		clauses[i] = "interface GLOB ?"
	}
	return "(" + strings.Join(clauses, join) + ")"
}

func globArgs(patterns []string) []interface{} {
	args := make([]interface{}, len(patterns))
	for i, pattern := range patterns {
		args[i] = pattern
	}
	return args
}

var routes = map[string]bool{"exit-node": true, "subnet-router": true, "via-tailnet": true, "any": true}

var endpointKinds = map[string]bool{"pod": true, "node": true, "service": true, "endpoint": true, "none": true}

// validateEventFilters rejects filter values that would silently match
// nothing, so a typo is not mistaken for "no such traffic".
func validateEventFilters(query url.Values) error {
	if value := query.Get("ifaceRole"); value != "" {
		if _, ok := interfaceRoles[value]; !ok {
			return fmt.Errorf("unknown ifaceRole %q", value)
		}
	}
	if value := query.Get("ipVersion"); value != "" && value != "4" && value != "6" {
		return fmt.Errorf("ipVersion must be 4 or 6")
	}
	if value := query.Get("withProcess"); value != "" && value != "yes" && value != "no" {
		return fmt.Errorf("withProcess must be yes or no")
	}
	for _, key := range []string{"srcKind", "dstKind"} {
		if value := query.Get(key); value != "" && !endpointKinds[value] {
			return fmt.Errorf("%s must be pod, node, service, endpoint or none", key)
		}
	}
	if value := query.Get("route"); value != "" && !routes[value] {
		return fmt.Errorf("route must be exit-node, subnet-router, via-tailnet or any")
	}
	if value := query.Get("port"); value != "" {
		if port, err := strconv.Atoi(value); err != nil || port < 0 || port > 65535 {
			return fmt.Errorf("port must be 0..65535")
		}
	}
	return nil
}
