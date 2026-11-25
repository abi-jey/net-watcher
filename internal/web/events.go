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
// at most 7 days) with keyset pagination: from, to, limit and cursor. f is a
// filter expression (filter.go); the older one-value parameters (eventType,
// srcIP, dstIP, q, collector, iface, ifaceRole, ipVersion, withProcess,
// srcKind, dstKind, namespace, port, route and a process identity) still
// work and must hold as well.
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
	filter, err := eventsRequestFilter(query)
	if err != nil {
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
		err := eventsSlice(s.db.WithContext(ctx), filter, sliceStart, position, limit-len(response.Events)).Find(&rows).Error
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

// eventsRequestFilter reads a request's filter: the expression in f and the
// older one-value parameters, all of which must hold.
func eventsRequestFilter(query url.Values) (*expr, error) {
	parsed, err := parseFilter(query.Get("f"))
	if err != nil {
		return nil, err
	}
	var terms []*expr
	add := func(param, name, op string, values ...string) error {
		canonical, field, _ := lookupField(name)
		term, err := newCompare(canonical, field, op, values, 0)
		if err != nil {
			var filterError *FilterError
			if errors.As(err, &filterError) {
				return fmt.Errorf("%s: %s", param, filterError.Message)
			}
			return err
		}
		terms = append(terms, term)
		return nil
	}
	for _, legacy := range []struct{ param, field, op string }{
		{"srcIP", "src.ip", "~"}, {"dstIP", "dst.ip", "~"}, {"collector", "node", "="}, {"iface", "iface", "="}, {"ifaceRole", "iface.type", "="},
		{"ipVersion", "ipv", "="}, {"srcKind", "src.kind", "="}, {"dstKind", "dst.kind", "="}, {"namespace", "ns", "="}, {"port", "port", "="},
	} {
		if value := query.Get(legacy.param); value != "" {
			if err := add(legacy.param, legacy.field, legacy.op, value); err != nil {
				return nil, err
			}
		}
	}
	if value := query.Get("eventType"); value != "" {
		if err := add("eventType", "type", "=", strings.Split(value, ",")...); err != nil {
			return nil, err
		}
	}
	// An exact process identity, as listed by /api/processes; an empty pod
	// selects host processes.
	if value := query.Get("process"); value != "" {
		identity, err := processIdentityFilter(value, orNone(query.Get("processPod")), orNone(query.Get("processContainer")))
		if err != nil {
			return nil, fmt.Errorf("process: %w", err)
		}
		terms = append(terms, identity)
	}
	switch value := query.Get("withProcess"); value {
	case "":
	case "yes", "no":
		op := map[string]string{"yes": "!=", "no": "="}[value]
		if err := add("withProcess", "process.side", op, "none"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("withProcess must be yes or no")
	}
	switch value := query.Get("route"); value {
	case "":
	case "any":
		if err := add("route", "route", "!=", "none"); err != nil {
			return nil, err
		}
	default:
		if err := add("route", "route", "=", value); err != nil {
			return nil, err
		}
	}
	if text := query.Get("q"); text != "" {
		terms = append(terms, &expr{kind: exprText, raw: []string{text}, norm: []value{{text: text}}})
	}
	return andFilters(append(terms, parsed)...), nil
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

// processIdentityFilter selects connections where the process at one end
// has this command, pod and container: all three hold at the same end, so a
// host process is not matched by a connection whose other end is a pod.
func processIdentityFilter(command, pod, container string) (*expr, error) {
	var ends []*expr
	for _, end := range []string{"src.", "dst."} {
		var terms []*expr
		for _, c := range [][2]string{{"process", command}, {"process.pod", pod}, {"process.container", container}} {
			name, field, _ := lookupField(end + c[0])
			term, err := newCompare(name, field, "=", []string{c[1]}, 0)
			if err != nil {
				return nil, err
			}
			terms = append(terms, term)
		}
		ends = append(ends, join(exprAnd, terms))
	}
	return join(exprOr, ends), nil
}

// processIdentity finds a condition that pins one end's process to a single
// command, pod and container: src. or dst. comparisons of all three with one
// value each, among the top-level conditions or as the alternatives of an
// "or" (as processIdentityFilter writes it) that all name the same identity.
func processIdentity(conditions []*expr) ([3]string, bool) {
	bound := func(terms []*expr) ([3]string, bool) {
		for _, end := range []string{"src.", "dst."} {
			var identity [3]string
			found := 0
			for i, name := range []string{"process", "process.pod", "process.container"} {
				for _, c := range terms {
					if c.kind == exprCompare && c.name == end+name && c.op == "=" && len(c.norm) == 1 {
						identity[i] = c.norm[0].text
						found++
						break
					}
				}
			}
			if found == 3 && identity[0] != "" {
				return identity, true
			}
		}
		return [3]string{}, false
	}
	if identity, ok := bound(conditions); ok {
		return identity, true
	}
	for _, c := range conditions {
		if c.kind != exprOr {
			continue
		}
		var identity [3]string
		ok := true
		for i, alternative := range c.terms {
			terms := []*expr{alternative}
			if alternative.kind == exprAnd {
				terms = alternative.terms
			}
			found, matched := bound(terms)
			if !matched || (i > 0 && found != identity) {
				ok = false
				break
			}
			identity = found
		}
		if ok {
			return identity, true
		}
	}
	return [3]string{}, false
}

// eventsPart is one index walk of a page: the index and the conditions that
// let SQLite read it in time order.
type eventsPart struct {
	index, where string
	args         []any
}

// maxNamespaceWalks bounds the index walks a namespace list makes.
const maxNamespaceWalks = 8

// eventsParts chooses the indexes a page walks, newest first, from the
// filter's top-level conditions. A process identity at one end walks the
// partial indexes of recorded processes and peer processes; one Tailscale
// route walks a partial index holding only those rows in time order. Namespaces
// walk each side's (namespace, time) index, which lists only their events:
// walking all events by time would read a quiet namespace's whole window.
// Anything else walks all events by time.
func eventsParts(filter *expr) []eventsPart {
	conditions := []*expr{filter}
	if filter == nil {
		conditions = nil
	} else if filter.kind == exprAnd {
		conditions = filter.terms
	}
	single := func(name string) (string, bool) {
		for _, c := range conditions {
			if c.kind == exprCompare && c.name == name && c.op == "=" && len(c.norm) == 1 {
				return c.norm[0].text, true
			}
		}
		return "", false
	}
	if id, ok := processIdentity(conditions); ok {
		// The identity is at the end the filter names; either column pair may
		// hold it. Rows whose recorded process has it come from the first walk.
		return []eventsPart{
			{"idx_process_time", "process_command = ? AND process_pod = ? AND process_container = ? AND process_side > ''", []any{id[0], id[1], id[2]}},
			{"idx_peer_process_time", "peer_process_command = ? AND peer_process_pod = ? AND peer_process_container = ? AND peer_process_command > ''" +
				" AND NOT (COALESCE(process_command, '') = ? AND COALESCE(process_pod, '') = ? AND COALESCE(process_container, '') = ?)",
				[]any{id[0], id[1], id[2], id[0], id[1], id[2]}},
		}
	}
	if route, ok := single("route"); ok && route != "" {
		return []eventsPart{{"idx_route_time", "route = ? AND route > ''", []any{route}}} // The second term lets SQLite use the partial index.
	}
	for _, c := range conditions {
		if c.kind != exprCompare || c.op != "=" || len(c.norm) > maxNamespaceWalks || (c.name != "ns" && c.name != "src.ns" && c.name != "dst.ns") {
			continue
		}
		namespaces := make([]any, 0, len(c.norm))
		for _, v := range c.norm {
			if v.text != "" {
				namespaces = append(namespaces, v.text)
			}
		}
		if len(namespaces) < len(c.norm) {
			continue // Unset namespaces are not in the indexes' useful part.
		}
		var parts []eventsPart
		for _, namespace := range namespaces {
			if c.name != "dst.ns" {
				parts = append(parts, eventsPart{"idx_src_namespace_time", "src_namespace = ?", []any{namespace}})
			}
			switch c.name {
			case "dst.ns":
				parts = append(parts, eventsPart{"idx_dst_namespace_time", "dst_namespace = ?", []any{namespace}})
			case "ns":
				// Either end: events whose source is listed came from the
				// source walks.
				parts = append(parts, eventsPart{"idx_dst_namespace_time", "dst_namespace = ? AND COALESCE(src_namespace, '') NOT IN (" + placeholders(len(namespaces)) + ")",
					append([]any{namespace}, namespaces...)})
			}
		}
		return parts
	}
	return []eventsPart{{index: "idx_network_events_timestamp"}}
}

// eventsSlice selects one time slice of a page, newest first, before position.
func eventsSlice(db *gorm.DB, filter *expr, sliceStart time.Time, position cursor, limit int) *gorm.DB {
	var where string
	var args []any
	if filter != nil {
		where, args = filter.sql()
	}
	walk := func(tx *gorm.DB, part eventsPart) *gorm.DB {
		tx = tx.Table("network_events INDEXED BY " + part.index)
		if part.where != "" {
			tx = tx.Where(part.where, part.args...)
		}
		if where != "" {
			tx = tx.Where(where, args...)
		}
		return eventsWalk(tx, sliceStart, position, limit)
	}
	parts := eventsParts(filter)
	if len(parts) == 1 {
		return walk(db, parts[0])
	}
	// Each part starts its own statement on the caller's connection; the
	// newest of all make the page.
	session := func() *gorm.DB { return db.Session(&gorm.Session{NewDB: true}) }
	selects := make([]string, len(parts))
	walks := make([]any, len(parts))
	for i, part := range parts {
		selects[i], walks[i] = "SELECT * FROM (?)", walk(session(), part)
	}
	return session().Table("("+strings.Join(selects, " UNION ALL ")+") AS network_events", walks...).Order("timestamp DESC, id DESC").Limit(limit)
}

func eventsWalk(db *gorm.DB, sliceStart time.Time, position cursor, limit int) *gorm.DB {
	// A row value, not "t < ? OR (t = ? AND id < ?)": SQLite plans the OR
	// as a multi-index union and sorts the whole slice before LIMIT.
	return db.Where("timestamp >= ? AND (timestamp, id) < (?, ?)", sliceStart, position.at, position.id).
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
