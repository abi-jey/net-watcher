package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
// srcIP, dstIP and q (substring of addresses, names, Kubernetes identity or
// process), from, to, limit and cursor.
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
	filter := func(db *gorm.DB) *gorm.DB {
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
		if value := query.Get("q"); value != "" {
			like := "%" + value + "%"
			columns := []string{"src_ip", "dst_ip", "hostname", "dns_query", "tls_sni", "src_name", "dst_name", "src_namespace", "dst_namespace", "src_workload", "dst_workload", "process_command", "process_pod", "process_container"}
			clauses := make([]string, len(columns))
			args := make([]interface{}, len(columns))
			for i, column := range columns {
				clauses[i], args[i] = column+" LIKE ?", like
			}
			db = db.Where("("+strings.Join(clauses, " OR ")+")", args...)
		}
		return db
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
		err := filter(s.db.WithContext(ctx).Table("network_events INDEXED BY idx_network_events_timestamp")).
			// A row value, not "t < ? OR (t = ? AND id < ?)": SQLite plans the OR
			// as a multi-index union and sorts the whole slice before LIMIT.
			Where("timestamp >= ? AND (timestamp, id) < (?, ?)", sliceStart, position.at, position.id).
			Order("timestamp DESC, id DESC").Limit(limit - len(response.Events)).Find(&rows).Error
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
