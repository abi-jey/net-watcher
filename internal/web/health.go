package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/abja/net-watcher/internal/database"
)

// Thresholds for flagging collectors. They are deliberately loose: the goal is
// to surface a stalled or lossy collector within minutes, not to page on noise.
const (
	collectorStaleAfter   = 2 * time.Minute
	collectorBacklogAfter = 5 * time.Minute
	inventoryStaleAfter   = 90 * time.Second
)

// CollectorHealth is one collector's latest report plus derived problems.
type CollectorHealth struct {
	database.CollectorStatus
	State    string   `json:"state"`
	Problems []string `json:"problems"`
}

// GapSummary totals GAP events by collector and reason over the window.
type GapSummary struct {
	CollectorID string    `json:"collectorId"`
	Reason      string    `json:"reason"`
	Events      int64     `json:"events"`
	Lost        int64     `json:"lost"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
}

// HealthResponse is served by /api/collectors.
type HealthResponse struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Collectors  []CollectorHealth `json:"collectors"`
	Gaps        []GapSummary      `json:"gaps"`
	WindowHours int               `json:"windowHours"`
}

// assessCollector derives a state from a report. "stale" outranks everything:
// an old report says nothing reliable about current backlog or failures.
func assessCollector(status database.CollectorStatus, now time.Time) CollectorHealth {
	health := CollectorHealth{CollectorStatus: status, State: "ok", Problems: []string{}}
	if now.Sub(status.ReceivedAt) > collectorStaleAfter {
		health.State = "stale"
		health.Problems = append(health.Problems, "no report since "+status.ReceivedAt.UTC().Format(time.RFC3339))
		return health
	}
	if status.ConsecutiveFailures > 0 {
		health.State = "failing"
		health.Problems = append(health.Problems, "delivery failing: "+status.LastError)
	}
	if !status.OldestPendingAt.IsZero() && status.ReportedAt.Sub(status.OldestPendingAt) > collectorBacklogAfter {
		if health.State == "ok" {
			health.State = "backlog"
		}
		health.Problems = append(health.Problems, "oldest unforwarded event from "+status.OldestPendingAt.UTC().Format(time.RFC3339))
	}
	if status.StorageLimitBytes > 0 && status.StorageBytes > status.StorageLimitBytes*9/10 {
		health.Problems = append(health.Problems, "storage above 90% of limit")
	}
	if status.InventoryAgeSeconds > int64(inventoryStaleAfter.Seconds()) {
		health.Problems = append(health.Problems, "Kubernetes inventory stale; pod attribution unavailable")
	}
	if status.DiscardedEvents > 0 || status.CaptureDrops > 0 {
		health.Problems = append(health.Problems, "observations lost since collector start; see gaps")
	}
	if health.State == "ok" && len(health.Problems) > 0 {
		health.State = "degraded"
	}
	return health
}

func (s *Server) handleCollectors(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	window := 24
	var statuses []database.CollectorStatus
	if err := s.db.Order("collector_id").Find(&statuses).Error; err != nil {
		http.Error(w, "could not read collector status", http.StatusInternalServerError)
		return
	}
	response := HealthResponse{GeneratedAt: now, Collectors: make([]CollectorHealth, 0, len(statuses)), Gaps: []GapSummary{}, WindowHours: window}
	for _, status := range statuses {
		response.Collectors = append(response.Collectors, assessCollector(status, now))
	}
	// Aggregates lose SQLite's column type, so spans are computed per row.
	var gaps []database.NetworkEvent
	err := s.db.Select("collector_id, reason, event_count, timestamp, end_time").
		Where("event_type = ? AND timestamp >= ?", database.EventGap, now.Add(-time.Duration(window)*time.Hour)).
		Order("timestamp").Limit(100000).Find(&gaps).Error
	if err != nil {
		http.Error(w, "could not read gap events", http.StatusInternalServerError)
		return
	}
	response.Gaps = summarizeGaps(gaps)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func summarizeGaps(gaps []database.NetworkEvent) []GapSummary {
	index := map[[2]string]int{}
	summaries := []GapSummary{}
	for _, gap := range gaps {
		key := [2]string{gap.CollectorID, gap.Reason}
		end := gap.Timestamp
		if gap.EndTime.After(end) {
			end = gap.EndTime
		}
		position, ok := index[key]
		if !ok {
			position = len(summaries)
			index[key] = position
			summaries = append(summaries, GapSummary{CollectorID: gap.CollectorID, Reason: gap.Reason, First: gap.Timestamp, Last: end})
		}
		summary := &summaries[position]
		summary.Events++
		summary.Lost += gap.EventCount
		if gap.Timestamp.Before(summary.First) {
			summary.First = gap.Timestamp
		}
		if end.After(summary.Last) {
			summary.Last = end
		}
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Last.After(summaries[j].Last) })
	return summaries
}
