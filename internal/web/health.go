package web

import (
	"encoding/json"
	"fmt"
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
// Problems repeats the issue titles for older clients.
type CollectorHealth struct {
	database.CollectorStatus
	State    string           `json:"state"`
	Problems []string         `json:"problems"`
	Issues   []CollectorIssue `json:"issues"`
}

// CollectorIssue explains one problem in operator terms: what happened, what
// it means for the record, and what to do. Only critical and warning issues
// change the state; info issues describe loss that is no longer happening.
type CollectorIssue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // critical, warning or info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Action   string `json:"action,omitempty"`
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

// lossRecentWindow decides whether recorded loss still degrades a collector.
// Older loss stays visible as information for the rest of the gap window.
const lossRecentWindow = time.Hour

// gapExplanations describe each GAP reason. Units differ: capture drops count
// packets, the others count events.
var gapExplanations = map[string]struct{ unit, title, detail, action string }{
	database.GapCaptureDrops: {"packets", "The kernel dropped %s packets",
		"The capture ring buffer filled during traffic bursts, so the kernel discarded packets before Net Watcher could read them. Connections seen only in those packets are missing. Each burst is stored as a gap, so the record shows exactly when observation was incomplete.",
		"Occasional bursts are normal on busy nodes. If losses recur, capture less traffic with --interface-exclude, --traffic-exclude or --exclude-ports."},
	database.GapCollectorLimit: {"events", "%s unforwarded events were discarded at the storage limit",
		"The collector's local spool reached --max-collector-db-size-gb while it could not forward, so its oldest unforwarded events were deleted.",
		"Restore delivery to the ingester, or raise --max-collector-db-size-gb if the node has disk space."},
	database.GapRejectedByIngest: {"events", "The ingester rejected %s events as invalid",
		"A batch failed validation; the collector isolated the invalid events and forwarded the rest.",
		"Check the ingester log for the rejection reason; it usually indicates a version mismatch."},
	database.GapWriteFailure: {"events", "%s events were lost before they could be stored",
		"Events arrived faster than the database could write them and the in-memory buffer overflowed.",
		"Check disk latency and free space on the collector's node."},
}

// assessCollector derives a state from a report and the collector's recorded
// gaps. "stale" outranks everything: an old report says nothing reliable about
// current backlog or failures.
func assessCollector(status database.CollectorStatus, gaps []GapSummary, now time.Time) CollectorHealth {
	health := CollectorHealth{CollectorStatus: status, State: "ok", Problems: []string{}, Issues: []CollectorIssue{}}
	add := func(issue CollectorIssue) {
		health.Issues = append(health.Issues, issue)
		health.Problems = append(health.Problems, issue.Title)
	}
	if now.Sub(status.ReceivedAt) > collectorStaleAfter {
		health.State = "stale"
		add(CollectorIssue{Code: "stale", Severity: "critical",
			Title:  "No report since " + status.ReceivedAt.UTC().Format(time.RFC3339),
			Detail: "Collectors report every 30 seconds. The collector may be down, its node offline, or it cannot reach the ingester. Events it captures meanwhile stay in its local spool and are forwarded when it reconnects.",
			Action: "Check the collector pod on this node: kubectl -n net-watcher get pods -o wide"})
		return health
	}
	if status.ConsecutiveFailures > 0 {
		health.State = "failing"
		add(CollectorIssue{Code: "delivery-failing", Severity: "critical",
			Title:  fmt.Sprintf("Forwarding has failed %d times in a row", status.ConsecutiveFailures),
			Detail: "Last error: " + status.LastError + ". Nothing is lost yet: events stay in the collector's spool and are sent in order once delivery recovers.",
			Action: "Check that the ingester is running and reachable, and that the ingest token matches."})
	}
	if !status.OldestPendingAt.IsZero() && status.ReportedAt.Sub(status.OldestPendingAt) > collectorBacklogAfter {
		if health.State == "ok" {
			health.State = "backlog"
		}
		add(CollectorIssue{Code: "backlog", Severity: "warning",
			Title:  "Forwarding is behind by " + status.ReportedAt.Sub(status.OldestPendingAt).Round(time.Second).String(),
			Detail: fmt.Sprintf("%d events wait in the collector's spool; the oldest was captured at %s. The central view is incomplete for that period until they arrive.", status.PendingEvents, status.OldestPendingAt.UTC().Format(time.RFC3339)),
			Action: "Usually clears by itself after an ingester restart. If it keeps growing, check ingester CPU and disk."})
	}
	if status.StorageLimitBytes > 0 && status.StorageBytes > status.StorageLimitBytes*9/10 {
		add(CollectorIssue{Code: "storage", Severity: "warning",
			Title:  "Local storage is above 90% of its limit",
			Detail: "When the spool reaches the limit, the oldest unforwarded events are discarded and recorded as a gap.",
			Action: "Restore forwarding, or raise --max-collector-db-size-gb."})
	}
	if status.InventoryAgeSeconds > int64(inventoryStaleAfter.Seconds()) {
		add(CollectorIssue{Code: "inventory-stale", Severity: "warning",
			Title:  "Kubernetes inventory is stale",
			Detail: fmt.Sprintf("The last successful pod list is %d seconds old. New connections are still recorded, but their pod attribution is marked stale because an address may have moved to another pod.", status.InventoryAgeSeconds),
			Action: "Check the collector log for Kubernetes API errors and its RBAC permissions (pods: list, watch)."})
	} else if status.InventoryAgeSeconds >= 0 && !status.PodWatch {
		add(CollectorIssue{Code: "pod-watch", Severity: "warning",
			Title:  "Pod watch is disconnected",
			Detail: "The collector falls back to listing pods every 30 seconds. If a pod address is reused within that interval, the connection is marked ambiguous instead of attributed.",
			Action: "Usually reconnects by itself. If it persists, check the collector's RBAC permission to watch pods."})
	}
	recorded := false
	for _, gap := range gaps {
		explanation, known := gapExplanations[gap.Reason]
		if !known {
			explanation.unit, explanation.title, explanation.detail = "events", "%s observations were lost ("+gap.Reason+")", "The collector recorded a gap of this kind."
		}
		severity := "info"
		when := "in the last 24 hours, most recently at " + gap.Last.UTC().Format(time.RFC3339) + "."
		if now.Sub(gap.Last) <= lossRecentWindow {
			severity = "warning"
		}
		recorded = true
		add(CollectorIssue{Code: "loss:" + gap.Reason, Severity: severity,
			Title:  fmt.Sprintf(explanation.title, humanCount(gap.Lost)) + fmt.Sprintf(" in %d bursts", gap.Events),
			Detail: explanation.detail + " This happened " + when,
			Action: explanation.action})
	}
	if !recorded && (status.DiscardedEvents > 0 || status.CaptureDrops > 0) {
		add(CollectorIssue{Code: "loss-since-start", Severity: "info",
			Title:  fmt.Sprintf("%s packets dropped and %s events discarded since the collector started", humanCount(status.CaptureDrops), humanCount(status.DiscardedEvents)),
			Detail: "No gap records for this loss arrived in the last 24 hours: it is older, or its gap records are still being forwarded."})
	}
	if health.State == "ok" {
		for _, issue := range health.Issues {
			if issue.Severity != "info" {
				health.State = "degraded"
				break
			}
		}
	}
	return health
}

func humanCount(value int64) string {
	switch {
	case value >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(value)/1e6)
	case value >= 10_000:
		return fmt.Sprintf("%.0fk", float64(value)/1e3)
	default:
		return fmt.Sprint(value)
	}
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
	byCollector := map[string][]GapSummary{}
	for _, gap := range response.Gaps {
		byCollector[gap.CollectorID] = append(byCollector[gap.CollectorID], gap)
	}
	for _, status := range statuses {
		response.Collectors = append(response.Collectors, assessCollector(status, byCollector[status.CollectorID], now))
	}
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
