package web

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"gorm.io/gorm"
)

func processFlow(at time.Time, eventType database.EventType, collector, side, pod, container, command string, bytes int64) database.NetworkEvent {
	return database.NetworkEvent{Timestamp: at, EventType: eventType, SrcIP: "10.0.0.7", SrcPort: 40000, DstIP: "10.0.0.9", DstPort: 443, CollectorID: collector,
		ByteCount: bytes, ProcessPID: 7, ProcessCommand: command, ProcessSide: side, ProcessPod: pod, ProcessContainer: container}
}

// The hourly summary and the raw fallback report the same processes, and
// coverage compares attributed flow starts with all flow starts.
func TestProcessListSummaryMatchesRawEvents(t *testing.T) {
	type result struct {
		Coverage  ProcessCoverage
		Processes []ProcessSummary
	}
	var results [2]result
	// Both stores get the same events: summaries are hourly, coverage starts
	// at the earliest one, and fixtures reading the clock separately can fall
	// in different seconds.
	now := time.Now().UTC().Truncate(time.Second)
	for i, summaries := range []bool{true, false} {
		f := newPodFixtureWith(t, summaries)
		f.now = now
		var events []database.NetworkEvent
		for n := 0; n < 20; n++ {
			at := f.now.Add(-time.Duration(n+1) * time.Minute)
			events = append(events,
				processFlow(at, database.EventTCPStart, "node-a", "src", "demo/api-1", "api", "python3", 0),
				processFlow(at.Add(time.Second), database.EventTCPEnd, "node-a", "src", "demo/api-1", "api", "python3", 1500),
				processFlow(at, database.EventTCPStart, "node-a", "dst", "demo/db-0", "postgres", "postgres", 0),
				processFlow(at.Add(time.Second), database.EventTCPEnd, "node-a", "dst", "demo/db-0", "postgres", "postgres", 1500),
				database.NetworkEvent{Timestamp: at, EventType: database.EventUDPStart, SrcIP: "10.0.0.3", DstIP: "1.1.1.1", CollectorID: "node-a"},
			)
			if n%4 == 0 {
				events = append(events, processFlow(at, database.EventUDPStart, "node-b", "src", "", "", "tailscaled", 0))
			}
		}
		if err := f.writer.InsertBatch(events); err != nil {
			t.Fatal(err)
		}
		params := url.Values{"from": {f.now.Add(-time.Hour).Format(time.RFC3339)}, "to": {f.now.Add(2 * time.Second).Format(time.RFC3339)}}
		if code := f.get(t, "/api/processes", params, &results[i]); code != 200 {
			t.Fatalf("summaries=%v status %d", summaries, code)
		}
		if code := f.get(t, "/api/processes", url.Values{"namespace": {"demo"}, "from": params["from"], "to": params["to"]}, &results[i]); code != 200 || len(results[i].Processes) != 2 {
			t.Fatalf("namespace filter: %d %+v", code, results[i].Processes)
		}
		if code := f.get(t, "/api/processes", params, &results[i]); code != 200 {
			t.Fatal(code)
		}
		if !summaries {
			if code := f.get(t, "/api/processes", url.Values{}, nil); code != 503 {
				t.Fatalf("24h window without summary: status %d", code)
			}
		}
		// Filtering events by an exact process identity.
		var page EventsResponse
		if code := f.get(t, "/api/events", url.Values{"process": {"postgres"}, "processPod": {"demo/db-0"}, "processContainer": {"postgres"}}, &page); code != 200 || len(page.Events) != 40 {
			t.Fatalf("events for one process: %d, %d rows", code, len(page.Events))
		}
	}
	summary, raw := results[0], results[1]
	if len(summary.Processes) != 3 || len(raw.Processes) != 3 {
		t.Fatalf("processes: summary %+v raw %+v", summary.Processes, raw.Processes)
	}
	for i, got := range summary.Processes {
		want := raw.Processes[i]
		if got.Command != want.Command || got.Opened != want.Opened || got.Accepted != want.Accepted || got.OpenedBytes != want.OpenedBytes ||
			got.AcceptedBytes != want.AcceptedBytes || got.Events != want.Events || got.Namespace != want.Namespace ||
			!got.FirstSeen.Equal(want.FirstSeen) || !got.LastSeen.Equal(want.LastSeen) {
			t.Fatalf("row %d: summary %+v raw %+v", i, got, want)
		}
	}
	if p := summary.Processes[0]; p.Command != "postgres" && p.Command != "python3" {
		t.Fatalf("busiest first: %+v", summary.Processes)
	}
	pg := summary.Processes[0]
	if pg.Command != "postgres" {
		pg = summary.Processes[1]
	}
	if pg.Accepted != 20 || pg.Opened != 0 || pg.AcceptedBytes != 30000 || pg.Pod != "demo/db-0" || pg.Container != "postgres" {
		t.Fatalf("postgres row %+v", pg)
	}
	if summary.Coverage.Since == nil || raw.Coverage.Since == nil || !summary.Coverage.Since.Equal(*raw.Coverage.Since) {
		t.Fatalf("coverage start: summary %v raw %v", summary.Coverage.Since, raw.Coverage.Since)
	}
	summary.Coverage.Since, raw.Coverage.Since = nil, nil
	if summary.Coverage != raw.Coverage || summary.Coverage.FlowStarts != 65 || summary.Coverage.AttributedFlows != 45 {
		t.Fatalf("coverage summary %+v raw %+v", summary.Coverage, raw.Coverage)
	}
}

// The events page query a process drill-down runs walks the partial index of
// attributed events in order, without sorting; other searches walk time.
func TestEventsPageQueryPlans(t *testing.T) {
	f := newPodFixtureWith(t, false)
	plan := func(query url.Values) string {
		sql := f.server.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
			var rows []database.NetworkEvent
			return eventsSlice(tx, query, f.now.Add(-time.Hour), cursor{at: f.now}, 50).Find(&rows)
		})
		var steps []struct{ Detail string }
		if err := f.server.db.Raw("EXPLAIN QUERY PLAN " + sql).Scan(&steps).Error; err != nil {
			t.Fatal(err)
		}
		var details []string
		for _, step := range steps {
			details = append(details, step.Detail)
		}
		return strings.Join(details, "; ")
	}
	drill := plan(url.Values{"process": {"python3"}, "processPod": {"demo/api-1"}, "processContainer": {"api"}, "collector": {"node-a"}})
	if !strings.Contains(drill, "idx_process_time") || strings.Contains(drill, "TEMP B-TREE") {
		t.Fatalf("process drill-down plan: %s", drill)
	}
	exit := plan(url.Values{"route": {"exit-node"}})
	if !strings.Contains(exit, "idx_route_time") || strings.Contains(exit, "TEMP B-TREE") {
		t.Fatalf("route plan: %s", exit)
	}
	search := plan(url.Values{"q": {"api"}})
	if !strings.Contains(search, "idx_network_events_timestamp") || strings.Contains(search, "TEMP B-TREE") {
		t.Fatalf("search plan: %s", search)
	}
}
