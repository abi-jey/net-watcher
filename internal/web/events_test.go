package web

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"gorm.io/gorm"
)

func TestEventsKeysetPagesAcrossSparseSlices(t *testing.T) {
	f := newPodFixture(t)
	var events []database.NetworkEvent
	for i := 0; i < 61; i++ {
		// Clusters of three identical timestamps, separated by gaps longer
		// than the largest scan slice; every fifth event is filtered out.
		at := f.now.Add(-time.Duration(i/3) * 5 * time.Hour)
		host := "match.example"
		if i%5 == 0 {
			host = "other.example"
		}
		events = append(events, database.NetworkEvent{Timestamp: at, EventType: database.EventTLSSNI, SrcIP: "10.0.0.1", DstIP: "203.0.113.5", Hostname: host})
	}
	if err := f.writer.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	params := url.Values{"q": {"match"}, "limit": {"7"}, "from": {f.now.Add(-6 * 24 * time.Hour).Format(time.RFC3339)}, "to": {f.now.Add(time.Second).Format(time.RFC3339)}}
	seen := map[uint]bool{}
	var previous *database.NetworkEvent
	for page := 0; ; page++ {
		if page > 40 {
			t.Fatal("pagination did not finish")
		}
		var response EventsResponse
		if code := f.get(t, "/api/events", params, &response); code != 200 {
			t.Fatalf("page %d status %d params %v", page, code, params)
		}
		for i := range response.Events {
			event := response.Events[i]
			if seen[event.ID] || event.Hostname != "match.example" {
				t.Fatalf("duplicate or unfiltered event %+v", event)
			}
			if previous != nil && (event.Timestamp.After(previous.Timestamp) || (event.Timestamp.Equal(previous.Timestamp) && event.ID > previous.ID)) {
				t.Fatalf("not newest first: %v/%d after %v/%d", event.Timestamp, event.ID, previous.Timestamp, previous.ID)
			}
			seen[event.ID] = true
			previous = &event
		}
		if response.Complete {
			if response.NextCursor != "" {
				t.Fatal("complete response with a cursor")
			}
			break
		}
		if response.NextCursor == "" || response.SearchedFrom.IsZero() {
			t.Fatalf("incomplete response without position: %+v", response)
		}
		params.Set("cursor", response.NextCursor)
	}
	if len(seen) != 48 {
		t.Fatalf("saw %d matches, want 48", len(seen))
	}
	var bad struct{}
	if code := f.get(t, "/api/events", url.Values{"from": {f.now.Add(-8 * 24 * time.Hour).Format(time.RFC3339)}}, &bad); code != 400 {
		t.Fatalf("window over 7 days: status %d", code)
	}
}

// A namespace page holds its events from either side, once each, newest
// first across pages, and walks only that namespace's index entries.
func TestEventsNamespaceWalksBothSides(t *testing.T) {
	f := newPodFixture(t)
	var events []database.NetworkEvent
	want := map[string]bool{}
	for i := 0; i < 40; i++ {
		// Pairs of identical timestamps, so pages split ties by ID.
		event := database.NetworkEvent{Timestamp: f.now.Add(-time.Duration(i/2) * time.Minute), EventType: database.EventTCPStart,
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: uint16(1000 + i), Interface: "lxc1"}
		switch i % 4 {
		case 0:
			event.SrcNamespace = "quiet"
		case 1:
			event.DstNamespace = "quiet"
		case 2:
			event.SrcNamespace, event.DstNamespace = "quiet", "quiet" // Matches once, not twice.
		default:
			event.SrcNamespace, event.DstNamespace = "busy", "other"
		}
		if i%8 == 1 {
			event.Interface = "eth0" // Excluded by the interface filter below.
		}
		if event.SrcNamespace == "quiet" || event.DstNamespace == "quiet" {
			if event.Interface == "lxc1" {
				want[fmt.Sprint(event.DstPort)] = true
			}
		}
		events = append(events, event)
	}
	if err := f.writer.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	params := url.Values{"namespace": {"quiet"}, "iface": {"lxc1"}, "limit": {"4"},
		"from": {f.now.Add(-time.Hour).Format(time.RFC3339)}, "to": {f.now.Add(time.Second).Format(time.RFC3339)}}
	seen := map[string]bool{}
	var previous *database.NetworkEvent
	for page := 0; ; page++ {
		if page > 20 {
			t.Fatal("pagination did not finish")
		}
		var response EventsResponse
		if code := f.get(t, "/api/events", params, &response); code != 200 {
			t.Fatalf("page %d status %d", page, code)
		}
		for i := range response.Events {
			event := response.Events[i]
			port := fmt.Sprint(event.DstPort)
			if seen[port] || !want[port] {
				t.Fatalf("duplicate or unfiltered event %+v", event)
			}
			if previous != nil && (event.Timestamp.After(previous.Timestamp) || (event.Timestamp.Equal(previous.Timestamp) && event.ID > previous.ID)) {
				t.Fatalf("not newest first: %v/%d after %v/%d", event.Timestamp, event.ID, previous.Timestamp, previous.ID)
			}
			seen[port], previous = true, &event
		}
		if response.Complete {
			break
		}
		params.Set("cursor", response.NextCursor)
	}
	if len(seen) != len(want) {
		t.Fatalf("saw %d events, want %d", len(seen), len(want))
	}

	sql := f.server.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		var rows []database.NetworkEvent
		return eventsSlice(tx, requestFilter(t, url.Values{"namespace": {"quiet"}}), f.now.Add(-time.Hour), cursor{at: f.now}, 50).Find(&rows)
	})
	var steps []struct{ Detail string }
	if err := f.server.db.Raw("EXPLAIN QUERY PLAN " + sql).Scan(&steps).Error; err != nil {
		t.Fatal(err, sql)
	}
	var plan []string
	for _, step := range steps {
		plan = append(plan, step.Detail)
	}
	joined := strings.Join(plan, "; ")
	if !strings.Contains(joined, "idx_src_namespace_time (src_namespace=? AND timestamp") || !strings.Contains(joined, "idx_dst_namespace_time (dst_namespace=? AND timestamp") {
		t.Fatalf("namespace plan: %s", joined)
	}
	// Each side walks its index in order and stops at the page size; only
	// those bounded results are sorted for the merge.
	for i, step := range plan {
		if strings.Contains(step, "TEMP B-TREE") && (i == 0 || !strings.HasPrefix(plan[i-1], "SCAN (subquery-")) {
			t.Fatalf("namespace plan sorts an index walk: %s", joined)
		}
	}
}
