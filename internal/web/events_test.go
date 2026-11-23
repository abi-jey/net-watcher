package web

import (
	"net/url"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
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
