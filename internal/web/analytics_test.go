package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
)

func TestSummaryDashboardAPIs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "analytics.db")
	writer, err := database.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.EnableSummaries(t.Context()); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rows := []database.NetworkEvent{
		{Timestamp: at.Add(18 * time.Minute), EventType: database.EventTCPEnd, SrcIP: "172.31.0.1", DstIP: "8.8.8.8", Hostname: "api.test", ByteCount: 10},
		{Timestamp: at.Add(time.Hour), EventType: database.EventDNS, SrcIP: "8.8.8.8", DstIP: "fd00::1", Hostname: "api.test", ByteCount: 20},
		{Timestamp: at.Add(65 * time.Minute), EventType: database.EventDNS, SrcIP: "203.0.113.1", DstIP: "8.8.8.8", Hostname: "other.test", ByteCount: 30},
		{Timestamp: at.Add(24*time.Hour + 17*time.Minute), EventType: database.EventDNS, SrcIP: "172.31.0.1", DstIP: "8.8.8.8", ByteCount: 1000},
	}
	if err := writer.InsertBatch(rows); err != nil {
		t.Fatal(err)
	}
	reader, err := database.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	server := &Server{db: reader, OwnedCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")}}
	request := func(handler http.HandlerFunc, path string, result interface{}) {
		t.Helper()
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest("GET", path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), result); err != nil {
			t.Fatal(err)
		}
	}
	var stats StatsResponse
	request(server.handleStats, "/api/stats", &stats)
	if stats.TotalEvents != 4 || stats.EventCounts["DNS"] != 3 {
		t.Fatalf("stats=%+v", stats)
	}
	for _, test := range []struct {
		query string
		count int64
	}{{"", 4}, {"?eventType=DNS", 3}, {"?srcIP=203.0.113.1", 1}, {"?q=api.test", 2}, {"?startDate=2026-01-02", 1}} {
		var events EventsResponse
		request(server.handleEvents, "/api/events"+test.query, &events)
		if events.Total != test.count || len(events.Events) != int(test.count) {
			t.Fatalf("%s got total=%d rows=%d", test.query, events.Total, len(events.Events))
		}
	}
	var hosts TopHostsResponse
	request(server.handleTopHosts, "/api/top-hosts?type=hostname&metric=events&hours=all&limit=1", &hosts)
	if hosts.Total != 2 || len(hosts.Hosts) != 1 || hosts.Hosts[0].Host != "api.test" || hosts.Hosts[0].ByteCount != 30 {
		t.Fatalf("hosts=%+v", hosts)
	}
	var timeline TrafficTimelineResponse
	params := url.Values{"start": {at.Add(17 * time.Minute).Format(time.RFC3339)}, "end": {at.Add(24*time.Hour + 17*time.Minute).Format(time.RFC3339)}}
	request(server.handleTrafficTimeline, "/api/traffic-timeline?"+params.Encode(), &timeline)
	if timeline.BucketSize != "1hour" || timeline.TotalIn != 20 || timeline.TotalOut != 40 {
		t.Fatalf("timeline=%+v", timeline)
	}
	var count int64
	for _, point := range timeline.Data {
		count += point.EventCount
		if point.Timestamp.Minute() != 0 || point.Timestamp.Second() != 0 {
			t.Fatalf("unaligned bucket: %v", point.Timestamp)
		}
	}
	if count != 3 || len(timeline.Data) != 25 {
		t.Fatalf("timeline count=%d buckets=%d", count, len(timeline.Data))
	}
	params.Set("end", at.Add(31*time.Minute).Format(time.RFC3339))
	request(server.handleTrafficTimeline, "/api/traffic-timeline?"+params.Encode(), &timeline)
	if timeline.BucketSize != "5min" || len(timeline.Data) != 4 || timeline.Data[0].Timestamp.Minute() != 15 || timeline.Data[0].EventCount != 1 || timeline.TotalOut != 10 {
		t.Fatalf("fine timeline=%+v", timeline)
	}
}
