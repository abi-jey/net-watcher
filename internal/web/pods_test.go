package web

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

type podFixture struct {
	server *Server
	writer *database.DB
	now    time.Time
}

func newPodFixture(t *testing.T) podFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "central.db")
	writer, err := database.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	reader, err := database.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return podFixture{server: &Server{db: reader, logger: log.Default()}, writer: writer, now: time.Now().UTC().Truncate(time.Second)}
}

func podEvent(at time.Time, srcIP, srcUID, srcName, dstIP, dstUID, dstName string) database.NetworkEvent {
	event := database.NetworkEvent{Timestamp: at, EventType: database.EventTCPStart, SrcIP: srcIP, SrcPort: 40000, DstIP: dstIP, DstPort: 443, CollectorID: "node-a", Interface: "lxc1"}
	if srcUID != "" {
		event.SrcKind, event.SrcNamespace, event.SrcName, event.SrcUID, event.SrcWorkload, event.SrcAttribution = "pod", "demo", srcName, srcUID, "Deployment/api", "exact"
	}
	if dstUID != "" {
		event.DstKind, event.DstNamespace, event.DstName, event.DstUID, event.DstWorkload, event.DstAttribution = "pod", "demo", dstName, dstUID, "Deployment/db", "exact"
	}
	return event
}

func (f podFixture) get(t *testing.T, path string, params url.Values, target interface{}) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", path+"?"+params.Encode(), nil)
	switch path {
	case "/api/pods":
		f.server.handlePods(recorder, request)
	default:
		f.server.handlePodConnections(recorder, request)
	}
	if recorder.Code == 200 && target != nil {
		if err := json.Unmarshal(recorder.Body.Bytes(), target); err != nil {
			t.Fatal(err)
		}
	}
	return recorder.Code
}

// Same pod name and IP, recreated with a new UID: inspection pinned to a UID
// must only show that instance; the workload view spans both.
func TestPodConnectionsPinToUIDAcrossIPReuse(t *testing.T) {
	f := newPodFixture(t)
	events := []database.NetworkEvent{
		podEvent(f.now.Add(-50*time.Minute), "10.0.0.7", "old", "api-1", "203.0.113.5", "", ""),
		podEvent(f.now.Add(-10*time.Minute), "10.0.0.7", "new", "api-1", "203.0.113.6", "", ""),
		podEvent(f.now.Add(-5*time.Minute), "10.0.0.9", "web", "web-1", "10.0.0.7", "new", "api-1"),
	}
	events[2].SrcWorkload, events[2].DstWorkload = "Deployment/web", "Deployment/api"
	if err := f.writer.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	var response PodConnectionsResponse
	if code := f.get(t, "/api/pod-connections", url.Values{"uid": {"new"}}, &response); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(response.Connections) != 2 {
		t.Fatalf("connections = %+v", response.Connections)
	}
	if c := response.Connections[0]; c.Direction != "ingress" || c.Peer.Name != "web-1" || c.Pod.UID != "new" || c.Verdict != "unknown" {
		t.Fatalf("ingress row = %+v", c)
	}
	if c := response.Connections[1]; c.Direction != "egress" || c.Peer.IP != "203.0.113.6" || c.Peer.Attribution != "none" {
		t.Fatalf("egress row = %+v", c)
	}
	if code := f.get(t, "/api/pod-connections", url.Values{"uid": {"new"}, "direction": {"egress"}}, &response); code != 200 || len(response.Connections) != 1 {
		t.Fatalf("egress filter: %d %+v", code, response.Connections)
	}
	if code := f.get(t, "/api/pod-connections", url.Values{"namespace": {"demo"}, "workload": {"Deployment/api"}, "direction": {"egress"}}, &response); code != 200 || len(response.Connections) != 2 {
		t.Fatalf("workload view: %d %+v", code, response.Connections)
	}
	var pods struct{ Pods []PodSummary }
	if code := f.get(t, "/api/pods", url.Values{}, &pods); code != 200 {
		t.Fatalf("pods status %d", code)
	}
	replacements := 0
	for _, pod := range pods.Pods {
		if pod.Name == "api-1" && pod.Replacement {
			replacements++
		}
	}
	if replacements != 2 {
		t.Fatalf("replacement not flagged: %+v", pods.Pods)
	}
}

// Filtering happens before the limit, and keyset pagination returns every
// row exactly once even with identical timestamps.
func TestPodConnectionsPaginateAfterFiltering(t *testing.T) {
	f := newPodFixture(t)
	var events []database.NetworkEvent
	for i := 0; i < 25; i++ {
		at := f.now.Add(-time.Duration(i/2) * time.Minute) // Pairs share a timestamp.
		events = append(events, podEvent(at, "10.0.0.7", "target", "api-1", fmt.Sprintf("203.0.113.%d", i), "", ""))
		events = append(events, podEvent(at, "10.0.0.8", "other", "api-2", "203.0.113.200", "", ""))
	}
	if err := f.writer.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	seen := map[uint]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		params := url.Values{"uid": {"target"}, "limit": {"7"}}
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		var response PodConnectionsResponse
		if code := f.get(t, "/api/pod-connections", params, &response); code != 200 {
			t.Fatalf("status %d", code)
		}
		for _, c := range response.Connections {
			if c.Pod.UID != "target" || seen[c.ID] {
				t.Fatalf("unexpected or duplicate row %+v", c)
			}
			seen[c.ID] = true
		}
		if response.NextCursor == "" {
			break
		}
		cursor = response.NextCursor
	}
	if len(seen) != 25 {
		t.Fatalf("paginated %d rows, want 25", len(seen))
	}
}

func TestPodConnectionsIncludeDNSEvidenceGapsAndBounds(t *testing.T) {
	f := newPodFixture(t)
	resolution := database.DNSResolution{Name: "api.example", IP: "203.0.113.5", TTL: 30, ResponseTime: f.now.Add(-2 * time.Minute), ExpiresAt: f.now.Add(-90 * time.Second), ResolverIP: "10.96.0.10"}
	if err := f.writer.Create(&resolution).Error; err != nil {
		t.Fatal(err)
	}
	withDNS := podEvent(f.now.Add(-2*time.Minute), "fd00::7", "target", "api-1", "203.0.113.5", "", "")
	withDNS.IPVersion = 6
	withDNS.DNSResolutionIDs = fmt.Sprintf("[%d]", resolution.ID)
	direct := podEvent(f.now.Add(-time.Minute), "10.0.0.7", "target", "api-1", "198.51.100.1", "", "")
	gap := database.NewGapEvent(database.GapCaptureDrops, 12, f.now.Add(-3*time.Minute), f.now.Add(-150*time.Second), "lxc1")
	gap.CollectorID = "node-a"
	if err := f.writer.InsertBatch([]database.NetworkEvent{withDNS, direct, gap}); err != nil {
		t.Fatal(err)
	}
	var response PodConnectionsResponse
	if code := f.get(t, "/api/pod-connections", url.Values{"uid": {"target"}}, &response); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(response.Connections) != 2 {
		t.Fatalf("connections = %+v", response.Connections)
	}
	if len(response.Connections[0].DNSEvidence) != 0 {
		t.Fatal("direct-IP flow gained DNS evidence")
	}
	evidence := response.Connections[1].DNSEvidence
	if len(evidence) != 1 || evidence[0].Name != "api.example" || evidence[0].TTL != 30 {
		t.Fatalf("evidence = %+v", evidence)
	}
	if len(response.Gaps) != 1 || response.Gaps[0].Lost != 12 {
		t.Fatalf("gaps = %+v", response.Gaps)
	}
	for _, bad := range []url.Values{
		{},
		{"uid": {"target"}, "direction": {"sideways"}},
		{"uid": {"target"}, "limit": {"5000"}},
		{"uid": {"target"}, "from": {f.now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)}},
		{"uid": {"target"}, "cursor": {"nonsense"}},
	} {
		if code := f.get(t, "/api/pod-connections", bad, nil); code != 400 {
			t.Errorf("params %v: status %d, want 400", bad, code)
		}
	}
}
