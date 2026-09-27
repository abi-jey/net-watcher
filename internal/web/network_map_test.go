package web

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/abja/net-watcher/internal/kube"
)

func TestMapSeparatesDNSProofFromSNIAndUnknownConnections(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "map.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	context := `{"Kind":"pod","Namespace":"demo","Name":"worker","UID":"original-pod"}`
	now := time.Now()
	evidence := database.DNSResolution{Name: "api.test", ClientIP: "10.2.0.8", IP: "203.0.113.20", QueryTime: now.Add(-time.Second), ResponseTime: now, ExpiresAt: now.Add(time.Minute), TTL: 60, ClientContext: context}
	if err := db.Create(&evidence).Error; err != nil {
		t.Fatal(err)
	}
	ids, _ := json.Marshal([]uint{evidence.ID})
	events := []database.NetworkEvent{
		{Timestamp: now, EventType: database.EventTCPStart, SrcIP: "10.2.0.8", DstIP: evidence.IP, DstPort: 443, SourceContext: context, DNSResolutionIDs: string(ids)},
		{Timestamp: now, EventType: database.EventTLSSNI, SrcIP: "10.2.0.8", DstIP: "203.0.113.30", DstPort: 443, SourceContext: context, TLSSNI: "sni-only.test"},
		{Timestamp: now, EventType: database.EventTCPStart, SrcIP: "10.2.0.9", DstIP: "203.0.113.40", DstPort: 80},
	}
	if err := db.InsertBatch(events); err != nil {
		t.Fatal(err)
	}
	server := &Server{db: db, Kubernetes: kube.New(nil)}
	recorder := httptest.NewRecorder()
	server.handleNetworkMap(recorder, httptest.NewRequest("GET", "/api/network-map?namespace=demo", nil))
	if recorder.Code != 200 {
		t.Fatal(recorder.Body.String())
	}
	var result NetworkMap
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence) != 1 || result.Observations != 2 {
		t.Fatalf("wrong filtered sample: %+v", result)
	}
	var proof, sni, answer bool
	nodes := map[string]bool{}
	for _, node := range result.Nodes {
		nodes[node.ID] = true
		if node.IP == "10.2.0.9" {
			t.Fatal("namespace filter leaked unknown endpoint")
		}
	}
	for _, link := range result.Links {
		if !nodes[link.Source] || !nodes[link.Target] {
			t.Fatal("dangling map edge")
		}
		if link.Kind == "dns_answer" {
			answer = true
		}
		if link.Kind == "connection" && len(link.EvidenceIDs) > 0 {
			proof = true
		}
		if len(link.SNI) > 0 {
			sni = true
			if len(link.EvidenceIDs) != 0 {
				t.Fatal("SNI mislabeled as DNS proof")
			}
		}
	}
	if !proof || !sni || !answer {
		t.Fatal("map lost observed relationships")
	}
	for _, query := range []string{"since=invalid", "since=48h", "limit=9000", "ip=not-an-ip"} {
		r := httptest.NewRecorder()
		server.handleNetworkMap(r, httptest.NewRequest("GET", "/api/network-map?"+query, nil))
		if r.Code != 400 {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
	r := httptest.NewRecorder()
	server.handleDNSEvidence(r, httptest.NewRequest("GET", "/api/dns-evidence?ids=1", nil))
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
}
