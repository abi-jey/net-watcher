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

func TestMapDistinguishesKubernetesOwnershipFromAddressScope(t *testing.T) {
	owned, err := ParseOwnedCIDRs("192.168.1.80/32,203.0.113.5/32")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip, context, scope, ownership, source, label string
	}{
		{"10.0.1.155", `{"Kind":"node","Name":"abja","UID":"node-1"}`, "internal", "ours", "kubernetes", "abja"},
		{"10.2.0.8", `{"Kind":"pod","Namespace":"demo","Name":"worker","UID":"pod-1"}`, "internal", "ours", "kubernetes", "demo/worker"},
		{"203.0.113.8", `{"Kind":"service","Namespace":"demo","Name":"public","UID":"svc-1"}`, "external", "ours", "kubernetes", "demo/public"},
		{"192.168.1.80", "", "internal", "ours", "configured", "192.168.1.80"},
		{"203.0.113.5", "", "external", "ours", "configured", "203.0.113.5"},
		{"192.168.1.81", "", "internal", "unattributed", "", "192.168.1.81"},
		{"100.88.1.4", "", "internal", "unattributed", "", "100.88.1.4"},
		{"fd00::1", "", "internal", "unattributed", "", "fd00::1"},
		{"8.8.8.8", "", "external", "unattributed", "", "8.8.8.8"},
	} {
		node := networkNode(tc.ip, tc.context, owned)
		if node.Scope != tc.scope || node.Ownership != tc.ownership || node.OwnershipSource != tc.source || node.Label != tc.label {
			t.Errorf("%s classified as %+v, want scope=%s ownership=%s source=%s label=%s", tc.ip, node, tc.scope, tc.ownership, tc.source, tc.label)
		}
	}
	for _, value := range []string{"not-a-network", "10.0.0.0/16,"} {
		if _, err := ParseOwnedCIDRs(value); err == nil {
			t.Fatalf("invalid owned CIDR accepted: %q", value)
		}
	}
}

func TestMapAssociatesUnattributedNodeHistoryOnlyWhenIdentityIsUnambiguous(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "node-history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now()
	old := database.NetworkEvent{Timestamp: at.Add(-time.Minute), EventType: database.EventTCPStart, SrcIP: "10.0.1.155", DstIP: "10.2.0.8", DstPort: 8000}
	current := database.NetworkEvent{Timestamp: at, EventType: database.EventTCPStart, SrcIP: old.SrcIP, DstIP: old.DstIP, DstPort: 8000, SourceContext: `{"Kind":"node","Name":"abja","UID":"node-1"}`}
	if err := db.InsertBatch([]database.NetworkEvent{old, current}); err != nil {
		t.Fatal(err)
	}
	server := &Server{db: db, Kubernetes: kube.New(nil)}
	read := func() NetworkMap {
		t.Helper()
		recorder := httptest.NewRecorder()
		server.handleNetworkMap(recorder, httptest.NewRequest("GET", "/api/network-map?ip=10.0.1.155", nil))
		if recorder.Code != 200 {
			t.Fatal(recorder.Body.String())
		}
		var result NetworkMap
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	result := read()
	var matches []MapNode
	for _, node := range result.Nodes {
		if node.IP == old.SrcIP {
			matches = append(matches, node)
		}
	}
	if len(matches) != 1 || matches[0].Label != "abja" || matches[0].Ownership != "ours" || len(result.Links) != 1 || result.Links[0].Events != 2 {
		t.Fatalf("stable node IP was not unified: nodes=%+v links=%+v", matches, result.Links)
	}
	replacement := current
	replacement.ID = 0
	replacement.Timestamp = at.Add(time.Second)
	replacement.SourceContext = `{"Kind":"node","Name":"replacement","UID":"node-2"}`
	if err := db.InsertEvent(&replacement); err != nil {
		t.Fatal(err)
	}
	result = read()
	matches = nil
	for _, node := range result.Nodes {
		if node.IP == old.SrcIP {
			matches = append(matches, node)
		}
	}
	if len(matches) != 3 {
		t.Fatalf("ambiguous node IP was reassigned: %+v", matches)
	}
}
