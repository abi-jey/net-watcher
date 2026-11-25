package ingest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

func postRecorded(t *testing.T, handler http.Handler, batch Batch) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, batchPath, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func heartbeat(collector string, at time.Time, addresses ...string) Batch {
	return Batch{CollectorID: collector, Events: []database.NetworkEvent{}, Resolutions: []database.DNSResolution{},
		Health: &Health{Version: "test", ReportedAt: at, Addresses: addresses}}
}

func TestOtherNodesAddressesAreAttributedAtIngest(t *testing.T) {
	central := testDB(t, "central.db")
	receiver := &Receiver{DB: central, Token: "token"}
	now := time.Now().UTC().Truncate(time.Millisecond)
	response := postRecorded(t, receiver.Handler(), heartbeat("desktop", now,
		"2001:db8::d1", "100.64.1.1", "2001:db8::99", "192.168.1.5", "172.17.0.1", "fe80::1", "127.0.0.1"))
	if response.Code != http.StatusNoContent || response.Header().Get(acceptsHeader) != acceptsAddresses+", "+acceptsPeerProcesses {
		t.Fatalf("heartbeat: %d, accepts %q", response.Code, response.Header().Get(acceptsHeader))
	}
	if code := postRecorded(t, receiver.Handler(), heartbeat("abja", now, "2001:db8::99")).Code; code != http.StatusNoContent {
		t.Fatalf("second heartbeat: %d", code)
	}

	event := func(id uint, at time.Time, dst string) database.NetworkEvent {
		return database.NetworkEvent{ID: id, Timestamp: at, EventType: database.EventTCPStart, IPVersion: 6,
			SrcIP: "2001:db8::a1", SrcKind: "node", SrcName: "abja", SrcAttribution: "node", DstIP: dst, DstPort: 443}
	}
	alreadyKnown := event(5, now, "2001:db8::d1")
	alreadyKnown.DstKind, alreadyKnown.DstName, alreadyKnown.DstAttribution = "pod", "api-1", "exact"
	batch := Batch{CollectorID: "abja", Resolutions: []database.DNSResolution{}, Events: []database.NetworkEvent{
		event(1, now.Add(-time.Minute), "2001:db8::d1"),
		event(2, now, "192.168.1.5"),                    // Private: not reported, so not attributed.
		event(3, now, "2001:db8::99"),                   // Reported by two nodes.
		event(4, now.Add(-2*time.Hour), "2001:db8::d1"), // Before the node held it.
		alreadyKnown,
		event(6, now, "100.64.1.1"),
	}}
	if code := postRecorded(t, receiver.Handler(), batch).Code; code != http.StatusNoContent {
		t.Fatalf("batch: %d", code)
	}
	stored := func() map[uint]database.NetworkEvent {
		var rows []database.NetworkEvent
		if err := central.Order("id").Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		bySource := map[uint]database.NetworkEvent{}
		var keys []database.IngestedEvent
		central.Find(&keys)
		for _, key := range keys {
			for _, row := range rows {
				if row.ID == key.EventID {
					bySource[key.SourceID] = row
				}
			}
		}
		return bySource
	}
	rows := stored()
	for id, want := range map[uint]string{1: "desktop", 2: "", 3: "", 4: "", 6: "desktop"} {
		row := rows[id]
		if row.DstName != want || (want != "" && (row.DstKind != "node" || row.DstAttribution != "node" || !strings.Contains(row.DestinationContext, "reported by the node's collector"))) {
			t.Errorf("event %d: dst kind=%q name=%q attribution=%q context=%q, want node %q", id, row.DstKind, row.DstName, row.DstAttribution, row.DestinationContext, want)
		}
		if row.SrcName != "abja" {
			t.Errorf("event %d: source attribution changed: %q", id, row.SrcName)
		}
	}
	if row := rows[5]; row.DstKind != "pod" || row.DstName != "api-1" {
		t.Errorf("existing attribution overridden: %+v", row)
	}

	var recorded []database.NodeAddress
	if err := central.Order("node, address").Find(&recorded).Error; err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, row := range recorded {
		names = append(names, row.Node+" "+row.Address)
	}
	if strings.Join(names, ", ") != "abja 2001:db8::99, desktop 100.64.1.1, desktop 2001:db8::99, desktop 2001:db8::d1" {
		t.Fatalf("recorded addresses: %v", names)
	}

	// A restarted ingester attributes from the recorded addresses.
	restarted := &Receiver{DB: central, Token: "token"}
	later := Batch{CollectorID: "abja", Resolutions: []database.DNSResolution{}, Events: []database.NetworkEvent{event(7, now, "2001:db8::d1")}}
	if code := postRecorded(t, restarted.Handler(), later).Code; code != http.StatusNoContent {
		t.Fatalf("batch after restart: %d", code)
	}
	if row := stored()[7]; row.DstName != "desktop" {
		t.Fatalf("after restart: dst %q", row.DstName)
	}
}

func TestForwarderSendsAddressesOnlyToIngesterThatAcceptsThem(t *testing.T) {
	for _, accepts := range []bool{false, true} {
		var bodies []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			body, _ := io.ReadAll(request.Body)
			bodies = append(bodies, string(body))
			if accepts {
				w.Header().Set(acceptsHeader, acceptsAddresses)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		forwarder := Forwarder{DB: testDB(t, "local.db"), URL: server.URL, Token: "token", CollectorID: "abja", Version: "test", Logger: log.Default(),
			Stats: func() LocalStats {
				return LocalStats{InventoryAgeSeconds: -1, Addresses: []string{"2001:db8::a1", "10.0.0.31", "fe80::1", "2001:db8::a1"}}
			}}
		for range 2 {
			forwarder.lastHeartbeat = time.Time{}
			if _, err := forwarder.send(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		server.Close()
		if len(bodies) != 2 || strings.Contains(bodies[0], "addresses") {
			t.Fatalf("accepts=%t: first report %v", accepts, bodies)
		}
		if got := strings.Contains(bodies[1], `"addresses":["2001:db8::a1"]`); got != accepts {
			t.Fatalf("accepts=%t: second report %s", accepts, bodies[1])
		}
	}
}

func TestForwarderSendsPeerProcessesOnlyToIngesterThatAcceptsThem(t *testing.T) {
	for _, accepts := range []bool{false, true} {
		var bodies []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			body, _ := io.ReadAll(request.Body)
			bodies = append(bodies, string(body))
			if accepts {
				w.Header().Set(acceptsHeader, acceptsAddresses+", "+acceptsPeerProcesses)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		local := testDB(t, "local.db")
		check := database.NetworkEvent{Timestamp: time.Now().UTC(), EventType: database.EventTCPStart, SrcIP: "10.0.1.155", DstIP: "10.0.1.84", DstPort: 8081,
			ProcessPID: 10, ProcessCommand: "kubelet", ProcessSide: "src", PeerProcessPID: 20, PeerProcessCommand: "keda", PeerProcessPod: "keda/keda-operator-1", PeerProcessContainer: "keda-operator"}
		if err := local.Create(&check).Error; err != nil {
			t.Fatal(err)
		}
		forwarder := Forwarder{DB: local, URL: server.URL, Token: "token", CollectorID: "abja", Version: "test", Logger: log.Default()}
		if sent, err := forwarder.send(t.Context()); err != nil || !sent {
			t.Fatalf("send: %t, %v", sent, err)
		}
		server.Close()
		// The first request only asks what the ingester accepts.
		if len(bodies) != 2 || strings.Contains(bodies[0], "kubelet") {
			t.Fatalf("accepts=%t: requests %v", accepts, bodies)
		}
		if !strings.Contains(bodies[1], `"ProcessCommand":"kubelet"`) {
			t.Fatalf("accepts=%t: event not sent: %s", accepts, bodies[1])
		}
		if got := strings.Contains(bodies[1], `"PeerProcessCommand":"keda"`); got != accepts {
			t.Fatalf("accepts=%t: peer sent %t: %s", accepts, got, bodies[1])
		}
		if !accepts && strings.Contains(bodies[1], "PeerProcess") {
			t.Fatalf("an older ingester must not see peer fields at all: %s", bodies[1])
		}
	}
}
