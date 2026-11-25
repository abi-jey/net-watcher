package watcher

import (
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/google/gopacket/layers"
)

// storedEvents writes what the manager buffered and returns all its records.
func storedEvents(t *testing.T, sm *SessionManager) []database.NetworkEvent {
	t.Helper()
	sm.flushEvents()
	var events []database.NetworkEvent
	if err := sm.db.Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func noTunnels(sm *SessionManager) {
	none := map[uint16]string{}
	sm.tunnels.Store(&none)
}

// sumBytes adds up ByteCount over records, as summaries do.
func sumBytes(events []database.NetworkEvent) int64 {
	var total int64
	for _, event := range events {
		total += event.ByteCount
	}
	return total
}

// A flow's records count what each end sent; its start, any updates and its
// end share one flow ID.
func TestFlowTotalsByDirection(t *testing.T) {
	sm := testManager(t)
	noTunnels(sm)
	client, server := "[10.2.0.8]:40000", "[10.2.0.9]:9000"
	for range 3 {
		sm.TrackUDP("veth0", client, server, 40000, 9000, 100, false)
	}
	for range 2 {
		sm.TrackUDP("veth0", server, client, 9000, 40000, 500, false)
	}
	sm.recordFlows(time.Now().Add(sm.sessionTimeout + time.Second))

	sm.TrackTCP("veth0", "[10.2.0.8]:41000", "[10.2.0.9]:443", true, false, false, 74, false)
	sm.TrackTCP("veth0", "[10.2.0.9]:443", "[10.2.0.8]:41000", false, false, false, 74, false) // SYN-ACK
	sm.TrackTCP("veth0", "[10.2.0.8]:41000", "[10.2.0.9]:443", false, false, false, 1500, false)
	sm.TrackTCP("veth0", "[10.2.0.9]:443", "[10.2.0.8]:41000", false, false, false, 66, false)
	sm.TrackTCP("veth0", "[10.2.0.8]:41000", "[10.2.0.9]:443", false, true, false, 66, false)

	events := storedEvents(t, sm)
	if len(events) != 4 {
		t.Fatalf("records: %+v", events)
	}
	start, end := events[0], events[1]
	if start.EventType != database.EventUDPStart || start.FlowID == "" || start.SrcBytes != 100 || start.SrcPackets != 1 || start.ByteCount != 0 {
		t.Fatalf("UDP start: %+v", start)
	}
	if end.EventType != database.EventUDPEnd || end.FlowID != start.FlowID || end.SrcBytes != 300 || end.SrcPackets != 3 || end.DstBytes != 1000 || end.DstPackets != 2 || end.ByteCount != 1300 {
		t.Fatalf("UDP end: %+v", end)
	}
	tcpStart, tcpEnd := events[2], events[3]
	if tcpStart.EventType != database.EventTCPStart || tcpEnd.EventType != database.EventTCPEnd || tcpEnd.FlowID != tcpStart.FlowID || tcpEnd.FlowID == start.FlowID {
		t.Fatalf("TCP records: %+v %+v", tcpStart, tcpEnd)
	}
	if tcpEnd.SrcBytes != 74+1500+66 || tcpEnd.SrcPackets != 3 || tcpEnd.DstBytes != 74+66 || tcpEnd.DstPackets != 2 || tcpEnd.ByteCount != tcpEnd.SrcBytes+tcpEnd.DstBytes {
		t.Fatalf("TCP end: %+v", tcpEnd)
	}
}

// An open flow gets progress records while it carries traffic. Each record
// carries the bytes since the flow's previous one, so their sum is the
// flow's total: summaries add ByteCount over all records.
func TestFlowUpdatesCountEachByteOnce(t *testing.T) {
	sm := testManager(t)
	noTunnels(sm)
	sm.updateInterval = time.Millisecond
	client, server := "[10.2.0.8]:40000", "[203.0.113.7]:4500"
	sm.TrackUDP("eth0", client, server, 40000, 4500, 1000, false)
	sm.TrackUDP("eth0", client, server, 40000, 4500, 2000, false)
	time.Sleep(2 * time.Millisecond)
	sm.recordFlows(time.Now())
	time.Sleep(2 * time.Millisecond)
	sm.recordFlows(time.Now()) // Nothing sent since: no record.
	sm.TrackUDP("eth0", server, client, 4500, 40000, 50, false)
	sm.recordFlows(time.Now().Add(sm.sessionTimeout + time.Second))

	events := storedEvents(t, sm)
	types := []database.EventType{}
	for _, event := range events {
		types = append(types, event.EventType)
		if event.FlowID != events[0].FlowID {
			t.Fatalf("records of one flow with two IDs: %+v", events)
		}
	}
	if len(events) != 3 || events[1].EventType != database.EventUDPUpdate || events[2].EventType != database.EventUDPEnd {
		t.Fatalf("records %v", types)
	}
	update, end := events[1], events[2]
	if update.ByteCount != 3000 || update.SrcBytes != 3000 || update.SrcPackets != 2 || update.DstBytes != 0 {
		t.Fatalf("update: %+v", update)
	}
	if end.ByteCount != 50 || end.SrcBytes != 3000 || end.DstBytes != 50 || end.DstPackets != 1 {
		t.Fatalf("end: %+v", end)
	}
	if sum := sumBytes(events); sum != end.SrcBytes+end.DstBytes {
		t.Fatalf("records add up to %d bytes, the flow carried %d", sum, end.SrcBytes+end.DstBytes)
	}
}

// The kernel sends each connection a tunnel carries from its own source
// port; the tunnel is still one flow between the two hosts.
func TestTunnelTrafficIsOneFlowPerHostPair(t *testing.T) {
	sm := testManager(t)
	tunnels := map[uint16]string{8472: "vxlan cilium_vxlan"}
	sm.tunnels.Store(&tunnels)
	for port := uint16(50000); port < 50005; port++ {
		sm.TrackUDP("tailscale0", "[100.64.1.1]:"+itoa(port), "[100.64.99.55]:8472", port, 8472, 150, false)
	}
	for port := uint16(60000); port < 60003; port++ {
		sm.TrackUDP("tailscale0", "[100.64.99.55]:"+itoa(port), "[100.64.1.1]:8472", port, 8472, 1400, false)
	}
	sm.TrackUDP("tailscale0", "[100.64.1.1]:50000", "[100.64.99.55]:9999", 50000, 9999, 10, false) // Not the tunnel.
	sm.recordFlows(time.Now().Add(sm.sessionTimeout + time.Second))

	events := storedEvents(t, sm)
	var tunnel []database.NetworkEvent
	for _, event := range events {
		if event.DstPort == 8472 {
			tunnel = append(tunnel, event)
		}
	}
	if len(events) != 4 || len(tunnel) != 2 {
		t.Fatalf("records: %+v", events)
	}
	start, end := tunnel[0], tunnel[1]
	if start.EventType != database.EventUDPStart || start.SrcIP != "100.64.1.1" || start.SrcPort != 0 || start.DstIP != "100.64.99.55" || start.Protocol != "VXLAN" {
		t.Fatalf("tunnel start: %+v", start)
	}
	if end.SrcPackets != 5 || end.SrcBytes != 750 || end.DstPackets != 3 || end.DstBytes != 4200 || end.Protocol != "VXLAN" {
		t.Fatalf("tunnel end: %+v", end)
	}
}

func itoa(port uint16) string {
	digits := []byte{}
	for ; port > 0; port /= 10 {
		digits = append([]byte{byte('0' + port%10)}, digits...)
	}
	return string(digits)
}

// One lookup is one record on a node, however many of its interfaces the
// query and the response cross; a query sent again is the same lookup.
func TestDNSLookupIsOneRecordPerNode(t *testing.T) {
	sm := testManager(t)
	at := time.Now().Add(-time.Second)
	client, resolver := "[10.0.1.84]:51000", "[10.0.0.20]:53"
	query := dnsMessage(t, 7, false, "base-server.base.svc.cluster.local", nil)
	response := dnsMessage(t, 7, true, "base-server.base.svc.cluster.local", []layers.DNSResourceRecord{addressRecord("base-server.base.svc.cluster.local", "10.96.4.2", 30)})
	queryBytes, responseBytes := len(query)+42, len(response)+42
	for _, packet := range []struct {
		iface    string
		response bool
		after    time.Duration
	}{
		{"lxc1", false, 0},
		{"cilium_vxlan", false, 2 * time.Millisecond}, // The same query on its way out.
		{"lxc1", false, 500 * time.Millisecond},       // Sent again.
		{"cilium_vxlan", true, 600 * time.Millisecond},
		{"lxc1", true, 601 * time.Millisecond}, // The same response on its way in.
	} {
		src, dst, payload, size := client, resolver, query, queryBytes
		if packet.response {
			src, dst, payload, size = resolver, client, response, responseBytes
		}
		if !sm.TrackDNSPacket(packet.iface, src, dst, "UDP", payload, at.Add(packet.after), false, size) {
			t.Fatal("a DNS message was not taken as DNS")
		}
	}
	sm.releaseQueries(time.Now().Add(time.Minute))
	events := storedEvents(t, sm)
	if len(events) != 1 {
		t.Fatalf("%d records: %+v", len(events), events)
	}
	lookup := events[0]
	if lookup.DNSType != "RESPONSE" || !lookup.DNSMatched || lookup.Interface != "cilium_vxlan" || !lookup.DNSQueryTime.Equal(at) {
		t.Fatalf("lookup: %+v", lookup)
	}
	if lookup.DstBytes != int64(2*queryBytes) || lookup.DstPackets != 2 || lookup.SrcBytes != int64(responseBytes) || lookup.SrcPackets != 1 || lookup.ByteCount != lookup.SrcBytes+lookup.DstBytes {
		t.Fatalf("lookup sizes: %+v", lookup)
	}
}

// A query that gets no response is recorded as one, once its wait is over.
func TestUnansweredQueryIsRecorded(t *testing.T) {
	sm := testManager(t)
	query := dnsMessage(t, 9, false, "gone.test", nil)
	sm.TrackDNSPacket("eth0", "[10.0.1.84]:51001", "[10.0.0.20]:53", "UDP", query, time.Now(), false, len(query)+42)
	sm.releaseQueries(time.Now().Add(-time.Second)) // Still waiting.
	if events := storedEvents(t, sm); len(events) != 0 {
		t.Fatalf("recorded before its wait: %+v", events)
	}
	sm.releaseQueries(time.Now().Add(time.Second))
	events := storedEvents(t, sm)
	if len(events) != 1 || events[0].DNSType != "QUERY" || events[0].DNSQuery != "gone.test" || events[0].ByteCount != int64(len(query)+42) || events[0].SrcPackets != 1 {
		t.Fatalf("records: %+v", events)
	}
}

// Port 53 carrying something other than DNS stays a UDP flow.
func TestNonDNSOnPort53IsNotALookup(t *testing.T) {
	sm := testManager(t)
	if sm.TrackDNSPacket("eth0", "[10.0.1.84]:51002", "[10.0.0.20]:53", "UDP", []byte("not a DNS message"), time.Now(), false, 60) {
		t.Fatal("garbage taken as DNS")
	}
}

// The lookup's record names the process that asked, found by the query's
// lookup, when the response found none itself.
func TestLookupRecordTakesTheQueryProcess(t *testing.T) {
	for _, c := range []struct {
		name  string
		query database.NetworkEvent
		check func(database.NetworkEvent) bool
	}{
		{"client", database.NetworkEvent{ProcessSide: "src", ProcessPID: 4100, ProcessCommand: "prometheus", ProcessPod: "monitoring/prometheus-0"},
			func(e database.NetworkEvent) bool {
				return e.ProcessSide == "dst" && e.ProcessCommand == "prometheus" && e.ProcessPod == "monitoring/prometheus-0" && e.PeerProcessCommand == ""
			}},
		{"both ends", database.NetworkEvent{ProcessSide: "src", ProcessCommand: "curl", PeerProcessCommand: "coredns", PeerProcessPod: "kube-system/coredns-1"},
			func(e database.NetworkEvent) bool {
				return e.ProcessSide == "src" && e.ProcessCommand == "coredns" && e.ProcessPod == "kube-system/coredns-1" && e.PeerProcessCommand == "curl"
			}},
	} {
		sm := testManager(t)
		query := c.query
		query.EventType, query.DNSVersion, query.DNSType, query.DNSID, query.DNSQuery, query.DNSQuestionType, query.Protocol = database.EventDNS, 1, "QUERY", 5, "api.test", "A", "UDP"
		query.Timestamp, query.SrcIP, query.SrcPort, query.DstIP, query.DstPort = time.Now(), "10.0.1.84", 51003, "10.0.0.20", 53
		response := query
		response.DNSType, response.SrcIP, response.SrcPort, response.DstIP, response.DstPort = "RESPONSE", query.DstIP, query.DstPort, query.SrcIP, query.SrcPort
		response.ProcessSide, response.ProcessPID, response.ProcessCommand, response.ProcessPod = "", 0, "", ""
		response.PeerProcessCommand, response.PeerProcessPod = "", ""
		sm.appendEvent(query)
		sm.appendEvent(response)
		sm.releaseQueries(time.Now().Add(time.Minute))
		events := storedEvents(t, sm)
		if len(events) != 1 || !c.check(events[0]) {
			t.Fatalf("%s: %+v", c.name, events)
		}
	}
}

func TestTLSServerNameJoinsItsFlow(t *testing.T) {
	sm := testManager(t)
	sm.TrackTCP("veth0", "[10.2.0.8]:41000", "[203.0.113.9]:443", true, false, false, 74, false)
	sm.TrackTLSHandshake("veth0", "[10.2.0.8]:41000", "[203.0.113.9]:443", "api.example.test", false)
	events := storedEvents(t, sm)
	if len(events) != 2 || events[1].EventType != database.EventTLSSNI || events[1].FlowID == "" || events[1].FlowID != events[0].FlowID {
		t.Fatalf("records: %+v", events)
	}
}
