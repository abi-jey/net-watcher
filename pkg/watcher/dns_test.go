package watcher

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func testManager(t *testing.T) *SessionManager {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	sm := NewSessionManager(log.New(io.Discard), db, "", "", "")
	t.Cleanup(func() { sm.Stop(); _ = db.Close() })
	return sm
}

func dnsMessage(t *testing.T, id uint16, response bool, name string, answers []layers.DNSResourceRecord) []byte {
	t.Helper()
	message := layers.DNS{ID: id, QR: response, RD: true, Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}, Answers: answers}
	return serializeDNS(t, message)
}
func serializeDNS(t *testing.T, message layers.DNS) []byte {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	if err := message.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func addressRecord(name, ip string, ttl uint32) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: ttl, IP: net.ParseIP(ip)}
}
func resolutions(t *testing.T, sm *SessionManager) []database.DNSResolution {
	t.Helper()
	var rows []database.DNSResolution
	if err := sm.db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestDNSMatchedEvidenceIsClientScopedAndTTLBounded(t *testing.T) {
	sm := testManager(t)
	at := time.Now().Add(-time.Second)
	client, resolver := "[10.2.0.8]:40500", "[10.2.0.53]:53"
	sm.TrackDNSPacket("veth-test", client, resolver, "UDP", dnsMessage(t, 42, false, "API.Example.test", nil), at, false)
	answers := []layers.DNSResourceRecord{
		{Name: []byte("api.example.test"), Type: layers.DNSTypeCNAME, Class: layers.DNSClassIN, TTL: 10, CNAME: []byte("edge.example.test")},
		addressRecord("edge.example.test", "203.0.113.20", 60),
		addressRecord("unrelated.test", "203.0.113.99", 60),
	}
	sm.TrackDNSPacket("veth-test", resolver, client, "UDP", dnsMessage(t, 42, true, "api.example.test", answers), at.Add(time.Millisecond), false)
	rows := resolutions(t, sm)
	if len(rows) != 1 || rows[0].IP != "203.0.113.20" || rows[0].TTL != 10 || rows[0].TransactionID != 42 {
		t.Fatalf("incorrect evidence: %+v", rows)
	}
	if !rows[0].QueryTime.Equal(at) || !rows[0].ExpiresAt.Equal(at.Add(time.Millisecond+10*time.Second)) {
		t.Fatal("timestamps or TTL were lost")
	}
	if got := sm.dns.lookup("10.2.0.9", rows[0].IP, at.Add(time.Second)); len(got) != 0 {
		t.Fatal("another pod inherited DNS evidence")
	}
	if got := sm.dns.lookup("10.2.0.8", rows[0].IP, rows[0].ExpiresAt); len(got) != 0 {
		t.Fatal("expired mapping used")
	}
	sm.TrackTCP("veth-test", client, "[203.0.113.20]:443", true, false, false, 60, false)
	sm.flushEvents()
	var event database.NetworkEvent
	if err := sm.db.Where("event_type = ?", database.EventTCPStart).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	var ids []uint
	if json.Unmarshal([]byte(event.DNSResolutionIDs), &ids) != nil || len(ids) != 1 || ids[0] != rows[0].ID {
		t.Fatalf("connection missing evidence: %+v", event)
	}
	if event.Hostname != "api.example.test" {
		t.Fatal(event.Hostname)
	}
	restored := newDNSTracker()
	if err := restored.restore(sm.db); err != nil {
		t.Fatal(err)
	}
	if len(restored.lookup("10.2.0.8", rows[0].IP, at.Add(time.Second))) != 1 {
		t.Fatal("persisted evidence was not restored")
	}
}

func TestDNSRejectsUnprovenMappings(t *testing.T) {
	for _, scenario := range []string{"unsolicited", "wrong-client", "wrong-resolver", "wrong-id", "wrong-name", "wrong-type", "late", "truncated", "nxdomain", "unrelated-answer"} {
		t.Run(scenario, func(t *testing.T) {
			sm := testManager(t)
			at := time.Now()
			client, resolver := "[10.2.0.8]:40500", "[10.2.0.53]:53"
			if scenario != "unsolicited" {
				sm.TrackDNSPacket("eth0", client, resolver, "UDP", dnsMessage(t, 42, false, "api.test", nil), at, false)
			}
			message := layers.DNS{ID: 42, QR: true, Questions: []layers.DNSQuestion{{Name: []byte("api.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}, Answers: []layers.DNSResourceRecord{addressRecord("api.test", "203.0.113.20", 60)}}
			switch scenario {
			case "wrong-client":
				client = "[10.2.0.9]:40500"
			case "wrong-resolver":
				resolver = "[10.2.0.54]:53"
			case "wrong-id":
				message.ID++
			case "wrong-name":
				message.Questions[0].Name = []byte("other.test")
			case "wrong-type":
				message.Questions[0].Type = layers.DNSTypeAAAA
			case "late":
				at = at.Add(time.Minute)
			case "truncated":
				message.TC = true
			case "nxdomain":
				message.ResponseCode = layers.DNSResponseCodeNXDomain
			case "unrelated-answer":
				message.Answers[0].Name = []byte("other.test")
			}
			sm.TrackDNSPacket("eth0", resolver, client, "UDP", serializeDNS(t, message), at.Add(time.Millisecond), false)
			if got := resolutions(t, sm); len(got) != 0 {
				t.Fatalf("false DNS evidence: %+v", got)
			}
		})
	}
}

func TestDNSZeroTTLAndDuplicateResponse(t *testing.T) {
	sm := testManager(t)
	at := time.Now()
	query := dnsMessage(t, 1, false, "zero.test", nil)
	response := dnsMessage(t, 1, true, "zero.test", []layers.DNSResourceRecord{addressRecord("zero.test", "203.0.113.20", 0)})
	sm.TrackDNSPacket("veth0", "[10.2.0.8]:1000", "[10.2.0.53]:53", "UDP", query, at, false)
	for range 2 {
		sm.TrackDNSPacket("veth0", "[10.2.0.53]:53", "[10.2.0.8]:1000", "UDP", response, at.Add(time.Millisecond), false)
	}
	if got := resolutions(t, sm); len(got) != 1 {
		t.Fatalf("expected one historical mapping: %d", len(got))
	}
	if len(sm.dns.lookup("10.2.0.8", "203.0.113.20", at.Add(time.Second))) != 0 {
		t.Fatal("zero-TTL evidence was reused")
	}
}

func TestDNSTCPFramingAndMissingCapture(t *testing.T) {
	for _, gap := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "sequence-gap"}[gap], func(t *testing.T) {
			sm := testManager(t)
			at := time.Now()
			client, resolver := "[10.2.0.8]:1000", "[10.2.0.53]:53"
			frame := func(message []byte) []byte {
				result := make([]byte, 2)
				binary.BigEndian.PutUint16(result, uint16(len(message)))
				return append(result, message...)
			}
			query := frame(dnsMessage(t, 20, false, "tcp.test", nil))
			reply := frame(dnsMessage(t, 20, true, "tcp.test", []layers.DNSResourceRecord{addressRecord("tcp.test", "203.0.113.20", 60)}))
			sm.TrackDNSTCP("eth0", client, resolver, &layers.TCP{Seq: 100, SYN: true}, at, false)
			first := &layers.TCP{Seq: 101}
			first.Payload = query[:4]
			sm.TrackDNSTCP("eth0", client, resolver, first, at, false)
			second := &layers.TCP{Seq: 105}
			second.Payload = query[4:]
			if gap {
				second.Seq++
			}
			sm.TrackDNSTCP("eth0", client, resolver, second, at, false)
			sm.TrackDNSTCP("eth0", resolver, client, &layers.TCP{Seq: 200, SYN: true, ACK: true}, at, false)
			response := &layers.TCP{Seq: 201}
			response.Payload = reply
			sm.TrackDNSTCP("eth0", resolver, client, response, at.Add(time.Millisecond), false)
			want := 1
			if gap {
				want = 0
			}
			if rows := resolutions(t, sm); len(rows) != want {
				t.Fatalf("got %d mappings, want %d", len(rows), want)
			}
		})
	}
}

func TestDNSAnswerOwnershipIPv6AndLoops(t *testing.T) {
	duplicates := resolveAnswers("ttl.test", "A", []DNSRecord{{"ttl.test", "A", "203.0.113.20", 60}, {"ttl.test", "A", "203.0.113.20", 5}})
	if len(duplicates) != 1 || duplicates[0].TTL != 5 {
		t.Fatal("duplicate RR extended the observed TTL")
	}
	rows := resolveAnswers("v6.test", "AAAA", []DNSRecord{{"v6.test", "AAAA", "2001:db8::20", 20}, {"v6.test", "A", "203.0.113.1", 100}})
	if len(rows) != 1 || rows[0].IP != "2001:db8::20" {
		t.Fatal(rows)
	}
	rows = resolveAnswers("a.test", "A", []DNSRecord{{"a.test", "CNAME", "b.test", 20}, {"b.test", "CNAME", "a.test", 20}, {"a.test", "A", "203.0.113.1", 100}})
	if len(rows) != 0 {
		t.Fatal("CNAME cycle produced evidence")
	}
}

func TestDNSPodIPReuseDoesNotInheritEvidence(t *testing.T) {
	sm := testManager(t)
	identity := `{"UID":"old-pod"}`
	sm.contextLookup = func(string, uint16, string) string { return identity }
	at := time.Now().Add(-time.Second)
	sm.TrackDNSPacket("veth0", "[10.2.0.8]:1000", "[10.2.0.53]:53", "UDP", dnsMessage(t, 1, false, "api.test", nil), at, false)
	sm.TrackDNSPacket("veth0", "[10.2.0.53]:53", "[10.2.0.8]:1000", "UDP", dnsMessage(t, 1, true, "api.test", []layers.DNSResourceRecord{addressRecord("api.test", "203.0.113.20", 60)}), at.Add(time.Millisecond), false)
	identity = `{"UID":"replacement-pod"}`
	sm.TrackTCP("veth0", "[10.2.0.8]:5000", "[203.0.113.20]:443", true, false, false, 60, false)
	sm.flushEvents()
	var event database.NetworkEvent
	if err := sm.db.Where("event_type = ?", database.EventTCPStart).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.DNSResolutionIDs != "[]" || event.Hostname != "" {
		t.Fatalf("reused IP inherited another pod's proof: %+v", event)
	}
}

func TestTCPReplyRetainsOriginalConnectionDirection(t *testing.T) {
	sm := testManager(t)
	sm.TrackTCP("eth0", "[10.2.0.8]:5000", "[203.0.113.20]:443", true, false, false, 60, false)
	sm.TrackTCP("eth0", "[203.0.113.20]:443", "[10.2.0.8]:5000", false, true, false, 100, false)
	sm.flushEvents()
	var event database.NetworkEvent
	if err := sm.db.Where("event_type = ?", database.EventTCPEnd).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.SrcIP != "10.2.0.8" || event.DstPort != 443 || event.ByteCount != 160 {
		t.Fatalf("reply became a different connection: %+v", event)
	}
}
