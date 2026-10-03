package watcher

import (
	"io"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ownedReader struct {
	last  []byte
	reads byte
}

func (r *ownedReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	r.reads++
	r.last = []byte{r.reads, 2, 3}
	return r.last, gopacket.CaptureInfo{CaptureLength: 3, Length: 3}, nil
}

func TestOwnedPacketSourceDoesNotCopyOrReusePacketBytes(t *testing.T) {
	r := &ownedReader{}
	source := ownedPacketSource(r, gopacket.LayerTypePayload)
	first, err := source.NextPacket()
	if err != nil {
		t.Fatal(err)
	}
	if &first.Data()[0] != &r.last[0] {
		t.Fatal("packet source copied an already-owned buffer")
	}
	second, err := source.NextPacket()
	if err != nil {
		t.Fatal(err)
	}
	if first.Data()[0] != 1 || second.Data()[0] != 2 {
		t.Fatal("subsequent read modified retained packet bytes")
	}
}

type countedPacket struct {
	gopacket.Packet
	dataReads int
}

func (p *countedPacket) Data() []byte { p.dataReads++; return p.Packet.Data() }

func TestPacketHexFormattingOnlyAtDebugLevel(t *testing.T) {
	logger := log.New(io.Discard)
	packet := &countedPacket{Packet: gopacket.NewPacket([]byte{0x45}, layers.LayerTypeIPv4, gopacket.Default)}
	watcher := &Watcher{logger: logger}
	watcher.processPacket(packet, "test")
	if packet.dataReads != 0 {
		t.Fatal("disabled debug logging read packet bytes for formatting")
	}
	logger.SetLevel(log.DebugLevel)
	watcher.processPacket(packet, "test")
	if packet.dataReads != 1 {
		t.Fatal("debug packet dump did not read data")
	}
}

func TestDNSPruneIsThrottledWithoutExtendingEntryExpiry(t *testing.T) {
	d := newDNSTracker()
	at := time.Now()
	d.bindings["client\x00ip"] = []database.DNSResolution{{ResponseTime: at, ExpiresAt: at.Add(200 * time.Millisecond)}}
	d.prune(at)
	d.prune(at.Add(500 * time.Millisecond))
	if !d.lastPrune.Equal(at) || len(d.bindings) != 1 {
		t.Fatal("global scan was not throttled")
	}
	if rows := d.lookup("client", "ip", at.Add(500*time.Millisecond)); len(rows) != 0 {
		t.Fatal("expired evidence was usable between global scans")
	}
	d.prune(at.Add(dnsPruneInterval))
	if len(d.bindings) != 0 {
		t.Fatal("scheduled cleanup did not evict expired entries")
	}
}

func TestDNSReusedQueryIDExpiresBeforeNextGlobalScan(t *testing.T) {
	sm := testManager(t)
	at := time.Now().Add(-time.Minute)
	client, resolver := "[10.0.0.1]:12345", "[10.0.0.53]:53"
	query := dnsMessage(t, 1, false, "api.test", nil)
	sm.TrackDNSPacket("test", client, resolver, "UDP", query, at, false)
	sm.dns.prune(at.Add(dnsWindow - 100*time.Millisecond))
	newTime := at.Add(dnsWindow + 100*time.Millisecond)
	sm.TrackDNSPacket("test", client, resolver, "UDP", query, newTime, false)
	sm.TrackDNSPacket("test", resolver, client, "UDP", dnsMessage(t, 1, true, "api.test", []layers.DNSResourceRecord{addressRecord("api.test", "203.0.113.1", 60)}), newTime.Add(time.Millisecond), false)
	rows := resolutions(t, sm)
	if len(rows) != 1 || !rows[0].QueryTime.Equal(newTime) {
		t.Fatalf("reused ID retained expired query: %+v", rows)
	}
}

func TestDNSStreamExpiresBeforeNextGlobalScan(t *testing.T) {
	sm := testManager(t)
	at := time.Now().Add(-time.Minute)
	client, resolver := "[10.0.0.1]:12345", "[10.0.0.53]:53"
	sm.TrackDNSTCP("test", client, resolver, &layers.TCP{SYN: true, Seq: 100}, at, false)
	sm.dns.prune(at.Add(dnsWindow - 100*time.Millisecond))
	sm.TrackDNSTCP("test", client, resolver, &layers.TCP{Seq: 101, BaseLayer: layers.BaseLayer{Payload: []byte{0, 12}}}, at.Add(dnsWindow+100*time.Millisecond), false)
	if len(sm.dns.streams) != 0 {
		t.Fatal("expired TCP stream survived a throttled cleanup")
	}
}
