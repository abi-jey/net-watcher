package watcher

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
)

func TestParseProcAddress(t *testing.T) {
	for _, check := range []struct {
		encoded string
		ip      netip.Addr
		port    uint16
	}{
		{"5001A8C0:E1BA", netip.MustParseAddr("192.168.1.80"), 57786},
		{"00000000000000000000000001000000:01BB", netip.IPv6Loopback(), 443},
	} {
		ip, port, ok := parseProcAddress(check.encoded)
		if !ok || ip != check.ip || port != check.port {
			t.Fatalf("parsed %q as %s:%d, ok=%t", check.encoded, ip, port, ok)
		}
	}
}

func TestHostProcessLookupMatchesSocketInode(t *testing.T) {
	root := t.TempDir()
	pid := 1234
	if err := os.MkdirAll(filepath.Join(root, "net"), 0700); err != nil {
		t.Fatal(err)
	}
	fdDirectory := filepath.Join(root, fmt.Sprint(pid), "fd")
	if err := os.MkdirAll(fdDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	row := fmt.Sprintf(" 0: 5001A8C0:E1BA 2279528C:01BB 01 00000000:00000000 00:00000000 00000000 %d 0 4242 1\n", os.Getuid())
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"+row), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, fmt.Sprint(pid), "comm"), []byte("image-puller\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[4242]", filepath.Join(fdDirectory, "7")); err != nil {
		t.Fatal(err)
	}
	lookup := &processAttributor{root: root, hostIPs: map[string]bool{"192.168.1.80": true}}
	event := database.NetworkEvent{SrcIP: "192.168.1.80", SrcPort: 57786, DstIP: "140.82.121.34", DstPort: 443}
	identity, found := lookup.lookup(event, time.Now().Add(time.Second))
	if !found || identity.PID != pid || identity.Command != "image-puller" {
		t.Fatalf("lookup: %+v, found=%t", identity, found)
	}
	event.SrcPort++
	if _, found := lookup.lookup(event, time.Now().Add(time.Second)); found {
		t.Fatal("matched a different connection")
	}
	if _, found := lookup.lookup(event, time.Now().Add(-time.Second)); found {
		t.Fatal("ignored lookup deadline")
	}
}

func TestProcessAttributionQueueNeverWaitsForProcfs(t *testing.T) {
	lookup := &processAttributor{hostIPs: map[string]bool{"192.168.1.80": true}, jobs: make(chan database.NetworkEvent, 1)}
	event := database.NetworkEvent{SrcIP: "192.168.1.80", EventType: database.EventTLSSNI}
	if !lookup.enqueue(event) || lookup.enqueue(event) || lookup.queueFull.Load() != 1 {
		t.Fatal("attribution backpressure blocked or dropped packet events")
	}
}
