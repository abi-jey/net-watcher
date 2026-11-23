package watcher

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
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

const (
	testPodUID      = "0f3e9c1a-1b2c-4d5e-8f90-123456789abc"
	testContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testSidecarID   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestParseCgroup(t *testing.T) {
	systemdUID := strings.ReplaceAll(testPodUID, "-", "_")
	for content, want := range map[string][2]string{
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + systemdUID + ".slice/cri-containerd-" + testContainerID + ".scope\n":        {testPodUID, testContainerID},
		"12:pids:/kubepods/besteffort/pod" + testPodUID + "/" + testContainerID + "\n11:cpu:/kubepods/besteffort/pod" + testPodUID + "/" + testContainerID: {testPodUID, testContainerID},
		"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + systemdUID + ".slice/crio-" + testContainerID + ".scope/container\n":      {testPodUID, testContainerID},
		"0::/kubepods.slice/kubepods-pod" + systemdUID + ".slice\n":                                                                                        {testPodUID, ""},
		"0::/system.slice/containerd.service\n": {"", ""},
	} {
		uid, id := parseCgroup(content)
		if uid != want[0] || id != want[1] {
			t.Errorf("%q: got %q %q", content, uid, id)
		}
	}
}

// procAddr encodes an address the way /proc/net/tcp prints it.
func procAddr(ip string, port uint16) string {
	b := netip.MustParseAddr(ip).AsSlice()
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return fmt.Sprintf("%X:%04X", b, port)
}

func socketRow(local string, localPort uint16, remote string, remotePort uint16, state, inode string) string {
	return fmt.Sprintf(" 0: %s %s %s 00000000:00000000 00:00000000 00000000 %d 0 %s 1\n", procAddr(local, localPort), procAddr(remote, remotePort), state, os.Getuid(), inode)
}

type fakeProcess struct {
	pid                 int
	netns, cgroup, comm string
	sockets             []string // Inodes held as file descriptors.
	tables              map[string]string
}

func writeFakeProc(t *testing.T, root string, processes []fakeProcess) {
	t.Helper()
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for _, p := range processes {
		dir := filepath.Join(root, fmt.Sprint(p.pid))
		for _, sub := range []string{"ns", "fd", "net"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
				t.Fatal(err)
			}
		}
		must := func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		}
		must(os.Symlink(p.netns, filepath.Join(dir, "ns", "net")))
		must(os.WriteFile(filepath.Join(dir, "cgroup"), []byte(p.cgroup), 0600))
		must(os.WriteFile(filepath.Join(dir, "comm"), []byte(p.comm+"\n"), 0600))
		must(os.Symlink("/dev/null", filepath.Join(dir, "fd", "0")))
		for i, inode := range p.sockets {
			must(os.Symlink("socket:["+inode+"]", filepath.Join(dir, "fd", fmt.Sprint(i+3))))
		}
		for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
			must(os.WriteFile(filepath.Join(dir, "net", table), []byte(header+p.tables[table]), 0600))
		}
	}
}

func newTestAttributor(t *testing.T) (*processAttributor, chan database.NetworkEvent) {
	t.Helper()
	root := t.TempDir()
	hostTables := map[string]string{"tcp": socketRow("192.0.2.10", 51000, "140.82.121.34", 443, "01", "900")}
	podTables := map[string]string{
		"tcp": socketRow("10.2.0.8", 40000, "10.96.0.1", 443, "01", "700") + socketRow("0.0.0.0", 8080, "0.0.0.0", 0, "0A", "701"),
		// The sidecar's dual-stack socket shows a v4 flow v4-mapped.
		"tcp6": socketRow("::ffff:10.2.0.8", 15001, "::ffff:10.2.0.20", 52000, "01", "702"),
		"udp":  socketRow("0.0.0.0", 5353, "0.0.0.0", 0, "07", "703"),
	}
	podCgroup := func(id string) string {
		return "0::/kubepods.slice/kubepods-pod" + strings.ReplaceAll(testPodUID, "-", "_") + ".slice/cri-containerd-" + id + ".scope\n"
	}
	writeFakeProc(t, root, []fakeProcess{
		{pid: 1, netns: "net:[1]", cgroup: "0::/init.scope\n", comm: "systemd", tables: hostTables},
		{pid: 200, netns: "net:[2]", cgroup: podCgroup(testContainerID), comm: "python3", sockets: []string{"700", "701", "703"}, tables: podTables},
		{pid: 201, netns: "net:[2]", cgroup: podCgroup(testSidecarID), comm: "envoy", sockets: []string{"702"}, tables: podTables},
		{pid: 300, netns: "net:[1]", cgroup: "0::/system.slice/k3s.service\n", comm: "k3s-server", sockets: []string{"900"}, tables: hostTables},
	})
	events := make(chan database.NetworkEvent, 16)
	a := &processAttributor{
		root:      root,
		addresses: func() map[string]bool { return map[string]bool{"192.0.2.10": true} },
		containers: func(id string) (string, string, string, bool) {
			name := map[string]string{testContainerID: "api", testSidecarID: "envoy"}[id]
			return "demo", "api-1", name, name != ""
		},
		onEvent: func(event database.NetworkEvent) { events <- event },
		logger:  log.Default(),
	}
	if err := a.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.stop)
	return a, events
}

// attributed passes an event through handle like the session does and
// returns it as it would be stored.
func attributed(t *testing.T, a *processAttributor, events chan database.NetworkEvent, event database.NetworkEvent) database.NetworkEvent {
	t.Helper()
	if !a.handle(&event) {
		return event
	}
	select {
	case event = <-events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("attributor never returned the event")
		return event
	}
}

func podSide(event *database.NetworkEvent, side string) {
	if side == "src" {
		event.SrcKind, event.SrcUID, event.SrcNamespace, event.SrcName = "pod", testPodUID, "demo", "api-1"
	} else {
		event.DstKind, event.DstUID, event.DstNamespace, event.DstName = "pod", testPodUID, "demo", "api-1"
	}
}

func TestProcessAttributionInPodAndHostNamespaces(t *testing.T) {
	a, events := newTestAttributor(t)

	outgoing := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "10.2.0.8", SrcPort: 40000, DstIP: "10.96.0.1", DstPort: 443}
	podSide(&outgoing, "src")
	accepted := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "10.2.0.30", SrcPort: 41000, DstIP: "10.2.0.8", DstPort: 8080,
		SrcKind: "pod", SrcUID: "elsewhere"}
	podSide(&accepted, "dst")
	sidecar := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "10.2.0.20", SrcPort: 52000, DstIP: "10.2.0.8", DstPort: 15001}
	podSide(&sidecar, "dst")
	query := database.NetworkEvent{EventType: database.EventUDPStart, SrcIP: "10.2.0.8", SrcPort: 5353, DstIP: "224.0.0.251", DstPort: 5353}
	podSide(&query, "src")
	host := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "192.0.2.10", SrcPort: 51000, DstIP: "140.82.121.34", DstPort: 443}

	for name, check := range map[string]struct {
		event                         database.NetworkEvent
		pid                           int
		command, side, pod, container string
	}{
		"pod client, exact socket":     {outgoing, 200, "python3", "src", "demo/api-1", "api"},
		"pod server, listening socket": {accepted, 200, "python3", "dst", "demo/api-1", "api"},
		"sidecar, v4-mapped socket":    {sidecar, 201, "envoy", "dst", "demo/api-1", "envoy"},
		"pod unconnected UDP socket":   {query, 200, "python3", "src", "demo/api-1", "api"},
		"host process":                 {host, 300, "k3s-server", "src", "", ""},
	} {
		got := attributed(t, a, events, check.event)
		if got.ProcessPID != check.pid || got.ProcessCommand != check.command || got.ProcessSide != check.side || got.ProcessPod != check.pod || got.ProcessContainer != check.container {
			t.Errorf("%s: pid=%d command=%q side=%q pod=%q container=%q", name, got.ProcessPID, got.ProcessCommand, got.ProcessSide, got.ProcessPod, got.ProcessContainer)
		}
	}

	// Later events of a flow reuse the identity without a lookup, in either
	// orientation, and are never queued.
	end := outgoing
	end.EventType = database.EventTCPEnd
	if a.handle(&end) || end.ProcessPID != 200 || end.ProcessSide != "src" {
		t.Fatalf("flow end not attributed from cache: %+v", end)
	}
	reply := database.NetworkEvent{EventType: database.EventTCPEnd, SrcIP: "10.96.0.1", SrcPort: 443, DstIP: "10.2.0.8", DstPort: 40000}
	if a.handle(&reply) || reply.ProcessPID != 200 || reply.ProcessSide != "dst" {
		t.Fatalf("reverse orientation: %+v", reply)
	}

	// Traffic with no endpoint on this node is not looked up.
	transit := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "198.51.100.1", SrcPort: 1, DstIP: "203.0.113.1", DstPort: 2}
	if a.handle(&transit) || transit.ProcessSide != "" {
		t.Fatalf("transit flow queued or attributed: %+v", transit)
	}
	// A second client of the listener is found through the socket index,
	// without scanning descriptors again.
	before := a.indexed.Load()
	second := accepted
	second.SrcPort++
	if got := attributed(t, a, events, second); got.ProcessPID != 200 || got.ProcessSide != "dst" || a.indexed.Load() != before+1 {
		t.Fatalf("second accepted connection: %+v, indexed %d -> %d", got, before, a.indexed.Load())
	}
	// A source port that equals a listener's port (as after NAT) is not the
	// listener's connection.
	sourcePort := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "10.2.0.8", SrcPort: 8080, DstIP: "10.96.0.5", DstPort: 443}
	podSide(&sourcePort, "src")
	if got := attributed(t, a, events, sourcePort); got.ProcessSide != "" {
		t.Fatalf("listener attributed as a client: %+v", got)
	}
	// A different connection on the same port is not matched to the client socket.
	other := outgoing
	other.DstPort = 8443
	if got := attributed(t, a, events, other); got.ProcessSide != "" {
		t.Fatalf("matched an unrelated connection: %+v", got)
	}
}

func TestProcessAttributionNeverBlocksPackets(t *testing.T) {
	a := &processAttributor{jobs: make(chan processJob, 1), flows: map[string]processIdentity{}, logger: log.Default()}
	event := database.NetworkEvent{EventType: database.EventTCPStart, SrcKind: "pod", SrcUID: "x"}
	if !a.handle(&event) || a.handle(&event) || a.queueFull.Load() != 1 {
		t.Fatal("a full queue blocked or was not counted")
	}
	a.stop()
	if a.handle(&event) {
		t.Fatal("queued after stop")
	}
}

func TestProcessAttributionRequiresNamespaceAccess(t *testing.T) {
	if _, err := newProcessAttributor(t.TempDir(), nil, log.Default(), func(database.NetworkEvent) {}); err == nil {
		t.Fatal("started without a readable host procfs")
	}
}
