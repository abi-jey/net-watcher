package watcher

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/abja/net-watcher/internal/kube"
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

func newTestAttributor(t *testing.T, configure ...func(*processAttributor)) (*processAttributor, chan database.NetworkEvent) {
	t.Helper()
	root := t.TempDir()
	hostTables := map[string]string{"tcp": socketRow("192.0.2.10", 51000, "140.82.121.34", 443, "01", "900") +
		// The kubelet's health check of the pod's server.
		socketRow("192.0.2.10", 52000, "10.2.0.8", 8080, "01", "901")}
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
		{pid: 301, netns: "net:[1]", cgroup: "0::/system.slice/kubelet.service\n", comm: "kubelet", sockets: []string{"901"}, tables: hostTables},
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
	for _, change := range configure {
		change(a)
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
	// A kernel-owned tunnel (no socket on the node) is looked up once, then
	// skipped for a while whatever its varying source port.
	tunnel := database.NetworkEvent{EventType: database.EventUDPStart, SrcIP: "192.0.2.10", SrcPort: 40001, DstIP: "198.51.100.9", DstPort: 8472}
	misses := a.knownMiss.Load()
	for port := range uint16(3) {
		tunnel.SrcPort += port
		if got := attributed(t, a, events, tunnel); got.ProcessSide != "" {
			t.Fatalf("tunnel attributed: %+v", got)
		}
	}
	if a.knownMiss.Load() != misses+2 {
		t.Fatalf("known misses %d -> %d, want +2", misses, a.knownMiss.Load())
	}
	// DNS responses never start a lookup; they reuse the query's result.
	response := database.NetworkEvent{EventType: database.EventDNS, DNSType: "RESPONSE", SrcIP: "10.96.0.10", SrcPort: 53, DstIP: "10.2.0.8", DstPort: 5353}
	podSide(&response, "dst")
	if a.handle(&response) {
		t.Fatal("DNS response queued for lookup")
	}
	// A different connection on the same port is not matched to the client socket.
	other := outgoing
	other.DstPort = 8443
	if got := attributed(t, a, events, other); got.ProcessSide != "" {
		t.Fatalf("matched an unrelated connection: %+v", got)
	}
}

// A connection between two processes on this node, such as the kubelet's
// health check of a local pod, records both: the opener and the acceptor.
func TestProcessAttributionRecordsBothLocalEnds(t *testing.T) {
	a, events := newTestAttributor(t)
	check := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "192.0.2.10", SrcPort: 52000, DstIP: "10.2.0.8", DstPort: 8080, SrcKind: "node"}
	podSide(&check, "dst")
	got := attributed(t, a, events, check)
	if got.ProcessSide != "src" || got.ProcessCommand != "kubelet" || got.ProcessPID != 301 || got.ProcessPod != "" {
		t.Fatalf("opener: side=%q command=%q pid=%d pod=%q", got.ProcessSide, got.ProcessCommand, got.ProcessPID, got.ProcessPod)
	}
	if got.PeerProcessCommand != "python3" || got.PeerProcessPID != 200 || got.PeerProcessPod != "demo/api-1" || got.PeerProcessContainer != "api" {
		t.Fatalf("acceptor: command=%q pid=%d pod=%q container=%q", got.PeerProcessCommand, got.PeerProcessPID, got.PeerProcessPod, got.PeerProcessContainer)
	}
	if a.bothEnds.Load() != 1 {
		t.Fatalf("both_ends = %d, want 1", a.bothEnds.Load())
	}
	// The client's end is looked up first, while its socket still exists;
	// the server's listener outlives the connection.
	if c := a.candidates(check, time.Now(), time.Now()); len(c) != 2 || c[0].side != "src" || !c[0].host {
		t.Fatalf("lookup order: %+v", c)
	}
	// The server's reply carries the same two processes, its own end first.
	reply := database.NetworkEvent{EventType: database.EventTCPEnd, SrcIP: "10.2.0.8", SrcPort: 8080, DstIP: "192.0.2.10", DstPort: 52000}
	if a.handle(&reply) || reply.ProcessSide != "src" || reply.ProcessCommand != "python3" || reply.PeerProcessCommand != "kubelet" || reply.PeerProcessPod != "" {
		t.Fatalf("reply: %+v", reply)
	}
}

func TestSecondEndLookupsNeedSpareBudget(t *testing.T) {
	now := time.Now()
	b := newWorkBudget(10*time.Millisecond, now)
	if !b.spare(now) {
		t.Fatal("a full budget has room to spare")
	}
	b.spend(7 * time.Millisecond)
	if b.spare(now) || !b.ready(now) {
		t.Fatal("3ms left of 10ms/s: first lookups may run, second-end lookups may not")
	}
	if !b.spare(now.Add(300 * time.Millisecond)) {
		t.Fatal("the allowance refills")
	}
}

func TestProcessAttributionNeverBlocksPackets(t *testing.T) {
	a := &processAttributor{jobs: make(chan processJob, 1), flows: map[string]flowProcesses{}, logger: log.Default()}
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
	if _, err := newProcessAttributor(t.TempDir(), nil, 0, false, log.Default(), func(database.NetworkEvent) {}); err == nil {
		t.Fatal("started without a readable host procfs")
	}
}

// Processes running as another user keep their descriptors private even from
// CAP_SYS_PTRACE. The socket's owner then names container and command when
// every process of that owner in the pod agrees; the PID stays unknown.
func TestProcessIdentifiedBySocketOwnerWhenDescriptorsArePrivate(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads private descriptor directories")
	}
	for name, commands := range map[string][2]string{"same command": {"gunicorn", "gunicorn"}, "different commands": {"gunicorn", "celery"}} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			tables := map[string]string{"tcp": socketRow("10.2.0.8", 40000, "10.96.0.1", 443, "01", "800")}
			cgroup := "0::/kubepods.slice/kubepods-pod" + strings.ReplaceAll(testPodUID, "-", "_") + ".slice/crio-" + testContainerID + ".scope/container\n"
			writeFakeProc(t, root, []fakeProcess{
				{pid: 1, netns: "net:[1]", cgroup: "0::/init.scope\n", comm: "systemd"},
				{pid: 400, netns: "net:[4]", cgroup: cgroup, comm: commands[0], sockets: []string{"800"}, tables: tables},
				{pid: 401, netns: "net:[4]", cgroup: cgroup, comm: commands[1], tables: tables},
			})
			for _, pid := range []string{"400", "401"} {
				directory := filepath.Join(root, pid, "fd")
				if err := os.Chmod(directory, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
			}
			events := make(chan database.NetworkEvent, 4)
			a := &processAttributor{root: root, addresses: func() map[string]bool { return map[string]bool{} },
				containers: func(string) (string, string, string, bool) { return "demo", "api-1", "api", true },
				onEvent:    func(event database.NetworkEvent) { events <- event }, logger: log.Default()}
			if err := a.start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.stop)
			event := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "10.2.0.8", SrcPort: 40000, DstIP: "10.96.0.1", DstPort: 443}
			podSide(&event, "src")
			got := attributed(t, a, events, event)
			if commands[0] == commands[1] {
				if got.ProcessPID != 0 || got.ProcessCommand != "gunicorn" || got.ProcessContainer != "api" || got.ProcessSide != "src" || a.byOwner.Load() != 1 {
					t.Fatalf("not identified by owner: %+v", got)
				}
			} else if got.ProcessSide != "" {
				t.Fatalf("ambiguous owner attributed: %+v", got)
			}
		})
	}
}

// One socket table read serves every lookup queued before it started: such a
// read lists each of their sockets that was still open. Flows queued later
// need a new read, and the table that held a namespace's last socket is read
// first.
func TestSocketTableReadServesLookupsQueuedBeforeIt(t *testing.T) {
	a, _ := newTestAttributor(t)
	procDir := filepath.Join(a.root, "200")
	deadline := time.Now().Add(time.Minute)
	queued := time.Now()
	client := candidate{side: "src", ip: "10.2.0.8", port: 40000, otherIP: "10.96.0.1", otherPort: 443, netns: "net:[2]", queuedAt: queued}
	if inode, _, _ := a.findSocket(client, procDir, false, deadline); inode != "700" {
		t.Fatalf("client socket: %q", inode)
	}
	server := candidate{side: "dst", ip: "10.2.0.8", port: 8080, otherIP: "10.2.0.30", otherPort: 41000, netns: "net:[2]", queuedAt: queued}
	if inode, _, _ := a.findSocket(server, procDir, false, deadline); inode != "701" || a.tableReads.Load() != 1 || a.tableReuse.Load() != 1 {
		t.Fatalf("listener %q from %d reads, %d reused", inode, a.tableReads.Load(), a.tableReuse.Load())
	}

	// A socket opened after the read is found by a flow queued after it.
	file, err := os.OpenFile(filepath.Join(procDir, "net", "tcp"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString(socketRow("10.2.0.8", 40001, "10.96.0.1", 443, "01", "704"))
	_ = file.Close()
	later := client
	later.port, later.queuedAt = 40001, time.Now()
	if inode, _, _ := a.findSocket(later, procDir, false, deadline); inode != "704" || a.tableReads.Load() != 2 {
		t.Fatalf("new socket %q after %d reads", inode, a.tableReads.Load())
	}

	// The sidecar's dual-stack socket is in tcp6; after one find there, the
	// namespace's tcp6 table is read first.
	sidecar := candidate{side: "src", ip: "10.2.0.8", port: 15001, otherIP: "10.2.0.20", otherPort: 52000, netns: "net:[2]", queuedAt: time.Now()}
	if inode, _, _ := a.findSocket(sidecar, procDir, false, deadline); inode != "702" || a.tableReads.Load() != 4 {
		t.Fatalf("v4-mapped socket %q after %d reads", inode, a.tableReads.Load())
	}
	sidecar.queuedAt = time.Now()
	if inode, _, _ := a.findSocket(sidecar, procDir, false, deadline); inode != "702" || a.tableReads.Load() != 5 {
		t.Fatalf("tcp6 not read first: %q after %d reads", inode, a.tableReads.Load())
	}
}

func TestHostSocketsAreQueriedFromTheKernel(t *testing.T) {
	self, err := os.Readlink(selfNetnsPath)
	if err != nil {
		t.Skipf("own network namespace: %v", err)
	}
	if diag, err := openSockDiag(); err != nil {
		t.Skipf("sock_diag unavailable: %v", err)
	} else {
		diag.close()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()

	// The host namespace is this test's own, and its socket tables are empty:
	// only a kernel query can find the connection.
	root := t.TempDir()
	writeFakeProc(t, root, []fakeProcess{
		{pid: 1, netns: self, cgroup: "0::/init.scope\n", comm: "systemd"},
		{pid: 400, netns: self, cgroup: "0::/system.slice/fetch.service\n", comm: "fetch",
			sockets: []string{fmt.Sprint(socketInode(t, client.(*net.TCPConn)))}},
		{pid: 401, netns: self, cgroup: "0::/system.slice/web.service\n", comm: "web",
			sockets: []string{fmt.Sprint(socketInode(t, listener.(*net.TCPListener))), fmt.Sprint(socketInode(t, server.(*net.TCPConn)))}},
	})
	events := make(chan database.NetworkEvent, 4)
	// This tests which lookups run, not how fast: a shared CI runner under the
	// race detector has taken 47ms for one, past the default deadline and the
	// host's budget.
	a := &processAttributor{root: root, logger: log.Default(), budget: time.Second, deadline: time.Second,
		addresses:  func() map[string]bool { return map[string]bool{"127.0.0.1": true} },
		containers: func(string) (string, string, string, bool) { return "", "", "", false },
		onEvent:    func(event database.NetworkEvent) { events <- event }}
	if err := a.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.stop)
	if a.diag == nil {
		t.Fatal("kernel socket queries not used in the collector's own namespace")
	}

	clientAddr, serverAddr := client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)
	connection := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "127.0.0.1", SrcPort: uint16(clientAddr.Port), DstIP: "127.0.0.1", DstPort: uint16(serverAddr.Port)}
	if got := attributed(t, a, events, connection); got.ProcessPID != 400 || got.ProcessCommand != "fetch" || got.ProcessSide != "src" ||
		got.PeerProcessPID != 401 || got.PeerProcessCommand != "web" {
		t.Fatalf("host client and server: pid=%d command=%q side=%q, peer pid=%d command=%q", got.ProcessPID, got.ProcessCommand, got.ProcessSide, got.PeerProcessPID, got.PeerProcessCommand)
	}
	// A connection from a port nothing holds (forwarded traffic after NAT)
	// reaches the server's listener on the receiving side only.
	forwarded := connection
	forwarded.SrcPort = 9
	if got := attributed(t, a, events, forwarded); got.ProcessPID != 401 || got.ProcessSide != "dst" {
		t.Fatalf("forwarded connection: pid=%d side=%q", got.ProcessPID, got.ProcessSide)
	}
	if a.tableReads.Load() != 0 || a.diagLookups.Load() < 3 {
		t.Fatalf("tables read %d, kernel queries %d", a.tableReads.Load(), a.diagLookups.Load())
	}
}

// Connections from a node to its pods' probe ports are matched against the
// pods' probes; other connections are not looked up.
func TestNodeToPodConnectionsAreMatchedToProbes(t *testing.T) {
	sm := testManager(t)
	sm.contextLookup = func(ip string, _ uint16, _ string, _ time.Time) kube.Attribution {
		if ip == "10.0.1.155" {
			return kube.Attribution{Kind: "node", Name: "abja"}
		}
		return kube.Attribution{Kind: "pod", Namespace: "keda", Name: ip}
	}
	var asked []string
	sm.probeLookup = func(ip string, port uint16, node string, _ time.Time) string {
		asked = append(asked, fmt.Sprintf("%s:%d from %s", ip, port, node))
		if ip == "10.0.1.84" && port == 8081 && node == "abja" {
			return "keda-operator:liveness,readiness"
		}
		return ""
	}
	sm.TrackTCP("lxc1", "[10.0.1.155]:44640", "[10.0.1.84]:8081", true, false, false, 60, false)
	sm.TrackTCP("lxc1", "[10.0.1.155]:44650", "[10.0.1.84]:9999", true, false, false, 60, false)
	sm.TrackTCP("lxc2", "[10.0.1.90]:5000", "[10.0.1.84]:8081", true, false, false, 60, false)
	sm.flushEvents()
	var events []database.NetworkEvent
	if err := sm.db.Where("event_type = ?", database.EventTCPStart).Order("src_port").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	probes := map[uint16]string{}
	for _, e := range events {
		probes[e.SrcPort] = e.Probe
	}
	if want := map[uint16]string{44640: "keda-operator:liveness,readiness", 44650: "", 5000: ""}; !reflect.DeepEqual(probes, want) {
		t.Fatalf("probes by source port = %v, want %v", probes, want)
	}
	if want := []string{"10.0.1.84:8081 from abja", "10.0.1.84:9999 from abja"}; !reflect.DeepEqual(asked, want) {
		t.Fatalf("looked up %v, want %v (pod to pod is not a probe)", asked, want)
	}
}

// A probe match stands unless the connection's opener was identified as a
// process other than the kubelet.
func TestProbeMatchYieldsToAnotherObservedOpener(t *testing.T) {
	kubelet := processIdentity{PID: 301, Command: "kubelet"}
	server := processIdentity{PID: 200, Command: "python3", Pod: "demo/api-1", Container: "api"}
	tunnel := processIdentity{PID: 900, Command: "cloudflared", Pod: "cloudflared/cloudflared-nrm9h", Container: "cloudflared"}
	for _, c := range []struct {
		name string
		flow flowProcesses
		keep bool
	}{
		{"the kubelet opened it", flowProcesses{src: kubelet, hasSrc: true, dst: server, hasDst: true}, true},
		{"only the server is known", flowProcesses{dst: server, hasDst: true}, true},
		{"no process known", flowProcesses{}, true},
		{"a kubelet embedded in k3s", flowProcesses{src: processIdentity{PID: 7, Command: "k3s-agent"}, hasSrc: true}, true},
		{"a host-network pod opened it", flowProcesses{src: tunnel, hasSrc: true, dst: server, hasDst: true}, false},
	} {
		event := database.NetworkEvent{Probe: "api:liveness"}
		c.flow.apply(&event)
		if kept := event.Probe != ""; kept != c.keep {
			t.Errorf("%s: probe kept = %v, want %v", c.name, kept, c.keep)
		}
	}
}

type fakeConnects map[connectKey]connectRecord

func (f fakeConnects) opener(src, dst netip.AddrPort, _ time.Time) (connectRecord, bool) {
	record, ok := f[connectKey{src, dst}]
	return record, ok
}
func (f fakeConnects) stats(time.Time) (uint64, uint64, uint64, int) { return 0, 0, 0, len(f) }
func (f fakeConnects) close()                                        {}

// A health check whose kubelet socket has closed: connect tracing names the
// opener without a lookup, and the server's lookup still runs as the first
// one, needing only a ready budget, not a spare one.
func TestTracedOpenerOfAClosedConnection(t *testing.T) {
	src, dst := netip.MustParseAddrPort("192.0.2.10:52999"), netip.MustParseAddrPort("10.2.0.8:8080")
	a, events := newTestAttributor(t, func(a *processAttributor) {
		a.connects = fakeConnects{{src, dst}: {pid: 301, command: "kubelet", at: time.Now()}}
	})
	a.podWork.spend(a.podWork.available * 3 / 4) // Ready, nothing to spare.
	check := database.NetworkEvent{EventType: database.EventTCPStart, Timestamp: time.Now(), SrcIP: "192.0.2.10", SrcPort: 52999, DstIP: "10.2.0.8", DstPort: 8080, SrcKind: "node"}
	podSide(&check, "dst")
	got := attributed(t, a, events, check)
	if got.ProcessSide != "src" || got.ProcessCommand != "kubelet" || got.ProcessPID != 301 || got.ProcessPod != "" {
		t.Fatalf("opener: side=%q command=%q pid=%d pod=%q", got.ProcessSide, got.ProcessCommand, got.ProcessPID, got.ProcessPod)
	}
	if got.PeerProcessCommand != "python3" || got.PeerProcessPod != "demo/api-1" {
		t.Fatalf("acceptor: %q %q", got.PeerProcessCommand, got.PeerProcessPod)
	}
	if a.traced.Load() != 1 || a.peerSkipped.Load() != 0 {
		t.Fatalf("traced=%d second_end_skipped=%d", a.traced.Load(), a.peerSkipped.Load())
	}
	// A pod's connection names the pod even before its container is known.
	podSrc := netip.MustParseAddrPort("10.2.0.8:40999")
	a.connects.(fakeConnects)[connectKey{podSrc, netip.MustParseAddrPort("10.96.0.1:443")}] = connectRecord{pid: 4242, command: "worker", containerID: "unknown", at: time.Now()}
	outgoing := database.NetworkEvent{EventType: database.EventTCPStart, Timestamp: time.Now(), SrcIP: "10.2.0.8", SrcPort: 40999, DstIP: "10.96.0.1", DstPort: 443}
	podSide(&outgoing, "src")
	if identity, ok := a.connectOpener(outgoing); !ok || identity.Pod != "demo/api-1" || identity.Command != "worker" || identity.Container != "" {
		t.Fatalf("pod opener %+v %t", identity, ok)
	}
}

// Ends of a kernel tunnel are the kernel's: no lookup, no process scan.
func TestKernelTunnelEnds(t *testing.T) {
	a, events := newTestAttributor(t, func(a *processAttributor) {
		a.tunnelLookup = func() (map[uint16]string, error) { return map[uint16]string{8472: "vxlan cilium_vxlan"}, nil }
	})
	sent := attributed(t, a, events, database.NetworkEvent{EventType: database.EventUDPStart, SrcIP: "192.0.2.10", SrcPort: 53735, DstIP: "192.0.2.20", DstPort: 8472, SrcKind: "node", DstKind: "node"})
	if sent.ProcessSide != "src" || sent.ProcessCommand != "kernel" || sent.ProcessPID != 0 {
		t.Fatalf("sent: %+v", sent)
	}
	received := attributed(t, a, events, database.NetworkEvent{EventType: database.EventUDPStart, SrcIP: "192.0.2.20", SrcPort: 40000, DstIP: "192.0.2.10", DstPort: 8472, SrcKind: "node", DstKind: "node"})
	if received.ProcessSide != "dst" || received.ProcessCommand != "kernel" {
		t.Fatalf("received: %+v", received)
	}
	if a.kernelEnds.Load() != 2 || a.attempted.Load() != 0 {
		t.Fatalf("kernel=%d attempted=%d: tunnel ends must not be looked up", a.kernelEnds.Load(), a.attempted.Load())
	}
	// Not a tunnel: TCP to that port, or UDP to it at an address that is no node.
	for _, event := range []database.NetworkEvent{
		{EventType: database.EventTCPStart, SrcIP: "192.0.2.10", SrcPort: 53736, DstIP: "192.0.2.20", DstPort: 8472, SrcKind: "node", DstKind: "node"},
		{EventType: database.EventUDPStart, SrcIP: "192.0.2.10", SrcPort: 53737, DstIP: "203.0.113.9", DstPort: 8472, SrcKind: "node"},
	} {
		if got := attributed(t, a, events, event); got.ProcessCommand == "kernel" {
			t.Fatalf("not a tunnel end: %+v", got)
		}
	}
}

func TestTunnelInfoFromLinkAttributes(t *testing.T) {
	attr := func(kind uint16, value []byte) []byte {
		length := unix.SizeofRtAttr + len(value)
		out := make([]byte, (length+3)&^3)
		binary.NativeEndian.PutUint16(out[0:], uint16(length))
		binary.NativeEndian.PutUint16(out[2:], kind)
		copy(out[unix.SizeofRtAttr:], value)
		return out
	}
	port := func(n uint16) []byte { return binary.BigEndian.AppendUint16(nil, n) }
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	vxlan := join(attr(unix.IFLA_INFO_KIND, []byte("vxlan\x00")),
		attr(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, join(attr(unix.IFLA_VXLAN_ID, []byte{1, 0, 0, 0}), attr(unix.IFLA_VXLAN_PORT, port(8472)))))
	if kind, got := tunnelInfo(vxlan); kind != "vxlan" || got != 8472 {
		t.Fatalf("vxlan: %q %d", kind, got)
	}
	geneve := join(attr(unix.IFLA_INFO_KIND, []byte("geneve")), attr(unix.IFLA_INFO_DATA, attr(unix.IFLA_GENEVE_PORT, port(6081))))
	if kind, got := tunnelInfo(geneve); kind != "geneve" || got != 6081 {
		t.Fatalf("geneve: %q %d", kind, got)
	}
	if _, got := tunnelInfo(join(attr(unix.IFLA_INFO_KIND, []byte("veth")))); got != 0 {
		t.Fatal("veth has no tunnel port")
	}
	if _, got := tunnelInfo([]byte{0xff, 0xff, 1}); got != 0 {
		t.Fatal("garbage parsed")
	}
	// The host's own links list without privilege.
	if _, err := tunnelPorts(); err != nil {
		t.Fatal(err)
	}
}

// A short connection's end arrives while its start still waits for a
// lookup: it follows the start through the queue and inherits both ends.
func TestEndOfAShortConnectionFollowsItsStart(t *testing.T) {
	gate := make(chan struct{})
	var once sync.Once
	a, events := newTestAttributor(t, func(a *processAttributor) {
		deliver := a.onEvent
		a.onEvent = func(event database.NetworkEvent) {
			once.Do(func() { <-gate }) // The worker is busy with an earlier event.
			deliver(event)
		}
	})
	earlier := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "10.2.0.8", SrcPort: 40000, DstIP: "10.96.0.1", DstPort: 443}
	podSide(&earlier, "src")
	start := database.NetworkEvent{EventType: database.EventTCPStart, SrcIP: "192.0.2.10", SrcPort: 52000, DstIP: "10.2.0.8", DstPort: 8080, SrcKind: "node"}
	podSide(&start, "dst")
	end := start
	end.EventType, end.Reason = database.EventTCPEnd, "FIN"
	for _, event := range []*database.NetworkEvent{&earlier, &start, &end} {
		if !a.handle(event) {
			t.Fatalf("%s was not queued", event.EventType)
		}
	}
	close(gate)
	var got []database.NetworkEvent
	for range 3 {
		select {
		case event := <-events:
			got = append(got, event)
		case <-time.After(5 * time.Second):
			t.Fatal("events not returned")
		}
	}
	last := got[2]
	if last.EventType != database.EventTCPEnd || last.ProcessCommand != "kubelet" || last.PeerProcessCommand != "python3" {
		t.Fatalf("end: %+v", last)
	}
	if a.isPending(start) {
		t.Fatal("the start is still counted as queued")
	}
	// With nothing queued for its flow, an end is not queued.
	orphan := database.NetworkEvent{EventType: database.EventTCPEnd, SrcIP: "192.0.2.10", SrcPort: 52555, DstIP: "10.2.0.8", DstPort: 8080}
	if a.handle(&orphan) {
		t.Fatal("an end without a queued start was queued")
	}
}
