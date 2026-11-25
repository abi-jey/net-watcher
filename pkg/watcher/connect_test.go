package watcher

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

func connectEvent(pid uint32, family uint16, comm string, src, dst netip.AddrPort, cgroup uint64) []byte {
	raw := make([]byte, connectEventSize)
	binary.NativeEndian.PutUint32(raw[0:], pid)
	binary.NativeEndian.PutUint16(raw[4:], family)
	binary.BigEndian.PutUint16(raw[6:], dst.Port())
	binary.NativeEndian.PutUint16(raw[8:], src.Port())
	copy(raw[16:32], comm)
	if src.Addr().Is4() {
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(raw[32:36], s[:])
		copy(raw[36:40], d[:])
	}
	if family == unix.AF_INET6 {
		s, d := src.Addr().As16(), dst.Addr().As16()
		copy(raw[40:56], s[:])
		copy(raw[56:72], d[:])
	}
	binary.NativeEndian.PutUint64(raw[72:], cgroup)
	return raw
}

func TestParseConnectEvent(t *testing.T) {
	v4src, v4dst := netip.MustParseAddrPort("10.0.1.155:41898"), netip.MustParseAddrPort("10.0.1.169:8000")
	for _, c := range []struct {
		name string
		raw  []byte
		want connectKey
	}{
		{"IPv4", connectEvent(13396, unix.AF_INET, "kubelet", v4src, v4dst, 7), connectKey{v4src, v4dst}},
		{"IPv6", connectEvent(13396, unix.AF_INET6, "kubelet", netip.MustParseAddrPort("[fd00::1]:5000"), netip.MustParseAddrPort("[fd00::2]:443"), 7),
			connectKey{netip.MustParseAddrPort("[fd00::1]:5000"), netip.MustParseAddrPort("[fd00::2]:443")}},
		// A dual-stack socket reaching an IPv4 address connects through IPv4:
		// its IPv6 source is still unset, the IPv4 fields hold both ends.
		{"IPv4-mapped", func() []byte {
			raw := connectEvent(13396, unix.AF_INET6, "kubelet", v4src, v4dst, 7)
			mapped := netip.AddrFrom16(v4dst.Addr().As16()).As16()
			copy(raw[40:56], make([]byte, 16))
			copy(raw[56:72], mapped[:])
			return raw
		}(), connectKey{v4src, v4dst}},
	} {
		pid, cgroup, comm, key, ok := parseConnectEvent(c.raw)
		if !ok || pid != 13396 || cgroup != 7 || comm != "kubelet" || key != c.want {
			t.Errorf("%s: pid=%d cgroup=%d comm=%q key=%v ok=%t, want %v", c.name, pid, cgroup, comm, key, ok, c.want)
		}
	}
	if _, _, _, _, ok := parseConnectEvent(connectEvent(1, unix.AF_INET, "x", netip.MustParseAddrPort("10.0.0.1:0"), v4dst, 0)); ok {
		t.Error("a record without a source port was accepted")
	}
	if _, _, _, _, ok := parseConnectEvent(make([]byte, 10)); ok {
		t.Error("a short record was accepted")
	}
}

// The record names the process, not the thread that connected, and its
// container, read while it still runs.
func TestConnectRecordsNameTheProcess(t *testing.T) {
	root := t.TempDir()
	process := filepath.Join(root, "4100")
	if err := os.MkdirAll(process, 0o755); err != nil {
		t.Fatal(err)
	}
	cgroup := "0::/kubepods.slice/kubepods-pod" + strings.ReplaceAll(testPodUID, "-", "_") + ".slice/crio-" + testContainerID + ".scope\n"
	if err := os.WriteFile(filepath.Join(process, "cgroup"), []byte(cgroup), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(process, "comm"), []byte("keda\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tracer := &connectTracer{root: root, records: map[connectKey]connectRecord{}, processes: map[connectProcessKey]connectProcess{}}
	src, dst := netip.MustParseAddrPort("10.0.1.84:51000"), netip.MustParseAddrPort("10.96.0.1:443")
	now := time.Now()
	tracer.add(connectEvent(4100, unix.AF_INET, "keda-worker-3", src, dst, 9), now)
	record, ok := tracer.opener(src, dst, now.Add(time.Second))
	if !ok || record.pid != 4100 || record.command != "keda" || record.containerID != testContainerID {
		t.Fatalf("record %+v, %t", record, ok)
	}
	// IPv4-mapped lookups find it too.
	if _, ok := tracer.opener(netip.AddrPortFrom(netip.AddrFrom16(src.Addr().As16()), src.Port()), dst, now); !ok {
		t.Fatal("mapped lookup missed")
	}
	if _, ok := tracer.opener(src, dst, now.Add(2*connectRecordTTL)); ok {
		t.Fatal("an expired record named a later connection")
	}
	// A process that exited before it was read stays unnamed.
	tracer.add(connectEvent(4200, unix.AF_INET, "curl", netip.MustParseAddrPort("10.0.1.84:51001"), dst, 9), now)
	if _, ok := tracer.opener(netip.MustParseAddrPort("10.0.1.84:51001"), dst, now); ok || tracer.unresolved.Load() != 1 {
		t.Fatal("an unreadable process was recorded")
	}
}

// The offsets of struct sock_common's connection fields have been the same
// for years; reading them from this kernel's BTF must agree.
func TestSocketOffsetsFromKernelBTF(t *testing.T) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skip("no kernel BTF:", err)
	}
	o, err := socketOffsets(kernel)
	if err != nil {
		t.Fatal(err)
	}
	if o.daddr != 0 || o.saddr != 4 || o.dport != 12 || o.sport != 14 || o.family != 16 || !o.ipv6 || o.daddr6 == 0 || o.saddr6 != o.daddr6+16 {
		t.Fatalf("offsets %+v", o)
	}
	if len(connectProgram(o)) == 0 {
		t.Fatal("no program")
	}
}

// Loads the program into the running kernel: needs CAP_BPF and CAP_PERFMON
// and the host's /proc (run with NET_WATCHER_BPF_TEST=1; see docs).
func TestConnectTracerRecordsConnections(t *testing.T) {
	if os.Getenv("NET_WATCHER_BPF_TEST") == "" {
		t.Skip("set NET_WATCHER_BPF_TEST=1 to load the eBPF program")
	}
	tracer, err := newConnectTracer("/proc")
	if err != nil {
		t.Fatal(err)
	}
	defer tracer.close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	src, dst := netip.MustParseAddrPort(conn.LocalAddr().String()), netip.MustParseAddrPort(conn.RemoteAddr().String())
	_ = conn.Close() // Recorded at connect: closing first changes nothing.
	deadline := time.Now().Add(2 * time.Second)
	for {
		record, ok := tracer.opener(src, dst, time.Now())
		if ok {
			if record.pid != os.Getpid() {
				t.Fatalf("pid %d, want %d", record.pid, os.Getpid())
			}
			comm, _ := os.ReadFile("/proc/self/comm")
			if want := string(comm[:len(comm)-1]); record.command != want {
				t.Fatalf("command %q, want %q", record.command, want)
			}
			break
		}
		if time.Now().After(deadline) {
			received, unresolved, lost, kept := tracer.stats(time.Now())
			t.Fatalf("no record for %v -> %v (received %d, unnamed %d, lost %d, kept %d)", src, dst, received, unresolved, lost, kept)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Log("recorded", src, "->", dst, "by pid", strconv.Itoa(os.Getpid()))
}
