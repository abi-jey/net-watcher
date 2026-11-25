package watcher

// Connect tracing records which process opened each outgoing TCP connection
// on the node, at the moment it opened it. Socket lookups (process.go) run
// after the packet was captured and miss connections that have already
// closed: a kubelet health check lasts under a millisecond, while packets
// reach the collector in ring blocks up to 64 ms later.
//
// An eBPF program attached at the entry of the kernel's tcp_connect function
// (fentry, which needs CAP_BPF and CAP_PERFMON) copies the connecting task's
// process ID, command and cgroup, and the socket's addresses and ports, into
// a ring buffer. tcp_connect runs in the connecting process's context once
// the source port is chosen, for every network namespace: pods and host
// alike. The program is assembled here, without a C toolchain; the socket
// field offsets come from the running kernel's BTF. It only reads: it cannot
// change, delay or drop a connection.
//
// UDP has no connect: a socket bound to a port sends to anyone (a BitTorrent
// client's DHT, QUIC, a resolver), and lookups find its socket but often not
// the process holding it: the collector cannot list the descriptors of
// processes it does not own. A second program, at the entry of udp_sendmsg
// and udpv6_sendmsg, reports the sending process with the socket's inode,
// the number lookups find, at most once per socket every udpReportEvery
// while it sends: an LRU map in the kernel remembers when it last did.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	// connectEventSize is one ring buffer record:
	//
	//	 0 u32 process ID (tgid)   4 u16 family   6 be16 dport   8 u16 sport
	//	16 comm[16]               32 be32 IPv4 source          36 be32 IPv4 destination
	//	40 IPv6 source[16]        56 IPv6 destination[16]      72 u64 cgroup ID
	connectEventSize = 80
	connectRingBytes = 1 << 20 // About 12,000 records between reads.
	// udpEventSize is one UDP sender record:
	//
	//	 0 u32 process ID (tgid)   4 u16 family   6 u16 local port   8 u64 socket inode
	//	16 comm[16]               32 u64 cgroup ID
	udpEventSize   = 40
	udpRingBytes   = 1 << 18
	udpReportEvery = 30 * time.Second
	// udpSenderTTL keeps a socket's sender after its last report, for a
	// socket that receives for a while without sending. Inodes are not reused
	// while a socket lives, so a record cannot name another socket's process.
	udpSenderTTL   = 10 * time.Minute
	udpMaxSenders  = 100_000
	udpSeenSockets = 1 << 16 // Sockets the kernel remembers reporting.
	// A record is kept until the flow's start has surely been attributed:
	// lookups run within processQueueAge of the packet. Linux does not reuse
	// a connection's addresses and ports within TIME_WAIT (60 s), so a record
	// cannot name a later connection's opener.
	connectRecordTTL  = time.Minute
	connectMaxRecords = 100_000
	// Processes are named when their record arrives, while they still run;
	// the result is reused for the same process and cgroup.
	connectProcessTTL = 10 * time.Second
	// connectResolveRate bounds /proc reads for naming connecting processes.
	connectResolveRate = 2000 // Per second.
)

// sockOffsets are byte offsets of struct sock fields in the running kernel.
type sockOffsets struct {
	family, dport, sport, saddr, daddr uint32
	saddr6, daddr6                     uint32
	ipv6                               bool // The kernel has IPv6 socket fields.
	// socket is struct sock's sk_socket; inode is i_ino's offset from the
	// struct socket it points to, which socket_alloc places before its inode.
	socket, inode uint32
	hasInode      bool
}

// connectKey is a connection's source and destination; IPv4-mapped IPv6
// addresses are unmapped, as captured packets carry them.
type connectKey struct{ src, dst netip.AddrPort }

// connectRecord is the process that opened a connection.
type connectRecord struct {
	pid         int
	command     string
	containerID string // Empty for a process outside any container.
	at          time.Time
}

type connectProcess struct {
	command, containerID string
	at                   time.Time
}

type connectProcessKey struct {
	pid    uint32
	cgroup uint64
}

type connectTracer struct {
	root       string // Host procfs.
	collection *ebpf.Collection
	link       link.Link
	reader     *ringbuf.Reader
	done       chan struct{}

	// UDP senders (udpSenderProgram); nil when the kernel lacks what they need.
	udpLinks  []link.Link
	udpReader *ringbuf.Reader
	udpDone   chan struct{}

	mu        sync.Mutex
	records   map[connectKey]connectRecord
	senders   map[uint64]connectRecord // By socket inode.
	processes map[connectProcessKey]connectProcess
	second    int64 // Unix second of resolveCount.
	resolves  int

	received, unresolved atomic.Uint64
	sent, sentUnresolved atomic.Uint64
	lostSeen, sentLost   uint64 // Kernel drop counts already reported; under mu.
}

// traceStats are a tracer's counts since the last report.
type traceStats struct {
	connects, unnamed, lost uint64
	records                 int
	senders, sendersUnnamed uint64 // UDP sender records.
	sendersLost             uint64
	sockets                 int // UDP sockets with a known sender.
	udp                     bool
}

// newConnectTracer loads and attaches the program and starts reading its
// records. root is the host procfs, for naming the connecting processes.
func newConnectTracer(root string) (*connectTracer, error) {
	_ = rlimit.RemoveMemlock() // Needed only on kernels before 5.11.
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("kernel BTF: %w", err)
	}
	offsets, err := socketOffsets(kernel)
	if err != nil {
		return nil, err
	}
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"events": {Name: "nw_connects", Type: ebpf.RingBuf, MaxEntries: connectRingBytes},
			"lost":   {Name: "nw_connect_lost", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"connect": {Name: "nw_tcp_connect", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: "tcp_connect",
				License: "Dual MIT/GPL", Instructions: connectProgram(offsets)},
		},
	}
	// UDP senders, at each send function this kernel has (udpv6_sendmsg is
	// missing when IPv6 is a module, whose types vmlinux does not hold).
	var udpPrograms []string
	if offsets.hasInode {
		spec.Maps["udp_events"] = &ebpf.MapSpec{Name: "nw_udp_senders", Type: ebpf.RingBuf, MaxEntries: udpRingBytes}
		spec.Maps["udp_lost"] = &ebpf.MapSpec{Name: "nw_udp_lost", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}
		spec.Maps["udp_seen"] = &ebpf.MapSpec{Name: "nw_udp_seen", Type: ebpf.LRUHash, KeySize: 8, ValueSize: 8, MaxEntries: udpSeenSockets}
		for _, function := range []string{"udp_sendmsg", "udpv6_sendmsg"} {
			var fn *btf.Func
			if kernel.TypeByName(function, &fn) != nil {
				continue
			}
			name := "udp_" + strconv.Itoa(len(udpPrograms))
			spec.Programs[name] = &ebpf.ProgramSpec{Name: "nw_" + strings.TrimSuffix(function, "_sendmsg") + "_send", Type: ebpf.Tracing,
				AttachType: ebpf.AttachTraceFEntry, AttachTo: function, License: "Dual MIT/GPL", Instructions: udpSenderProgram(offsets)}
			udpPrograms = append(udpPrograms, name)
		}
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: kernel}})
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("loading the eBPF program needs CAP_BPF and CAP_PERFMON: %w", err)
		}
		return nil, fmt.Errorf("loading the eBPF program: %w", err)
	}
	t := &connectTracer{root: root, collection: collection, done: make(chan struct{}),
		records: map[connectKey]connectRecord{}, senders: map[uint64]connectRecord{}, processes: map[connectProcessKey]connectProcess{}}
	if t.reader, err = ringbuf.NewReader(collection.Maps["events"]); err != nil {
		collection.Close()
		return nil, err
	}
	if t.link, err = link.AttachTracing(link.TracingOptions{Program: collection.Programs["connect"], AttachType: ebpf.AttachTraceFEntry}); err != nil {
		_ = t.reader.Close()
		collection.Close()
		return nil, fmt.Errorf("attaching to tcp_connect: %w", err)
	}
	go t.run()
	if len(udpPrograms) > 0 {
		if t.udpReader, err = ringbuf.NewReader(collection.Maps["udp_events"]); err != nil {
			t.close()
			return nil, err
		}
		t.udpDone = make(chan struct{})
		go t.runSenders()
		for _, name := range udpPrograms {
			attached, err := link.AttachTracing(link.TracingOptions{Program: collection.Programs[name], AttachType: ebpf.AttachTraceFEntry})
			if err != nil {
				t.close()
				return nil, fmt.Errorf("attaching to %s: %w", spec.Programs[name].AttachTo, err)
			}
			t.udpLinks = append(t.udpLinks, attached)
		}
	}
	return t, nil
}

// udpSenderProgram reports the process sending on a UDP socket with the
// socket's inode, unless it reported that socket in the last udpReportEvery.
func udpSenderProgram(o sockOffsets) asm.Instructions {
	const event = -udpEventSize // The record, on the stack below the frame pointer.
	const inode = event + 8     // Also the key of the seen map.
	const seen = event - 8      // The seen map's value: when it was reported.
	const socket = seen - 8     // sk->sk_socket.
	const key = socket - 8      // Index 0 of the lost counter.
	read := func(to int32, size int32, base asm.Register, field uint32) asm.Instructions {
		return asm.Instructions{
			asm.Mov.Reg(asm.R3, base), asm.Add.Imm(asm.R3, int32(field)),
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, to),
			asm.Mov.Imm(asm.R2, size),
			asm.FnProbeReadKernel.Call(),
		}
	}
	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord), // struct sock *sk: the send function's first argument.
		asm.Mov.Imm(asm.R0, 0),
	}
	for offset := int16(key); offset < 0; offset += 8 {
		insns = append(insns, asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord))
	}
	insns = append(insns, read(socket, 8, asm.R6, o.socket)...)
	insns = append(insns,
		asm.LoadMem(asm.R7, asm.RFP, socket, asm.DWord),
		asm.JEq.Imm(asm.R7, 0, "exit"), // A kernel socket without a struct socket.
	)
	insns = append(insns, read(inode, 8, asm.R7, o.inode)...)
	insns = append(insns,
		asm.LoadMem(asm.R1, asm.RFP, inode, asm.DWord),
		asm.JEq.Imm(asm.R1, 0, "exit"),
		asm.FnKtimeGetNs.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LoadMapPtr(asm.R1, 0).WithReference("udp_seen"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, inode),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "report"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.R7),
		asm.Sub.Reg(asm.R2, asm.R1),
		asm.LoadImm(asm.R3, int64(udpReportEvery), asm.DWord),
		asm.JLT.Reg(asm.R2, asm.R3, "exit"), // Reported moments ago.
		asm.StoreMem(asm.RFP, seen, asm.R7, asm.DWord).WithSymbol("report"),
		asm.LoadMapPtr(asm.R1, 0).WithReference("udp_seen"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, inode),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, seen),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, event, asm.R0, asm.Word),
		asm.FnGetCurrentCgroupId.Call(),
		asm.StoreMem(asm.RFP, event+32, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, event+16), asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	insns = append(insns, read(event+4, 2, asm.R6, o.family)...)
	insns = append(insns, read(event+6, 2, asm.R6, o.sport)...)
	return append(insns,
		asm.LoadMapPtr(asm.R1, 0).WithReference("udp_events"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, event),
		asm.Mov.Imm(asm.R3, udpEventSize),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMapPtr(asm.R1, 0).WithReference("udp_lost"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, key),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
}

// connectProgram copies the connecting task and the socket's addresses into
// a ring buffer record, counting records the full buffer refused.
func connectProgram(o sockOffsets) asm.Instructions {
	const event = -connectEventSize // The record, on the stack below the frame pointer.
	const key = event - 8           // Index 0 of the lost counter.
	read := func(at int32, size int32, field uint32) asm.Instructions {
		return asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, event+at),
			asm.Mov.Imm(asm.R2, size),
			asm.Mov.Reg(asm.R3, asm.R6), asm.Add.Imm(asm.R3, int32(field)),
			asm.FnProbeReadKernel.Call(),
		}
	}
	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord), // struct sock *sk: tcp_connect's argument.
		asm.Mov.Imm(asm.R0, 0),
	}
	for offset := int16(key); offset < 0; offset += 8 {
		insns = append(insns, asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord))
	}
	insns = append(insns,
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, event, asm.R0, asm.Word),
		asm.FnGetCurrentCgroupId.Call(),
		asm.StoreMem(asm.RFP, event+72, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, event+16), asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	insns = append(insns, read(4, 2, o.family)...)
	insns = append(insns, read(6, 2, o.dport)...)
	insns = append(insns, read(8, 2, o.sport)...)
	insns = append(insns, read(32, 4, o.saddr)...)
	insns = append(insns, read(36, 4, o.daddr)...)
	if o.ipv6 {
		insns = append(insns, read(40, 16, o.saddr6)...)
		insns = append(insns, read(56, 16, o.daddr6)...)
	}
	return append(insns,
		asm.LoadMapPtr(asm.R1, 0).WithReference("events"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, event),
		asm.Mov.Imm(asm.R3, connectEventSize),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMapPtr(asm.R1, 0).WithReference("lost"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, key),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
}

// socketOffsets finds the connection fields of struct sock in kernel BTF.
func socketOffsets(kernel *btf.Spec) (sockOffsets, error) {
	var sock, common *btf.Struct
	if err := kernel.TypeByName("sock", &sock); err != nil {
		return sockOffsets{}, fmt.Errorf("struct sock: %w", err)
	}
	if err := kernel.TypeByName("sock_common", &common); err != nil {
		return sockOffsets{}, fmt.Errorf("struct sock_common: %w", err)
	}
	base, ok := memberOffset(sock, "__sk_common")
	if !ok {
		return sockOffsets{}, errors.New("struct sock has no __sk_common")
	}
	var missing []string
	field := func(name string) uint32 {
		offset, ok := memberOffset(common, name)
		if !ok {
			missing = append(missing, name)
		}
		return base + offset
	}
	o := sockOffsets{family: field("skc_family"), dport: field("skc_dport"), sport: field("skc_num"), saddr: field("skc_rcv_saddr"), daddr: field("skc_daddr")}
	if len(missing) > 0 {
		return sockOffsets{}, fmt.Errorf("struct sock_common lacks %s", strings.Join(missing, ", "))
	}
	o.saddr6, o.daddr6 = field("skc_v6_rcv_saddr"), field("skc_v6_daddr")
	o.ipv6 = len(missing) == 0
	// The socket's inode, for UDP senders: optional, as connect tracing works without.
	var alloc, inode *btf.Struct
	socket, hasSocket := memberOffset(sock, "sk_socket")
	if hasSocket && kernel.TypeByName("socket_alloc", &alloc) == nil && kernel.TypeByName("inode", &inode) == nil {
		start, hasStart := memberOffset(alloc, "socket")
		vfs, hasVFS := memberOffset(alloc, "vfs_inode")
		ino, hasIno := memberOffset(inode, "i_ino")
		if hasStart && hasVFS && hasIno && vfs > start {
			o.socket, o.inode, o.hasInode = socket, vfs-start+ino, true
		}
	}
	return o, nil
}

// memberOffset finds a member by name, also inside anonymous structs and
// unions, and returns its byte offset.
func memberOffset(typ btf.Type, name string) (uint32, bool) {
	var members []btf.Member
	switch t := btf.UnderlyingType(typ).(type) {
	case *btf.Struct:
		members = t.Members
	case *btf.Union:
		members = t.Members
	default:
		return 0, false
	}
	for _, member := range members {
		if member.Name == name {
			return member.Offset.Bytes(), true
		}
		if member.Name == "" {
			if offset, ok := memberOffset(member.Type, name); ok {
				return member.Offset.Bytes() + offset, true
			}
		}
	}
	return 0, false
}

// parseConnectEvent decodes one record. A socket of the IPv6 family
// connecting to an IPv4-mapped address goes through IPv4, whose fields then
// hold the addresses.
func parseConnectEvent(raw []byte) (pid uint32, cgroup uint64, comm string, key connectKey, ok bool) {
	if len(raw) < connectEventSize {
		return 0, 0, "", connectKey{}, false
	}
	pid = binary.NativeEndian.Uint32(raw[0:])
	family := binary.NativeEndian.Uint16(raw[4:])
	dport := binary.BigEndian.Uint16(raw[6:])
	sport := binary.NativeEndian.Uint16(raw[8:])
	comm, _, _ = strings.Cut(string(raw[16:32]), "\x00")
	cgroup = binary.NativeEndian.Uint64(raw[72:])
	var src, dst netip.Addr
	switch family {
	case unix.AF_INET:
		src, dst = netip.AddrFrom4([4]byte(raw[32:36])), netip.AddrFrom4([4]byte(raw[36:40]))
	case unix.AF_INET6:
		src, dst = netip.AddrFrom16([16]byte(raw[40:56])), netip.AddrFrom16([16]byte(raw[56:72]))
		if dst.Is4In6() {
			src, dst = netip.AddrFrom4([4]byte(raw[32:36])), netip.AddrFrom4([4]byte(raw[36:40]))
		}
	default:
		return 0, 0, "", connectKey{}, false
	}
	if sport == 0 || dport == 0 || !dst.IsValid() || dst.IsUnspecified() {
		return 0, 0, "", connectKey{}, false
	}
	return pid, cgroup, comm, connectKey{netip.AddrPortFrom(src.Unmap(), sport), netip.AddrPortFrom(dst.Unmap(), dport)}, true
}

func (t *connectTracer) run() {
	defer close(t.done)
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		t.add(record.RawSample, time.Now())
	}
}

func (t *connectTracer) runSenders() {
	defer close(t.udpDone)
	for {
		record, err := t.udpReader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		t.addSender(record.RawSample, time.Now())
	}
}

// parseUDPEvent decodes one UDP sender record.
func parseUDPEvent(raw []byte) (pid uint32, cgroup uint64, comm string, inode uint64, ok bool) {
	if len(raw) < udpEventSize {
		return 0, 0, "", 0, false
	}
	pid, inode = binary.NativeEndian.Uint32(raw[0:]), binary.NativeEndian.Uint64(raw[8:])
	comm, _, _ = strings.Cut(string(raw[16:32]), "\x00")
	cgroup = binary.NativeEndian.Uint64(raw[32:])
	return pid, cgroup, comm, inode, pid != 0 && inode != 0
}

// addSender stores which process sends on a UDP socket.
func (t *connectTracer) addSender(raw []byte, now time.Time) {
	pid, cgroup, comm, inode, ok := parseUDPEvent(raw)
	if !ok {
		return
	}
	t.sent.Add(1)
	process, ok := t.process(pid, cgroup, comm, now)
	if !ok {
		t.sentUnresolved.Add(1)
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, known := t.senders[inode]; !known && len(t.senders) >= udpMaxSenders {
		t.expire(now)
		if len(t.senders) >= udpMaxSenders {
			return
		}
	}
	t.senders[inode] = connectRecord{pid: int(pid), command: process.command, containerID: process.containerID, at: now}
}

// sender returns the process that last sent on the UDP socket with this
// inode, if it did within udpSenderTTL of time at.
func (t *connectTracer) sender(inode uint64, at time.Time) (connectRecord, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	record, ok := t.senders[inode]
	if !ok || at.Sub(record.at) > udpSenderTTL {
		return connectRecord{}, false
	}
	return record, true
}

// add stores a record, naming its process from /proc while it still runs.
func (t *connectTracer) add(raw []byte, now time.Time) {
	pid, cgroup, comm, key, ok := parseConnectEvent(raw)
	if !ok {
		return
	}
	t.received.Add(1)
	process, ok := t.process(pid, cgroup, comm, now)
	if !ok {
		t.unresolved.Add(1)
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.records) >= connectMaxRecords {
		t.expire(now)
		if len(t.records) >= connectMaxRecords {
			return
		}
	}
	t.records[key] = connectRecord{pid: int(pid), command: process.command, containerID: process.containerID, at: now}
}

// process names a connecting process: its command (the process's, not the
// connecting thread's) and container, from /proc. Unnamed when it has
// already exited or the read rate is exhausted.
func (t *connectTracer) process(pid uint32, cgroup uint64, comm string, now time.Time) (connectProcess, bool) {
	key := connectProcessKey{pid, cgroup}
	t.mu.Lock()
	if known, ok := t.processes[key]; ok && now.Sub(known.at) < connectProcessTTL {
		t.mu.Unlock()
		return known, true
	}
	if second := now.Unix(); second != t.second {
		t.second, t.resolves = second, 0
	}
	if t.resolves >= connectResolveRate {
		t.mu.Unlock()
		return connectProcess{}, false
	}
	t.resolves++
	t.mu.Unlock()

	directory := filepath.Join(t.root, strconv.FormatUint(uint64(pid), 10))
	cgroups, err := os.ReadFile(filepath.Join(directory, "cgroup"))
	if err != nil {
		return connectProcess{}, false
	}
	_, containerID := parseCgroup(string(cgroups))
	process := connectProcess{command: comm, containerID: containerID, at: now}
	if name, err := os.ReadFile(filepath.Join(directory, "comm")); err == nil {
		process.command = string(bytes.TrimSpace(name))
	}
	t.mu.Lock()
	t.processes[key] = process
	t.mu.Unlock()
	return process, true
}

// opener returns the process that opened the connection from src to dst,
// recorded around time at.
func (t *connectTracer) opener(src, dst netip.AddrPort, at time.Time) (connectRecord, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	record, ok := t.records[connectKey{netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())}]
	if !ok || at.Sub(record.at) > connectRecordTTL || record.at.Sub(at) > processQueueAge {
		return connectRecord{}, false
	}
	return record, true
}

// expire drops old records and process names. Callers hold t.mu.
func (t *connectTracer) expire(now time.Time) {
	for key, record := range t.records {
		if now.Sub(record.at) > connectRecordTTL {
			delete(t.records, key)
		}
	}
	for key, process := range t.processes {
		if now.Sub(process.at) > connectProcessTTL {
			delete(t.processes, key)
		}
	}
	for inode, record := range t.senders {
		if now.Sub(record.at) > udpSenderTTL {
			delete(t.senders, inode)
		}
	}
}

// stats returns and resets counters: records received and unnamed, records
// the kernel dropped for a full buffer, and records kept, for connects and
// for UDP senders.
func (t *connectTracer) stats(now time.Time) traceStats {
	var connectsLost, sendersLost uint64
	errConnects := t.collection.Maps["lost"].Lookup(uint32(0), &connectsLost)
	errSenders := errors.New("no UDP senders")
	if m := t.collection.Maps["udp_lost"]; m != nil && t.udpReader != nil {
		errSenders = m.Lookup(uint32(0), &sendersLost)
	}
	s := traceStats{udp: t.udpReader != nil}
	t.mu.Lock()
	if errConnects == nil && connectsLost >= t.lostSeen {
		s.lost, t.lostSeen = connectsLost-t.lostSeen, connectsLost
	}
	if errSenders == nil && sendersLost >= t.sentLost {
		s.sendersLost, t.sentLost = sendersLost-t.sentLost, sendersLost
	}
	t.expire(now)
	s.records, s.sockets = len(t.records), len(t.senders)
	t.mu.Unlock()
	s.connects, s.unnamed = t.received.Swap(0), t.unresolved.Swap(0)
	s.senders, s.sendersUnnamed = t.sent.Swap(0), t.sentUnresolved.Swap(0)
	return s
}

func (t *connectTracer) close() {
	// Detach first: no new records.
	if t.link != nil {
		_ = t.link.Close()
	}
	for _, attached := range t.udpLinks {
		_ = attached.Close()
	}
	if t.reader != nil {
		_ = t.reader.Close()
		<-t.done
	}
	if t.udpReader != nil {
		_ = t.udpReader.Close()
		if t.udpDone != nil {
			<-t.udpDone
		}
	}
	t.collection.Close()
}
