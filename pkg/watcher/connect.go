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

	mu        sync.Mutex
	records   map[connectKey]connectRecord
	processes map[connectProcessKey]connectProcess
	second    int64 // Unix second of resolveCount.
	resolves  int

	received, unresolved atomic.Uint64
	lostSeen             uint64 // Kernel drop count already reported; under mu.
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
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: kernel}})
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("loading the eBPF program needs CAP_BPF and CAP_PERFMON: %w", err)
		}
		return nil, fmt.Errorf("loading the eBPF program: %w", err)
	}
	t := &connectTracer{root: root, collection: collection, done: make(chan struct{}),
		records: map[connectKey]connectRecord{}, processes: map[connectProcessKey]connectProcess{}}
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
	return t, nil
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
}

// stats returns and resets counters: records received and unnamed, records
// the kernel dropped for a full buffer, and records kept.
func (t *connectTracer) stats(now time.Time) (received, unresolved, lost uint64, kept int) {
	var total uint64
	err := t.collection.Maps["lost"].Lookup(uint32(0), &total)
	t.mu.Lock()
	if err == nil && total >= t.lostSeen {
		lost, t.lostSeen = total-t.lostSeen, total
	}
	t.expire(now)
	kept = len(t.records)
	t.mu.Unlock()
	return t.received.Swap(0), t.unresolved.Swap(0), lost, kept
}

func (t *connectTracer) close() {
	_ = t.link.Close() // Detach first: no new records.
	_ = t.reader.Close()
	<-t.done
	t.collection.Close()
}
