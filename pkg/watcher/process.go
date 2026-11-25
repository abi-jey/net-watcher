package watcher

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

// Process attribution maps a flow to the process that owns its socket, read
// from a read-only host procfs. Reading other processes' namespaces and file
// descriptors needs CAP_SYS_PTRACE; nothing is written, traced or signalled.
//
// Pod traffic lives in the pod's network namespace, so its socket appears only
// in that namespace's tables. A pod's processes are found through their cgroup
// (which names the pod UID and container ID); the socket is looked up in their
// namespace's table and its owner among only their file descriptors.
// Host-network traffic, including host-network pods, uses the host namespace.
//
// All /proc work runs on one worker goroutine within a CPU-time budget; packet
// handlers only consult a flow cache or enqueue. Later events of a flow (TLS,
// end, timeout) reuse the identity found at its start.
const (
	processSnapshotEvery  = 15 * time.Second
	processSnapshotOnMiss = 3 * time.Second // A pod unknown to the snapshot may have just started.
	processRemoteFor      = time.Minute     // A pod UID with no processes here is on another node.
	// A TCP socket table read walks the kernel's node-wide connection hash,
	// whichever namespace it is for: about 1 ms even when nearly empty, more
	// on large or busy nodes.
	processLookupDeadline = 25 * time.Millisecond
	processMaxFDLinks     = 4096
	processQueueAge       = 2 * time.Second // Older sockets have likely closed.
	processFlowTTL        = 15 * time.Minute
	processMaxFlows       = 100_000
	processMaxSockets     = 100_000
	processMissTTL        = time.Minute // How long an endpoint with no socket is not looked up again.
	processMaxMisses      = 50_000
	processQueueSize      = 256
	processFullRescan     = time.Minute // Between rescans, only new PIDs are read in full.
	processMaxTables      = 64          // Socket tables kept for lookups queued before they were read.
	// /proc work is bounded by default to about 3% of one core on average,
	// with bursts of twice that: two thirds for pod lookups and snapshots,
	// which are cheap and most useful, one third for host lookups, which may
	// scan the descriptors of many processes. Neither can starve the other.
	DefaultProcessBudget = 30 * time.Millisecond
)

// ContainerLookup names a container by runtime ID.
type ContainerLookup func(id string) (namespace, pod, name string, ok bool)

type processIdentity struct {
	PID                     int
	Command, Pod, Container string
}

// flowProcesses are the processes found at a flow's ends. Both are looked up
// when both ends are on this node: a kubelet health check is opened by the
// kubelet and accepted by the pod's server, and either alone would mislead.
type flowProcesses struct {
	src, dst       processIdentity
	hasSrc, hasDst bool
	used           time.Time
}

func (f flowProcesses) reversed() flowProcesses {
	f.src, f.dst, f.hasSrc, f.hasDst = f.dst, f.src, f.hasDst, f.hasSrc
	return f
}

// apply records the processes on an event: the source's (the process that
// opened the flow) when known, else the destination's, and the destination's
// as the peer when both are.
func (f *flowProcesses) set(side string, identity processIdentity) {
	if side == "src" {
		f.src, f.hasSrc = identity, true
	} else {
		f.dst, f.hasDst = identity, true
	}
}

func (f flowProcesses) apply(event *database.NetworkEvent) {
	primary, side := f.src, "src"
	switch {
	case !f.hasSrc && !f.hasDst:
		return
	case !f.hasSrc:
		primary, side = f.dst, "dst"
	case f.hasDst:
		event.PeerProcessPID, event.PeerProcessCommand = f.dst.PID, f.dst.Command
		event.PeerProcessPod, event.PeerProcessContainer = f.dst.Pod, f.dst.Container
	}
	event.ProcessPID, event.ProcessCommand, event.ProcessSide = primary.PID, primary.Command, side
	event.ProcessPod, event.ProcessContainer = primary.Pod, primary.Container
	if f.hasSrc && !kubeletCommands[f.src.Command] {
		// Another process opened it: whatever port it reached, not a probe.
		event.Probe = ""
	}
}

// kubeletCommands are the command names the kubelet runs under: its own
// binary, or a distribution's single binary that embeds it.
var kubeletCommands = map[string]bool{"kubelet": true, "kubelite": true, "k3s-server": true, "k3s-agent": true}

type procEntry struct {
	pid                 int
	uid                 uint32
	podUID, containerID string
}

type procSnapshot struct {
	at        time.Time
	hostNetns string
	byPod     map[string][]procEntry // Pod UID -> processes in the pod's own network namespace.
	host      []procEntry            // Processes in the host network namespace.
	hostIPs   map[string]bool
	podNetns  map[string]string // Pod UID -> network namespace.
}

type processJob struct {
	event    database.NetworkEvent
	queuedAt time.Time
}

// workBudget is a token bucket of CPU time.
type workBudget struct {
	rate, available time.Duration
	last            time.Time
}

func newWorkBudget(rate time.Duration, now time.Time) workBudget {
	return workBudget{rate: rate, available: rate, last: now}
}

func (b *workBudget) ready(now time.Time) bool {
	b.available = min(2*b.rate, b.available+time.Duration(float64(b.rate)*now.Sub(b.last).Seconds()))
	b.last = now
	return b.available > 0
}

func (b *workBudget) spend(d time.Duration) { b.available -= d }

// spare reports whether at least half a second's allowance is left: a
// lookup for a flow's second end only adds detail, so it must not use time
// that a flow with no process found yet could use.
func (b *workBudget) spare(now time.Time) bool {
	return b.ready(now) && b.available >= b.rate/2
}

type processAttributor struct {
	root       string
	containers ContainerLookup
	addresses  func() map[string]bool
	onEvent    func(database.NetworkEvent)
	logger     *log.Logger
	budget     time.Duration // CPU time per second; DefaultProcessBudget when zero.
	deadline   time.Duration // Per lookup; processLookupDeadline when zero.
	// tunnelLookup lists the UDP ports of kernel tunnel devices (tunnels.go).
	tunnelLookup func() (map[uint16]string, error)
	// traceConnects loads the connect tracer (connect.go) at start; connects
	// is it, or a test's stand-in.
	traceConnects bool
	connects      connectSource

	jobsMu  sync.RWMutex
	closed  bool
	jobs    chan processJob
	workers sync.WaitGroup

	// Owned by the worker goroutine.
	snapshot *procSnapshot
	known    map[int]knownProc    // Per-PID details kept between snapshots.
	fullAt   time.Time            // Last full rescan.
	sockets  map[string]socketRef // Socket inode -> where a scan last saw it.
	remote   map[string]time.Time // Pod UID -> until when it is treated as remote.
	misses   map[string]time.Time // Endpoint with no socket -> until when it is skipped.
	recent   []int                // Host PIDs that recently owned sockets, newest first.
	podWork  workBudget
	hostWork workBudget
	tunnels  map[uint16]string // Kernel tunnel ports, refreshed with each snapshot.
	// lastCacheable: the last lookup completed without a match (no socket, or
	// no process that can be named), so the same endpoint will miss again.
	lastCacheable bool
	// resume: where a descriptor scan that ran out of time continues for the
	// same socket, so a socket held deep in a busy host is found eventually.
	resume map[string]int
	// tables: recently read socket tables by namespace and name. A table read
	// after a flow was queued lists its socket if it was still open, so one
	// read serves every lookup waiting for that namespace.
	tables map[string]socketTable
	// tableFirst: per namespace, protocol and side, the table (IPv4 or IPv6)
	// that last held the socket, read first next time.
	tableFirst map[string]int
	// diag looks sockets up exactly in diagNetns, the namespace this process
	// runs in (the host's, for a host-network collector), instead of reading
	// its socket tables. diagErrors counts consecutive failures; after
	// sockDiagMaxErrors, lookups go back to the tables.
	diag       *sockDiag
	diagNetns  string
	diagErrors int

	hostIPs atomic.Pointer[map[string]bool]

	flowMu sync.Mutex
	flows  map[string]flowProcesses
	// pending counts queued flow starts by flow key: until a start is looked
	// up, the flow's later events (a short connection's end) queue behind it
	// and inherit what it finds.
	pending map[string]int

	// A few failed lookups per report interval, with their reason, so
	// operators can see why connections stay unattributed.
	exampleMu sync.Mutex
	examples  []string

	attempted, matched, inherited, notLocal atomic.Uint64
	bothEnds, peerSkipped                   atomic.Uint64 // Flows with both ends' processes; second-end lookups left for lack of spare budget.
	traced, kernelEnds                      atomic.Uint64 // Openers from connect tracing; ends owned by a kernel tunnel.
	budgetHit, overBudget, expired          atomic.Uint64
	queueFull, noSocket, snapshots, indexed atomic.Uint64
	knownMiss, noOwner, byOwner             atomic.Uint64
	tableReads, tableReuse, diagLookups     atomic.Uint64
	work, snapshotWork                      atomic.Int64 // Nanoseconds spent reading /proc.
}

// connectSource names the process that opened a TCP connection from this
// node (connectTracer).
type connectSource interface {
	opener(src, dst netip.AddrPort, at time.Time) (connectRecord, bool)
	stats(now time.Time) (received, unresolved, lost uint64, kept int)
	close()
}

type socketTable struct {
	at   time.Time // When the read started.
	data []byte
}

type knownProc struct {
	netns string
	entry procEntry
}

type socketRef struct {
	pid int
	fd  string
}

func newProcessAttributor(root string, containers ContainerLookup, budget time.Duration, traceConnects bool, logger *log.Logger, onEvent func(database.NetworkEvent)) (*processAttributor, error) {
	a := &processAttributor{root: root, containers: containers, budget: budget, addresses: localAddresses, tunnelLookup: tunnelPorts,
		traceConnects: traceConnects, onEvent: onEvent, logger: logger}
	if err := a.start(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *processAttributor) start() error {
	if _, err := os.Lstat(filepath.Join(a.root, "1", "ns", "net")); err != nil {
		return fmt.Errorf("host procfs at %s: %w", a.root, err)
	}
	a.jobs = make(chan processJob, processQueueSize)
	a.flows, a.pending = map[string]flowProcesses{}, map[string]int{}
	a.remote = map[string]time.Time{}
	a.misses = map[string]time.Time{}
	a.resume = map[string]int{}
	a.tables, a.tableFirst = map[string]socketTable{}, map[string]int{}
	budget := a.budget
	if budget <= 0 {
		budget = DefaultProcessBudget
	}
	a.podWork, a.hostWork = newWorkBudget(budget*2/3, time.Now()), newWorkBudget(budget/3, time.Now())
	if a.deadline <= 0 {
		a.deadline = processLookupDeadline
	}
	a.refresh(time.Now())
	if a.snapshot.hostNetns == "" || len(a.snapshot.host) == 0 {
		return fmt.Errorf("cannot read process namespaces under %s; process attribution needs CAP_SYS_PTRACE", a.root)
	}
	if self, err := os.Readlink(selfNetnsPath); err == nil && self == a.snapshot.hostNetns {
		if diag, err := openSockDiag(); err == nil {
			a.diag, a.diagNetns = diag, self
		} else {
			a.logger.Warn("Host socket lookups read socket tables", "error", err)
		}
	}
	if a.traceConnects && a.connects == nil {
		if tracer, err := newConnectTracer(a.root); err != nil {
			a.logger.Warn("Connect tracing unavailable; openers of short connections will often be missed", "error", err)
		} else {
			a.connects = tracer
			a.logger.Info("Connect tracing enabled: the process opening each TCP connection on this node is recorded when it connects")
		}
	}
	a.workers.Add(1)
	go a.run()
	return nil
}

func flowKey(event database.NetworkEvent, reverse bool) string {
	protocol := "udp"
	if strings.HasPrefix(string(event.EventType), "TCP") || event.EventType == database.EventTLSSNI || event.Protocol == "TCP" {
		protocol = "tcp"
	}
	if reverse {
		return protocol + "|" + event.DstIP + "|" + strconv.Itoa(int(event.DstPort)) + "|" + event.SrcIP + "|" + strconv.Itoa(int(event.SrcPort))
	}
	return protocol + "|" + event.SrcIP + "|" + strconv.Itoa(int(event.SrcPort)) + "|" + event.DstIP + "|" + strconv.Itoa(int(event.DstPort))
}

// cached returns a flow's processes in either orientation, with the ends as
// seen from this event, and keeps the entry alive for long-lived flows.
func (a *processAttributor) cached(event database.NetworkEvent, now time.Time) (flowProcesses, bool) {
	a.flowMu.Lock()
	defer a.flowMu.Unlock()
	for _, reverse := range []bool{false, true} {
		key := flowKey(event, reverse)
		flow, ok := a.flows[key]
		if !ok {
			continue
		}
		flow.used = now
		a.flows[key] = flow
		if reverse {
			flow = flow.reversed()
		}
		return flow, true
	}
	return flowProcesses{}, false
}

func (a *processAttributor) remember(event database.NetworkEvent, flow flowProcesses) {
	a.flowMu.Lock()
	defer a.flowMu.Unlock()
	if len(a.flows) < processMaxFlows {
		a.flows[flowKey(event, false)] = flow
	}
}

// attributable reports which events start a lookup: those emitted while the
// flow's socket most likely still exists. A DNS response arrives just before
// the client closes its socket; it reuses the query's result instead.
func attributable(event database.NetworkEvent) bool {
	switch event.EventType {
	case database.EventTCPStart, database.EventUDPStart, database.EventTLSSNI:
		return true
	case database.EventDNS:
		return event.DNSType == "QUERY"
	}
	return false
}

// handle runs on packet-processing goroutines and never touches /proc. It
// applies a known identity, or hands a flow start to the worker and reports
// whether the worker now owns the event.
func (a *processAttributor) handle(event *database.NetworkEvent) bool {
	if event.ProcessSide != "" || event.EventType == database.EventGap {
		return false
	}
	now := time.Now()
	if flow, ok := a.cached(*event, now); ok {
		flow.apply(event)
		a.inherited.Add(1)
		return false
	}
	start := attributable(*event)
	if !start && !a.isPending(*event) {
		a.applyTraced(event, now, false)
		return false
	}
	if start {
		hosts := a.hostIPs.Load()
		local := event.SrcKind == "pod" || event.DstKind == "pod" || (hosts != nil && ((*hosts)[event.SrcIP] || (*hosts)[event.DstIP]))
		if !local {
			return false
		}
	}
	a.jobsMu.RLock()
	defer a.jobsMu.RUnlock()
	if a.closed {
		return false
	}
	if start {
		a.setPending(*event, true) // Before the worker can take it.
	}
	select {
	case a.jobs <- processJob{event: *event, queuedAt: now}:
		return true
	default:
		if start {
			a.setPending(*event, false)
		}
		a.queueFull.Add(1)
		a.applyTraced(event, now, start) // Needs no lookup.
		return false
	}
}

// setPending counts a flow start in or out of the queue.
func (a *processAttributor) setPending(event database.NetworkEvent, queued bool) {
	key := flowKey(event, false)
	a.flowMu.Lock()
	defer a.flowMu.Unlock()
	if a.pending == nil {
		a.pending = map[string]int{}
	}
	switch {
	case queued:
		a.pending[key]++
	case a.pending[key] <= 1:
		delete(a.pending, key)
	default:
		a.pending[key]--
	}
}

// isPending reports whether the flow's start, in either orientation, waits
// in the queue.
func (a *processAttributor) isPending(event database.NetworkEvent) bool {
	a.flowMu.Lock()
	defer a.flowMu.Unlock()
	return a.pending[flowKey(event, false)] > 0 || a.pending[flowKey(event, true)] > 0
}

// applyTraced applies the opener connect tracing recorded, for an event that
// gets no lookups. keep remembers it for the flow's later events; a later
// event's result is not kept, or it would hide what its start's lookup finds.
func (a *processAttributor) applyTraced(event *database.NetworkEvent, now time.Time, keep bool) {
	if opener, ok := a.connectOpener(*event); ok {
		flow := flowProcesses{src: opener, hasSrc: true, used: now}
		flow.apply(event)
		if keep {
			a.remember(*event, flow)
		}
		a.traced.Add(1)
	}
}

// connectOpener is the process connect tracing saw open this TCP flow.
func (a *processAttributor) connectOpener(event database.NetworkEvent) (processIdentity, bool) {
	tcp := strings.HasPrefix(string(event.EventType), "TCP") || event.EventType == database.EventTLSSNI || (event.EventType == database.EventTimeout && event.Protocol == "TCP")
	if a.connects == nil || !tcp {
		return processIdentity{}, false
	}
	src, err := netip.ParseAddr(event.SrcIP)
	if err != nil {
		return processIdentity{}, false
	}
	dst, err := netip.ParseAddr(event.DstIP)
	if err != nil {
		return processIdentity{}, false
	}
	record, ok := a.connects.opener(netip.AddrPortFrom(src, event.SrcPort), netip.AddrPortFrom(dst, event.DstPort), event.Timestamp)
	if !ok {
		return processIdentity{}, false
	}
	identity := processIdentity{PID: record.pid, Command: record.command}
	if record.containerID != "" && a.containers != nil {
		if namespace, pod, name, ok := a.containers(record.containerID); ok {
			identity.Pod, identity.Container = namespace+"/"+pod, name
		}
	}
	if identity.Pod == "" && event.SrcKind == "pod" {
		identity.Pod = event.SrcNamespace + "/" + event.SrcName // Its own network namespace: the pod's.
	}
	return identity, true
}

// kernelEnd reports whether a kernel tunnel device owns this end of a UDP
// flow: it receives on the device's port here, or this node sends to that
// port on another node (tunnels.go).
func (a *processAttributor) kernelEnd(event database.NetworkEvent, c candidate) bool {
	if !c.host || len(a.tunnels) == 0 || !strings.HasPrefix(string(event.EventType), "UDP") {
		return false
	}
	if c.side == "dst" {
		return a.tunnels[c.port] != ""
	}
	return a.tunnels[c.otherPort] != "" && event.DstKind == "node"
}

// stop drains queued events through onEvent and stops the worker.
func (a *processAttributor) stop() {
	a.jobsMu.Lock()
	if !a.closed {
		a.closed = true
		close(a.jobs)
	}
	a.jobsMu.Unlock()
	a.workers.Wait()
	if a.diag != nil {
		a.diag.close()
		a.diag = nil
	}
	a.report()
	if a.connects != nil {
		a.connects.close()
	}
}

// report logs and resets counters and expires remembered flows. The session
// cleanup loop calls it every 30 seconds.
func (a *processAttributor) report() {
	now := time.Now()
	a.flowMu.Lock()
	for key, flow := range a.flows {
		if now.Sub(flow.used) > processFlowTTL {
			delete(a.flows, key)
		}
	}
	flows := len(a.flows)
	a.flowMu.Unlock()
	attempted, matched, inherited, notLocal := a.attempted.Swap(0), a.matched.Swap(0), a.inherited.Swap(0), a.notLocal.Swap(0)
	bothEnds, peerSkipped := a.bothEnds.Swap(0), a.peerSkipped.Swap(0)
	traced, kernelEnds := a.traced.Swap(0), a.kernelEnds.Swap(0)
	budgetHit, overBudget, expired := a.budgetHit.Swap(0), a.overBudget.Swap(0), a.expired.Swap(0)
	queueFull, noSocket, snapshots, work := a.queueFull.Swap(0), a.noSocket.Swap(0), a.snapshots.Swap(0), a.work.Swap(0)
	indexed, snapshotWork, knownMiss, noOwner := a.indexed.Swap(0), a.snapshotWork.Swap(0), a.knownMiss.Swap(0), a.noOwner.Swap(0)
	byOwner, tableReads, tableReuse, diagLookups := a.byOwner.Swap(0), a.tableReads.Swap(0), a.tableReuse.Swap(0), a.diagLookups.Swap(0)
	a.exampleMu.Lock()
	examples := a.examples
	a.examples = nil
	a.exampleMu.Unlock()
	if a.connects != nil {
		received, unresolved, lost, kept := a.connects.stats(now)
		if received+lost > 0 {
			a.logger.Info("Connect tracing", "connects", received, "unnamed", unresolved, "lost", lost, "records", kept)
		}
	}
	if attempted+inherited+overBudget+expired+queueFull+traced+kernelEnds > 0 {
		a.logger.Info("Process attribution", "attempted", attempted, "matched", matched, "traced", traced, "kernel", kernelEnds, "both_ends", bothEnds, "second_end_skipped", peerSkipped, "from_index", indexed, "by_owner", byOwner, "inherited", inherited,
			"no_socket", noSocket, "no_owner", noOwner, "known_miss", knownMiss, "not_local", notLocal, "deadline_hit", budgetHit, "over_budget", overBudget,
			"expired", expired, "queue_full", queueFull, "flows", flows, "snapshots", snapshots, "tables_read", tableReads, "tables_reused", tableReuse, "socket_queries", diagLookups,
			"snapshot_ms", time.Duration(snapshotWork).Milliseconds(), "lookup_ms", time.Duration(work).Milliseconds(), "misses", strings.Join(examples, "; "))
	}
}

func (a *processAttributor) run() {
	defer a.workers.Done()
	for queued := range a.jobs {
		event := queued.event
		now := time.Now()
		start := attributable(event)
		if flow, ok := a.cached(event, now); ok { // Attributed meanwhile, or by the start it followed.
			flow.apply(&event)
			a.inherited.Add(1)
		} else if !start {
			a.applyTraced(&event, now, false) // Its start found nothing.
		} else if now.Sub(queued.queuedAt) > processQueueAge {
			a.expired.Add(1)
			a.applyTraced(&event, now, true)
		} else {
			if now.Sub(a.snapshot.at) > processSnapshotEvery && a.podWork.ready(now) {
				a.refresh(now)
			}
			a.attribute(&event, queued.queuedAt, now)
		}
		if start {
			a.setPending(event, false)
		}
		a.onEvent(event)
	}
}

// candidate is one endpoint of a flow whose socket may be on this node.
type candidate struct {
	side            string
	ip, otherIP     string
	port, otherPort uint16
	procs           []procEntry
	host            bool
	netns           string
	queuedAt        time.Time
}

func (a *processAttributor) candidates(event database.NetworkEvent, queuedAt, now time.Time) []candidate {
	var list []candidate
	for _, side := range []struct {
		name, kind, uid, ip, otherIP string
		port, otherPort              uint16
	}{
		{"src", event.SrcKind, event.SrcUID, event.SrcIP, event.DstIP, event.SrcPort, event.DstPort},
		{"dst", event.DstKind, event.DstUID, event.DstIP, event.SrcIP, event.DstPort, event.SrcPort},
	} {
		c := candidate{side: side.name, ip: side.ip, otherIP: side.otherIP, port: side.port, otherPort: side.otherPort, queuedAt: queuedAt}
		if side.kind == "pod" && side.uid != "" {
			if now.Before(a.remote[side.uid]) {
				continue
			}
			procs := a.snapshot.byPod[side.uid]
			if len(procs) == 0 && now.Sub(a.snapshot.at) > processSnapshotOnMiss && a.podWork.ready(now) {
				a.refresh(now)
				procs = a.snapshot.byPod[side.uid]
			}
			if len(procs) == 0 {
				// Only a snapshot taken after the packet proves the pod is
				// not here; an older one may predate the pod.
				if !a.snapshot.at.Before(queuedAt) {
					a.remote[side.uid] = now.Add(processRemoteFor)
				}
				continue
			}
			c.procs, c.netns = procs, a.snapshot.podNetns[side.uid]
			list = append(list, c)
			continue
		}
		if a.snapshot.hostIPs[side.ip] {
			c.procs, c.host, c.netns = a.hostOrder(), true, a.snapshot.hostNetns
			list = append(list, c)
		}
	}
	// Every candidate is looked up, source first: both ends may be on this
	// node, and the source's socket is the one that disappears. A short
	// connection (a kubelet health check takes a few milliseconds) may have
	// closed by the time the second lookup runs; the destination's listening
	// socket still names the server then, the client's closed socket names
	// nothing.
	return list
}

// hostOrder lists host processes, those that recently owned sockets first:
// most host traffic comes from a few daemons.
func (a *processAttributor) hostOrder() []procEntry {
	if len(a.recent) == 0 {
		return a.snapshot.host
	}
	first := make(map[int]bool, len(a.recent))
	ordered := make([]procEntry, 0, len(a.snapshot.host))
	for _, pid := range a.recent {
		first[pid] = true
	}
	for _, proc := range a.snapshot.host {
		if first[proc.pid] {
			ordered = append(ordered, proc)
		}
	}
	for _, proc := range a.snapshot.host {
		if !first[proc.pid] {
			ordered = append(ordered, proc)
		}
	}
	return ordered
}

func (a *processAttributor) noteHostPID(pid int) {
	list := []int{pid}
	for _, known := range a.recent {
		if known != pid && len(list) < 16 {
			list = append(list, known)
		}
	}
	a.recent = list
}

func (a *processAttributor) attribute(event *database.NetworkEvent, queuedAt, now time.Time) {
	var flow flowProcesses
	// Recorded when it connected: found even after the connection closed,
	// with no lookup.
	if opener, ok := a.connectOpener(*event); ok {
		flow.set("src", opener)
		a.traced.Add(1)
	}
	candidates := a.candidates(*event, queuedAt, now)
	if len(candidates) == 0 && !flow.hasSrc {
		a.notLocal.Add(1)
		return
	}
	found := false // A lookup matched; another needs budget to spare.
	for _, c := range candidates {
		if c.side == "src" && flow.hasSrc {
			continue
		}
		if a.kernelEnd(*event, c) {
			flow.set(c.side, kernelProcess)
			a.kernelEnds.Add(1)
			continue
		}
		miss := missKey(*event, c)
		if miss != "" && now.Before(a.misses[miss]) {
			a.knownMiss.Add(1)
			continue
		}
		budget := &a.podWork
		if c.host {
			budget = &a.hostWork
		}
		second := found
		if second && !budget.spare(now) {
			a.peerSkipped.Add(1)
			continue
		}
		if !second && !budget.ready(now) {
			a.overBudget.Add(1)
			continue
		}
		a.attempted.Add(1)
		started := time.Now()
		identity, ok := a.lookup(*event, c, started.Add(a.deadline))
		spent := time.Since(started)
		budget.spend(spent)
		a.work.Add(int64(spent))
		if !ok {
			if miss != "" && a.lastCacheable && len(a.misses) < processMaxMisses {
				a.misses[miss] = now.Add(processMissTTL)
			}
			continue
		}
		flow.set(c.side, identity)
		found = true
		a.matched.Add(1)
		if c.host {
			a.noteHostPID(identity.PID)
		}
	}
	if !flow.hasSrc && !flow.hasDst {
		return
	}
	if flow.hasSrc && flow.hasDst {
		a.bothEnds.Add(1)
	}
	flow.used = now
	flow.apply(event)
	a.remember(*event, flow)
}

func (a *processAttributor) lookup(event database.NetworkEvent, c candidate, deadline time.Time) (processIdentity, bool) {
	udp := strings.HasPrefix(string(event.EventType), "UDP") || (event.EventType == database.EventDNS && event.Protocol != "TCP")
	// Every process in the list shares one network namespace; any of them
	// that is still alive shows its socket table.
	var inode string
	var owner uint32
	opened := false
	for i := 0; i < len(c.procs) && i < 3 && !opened; i++ {
		procDir := filepath.Join(a.root, strconv.Itoa(c.procs[i].pid))
		inode, owner, opened = a.findSocket(c, procDir, udp, deadline)
	}
	a.lastCacheable = false
	if inode == "" {
		if time.Now().After(deadline) {
			a.budgetHit.Add(1)
			a.example(event, c, "deadline reading socket tables")
		} else {
			a.noSocket.Add(1)
			a.lastCacheable = opened
			a.example(event, c, fmt.Sprintf("no socket (tables readable: %t)", opened))
		}
		return processIdentity{}, false
	}
	target := "socket:[" + inode + "]"
	if proc, ok := a.indexedOwner(target, c.procs); ok {
		a.indexed.Add(1)
		return a.identify(event, c, proc), true
	}
	followed := 0
	unreadable := map[int]bool{}
	start := a.resume[target]
	if start >= len(c.procs) {
		start = 0
	}
	if start > 0 {
		unreadable = nil // Earlier processes were scanned by an earlier lookup; ownership cannot be inferred.
	}
	for i := start; i < len(c.procs); i++ {
		proc := c.procs[i]
		if time.Now().After(deadline) || followed >= processMaxFDLinks {
			a.budgetHit.Add(1)
			a.example(event, c, fmt.Sprintf("deadline scanning descriptors (%d links)", followed))
			if len(a.resume) < processMaxMisses {
				a.resume[target] = i
			}
			return processIdentity{}, false
		}
		if c.host && proc.uid != owner {
			continue // The socket's owner uid narrows the host's many processes.
		}
		found, readable := a.holdsSocket(proc.pid, target, deadline, &followed)
		if found {
			delete(a.resume, target)
			return a.identify(event, c, proc), true
		}
		if !readable && unreadable != nil {
			unreadable[proc.pid] = true
		}
	}
	delete(a.resume, target)
	if unreadable != nil {
		if identity, ok := a.identifyByOwner(event, c, owner, unreadable); ok {
			a.byOwner.Add(1)
			return identity, true
		}
	}
	a.noOwner.Add(1)
	a.lastCacheable = true
	a.example(event, c, fmt.Sprintf("socket %s (uid %d) held by none of %d processes (%d links read)", inode, owner, len(c.procs), followed))
	return processIdentity{}, false
}

func (a *processAttributor) example(event database.NetworkEvent, c candidate, reason string) {
	a.exampleMu.Lock()
	defer a.exampleMu.Unlock()
	if len(a.examples) >= 4 {
		return
	}
	where := "host"
	if !c.host {
		where = "pod " + c.procs[0].podUID
	}
	a.examples = append(a.examples, fmt.Sprintf("%s %s:%d->%s:%d %s side, %s: %s", event.EventType, event.SrcIP, event.SrcPort, event.DstIP, event.DstPort, c.side, where, reason))
}

// missKey names what a lookup that found no socket says about later flows:
// nothing on the receiving side listens on that port, and for a UDP source,
// nothing on the node owns its sockets to that remote endpoint (kernel
// tunnels such as VXLAN). A TCP source's ephemeral port says nothing.
func missKey(event database.NetworkEvent, c candidate) string {
	udp := strings.HasPrefix(string(event.EventType), "UDP") || (event.EventType == database.EventDNS && event.Protocol != "TCP")
	switch {
	case c.side == "dst":
		return fmt.Sprintf("dst|%t|%s|%d", udp, c.ip, c.port)
	case udp:
		return fmt.Sprintf("src|%s|%s|%d", c.ip, c.otherIP, c.otherPort)
	}
	return ""
}

// indexedOwner checks where an earlier scan saw the socket, with one link read.
func (a *processAttributor) indexedOwner(target string, procs []procEntry) (procEntry, bool) {
	ref, ok := a.sockets[target]
	if !ok {
		return procEntry{}, false
	}
	if link, err := os.Readlink(filepath.Join(a.root, strconv.Itoa(ref.pid), "fd", ref.fd)); err != nil || link != target {
		delete(a.sockets, target)
		return procEntry{}, false
	}
	for _, proc := range procs {
		if proc.pid == ref.pid {
			return proc, true
		}
	}
	return procEntry{}, false
}

// identifyByOwner names the process when its descriptors cannot be read: a
// process running as another user keeps /proc/<pid>/fd private to that user,
// which CAP_SYS_PTRACE does not override. The socket table records the
// socket's owner uid; if every process of that uid in the namespace (none of
// whose descriptors could be read) has the same container and command, those
// are certain and only the PID is not, so it is left zero.
func (a *processAttributor) identifyByOwner(event database.NetworkEvent, c candidate, owner uint32, unreadable map[int]bool) (processIdentity, bool) {
	var first *procEntry
	var command string
	matches := 0
	for i := range c.procs {
		proc := &c.procs[i]
		if proc.uid != owner {
			continue
		}
		if !unreadable[proc.pid] || matches >= 32 {
			return processIdentity{}, false
		}
		comm, err := os.ReadFile(filepath.Join(a.root, strconv.Itoa(proc.pid), "comm"))
		if err != nil {
			continue // Exited.
		}
		name := strings.TrimSpace(string(comm))
		if first == nil {
			first, command = proc, name
		} else if proc.containerID != first.containerID || name != command {
			return processIdentity{}, false
		}
		matches++
	}
	if first == nil {
		return processIdentity{}, false
	}
	identity := a.identify(event, c, *first)
	identity.PID, identity.Command = 0, command
	return identity, true
}

func (a *processAttributor) identify(event database.NetworkEvent, c candidate, proc procEntry) processIdentity {
	path := filepath.Join(a.root, strconv.Itoa(proc.pid))
	identity := processIdentity{PID: proc.pid}
	if command, err := os.ReadFile(filepath.Join(path, "comm")); err == nil {
		identity.Command = strings.TrimSpace(string(command))
	}
	if proc.containerID != "" && a.containers != nil {
		if namespace, pod, name, ok := a.containers(proc.containerID); ok {
			identity.Pod, identity.Container = namespace+"/"+pod, name
		}
	}
	if identity.Pod == "" && !c.host {
		if c.side == "src" {
			identity.Pod = event.SrcNamespace + "/" + event.SrcName
		} else {
			identity.Pod = event.DstNamespace + "/" + event.DstName
		}
	}
	return identity
}

// holdsSocket scans a process's descriptors for the socket, indexing every
// socket it passes so later lookups of long-lived sockets need no scan. It
// also reports whether the descriptors were readable at all.
func (a *processAttributor) holdsSocket(pid int, target string, deadline time.Time, followed *int) (found, readable bool) {
	directory := filepath.Join(a.root, strconv.Itoa(pid), "fd")
	fds, err := os.Open(directory)
	if err != nil {
		return false, false
	}
	defer func() { _ = fds.Close() }()
	// Links that cannot be read (as opposed to descriptors closed meanwhile)
	// make the process as unreadable as a private directory.
	links, denied := 0, 0
	readable = true
	for time.Now().Before(deadline) && *followed < processMaxFDLinks {
		names, readErr := fds.Readdirnames(64)
		for _, name := range names {
			*followed++
			links++
			link, err := os.Readlink(filepath.Join(directory, name))
			if errors.Is(err, os.ErrPermission) {
				denied++
			}
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if len(a.sockets) < processMaxSockets {
				a.sockets[link] = socketRef{pid: pid, fd: name}
			}
			if link == target {
				return true, true
			}
		}
		if readErr != nil || len(names) == 0 {
			break
		}
	}
	return false, links == 0 || denied != links
}

var (
	cgroupPodUID      = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)
	cgroupContainerID = regexp.MustCompile(`(?:^|[/-])([0-9a-f]{64})(?:\.scope)?(?:/|$)`)
)

// parseCgroup extracts the pod UID and container ID from /proc/<pid>/cgroup
// for the systemd ("kubepods-pod<uid>.slice/cri-containerd-<id>.scope", or
// "crio-<id>.scope/container" where the runtime nests the process) and cgroupfs
// ("/kubepods/pod<uid>/<id>") drivers. The innermost ID is the container's.
func parseCgroup(content string) (podUID, containerID string) {
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if match := cgroupPodUID.FindStringSubmatch(parts[2]); match != nil {
			podUID = strings.ReplaceAll(match[1], "_", "-")
			if ids := cgroupContainerID.FindAllStringSubmatch(parts[2], -1); ids != nil {
				containerID = ids[len(ids)-1][1]
			}
			return podUID, containerID
		}
	}
	return "", ""
}

// refresh records every process's network namespace and pod. Each process's
// namespace link is read every time; its owner and cgroup only when it is new
// or changed namespace, and for all processes once a minute.
func (a *processAttributor) refresh(now time.Time) {
	started := time.Now()
	defer func() {
		spent := time.Since(started)
		a.podWork.spend(spent)
		a.snapshotWork.Add(int64(spent))
		a.snapshots.Add(1)
	}()
	if a.known == nil || now.Sub(a.fullAt) > processFullRescan {
		a.known, a.fullAt = map[int]knownProc{}, now
		a.sockets = map[string]socketRef{}
		a.resume = map[string]int{}
		a.tableFirst = map[string]int{}
	}
	snapshot := &procSnapshot{at: now, byPod: map[string][]procEntry{}, hostIPs: a.addresses()}
	a.hostIPs.Store(&snapshot.hostIPs)
	if a.tunnelLookup != nil {
		if ports, err := a.tunnelLookup(); err == nil {
			a.tunnels = ports
		}
	}
	for uid, until := range a.remote {
		if now.After(until) {
			delete(a.remote, uid)
		}
	}
	for key, until := range a.misses {
		if now.After(until) {
			delete(a.misses, key)
		}
	}
	a.snapshot = snapshot
	snapshot.hostNetns, _ = os.Readlink(filepath.Join(a.root, "1", "ns", "net"))
	if snapshot.hostNetns == "" {
		return
	}
	entries, err := os.ReadDir(a.root)
	if err != nil {
		return
	}
	known := make(map[int]knownProc, len(a.known))
	podNetns := map[string]string{}
	snapshot.podNetns = podNetns
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 {
			continue
		}
		path := filepath.Join(a.root, entry.Name())
		netns, err := os.Readlink(filepath.Join(path, "ns", "net"))
		if err != nil {
			continue // Exited, or a kernel thread.
		}
		cached, ok := a.known[pid]
		if !ok || cached.netns != netns {
			cached = knownProc{netns: netns, entry: procEntry{pid: pid}}
			if info, err := os.Stat(path); err == nil {
				if owner, ok := info.Sys().(*syscall.Stat_t); ok {
					cached.entry.uid = owner.Uid
				}
			}
			if content, err := os.ReadFile(filepath.Join(path, "cgroup")); err == nil {
				cached.entry.podUID, cached.entry.containerID = parseCgroup(string(content))
			}
		}
		known[pid] = cached
		proc := cached.entry
		if netns == snapshot.hostNetns {
			snapshot.host = append(snapshot.host, proc)
			continue
		}
		// A pod's containers share one namespace; a process that entered
		// another one (a nested sandbox) would show the wrong socket table.
		if proc.podUID == "" {
			continue
		}
		if namespace, ok := podNetns[proc.podUID]; ok && namespace != netns {
			continue
		}
		podNetns[proc.podUID] = netns
		snapshot.byPod[proc.podUID] = append(snapshot.byPod[proc.podUID], proc)
	}
	a.known = known
}

func localAddresses() map[string]bool {
	local := map[string]bool{}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return local
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			local[network.IP.String()] = true
		}
	}
	return local
}

// findSocket returns the inode and owner uid of a candidate's socket in the
// network namespace of process directory procDir, and whether any table was
// readable. An exact match wins; otherwise, for the receiving side, a TCP
// listener on the local port (the server of a connection not yet accepted), or
// an unconnected UDP socket bound to it. IPv4 flows are also looked up in the
// IPv6 tables, where dual-stack sockets appear v4-mapped.
func (a *processAttributor) findSocket(c candidate, procDir string, udp bool, deadline time.Time) (string, uint32, bool) {
	local, localErr := netip.ParseAddr(c.ip)
	remote, remoteErr := netip.ParseAddr(c.otherIP)
	if localErr != nil || remoteErr != nil {
		return "", 0, true
	}
	local, remote = local.Unmap(), remote.Unmap()
	if a.diag != nil && c.netns != "" && c.netns == a.diagNetns {
		if inode, uid, answered := a.querySocket(udp, c.side == "dst", netip.AddrPortFrom(local, c.port), netip.AddrPortFrom(remote, c.otherPort)); answered {
			return inode, uid, true
		}
	}
	tables := []string{"tcp", "tcp6"}
	if udp {
		tables = []string{"udp", "udp6"}
	}
	if local.Is6() {
		tables = tables[1:]
	}
	hint := c.netns + "|" + tables[0] + "|" + c.side
	if len(tables) == 2 && a.tableFirst[hint] == 1 {
		tables[0], tables[1] = tables[1], tables[0]
	}
	server := c.side == "dst"
	needle := []byte(fmt.Sprintf(":%04X ", c.port))
	opened := false
	for _, name := range tables {
		data, ok := a.socketTable(c, procDir, name, deadline)
		if !ok {
			if time.Now().After(deadline) {
				return "", 0, opened
			}
			continue
		}
		opened = true
		inode, uid := scanSocketTable(data, needle, udp, server, local, c.port, remote, c.otherPort)
		if inode == "" {
			continue
		}
		if len(tables) == 2 {
			if name == "tcp6" || name == "udp6" {
				a.tableFirst[hint] = 1
			} else {
				delete(a.tableFirst, hint)
			}
		}
		// A listener or unconnected socket found here is the answer too: an
		// accepted connection is in its listener's table, so the other table
		// cannot hold an exact match for it.
		return inode, uid, true
	}
	return "", 0, opened
}

// selfNetnsPath names the network namespace this process runs in.
var selfNetnsPath = "/proc/self/ns/net"

// sockDiagMaxErrors consecutive failed queries switch lookups back to reading
// socket tables.
const sockDiagMaxErrors = 3

// querySocket asks the kernel for the socket; answered is false when the
// query itself failed and the tables must be read instead.
func (a *processAttributor) querySocket(udp, server bool, local, remote netip.AddrPort) (inode string, uid uint32, answered bool) {
	a.diagLookups.Add(1)
	found, owner, err := a.diag.find(udp, server, local, remote)
	switch {
	case err == nil:
		a.diagErrors = 0
		return strconv.FormatUint(uint64(found), 10), owner, true
	case errors.Is(err, errNoSocket):
		a.diagErrors = 0
		return "", 0, true
	}
	a.diagErrors++
	if a.diagErrors >= sockDiagMaxErrors {
		a.logger.Warn("Host socket lookups read socket tables from now on", "error", err)
		a.diag.close()
		a.diag = nil
	}
	return "", 0, false
}

// socketTable returns a namespace's socket table, reusing a read that started
// after the candidate's flow was queued: such a read lists the flow's socket
// if it was still open, as a new read would.
func (a *processAttributor) socketTable(c candidate, procDir, name string, deadline time.Time) ([]byte, bool) {
	key := c.netns + "|" + name
	if cached, ok := a.tables[key]; ok && c.netns != "" && !cached.at.Before(c.queuedAt) {
		a.tableReuse.Add(1)
		return cached.data, true
	}
	started := time.Now()
	file, err := os.Open(filepath.Join(procDir, "net", name))
	if err != nil {
		return nil, false
	}
	defer func() { _ = file.Close() }()
	data := make([]byte, 0, 64<<10)
	for {
		if time.Now().After(deadline) {
			return nil, false
		}
		if len(data) == cap(data) {
			data = append(data, 0)[:len(data)]
		}
		n, err := file.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil || n == 0 {
			break
		}
	}
	a.tableReads.Add(1)
	if c.netns != "" {
		if len(a.tables) >= processMaxTables {
			for k, table := range a.tables {
				if started.Sub(table.at) > processQueueAge {
					delete(a.tables, k)
				}
			}
			if len(a.tables) >= processMaxTables {
				a.tables = map[string]socketTable{}
			}
		}
		a.tables[key] = socketTable{at: started, data: data}
	}
	return data, true
}

// scanSocketTable finds a socket in the text of a /proc/net socket table. Only
// lines containing the local port in hex are parsed.
func scanSocketTable(data, needle []byte, udp, server bool, local netip.Addr, localPort uint16, remote netip.Addr, remotePort uint16) (inode string, uid uint32) {
	var fallback string
	var fallbackUID uint32
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		if !bytes.Contains(line, needle) {
			continue
		}
		fields := strings.Fields(string(line))
		if len(fields) < 10 || fields[9] == "0" {
			continue // Header, or a request socket not yet accepted.
		}
		from, fromPort, fromOK := parseProcAddress(fields[1])
		if !fromOK || fromPort != localPort {
			continue
		}
		to, toPort, toOK := parseProcAddress(fields[2])
		owner, err := strconv.ParseUint(fields[7], 10, 32)
		if !toOK || err != nil {
			continue
		}
		from, to = from.Unmap(), to.Unmap()
		if from == local && to == remote && toPort == remotePort {
			return fields[9], uint32(owner)
		}
		boundHere := from == local || from.IsUnspecified()
		listening := server && !udp && fields[3] == "0A"
		unconnected := udp && to.IsUnspecified() && toPort == 0
		if fallback == "" && boundHere && (listening || unconnected) {
			fallback, fallbackUID = fields[9], uint32(owner)
		}
	}
	return fallback, fallbackUID
}

func parseProcAddress(value string) (netip.Addr, uint16, bool) {
	hexIP, hexPort, ok := strings.Cut(value, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	decoded, err := hex.DecodeString(hexIP)
	if err != nil || (len(decoded) != 4 && len(decoded) != 16) {
		return netip.Addr{}, 0, false
	}
	for start := 0; start < len(decoded); start += 4 {
		decoded[start], decoded[start+3] = decoded[start+3], decoded[start]
		decoded[start+1], decoded[start+2] = decoded[start+2], decoded[start+1]
	}
	if len(decoded) == 4 {
		return netip.AddrFrom4([4]byte(decoded)), uint16(port), true
	}
	return netip.AddrFrom16([16]byte(decoded)), uint16(port), true
}
