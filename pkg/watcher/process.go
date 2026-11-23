package watcher

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	processLookupDeadline = 10 * time.Millisecond
	processMaxFDLinks     = 4096
	processQueueAge       = 2 * time.Second // Older sockets have likely closed.
	processFlowTTL        = 15 * time.Minute
	processMaxFlows       = 100_000
	processMaxSockets     = 100_000
	processMissTTL        = time.Minute // How long an endpoint with no socket is not looked up again.
	processMaxMisses      = 50_000
	processQueueSize      = 256
	processFullRescan     = time.Minute // Between rescans, only new PIDs are read in full.
	// /proc work is bounded to about 3% of one core on average, with bursts of
	// twice that: two thirds for pod lookups and snapshots, which are cheap
	// and most useful, one third for host lookups, which may scan the
	// descriptors of many processes. Neither can starve the other.
	podWorkPerSecond  = 20 * time.Millisecond
	hostWorkPerSecond = 10 * time.Millisecond
)

// ContainerLookup names a container by runtime ID.
type ContainerLookup func(id string) (namespace, pod, name string, ok bool)

type processIdentity struct {
	PID                           int
	Command, Side, Pod, Container string
	used                          time.Time
}

func (identity processIdentity) apply(event *database.NetworkEvent, side string) {
	event.ProcessPID, event.ProcessCommand, event.ProcessSide = identity.PID, identity.Command, side
	event.ProcessPod, event.ProcessContainer = identity.Pod, identity.Container
}

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

type processAttributor struct {
	root       string
	containers ContainerLookup
	addresses  func() map[string]bool
	onEvent    func(database.NetworkEvent)
	logger     *log.Logger

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
	// lastNoSocket: the last lookup read the socket tables and found nothing.
	lastNoSocket bool

	hostIPs atomic.Pointer[map[string]bool]

	flowMu sync.Mutex
	flows  map[string]processIdentity

	// A few failed lookups per report interval, with their reason, so
	// operators can see why connections stay unattributed.
	exampleMu sync.Mutex
	examples  []string

	attempted, matched, inherited, notLocal atomic.Uint64
	budgetHit, overBudget, expired          atomic.Uint64
	queueFull, noSocket, snapshots, indexed atomic.Uint64
	knownMiss, noOwner, byOwner             atomic.Uint64
	work, snapshotWork                      atomic.Int64 // Nanoseconds spent reading /proc.
}

type knownProc struct {
	netns string
	entry procEntry
}

type socketRef struct {
	pid int
	fd  string
}

func newProcessAttributor(root string, containers ContainerLookup, logger *log.Logger, onEvent func(database.NetworkEvent)) (*processAttributor, error) {
	a := &processAttributor{root: root, containers: containers, addresses: localAddresses, onEvent: onEvent, logger: logger}
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
	a.flows = map[string]processIdentity{}
	a.remote = map[string]time.Time{}
	a.misses = map[string]time.Time{}
	a.podWork, a.hostWork = newWorkBudget(podWorkPerSecond, time.Now()), newWorkBudget(hostWorkPerSecond, time.Now())
	a.refresh(time.Now())
	if a.snapshot.hostNetns == "" || len(a.snapshot.host) == 0 {
		return fmt.Errorf("cannot read process namespaces under %s; process attribution needs CAP_SYS_PTRACE", a.root)
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

// cached returns a flow's identity in either orientation, with the side as
// seen from this event, and keeps the entry alive for long-lived flows.
func (a *processAttributor) cached(event database.NetworkEvent, now time.Time) (processIdentity, string, bool) {
	a.flowMu.Lock()
	defer a.flowMu.Unlock()
	for _, reverse := range []bool{false, true} {
		key := flowKey(event, reverse)
		identity, ok := a.flows[key]
		if !ok {
			continue
		}
		identity.used = now
		a.flows[key] = identity
		side := identity.Side
		if reverse {
			side = map[string]string{"src": "dst", "dst": "src"}[side]
		}
		return identity, side, true
	}
	return processIdentity{}, "", false
}

func (a *processAttributor) remember(event database.NetworkEvent, identity processIdentity) {
	a.flowMu.Lock()
	defer a.flowMu.Unlock()
	if len(a.flows) < processMaxFlows {
		a.flows[flowKey(event, false)] = identity
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
	if identity, side, ok := a.cached(*event, now); ok {
		identity.apply(event, side)
		a.inherited.Add(1)
		return false
	}
	if !attributable(*event) {
		return false
	}
	hosts := a.hostIPs.Load()
	local := event.SrcKind == "pod" || event.DstKind == "pod" || (hosts != nil && ((*hosts)[event.SrcIP] || (*hosts)[event.DstIP]))
	if !local {
		return false
	}
	a.jobsMu.RLock()
	defer a.jobsMu.RUnlock()
	if a.closed {
		return false
	}
	select {
	case a.jobs <- processJob{event: *event, queuedAt: now}:
		return true
	default:
		a.queueFull.Add(1)
		return false
	}
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
	a.report()
}

// report logs and resets counters and expires remembered flows. The session
// cleanup loop calls it every 30 seconds.
func (a *processAttributor) report() {
	now := time.Now()
	a.flowMu.Lock()
	for key, identity := range a.flows {
		if now.Sub(identity.used) > processFlowTTL {
			delete(a.flows, key)
		}
	}
	flows := len(a.flows)
	a.flowMu.Unlock()
	attempted, matched, inherited, notLocal := a.attempted.Swap(0), a.matched.Swap(0), a.inherited.Swap(0), a.notLocal.Swap(0)
	budgetHit, overBudget, expired := a.budgetHit.Swap(0), a.overBudget.Swap(0), a.expired.Swap(0)
	queueFull, noSocket, snapshots, work := a.queueFull.Swap(0), a.noSocket.Swap(0), a.snapshots.Swap(0), a.work.Swap(0)
	indexed, snapshotWork, knownMiss, noOwner := a.indexed.Swap(0), a.snapshotWork.Swap(0), a.knownMiss.Swap(0), a.noOwner.Swap(0)
	byOwner := a.byOwner.Swap(0)
	a.exampleMu.Lock()
	examples := a.examples
	a.examples = nil
	a.exampleMu.Unlock()
	if attempted+inherited+overBudget+expired+queueFull > 0 {
		a.logger.Info("Process attribution", "attempted", attempted, "matched", matched, "from_index", indexed, "by_owner", byOwner, "inherited", inherited,
			"no_socket", noSocket, "no_owner", noOwner, "known_miss", knownMiss, "not_local", notLocal, "deadline_hit", budgetHit, "over_budget", overBudget,
			"expired", expired, "queue_full", queueFull, "flows", flows, "snapshots", snapshots,
			"snapshot_ms", time.Duration(snapshotWork).Milliseconds(), "lookup_ms", time.Duration(work).Milliseconds(), "misses", strings.Join(examples, "; "))
	}
}

func (a *processAttributor) run() {
	defer a.workers.Done()
	for queued := range a.jobs {
		event := queued.event
		now := time.Now()
		if identity, side, ok := a.cached(event, now); ok { // Attributed meanwhile.
			identity.apply(&event, side)
			a.inherited.Add(1)
		} else if now.Sub(queued.queuedAt) > processQueueAge {
			a.expired.Add(1)
		} else {
			if now.Sub(a.snapshot.at) > processSnapshotEvery && a.podWork.ready(now) {
				a.refresh(now)
			}
			a.attribute(&event, queued.queuedAt, now)
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
		c := candidate{side: side.name, ip: side.ip, otherIP: side.otherIP, port: side.port, otherPort: side.otherPort}
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
			c.procs = procs
			list = append(list, c)
			continue
		}
		if a.snapshot.hostIPs[side.ip] {
			c.procs, c.host = a.hostOrder(), true
			list = append(list, c)
		}
	}
	// Pod lookups are cheap (few processes, small tables) and tried first;
	// within each kind the source, which opened the flow, comes first.
	sort.SliceStable(list, func(i, j int) bool { return !list[i].host && list[j].host })
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
	candidates := a.candidates(*event, queuedAt, now)
	if len(candidates) == 0 {
		a.notLocal.Add(1)
		return
	}
	for _, c := range candidates {
		miss := missKey(*event, c)
		if miss != "" && now.Before(a.misses[miss]) {
			a.knownMiss.Add(1)
			continue
		}
		budget := &a.podWork
		if c.host {
			budget = &a.hostWork
		}
		if !budget.ready(now) {
			a.overBudget.Add(1)
			continue
		}
		a.attempted.Add(1)
		started := time.Now()
		identity, ok := a.lookup(*event, c, started.Add(processLookupDeadline))
		spent := time.Since(started)
		budget.spend(spent)
		a.work.Add(int64(spent))
		if !ok {
			if miss != "" && a.lastNoSocket && len(a.misses) < processMaxMisses {
				a.misses[miss] = now.Add(processMissTTL)
			}
			continue
		}
		identity.Side, identity.used = c.side, now
		identity.apply(event, c.side)
		a.matched.Add(1)
		a.remember(*event, identity)
		if c.host {
			a.noteHostPID(identity.PID)
		}
		return
	}
}

func (a *processAttributor) lookup(event database.NetworkEvent, c candidate, deadline time.Time) (processIdentity, bool) {
	udp := strings.HasPrefix(string(event.EventType), "UDP") || (event.EventType == database.EventDNS && event.Protocol != "TCP")
	// Every process in the list shares one network namespace; any of them
	// that is still alive shows its socket table.
	var inode string
	var owner uint32
	opened := false
	for i := 0; i < len(c.procs) && i < 3 && !opened; i++ {
		inode, owner, opened = findSocket(filepath.Join(a.root, strconv.Itoa(c.procs[i].pid)), udp, c.side == "dst", c.ip, c.port, c.otherIP, c.otherPort, deadline)
	}
	a.lastNoSocket = false
	if inode == "" {
		if time.Now().After(deadline) {
			a.budgetHit.Add(1)
			a.example(event, c, "deadline reading socket tables")
		} else {
			a.noSocket.Add(1)
			a.lastNoSocket = opened
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
	for _, proc := range c.procs {
		if time.Now().After(deadline) || followed >= processMaxFDLinks {
			a.budgetHit.Add(1)
			a.example(event, c, fmt.Sprintf("deadline scanning descriptors (%d links)", followed))
			return processIdentity{}, false
		}
		if c.host && proc.uid != owner {
			continue // The socket's owner uid narrows the host's many processes.
		}
		found, readable := a.holdsSocket(proc.pid, target, deadline, &followed)
		if found {
			return a.identify(event, c, proc), true
		}
		if !readable {
			unreadable[proc.pid] = true
		}
	}
	if identity, ok := a.identifyByOwner(event, c, owner, unreadable); ok {
		a.byOwner.Add(1)
		return identity, true
	}
	a.noOwner.Add(1)
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
	defer fds.Close()
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
	return false, !(links > 0 && denied == links)
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
	}
	snapshot := &procSnapshot{at: now, byPod: map[string][]procEntry{}, hostIPs: a.addresses()}
	a.hostIPs.Store(&snapshot.hostIPs)
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

// findSocket returns the inode and owner uid of a flow's socket in the network
// namespace of process directory procDir, and whether any table was readable.
// An exact match wins; otherwise, for the receiving side, a TCP listener on the
// local port (the server of a connection not yet accepted), or an unconnected
// UDP socket bound to it.
// IPv4 flows are also looked up in the IPv6 tables, where dual-stack sockets
// appear v4-mapped.
func findSocket(procDir string, udp, server bool, localIP string, localPort uint16, remoteIP string, remotePort uint16, deadline time.Time) (string, uint32, bool) {
	local, localErr := netip.ParseAddr(localIP)
	remote, remoteErr := netip.ParseAddr(remoteIP)
	if localErr != nil || remoteErr != nil {
		return "", 0, true
	}
	local, remote = local.Unmap(), remote.Unmap()
	tables := []string{"tcp", "tcp6"}
	if udp {
		tables = []string{"udp", "udp6"}
	}
	if local.Is6() {
		tables = tables[1:]
	}
	var fallback string
	var fallbackUID uint32
	opened := false
	for _, table := range tables {
		file, err := os.Open(filepath.Join(procDir, "net", table))
		if err != nil {
			continue
		}
		opened = true
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if time.Now().After(deadline) {
				_ = file.Close()
				return "", 0, true
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[9] == "0" {
				continue // Header, or a request socket not yet accepted.
			}
			from, fromPort, fromOK := parseProcAddress(fields[1])
			if !fromOK || fromPort != localPort {
				continue
			}
			to, toPort, toOK := parseProcAddress(fields[2])
			uid, err := strconv.ParseUint(fields[7], 10, 32)
			if !toOK || err != nil {
				continue
			}
			from, to = from.Unmap(), to.Unmap()
			if from == local && to == remote && toPort == remotePort {
				_ = file.Close()
				return fields[9], uint32(uid), true
			}
			boundHere := from == local || from.IsUnspecified()
			listening := server && !udp && fields[3] == "0A"
			unconnected := udp && to.IsUnspecified() && toPort == 0
			if fallback == "" && boundHere && (listening || unconnected) {
				fallback, fallbackUID = fields[9], uint32(uid)
			}
		}
		_ = file.Close()
	}
	return fallback, fallbackUID, opened
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
