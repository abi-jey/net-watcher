package watcher

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/abja/net-watcher/internal/kube"
	"github.com/charmbracelet/log"
)

// Protocol types for session tracking
type Protocol string

const (
	ProtoTCP  Protocol = "TCP"
	ProtoUDP  Protocol = "UDP"
	ProtoICMP Protocol = "ICMP"
)

// Session represents an active connection in memory
type Session struct {
	ID        string
	Protocol  Protocol
	Src       string
	Dst       string
	Iface     string
	IPVersion uint8 // 4 or 6
	StartTime time.Time
	LastSeen  time.Time
	ByteCount int64
	Hostname  string // Cached hostname for this connection
	// FlowID links the flow's records; the totals count what each end sent.
	FlowID                                     string
	SrcBytes, DstBytes, SrcPackets, DstPackets int64
	Service                                    string // UDP service name, such as DNS or VXLAN.
	// reported is the part of ByteCount earlier records accounted for, as of
	// lastRecord.
	reported   int64
	lastRecord time.Time
	// tunnel: a kernel tunnel's flow between two hosts, whatever source
	// ports the kernel picks; its ends are told apart by address.
	tunnel bool
	// DNS specific
	DNSQueries []string
	// TLS specific
	SNI string
}

// SessionManager handles the state of active connections
type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
	logger   *log.Logger
	db       *database.DB
	// This host's addresses and tailnet device names, for Tailscale routes.
	hostAddrs *hostAddresses
	tailnet   *tailnetNames
	// Configuration
	cleanupInterval time.Duration
	sessionTimeout  time.Duration
	// updateInterval: an open flow that carried traffic since its last
	// record gets a progress record this often.
	updateInterval time.Duration
	// tunnels are this host's kernel tunnel ports (see tunnelPorts).
	tunnels atomic.Pointer[map[uint16]string]
	// dnsHeld are DNS queries waiting for their response, which records the
	// lookup; by lookup key (dnsLookupKey).
	dnsHoldMu   sync.Mutex
	dnsHeld     map[string]heldLookup
	stopChan    chan struct{}
	cleanupDone chan struct{}
	// Filters - which protocols/events to log
	filters      map[string]bool
	exclusions   map[string]bool
	excludePorts map[uint16]bool
	// Track recent rejected UDP to combine with ICMP unreachable
	recentUDPRejects map[string]time.Time
	dns              *dnsTracker
	contextLookup    ContextLookup
	probeLookup      ProbeLookup
	processMux       sync.RWMutex
	processLookup    *processAttributor
	// Event batching. Packet handlers only append to the buffer; a separate
	// goroutine writes it, because a database write under the session mutex
	// stalls every capture goroutine and overflows the kernel rings.
	eventBuffer    []database.NetworkEvent
	eventBufferMux sync.Mutex
	batchSize      int
	flushSignal    chan struct{} // Buffered 1: "a batch is ready".
	flushDone      chan struct{}
	flushMux       sync.Mutex // Serialises writes so retried events keep their order.
	// Events that failed to write are retried up to maxRetainedEvents; beyond
	// that the oldest are discarded and summarised as a GAP event.
	writeLoss    lossSpan
	discarded    atomic.Int64
	captureDrops atomic.Int64
	maxRetained  int // Zero means maxRetainedEvents.
}

func (sm *SessionManager) retainLimit() int {
	if sm.maxRetained > 0 {
		return sm.maxRetained
	}
	return maxRetainedEvents
}

// ContextLookup attributes an address to its Kubernetes identity at a time.
type ContextLookup func(ip string, port uint16, protocol string, at time.Time) kube.Attribution

// ProbeLookup names the probes of the pod holding ip at time at that target
// port, when that pod runs on node (see kube.Index.Probe).
type ProbeLookup func(ip string, port uint16, node string, at time.Time) string

// maxRetainedEvents bounds memory used for events awaiting a successful write.
const maxRetainedEvents = 50000

type lossSpan struct {
	count       int64
	first, last time.Time
}

func (l *lossSpan) add(events []database.NetworkEvent) {
	for _, event := range events {
		if l.first.IsZero() || event.Timestamp.Before(l.first) {
			l.first = event.Timestamp
		}
		if event.Timestamp.After(l.last) {
			l.last = event.Timestamp
		}
	}
	l.count += int64(len(events))
}

// Stats reports cumulative loss counters for collector health.
type Stats struct {
	DiscardedEvents int64
	CaptureDrops    int64
	BufferedEvents  int
}

// Stats returns cumulative counters since the process started.
func (sm *SessionManager) Stats() Stats {
	sm.eventBufferMux.Lock()
	buffered := len(sm.eventBuffer)
	sm.eventBufferMux.Unlock()
	return Stats{DiscardedEvents: sm.discarded.Load(), CaptureDrops: sm.captureDrops.Load(), BufferedEvents: buffered}
}

// RecordCaptureDrops records kernel packet drops as a GAP event for the interval.
func (sm *SessionManager) RecordCaptureDrops(iface string, drops int64, from, to time.Time) {
	if drops <= 0 || sm.db == nil {
		return
	}
	sm.captureDrops.Add(drops)
	sm.eventBufferMux.Lock()
	sm.eventBuffer = append(sm.eventBuffer, database.NewGapEvent(database.GapCaptureDrops, drops, from, to, iface))
	sm.eventBufferMux.Unlock()
}

// NewSessionManager creates a new session manager and starts the cleanup goroutine
// onlyFilter is a comma-separated list of protocols to log (tcp,udp,icmp,dns,tls)
// excludeFilter is a comma-separated list of traffic to exclude
// excludePortsStr is a comma-separated list of ports to exclude
// Empty string means log everything / exclude nothing
func NewSessionManager(logger *log.Logger, db *database.DB, onlyFilter, excludeFilter, excludePortsStr string) *SessionManager {
	filters := parseFilters(onlyFilter)
	exclusions := parseFilters(excludeFilter)
	excludePorts := parsePortsFilter(excludePortsStr)

	// Debug: log excluded ports
	if len(excludePorts) > 0 {
		var ports []uint16
		for p := range excludePorts {
			ports = append(ports, p)
		}
		logger.Info("Excluding ports", "ports", ports)
	}

	sm := &SessionManager{
		hostAddrs:        newHostAddresses(localAddresses),
		tailnet:          newTailnetNames(),
		sessions:         make(map[string]*Session),
		logger:           logger,
		db:               db,
		cleanupInterval:  30 * time.Second,
		sessionTimeout:   2 * time.Minute,
		updateInterval:   flowUpdateInterval,
		dnsHeld:          map[string]heldLookup{},
		stopChan:         make(chan struct{}),
		cleanupDone:      make(chan struct{}),
		filters:          filters,
		exclusions:       exclusions,
		excludePorts:     excludePorts,
		recentUDPRejects: make(map[string]time.Time),
		dns:              newDNSTracker(),
		eventBuffer:      make([]database.NetworkEvent, 0, 100),
		batchSize:        100,
		flushSignal:      make(chan struct{}, 1),
		flushDone:        make(chan struct{}),
	}
	// Start Garbage Collector in background
	if db != nil {
		if err := sm.dns.restore(db); err != nil {
			logger.Warn("Could not restore DNS evidence cache", "error", err)
		}
	}
	sm.refreshTunnels()
	go sm.cleanupLoop()
	go sm.flushLoop()
	sm.tailnet.failed = func(ip string, err error) {
		logger.Warn("Tailnet device name lookup failed; events keep its address only", "address", ip, "resolver", tailnetResolver, "error", err)
	}
	return sm
}

// flushLoop writes full batches off the packet path.
func (sm *SessionManager) flushLoop() {
	defer close(sm.flushDone)
	sweep := time.NewTicker(dnsSweepInterval)
	defer sweep.Stop()
	for {
		select {
		case <-sm.stopChan:
			return
		case <-sm.flushSignal:
			sm.flushEvents()
		case now := <-sweep.C:
			sm.releaseParked(now, false)
			sm.releaseQueries(now, false)
		}
	}
}

// parseFilters converts comma-separated filter string to a map
func parseFilters(filterStr string) map[string]bool {
	filters := make(map[string]bool)
	if filterStr == "" {
		// Empty means log everything
		return filters
	}
	for _, f := range strings.Split(strings.ToLower(filterStr), ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			filters[f] = true
		}
	}
	return filters
}

// parsePortsFilter converts comma-separated port string to a map
func parsePortsFilter(portsStr string) map[uint16]bool {
	ports := make(map[uint16]bool)
	if portsStr == "" {
		return ports
	}
	for _, p := range strings.Split(portsStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port <= 65535 {
				ports[uint16(port)] = true
			}
		}
	}
	return ports
}

// shouldLog returns true if the given protocol should be logged
func (sm *SessionManager) shouldLog(protocol string) bool {
	// If no filters specified, log everything
	if len(sm.filters) == 0 {
		return true
	}
	return sm.filters[strings.ToLower(protocol)]
}

// shouldExclude checks if traffic should be excluded based on src/dst addresses and ports
func (sm *SessionManager) shouldExclude(src, dst string, srcPort, dstPort uint16) bool {
	// Check for explicitly excluded ports first (independent of --exclude flag)
	if len(sm.excludePorts) > 0 {
		if sm.excludePorts[srcPort] || sm.excludePorts[dstPort] {
			return true
		}
	}

	if len(sm.exclusions) == 0 {
		return false
	}

	// Check for multicast exclusion (224.0.0.0/4 for IPv4, ff00::/8 for IPv6)
	if sm.exclusions["multicast"] {
		if isMulticastAddress(dst) {
			return true
		}
	}

	// Check for broadcast exclusion
	if sm.exclusions["broadcast"] {
		if strings.Contains(dst, "255.255.255.255") {
			return true
		}
	}

	// Check for link-local exclusion (169.254.x.x, fe80::)
	if sm.exclusions["linklocal"] {
		if isLinkLocalAddress(src) || isLinkLocalAddress(dst) {
			return true
		}
	}

	// Check for BitTorrent exclusion (common DHT ports)
	if sm.exclusions["bittorrent"] {
		btPorts := map[uint16]bool{
			6881: true, 6882: true, 6883: true, 6884: true, 6885: true,
			6886: true, 6887: true, 6888: true, 6889: true, 6890: true,
			51413: true, // Transmission default
		}
		if btPorts[srcPort] || btPorts[dstPort] {
			return true
		}
	}

	// Check for mDNS exclusion
	if sm.exclusions["mdns"] {
		if srcPort == 5353 || dstPort == 5353 {
			return true
		}
	}

	// Check for SSDP/UPnP exclusion
	if sm.exclusions["ssdp"] {
		if srcPort == 1900 || dstPort == 1900 {
			return true
		}
	}

	// Check for cloud metadata service exclusion (169.254.169.254)
	if sm.exclusions["metadata"] {
		if isMetadataAddress(src) || isMetadataAddress(dst) {
			return true
		}
	}

	return false
}

// isMulticastAddress checks if address is multicast
func isMulticastAddress(addr string) bool {
	// IPv4 multicast: 224.0.0.0 - 239.255.255.255
	// IPv6 multicast: ff00::/8
	if strings.HasPrefix(addr, "[224.") || strings.HasPrefix(addr, "[225.") ||
		strings.HasPrefix(addr, "[226.") || strings.HasPrefix(addr, "[227.") ||
		strings.HasPrefix(addr, "[228.") || strings.HasPrefix(addr, "[229.") ||
		strings.HasPrefix(addr, "[230.") || strings.HasPrefix(addr, "[231.") ||
		strings.HasPrefix(addr, "[232.") || strings.HasPrefix(addr, "[233.") ||
		strings.HasPrefix(addr, "[234.") || strings.HasPrefix(addr, "[235.") ||
		strings.HasPrefix(addr, "[236.") || strings.HasPrefix(addr, "[237.") ||
		strings.HasPrefix(addr, "[238.") || strings.HasPrefix(addr, "[239.") ||
		strings.HasPrefix(addr, "[ff") {
		return true
	}
	return false
}

// isLinkLocalAddress checks if address is link-local
func isLinkLocalAddress(addr string) bool {
	// IPv4 link-local: 169.254.x.x
	// IPv6 link-local: fe80::/10
	if strings.HasPrefix(addr, "[169.254.") || strings.HasPrefix(addr, "[fe80:") ||
		strings.HasPrefix(addr, "169.254.") || strings.HasPrefix(addr, "fe80:") {
		return true
	}
	return false
}

// isMetadataAddress checks if address is cloud metadata service (169.254.169.254)
func isMetadataAddress(addr string) bool {
	return strings.Contains(addr, "169.254.169.254")
}

// Stop stops the session manager cleanup goroutine and flushes remaining events
func (sm *SessionManager) Stop() {
	close(sm.stopChan)
	<-sm.cleanupDone
	<-sm.flushDone
	if lookup := sm.currentProcessLookup(); lookup != nil {
		lookup.stop()
	}
	sm.releaseParked(time.Now(), true)
	sm.releaseQueries(time.Now(), true) // Unanswered queries, and responses whose query did not come.
	// Flush any remaining buffered events
	sm.flushEvents()
}

// EnableProcessAttribution attributes flows on this node to the processes
// owning their sockets, reading the host procfs mounted at root, within
// budget of CPU time per second (DefaultProcessBudget when zero).
func (sm *SessionManager) EnableProcessAttribution(root string, containers ContainerLookup, budget time.Duration, traceConnects bool) error {
	lookup, err := newProcessAttributor(root, containers, budget, traceConnects, sm.logger, sm.appendEvent)
	if err != nil {
		return err
	}
	sm.processMux.Lock()
	sm.processLookup = lookup
	sm.processMux.Unlock()
	return nil
}

func (sm *SessionManager) currentProcessLookup() *processAttributor {
	sm.processMux.RLock()
	defer sm.processMux.RUnlock()
	return sm.processLookup
}

// queueEvent enriches an event with pod and DNS context, attributes its
// process when that is known or can be looked up, and buffers it.
func (sm *SessionManager) queueEvent(event database.NetworkEvent) {
	if sm.db == nil {
		return
	}
	protocol := event.Protocol
	if strings.HasPrefix(string(event.EventType), "TCP") || event.EventType == database.EventTLSSNI {
		protocol = "TCP"
	}
	if strings.HasPrefix(string(event.EventType), "UDP") {
		protocol = "UDP"
	}
	if sm.contextLookup != nil && event.EventType != database.EventGap {
		// Attribute at capture time: the address may since belong to another pod.
		src := sm.contextLookup(event.SrcIP, event.SrcPort, protocol, event.Timestamp)
		dst := sm.contextLookup(event.DstIP, event.DstPort, protocol, event.Timestamp)
		event.SourceContext, event.DestinationContext = src.Context, dst.Context
		event.SrcKind, event.SrcNamespace, event.SrcName, event.SrcUID, event.SrcWorkload, event.SrcAttribution = src.Kind, src.Namespace, src.Name, src.UID, src.Workload, src.Confidence
		event.DstKind, event.DstNamespace, event.DstName, event.DstUID, event.DstWorkload, event.DstAttribution = dst.Kind, dst.Namespace, dst.Name, dst.UID, dst.Workload, dst.Confidence
		if sm.probeLookup != nil && protocol == "TCP" && src.Kind == "node" && dst.Kind == "pod" {
			// Process attribution below clears it if another process opened the connection.
			event.Probe = sm.probeLookup(event.DstIP, event.DstPort, src.Name, event.Timestamp)
		}
	}
	if event.EventType != database.EventGap {
		if route, peer := tailnetRoute(event.Interface, event.SrcIP, event.DstIP, sm.hostAddrs.has); route != "" {
			event.Route, event.TailnetPeer = route, peer
			if peer != "" {
				event.TailnetPeerName = sm.tailnet.name(peer)
			}
		}
	}
	if event.EventType == database.EventTCPStart || event.EventType == database.EventUDPStart || event.EventType == database.EventTLSSNI {
		matches := sm.dns.lookup(event.SrcIP, event.DstIP, event.Timestamp)
		ids := make([]uint, 0, len(matches))
		identity := contextIdentity(event.SourceContext)
		event.Hostname, event.DNSAge = "", 0
		for _, entry := range matches {
			if contextIdentity(entry.ClientContext) != identity {
				continue
			}
			ids = append(ids, entry.ID)
			event.Hostname, event.DNSAge = entry.Name, event.Timestamp.Sub(entry.ResponseTime).Milliseconds()
		}
		encoded, _ := json.Marshal(ids)
		event.DNSResolutionIDs = string(encoded)
	}
	if lookup := sm.currentProcessLookup(); lookup != nil && lookup.handle(&event) {
		return // The attributor appends it after the lookup.
	}
	sm.appendEvent(event)
}

// appendEvent buffers an event and signals a flush when the batch is full;
// a DNS query waits for its response instead (holdQuery).
func (sm *SessionManager) appendEvent(event database.NetworkEvent) {
	if sm.holdQuery(&event) {
		return
	}
	sm.bufferEvent(event)
}

func (sm *SessionManager) bufferEvent(event database.NetworkEvent) {
	sm.eventBufferMux.Lock()
	sm.eventBuffer = append(sm.eventBuffer, event)
	shouldFlush := len(sm.eventBuffer) >= sm.batchSize
	sm.eventBufferMux.Unlock()

	if shouldFlush {
		select {
		case sm.flushSignal <- struct{}{}:
		default: // A flush is already pending; it will take this batch too.
		}
	}
}

// flushEvents writes all buffered events to the database. On failure the events
// are kept for the next flush rather than dropped; if failures persist, the
// oldest events beyond maxRetainedEvents are discarded and recorded as a GAP.
func (sm *SessionManager) flushEvents() {
	sm.flushMux.Lock()
	defer sm.flushMux.Unlock()
	sm.eventBufferMux.Lock()
	if len(sm.eventBuffer) == 0 {
		sm.eventBufferMux.Unlock()
		return
	}
	events := make([]database.NetworkEvent, len(sm.eventBuffer), len(sm.eventBuffer)+1)
	copy(events, sm.eventBuffer)
	sm.eventBuffer = sm.eventBuffer[:0]
	loss := sm.writeLoss
	sm.eventBufferMux.Unlock()

	if loss.count > 0 {
		events = append(events, database.NewGapEvent(database.GapWriteFailure, loss.count, loss.first, loss.last, ""))
	}
	if err := sm.db.InsertBatch(events); err != nil {
		if loss.count > 0 {
			events = events[:len(events)-1]
		}
		sm.eventBufferMux.Lock()
		// Keep failed events ahead of anything captured meanwhile to preserve order.
		retained := append(events, sm.eventBuffer...)
		if overflow := len(retained) - sm.retainLimit(); overflow > 0 {
			sm.writeLoss.add(retained[:overflow])
			sm.discarded.Add(int64(overflow))
			retained = retained[overflow:]
		}
		sm.eventBuffer = retained
		sm.eventBufferMux.Unlock()
		sm.logger.Error("Failed to insert event batch; retaining for retry", "count", len(events), "retained", len(retained), "error", err)
		return
	}
	if loss.count > 0 {
		sm.eventBufferMux.Lock()
		sm.writeLoss.count -= loss.count
		if sm.writeLoss.count == 0 {
			sm.writeLoss = lossSpan{}
		}
		sm.eventBufferMux.Unlock()
	}
	sm.logger.Debug("Flushed event batch", "count", len(events))
	for i := range events {
		database.PublishEvent(&events[i])
	}
}

// TrackTCP handles TCP connection state machine
func (sm *SessionManager) TrackTCP(iface, src, dst string, isSyn, isFin, isRst bool, length int, isIPv6 bool) {
	if !sm.shouldLog("tcp") {
		return
	}

	ipVersion := uint8(4)
	if isIPv6 {
		ipVersion = 6
	}

	// Check metadata service exclusion
	if sm.exclusions["metadata"] {
		if isMetadataAddress(src) || isMetadataAddress(dst) {
			return
		}
	}

	// Generate a consistent key for this connection
	key := fmt.Sprintf("TCP:%s->%s", src, dst)

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[key]
	if !exists && !isSyn {
		reverseKey := fmt.Sprintf("TCP:%s->%s", dst, src)
		if reverse, found := sm.sessions[reverseKey]; found {
			session, exists, key = reverse, true, reverseKey
		}
	}

	// CASE A: New Connection (SYN without ACK)
	if isSyn && !exists {
		// Look up hostname from DNS cache
		dstIP := extractIPFromAddr(dst)
		hostname, dnsAge := sm.lookupDNSCache(extractIPFromAddr(src), dstIP)

		now := time.Now()
		session = &Session{
			ID:         key,
			Protocol:   ProtoTCP,
			Src:        src,
			Dst:        dst,
			Iface:      iface,
			IPVersion:  ipVersion,
			Hostname:   hostname,
			StartTime:  now,
			LastSeen:   now,
			FlowID:     newFlowID(),
			lastRecord: now,
		}
		session.count(true, length)
		sm.sessions[key] = session

		srcIP, srcPortNum := parseAddr(src)
		dstIPParsed, dstPortNum := parseAddr(dst)

		// Log and save to DB
		if hostname != "" {
			sm.logger.Debug("[TCP START]",
				"iface", iface,
				"src", src,
				"dst", dst,
				"hostname", hostname,
				"dns_age", dnsAge.Round(time.Millisecond),
			)
			sm.queueEvent(database.NetworkEvent{
				Timestamp: time.Now(),
				EventType: database.EventTCPStart,
				Interface: iface,
				IPVersion: ipVersion,
				SrcIP:     srcIP,
				SrcPort:   srcPortNum,
				DstIP:     dstIPParsed,
				DstPort:   dstPortNum,
				Hostname:  hostname,
				DNSAge:    dnsAge.Milliseconds(),
				FlowID:    session.FlowID, SrcBytes: session.SrcBytes, SrcPackets: session.SrcPackets,
			})
		} else {
			sm.logger.Debug("[TCP START]",
				"iface", iface,
				"src", src,
				"dst", dst,
			)
			sm.queueEvent(database.NetworkEvent{
				Timestamp: time.Now(),
				EventType: database.EventTCPStart,
				Interface: iface,
				IPVersion: ipVersion,
				SrcIP:     srcIP,
				SrcPort:   srcPortNum,
				DstIP:     dstIPParsed,
				DstPort:   dstPortNum,
				FlowID:    session.FlowID, SrcBytes: session.SrcBytes, SrcPackets: session.SrcPackets,
			})
		}
		return
	}

	// CASE B: Existing Connection (Update)
	if exists {
		session.LastSeen = time.Now()
		session.count(src == session.Src, length)

		// CASE C: End of Connection (FIN or RST)
		if isFin || isRst {
			duration := time.Since(session.StartTime)
			endReason := "FIN"
			if isRst {
				endReason = "RST"
			}
			sm.logger.Debug("[TCP END]",
				"iface", session.Iface,
				"src", src,
				"dst", dst,
				"duration", duration.Round(time.Millisecond),
				"bytes", session.ByteCount,
				"reason", endReason,
			)

			srcIP, srcPortNum := parseAddr(session.Src)
			dstIP, dstPortNum := parseAddr(session.Dst)
			end := database.NetworkEvent{
				Timestamp: time.Now(),
				EventType: database.EventTCPEnd,
				Interface: session.Iface,
				IPVersion: session.IPVersion,
				SrcIP:     srcIP,
				SrcPort:   srcPortNum,
				DstIP:     dstIP,
				DstPort:   dstPortNum,
				Hostname:  session.Hostname,
				Duration:  duration.Milliseconds(),
				Reason:    endReason,
			}
			session.account(&end, end.Timestamp)
			sm.queueEvent(end)
			delete(sm.sessions, key)
		}
	}
}

// TrackUDP tracks UDP flows: packets between two addresses and ports, in
// either direction, until neither has sent for the session timeout. A
// kernel tunnel's traffic (VXLAN, Geneve) is one flow per pair of hosts: the
// kernel sends each connection it carries from a source port of its own,
// which would make each of them a tunnel flow too, and they are recorded as
// flows of their own on the tunnel device.
func (sm *SessionManager) TrackUDP(iface, src, dst string, srcPort, dstPort uint16, length int, isIPv6 bool) {
	if !sm.shouldLog("udp") {
		return
	}

	// Check exclusions
	if sm.shouldExclude(src, dst, srcPort, dstPort) {
		return
	}

	ipVersion := uint8(4)
	if isIPv6 {
		ipVersion = 6
	}

	sender := src
	service, tunnel := "", false
	key := fmt.Sprintf("UDP:%s<->%s", src, dst)
	reverseKey := fmt.Sprintf("UDP:%s<->%s", dst, src)
	if kind, port, ok := sm.tunnelEnd(srcPort, dstPort); ok {
		// The end at the tunnel port is the destination.
		from, to := hostOf(src), hostOf(dst)
		if dstPort != port {
			from, to = to, from
		}
		low, high := from, to
		if high < low {
			low, high = high, low
		}
		key = fmt.Sprintf("UDP-TUNNEL:%s<->%s:%d", low, high, port)
		reverseKey = key
		src, dst, srcPort, dstPort = from+":0", fmt.Sprintf("%s:%d", to, port), 0, port
		service, tunnel = kind, true
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Check if session exists in either direction
	session, exists := sm.sessions[key]
	if !exists {
		session, exists = sm.sessions[reverseKey]
		if exists {
			key = reverseKey
		}
	}

	if exists {
		session.LastSeen = time.Now()
		fromSrc := sender == session.Src
		if session.tunnel {
			fromSrc = hostOf(sender) == hostOf(session.Src)
		}
		session.count(fromSrc, length)
		return
	}

	if service == "" {
		service = identifyUDPService(srcPort, dstPort)
	}
	now := time.Now()
	session = &Session{
		ID:         key,
		Protocol:   ProtoUDP,
		Src:        src,
		Dst:        dst,
		Iface:      iface,
		IPVersion:  ipVersion,
		StartTime:  now,
		LastSeen:   now,
		FlowID:     newFlowID(),
		Service:    service,
		lastRecord: now,
		tunnel:     tunnel,
	}
	session.count(true, length)
	sm.sessions[key] = session

	srcIP, srcPortNum := parseAddr(src)
	dstIP, dstPortNum := parseAddr(dst)
	sm.logger.Debug("[UDP START]", "iface", iface, "src", src, "dst", dst, "service", service)
	sm.queueEvent(database.NetworkEvent{
		Timestamp:  now,
		EventType:  database.EventUDPStart,
		Interface:  iface,
		IPVersion:  ipVersion,
		SrcIP:      srcIP,
		SrcPort:    srcPortNum,
		DstIP:      dstIP,
		DstPort:    dstPortNum,
		Protocol:   service,
		FlowID:     session.FlowID,
		SrcBytes:   session.SrcBytes,
		SrcPackets: session.SrcPackets,
	})
}

// flowUpdateInterval: how often an open flow that carries traffic gets a
// progress record, so its volume shows while it lasts.
const flowUpdateInterval = 5 * time.Minute

func newFlowID() string {
	var id [8]byte
	_, _ = rand.Read(id[:]) // Never fails on Linux.
	return hex.EncodeToString(id[:])
}

// count adds a packet to the flow's totals, by the end that sent it.
func (s *Session) count(fromSrc bool, length int) {
	s.ByteCount += int64(length)
	if fromSrc {
		s.SrcBytes += int64(length)
		s.SrcPackets++
	} else {
		s.DstBytes += int64(length)
		s.DstPackets++
	}
}

// account fills a flow's update or end record: its totals, and as
// ByteCount the bytes since the flow's previous record.
func (s *Session) account(event *database.NetworkEvent, at time.Time) {
	event.ByteCount = s.ByteCount - s.reported
	s.reported, s.lastRecord = s.ByteCount, at
	if s.FlowID == "" {
		return
	}
	event.FlowID = s.FlowID
	event.SrcBytes, event.DstBytes, event.SrcPackets, event.DstPackets = s.SrcBytes, s.DstBytes, s.SrcPackets, s.DstPackets
}

// record is a flow's update, or its end when it expired, made at time at. It
// carries the time of the flow's last packet: the traffic it accounts for
// moved by then, and an idle flow ended then, not when the sweep noticed.
// An update is only made for traffic since the previous record, so a flow's
// records stay in order.
func (s *Session) record(at time.Time, ended bool) database.NetworkEvent {
	srcIP, srcPort := parseAddr(s.Src)
	dstIP, dstPort := parseAddr(s.Dst)
	last := s.LastSeen
	if last.IsZero() || last.After(at) {
		last = at
	}
	event := database.NetworkEvent{
		Timestamp: last,
		Interface: s.Iface,
		IPVersion: s.IPVersion,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Duration:  s.LastSeen.Sub(s.StartTime).Milliseconds(),
	}
	switch {
	case s.Protocol == ProtoUDP && ended:
		event.EventType, event.Protocol = database.EventUDPEnd, s.Service
	case s.Protocol == ProtoUDP:
		event.EventType, event.Protocol = database.EventUDPUpdate, s.Service
	case ended:
		event.EventType, event.Protocol = database.EventTimeout, string(s.Protocol)
	default:
		event.EventType, event.Hostname = database.EventTCPUpdate, s.Hostname
	}
	s.account(&event, at)
	return event
}

// hostOf is an address without its port: "[192.0.2.1]" of "[192.0.2.1]:53".
func hostOf(address string) string {
	if i := strings.LastIndexByte(address, ':'); i >= 0 {
		return address[:i]
	}
	return address
}

// tunnelEnd reports whether either port is one of this host's kernel
// tunnel ports, with the tunnel's kind.
func (sm *SessionManager) tunnelEnd(srcPort, dstPort uint16) (kind string, port uint16, ok bool) {
	ports := sm.tunnels.Load()
	if ports == nil {
		return "", 0, false
	}
	for _, port := range []uint16{dstPort, srcPort} {
		if device, found := (*ports)[port]; found {
			return tunnelService(device), port, true
		}
	}
	return "", 0, false
}

// tunnelService names a tunnel's protocol from tunnelPorts' "kind device".
func tunnelService(device string) string {
	kind, _, _ := strings.Cut(device, " ")
	switch kind {
	case "vxlan":
		return "VXLAN"
	case "geneve":
		return "Geneve"
	}
	return kind
}

// refreshTunnels reads this host's kernel tunnel ports; devices come and go
// with the network plugin.
func (sm *SessionManager) refreshTunnels() {
	ports, err := tunnelPorts()
	if err != nil {
		sm.logger.Debug("Could not list tunnel devices", "error", err)
		return
	}
	sm.tunnels.Store(&ports)
}

// TrackICMP handles ICMP packets
// icmpPayload contains the original packet header for destination unreachable messages
func (sm *SessionManager) TrackICMP(iface, src, dst string, icmpType, icmpCode uint8, length int, isIPv6 bool, icmpPayload []byte) {
	if !sm.shouldLog("icmp") {
		return
	}

	// Check NDP exclusion (ICMPv6 types 133-137 are NDP)
	if sm.exclusions["ndp"] && isIPv6 {
		if icmpType >= 133 && icmpType <= 137 {
			return
		}
	}

	// Check destination unreachable exclusion
	if sm.exclusions["unreachable"] {
		if (!isIPv6 && icmpType == 3) || (isIPv6 && icmpType == 1) {
			return
		}
	}

	// For ICMP destination unreachable, check if the original packet's port is excluded
	// ICMPv4 type 3 code 3 = Port Unreachable, ICMPv6 type 1 code 4 = Port Unreachable
	if len(sm.excludePorts) > 0 {
		if (!isIPv6 && icmpType == 3 && icmpCode == 3) || (isIPv6 && icmpType == 1 && icmpCode == 4) {
			port := extractPortFromICMPPayload(icmpPayload, isIPv6)
			if port > 0 && sm.excludePorts[port] {
				return
			}
		}
	}

	key := fmt.Sprintf("ICMP:%s->%s", src, dst)

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[key]

	ipVersion := uint8(4)
	if isIPv6 {
		ipVersion = 6
	}

	if !exists {
		sm.sessions[key] = &Session{
			ID:        key,
			Protocol:  ProtoICMP,
			Src:       src,
			Dst:       dst,
			Iface:     iface,
			IPVersion: ipVersion,
			StartTime: time.Now(),
			LastSeen:  time.Now(),
			ByteCount: int64(length),
		}

		desc := icmpTypeDescription(icmpType, isIPv6)
		sm.logger.Debug("[ICMP]",
			"iface", iface,
			"src", src,
			"dst", dst,
			"type", icmpType,
			"code", icmpCode,
			"desc", desc,
		)

		sm.queueEvent(database.NetworkEvent{
			Timestamp: time.Now(),
			EventType: database.EventICMP,
			Interface: iface,
			IPVersion: ipVersion,
			SrcIP:     src,
			DstIP:     dst,
			ICMPType:  icmpType,
			ICMPCode:  icmpCode,
			ICMPDesc:  desc,
		})
	} else {
		session.LastSeen = time.Now()
		session.ByteCount += int64(length)
	}
}

// TrackDNS records legacy caller-supplied observations without treating them as
// verified resolutions. Wire capture uses TrackDNSPacket with transaction metadata.
func (sm *SessionManager) TrackDNS(iface, src, dst string, queries []string, isResponse bool, resolvedIPs []string, cnames []string, isIPv6 bool) {
	if !sm.shouldLog("dns") {
		return
	}

	ipVersion := uint8(4)
	if isIPv6 {
		ipVersion = 6
	}

	queryType := "QUERY"
	if isResponse {
		queryType = "RESPONSE"

	}

	srcIP, srcPort := parseAddr(src)
	dstIP, dstPort := parseAddr(dst)

	for _, q := range queries {
		answersStr := ""
		cnamesStr := ""
		if isResponse && len(resolvedIPs) > 0 {
			answersStr = strings.Join(resolvedIPs, ",")
			if len(cnames) > 0 {
				cnamesStr = strings.Join(cnames, ",")
				sm.logger.Debug("[DNS]",
					"iface", iface,
					"type", queryType,
					"src", src,
					"dst", dst,
					"domain", q,
					"cnames", cnames,
					"answers", resolvedIPs,
				)
			} else {
				sm.logger.Debug("[DNS]",
					"iface", iface,
					"type", queryType,
					"src", src,
					"dst", dst,
					"domain", q,
					"answers", resolvedIPs,
				)
			}
		} else {
			sm.logger.Debug("[DNS]",
				"iface", iface,
				"type", queryType,
				"src", src,
				"dst", dst,
				"domain", q,
			)
		}

		sm.queueEvent(database.NetworkEvent{
			Timestamp:  time.Now(),
			EventType:  database.EventDNS,
			Interface:  iface,
			IPVersion:  ipVersion,
			SrcIP:      srcIP,
			SrcPort:    srcPort,
			DstIP:      dstIP,
			DstPort:    dstPort,
			DNSQuery:   q,
			DNSType:    queryType,
			DNSAnswers: answersStr,
			DNSCNAMEs:  cnamesStr,
		})
	}
}

// TrackTLSHandshake logs TLS SNI (Server Name Indication)
func (sm *SessionManager) TrackTLSHandshake(iface, src, dst, sni string, isIPv6 bool) {
	if !sm.shouldLog("tls") {
		return
	}

	ipVersion := uint8(4)
	if isIPv6 {
		ipVersion = 6
	}

	sm.logger.Debug("[TLS SNI]",
		"iface", iface,
		"src", src,
		"dst", dst,
		"server_name", sni,
	)

	srcIP, srcPort := parseAddr(src)
	dstIP, dstPort := parseAddr(dst)
	flowID := ""
	sm.mutex.Lock()
	for _, key := range []string{"TCP:" + src + "->" + dst, "TCP:" + dst + "->" + src} {
		if session, ok := sm.sessions[key]; ok {
			flowID = session.FlowID
			break
		}
	}
	sm.mutex.Unlock()

	sm.queueEvent(database.NetworkEvent{
		FlowID:    flowID,
		Timestamp: time.Now(),
		EventType: database.EventTLSSNI,
		Interface: iface,
		IPVersion: ipVersion,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		TLSSNI:    sni,
	})
}

// recordFlows ends the flows idle for the session timeout and records the
// progress of open ones due an update. It expires under the lock, but
// enriches and queues the records after releasing it: every capture
// goroutine waits for this mutex.
func (sm *SessionManager) recordFlows(now time.Time) {
	var records []database.NetworkEvent
	sm.mutex.Lock()
	threshold := now.Add(-sm.sessionTimeout)
	for key, session := range sm.sessions {
		switch {
		case session.LastSeen.Before(threshold):
			records = append(records, session.record(now, true))
			delete(sm.sessions, key)
		case session.FlowID != "" && now.Sub(session.lastRecord) >= sm.updateInterval && session.ByteCount > session.reported:
			records = append(records, session.record(now, false))
		}
	}
	sm.mutex.Unlock()
	for _, record := range records {
		sm.queueEvent(record)
	}
}

// cleanupLoop removes stale connections (the "Ghost" problem solution)
func (sm *SessionManager) cleanupLoop() {
	defer close(sm.cleanupDone)
	ticker := time.NewTicker(sm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopChan:
			return
		case <-ticker.C:
			if lookup := sm.currentProcessLookup(); lookup != nil {
				lookup.report()
			}
			sm.refreshTunnels()
			sm.recordFlows(time.Now())

			sm.dns.mu.Lock()
			sm.dns.prune(time.Now())
			sm.dns.mu.Unlock()

			// Periodic flush to ensure events are visible to web readers
			sm.flushEvents()
		}
	}
}

// lookupDNSCache returns the hostname and age for a given IP
func (sm *SessionManager) lookupDNSCache(client, ip string) (string, time.Duration) {
	entries := sm.dns.lookup(client, ip, time.Now())
	identity := ""
	if sm.contextLookup != nil {
		identity = contextIdentity(sm.contextLookup(client, 0, "", time.Now()).Context)
	}
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		if contextIdentity(entry.ClientContext) == identity {
			return entry.Name, time.Since(entry.ResponseTime)
		}
	}
	return "", 0
}

// extractIPFromAddr extracts IP from "[ip]:port" format
func extractIPFromAddr(addr string) string {
	// Handle "[ip]:port" format
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end > 1 {
			return addr[1:end]
		}
	}
	// Handle "ip:port" format (shouldn't happen but just in case)
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return addr[:idx]
	}
	return addr
}

// parseAddr extracts IP and port from "[ip]:port" format
func parseAddr(addr string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	var port uint16
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

// GetActiveSessions returns a snapshot of active sessions (for debugging/stats)
func (sm *SessionManager) GetActiveSessions() []Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	sessions := make([]Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		sessions = append(sessions, *s)
	}
	return sessions
}

// icmpTypeDescription returns human-readable ICMP type
func icmpTypeDescription(icmpType uint8, isIPv6 bool) string {
	if isIPv6 {
		return icmpv6TypeDescription(icmpType)
	}
	return icmpv4TypeDescription(icmpType)
}

// icmpv4TypeDescription returns human-readable ICMPv4 type
func icmpv4TypeDescription(icmpType uint8) string {
	switch icmpType {
	case 0:
		return "Echo Reply"
	case 3:
		return "Destination Unreachable"
	case 5:
		return "Redirect"
	case 8:
		return "Echo Request (Ping)"
	case 11:
		return "Time Exceeded"
	default:
		return fmt.Sprintf("Type %d", icmpType)
	}
}

// icmpv6TypeDescription returns human-readable ICMPv6 type
func icmpv6TypeDescription(icmpType uint8) string {
	switch icmpType {
	case 1:
		return "Destination Unreachable"
	case 2:
		return "Packet Too Big"
	case 3:
		return "Time Exceeded"
	case 128:
		return "Echo Request (Ping)"
	case 129:
		return "Echo Reply"
	case 130:
		return "Multicast Listener Query"
	case 131:
		return "Multicast Listener Report"
	case 133:
		return "Router Solicitation"
	case 134:
		return "Router Advertisement"
	case 135:
		return "Neighbor Solicitation"
	case 136:
		return "Neighbor Advertisement"
	case 143:
		return "MLDv2 Report"
	default:
		return fmt.Sprintf("Type %d", icmpType)
	}
}

// extractPortFromICMPPayload extracts the destination port from the original packet
// embedded in an ICMP destination unreachable message
// ICMP payload contains: Original IP header + first 8 bytes of original datagram (UDP/TCP header)
func extractPortFromICMPPayload(payload []byte, isIPv6 bool) uint16 {
	if len(payload) < 8 {
		return 0
	}

	var ipHeaderLen int
	if isIPv6 {
		// IPv6 header is fixed 40 bytes, but ICMP payload starts after ICMP header
		// The payload should already be the original packet (IP header + transport)
		ipHeaderLen = 40
	} else {
		// IPv4: IHL field (lower 4 bits of first byte) * 4
		if len(payload) < 1 {
			return 0
		}
		ipHeaderLen = int(payload[0]&0x0f) * 4
	}

	// After IP header, we have the transport header
	// UDP header: src port (2 bytes) + dst port (2 bytes)
	// We want the destination port (bytes 2-3 of transport header)
	transportOffset := ipHeaderLen
	if len(payload) < transportOffset+4 {
		return 0
	}

	// Destination port is at offset 2-3 of UDP/TCP header
	dstPort := binary.BigEndian.Uint16(payload[transportOffset+2 : transportOffset+4])
	return dstPort
}

// identifyUDPService returns service name based on port
func identifyUDPService(srcPort, dstPort uint16) string {
	// Check destination port first, then source
	ports := []uint16{dstPort, srcPort}
	for _, port := range ports {
		switch port {
		case 53:
			return "DNS"
		case 443:
			return "QUIC"
		case 80:
			return "HTTP/UDP"
		case 123:
			return "NTP"
		case 500, 4500:
			return "IKE/IPsec"
		case 51820:
			return "WireGuard"
		case 41641:
			return "Tailscale"
		case 3478, 3479, 5349:
			return "STUN/TURN"
		case 5353:
			return "mDNS"
		case 1900:
			return "SSDP/UPnP"
		case 5351:
			return "NAT-PMP"
		case 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889:
			return "BitTorrent"
		}
	}
	return ""
}

// ParseDNSResponse extracts domain names, resolved IPs, and CNAMEs from DNS response
func ParseDNSResponse(payload []byte) (queries []string, resolvedIPs []string, cnames []string, isResponse bool) {
	if len(payload) < 12 {
		return nil, nil, nil, false
	}

	// DNS header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	flags := binary.BigEndian.Uint16(payload[2:4])
	isResponse = (flags & 0x8000) != 0
	qdCount := binary.BigEndian.Uint16(payload[4:6])
	anCount := binary.BigEndian.Uint16(payload[6:8])

	offset := 12 // Start of questions section

	// Parse questions
	for i := uint16(0); i < qdCount && offset < len(payload); i++ {
		name, newOffset := parseDNSName(payload, offset)
		if name != "" {
			queries = append(queries, name)
		}
		offset = newOffset + 4 // Skip QTYPE(2) + QCLASS(2)
	}

	// Parse answers (only if response)
	if isResponse && anCount > 0 {
		for i := uint16(0); i < anCount && offset < len(payload); i++ {
			// Skip name (might be compressed)
			_, newOffset := parseDNSName(payload, offset)
			offset = newOffset

			if offset+10 > len(payload) {
				break
			}

			rtype := binary.BigEndian.Uint16(payload[offset : offset+2])
			// Skip rclass(2)
			offset += 4
			// Skip TTL(4)
			offset += 4
			rdlength := binary.BigEndian.Uint16(payload[offset : offset+2])
			offset += 2

			if offset+int(rdlength) > len(payload) {
				break
			}

			// A record (IPv4)
			if rtype == 1 && rdlength == 4 {
				ip := net.IP(payload[offset : offset+4])
				resolvedIPs = append(resolvedIPs, ip.String())
			}
			// AAAA record (IPv6)
			if rtype == 28 && rdlength == 16 {
				ip := net.IP(payload[offset : offset+16])
				resolvedIPs = append(resolvedIPs, ip.String())
			}
			// CNAME record
			if rtype == 5 {
				cname, _ := parseDNSName(payload, offset)
				if cname != "" {
					cnames = append(cnames, cname)
				}
			}

			offset += int(rdlength)
		}
	}

	return queries, resolvedIPs, cnames, isResponse
}

// ParseDNSQueries extracts domain names from DNS layer (legacy, use ParseDNSResponse instead)
func ParseDNSQueries(payload []byte) ([]string, bool) {
	queries, _, _, isResponse := ParseDNSResponse(payload)
	return queries, isResponse
}

// parseDNSName parses a DNS name from the packet
func parseDNSName(payload []byte, offset int) (string, int) {
	var name string
	for offset < len(payload) {
		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}
		// Check for compression pointer
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(payload) {
				break
			}
			// Follow pointer (not implementing full recursion for simplicity)
			offset += 2
			break
		}
		offset++
		if offset+length > len(payload) {
			break
		}
		if name != "" {
			name += "."
		}
		name += string(payload[offset : offset+length])
		offset += length
	}
	return name, offset
}

// ParseTLSSNI extracts Server Name Indication from TLS ClientHello
func ParseTLSSNI(payload []byte) string {
	// Minimum TLS record: 5 bytes header + some content
	if len(payload) < 43 {
		return ""
	}

	// Check TLS Handshake record type (0x16)
	if payload[0] != 0x16 {
		return ""
	}

	// Check for ClientHello (handshake type 0x01)
	// TLS record header: Type(1) + Version(2) + Length(2)
	// Handshake header: Type(1) + Length(3)
	if payload[5] != 0x01 {
		return ""
	}

	// Skip to extensions
	// ClientHello: Version(2) + Random(32) + SessionID(1+var) + CipherSuites(2+var) + Compression(1+var)
	offset := 5 + 4 // TLS header + Handshake header

	// Skip version
	offset += 2

	// Skip random
	offset += 32

	// Skip session ID
	if offset >= len(payload) {
		return ""
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Skip cipher suites
	if offset+2 > len(payload) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	// Skip compression methods
	if offset >= len(payload) {
		return ""
	}
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen

	// Extensions length
	if offset+2 > len(payload) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	// Parse extensions looking for SNI (type 0x0000)
	endOffset := offset + extensionsLen
	if endOffset > len(payload) {
		endOffset = len(payload)
	}

	for offset+4 <= endOffset {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > endOffset {
			break
		}

		// SNI extension type is 0x0000
		if extType == 0x0000 && extLen > 5 {
			// SNI list length (2) + name type (1) + name length (2) + name
			nameLen := int(binary.BigEndian.Uint16(payload[offset+3 : offset+5]))
			if offset+5+nameLen <= endOffset {
				return string(payload[offset+5 : offset+5+nameLen])
			}
		}

		offset += extLen
	}

	return ""
}
