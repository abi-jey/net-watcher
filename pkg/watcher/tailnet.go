package watcher

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Tailscale assigns tailnet devices addresses from these ranges.
var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

func isTailnet(addr netip.Addr) bool {
	addr = addr.Unmap()
	return tailnetV4.Contains(addr) || tailnetV6.Contains(addr)
}

func isTailscaleInterface(name string) bool {
	return strings.HasPrefix(name, "tailscale") || (len(name) > 2 && strings.HasPrefix(name, "ts") && name[2] >= '0' && name[2] <= '9')
}

// tailnetRoute classifies traffic seen on a Tailscale interface that is not
// between two tailnet devices. The interface carries only tunnel traffic, so
// a remote tailnet device exchanging packets with an address that is neither
// a tailnet device nor this node is traffic this node forwards for it: as its
// exit node (to the internet) or subnet router (to a private network). This
// node's own traffic to such an address goes into the tailnet, toward
// another device's exit node or subnet route. peer is the remote tailnet
// device this node forwarded for.
func tailnetRoute(iface, srcIP, dstIP string, local func(string) bool) (route, peer string) {
	if !isTailscaleInterface(iface) {
		return "", ""
	}
	src, srcErr := netip.ParseAddr(srcIP)
	dst, dstErr := netip.ParseAddr(dstIP)
	if srcErr != nil || dstErr != nil {
		return "", ""
	}
	// beyond is the route to an address outside the tailnet and this node.
	beyond := func(addr netip.Addr, text string) string {
		addr = addr.Unmap()
		if isTailnet(addr) || local(text) || !addr.IsGlobalUnicast() {
			return "" // Tailnet, this node, link-local, multicast or unspecified.
		}
		if addr.IsPrivate() {
			return "subnet-router"
		}
		return "exit-node"
	}
	srcPeer := isTailnet(src) && !local(srcIP)
	dstPeer := isTailnet(dst) && !local(dstIP)
	switch {
	case srcPeer && !dstPeer:
		if r := beyond(dst, dstIP); r != "" {
			return r, srcIP
		}
	case dstPeer && !srcPeer:
		if r := beyond(src, srcIP); r != "" {
			return r, dstIP
		}
	case local(srcIP) && beyond(dst, dstIP) != "", local(dstIP) && beyond(src, srcIP) != "":
		return "via-tailnet", ""
	}
	return "", ""
}

// hostAddresses caches this host's interface addresses for the packet path,
// refreshing them in the background: temporary IPv6 addresses rotate.
type hostAddresses struct {
	mu         sync.Mutex
	set        map[string]bool
	at         time.Time
	refreshing bool
	list       func() map[string]bool
	every      time.Duration
}

func newHostAddresses(list func() map[string]bool) *hostAddresses {
	return &hostAddresses{list: list, every: 30 * time.Second}
}

func (h *hostAddresses) has(ip string) bool {
	h.mu.Lock()
	set, stale := h.set, time.Since(h.at) > h.every && !h.refreshing
	if stale {
		h.refreshing = true
	}
	h.mu.Unlock()
	if stale {
		if set == nil {
			set = h.refresh() // First use: nothing to answer from yet.
		} else {
			go h.refresh()
		}
	}
	return set[ip]
}

func (h *hostAddresses) refresh() map[string]bool {
	set := h.list()
	h.mu.Lock()
	h.set, h.at, h.refreshing = set, time.Now(), false
	h.mu.Unlock()
	return set
}

// tailnetNames names tailnet devices through Tailscale's resolver on this
// node (MagicDNS answers reverse lookups for tailnet addresses). Lookups run
// in the background; the packet path only reads the cache, so the first
// events of a new device may carry no name.
type tailnetNames struct {
	mu       sync.Mutex
	names    map[string]tailnetName
	inFlight chan struct{}
	lookup   func(ctx context.Context, ip string) (string, error)
}

type tailnetName struct {
	name  string
	until time.Time
}

const (
	tailnetNameTTL   = time.Hour
	tailnetMissTTL   = 10 * time.Minute
	tailnetMaxNames  = 4096
	tailnetResolver  = "100.100.100.100:53"
	tailnetLookupFor = 2 * time.Second
)

func newTailnetNames() *tailnetNames {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "udp", tailnetResolver)
	}}
	return &tailnetNames{names: map[string]tailnetName{}, inFlight: make(chan struct{}, 4), lookup: func(ctx context.Context, ip string) (string, error) {
		names, err := resolver.LookupAddr(ctx, ip)
		if err != nil || len(names) == 0 {
			return "", err
		}
		return strings.TrimSuffix(names[0], "."), nil
	}}
}

// name returns the cached name of a tailnet address, starting a lookup when
// none is cached.
func (t *tailnetNames) name(ip string) string {
	now := time.Now()
	t.mu.Lock()
	entry, ok := t.names[ip]
	if ok && now.Before(entry.until) {
		t.mu.Unlock()
		return entry.name
	}
	if len(t.names) >= tailnetMaxNames {
		t.names = map[string]tailnetName{}
	}
	// Mark the lookup as running so concurrent packets do not start another.
	t.names[ip] = tailnetName{name: entry.name, until: now.Add(tailnetLookupFor + time.Second)}
	t.mu.Unlock()
	select {
	case t.inFlight <- struct{}{}:
	default:
		return entry.name // Enough lookups running; a later packet retries.
	}
	go func() {
		defer func() { <-t.inFlight }()
		ctx, cancel := context.WithTimeout(context.Background(), tailnetLookupFor)
		defer cancel()
		name, err := t.lookup(ctx, ip)
		ttl := tailnetNameTTL
		if err != nil || name == "" {
			name, ttl = entry.name, tailnetMissTTL // Keep a known name through resolver hiccups.
		}
		t.mu.Lock()
		t.names[ip] = tailnetName{name: name, until: time.Now().Add(ttl)}
		t.mu.Unlock()
	}()
	return entry.name
}

// cached returns the cached name without starting a lookup.
func (t *tailnetNames) cached(ip string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.names[ip].name
}
