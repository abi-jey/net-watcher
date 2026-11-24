package watcher

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestTailnetRoute(t *testing.T) {
	// This node: LAN 192.168.1.80, tailnet 100.64.99.55 / fd7a:115c:a1e0::55.
	local := func(ip string) bool {
		return map[string]bool{"192.168.1.80": true, "100.64.99.55": true, "fd7a:115c:a1e0::55": true, "fe80::1": true}[ip]
	}
	for _, test := range []struct {
		name, iface, src, dst, route, peer string
	}{
		{"phone to the internet through this node", "tailscale0", "100.99.117.15", "157.240.17.40", "exit-node", "100.99.117.15"},
		{"the answer back to the phone", "tailscale0", "1.1.1.1", "100.99.117.15", "exit-node", "100.99.117.15"},
		{"IPv6 exit traffic", "tailscale0", "fd7a:115c:a1e0::99", "2001:4860:4860::8888", "exit-node", "fd7a:115c:a1e0::99"},
		{"phone to the home network", "tailscale0", "100.99.117.15", "192.168.1.10", "subnet-router", "100.99.117.15"},
		{"phone to this node", "tailscale0", "100.99.117.15", "100.64.99.55", "", ""},
		{"phone to the node's LAN address", "tailscale0", "100.99.117.15", "192.168.1.80", "", ""},
		{"between tailnet devices", "tailscale0", "100.99.117.15", "100.64.1.1", "", ""},
		{"this node into the tailnet", "tailscale0", "100.64.99.55", "91.189.91.58", "via-tailnet", ""},
		{"and back", "tailscale0", "91.189.91.58", "100.64.99.55", "via-tailnet", ""},
		{"multicast is not routed", "tailscale0", "fe80::1", "ff02::2", "", ""},
		{"other interfaces are not Tailscale", "enp0s25", "100.99.117.15", "157.240.17.40", "", ""},
		{"ts0 is Tailscale too", "ts0", "100.99.117.15", "157.240.17.40", "exit-node", "100.99.117.15"},
	} {
		route, peer := tailnetRoute(test.iface, test.src, test.dst, local)
		if route != test.route || peer != test.peer {
			t.Errorf("%s: got %q %q, want %q %q", test.name, route, peer, test.route, test.peer)
		}
	}
}

func TestTailnetNamesAreLookedUpInTheBackground(t *testing.T) {
	var calls atomic.Int32
	names := newTailnetNames()
	names.lookup = func(_ context.Context, ip string) (string, error) {
		calls.Add(1)
		if ip == "100.99.117.16" {
			return "", errors.New("NXDOMAIN")
		}
		return "m2003j15sc.tailnet.ts.net", nil
	}
	wait := func(ip, want string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for names.cached(ip) != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: cached %q, want %q", ip, names.cached(ip), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if got := names.name("100.99.117.15"); got != "" {
		t.Fatalf("first packet must not wait for the lookup: %q", got)
	}
	wait("100.99.117.15", "m2003j15sc.tailnet.ts.net")
	if got := names.name("100.99.117.15"); got != "m2003j15sc.tailnet.ts.net" {
		t.Fatalf("cached name: %q", got)
	}
	names.name("100.99.117.16")
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	names.name("100.99.117.16") // The failure is cached: no new lookup.
	names.name("100.99.117.15")
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatalf("lookups: %d, want 2", calls.Load())
	}
}

// Some Tailscale versions answer reverse lookups only for IPv4; an IPv6
// address is then named by resolving known devices forward.
func TestTailnetIPv6NamedThroughKnownDevices(t *testing.T) {
	names := newTailnetNames()
	names.lookup = func(_ context.Context, ip string) (string, error) {
		if ip == "100.67.31.108" {
			return "pixel-8a.tailnet.ts.net", nil
		}
		return "", errors.New("NXDOMAIN")
	}
	names.addresses = func(_ context.Context, name string) ([]netip.Addr, error) {
		if name == "pixel-8a.tailnet.ts.net" {
			return []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::401:1f73")}, nil
		}
		return nil, errors.New("NXDOMAIN")
	}
	wait := func(ip, want string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for names.cached(ip) != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: cached %q, want %q", ip, names.cached(ip), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// The IPv6 address is seen first, before any device is named: it fails.
	names.name("fd7a:115c:a1e0::401:1f73")
	deadline := time.Now().Add(2 * time.Second)
	for !names.settled("fd7a:115c:a1e0::401:1f73") {
		if time.Now().After(deadline) {
			t.Fatal("IPv6 lookup did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	names.name("100.67.31.108")
	wait("100.67.31.108", "pixel-8a.tailnet.ts.net")
	// Naming the device lets the failed IPv6 address retry at once.
	names.name("fd7a:115c:a1e0::401:1f73")
	wait("fd7a:115c:a1e0::401:1f73", "pixel-8a.tailnet.ts.net")
}

// Both addresses of a device are often looked up at once. When the IPv6
// lookup fails while the IPv4 one names the device, the IPv6 miss must not
// be kept: the next packet retries.
func TestTailnetIPv6RetriedWhenNamedConcurrently(t *testing.T) {
	names := newTailnetNames()
	ipv4Named := make(chan struct{})
	names.lookup = func(_ context.Context, ip string) (string, error) {
		if ip == "100.67.31.108" {
			return "pixel-8a.tailnet.ts.net", nil
		}
		<-ipv4Named // The IPv6 lookup is still running when the device is named.
		return "", errors.New("NXDOMAIN")
	}
	var forward atomic.Int32
	names.addresses = func(_ context.Context, _ string) ([]netip.Addr, error) {
		if forward.Add(1) == 1 {
			return nil, errors.New("timeout") // The first forward lookup fails.
		}
		return []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::401:1f73")}, nil
	}
	names.name("fd7a:115c:a1e0::401:1f73")
	names.name("100.67.31.108")
	deadline := time.Now().Add(2 * time.Second)
	for names.cached("100.67.31.108") == "" {
		if time.Now().After(deadline) {
			t.Fatal("IPv4 not named")
		}
		time.Sleep(time.Millisecond)
	}
	close(ipv4Named)
	for forward.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("IPv6 lookup did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	for names.cached("fd7a:115c:a1e0::401:1f73") != "pixel-8a.tailnet.ts.net" {
		if time.Now().After(deadline) {
			t.Fatalf("IPv6 not retried: %q after %d forward lookups", names.cached("fd7a:115c:a1e0::401:1f73"), forward.Load())
		}
		names.name("fd7a:115c:a1e0::401:1f73") // The next packet.
		time.Sleep(5 * time.Millisecond)
	}
}
