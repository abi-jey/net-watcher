package watcher

import (
	"context"
	"errors"
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
