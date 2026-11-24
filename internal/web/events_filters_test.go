package web

import (
	"net/url"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
)

// Each events filter selects exactly the matching events, and invalid values
// are rejected rather than matching nothing.
func TestEventsFilters(t *testing.T) {
	f := newPodFixtureWith(t, false)
	at := f.now.Add(-10 * time.Minute)
	event := func(iface string, version uint8, srcIP, dstIP string, dstPort uint16) database.NetworkEvent {
		return database.NetworkEvent{Timestamp: at, EventType: database.EventTCPStart, CollectorID: "node-a", Interface: iface, IPVersion: version,
			SrcIP: srcIP, SrcPort: 40000, DstIP: dstIP, DstPort: dstPort}
	}
	podToService := event("lxc12ab", 4, "10.0.1.7", "10.96.0.10", 53)
	podToService.SrcKind, podToService.SrcNamespace, podToService.SrcName = "pod", "demo", "api-1"
	podToService.DstKind, podToService.DstNamespace, podToService.DstName = "service", "kube-system", "kube-dns"
	nodeToInternet := event("enp0s25", 6, "2001:db8::7", "2001:db8:1::316", 443)
	nodeToInternet.CollectorID, nodeToInternet.SrcKind, nodeToInternet.SrcName = "node-b", "node", "node-b"
	nodeToInternet.ProcessCommand, nodeToInternet.ProcessSide, nodeToInternet.ProcessPID = "tailscaled", "src", 308
	sidecar := event("eni77", 4, "10.0.1.8", "10.0.1.9", 8080) // AWS pod link, not an uplink.
	tunnel := event("tailscale0", 4, "100.64.0.1", "100.64.0.2", 22)
	exit := event("tailscale1", 4, "100.99.117.15", "157.240.17.40", 443)
	exit.Route, exit.TailnetPeer, exit.TailnetPeerName = "exit-node", "100.99.117.15", "m2003j15sc.tailnet.ts.net"
	if err := f.writer.InsertBatch([]database.NetworkEvent{podToService, nodeToInternet, sidecar, tunnel, exit}); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		params url.Values
		want   []string // Interfaces of the matching events.
	}{
		"pod links":         {url.Values{"ifaceRole": {"pod"}}, []string{"lxc12ab", "eni77"}},
		"uplinks":           {url.Values{"ifaceRole": {"uplink"}}, []string{"enp0s25"}},
		"tailscale":         {url.Values{"ifaceRole": {"tailscale"}}, []string{"tailscale0", "tailscale1"}},
		"exit node":         {url.Values{"route": {"exit-node"}}, []string{"tailscale1"}},
		"any route":         {url.Values{"route": {"any"}}, []string{"tailscale1"}},
		"peer name":         {url.Values{"q": {"m2003j15sc"}}, []string{"tailscale1"}},
		"interface name":    {url.Values{"iface": {"eni77"}}, []string{"eni77"}},
		"IPv6":              {url.Values{"ipVersion": {"6"}}, []string{"enp0s25"}},
		"node":              {url.Values{"collector": {"node-b"}}, []string{"enp0s25"}},
		"with a process":    {url.Values{"withProcess": {"yes"}}, []string{"enp0s25"}},
		"without a process": {url.Values{"withProcess": {"no"}}, []string{"lxc12ab", "eni77", "tailscale0", "tailscale1"}},
		"source is a pod":   {url.Values{"srcKind": {"pod"}}, []string{"lxc12ab"}},
		"source is a node":  {url.Values{"srcKind": {"node"}}, []string{"enp0s25"}},
		"unknown dest":      {url.Values{"dstKind": {"none"}}, []string{"enp0s25", "eni77", "tailscale0", "tailscale1"}},
		"to a service":      {url.Values{"dstKind": {"service"}}, []string{"lxc12ab"}},
		"namespace":         {url.Values{"namespace": {"kube-system"}}, []string{"lxc12ab"}},
		"port":              {url.Values{"port": {"443"}}, []string{"enp0s25", "tailscale1"}},
		"combined":          {url.Values{"ifaceRole": {"pod"}, "dstKind": {"none"}}, []string{"eni77"}},
	} {
		t.Run(name, func(t *testing.T) {
			params := test.params
			params.Set("from", f.now.Add(-time.Hour).Format(time.RFC3339))
			params.Set("to", f.now.Format(time.RFC3339))
			var page EventsResponse
			if code := f.get(t, "/api/events", params, &page); code != 200 {
				t.Fatalf("status %d", code)
			}
			got := map[string]bool{}
			for _, event := range page.Events {
				got[event.Interface] = true
			}
			if len(got) != len(test.want) || len(page.Events) != len(test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
			for _, iface := range test.want {
				if !got[iface] {
					t.Fatalf("got %v, want %v", got, test.want)
				}
			}
		})
	}
	for _, bad := range []url.Values{{"ifaceRole": {"pods"}}, {"ipVersion": {"5"}}, {"withProcess": {"maybe"}}, {"srcKind": {"pods"}}, {"port": {"https"}}, {"route": {"exit"}},
		{"f": {"kind = pods"}}, {"f": {"colour = red"}}, {"f": {"port = (53,"}}, {"f": {"ip = 10.0.0.0/33"}}, {"f": {"bytes > lots"}}, {"f": {"ns = x or"}}} {
		if code := f.get(t, "/api/events", bad, nil); code != 400 {
			t.Errorf("%v: status %d, want 400", bad, code)
		}
	}
}
