package web

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"gorm.io/gorm"
)

// filterVectors are parse cases shared with web/src/lib/filter.test.ts, so
// the page reads an expression as the server does.
type filterVector struct {
	Input     string `json:"input"`
	Canonical string `json:"canonical,omitempty"`
	Error     string `json:"error,omitempty"`
	// ServerOnly: a value check only the server makes.
	ServerOnly bool `json:"serverOnly,omitempty"`
}

func TestFilterParseVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "filter.vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []filterVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		parsed, err := parseFilter(v.Input)
		if v.Error != "" {
			if err == nil || !strings.Contains(err.Error(), v.Error) {
				t.Errorf("%q: error %v, want %q", v.Input, err, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", v.Input, err)
			continue
		}
		if got := parsed.String(); got != v.Canonical {
			t.Errorf("%q: canonical %q, want %q", v.Input, got, v.Canonical)
		}
		// The canonical text reads back as itself.
		again, err := parseFilter(parsed.String())
		if err != nil || again.String() != parsed.String() {
			t.Errorf("%q: canonical %q reads back as %v, %v", v.Input, parsed.String(), again, err)
		}
	}
}

// filterEvents is a small store of events whose values overlap, with some
// columns NULL as on rows stored before the column existed.
func filterEvents(t *testing.T, db *gorm.DB, now time.Time, n int, seed uint64) []database.NetworkEvent {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, 1))
	pick := func(values ...string) string { return values[r.IntN(len(values))] }
	number := func(values ...int64) int64 { return values[r.IntN(len(values))] }
	ips := []string{"10.0.0.7", "10.0.1.20", "100.64.1.1", "100.127.0.9", "fd7a:115c:a1e0::1", "2a02:aa12::5", "192.168.1.5", "8.8.8.8", ""}
	names := []string{"api.example.com", "example.com.", "EXAMPLE.org", "notexample.com", "x_y%z.test", ""}
	events := make([]database.NetworkEvent, n)
	for i := range events {
		e := database.NetworkEvent{
			Timestamp:   now.Add(-time.Duration(r.IntN(3600)) * time.Second),
			EventType:   database.EventType(pick("TCP_START", "TCP_END", "UDP_START", "UDP_END", "DNS", "TLS_SNI", "ICMP", "GAP")),
			CollectorID: pick("abja", "desktop", ""), Interface: pick("lxc12", "enp0s25", "eni3", "tailscale0", "ts1", "cilium_host", "wlan0", "lo", ""),
			IPVersion: uint8(number(4, 6)), SrcIP: pick(ips...), DstIP: pick(ips...), SrcPort: uint16(number(0, 53, 443, 1500, 40000, 65535)), DstPort: uint16(number(0, 53, 443, 8472, 40000)),
			SrcKind: pick("pod", "node", "service", "endpoint", ""), DstKind: pick("pod", "node", ""),
			SrcNamespace: pick("default", "kube-system", "Monitoring", ""), DstNamespace: pick("default", "kube-system", ""),
			SrcName: pick("api-1", "coredns-x", "abja", ""), DstName: pick("db-0", "desktop", ""), SrcWorkload: pick("default/api", ""), DstWorkload: pick("kube-system/coredns", ""),
			Route: pick("exit-node", "subnet-router", "via-tailnet", ""), TailnetPeer: pick("100.101.1.2", ""), TailnetPeerName: pick("phone.tail.ts.net.", ""),
			Hostname: pick(names...), DNSQuery: pick(names...), TLSSNI: pick(names...), DNSResponseCode: pick("No Error", "Non-Existent Domain", "Server Failure ", ""),
			ByteCount: number(0, 100, 1500, 2<<20), Duration: number(0, 250, 5000, 120_000),
		}
		// Process fields are set together, as the collector sets them.
		if r.IntN(2) == 0 {
			e.ProcessCommand, e.ProcessSide = pick("curl", "python3", "tailscaled", "kubelet"), pick("src", "dst")
			e.ProcessPod, e.ProcessContainer = pick("demo/api-1", ""), pick("api", "")
			// The other end's process, when both ends were on the node.
			if r.IntN(2) == 0 {
				e.PeerProcessCommand, e.PeerProcessPod, e.PeerProcessContainer = pick("python3", "kubelet", "curl"), pick("demo/api-1", ""), pick("api", "")
			}
		}
		events[i] = e
	}
	if err := db.CreateInBatches(&events, 100).Error; err != nil {
		t.Fatal(err)
	}
	// Unset columns are NULL in rows stored before the column existed. A
	// process's fields are added and written together, so in rows with a
	// process (or peer process) its pod and container are never NULL: the
	// process index walks rely on it.
	together := map[string]string{"process_pod": "process_side", "process_container": "process_side",
		"peer_process_pod": "peer_process_command", "peer_process_container": "peer_process_command"}
	for _, column := range append(append([]string{}, textColumns...), "collector_id", "interface", "route", "process_side", "src_kind", "dst_kind", "dns_response_code") {
		condition := ""
		if owner, ok := together[column]; ok {
			condition = " AND COALESCE(" + owner + ", '') = ''"
		}
		if err := db.Exec("UPDATE network_events SET " + column + " = NULL WHERE " + column + " = '' AND id % 3 = 0" + condition).Error; err != nil {
			t.Fatal(err)
		}
	}
	var stored []database.NetworkEvent
	if err := db.Order("id").Find(&stored).Error; err != nil {
		t.Fatal(err)
	}
	return stored
}

// randomFilter writes a random valid expression over every field.
func randomFilter(r *rand.Rand, depth int) string {
	if depth > 0 && r.IntN(3) > 0 {
		left, right := randomFilter(r, depth-1), randomFilter(r, depth-1)
		switch r.IntN(4) {
		case 0:
			return "(" + left + " or " + right + ")"
		case 1:
			return "not (" + left + ")"
		case 2:
			return left + " " + right
		}
		return left + " and " + right
	}
	if r.IntN(8) == 0 {
		return []string{"api", "EXAMPLE", "%", "_", "10.0", "tail", "-coredns", `"x_y%z"`}[r.IntN(8)]
	}
	names := sortedKeys(filterFields)
	name := names[r.IntN(len(names))]
	field := filterFields[name]
	var pool []string
	switch field.kind {
	case enumField:
		pool = sortedKeys(field.values)
	case roleField:
		pool = sortedKeys(interfaceRoles)
	case ipField:
		pool = []string{"10.0.0.7", "100.64.0.0/10", "10.0.0.0/8", "fd7a:115c:a1e0::/48", "2a02:aa12::5", "8.8.8.8", "none", "0.0.0.0/0"}
	case domainField:
		pool = []string{"example.com", "EXAMPLE.org", "x_y%z.test", "com", "none"}
	case numberField:
		switch name {
		case "ipv":
			pool = []string{"4", "6"}
		case "bytes":
			pool = []string{"0", "100", "1.5k", "2M", "100-2000"}
		case "duration":
			pool = []string{"0", "250ms", "5s", "2m", "1-6000"}
		default:
			pool = []string{"0", "53", "443", "40000", "1000-50000"}
		}
	default:
		pool = []string{"abja", "desktop", "default", "kube-system", "Monitoring", "api-1", "curl", "demo/api-1", "api", "100.101.1.2", "phone.tail.ts.net.", "NXDOMAIN", "lxc12", "none"}
	}
	ops := []string{"=", "!="}
	if field.kind == numberField {
		ops = append(ops, "<", "<=", ">", ">=")
	} else if field.kind != roleField {
		ops = append(ops, "~", "!~")
	}
	op := ops[r.IntN(len(ops))]
	quote := func(s string) string { return quoteValue(s, false) }
	if op == "~" || op == "!~" {
		parts := []string{"a", "E", "10.", "%", "_", ".com", "kube", "1"}
		return name + " " + op + " " + quote(parts[r.IntN(len(parts))])
	}
	if len(op) == 2 && op[0] != '!' || op == "<" || op == ">" {
		value := pool[r.IntN(len(pool))]
		if strings.Contains(value, "-") {
			value = strings.Split(value, "-")[0]
		}
		return name + " " + op + " " + value
	}
	if r.IntN(3) == 0 {
		a, b := pool[r.IntN(len(pool))], pool[r.IntN(len(pool))]
		return name + " " + op + " (" + quote(a) + ", " + quote(b) + ")"
	}
	return name + " " + op + " " + quote(pool[r.IntN(len(pool))])
}

// The SQL a filter compiles to, the Go evaluation the live tail uses and the
// page query with its index walks all select the same events.
func TestFilterSQLAndLiveTailAgree(t *testing.T) {
	f := newPodFixtureWith(t, false)
	now := time.Now().UTC().Truncate(time.Second)
	events := filterEvents(t, f.writer.DB, now, 600, 7)
	r := rand.New(rand.NewPCG(11, 3))
	checked, nonTrivial := 0, 0
	// Process identities at one end, as the Processes page links them, walk
	// the process and peer process indexes; random filters rarely do.
	identities := []string{
		"src.process = python3 and src.process.pod = demo/api-1 and src.process.container = api",
		"dst.process = python3 and dst.process.pod = demo/api-1 and dst.process.container = api and type = TCP_START",
		"(src.process = kubelet and src.process.pod = none and src.process.container = none) or (dst.process = kubelet and dst.process.pod = none and dst.process.container = none)",
		"(src.process = curl and src.process.pod = demo/api-1 and src.process.container = api) or (dst.process = curl and dst.process.pod = demo/api-1 and dst.process.container = api)",
	}
	for i := 0; i < 800+len(identities); i++ {
		text := ""
		if i < len(identities) {
			text = identities[i]
			if filter, _ := parseFilter(text); len(eventsParts(filter)) != 2 {
				t.Fatalf("%q does not walk the process indexes: %v", text, eventsParts(filter))
			}
		} else {
			text = randomFilter(r, 3)
		}
		filter, err := parseFilter(text)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		var want []uint
		for i := range events {
			if filter.matches(&events[i]) {
				want = append(want, events[i].ID)
			}
		}
		where, args := filter.sql()
		var got []uint
		if err := f.server.db.Table("network_events").Where(where, args...).Order("id").Pluck("id", &got).Error; err != nil {
			t.Fatalf("%q: %s: %v", text, where, err)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%q\nSQL %s\nSQL selects %d events, Go %d: %v vs %v", text, where, len(got), len(want), difference(got, want), difference(want, got))
		}
		var page []database.NetworkEvent
		if err := eventsSlice(f.server.db.DB, filter, now.Add(-2*time.Hour), cursor{at: now.Add(time.Second)}, 10_000).Find(&page).Error; err != nil {
			t.Fatalf("%q: page: %v", text, err)
		}
		paged := make([]uint, len(page))
		for i, e := range page {
			paged[i] = e.ID
		}
		sort.Slice(paged, func(i, j int) bool { return paged[i] < paged[j] })
		if fmt.Sprint(paged) != fmt.Sprint(want) {
			t.Fatalf("%q: page (%v) selects %d events, want %d", text, eventsParts(filter), len(paged), len(want))
		}
		checked++
		if len(want) > 0 && len(want) < len(events) {
			nonTrivial++
		}
	}
	// Most filters must select some but not all events to test anything.
	if nonTrivial < checked/2 {
		t.Fatalf("only %d of %d filters selected a strict subset", nonTrivial, checked)
	}
}

func difference(a, b []uint) []uint {
	in := map[uint]bool{}
	for _, id := range b {
		in[id] = true
	}
	var out []uint
	for _, id := range a {
		if !in[id] {
			out = append(out, id)
		}
	}
	return out
}

// What a few expressions mean, by example.
func TestFilterMeanings(t *testing.T) {
	podToNode := database.NetworkEvent{EventType: "TCP_START", SrcKind: "pod", SrcNamespace: "default", SrcIP: "10.0.1.5", DstKind: "node", DstIP: "100.64.1.1", DstPort: 443, Interface: "lxc1"}
	external := database.NetworkEvent{EventType: "TLS_SNI", SrcKind: "node", SrcIP: "192.168.1.5", DstIP: "142.250.1.1", DstPort: 443, TLSSNI: "api.Example.com.", ByteCount: 3000, Interface: "enp0s25"}
	dns := database.NetworkEvent{EventType: "DNS", SrcKind: "pod", SrcNamespace: "kube-system", SrcName: "coredns-1", DstIP: "1.1.1.1", DstPort: 53, DNSQuery: "notexample.com", DNSResponseCode: "Non-Existent Domain"}
	// The kubelet's health check of a pod on its node: both processes known.
	probe := database.NetworkEvent{EventType: "TCP_START", SrcKind: "node", SrcIP: "10.0.1.155", DstKind: "pod", DstNamespace: "keda", DstIP: "10.0.1.84", DstPort: 8081,
		ProcessCommand: "kubelet", ProcessSide: "src", PeerProcessCommand: "keda", PeerProcessPod: "keda/keda-operator-1", PeerProcessContainer: "keda-operator"}
	// Only the accepting process known.
	accepted := database.NetworkEvent{EventType: "TCP_START", SrcIP: "10.0.0.31", DstKind: "pod", DstNamespace: "base", DstIP: "10.0.1.112", DstPort: 8000,
		ProcessCommand: "python", ProcessSide: "dst", ProcessPod: "base/base-server-1", ProcessContainer: "base-server"}
	for _, set := range []struct {
		events map[string]*database.NetworkEvent
		tests  [][2]string // Filter, the events it selects.
	}{
		{map[string]*database.NetworkEvent{"podToNode": &podToNode, "external": &external, "dns": &dns}, [][2]string{
			{"kind != pod", "external"},                           // Neither end a pod.
			{"src.kind != pod", "external"},                       // The source is not a pod.
			{"kind = node", "external podToNode"},                 // Either end a node.
			{"dst.kind = none", "dns external"},                   // The destination is outside the cluster.
			{"ip = 100.64.0.0/10", "podToNode"},                   // Either address in the tailnet range.
			{"domain = example.com", "external"},                  // The name or a subdomain, in any case.
			{"domain ~ example", "dns external"},                  // Contains.
			{"bytes > 2k", "external"},                            // Units in powers of 1024.
			{"port = 50-500", "dns external podToNode"},           // A range.
			{"port = 53 or iface.type = uplink", "dns external"},  // Mixed conditions.
			{"-coredns", "external podToNode"},                    // A negated word.
			{"rcode = NXDOMAIN and not ns = default", "dns"},      // Negated comparison.
			{`rcode = "non-existent domain"`, "dns"},              // As stored.
			{"rcode != (noerror, servfail) and port = 53", "dns"}, // Standard names.
			{"(kind = pod or port = 443) and -ns=kube-system", "external podToNode"},
			{"ns = none", "dns external podToNode"}, // At least one end outside a namespace.
			{"src.ns = none", "external"},
			{"type = (dns, tls_sni)", "dns external"},
		}},
		{map[string]*database.NetworkEvent{"probe": &probe, "accepted": &accepted, "external": &external}, [][2]string{
			{"src.process = kubelet", "probe"},                          // The process that opened it.
			{"dst.process = keda", "probe"},                             // The process that accepted it.
			{"process = keda", "probe"},                                 // A process at either end.
			{"dst.process = python", "accepted"},                        // Accepted; the opener is unknown.
			{"src.process = python", ""},                                // Not at the source.
			{"dst.process.pod = keda/keda-operator-1", "probe"},         // Pod of the accepting process.
			{"src.process.pod = none and src.process != none", "probe"}, // Opened by a process outside any pod.
			{"process.side = src", "probe"},                             // The opener is known.
			{"process.side = none", "external"},                         // No process known.
		}},
	} {
		for _, test := range set.tests {
			filter, err := parseFilter(test[0])
			if err != nil {
				t.Fatalf("%q: %v", test[0], err)
			}
			var got []string
			for _, name := range sortedKeys(set.events) {
				if filter.matches(set.events[name]) {
					got = append(got, name)
				}
			}
			if strings.Join(got, " ") != test[1] {
				t.Errorf("%q selects %v, want %q", test[0], got, test[1])
			}
		}
	}
}

// A list of namespaces walks each side's index per namespace, and returns
// an event once even when both its ends are listed.
func TestFilterNamespaceListWalksIndexes(t *testing.T) {
	filter, err := parseFilter("ns = (default, kube-system) and port != 22")
	if err != nil {
		t.Fatal(err)
	}
	parts := eventsParts(filter)
	if len(parts) != 4 || parts[0].index != "idx_src_namespace_time" || parts[1].index != "idx_dst_namespace_time" {
		t.Fatalf("parts: %+v", parts)
	}
	for _, text := range []string{"ns != default", "ns = (default, none)", "port = 53 or ns = default", "ns ~ def"} {
		filter, _ := parseFilter(text)
		if parts := eventsParts(filter); len(parts) != 1 || parts[0].index != "idx_network_events_timestamp" {
			t.Errorf("%q walks %+v", text, parts)
		}
	}
}
