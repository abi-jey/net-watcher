# Kubernetes-aware network map and DNS evidence

The **Network map** page visualizes captured connections and their DNS evidence.
It supports draggable nodes, pan/zoom, fit/reset, time-window and namespace/IP
filters, live refresh, and a details panel. The event list also exposes Kubernetes
endpoint names and an **Inspect DNS evidence** action.

Solid edges are connection observations. Dashed green edges show a matched DNS
query/answer relationship. Neither edge style represents a firewall allow/deny
decision. Multiple capture interfaces can observe the same traffic; observation
counts are not exact unique-connection counts.

Node colors and labels distinguish **Ours**, **Internal · unattributed**, and
**External · unattributed**. “Ours” requires a captured Kubernetes pod, Service,
or node identity, or an explicitly configured address; it does not follow merely
from a private IP. “Internal” includes private, link-local and shared
Tailscale-range addresses. An unattributed address
may still be yours; the map does not claim ownership from its address range.
Ownership and network scope are separate, so a Kubernetes-owned external address
can be both **Ours** and **External** in the inspector. Add LAN or public addresses
that you own to the web instance with `--owned-cidrs=192.0.2.10/32,2001:db8::/48`.
These optional ranges only change map labels; they do not rewrite stored events.

## Running

Build using the repository Makefile. The current CLI command is `start`.

```bash
make build

# Capture one Linux interface. Raw packet capture requires CAP_NET_RAW.
sudo ./net-watcher start --interface eth0 \
  --db /var/lib/net-watcher/netwatcher.db \
  --web-host 127.0.0.1 --web-port 8920

# View an existing database without starting capture or requiring CAP_NET_RAW.
./net-watcher start --capture=false --db /path/to/netwatcher.db \
  --web-host 127.0.0.1 --web-port 8920
```

Open `http://127.0.0.1:8920/#map` or select **Network map** in the sidebar. The database parent directory
must exist. Opening a database adds the new columns and DNS evidence table through
the existing migration mechanism. Historical events remain readable; old hostname
labels do not become verified DNS evidence retroactively.

Keep real deployment addresses, kubeconfig references, captures, and local helper
scripts under `.local/`, which is ignored by Git. The public examples here contain
no deployment-specific addresses or credentials.

## Kubernetes discovery

On a Kubernetes node with `kubectl`, choose a context explicitly:

```bash
./net-watcher start --kubernetes --kube-context YOUR_CONTEXT \
  --db /path/to/netwatcher.db --web-host 127.0.0.1
```

Run with the user's intended kubeconfig identity and the packet-capture capability;
using `sudo` may select a different home directory/kubeconfig. Net Watcher does not
change cluster resources. Without `--kube-context`, `--kubernetes` uses the standard
in-cluster service-account token and CA. The token is reread for renewal and TLS
verification stays enabled.

Inventory discovery requires **list** access to:

| API group | Resources |
| --- | --- |
| Core | pods, services, nodes |
| apps | replicasets |
| discovery.k8s.io | endpointslices |
| cilium.io (optional) | ciliumnodes |

See `examples/kubernetes-reader-rbac.yaml` for an optional least-privilege reader
role and service account. Apply it only as part of your chosen deployment. A pod
running the capture process must see the node interfaces (for example, a node-local
collector with `hostNetwork: true` and `CAP_NET_RAW`). Kubernetes discovery alone
does not provide packets from other nodes: deploy capture on each relevant node or
inspect that node's collector separately. The distributed deployment aggregates
collector observations in the central ingester.

Discovery refreshes every 30 seconds and is published as a complete snapshot.
Metadata older than 90 seconds is no longer attached to new events. Failed discovery
is visible in the map while ordinary packet capture continues.

Enrichment includes:

- Pod names, namespaces, UIDs, node placement and owning workload (including
  ReplicaSet → Deployment ownership).
- IPv4/IPv6 pod addresses and Service VIPs.
- EndpointSlice membership associated with the actual backend port/protocol.
- Node addresses, optional Cilium internal/host addresses, and possible NodePort
  service membership. CiliumNode metadata is matched to a Kubernetes Node by name;
  missing or unreadable Cilium CRDs do not disable ordinary discovery.
- Host-network traffic identified as the node, rather than arbitrarily assigning
  the shared address to a particular host-network pod.

Endpoint metadata is saved **at capture time**. Stored observations are not
rewritten with today's owner of a reused pod IP. Inventory can lag between
refreshes; its timestamp is displayed in the inspector. Service membership is a
candidate based on inventory, not proof of a particular NAT traversal.
Within a selected map sample, older unattributed observations of a node address
share its node marker only if the sample contains one unambiguous captured node
identity for that IP. This read-time association does not alter stored events or
infer ownership for reused pod IPs.

`--kubernetes` includes virtual interfaces during automatic interface selection.
`--include-virtual` enables that behavior independently. Automatic discovery checks
for interface additions/removals every 10 seconds, including unnumbered pod veths.
An explicit `--interface` list stays fixed. Raw-IP interfaces are decoded as raw IP;
Ethernet interfaces use Ethernet decoding. Capture should be placed where original
pod IPs are visible, before SNAT. Observing only an encapsulated/encrypted underlay
does not reconstruct the hidden pod path.

## What qualifies as DNS evidence?

A persistent `DNSResolution` record is produced only when:

1. A DNS query was actually observed.
2. A response matches its client IP/port, resolver IP/port, transport, transaction
   ID, question name, type and class within 30 seconds.
3. It is a successful, non-truncated IN-class response.
4. Its A/AAAA answer belongs to the queried name or a CNAME chain rooted there.
   Unrelated answer records do not establish a mapping for the query.

The record retains the queried name, returned address, original answer records,
CNAME chain, transaction ID, requesting client, resolver, interface, both timestamps,
effective TTL, expiry time, and available client/address Kubernetes context.

Mappings are scoped to the **requesting client IP** and known Kubernetes resource
UID. A different pod cannot inherit another client's lookup. The minimum TTL across
the CNAME chain and address record bounds correlation with later connection events.
Zero-TTL replies remain historical evidence but are never reused as cached mappings.
Unexpired bindings are restored from SQLite after a collector restart.

New connections store references to the evidence valid when observed. Expired
records remain available as historical evidence rather than being mistaken for a
current DNS mapping. Unsolicited, failed, truncated and unmatched replies remain
ordinary DNS observations and do not populate this evidence cache.

UDP DNS and length-prefixed TCP DNS on port 53 are supported. TCP capture must see
the stream's SYN; split messages and retransmissions are handled, but a sequence
gap invalidates that direction rather than guessing message boundaries. Reordered
or missed packets can therefore reduce evidence coverage. Encrypted DNS, lookups
before capture, and application-local DNS caches may not be visible.

**“No matched DNS evidence” does not mean “the application used a literal IP.”**
Conversely, a matched record proves that a resolver returned that mapping to that
observed client; it does not prove which string the application passed to its socket
API. TLS SNI remains a separate field and is never promoted to DNS proof. No active
reverse-DNS lookup is used to invent evidence. This is passive observation, not
DNSSEC validation or cryptographic authentication of the responder.

The evidence table is independent of legacy DNS compaction. Existing compaction
does not pair/deduplicate versioned query/response rows using the old name-only
heuristic. Storage maintenance preserves evidence referenced by retained events;
unreferenced evidence is removed during size-based pruning on central/standalone
instances, or after expiration on forwarding collectors. See
`docs/kubernetes-deployment.md` for the configurable database limit.

## APIs

- `GET /api/network-map?since=1h&namespace=example&ip=10.0.0.8&limit=2000`
  returns nodes, connection/DNS edges, recent evidence and discovery status.
  `since` is bounded to 24 hours; `limit` is 1–5000. Graphs are capped at 250 nodes
  and explicitly report truncation. Namespace attribution uses stored metadata.
- `GET /api/dns-evidence?ids=1,2` returns up to 100 referenced evidence records,
  including historical records outside the current graph window.

## Verification

```bash
make test       # Go tests including race detection
make test-ui    # Dependency-free Node.js layout/evidence tests
make vet
make build
make lint      # Requires golangci-lint installed on PATH
```

Tests exercise transaction matching, cross-client and pod-IP-reuse isolation, TTLs,
CNAME ownership, negative/truncated/unsolicited replies, TCP DNS framing/gaps,
Kubernetes inventory and stale metadata, and map/evidence API behavior.
