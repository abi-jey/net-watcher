# Kubernetes deployment

`deploy/kubernetes/net-watcher.yaml` deploys Net Watcher as a DaemonSet. Each
Linux node captures traffic visible in its own network namespace and stores a
separate SQLite database at `/var/lib/net-watcher/netwatcher.db` on that node.
This is not a cluster-wide aggregate view.

The supplied ServiceAccount has only `list` access to the resources used for
Kubernetes enrichment (including optional CiliumNode host addresses). This
standalone collector runs as a non-root user with only `CAP_NET_RAW`; the short
init container owns its local data directory. It uses
host networking so AF_PACKET can observe node interfaces. No Service or Ingress
is supplied because the UI does not include authentication.

## Deploy

The manifests track `ghcr.io/abi-jey/net-watcher:latest`, which every `v*`
release pushes after its vulnerability scan, and pull it on each pod start
(`imagePullPolicy: Always`); a rollout restart picks up the newest release.
To run your own build, push it and point the manifests at it:

```bash
docker build --pull -t ghcr.io/<you>/net-watcher:latest .
docker push ghcr.io/<you>/net-watcher:latest
kubectl apply -f deploy/kubernetes/net-watcher.yaml
kubectl -n net-watcher rollout status daemonset/net-watcher
```

Open one node-local map through an authenticated Kubernetes API connection:

```bash
kubectl -n net-watcher get pods -o wide
kubectl -n net-watcher port-forward pod/NET_WATCHER_POD 8920:8920
```

Then open `http://127.0.0.1:8920/#map`. A pod on each node has its own map and
database. Keep environment-specific image tags, node restrictions, retention,
and exposure configuration outside Git under `.local/`.

## Operations

```bash
kubectl -n net-watcher get pods -o wide
kubectl -n net-watcher logs daemonset/net-watcher --all-containers=true --prefix
kubectl auth can-i --as=system:serviceaccount:net-watcher:net-watcher list pods -A
kubectl -n net-watcher delete daemonset net-watcher
```

Deleting the DaemonSet does not delete the node-local databases. Delete
`/var/lib/net-watcher` on each node only when intentionally removing captured
data.

## Distributed deployment

`deploy/kubernetes/distributed.yaml` adds one central ingester and a collector
DaemonSet. Each collector retains its node-local SQLite database and forwards
acknowledged batches to the ingester. The ingester records the collector ID and
source IDs, making retries idempotent and remapping referenced DNS evidence to
central IDs. The central database and its map therefore aggregate all collector
observations; capture duplicates remain observations, not unique flows.
Collectors run with `--web=false` because host-networked nodes can otherwise
conflict with the central UI's localhost port.

Storage maintenance starts after 10 minutes and runs every 10 minutes (or a longer
`--storage-check-interval`). The ingester keeps its SQLite database, WAL, and
shared-memory files under 10 GiB by default (`--max-db-size-gb=10`). Once the
limit is exceeded it removes oldest events and their ingest keys, releases
older unreferenced DNS evidence, and reclaims disk space. At most one vacuum is
performed per check; an unusually large database may need another cycle to
reach the limit. Set
`--max-db-size-gb=3` on the ingester to use a 3 GiB limit. The same limit
applies in standalone mode. Temporary SQLite files use the writable data
volume during compaction; allow enough free disk space for SQLite to vacuum.

Each collector keeps its own database until batches are acknowledged. Every
10 minutes it removes acknowledged events and DNS evidence that expired more
than 15 minutes ago and is no longer referenced, then reclaims unused disk
pages. The grace period covers events still buffered in memory that reference
an answer close to its expiry.

Collectors are bounded by `--max-collector-db-size-gb` (default 5 GiB). While the
ingester is unreachable a collector grows up to that limit; beyond it, the oldest
unforwarded events are discarded and replaced by one `GAP` event recording how
many events were lost and the time span they covered. The GAP is forwarded like
any other event, so the loss is visible centrally.

### Loss is recorded, never silent

Audit queries must distinguish "nothing happened" from "nothing was recorded".
Net Watcher writes a `GAP` event (`reason`, `event_count`, `timestamp`..`end_time`)
whenever observations are knowingly lost:

| Reason | Cause |
| --- | --- |
| `capture-drops` | The kernel capture ring dropped packets (per interface, per 30 s). |
| `write-buffer-overflow` | Local database writes failed long enough that more than 50,000 events were waiting. Failed writes are otherwise retried, not dropped. |
| `collector-size-limit` | Unforwarded events were discarded to respect `--max-collector-db-size-gb`. |
| `rejected-by-ingester` | The ingester permanently rejected one specific event. |

Delivery never stops on a single bad record. If an event references DNS
evidence that no longer exists locally, it is forwarded without that reference
and `DNSEvidenceMissing` counts the omission. If the ingester rejects a batch's
content (HTTP 400 with `X-Net-Watcher-Reject`), the collector narrows the batch
down to the offending event and skips only that one. A 400 without that header,
for example from an older ingester or a proxy, is retried and never skips data.
Upgrade the ingester before collectors: older ingesters reject the new fields.

On the ingester, a queued batch that fails to store 10 times over at least
10 minutes is moved to a `dead_batches` table in the queue database so later
batches continue. Set-aside batches are retried hourly and never deleted
automatically; their count appears in the `Ingestion queue status` log.

### Collector health

Every request from a collector carries a health report, and idle collectors send
a heartbeat every 30 seconds. `GET /api/collectors` on the central UI lists each
collector's last report (backlog, oldest unforwarded event, consecutive delivery
failures and last error, storage against its limit, discarded events, capture
drops, missing DNS evidence, Kubernetes inventory age) with a derived state:
`ok`, `degraded`, `backlog`, `failing`, or `stale` (no report for 2 minutes). It
also totals GAP events per collector and reason for the last 24 hours. The forwarder drains acknowledged batches immediately when behind,
and checks again after two seconds when idle or retrying a failure. The central
map may represent duplicate observations captured on multiple node interfaces.
The forwarder sends up to 250 events per request, splitting batches that would
exceed the 5 MiB request limit. The ingester looks up retry keys in indexed
groups and inserts new events and DNS evidence in bounded SQL batches inside a
transaction. The ingester first commits each request to a separate durable SQLite
queue (`<db>.ingest-queue.db`) before acknowledging it to the collector. A background
worker drains that queue into the central database, independently of the HTTP
request lifetime. Maintenance already runs in a background goroutine; when it
occupies the central writer, requests continue to enter the separate queue.
Both queue and central ingest commits use SQLite FULL synchronization so the
handoff remains durable before a queue entry is removed.
Pending batches survive restarts and are replayed idempotently. Invalid DNS
references are rejected before queuing.

`--ingest-queue-size-mb=256` bounds pending JSON payload bytes. Allow additional
disk space for SQLite pages and WAL; the queue is separate from `--max-db-size-gb`.
When full or unavailable, the ingester returns HTTP 503 and collectors retain
their local data for retry. Queue depth, payload bytes, and oldest batch age are
logged at startup and every minute, including during maintenance. The map reflects
drained events, so it can lag behind while maintenance runs. Keep one ingester
replica and use the supplied `Recreate` rollout strategy so only one worker
consumes the spool. Retry deduplication does not attempt to merge distinct capture
observations.

SQLite WAL keeps the single ingestion writer and the web query pool separate.
The web pool is read-only and limited to two connections, so slow filtering and
analytics cannot occupy the writer connection. The UI shares one statistics
request between its sidebar and Events page and pauses automatic polling in
hidden tabs. Frequently requested statistics are cached for 35 seconds, and
Top Hosts and timeline responses for 65 seconds.
Other read use cases can use the same read-only query path; long-range queries
use sparse hourly summaries instead of repeatedly scanning raw events. The
example ingester remains capped at 1 CPU core and 512 MiB memory.

### Sparse hourly summaries and historical prefill

The central ingester and standalone mode maintain two additional tables in the
same SQLite database, preserving atomicity with event writes and retry keys:

- `hourly_events`: counts and observed bytes per UTC hour and event type.
- `hourly_hosts`: counts and observed bytes per UTC hour and source IP,
  destination IP, or hostname, stored as three independent dimensions.

Only hours and hosts with events get rows. There are no source/destination pair,
port, or process combinations and no preallocated empty buckets. Repeated events
in an ingestion batch are combined before bulk upserts, limiting extra writer
work. Source bytes mean bytes observed on events with that source; destination
bytes mean bytes observed on events with that destination. These are observation
totals, not deduplicated physical-link traffic; multiple collectors/interfaces
can observe the same flow. Summaries describe retained raw events: pruning
subtracts their contributions transactionally and removes empty summary rows.

On upgrade, startup snapshots the historical maximum event ID without scanning
the full table. One background worker prefills at most 1,000 events per chunk,
then yields for at least 100 ms and at least nine times the chunk runtime. This
targets a low wall-time duty cycle, not an additional CPU allocation. New events
are summarized immediately in their insertion transaction. The historical cursor
is persisted with each chunk, so interruptions resume without double counting;
late-arriving timestamps and retention during backfill are supported. Collector-only
databases do not start prefill or maintain summaries.

`Hourly summary backfill` logs expose the cursor, target, and completion status
once per minute. While warming, queries combine completed summaries with only
historical IDs not yet processed; already-covered rows and live inserts are
excluded from the raw interior scan. Partial boundary hours and sub-hour charts
still use raw detail. Responses expose `aggregation` coverage status, and
automatic dashboard/statistics refresh slows to five minutes while warming.
Compaction that rewrites observations invalidates the
summaries and schedules another throttled rebuild. No second database copy or
per-event aggregation marker is required.

Statistics, event types, unfiltered/event-type-only event counts, and top-host
rankings use the summaries. The dashboard supports 1-hour, 24-hour, 7-day, and
all-retained host rankings (`/api/top-hosts?hours=24`). The standard 24-hour
timeline uses hourly buckets; ranges up to four hours retain 5-minute detail
from raw events. Larger timeline buckets combine hours. Partial boundary hours
use raw events to keep arbitrary time ranges exact, with an exclusive end time.
Traffic direction is evaluated using private IPv4/IPv6 addresses and configured
owned CIDRs at query time, so changing owned networks does not require a rebuild.
The existing SQLite size limit includes summary storage.

Collector INFO logs cover lifecycle changes and maintenance. Routine TCP/UDP,
DNS, TLS, ICMP, and per-interface statistics are available with `--debug`; event
recording is independent of the console log level. Capture decodes the owned
AF_PACKET read buffer without a second copy. DNS global cleanup runs at most once
per second, while individual lookups, reused query IDs, and TCP streams retain
their expiry checks.

The ingester exposes its authenticated batch endpoint only through the ClusterIP
Service on port 8921. The map UI is exposed through the Tailscale `ts-serve`
ingress at `https://net-watcher.tailfb4030.ts.net`. The bearer token is required
on both ends and must not be placed in Git:

```bash
kubectl -n net-watcher create secret generic net-watcher-ingest-token \
  --from-literal=token="$(openssl rand -base64 48)"
kubectl apply -f deploy/kubernetes/distributed.yaml
kubectl -n net-watcher rollout status deployment/net-watcher-ingest
kubectl -n net-watcher rollout status daemonset/net-watcher-collector
kubectl -n net-watcher port-forward deployment/net-watcher-ingest 8920:8920
```

Open `https://net-watcher.tailfb4030.ts.net/#map` for the combined map. Keep
the generated Secret, image digest override, and any environment-specific patch
below `.local/`; that directory is ignored by Git.

The map marks observed Kubernetes pods, Services, and nodes (including Cilium
host addresses when the optional CiliumNode inventory is available) as **Ours**.
The ingester can also mark operator-owned LAN or public IP ranges that are not
in Kubernetes with `--owned-cidrs=192.0.2.10/32,2001:db8::/48`. Set these in
your local ingester overlay; other private addresses remain **Internal ·
unattributed** rather than being assumed to belong to you.

The collector runs as UID 0 with every capability dropped except `CAP_NET_RAW`,
because this CRI-O configuration does not retain an added effective capability
for a non-root host-network process. It also has an `Unconfined` seccomp profile
because CRI-O's `RuntimeDefault` profile blocks AF_PACKET sockets. These
exceptions apply only to the node-local collector; the ingester remains
non-root, capability-free, and `RuntimeDefault`.

### Optional process attribution

With `--process-attribution`, each collector records which process on its node
opened or accepted a connection: the kernel command name (`comm`), host PID,
and for pods the pod and container name. It works for pods (each in its own
network namespace) and for host processes, including host-network pods. Add to
the collector:

```yaml
args:
  - --process-attribution
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_RAW", "SYS_PTRACE"]
  # Only on nodes where the runtime applies an AppArmor profile (for example
  # CRI-O 1.33's crio-default): such profiles deny reading other processes.
  appArmorProfile:
    type: Unconfined
volumeMounts:
  - name: host-proc
    mountPath: /host/proc
    readOnly: true
# under volumes:
  - name: host-proc
    hostPath:
      path: /proc
      type: Directory
```

`CAP_SYS_PTRACE` is needed only to *read* other processes' `/proc` entries
(their network namespace link, socket tables and file-descriptor links); the
collector never attaches to, traces or signals a process, and needs no
`hostPID`, eBPF or writable host mount. Command-line arguments are never read.
Where the container runtime confines containers with an AppArmor profile, that
profile also denies these reads, and the collector logs `Process attribution
unavailable ... needs CAP_SYS_PTRACE` at start even with the capability; the
`appArmorProfile: Unconfined` setting above lifts that for the collector only.

How it works: every 15 seconds (and at most every 3 when an unknown pod shows
up) the collector maps processes to pods through `/proc/<pid>/cgroup`, which
names the pod UID and container ID. When a connection starts, it looks the flow
up in the socket table of that pod's network namespace, then finds which of
that pod's processes holds the socket. For the host's own namespace, where the
host-network collector runs, it asks the kernel for that one socket through
`sock_diag` netlink (the query `ss` uses, no privilege needed) instead of
reading the node's whole socket table: microseconds instead of milliseconds,
which matters on gateways and exit nodes where much traffic is forwarded and
has no local socket. For the receiving side
of a connection not yet accepted, the listening socket identifies the server.
Later events of the same connection (TLS, end, timeout) reuse the result.

A process running as another (non-root) user keeps `/proc/<pid>/fd` private to
that user, which `CAP_SYS_PTRACE` does not override. For such sockets the
socket table's owner uid is matched against the pod's processes: if every
process of that uid in the namespace has the same container and command, those
are recorded with PID 0 ("PID not readable"); otherwise the connection stays
unattributed. Adding `CAP_DAC_READ_SEARCH` would make those descriptors
readable and record exact PIDs, at the cost of letting the collector read any
file it can reach through `/host/proc`.

All `/proc` reads happen on one background worker within a CPU-time budget,
so packet capture never waits for it; lookups beyond the budget are skipped
and counted as `over_budget`. `--process-budget` sets it in CPU time per
second (default `30ms`, about 3% of one core, with bursts of twice that): two
thirds for pod lookups and process snapshots, one third for host processes.
Raise it where `over_budget` stays high and the node has CPU to spare. Reading a TCP socket table walks the kernel's
node-wide connection hash whichever namespace it is for (about 1 ms even when
nearly empty), so one read serves every lookup for that namespace queued
before it started. Endpoints that cannot match (kernel tunnels such as VXLAN,
ports with no listener) are skipped for a minute.

Every 30 seconds the collector logs `Process attribution` with its counters
(`attempted`, `matched`, `by_owner`, `inherited`, `no_socket`, `no_owner`,
`known_miss`, `deadline_hit`, `over_budget`, `expired`, `tables_read`,
`tables_reused`, `socket_queries`, `lookup_ms`, `snapshot_ms`) and up to four example misses
with their reason.

Connections stay unattributed when the socket closed before the lookup ran,
when neither end runs on a node with a collector, or during bursts beyond the
budget. The Processes page shows the attributed share of connections. Remove
the flag, capability and mount to disable it.

## Pod attribution

Every event records the Kubernetes identity of its source and destination *at
capture time* in indexed columns (`src_*`/`dst_*`: kind, namespace, name, UID,
workload as `Kind/name` of the top-level owner, and attribution confidence), in
addition to the JSON context snapshot.

Collectors keep a history of which pod held each address. A pod's assignment
starts at its creation timestamp (an address cannot predate its pod) and ends
when its deletion or terminal phase is observed. Completed and failed pods keep
`status.podIP` in the API although the address is already released, so they
never claim it. With the `watch` permission on pods, a watch stream updates the
history within about a second; the 30-second full list remains as a safety net
and cannot undo or resurrect what the watch has seen. Ended assignments are kept
for 15 minutes so buffered events are still attributed correctly.

| Attribution | Meaning |
| --- | --- |
| `exact` | One pod held the address at capture time and the inventory was current. |
| `ambiguous` | The address changed hands near capture time. The newest pod is recorded; the JSON context lists the alternatives. |
| `stale` | Best candidate, but the inventory had not refreshed for over 90 seconds. |
| `node` | A node or host-network address. The pod cannot be determined from the address. |
| `service` | A Service virtual IP; the backend is not determined. |
| empty | Not a known cluster address. Events from before this change have empty columns (shown as `legacy` in the API when only JSON context exists). |

A collector's own interface addresses are attributed to its node (`node`) even
when Kubernetes does not list them: node objects carry internal IPs, not
temporary public IPv6 or Wi-Fi addresses. The collector re-reads its addresses
every 30 seconds, so a node's own connections over its public address show as
`node` rather than as internet-to-internet traffic.

If the watch is unavailable (missing RBAC, API errors), collector health reports
`pod watch disconnected` and attribution falls back to the list interval, where
reuse within those 30 seconds is reported as `ambiguous` rather than guessed.

### Tailscale exit nodes and subnet routers

A Tailscale interface carries only tunnel traffic, decrypted. When a remote
tailnet device (100.64.0.0/10 or fd7a:115c:a1e0::/48, not one of the node's own
addresses) exchanges packets there with an address that is neither a tailnet
device nor the node, the node is forwarding for that device. Events record the
classification in `route`:

| `route` | Meaning |
| --- | --- |
| `exit-node` | The node is the device's exit node: the other end is a public address. |
| `subnet-router` | The node routes the device into a private network it advertises. |
| `via-tailnet` | The node's own traffic leaves through the tailnet, toward another device's exit node or subnet route. |

`tailnet_peer` is the device's tailnet address and `tailnet_peer_name` its
MagicDNS name at capture time. Names are looked up in the background through
Tailscale's resolver on the node (`100.100.100.100`, reverse lookup; IPv6
addresses fall back to matching the forward records of devices already named)
and cached for an hour, ten minutes after a failure. Packets never wait for a
lookup, so a device's first events may carry only its address. Failed lookups
are logged at most every ten minutes. Some Tailscale versions answer reverse
lookups only for IPv4 addresses, and MagicDNS may serve no AAAA records; IPv6
addresses of devices then keep only the address.

The forwarded copy on the uplink (after the node's NAT) is a separate event
with the node's address as source; linking the two requires conntrack and is
not done. DNS queries the device sends to a public resolver appear as ordinary
`DNS` events with `route=exit-node`; queries answered by MagicDNS on the device
itself never reach the node.

### Filtering events

`GET /api/events` accepts, besides `from`, `to`, `limit`, `cursor`, `eventType`,
`srcIP`, `dstIP` (substring) and `q` (substring over addresses, names, DNS, SNI,
processes and tailnet peers):

| Parameter | Matches |
| --- | --- |
| `collector` | Node that captured the packet. |
| `iface` | Exact interface name. |
| `ifaceRole` | `pod`, `uplink`, `wifi`, `tailscale`, `overlay`, `cluster-host`, `bridge`, `wireguard`, `tunnel`, `loopback` (by interface name pattern). |
| `ipVersion` | `4` or `6`. |
| `withProcess` | `yes` or `no`: whether a process was identified. |
| `srcKind`, `dstKind` | `pod`, `node`, `service`, `endpoint`, or `none` for addresses outside the cluster. |
| `namespace` | Kubernetes namespace of either end. |
| `port` | Source or destination port. |
| `route` | `exit-node`, `subnet-router`, `via-tailnet`, or `any`. |
| `process`, `processPod`, `processContainer` | One exact process identity (with `collector`). |

Invalid values are rejected with 400. A process or a single route walks a
partial index of only those events, so rare matches return quickly over long
windows. In the UI, every tag in an event row (interface type, IP version, node,
process, namespace, kind, route) applies its filter when selected.

### Inspecting a pod

- `GET /api/pods?namespace=&from=&to=` lists pods observed in the window (default
  24 h), with egress/ingress counts, uncertain attributions, and a `replacement`
  flag when another pod with the same name appears in the window.
- `GET /api/pod-connections?uid=<pod UID>` (or `namespace=&workload=Deployment/api`
  for all replicas and restarts) returns connections for the window (default 1 h,
  at most 7 days), `direction=egress|ingress|both`, `limit` up to 1000 and a
  `cursor` for the next page. Filters are applied before the limit. Rows include
  the peer's capture-time identity, DNS evidence with TTL when an answer matched,
  capture source (collector and interface), and GAP totals overlapping the window.
  `verdict` is always `unknown`: a captured packet is an observation, not proof
  that a policy allowed or denied it.
