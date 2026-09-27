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

Build and push an image first. The manifest uses
`ghcr.io/abi-jey/net-watcher:map-k8s`; change that tag to an immutable image
digest before applying it in a durable environment.

```bash
docker build -t ghcr.io/abi-jey/net-watcher:map-k8s .
docker push ghcr.io/abi-jey/net-watcher:map-k8s
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
10 minutes it removes acknowledged events and expired, unreferenced DNS
evidence, then reclaims unused disk pages. Pending events are never discarded
to meet the central size limit; a collector can grow while ingestion is
unavailable. The forwarder drains acknowledged batches immediately when behind,
and checks again after two seconds when idle or retrying a failure. The central
map may represent duplicate observations captured on multiple node interfaces.
The forwarder sends up to 250 events per request, splitting batches that would
exceed the 5 MiB request limit. The ingester looks up retry keys in indexed
groups and inserts new events and DNS evidence in bounded SQL batches inside a
transaction; the collector cursor advances only after the transaction is
acknowledged. Retry deduplication does not attempt to merge distinct capture
observations.

SQLite WAL keeps the single ingestion writer and the web query pool separate.
The web pool is read-only and limited to two connections, so slow filtering and
analytics cannot occupy the writer connection. Frequently requested statistics
are cached for 5 seconds, and Top Hosts and timeline responses for 30 seconds.
Other read use cases can use the same read-only query path; long-range queries
should eventually use pre-aggregated views instead of repeatedly scanning raw
events. The example ingester is capped at 1.5 CPU cores and 512 MiB memory.

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
