import { useMemo, useState } from 'react';
import { ApiError, url, type PodSummary, type PodsResponse, type PodsWarming } from '../lib/api.ts';
import { rollupPods, splitWorkload, type WorkloadRow } from '../lib/rollup.ts';
import { href, setQuery, useResource } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { bytes, count, dateTime, time } from '../lib/format.ts';
import { Badge, Banner, Empty, ErrorBanner, Spinner, Stat, UpdatedAt, WindowSelect } from '../components/ui.tsx';

export function Pods({ query }: { query: URLSearchParams }) {
  const window = query.get('w') ?? '24h';
  const [filter, setFilter] = useState(query.get('f') ?? '');
  const pods = useResource<PodsResponse>(`pods:${window}`, 60_000, () => url('/api/pods', windowRange(window)));
  const warming = pods.error instanceof ApiError && pods.error.status === 503 ? (pods.error.body as PodsWarming) : undefined;

  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const toggle = (key: string) => setExpanded(previous => {
    const next = new Set(previous);
    if (!next.delete(key)) next.add(key);
    return next;
  });

  // One row per workload: rollouts and restarts would otherwise list every pod.
  const groups = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const matching = (pods.data?.pods ?? []).filter(pod => !needle || [pod.namespace, pod.name, pod.workload, pod.uid].some(value => value.toLowerCase().includes(needle)));
    return [...rollupPods(matching).entries()];
  }, [pods.data, filter]);
  const totals = useMemo(() => {
    const sum = { pods: 0, workloads: 0, egress: 0, ingress: 0, egressBytes: 0, ingressBytes: 0 };
    for (const [, rows] of groups) for (const row of rows) {
      sum.workloads++; sum.pods += row.pods.length;
      sum.egress += row.egress; sum.ingress += row.ingress; sum.egressBytes += row.egressBytes; sum.ingressBytes += row.ingressBytes;
    }
    return sum;
  }, [groups]);

  return (
    <>
      <div className="page-header">
        <div><h1>Pods</h1><p>Pods seen sending or receiving traffic, attributed at capture time</p></div>
        <div className="toolbar">
          <input aria-label="Filter pods" placeholder="Filter namespace, pod, workload or UID" value={filter} onChange={event => setFilter(event.target.value)} style={{ minWidth: 280 }} />
          <WindowSelect value={window} allowed={['1h', '6h', '24h', '7d']} onChange={value => setQuery(['pods'], { w: value, f: filter })} />
          <UpdatedAt at={pods.updatedAt} loading={pods.loading} />
        </div>
      </div>
      {warming ? (
        <Banner tone="warn" action={window !== '1h' && <button onClick={() => setQuery(['pods'], { w: '1h', f: filter })}>Show last hour</button>}>
          The pod summary is still being built ({count(Math.max(0, warming.aggregation.target - warming.aggregation.cursor))} events left). Windows longer than an hour become available when it finishes.
        </Banner>
      ) : <ErrorBanner error={pods.error} retry={pods.refresh} />}
      {pods.data && totals.pods > 0 && (
        <div className="grid stats">
          <Stat label="Workloads" value={count(totals.workloads)} hint={`${count(totals.pods)} pod${totals.pods === 1 ? '' : 's'} in ${groups.length} namespace${groups.length === 1 ? '' : 's'}`} />
          <Stat label="Egress traffic" value={bytes(totals.egressBytes)} hint={`${count(totals.egress)} events from pods`} />
          <Stat label="Ingress traffic" value={bytes(totals.ingressBytes)} hint={`${count(totals.ingress)} events to pods`} />
        </div>
      )}
      <p className="muted small">
        Egress is traffic of connections a pod opened; ingress is traffic of connections opened to it. Bytes count both directions of each connection and are recorded when the connection ends, so connections still open are not yet included.
        {pods.data?.granularity === 'hour' && <> Totals cover whole hours from {dateTime(pods.data.from)} to {dateTime(pods.data.to)}.</>}
      </p>
      {pods.data?.truncated && <Banner tone="warn">Only the first 2,000 pods are listed. Narrow the window or filter by namespace.</Banner>}
      {pods.loading && !pods.data && !warming && <Spinner />}
      {pods.data && !groups.length && <Empty>No pods {filter ? 'match this filter' : 'were attributed in this window'}. Traffic captured before pod attribution was enabled appears only in Events.</Empty>}
      {groups.map(([namespace, rows]) => (
        <section key={namespace} className="table-wrap ns-group">
          <table className="fixed">
            <colgroup><col style={{ width: '27%' }} /><col style={{ width: '25%' }} /><col style={{ width: '11%' }} /><col style={{ width: '11%' }} /><col style={{ width: '15%' }} /><col style={{ width: '11%' }} /></colgroup>
            <thead><tr>
              <th><span className="ns-title">{namespace}</span> <span className="muted">· {rows.length} workload{rows.length === 1 ? '' : 's'}</span></th>
              <th>Pods</th>
              <th className="num" title="Connections the pods opened: events where they were the source, and the bytes of those connections in both directions.">Egress</th>
              <th className="num" title="Connections opened to the pods: events where they were the destination, and the bytes of those connections in both directions.">Ingress</th>
              <th>Seen</th><th>Notes</th>
            </tr></thead>
            <tbody>
              {rows.map(row => {
                // A filter that matched pods rather than the workload shows them; the toggle still works.
                const needle = filter.trim().toLowerCase();
                const matchedPods = Boolean(needle) && ![row.namespace, row.workload].some(value => value.toLowerCase().includes(needle));
                return <Workload key={row.key} row={row} window={window} open={matchedPods !== expanded.has(row.key)} onToggle={() => toggle(row.key)} />;
              })}
            </tbody>
          </table>
        </section>
      ))}
    </>
  );
}

function Traffic({ item }: { item: { egress: number; ingress: number; egressBytes: number; ingressBytes: number; firstSeen: string; lastSeen: string } }) {
  return (
    <>
      <td className="num"><div className="cell-main">{bytes(item.egressBytes)}</div><div className="cell-sub">{count(item.egress)} events</div></td>
      <td className="num"><div className="cell-main">{bytes(item.ingressBytes)}</div><div className="cell-sub">{count(item.ingress)} events</div></td>
      <td className="small">{time(item.firstSeen)} –<br />{time(item.lastSeen)}</td>
    </>
  );
}

function Notes({ uncertain, replacement }: { uncertain: number; replacement?: boolean }) {
  return (
    <td><div className="toolbar">
      {replacement && <Badge tone="info" title="Another pod with the same name was seen in this window (restart or recreation). Each instance is listed separately by UID.">replaced</Badge>}
      {uncertain > 0 && <Badge tone="warn" title="Events whose attribution was ambiguous (address reuse) or based on stale inventory.">{count(uncertain)} uncertain</Badge>}
    </div></td>
  );
}

function Workload({ row, window, open, onToggle }: { row: WorkloadRow; window: string; open: boolean; onToggle: () => void }) {
  const { kind, name } = splitWorkload(row.workload);
  const podLink = (pod: PodSummary) => href(['pods', 'uid', pod.uid], { w: window });
  const target = row.workload ? href(['pods', 'workload', row.namespace, row.workload], { w: window }) : podLink(row.pods[0]);
  const single = row.pods.length === 1 ? row.pods[0] : undefined;
  return (
    <>
      <tr className="clickable" onClick={() => { location.hash = target; }}>
        <td>
          <a href={target} className="cell-main">{row.workload ? name : row.pods[0].name}</a>
          <div className="cell-sub">{row.workload ? kind : 'pod without an owner'}</div>
        </td>
        <td>
          {single
            ? <><a href={podLink(single)} onClick={event => event.stopPropagation()}>{single.name}</a><div className="cell-sub mono">{single.uid}</div></>
            : <>
              <button className="link small" aria-expanded={open} onClick={event => { event.stopPropagation(); onToggle(); }}>
                <span className={`disclosure ${open ? 'open' : ''}`} aria-hidden="true">▸</span> {row.pods.length} pods
              </button>
              <div className="cell-sub">newest {row.pods[0].name}</div>
            </>}
        </td>
        <Traffic item={row} />
        <Notes uncertain={row.uncertain} replacement={single?.replacement} />
      </tr>
      {open && !single && row.pods.map(pod => (
        <tr key={pod.uid} className="clickable sub-row" onClick={() => { location.hash = podLink(pod); }}>
          <td />
          <td><a href={podLink(pod)}>{pod.name}</a><div className="cell-sub mono">{pod.uid}</div></td>
          <Traffic item={pod} />
          <Notes uncertain={pod.uncertain} replacement={pod.replacement} />
        </tr>
      ))}
    </>
  );
}
