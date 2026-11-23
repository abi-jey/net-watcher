import { useMemo, useState } from 'react';
import { ApiError, url, type PodSummary, type PodsResponse, type PodsWarming } from '../lib/api.ts';
import { href, setQuery, useResource } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { bytes, count, dateTime, time } from '../lib/format.ts';
import { Badge, Banner, Empty, ErrorBanner, Spinner, Stat, UpdatedAt, WindowSelect } from '../components/ui.tsx';

export function Pods({ query }: { query: URLSearchParams }) {
  const window = query.get('w') ?? '24h';
  const [filter, setFilter] = useState(query.get('f') ?? '');
  const pods = useResource<PodsResponse>(`pods:${window}`, 60_000, () => url('/api/pods', windowRange(window)));
  const warming = pods.error instanceof ApiError && pods.error.status === 503 ? (pods.error.body as PodsWarming) : undefined;

  const groups = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const map = new Map<string, PodSummary[]>();
    for (const pod of pods.data?.pods ?? []) {
      if (needle && ![pod.namespace, pod.name, pod.workload, pod.uid].some(value => value.toLowerCase().includes(needle))) continue;
      map.set(pod.namespace, [...(map.get(pod.namespace) ?? []), pod]);
    }
    for (const items of map.values()) items.sort((a, b) => (b.egressBytes + b.ingressBytes) - (a.egressBytes + a.ingressBytes) || a.name.localeCompare(b.name));
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [pods.data, filter]);
  const totals = useMemo(() => {
    const sum = { pods: 0, egress: 0, ingress: 0, egressBytes: 0, ingressBytes: 0 };
    for (const [, items] of groups) for (const pod of items) {
      sum.pods++; sum.egress += pod.egress; sum.ingress += pod.ingress; sum.egressBytes += pod.egressBytes; sum.ingressBytes += pod.ingressBytes;
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
          <Stat label="Pods" value={count(totals.pods)} hint={`${groups.length} namespace${groups.length === 1 ? '' : 's'}`} />
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
      {groups.map(([namespace, items]) => (
        <section key={namespace} className="table-wrap ns-group">
          <table className="fixed">
            <colgroup><col style={{ width: '31%' }} /><col style={{ width: '21%' }} /><col style={{ width: '11%' }} /><col style={{ width: '11%' }} /><col style={{ width: '15%' }} /><col style={{ width: '11%' }} /></colgroup>
            <thead><tr>
              <th><span className="ns-title">{namespace}</span> <span className="muted">· {items.length} pod{items.length === 1 ? '' : 's'}</span></th>
              <th>Workload</th>
              <th className="num" title="Connections this pod opened: events where it was the source, and the bytes of those connections in both directions.">Egress</th>
              <th className="num" title="Connections opened to this pod: events where it was the destination, and the bytes of those connections in both directions.">Ingress</th>
              <th>Seen</th><th>Notes</th>
            </tr></thead>
            <tbody>
              {items.map(pod => (
                <tr key={pod.uid} className="clickable" onClick={() => { location.hash = href(['pods', 'uid', pod.uid], { w: window }); }}>
                  <td><a href={href(['pods', 'uid', pod.uid], { w: window })} className="cell-main">{pod.name}</a><div className="cell-sub mono">{pod.uid}</div></td>
                  <td>{pod.workload ? <a href={href(['pods', 'workload', pod.namespace, pod.workload], { w: window })} onClick={event => event.stopPropagation()}>{pod.workload}</a> : <span className="muted">—</span>}</td>
                  <td className="num"><div className="cell-main">{bytes(pod.egressBytes)}</div><div className="cell-sub">{count(pod.egress)} events</div></td>
                  <td className="num"><div className="cell-main">{bytes(pod.ingressBytes)}</div><div className="cell-sub">{count(pod.ingress)} events</div></td>
                  <td className="small">{time(pod.firstSeen)} –<br />{time(pod.lastSeen)}</td>
                  <td><div className="toolbar">
                    {pod.replacement && <Badge tone="info" title="Another pod with the same name was seen in this window (restart or recreation). Each instance is listed separately by UID.">replaced</Badge>}
                    {pod.uncertain > 0 && <Badge tone="warn" title="Events whose attribution was ambiguous (address reuse) or based on stale inventory.">{count(pod.uncertain)} uncertain</Badge>}
                  </div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
    </>
  );
}
