import { useMemo, useState } from 'react';
import { ApiError, url, type PodSummary, type PodsResponse, type PodsWarming } from '../lib/api.ts';
import { href, setQuery, useResource } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { count, dateTime, time } from '../lib/format.ts';
import { Badge, Banner, Empty, ErrorBanner, Spinner, UpdatedAt, WindowSelect } from '../components/ui.tsx';

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
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [pods.data, filter]);

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
          The pod summary is still being built ({count(warming.aggregation.cursor)} of {count(warming.aggregation.target)}). Windows longer than an hour become available when it finishes.
        </Banner>
      ) : <ErrorBanner error={pods.error} retry={pods.refresh} />}
      {pods.data?.granularity === 'hour' && <p className="muted small">Counts cover whole hours from {dateTime(pods.data.from)} to {dateTime(pods.data.to)}.</p>}
      {pods.data?.truncated && <Banner tone="warn">Only the first 2,000 pods are listed. Narrow the window or filter by namespace.</Banner>}
      {pods.loading && !pods.data && !warming && <Spinner />}
      {pods.data && !groups.length && <Empty>No pods {filter ? 'match this filter' : 'were attributed in this window'}. Traffic captured before pod attribution was enabled appears only in Events.</Empty>}
      {groups.map(([namespace, items]) => (
        <section key={namespace} className="table-wrap">
          <table>
            <thead><tr><th style={{ width: '32%' }}>{namespace}</th><th>Workload</th><th className="num">Egress</th><th className="num">Ingress</th><th>Seen</th><th>Notes</th></tr></thead>
            <tbody>
              {items.map(pod => (
                <tr key={pod.uid} className="clickable" onClick={() => { location.hash = href(['pods', 'uid', pod.uid], { w: window }); }}>
                  <td><a href={href(['pods', 'uid', pod.uid], { w: window })} className="cell-main">{pod.name}</a><div className="cell-sub mono">{pod.uid}</div></td>
                  <td>{pod.workload ? <a href={href(['pods', 'workload', pod.namespace, pod.workload], { w: window })} onClick={event => event.stopPropagation()}>{pod.workload}</a> : <span className="muted">—</span>}</td>
                  <td className="num">{count(pod.egress)}</td>
                  <td className="num">{count(pod.ingress)}</td>
                  <td className="nowrap small">{time(pod.firstSeen)} – {time(pod.lastSeen)}</td>
                  <td className="toolbar">
                    {pod.replacement && <Badge tone="info" title="Another pod with the same name was seen in this window (restart or recreation). Each instance is listed separately by UID.">replaced</Badge>}
                    {pod.uncertain > 0 && <Badge tone="warn" title="Events whose attribution was ambiguous (address reuse) or based on stale inventory.">{count(pod.uncertain)} uncertain</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
    </>
  );
}
