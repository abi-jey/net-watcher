import { useMemo, useState } from 'react';
import { ApiError, url, type PodsWarming, type ProcessesResponse, type ProcessSummary } from '../lib/api.ts';
import { href, setQuery, useResource } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { bytes, count, dateTime, time } from '../lib/format.ts';
import { Badge, Banner, Empty, ErrorBanner, Spinner, Stat, UpdatedAt, WindowSelect } from '../components/ui.tsx';

function percent(part: number, whole: number): string {
  if (!whole) return '—';
  const value = (100 * part) / whole;
  return `${value >= 10 ? Math.round(value) : value.toFixed(1)}%`;
}

function eventsLink(process: ProcessSummary, window: string): string {
  return href(['events'], { w: window, process: process.command, processPod: process.pod, processContainer: process.container, collector: process.collector });
}

export function Processes({ query }: { query: URLSearchParams }) {
  const window = query.get('w') ?? '24h';
  const [filter, setFilter] = useState(query.get('f') ?? '');
  const result = useResource<ProcessesResponse>(`processes:${window}`, 60_000, () => url('/api/processes', windowRange(window)));
  const warming = result.error instanceof ApiError && result.error.status === 503 ? (result.error.body as PodsWarming) : undefined;

  // Grouped by node: a process identity is only meaningful on its node.
  const groups = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const map = new Map<string, ProcessSummary[]>();
    for (const process of result.data?.processes ?? []) {
      if (needle && ![process.command, process.container, process.pod, process.collector].some(value => value.toLowerCase().includes(needle))) continue;
      map.set(process.collector, [...(map.get(process.collector) ?? []), process]);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [result.data, filter]);
  const totals = useMemo(() => {
    const sum = { processes: 0, opened: 0, accepted: 0, openedBytes: 0, acceptedBytes: 0, host: 0 };
    for (const [, items] of groups) for (const process of items) {
      sum.processes++; sum.opened += process.opened; sum.accepted += process.accepted;
      sum.openedBytes += process.openedBytes; sum.acceptedBytes += process.acceptedBytes;
      if (!process.pod) sum.host++;
    }
    return sum;
  }, [groups]);
  const coverage = result.data?.coverage;

  return (
    <>
      <div className="page-header">
        <div><h1>Processes</h1><p>Programs on each node that opened or accepted connections, identified by the socket each flow used</p></div>
        <div className="toolbar">
          <input aria-label="Filter processes" placeholder="Filter command, container, pod or node" value={filter} onChange={event => setFilter(event.target.value)} style={{ minWidth: 280 }} />
          <WindowSelect value={window} allowed={['1h', '6h', '24h', '7d']} onChange={value => setQuery(['processes'], { w: value, f: filter })} />
          <UpdatedAt at={result.updatedAt} loading={result.loading} />
        </div>
      </div>
      {warming ? (
        <Banner tone="warn" action={window !== '1h' && <button onClick={() => setQuery(['processes'], { w: '1h', f: filter })}>Show last hour</button>}>
          The process summary is being rebuilt ({count(Math.max(0, warming.aggregation.target - warming.aggregation.cursor))} events left). Windows longer than an hour become available when it finishes.
        </Banner>
      ) : <ErrorBanner error={result.error} retry={result.refresh} />}
      {result.data && (
        <div className="grid stats">
          <Stat label="Processes" value={count(totals.processes)} hint={`${count(totals.processes - totals.host)} in pods, ${count(totals.host)} on hosts`} />
          <Stat label="Connections opened" value={count(totals.opened)} hint={`${bytes(totals.openedBytes)} transferred`} />
          <Stat label="Connections accepted" value={count(totals.accepted)} hint={`${bytes(totals.acceptedBytes)} transferred`} />
          <Stat label="Coverage" value={percent(coverage?.attributedFlows ?? 0, coverage?.flowStarts ?? 0)}
            hint={coverage?.since
              ? `${count(coverage.attributedFlows)} of ${count(coverage.flowStarts)} connections since ${result.data.granularity === 'hour' ? time(coverage.since.slice(0, 13) + ':00:00Z') : time(coverage.since)}`
              : 'no attributed connections in this window'} />
        </div>
      )}
      <details className="card explain">
        <summary>How processes are found, and why some connections have none</summary>
        <p>
          When a connection starts, the collector on that node looks up its socket in the network namespace of the pod (or host) it belongs to, then finds which process holds that socket.
          It reads the host's process table read-only; nothing is traced or modified. Later events of the same connection reuse the result.
          <b> Opened</b> means the process held the source socket; <b>accepted</b> means it held the destination socket, such as a server's listener.
          Bytes count both directions of a connection and are recorded when it ends.
        </p>
        <p>Connections may have no process when:</p>
        <ul>
          <li>the socket was already closed when the lookup ran (very short connections),</li>
          <li>neither end is on a node with a collector, or the traffic is only forwarded through the node,</li>
          <li>the collector's lookup budget (about 3% of one CPU) was spent during a burst,</li>
          <li>the traffic was captured before process attribution was enabled.</li>
        </ul>
        <p className="muted small">The kernel's command name (up to 15 characters) is recorded, never command-line arguments. A process is identified by node, pod, container and command, so restarts with new PIDs stay one row.</p>
      </details>
      {result.data?.granularity === 'hour' && <p className="muted small">Totals cover whole hours from {dateTime(result.data.from)} to {dateTime(result.data.to)}.</p>}
      {result.data?.truncated && <Banner tone="warn">Only the 2,000 busiest processes are listed. Narrow the window.</Banner>}
      {result.loading && !result.data && !warming && <Spinner />}
      {result.data && !groups.length && (
        <Empty>{filter ? 'No processes match this filter.' : 'No connections were attributed to a process in this window. Collectors need process attribution enabled and CAP_SYS_PTRACE (see the deployment notes).'}</Empty>
      )}
      {groups.map(([collector, items]) => (
        <section key={collector} className="table-wrap ns-group">
          <table className="fixed">
            <colgroup><col style={{ width: '24%' }} /><col style={{ width: '30%' }} /><col style={{ width: '13%' }} /><col style={{ width: '13%' }} /><col style={{ width: '20%' }} /></colgroup>
            <thead><tr>
              <th><span className="ns-title">{collector || 'local'}</span> <span className="muted">· {items.length} process{items.length === 1 ? '' : 'es'}</span></th>
              <th>Runs in</th>
              <th className="num" title="Connections this process started (it owned the source socket), and their bytes in both directions.">Opened</th>
              <th className="num" title="Connections this process received (it owned the destination socket), and their bytes in both directions.">Accepted</th>
              <th>Seen</th>
            </tr></thead>
            <tbody>
              {items.map(process => {
                const link = eventsLink(process, window);
                return (
                  <tr key={`${process.pod}|${process.container}|${process.command}`} className="clickable" onClick={() => { location.hash = link; }}>
                    <td><a href={link} className="cell-main mono">{process.command || 'unknown'}</a>{process.container && <div className="cell-sub">container {process.container}</div>}</td>
                    <td>
                      {process.pod
                        ? <><Badge tone="info">pod</Badge> <span className="cell-main">{process.pod.slice(process.namespace.length + 1)}</span><div className="cell-sub">namespace {process.namespace}</div></>
                        : <><Badge tone="muted">host</Badge> <span className="muted small">node process outside any pod</span></>}
                    </td>
                    <td className="num">{process.opened ? <><div className="cell-main">{count(process.opened)}</div><div className="cell-sub">{bytes(process.openedBytes)}</div></> : <span className="muted">—</span>}</td>
                    <td className="num">{process.accepted ? <><div className="cell-main">{count(process.accepted)}</div><div className="cell-sub">{bytes(process.acceptedBytes)}</div></> : <span className="muted">—</span>}</td>
                    <td className="small">{time(process.firstSeen)} –<br />{time(process.lastSeen)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      ))}
    </>
  );
}
