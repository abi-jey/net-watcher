import { useEffect, useMemo, useRef, useState } from 'react';
import { getJSON, url, type PodConnection, type PodConnectionsResponse } from '../lib/api.ts';
import { href, setQuery } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { bytes, count, dateTime, endpoint, time } from '../lib/format.ts';
import { Attribution, Badge, Banner, Card, Empty, ErrorBanner, Segmented, Spinner, WindowSelect } from '../components/ui.tsx';

type Direction = 'both' | 'egress' | 'ingress';

function peerLabel(connection: PodConnection): string {
  const peer = connection.peer;
  if (peer.kind === 'pod') return `${peer.namespace}/${peer.name}`;
  if (peer.kind) return `${peer.kind} ${peer.name || peer.ip}`;
  return connection.hostname || connection.tlsSni || peer.ip;
}

export function PodInspector({ path, query }: { path: string[]; query: URLSearchParams }) {
  const [mode, ...selector] = path;
  const byUID = mode === 'uid';
  const window = query.get('w') ?? '1h';
  const direction = (query.get('dir') as Direction) ?? 'both';
  const [rows, setRows] = useState<PodConnection[]>([]);
  const [page, setPage] = useState<PodConnectionsResponse>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error>();
  const [selected, setSelected] = useState<number>();
  const range = useRef(windowRange(window));
  const controller = useRef<AbortController>(undefined);
  const params = byUID ? { uid: selector[0] } : { namespace: selector[0], workload: selector[1] };
  const key = `${path.join('/')}|${window}|${direction}`;

  const load = async (cursor?: string) => {
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    setLoading(true);
    setError(undefined);
    try {
      const result = await getJSON<PodConnectionsResponse>(url('/api/pod-connections', { ...params, ...range.current, direction, limit: 500, cursor }), abort.signal);
      setPage(result);
      const received = result.connections ?? [];
      setRows(previous => cursor ? [...previous, ...received] : received);
    } catch (failure) {
      if (!abort.signal.aborted) setError(failure as Error);
    } finally {
      if (!abort.signal.aborted) setLoading(false);
    }
  };

  useEffect(() => {
    range.current = windowRange(window);
    setRows([]);
    setPage(undefined);
    setSelected(undefined);
    void load();
    return () => controller.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const peers = useMemo(() => {
    const map = new Map<string, { label: string; ports: Set<string>; events: number; directions: Set<string>; evidence: Set<string>; attribution: string }>();
    for (const row of rows) {
      const label = peerLabel(row);
      const entry = map.get(label) ?? { label, ports: new Set(), events: 0, directions: new Set(), evidence: new Set(), attribution: row.peer.attribution };
      entry.events++;
      entry.ports.add(`${row.protocol}/${row.peer.port || row.pod.port}`);
      entry.directions.add(row.direction);
      (row.dnsEvidence ?? []).forEach(evidence => entry.evidence.add(evidence.name));
      map.set(label, entry);
    }
    return [...map.values()].sort((a, b) => b.events - a.events);
  }, [rows]);

  const subject = rows[0]?.pod;
  const title = byUID ? (subject?.name ? `${subject.namespace}/${subject.name}` : selector[0]) : `${selector[0]}/${selector[1]}`;
  const navigate = (next: Record<string, string>) => setQuery(['pods', ...path], { w: window, dir: direction, ...next });
  const lost = (page?.gaps ?? []).reduce((total, gap) => total + gap.lost, 0);

  return (
    <>
      <div className="page-header">
        <div>
          <a href="#/pods" className="small">← Pods</a>
          <h1>{title}</h1>
          <p>
            {byUID ? <>Pod instance <span className="mono">{selector[0]}</span>{subject?.workload && <> · <a href={href(['pods', 'workload', subject.namespace ?? '', subject.workload], { w: window, dir: direction })}>all of {subject.workload}</a></>}</>
              : 'All replicas and restarts of this workload'}
          </p>
        </div>
        <div className="toolbar">
          <Segmented<Direction> label="Direction" value={direction} onChange={value => navigate({ dir: value })} options={[{ value: 'both', label: 'Both' }, { value: 'egress', label: 'Outbound' }, { value: 'ingress', label: 'Inbound' }]} />
          <WindowSelect value={window} onChange={value => navigate({ w: value })} />
        </div>
      </div>
      <ErrorBanner error={error} retry={() => void load()} />
      {lost > 0 && (
        <Banner tone="warn">
          Known loss overlaps this window: {page!.gaps!.map(gap => `${count(gap.lost)} on ${gap.collectorId} (${gap.reason})`).join(', ')}. Connections during those periods may be missing.
        </Banner>
      )}
      {page?.notes?.map(note => <Banner key={note}>{note}</Banner>)}
      <Card title={`Peers (${peers.length})`} actions={<span className="muted small">from {rows.length.toLocaleString()} loaded observations</span>}>
        {peers.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Peer</th><th>Ports</th><th>Direction</th><th>DNS evidence</th><th className="num">Observations</th></tr></thead>
              <tbody>
                {peers.slice(0, 50).map(peer => (
                  <tr key={peer.label}>
                    <td><span className="cell-main">{peer.label}</span> <Attribution value={peer.attribution} /></td>
                    <td className="mono small">{[...peer.ports].slice(0, 6).join(', ')}</td>
                    <td>{[...peer.directions].map(item => <Badge key={item} tone={item === 'egress' ? 'info' : 'muted'}>{item === 'egress' ? 'outbound' : 'inbound'}</Badge>)}</td>
                    <td className="small">{peer.evidence.size ? [...peer.evidence].slice(0, 3).join(', ') : <span className="muted">none matched</span>}</td>
                    <td className="num">{count(peer.events)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : loading ? <Spinner /> : <Empty>No connections in this window.</Empty>}
      </Card>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Direction</th><th>Peer</th><th>Protocol</th><th>Name / evidence</th><th>Verdict</th><th>Captured by</th></tr></thead>
          <tbody>
            {rows.map(row => (
              <ConnectionRow key={row.id} row={row} expanded={selected === row.id} onToggle={() => setSelected(current => current === row.id ? undefined : row.id)} />
            ))}
          </tbody>
        </table>
        {loading && !rows.length && <Empty><Spinner /> Loading connections…</Empty>}
        <div className="table-foot">
          <span className="muted small">{rows.length.toLocaleString()} observations{page && ` · ${dateTime(page.from)} – ${dateTime(page.to)}`}</span>
          {page?.nextCursor && <button onClick={() => void load(page.nextCursor)} disabled={loading}>{loading ? 'Loading…' : 'Load older'}</button>}
        </div>
      </div>
    </>
  );
}

function ConnectionRow({ row, expanded, onToggle }: { row: PodConnection; expanded: boolean; onToggle: () => void }) {
  const evidence = row.dnsEvidence ?? [];
  const names = evidence.map(item => item.name);
  return (
    <>
      <tr className={`clickable ${expanded ? 'selected' : ''}`} onClick={onToggle} tabIndex={0} aria-expanded={expanded} onKeyDown={key => { if (key.key === 'Enter') onToggle(); }}>
        <td className="nowrap mono small" title={dateTime(row.timestamp)}>{time(row.timestamp)}</td>
        <td><Badge tone={row.direction === 'egress' ? 'info' : 'muted'}>{row.direction === 'egress' ? '→ out' : '← in'}</Badge></td>
        <td><div className="cell-main">{peerLabel(row)} <Attribution value={row.peer.attribution} /></div><div className="cell-sub mono">{endpoint(row.peer.ip, row.peer.port)}</div></td>
        <td className="small">{row.protocol} · {row.eventType}</td>
        <td className="small">{names.length ? names.join(', ') : row.tlsSni || row.hostname || row.dnsQuery || <span className="muted">no DNS evidence</span>}{row.dnsEvidenceMissing ? <Badge tone="warn"> {row.dnsEvidenceMissing} missing</Badge> : null}</td>
        <td><Badge tone="muted" title="A captured packet is an observation; it does not show whether a policy allowed or denied it.">{row.verdict}</Badge></td>
        <td className="cell-sub nowrap">{row.collectorId || 'local'} · {row.interface}</td>
      </tr>
      {expanded && (
        <tr><td colSpan={7} className="details">
          <div className="grid two">
            <dl className="kv">
              <dt>Pod</dt><dd>{row.pod.namespace}/{row.pod.name} <span className="mono small">{row.pod.uid}</span> <Attribution value={row.pod.attribution} /></dd>
              <dt>Pod address</dt><dd className="mono">{endpoint(row.pod.ip, row.pod.port)}</dd>
              <dt>Peer</dt><dd>{row.peer.kind ? `${row.peer.kind} ${row.peer.namespace ? `${row.peer.namespace}/` : ''}${row.peer.name ?? ''}` : 'not a known cluster address'} {row.peer.workload && `· ${row.peer.workload}`}</dd>
              <dt>Peer address</dt><dd className="mono">{endpoint(row.peer.ip, row.peer.port)}</dd>
              {row.processCommand && <><dt>Process</dt><dd className="mono">{row.processCommand}</dd></>}
              {row.byteCount ? <><dt>Bytes</dt><dd>{bytes(row.byteCount)}</dd></> : null}
              {row.tlsSni && <><dt>TLS SNI</dt><dd>{row.tlsSni}</dd></>}
              <dt>Observation</dt><dd>#{row.id} · {dateTime(row.timestamp)}</dd>
            </dl>
            <div className="evidence">
              <h3>DNS evidence</h3>
              {evidence.length ? evidence.map(evidence => (
                <dl className="kv" key={evidence.id}>
                  <dt>Name</dt><dd>{evidence.name}</dd>
                  <dt>Resolver</dt><dd className="mono">{evidence.resolver}</dd>
                  <dt>Answered</dt><dd>{dateTime(evidence.responseTime)}</dd>
                  <dt>TTL</dt><dd>{evidence.ttl} s (valid until {dateTime(evidence.expiresAt)})</dd>
                </dl>
              )) : <p className="muted small">No DNS answer matching this address was observed for this client within its TTL. That does not prove the application used a literal IP.</p>}
            </div>
          </div>
        </td></tr>
      )}
    </>
  );
}
