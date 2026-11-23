import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { url, type DNSResolution, type MapLink, type MapNode, type NetworkMap as MapData } from '../lib/api.ts';
import { useResource } from '../lib/hooks.ts';
import { bytes, count, dateTime } from '../lib/format.ts';
import { evidenceLabel, fit, layout, nodeHeight, nodeWidth, short, type Point } from '../lib/topology.ts';
import { Banner, Card, Empty, ErrorBanner, Spinner, UpdatedAt } from '../components/ui.tsx';

const ownership = (node?: MapNode) => !node ? 'Unknown' : node.Kind === 'dns' ? 'DNS evidence' : node.Ownership === 'ours' ? `Ours · ${node.Scope}` : `${node.Scope} · unattributed`;

export function NetworkMap() {
  const [since, setSince] = useState('1h');
  const [namespace, setNamespace] = useState('');
  const [ip, setIP] = useState('');
  const [ipDraft, setIPDraft] = useState('');
  const [live, setLive] = useState(true);
  const [selection, setSelection] = useState('');
  const [positions, setPositions] = useState<Record<string, Point>>({});
  const [view, setView] = useState({ x: 0, y: 0, scale: 0.8 });
  const svg = useRef<SVGSVGElement>(null);
  const drag = useRef<{ id: string; x: number; y: number; view: typeof view; position?: Point } | null>(null);
  const fitted = useRef(false);
  // 30 s refresh while visible; the server caches each variant for 15 s.
  const map = useResource<MapData>(url('/api/network-map', { since, namespace, ip }), live ? 30_000 : undefined);
  const data = map.data;

  useEffect(() => { fitted.current = false; }, [since, namespace, ip]);
  useEffect(() => { if (data) setPositions(previous => layout(data.Nodes ?? [], data.Links ?? [], previous)); }, [data]);
  const fitView = () => { const box = svg.current?.getBoundingClientRect(); if (box) setView(fit(positions, box.width, box.height)); };
  useEffect(() => { if (!fitted.current && Object.keys(positions).length && svg.current) { fitView(); fitted.current = true; } }, [positions]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const element = svg.current;
    if (!element) return;
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      const box = element.getBoundingClientRect();
      const x = event.clientX - box.left, y = event.clientY - box.top;
      setView(old => { const scale = Math.max(0.01, Math.min(3, old.scale * Math.exp(-event.deltaY * 0.001))); const ratio = scale / old.scale; return { x: x - (x - old.x) * ratio, y: y - (y - old.y) * ratio, scale }; });
    };
    element.addEventListener('wheel', wheel, { passive: false });
    return () => element.removeEventListener('wheel', wheel);
  }, []);

  const startDrag = (event: ReactPointerEvent, id = '') => {
    if (event.button !== 0) return;
    event.stopPropagation();
    svg.current?.setPointerCapture(event.pointerId);
    drag.current = { id, x: event.clientX, y: event.clientY, view, position: positions[id] };
    if (id) setSelection(id);
  };
  const moveDrag = (event: ReactPointerEvent) => {
    const current = drag.current;
    if (!current) return;
    const dx = event.clientX - current.x, dy = event.clientY - current.y;
    if (current.id && current.position) setPositions(previous => ({ ...previous, [current.id]: { x: current.position!.x + dx / current.view.scale, y: current.position!.y + dy / current.view.scale } }));
    else setView({ ...current.view, x: current.view.x + dx, y: current.view.y + dy });
  };

  const nodes = data?.Nodes ?? [];
  const links = data?.Links ?? [];
  const index = useMemo(() => new Map(nodes.map(node => [node.ID, node])), [nodes]);
  const names = [...new Set([namespace, ...(data?.Namespaces ?? [])].filter(Boolean))].sort();
  const activate = (event: React.KeyboardEvent, id: string) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelection(id); } };

  return (
    <>
      <div className="page-header">
        <div><h1>Network map</h1><p>Observed connections, Kubernetes context and DNS evidence</p></div>
        <UpdatedAt at={map.updatedAt} loading={map.loading} />
      </div>
      <div className="card toolbar">
        <select aria-label="Window" value={since} onChange={event => setSince(event.target.value)}>
          <option value="15m">Last 15 minutes</option><option value="1h">Last hour</option><option value="6h">Last 6 hours</option><option value="24h">Last 24 hours</option>
        </select>
        <select aria-label="Namespace" value={namespace} onChange={event => setNamespace(event.target.value)}>
          <option value="">All namespaces</option>{names.map(name => <option key={name}>{name}</option>)}
        </select>
        <form className="toolbar" onSubmit={event => { event.preventDefault(); setIP(ipDraft.trim()); }}>
          <input aria-label="Filter by IP" placeholder="Filter by IP address" value={ipDraft} onChange={event => setIPDraft(event.target.value)} />
          <button type="submit">Filter</button>
        </form>
        <label className="small"><input type="checkbox" checked={live} onChange={event => setLive(event.target.checked)} /> Auto-refresh</label>
        <button onClick={map.refresh} disabled={map.loading}>Refresh</button>
        <button onClick={fitView}>Fit</button>
        <button onClick={() => { if (data) setPositions(layout(data.Nodes ?? [], data.Links ?? [])); fitted.current = false; }}>Reset layout</button>
      </div>
      <ErrorBanner error={map.error} retry={map.refresh} />
      {data?.Truncated && <Banner tone="warn">This is a bounded sample. Narrow the window, pick a namespace or filter by IP to see more.</Banner>}
      {data?.Kubernetes?.Error && <Banner tone="warn">Kubernetes inventory: {data.Kubernetes.Error}</Banner>}
      <p className="muted small">{count(nodes.length)} nodes · {count(links.length)} relationships · {count(data?.Observations ?? 0)} connection observations</p>
      <div className="map-layout">
        <div className="card" style={{ padding: 8 }}>
          <svg ref={svg} className="map-canvas" role="application" aria-label="Interactive network map" onPointerDown={event => startDrag(event)} onPointerMove={moveDrag} onPointerUp={() => { drag.current = null; }} onPointerCancel={() => { drag.current = null; }}>
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent-work)" /></marker>
            </defs>
            <g transform={`translate(${view.x},${view.y}) scale(${view.scale})`}>
              {links.map(link => {
                const a = positions[link.Source], b = positions[link.Target];
                if (!a || !b) return null;
                const x1 = a.x + nodeWidth, y1 = a.y + nodeHeight / 2, x2 = b.x, y2 = b.y + nodeHeight / 2;
                const bend = Math.max(65, Math.abs(x2 - x1) / 2);
                const path = `M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`;
                const label = link.Kind === 'connection' ? `${link.Protocol} ${link.Port || ''} · ${link.Events}` : link.Kind === 'dns_query' ? 'DNS query' : 'DNS answer';
                return (
                  <g key={link.ID} className={`map-link ${link.Kind} ${selection === link.ID ? 'selected' : ''}`} role="button" tabIndex={0}
                    aria-label={`${label}: ${index.get(link.Source)?.Label} to ${index.get(link.Target)?.Label}`}
                    onKeyDown={event => activate(event, link.ID)} onPointerDown={event => event.stopPropagation()} onClick={() => setSelection(link.ID)}>
                    <path d={path} className="hit" /><path d={path} className="line" markerEnd="url(#arrow)" />
                    <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 8} textAnchor="middle">{label}</text>
                  </g>
                );
              })}
              {nodes.map(node => {
                const p = positions[node.ID];
                if (!p) return null;
                return (
                  <g key={node.ID} transform={`translate(${p.x},${p.y})`} className={`map-node ${node.Kind} ${node.Ownership === 'ours' ? 'owned' : node.Scope} ${selection === node.ID ? 'selected' : ''}`}
                    role="button" tabIndex={0} aria-label={`${node.Kind}: ${node.Label}, ${ownership(node)}`} onKeyDown={event => activate(event, node.ID)} onPointerDown={event => startDrag(event, node.ID)}>
                    <title>{`${node.Label}${node.IP ? ` (${node.IP})` : ''} · ${ownership(node)}`}</title>
                    <rect width={nodeWidth} height={nodeHeight} rx={10} />
                    <text x={14} y={20} className="kind">{`${node.Kind} · ${ownership(node)}`.toUpperCase()}</text>
                    <text x={14} y={43} className="title">{short(node.Label)}</text>
                    <text x={14} y={63} className="address">{node.IP || 'client-scoped DNS observation'}</text>
                  </g>
                );
              })}
            </g>
          </svg>
          {!nodes.length && (map.loading ? <Empty><Spinner /> Loading observations…</Empty> : <Empty>No observations in this window.</Empty>)}
          <div className="legend" style={{ padding: '8px 4px 0' }}>
            <span><span className="dot ok" />Ours (inventory or configured)</span>
            <span><span className="dot" style={{ background: 'var(--accent-work)' }} />Internal · unattributed</span>
            <span><span className="dot" style={{ background: 'var(--editorial)' }} />External · unattributed</span>
            <span>Drag nodes · drag background to pan · scroll to zoom</span>
          </div>
        </div>
        <Inspector selection={selection} data={data} index={index} onClose={() => setSelection('')} />
      </div>
      <p className="muted small">“Ours” means a pod, Service or node identified by Kubernetes inventory, or an address configured as owned. “Internal” includes private, link-local and Tailscale ranges; unattributed does not mean someone else owns them. The map shows capture observations, not firewall verdicts. NAT paths and encrypted DNS are not inferred.</p>
    </>
  );
}

function Inspector({ selection, data, index, onClose }: { selection: string; data?: MapData; index: Map<string, MapNode>; onClose: () => void }) {
  if (!selection || !data) return <Card title="Details"><p className="muted">Select a node or connection to see its endpoints, Kubernetes ownership and DNS evidence.</p></Card>;
  const node = index.get(selection);
  const allLinks = data.Links ?? [];
  const link = allLinks.find(item => item.ID === selection);
  if (!node && !link) return <Card title="Details" actions={<button onClick={onClose}>Clear</button>}><p className="muted">This item is outside the current window.</p></Card>;
  const related: MapLink[] = node ? allLinks.filter(edge => edge.Source === node.ID || edge.Target === node.ID) : [link!];
  const ids = [...new Set(related.flatMap(edge => edge.EvidenceIDs ?? []))];
  return (
    <div className="card inspector" aria-label="Details">
      <header style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
        <h2>{node ? node.Label : link!.Kind === 'connection' ? `${link!.Protocol} connection` : 'DNS relationship'}</h2>
        <button className="ghost" onClick={onClose} aria-label="Close details">✕</button>
      </header>
      {node && (
        <dl className="kv">
          <dt>Kind</dt><dd>{node.Kind}</dd>
          <dt>Address</dt><dd className="mono">{node.IP || 'DNS name'}</dd>
          {node.Kind !== 'dns' && <><dt>Ownership</dt><dd>{ownership(node)}{node.OwnershipSource ? ` (${node.OwnershipSource})` : ''}</dd></>}
          {node.Context?.Namespace && <><dt>Namespace</dt><dd>{node.Context.Namespace}</dd></>}
          {node.Context?.Owner?.Name && <><dt>Workload</dt><dd>{node.Context.Owner.Kind}/{node.Context.Owner.Name}</dd></>}
          {node.Context?.Node && <><dt>Node</dt><dd>{node.Context.Node}</dd></>}
          {node.Context?.UID && <><dt>UID</dt><dd className="mono">{node.Context.UID}</dd></>}
          {node.Context?.Kind && <><dt>Inventory snapshot</dt><dd>{dateTime(node.Context.ObservedAt)}</dd></>}
        </dl>
      )}
      {link && (
        <dl className="kv">
          <dt>Source</dt><dd>{index.get(link.Source)?.Label}</dd>
          <dt>Destination</dt><dd>{index.get(link.Target)?.Label}</dd>
          <dt>Protocol / port</dt><dd>{link.Protocol} / {link.Port || '—'}</dd>
          <dt>Captured by</dt><dd>{link.CollectorID || 'local'} · {link.Interface || '—'}</dd>
          <dt>Observations</dt><dd>{count(link.Events)} · {bytes(link.Bytes)}</dd>
          <dt>Seen</dt><dd>{dateTime(link.FirstSeen)} – {dateTime(link.LastSeen)}</dd>
          <dt>Evidence</dt><dd>{evidenceLabel(link)}</dd>
          {!!link.SNI?.length && <><dt>TLS SNI</dt><dd>{link.SNI.join(', ')}</dd></>}
        </dl>
      )}
      <Evidence ids={ids} />
    </div>
  );
}

function Evidence({ ids }: { ids: number[] }) {
  const key = ids.slice(0, 100).join(',');
  const records = useResource<DNSResolution[]>(key ? url('/api/dns-evidence', { ids: key }) : null);
  return (
    <section className="evidence">
      <h3>DNS evidence</h3>
      {!ids.length && <p className="muted small">No matched query and response was captured. This does not establish literal-IP use.</p>}
      {records.loading && key && <Spinner />}
      <ErrorBanner error={records.error} />
      {ids.length > 100 && <p className="small muted">Showing the first 100 of {ids.length} records.</p>}
      {records.data?.map(record => (
        <dl className="kv" key={record.ID}>
          <dt>Answer</dt><dd><strong>{record.Name}</strong> → <span className="mono">{record.IP}</span></dd>
          <dt>Client</dt><dd className="mono">{record.ClientIP}:{record.ClientPort}</dd>
          <dt>Resolver</dt><dd className="mono">{record.ResolverIP}:{record.ResolverPort} ({record.Transport})</dd>
          <dt>Query / answer</dt><dd>{dateTime(record.QueryTime)} / {dateTime(record.ResponseTime)}</dd>
          <dt>TTL</dt><dd>{record.TTL} s{new Date(record.ExpiresAt) < new Date() ? ' (expired)' : ''}</dd>
        </dl>
      ))}
      {ids.length > 0 && <p className="muted small">Evidence shows the client received this DNS mapping. It does not prove which name the application passed to its socket API.</p>}
    </section>
  );
}
