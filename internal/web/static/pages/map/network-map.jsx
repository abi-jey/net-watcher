(function () {
    const { useState, useEffect, useRef, useMemo } = React;
    const { Topology, CONFIG, Utils } = NetWatcher;
    const empty = { Nodes: [], Links: [], Evidence: [], Namespaces: [], Kubernetes: {} };
    const date = value => value && !value.startsWith('0001-') ? new Date(value).toLocaleString() : '—';
    const hostMark = node => !node ? 'Unknown' : node.Kind === 'dns' ? 'DNS evidence' : node.Ownership === 'ours' ? `Ours · ${node.Scope}` : `${node.Scope} · unattributed`;

    function Evidence({ ids }) {
        const [records, setRecords] = useState([]);
        const [error, setError] = useState('');
        const [loading, setLoading] = useState(false);
        const key = ids.slice(0, 100).join(',');
        useEffect(() => {
            const controller = new AbortController();
            setRecords([]); setError('');
            if (!key) { setLoading(false); return; }
            setLoading(true);
            fetch(`${CONFIG.API_BASE}/api/dns-evidence?ids=${encodeURIComponent(key)}`, { signal: controller.signal })
                .then(response => { if (!response.ok) throw new Error('Could not load DNS evidence'); return response.json(); })
                .then(setRecords).catch(error => { if (error.name !== 'AbortError') setError(error.message); })
                .finally(() => { if (!controller.signal.aborted) setLoading(false); });
            return () => controller.abort();
        }, [key]);
        return <section className="map-evidence">
            <h3>DNS evidence</h3>
            {!ids.length && <p>No matched query/response was captured for this connection. This does not establish literal-IP usage.</p>}
            {loading && <p role="status">Loading evidence…</p>}
            {error && <p role="alert">{error}</p>}
            {ids.length > 100 && <p>Showing the first 100 evidence records.</p>}
            {!loading && ids.length > 0 && !records.length && !error && <p>The referenced evidence is no longer available.</p>}
            {records.map(record => <article key={record.ID}>
                <strong>{record.Name} → {record.IP}</strong>
                <span className="map-proof">Observed query + matching response</span>
                <dl>
                    <dt>Client</dt><dd>{record.ClientIP}:{record.ClientPort}</dd>
                    <dt>Resolver</dt><dd>{record.ResolverIP}:{record.ResolverPort}</dd>
                    <dt>Transaction</dt><dd>{record.TransactionID} · {record.Transport} · {record.QueryType}</dd>
                    <dt>Query observed</dt><dd>{date(record.QueryTime)}</dd>
                    <dt>Response observed</dt><dd>{date(record.ResponseTime)}</dd>
                    <dt>Effective TTL</dt><dd>{record.TTL}s</dd>
                    <dt>Expires</dt><dd>{date(record.ExpiresAt)} {new Date(record.ExpiresAt) < new Date() ? '(historical)' : ''}</dd>
                    <dt>Interface</dt><dd>{record.Interface}</dd>
                </dl>
                <details><summary>Observed answer records and CNAME chain</summary>
                    <pre>{JSON.stringify(JSON.parse(record.AnswerRecords || '[]'), null, 2)}</pre>
                    <pre>{JSON.stringify(JSON.parse(record.CNAMEChain || '[]'), null, 2)}</pre>
                </details>
            </article>)}
            {ids.length > 0 && <p>Evidence proves that this client received the DNS mapping. It does not prove which hostname an application passed to its socket API. TLS SNI is a separate observation.</p>}
        </section>;
    }

    function Inspector({ selection, data, onClose }) {
        if (!selection) return <aside className="map-inspector"><h2>Explore a connection</h2><p>Select a node or an edge to inspect endpoints, Kubernetes ownership and the original DNS evidence.</p><p>Drag nodes to arrange them. Drag the background to pan; scroll to zoom.</p></aside>;
        const node = data.Nodes.find(node => node.ID === selection);
        const link = data.Links.find(link => link.ID === selection);
        if (!node && !link) return <aside className="map-inspector"><button onClick={onClose}>Clear selection</button><p>This item is outside the current time window.</p></aside>;
        const related = node ? data.Links.filter(edge => edge.Source === node.ID || edge.Target === node.ID) : [link];
        const ids = [...new Set(related.flatMap(edge => edge.EvidenceIDs || []))];
        const source = link && data.Nodes.find(node => node.ID === link.Source);
        const target = link && data.Nodes.find(node => node.ID === link.Target);
        return <aside className="map-inspector" aria-label="Network details">
            <button className="map-close" onClick={onClose}>Close details</button>
            <h2>{node ? node.Label : link.Kind === 'connection' ? `${link.Protocol} connection` : 'DNS relationship'}</h2>
            {node && <><dl>
                <dt>Kind</dt><dd>{node.Kind}</dd><dt>Address</dt><dd>{node.IP || 'DNS name'}</dd>
                {node.Kind !== 'dns' && <><dt>Network</dt><dd>{node.Scope}</dd><dt>Ownership</dt><dd>{node.Ownership === 'ours' ? node.OwnershipSource === 'configured' ? 'Ours · configured address' : node.OwnershipSource === 'observed-node' ? 'Ours · node identity observed in this view' : 'Ours · Kubernetes inventory' : 'Unattributed · ownership unknown'}</dd></>}
                {node.Context?.Namespace && <><dt>Namespace</dt><dd>{node.Context.Namespace}</dd></>}
                {node.Context?.Node && <><dt>Node</dt><dd>{node.Context.Node}</dd></>}
                {node.Context?.UID && <><dt>Resource UID</dt><dd>{node.Context.UID}</dd></>}
                {node.Context?.Kind && <><dt>Inventory snapshot</dt><dd>{date(node.Context.ObservedAt)}</dd></>}
                {node.Context?.Owner?.Name && <><dt>Workload</dt><dd>{node.Context.Owner.Kind}/{node.Context.Owner.Name}</dd></>}
            </dl>
            {!!node.Context?.Services?.length && <section><h3>Service endpoint membership</h3>
                {node.Context.Services.map((service, index) => <p key={index}>{service.Namespace}/{service.Name} · {service.Protocol}/{service.Port}</p>)}
                <p>Inventory membership, not proof that this connection traversed a Service VIP.</p>
            </section>}</>}
            {link && <><dl>
                <dt>Source</dt><dd>{source?.Label} <span className="map-host-mark">{hostMark(source)}</span></dd>
                <dt>Destination</dt><dd>{target?.Label} <span className="map-host-mark">{hostMark(target)}</span></dd>
                <dt>{link.Kind === 'connection' ? 'Protocol / port' : 'DNS transport / resolver port'}</dt><dd>{link.Protocol} / {link.Port || '—'}</dd>
                <dt>Interface</dt><dd>{link.Interface || 'See evidence'}</dd>
                <dt>Observations</dt><dd>{link.Events}</dd><dt>Recorded bytes</dt><dd>{Utils.formatBytes(link.Bytes)}</dd>
                <dt>First seen</dt><dd>{date(link.FirstSeen)}</dd><dt>Last seen</dt><dd>{date(link.LastSeen)}</dd>
            </dl><p className={ids.length ? 'map-proof' : ''}>{Topology.evidenceLabel(link)}</p>
            {!!link.SNI?.length && <section><h3>TLS SNI (separate from DNS)</h3>{link.SNI.map(name => <p key={name}>{name}</p>)}</section>}</>}
            <Evidence ids={ids} />
        </aside>;
    }

    NetWatcher.Components.DNSEvidence = Evidence;

    NetWatcher.Pages.NetworkMapPage = function () {
        const [data, setData] = useState(empty);
        const [since, setSince] = useState('24h');
        const [namespace, setNamespace] = useState('');
        const [ip, setIP] = useState('');
        const [ipDraft, setIPDraft] = useState('');
        const [live, setLive] = useState(true);
        const [revision, setRevision] = useState(0);
        const [error, setError] = useState('');
        const [loading, setLoading] = useState(true);
        const [selection, setSelection] = useState('');
        const [positions, setPositions] = useState({});
        const [view, setView] = useState({ x: 0, y: 0, scale: 0.8 });
        const svg = useRef(null);
        const drag = useRef(null);
        const fitted = useRef(false);

        useEffect(() => {
            let stopped = false;
            let controller;
            let timer;
            fitted.current = false;
            const refresh = async () => {
                controller = new AbortController(); setLoading(true);
                try {
                    const query = new URLSearchParams({ since, namespace, ip });
                    const response = await fetch(`${CONFIG.API_BASE}/api/network-map?${query}`, { signal: controller.signal });
                    if (!response.ok) throw new Error(await response.text());
                    const result = await response.json();
                    if (!stopped) { setData(result); setError(''); setPositions(previous => Topology.layout(result.Nodes, result.Links, previous)); }
                } catch (error) { if (!stopped && error.name !== 'AbortError') setError(error.message); }
                finally { if (!stopped) { setLoading(false); if (live) timer = setTimeout(refresh, 5000); } }
            };
            refresh();
            return () => { stopped = true; controller?.abort(); clearTimeout(timer); };
        }, [since, namespace, ip, live, revision]);

        const fit = () => { const box = svg.current?.getBoundingClientRect(); if (box) setView(Topology.fit(positions, box.width, box.height)); };
        useEffect(() => { if (!fitted.current && Object.keys(positions).length && svg.current) { fit(); fitted.current = true; } }, [positions]);
        useEffect(() => {
            const element = svg.current;
            const wheel = event => {
                event.preventDefault();
                const box = element.getBoundingClientRect();
                const x = event.clientX - box.left, y = event.clientY - box.top;
                setView(old => { const scale = Math.max(0.01, Math.min(3, old.scale * Math.exp(-event.deltaY * 0.001))); const ratio = scale / old.scale; return { x: x - (x - old.x) * ratio, y: y - (y - old.y) * ratio, scale }; });
            };
            element.addEventListener('wheel', wheel, { passive: false });
            return () => element.removeEventListener('wheel', wheel);
        }, []);

        const startDrag = (event, id = '') => {
            if (event.button !== 0) return;
            event.stopPropagation();
            svg.current.setPointerCapture(event.pointerId);
            drag.current = { id, x: event.clientX, y: event.clientY, view, position: positions[id] };
            if (id) setSelection(id);
        };
        const moveDrag = event => {
            const current = drag.current; if (!current) return;
            const dx = event.clientX - current.x, dy = event.clientY - current.y;
            if (current.id) setPositions(previous => ({ ...previous, [current.id]: { x: current.position.x + dx / current.view.scale, y: current.position.y + dy / current.view.scale } }));
            else setView({ ...current.view, x: current.view.x + dx, y: current.view.y + dy });
        };
        const names = [...new Set([namespace, ...(data.Namespaces || [])].filter(Boolean))].sort();
        const nodeIndex = useMemo(() => new Map(data.Nodes.map(node => [node.ID, node])), [data]);
        const hostCounts = data.Nodes.reduce((counts, node) => { if (node.Kind !== 'dns') counts[node.Ownership === 'ours' ? 'ours' : node.Scope] = (counts[node.Ownership === 'ours' ? 'ours' : node.Scope] || 0) + 1; return counts; }, { ours: 0, internal: 0, external: 0 });
        const activate = (event, id) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelection(id); } };
        return <>
            <header className="header"><div className="header-content"><div><h1>Network map</h1><p>Observed connections, Kubernetes context and DNS evidence</p></div></div></header>
            <div className="network-map-page">
                <div className="map-toolbar">
                    <label>Window <select value={since} onChange={e => setSince(e.target.value)}><option value="15m">15 minutes</option><option value="1h">1 hour</option><option value="6h">6 hours</option><option value="24h">24 hours</option></select></label>
                    <label>Namespace <select value={namespace} onChange={e => setNamespace(e.target.value)}><option value="">All namespaces</option>{names.map(name => <option key={name}>{name}</option>)}</select></label>
                    <form onSubmit={e => { e.preventDefault(); setIP(ipDraft.trim()); }}><input aria-label="Filter map by IP" placeholder="Filter by IP address" value={ipDraft} onChange={e => setIPDraft(e.target.value)} /><button type="submit">Filter</button></form>
                    <label><input type="checkbox" checked={live} onChange={e => setLive(e.target.checked)} /> Live</label>
                    <button onClick={() => setRevision(value => value + 1)} disabled={loading}>Refresh</button>
                    <button onClick={fit}>Fit map</button>
                    <button onClick={() => { setPositions(Topology.layout(data.Nodes, data.Links)); fitted.current = false; }}>Reset layout</button>
                </div>
                <div className="map-status" role="status">
                    {loading ? 'Refreshing…' : `${data.Nodes.length} nodes · ${data.Links.length} relationships · ${data.Observations || 0} connection observations`}
                    <span>{hostCounts.ours} ours · {hostCounts.internal} internal/unattributed · {hostCounts.external} external/unattributed</span>
                    <span>{data.Kubernetes?.Enabled ? `Kubernetes inventory: ${data.Kubernetes.Error ? 'unavailable/stale' : data.Kubernetes.LastSync ? 'synced' : 'waiting'}` : hostCounts.ours ? 'Ownership: captured inventory / configured addresses' : 'Kubernetes enrichment unavailable'}</span>
                </div>
                {error && <div className="map-warning" role="alert">Refresh failed: {error}. The canvas may show an earlier snapshot.</div>}
                {data.Truncated && <div className="map-warning">This is a bounded sample (up to 250 nodes). Narrow the time window or filter by IP to inspect additional activity.</div>}
                {data.Kubernetes?.Error && <div className="map-warning">{data.Kubernetes.Error}</div>}
                <div className="map-workspace">
                    <div className="map-canvas-wrap">
                        <svg ref={svg} className="map-canvas" aria-label="Interactive network map" onPointerDown={event => startDrag(event)} onPointerMove={moveDrag} onPointerUp={() => { drag.current = null; }} onPointerCancel={() => { drag.current = null; }}>
                            <defs>{['connection', 'dns_query', 'dns_answer'].map(kind => <marker key={kind} id={`map-arrow-${kind}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill={kind === 'connection' ? '#818cf8' : '#34d399'} /></marker>)}</defs>
                            <g transform={`translate(${view.x},${view.y}) scale(${view.scale})`}>
                                {data.Links.map(link => {
                                    const a = positions[link.Source], b = positions[link.Target]; if (!a || !b) return null;
                                    const x1 = a.x + 250, y1 = a.y + 39, x2 = b.x, y2 = b.y + 39;
                                    const bend = Math.max(65, Math.abs(x2 - x1) / 2);
                                    const path = `M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`;
                                    const label = link.Kind === 'connection' ? `${link.Protocol} ${link.Port || ''} · ${link.Events}` : link.Kind === 'dns_query' ? 'observed DNS query' : 'DNS answer → IP';
                                    return <g key={link.ID} className={`map-link ${link.Kind} ${selection === link.ID ? 'selected' : ''}`} role="button" tabIndex="0" aria-label={`${label}: ${nodeIndex.get(link.Source)?.Label} to ${nodeIndex.get(link.Target)?.Label}`} onKeyDown={event => activate(event, link.ID)} onPointerDown={event => event.stopPropagation()} onClick={() => setSelection(link.ID)}>
                                        <path d={path} className="map-link-hit" /><path d={path} className="map-link-line" markerEnd={`url(#map-arrow-${link.Kind})`} /><text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 8} textAnchor="middle">{label}</text>
                                    </g>;
                                })}
                                {data.Nodes.map(node => {
                                    const p = positions[node.ID]; if (!p) return null;
                                    return <g key={node.ID} transform={`translate(${p.x},${p.y})`} className={`map-node ${node.Kind} ${node.Ownership === 'ours' ? 'owned' : node.Scope} ${selection === node.ID ? 'selected' : ''}`} role="button" tabIndex="0" aria-label={`${node.Kind}: ${node.Label}, ${hostMark(node)}`} onKeyDown={event => activate(event, node.ID)} onPointerDown={event => startDrag(event, node.ID)}>
                                        <title>{node.Label}{node.IP ? ` (${node.IP})` : ''} · {hostMark(node)}</title><rect width="250" height="78" rx="12" />
                                        <text x="14" y="20" className="map-node-kind">{node.Kind.toUpperCase()} · {hostMark(node).toUpperCase()}</text>
                                        <text x="14" y="43" className="map-node-title">{Topology.short(node.Label)}</text>
                                        <text x="14" y="63" className="map-node-address">{node.IP || 'Client-scoped DNS observation'}</text>
                                    </g>;
                                })}
                            </g>
                        </svg>
                        {!data.Nodes.length && <div className="map-empty">{loading ? 'Loading network observations…' : 'No observations in this window. Start capture or widen the filters.'}</div>}
                        <div className="map-legend"><span className="map-legend-owned">● Our identified hosts</span><span className="map-legend-internal">● Internal · unattributed</span><span className="map-legend-external">● External · unattributed</span><span>━━ Connection observations</span><span className="map-proof">┄┄ Matched DNS evidence</span><span>Drag · pan · scroll to zoom</span></div>
                    </div>
                    <Inspector selection={selection} data={data} onClose={() => setSelection('')} />
                </div>
                <p className="map-note">“Ours” means a pod, Service, or node identified by Kubernetes inventory, or an address explicitly configured as owned. “Internal” includes private, link-local, and Tailscale-range addresses; unattributed does not mean someone else owns them. The map shows capture observations, not firewall verdicts. Multiple interfaces may observe the same traffic. Kubernetes labels are inventory snapshots; NAT paths and hidden/encrypted DNS are not inferred.</p>
                <details className="map-relationships"><summary>Connection list ({data.Links.filter(link => link.Kind === 'connection').length})</summary>
                    {data.Links.filter(link => link.Kind === 'connection').map(link => <button key={link.ID} onClick={() => setSelection(link.ID)}>{nodeIndex.get(link.Source)?.Label} → {nodeIndex.get(link.Target)?.Label} · {link.Protocol}/{link.Port} · {Topology.evidenceLabel(link)}</button>)}
                </details>
            </div>
        </>;
    };
})();
