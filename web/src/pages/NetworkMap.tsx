import { Fragment, useMemo, useState } from 'react';
import { url, type DNSResolution, type MapLink, type NetworkMap as MapData } from '../lib/api.ts';
import { href, useResource } from '../lib/hooks.ts';
import { bytes, count, dateTime } from '../lib/format.ts';
import { format, type Term } from '../lib/filter.ts';
import { evidenceLabel, flowFilter, flowWidth, groupFilter, groupMap, layoutFlows, short, type Box, type Flow, type Group } from '../lib/topology.ts';
import { Banner, Card, Empty, ErrorBanner, Spinner, UpdatedAt } from '../components/ui.tsx';

/** Selection: a group (on either side) or a flow, by id. */
type Selection = { group: string } | { flow: string } | null;

function tone(group: Group): string {
  if (group.kind === 'network') return group.scope === 'public' ? 'external' : 'internal';
  return group.kind;
}

function eventsLink(filter: Term | null, since: string): string {
  return href(['events'], { w: since, f: format(filter) || undefined });
}

/** The busiest values of a link property, as "443, 53 +3". */
function summary(links: MapLink[], value: (link: MapLink) => string, limit = 4): string {
  const totals = new Map<string, number>();
  for (const link of links) totals.set(value(link), (totals.get(value(link)) ?? 0) + link.Events);
  const sorted = [...totals.entries()].filter(([key]) => key).sort((a, b) => b[1] - a[1]).map(([key]) => key);
  return sorted.slice(0, limit).join(', ') + (sorted.length > limit ? ` +${sorted.length - limit}` : '');
}

export function NetworkMap() {
  const [since, setSince] = useState('1h');
  const [namespace, setNamespace] = useState('');
  const [ip, setIP] = useState('');
  const [ipDraft, setIPDraft] = useState('');
  const [live, setLive] = useState(true);
  const [selection, setSelection] = useState<Selection>(null);
  // 30 s refresh while visible; the server caches each variant for 15 s.
  const map = useResource<MapData>(url('/api/network-map', { since, namespace, ip }), live ? 30_000 : undefined);
  const data = map.data;

  const { groups, flows } = useMemo(() => groupMap(data?.Nodes ?? [], data?.Links ?? []), [data]);
  const layout = useMemo(() => layoutFlows(groups, flows), [groups, flows]);
  const position = useMemo(() => new Map(layout.boxes.map(box => [box.key, box])), [layout]);
  const most = Math.max(1, ...flows.map(flow => flow.events));
  const names = [...new Set([namespace, ...(data?.Namespaces ?? [])].filter(Boolean))].sort();
  const addresses = data?.Nodes?.length ?? 0;

  const selectedGroup = selection && 'group' in selection ? selection.group : '';
  const selectedFlow = selection && 'flow' in selection ? selection.flow : '';
  const related = (flow: Flow) => !selection || flow.id === selectedFlow || flow.source === selectedGroup || flow.target === selectedGroup;
  const activate = (event: React.KeyboardEvent, next: Selection) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelection(next); } };

  return (
    <>
      <div className="page-header">
        <div><h1>Network map</h1><p>Who opened connections to whom: pods grouped by workload, nodes by name, other addresses by network.</p></div>
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
      </div>
      <ErrorBanner error={map.error} retry={map.refresh} />
      {data?.Truncated && <Banner tone="warn">This is a bounded sample of the newest connections. Narrow the window, pick a namespace or filter by IP to see more.</Banner>}
      {data?.Kubernetes?.Error && <Banner tone="warn">Kubernetes inventory: {data.Kubernetes.Error}</Banner>}
      <p className="muted small">{count(groups.size)} groups · {count(flows.length)} flows · {count(addresses)} addresses · {count(data?.Observations ?? 0)} connection observations</p>
      <div className="map-layout">
        <div className="card map-card">
          {flows.length > 0 ? (
            <div className="map-scroll">
            <svg className="flow-map" viewBox={`0 0 ${layout.width} ${layout.height}`} style={{ aspectRatio: `${layout.width} / ${layout.height}` }}
              role="group" aria-label="Connections between groups; select a group or a flow for details" onClick={() => setSelection(null)}>
              <text x={0} y={14} className="column-title">Opened by</text>
              <text x={layout.width} y={14} className="column-title" textAnchor="end">Received by</text>
              {layout.headings.map(heading => (
                <text key={`${heading.side}:${heading.text}`} x={heading.side === 'source' ? 0 : layout.width} y={heading.y} textAnchor={heading.side === 'source' ? 'start' : 'end'} className="section-title">{heading.text}</text>
              ))}
              {[...flows].sort((a, b) => Number(related(a)) - Number(related(b)) || a.events - b.events).map(flow => {
                const a = position.get(`source:${flow.source}`), b = position.get(`target:${flow.target}`);
                if (!a || !b) return null;
                const x1 = a.x + layout.boxWidth, y1 = a.y + layout.boxHeight / 2, x2 = b.x, y2 = b.y + layout.boxHeight / 2;
                const bend = (x2 - x1) / 2;
                const path = `M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`;
                const protocol = summary(flow.links, link => link.Protocol, 1).toLowerCase();
                const title = `${a.group.label} → ${b.group.label}: ${count(flow.events)} ${flow.events === 1 ? 'connection' : 'connections'}${flow.bytes ? `, ${bytes(flow.bytes)}` : ''}; ports ${summary(flow.links, link => String(link.Port || ''))}`;
                return (
                  <g key={flow.id} className={`flow ${protocol} ${related(flow) ? '' : 'faded'} ${flow.id === selectedFlow ? 'selected' : ''}`}
                    role="button" tabIndex={0} aria-label={title} onKeyDown={event => activate(event, { flow: flow.id })}
                    onClick={event => { event.stopPropagation(); setSelection({ flow: flow.id }); }}>
                    <title>{title}</title>
                    <path d={path} className="hit" />
                    <path d={path} className="line" style={{ strokeWidth: flowWidth(flow.events, most) }} />
                  </g>
                );
              })}
              {layout.boxes.map(box => <GroupBox key={box.key} box={box} layout={layout} selected={box.group.id === selectedGroup}
                dim={Boolean(selection) && box.group.id !== selectedGroup && !flows.some(flow => related(flow) && (box.side === 'source' ? flow.source : flow.target) === box.group.id)}
                onSelect={() => setSelection({ group: box.group.id })} onKey={event => activate(event, { group: box.group.id })} />)}
            </svg>
            </div>
          ) : map.loading ? <Empty><Spinner /> Loading observations…</Empty> : <Empty>No connections in this window.</Empty>}
          <div className="legend">
            <span><span className="swatch-line workload" />Pods</span>
            <span><span className="swatch-line node" />Nodes</span>
            <span><span className="swatch-line service" />Services</span>
            <span><span className="swatch-line internal" />Private network, tailnet</span>
            <span><span className="swatch-line external" />Internet</span>
            <span>Line width: connections, on a log scale · select a box or line for details</span>
          </div>
        </div>
        <Inspector selection={selection} groups={groups} flows={flows} since={since} onClose={() => setSelection(null)} />
      </div>
      <p className="muted small">Groups come from Kubernetes inventory at capture time; addresses outside it are grouped by network and are not attributed to anyone. The map shows capture observations, not firewall verdicts. NAT paths and encrypted DNS are not inferred.</p>
    </>
  );
}

function GroupBox({ box, layout, selected, dim, onSelect, onKey }: { box: Box; layout: { boxWidth: number; boxHeight: number }; selected: boolean; dim: boolean; onSelect: () => void; onKey: (event: React.KeyboardEvent) => void }) {
  const { group } = box;
  return (
    <g transform={`translate(${box.x},${box.y})`} className={`group-box ${tone(group)} ${selected ? 'selected' : ''} ${dim ? 'faded' : ''}`}
      role="button" tabIndex={0} aria-label={`${group.label}, ${group.detail}, ${count(box.events)} connections ${box.side === 'source' ? 'opened' : 'received'}`}
      onKeyDown={onKey} onClick={event => { event.stopPropagation(); onSelect(); }}>
      <title>{`${group.label} · ${group.detail}`}</title>
      <rect width={layout.boxWidth} height={layout.boxHeight} rx={7} />
      <rect width={4} height={layout.boxHeight} rx={2} className="accent" />
      <text x={14} y={17} className="title">{short(group.label, 30)}</text>
      <text x={14} y={32} className="detail">{short(group.detail, 42)}</text>
      <text x={layout.boxWidth - 10} y={17} className="count" textAnchor="end">{count(box.events)}</text>
    </g>
  );
}

function Inspector({ selection, groups, flows, since, onClose }: { selection: Selection; groups: Map<string, Group>; flows: Flow[]; since: string; onClose: () => void }) {
  if (!selection) {
    return (
      <Card title="Details">
        <p className="muted">Select a group to see its members and connections, or a line to see one flow: ports, collectors, DNS evidence and its events.</p>
      </Card>
    );
  }
  const group = 'group' in selection ? groups.get(selection.group) : undefined;
  const flow = 'flow' in selection ? flows.find(item => item.id === selection.flow) : undefined;
  if (!group && !flow) return <Card title="Details" actions={<button onClick={onClose}>Clear</button>}><p className="muted">This item is outside the current window.</p></Card>;
  const links = flow ? flow.links : flows.filter(item => item.source === group!.id || item.target === group!.id).flatMap(item => item.links);
  const ids = [...new Set(links.flatMap(link => link.EvidenceIDs ?? []))];
  return (
    <div className="card inspector" aria-label="Details">
      <header style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
        <h2>{group ? group.label : `${groups.get(flow!.source)?.label} → ${groups.get(flow!.target)?.label}`}</h2>
        <button className="ghost" onClick={onClose} aria-label="Close details">✕</button>
      </header>
      {group ? <GroupDetails group={group} groups={groups} flows={flows} since={since} /> : <FlowDetails flow={flow!} groups={groups} since={since} />}
      <Evidence ids={ids} />
    </div>
  );
}

function GroupDetails({ group, groups, flows, since }: { group: Group; groups: Map<string, Group>; flows: Flow[]; since: string }) {
  const out = flows.filter(flow => flow.source === group.id).sort((a, b) => b.events - a.events);
  const into = flows.filter(flow => flow.target === group.id).sort((a, b) => b.events - a.events);
  const members = [...new Set(group.members.map(member => (group.kind === 'workload' ? member.Context?.Name : member.IP) || member.Label))].sort();
  const filter = groupFilter(group);
  return (
    <>
      <p className="muted small" style={{ margin: 0 }}>{group.detail}</p>
      {filter
        ? <a className="button small" href={eventsLink(filter, since)}>Show its events</a>
        : <p className="muted small" style={{ margin: 0 }}>Too many addresses to list in one filter; select a line to see one flow's events.</p>}
      <section>
        <h3>{group.kind === 'workload' ? 'Pods' : 'Addresses'} ({count(members.length)})</h3>
        <ul className="member-list mono">
          {members.slice(0, 40).map(member => <li key={member}>{member}</li>)}
          {members.length > 40 && <li className="muted">+{count(members.length - 40)} more</li>}
        </ul>
      </section>
      {[['Opened connections to', out, 'target'], ['Received connections from', into, 'source']].map(([title, list, end]) => (list as Flow[]).length > 0 && (
        <section key={title as string}>
          <h3>{title as string}</h3>
          <dl className="kv">
            {(list as Flow[]).slice(0, 12).map(flow => (
              <Fragment key={flow.id}>
                <dt><FlowLink flow={flow} groups={groups} since={since}>{short(groups.get(end === 'target' ? flow.target : flow.source)?.label ?? '', 26)}</FlowLink></dt>
                <dd>{count(flow.events)} · ports {summary(flow.links, link => String(link.Port || ''), 3) || '—'}</dd>
              </Fragment>
            ))}
          </dl>
        </section>
      ))}
    </>
  );
}

function addressList(addresses: Set<string>, limit = 6): string {
  const sorted = [...addresses].sort();
  return sorted.slice(0, limit).join(', ') + (sorted.length > limit ? ` +${sorted.length - limit}` : '');
}

function FlowLink({ flow, groups, since, children }: { flow: Flow; groups: Map<string, Group>; since: string; children: React.ReactNode }) {
  const filter = flowFilter(flow, groups);
  return filter ? <a href={eventsLink(filter, since)}>{children}</a> : <>{children}</>;
}

function FlowDetails({ flow, groups, since }: { flow: Flow; groups: Map<string, Group>; since: string }) {
  const source = groups.get(flow.source)!, target = groups.get(flow.target)!;
  const first = flow.links.map(link => link.FirstSeen).filter(Boolean).sort()[0];
  const last = flow.links.map(link => link.LastSeen).filter(Boolean).sort().at(-1);
  const names = [...new Set(flow.links.flatMap(link => link.SNI ?? []))];
  return (
    <>
      {flowFilter(flow, groups)
        ? <a className="button small" href={eventsLink(flowFilter(flow, groups), since)}>Show these events</a>
        : <p className="muted small" style={{ margin: 0 }}>Too many addresses to list in one filter; narrow the window or filter by IP.</p>}
      <dl className="kv">
        <dt>From</dt><dd>{source.label} <span className="muted">· {source.kind === 'network' ? addressList(flow.sourceAddresses) : source.detail}</span></dd>
        <dt>To</dt><dd>{target.label} <span className="muted">· {target.kind === 'network' ? addressList(flow.targetAddresses) : target.detail}</span></dd>
        <dt>Connections</dt><dd>{count(flow.events)}{flow.bytes ? ` · ${bytes(flow.bytes)}` : ''}</dd>
        <dt>Protocols</dt><dd>{summary(flow.links, link => link.Protocol)}</dd>
        <dt>Ports</dt><dd className="mono">{summary(flow.links, link => String(link.Port || ''), 8) || '—'}</dd>
        <dt>Captured by</dt><dd>{summary(flow.links, link => `${link.CollectorID || 'local'} · ${link.Interface || '—'}`, 3)}</dd>
        <dt>Seen</dt><dd>{dateTime(first)} – {dateTime(last)}</dd>
        <dt>Evidence</dt><dd>{flow.links.some(link => link.EvidenceIDs?.length) ? `${flow.links.filter(link => link.EvidenceIDs?.length).length} of ${flow.links.length} address pairs: ${evidenceLabel({ EvidenceIDs: [1] })}` : evidenceLabel({ EvidenceIDs: null })}</dd>
        {names.length > 0 && <><dt>TLS SNI</dt><dd>{names.slice(0, 8).join(', ')}{names.length > 8 ? ` +${names.length - 8}` : ''}</dd></>}
      </dl>
    </>
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
