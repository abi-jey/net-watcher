import { useEffect, useRef, useState, type FormEvent } from 'react';
import { getJSON, url, type EventsResponse, type HealthResponse, type NetworkEvent } from '../lib/api.ts';
import { setQuery, useResource } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { dateTime } from '../lib/format.ts';
import { eventLabel, family, interfaceRole, interfaceRoles, routeInfo } from '../lib/network.ts';
import { Banner, Empty, ErrorBanner, Spinner, WindowSelect } from '../components/ui.tsx';
import { EventRow, type Filter } from '../components/EventRow.tsx';

const eventTypes = ['TCP_START', 'TCP_END', 'UDP_START', 'UDP_END', 'DNS', 'TLS_SNI', 'ICMP', 'TIMEOUT', 'GAP'];
const pageSize = 100;
const liveLimit = 300;
// Scrolling loads older pages automatically up to this many rows; beyond it a
// button keeps the browser responsive.
const autoLoadLimit = 3000;

// Exact-match filters. Names are the URL and /api/events parameters alike.
const exactKeys = ['collector', 'iface', 'ifaceRole', 'ipVersion', 'withProcess', 'srcKind', 'dstKind', 'namespace', 'port', 'route'] as const;
type ExactKey = typeof exactKeys[number];
type Exact = Record<ExactKey, string>;

// A process filter comes from the Processes page or a process tag and selects
// one exact identity: pod, container and command (with the collector's node).
interface ProcessFilter { process: string; processPod: string; processContainer: string }
interface Search extends ProcessFilter, Exact { window: string; types: string[]; src: string; dst: string; q: string }

function readSearch(query: URLSearchParams): Search {
  const exact = Object.fromEntries(exactKeys.map(key => [key, query.get(key) ?? ''])) as Exact;
  return {
    ...exact, window: query.get('w') ?? '24h', types: (query.get('type') ?? '').split(',').filter(Boolean), src: query.get('src') ?? '', dst: query.get('dst') ?? '', q: query.get('q') ?? '',
    process: query.get('process') ?? '', processPod: query.get('processPod') ?? '', processContainer: query.get('processContainer') ?? '',
  };
}

/** The search as URL query parameters. */
function searchQuery(search: Search): Record<string, string | undefined> {
  const exact = Object.fromEntries(exactKeys.map(key => [key, search[key].trim() || undefined]));
  const process = search.process ? { process: search.process, processPod: search.processPod, processContainer: search.processContainer } : {};
  return { ...exact, ...process, w: search.window, type: search.types.join(','), src: search.src.trim(), dst: search.dst.trim(), q: search.q.trim() };
}

const kinds = [
  { id: 'pod', label: 'pod' }, { id: 'node', label: 'node' }, { id: 'service', label: 'service' }, { id: 'endpoint', label: 'endpoint' },
  { id: 'none', label: 'outside the cluster' },
];
const routes = [
  { id: 'any', label: 'any Tailscale route' }, { id: 'exit-node', label: 'exit node traffic' },
  { id: 'subnet-router', label: 'subnet route traffic' }, { id: 'via-tailnet', label: "node's traffic into the tailnet" },
];

/** Plain-language label of an active exact filter. */
function describe(key: ExactKey, value: string): string {
  switch (key) {
    case 'collector': return `node ${value}`;
    case 'iface': return `interface ${value}`;
    case 'ifaceRole': return `${interfaceRoles.find(role => role.id === value)?.label ?? value} interfaces`;
    case 'ipVersion': return `IPv${value}`;
    case 'withProcess': return value === 'yes' ? 'with a process' : 'without a process';
    case 'srcKind': return `source ${kinds.find(kind => kind.id === value)?.label ?? value}`;
    case 'dstKind': return `destination ${kinds.find(kind => kind.id === value)?.label ?? value}`;
    case 'namespace': return `namespace ${value}`;
    case 'port': return `port ${value}`;
    case 'route': return value === 'any' ? 'any Tailscale route' : routeInfo(value)?.label ?? value;
  }
}

/** Mirrors the server's filters for events arriving over the live tail. */
function matches(event: NetworkEvent, search: Search): boolean {
  const has = (value: string, needle: string) => !needle || value.includes(needle);
  const kind = (value: string, want: string) => !want || (want === 'none' ? !value : value === want);
  return (!search.types.length || search.types.includes(event.EventType)) && has(event.SrcIP, search.src) && has(event.DstIP, search.dst)
    && (!search.process || (event.ProcessCommand === search.process && event.ProcessPod === search.processPod && event.ProcessContainer === search.processContainer))
    && (!search.collector || event.CollectorID === search.collector)
    && (!search.iface || event.Interface === search.iface)
    && (!search.ifaceRole || interfaceRole(event.Interface).id === search.ifaceRole)
    && (!search.ipVersion || String(event.IPVersion) === search.ipVersion)
    && (!search.withProcess || (search.withProcess === 'yes') === Boolean(event.ProcessSide))
    && kind(event.SrcKind, search.srcKind) && kind(event.DstKind, search.dstKind)
    && (!search.namespace || event.SrcNamespace === search.namespace || event.DstNamespace === search.namespace)
    && (!search.port || String(event.SrcPort) === search.port || String(event.DstPort) === search.port)
    && (!search.route || (search.route === 'any' ? Boolean(event.Route) : event.Route === search.route))
    && (!search.q || [event.SrcIP, event.DstIP, event.Hostname, event.DNSQuery, event.TLSSNI, event.SrcName, event.DstName, event.SrcNamespace, event.DstNamespace, event.SrcWorkload, event.DstWorkload,
      event.ProcessCommand, event.ProcessPod, event.ProcessContainer, event.TailnetPeer, event.TailnetPeerName].some(value => value?.includes(search.q)));
}

/** A select of one exact filter, with "any" as the empty choice. */
function Pick({ label, value, options, onChange, title }: { label: string; value: string; options: { id: string; label: string }[]; onChange: (value: string) => void; title?: string }) {
  return (
    <label className="field" title={title}>{label}
      <select value={value} onChange={event => onChange(event.target.value)}>
        <option value="">any</option>
        {options.map(option => <option key={option.id} value={option.id}>{option.label}</option>)}
        {value && !options.some(option => option.id === value) && <option value={value}>{value}</option>}
      </select>
    </label>
  );
}

export function Events({ query }: { query: URLSearchParams }) {
  const search = readSearch(query);
  const key = query.toString();
  const [draft, setDraft] = useState(search);
  const exactActive = exactKeys.filter(key => search[key]);
  const [more, setMore] = useState(() => exactActive.length > 0);
  const collectors = useResource<HealthResponse>('/api/collectors', 60_000);
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [page, setPage] = useState<EventsResponse>();
  const [range, setRange] = useState(() => windowRange(search.window));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error>();
  const [expanded, setExpanded] = useState<number>();
  const [live, setLive] = useState(false);
  const [skipped, setSkipped] = useState(0);
  const controller = useRef<AbortController>(undefined);
  const sentinel = useRef<HTMLDivElement>(null);

  const load = async (cursor?: string, fixedRange = range) => {
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    setLoading(true);
    setError(undefined);
    try {
      const result = await getJSON<EventsResponse>(url('/api/events', {
        ...searchQuery(search), w: undefined, type: undefined, src: undefined, dst: undefined,
        ...fixedRange, limit: pageSize, cursor, eventType: search.types.join(','), srcIP: search.src, dstIP: search.dst,
      }), abort.signal);
      setPage(result);
      const received = result.events ?? [];
      setEvents(previous => cursor ? [...previous, ...received] : received);
    } catch (failure) {
      if (!abort.signal.aborted) setError(failure as Error);
    } finally {
      if (!abort.signal.aborted) setLoading(false);
    }
  };

  // A new search fixes its window so cursors stay valid while paging.
  useEffect(() => {
    setDraft(search);
    const fixed = windowRange(search.window);
    setRange(fixed);
    setExpanded(undefined);
    setEvents([]);
    setPage(undefined);
    void load(undefined, fixed);
    return () => controller.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  // Live tail over the WebSocket hub: newest events, gaps announced.
  useEffect(() => {
    if (!live) return;
    setSkipped(0);
    const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${location.pathname.replace(/[^/]*$/, '')}api/ws`);
    socket.onmessage = message => {
      const data = JSON.parse(message.data as string) as { type: string; data?: NetworkEvent; count?: number };
      if (data.type === 'skipped') setSkipped(total => total + (data.count ?? 0));
      if (data.type === 'event' && data.data && matches(data.data, search)) setEvents(previous => [data.data!, ...previous].slice(0, liveLimit));
    };
    return () => socket.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, key]);

  const paused = Boolean(page && !page.complete && (page.events?.length ?? 0) < pageSize);
  const canAutoLoad = Boolean(page?.nextCursor) && !paused && !loading && !live && !error && events.length < autoLoadLimit;

  // Infinite scroll: load the next older page when the end of the list comes
  // near. A paused search (time budget spent without filling a page) waits
  // for an explicit "Continue search" so a rare match cannot loop the server.
  const next = useRef<() => void>(() => {});
  next.current = () => { if (canAutoLoad) void load(page!.nextCursor); };
  useEffect(() => {
    const target = sentinel.current;
    if (!target || typeof IntersectionObserver === 'undefined') return;
    const observer = new IntersectionObserver(entries => { if (entries.some(entry => entry.isIntersecting)) next.current(); }, { rootMargin: '800px 0px' });
    observer.observe(target);
    return () => observer.disconnect();
  }, [canAutoLoad]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setQuery(['events'], searchQuery({ ...draft, process: search.process, processPod: search.processPod, processContainer: search.processContainer }));
  };
  // Tags and chips apply at once, on top of the current search.
  const apply = (change: Partial<Search>) => setQuery(['events'], searchQuery({ ...search, ...change }));
  const onFilter = (filter: Filter) => { setExpanded(undefined); apply(filter); };
  const clearProcess = () => apply({ process: '', processPod: '', processContainer: '' });
  const clearAll = () => apply({ ...Object.fromEntries(exactKeys.map(key => [key, ''])) as Exact, process: '', processPod: '', processContainer: '', src: '', dst: '', q: '', types: [] });
  const setExact = (key: ExactKey) => (value: string) => setDraft(previous => ({ ...previous, [key]: value }));
  const toggleType = (type: string) => setDraft(previous => ({ ...previous, types: previous.types.includes(type) ? previous.types.filter(item => item !== type) : [...previous.types, type] }));
  const filtered = Boolean(search.q || search.src || search.dst || search.types.length || search.process || exactActive.length);
  const nodes = (collectors.data?.collectors ?? []).map(collector => ({ id: collector.CollectorID, label: collector.CollectorID || 'local' }));

  return (
    <>
      <div className="page-header">
        <div><h1>Events</h1><p>Every stored observation, newest first. Select a row for its source, destination and capture details; select a tag in a row to show only events sharing it.</p></div>
        <label className="switch"><input type="checkbox" checked={live} onChange={event => setLive(event.target.checked)} /><span>Live tail</span></label>
      </div>
      <form className="card filters" onSubmit={submit}>
        <label className="field grow">Search<input type="search" value={draft.q} onChange={event => setDraft({ ...draft, q: event.target.value })} placeholder="IP, DNS name, SNI, pod, namespace, workload or process" /></label>
        <label className="field">Window<WindowSelect value={draft.window} onChange={value => setDraft({ ...draft, window: value })} /></label>
        <label className="field">Source IP<input value={draft.src} onChange={event => setDraft({ ...draft, src: event.target.value })} placeholder="any" size={12} title="Matches any part of the address, such as 10.0.1." /></label>
        <label className="field">Destination IP<input value={draft.dst} onChange={event => setDraft({ ...draft, dst: event.target.value })} placeholder="any" size={12} title="Matches any part of the address, such as 10.0.1." /></label>
        <button className="primary" type="submit" disabled={loading}>Search</button>
        <button type="button" className="ghost" aria-expanded={more} aria-controls="more-filters" onClick={() => setMore(open => !open)}>
          {more ? 'Fewer filters' : 'More filters'}{!more && exactActive.length > 0 && ` (${exactActive.length})`}
        </button>
        {more && (
          <div className="more-filters" id="more-filters">
            <Pick label="Node" value={draft.collector} options={nodes} onChange={setExact('collector')} title="Collector (node) that captured the packet" />
            <Pick label="Interface type" value={draft.ifaceRole} options={interfaceRoles} onChange={setExact('ifaceRole')} />
            <label className="field">Interface<input value={draft.iface} onChange={event => setExact('iface')(event.target.value)} placeholder="any" size={10} title="Exact interface name, such as tailscale0 or enp0s25" /></label>
            <Pick label="IP version" value={draft.ipVersion} options={[{ id: '4', label: 'IPv4' }, { id: '6', label: 'IPv6' }]} onChange={setExact('ipVersion')} />
            <Pick label="Process" value={draft.withProcess} options={[{ id: 'yes', label: 'identified' }, { id: 'no', label: 'not identified' }]} onChange={setExact('withProcess')} />
            <Pick label="Source is" value={draft.srcKind} options={kinds} onChange={setExact('srcKind')} title="Kubernetes identity of the source address" />
            <Pick label="Destination is" value={draft.dstKind} options={kinds} onChange={setExact('dstKind')} title="Kubernetes identity of the destination address" />
            <label className="field">Namespace<input value={draft.namespace} onChange={event => setExact('namespace')(event.target.value)} placeholder="any" size={10} title="Kubernetes namespace of either end" /></label>
            <label className="field">Port<input value={draft.port} onChange={event => setExact('port')(event.target.value.replace(/\D/g, ''))} placeholder="any" size={5} inputMode="numeric" title="Source or destination port" /></label>
            <Pick label="Tailscale" value={draft.route} options={routes} onChange={setExact('route')} title="Traffic this node forwarded as a tailnet device's exit node or subnet router, or its own traffic into the tailnet" />
          </div>
        )}
        <div className="chips" role="group" aria-label="Event types">
          {eventTypes.map(type => (
            <button key={type} type="button" className="chip" aria-pressed={draft.types.includes(type)} onClick={() => toggleType(type)} title={type}>
              <span className={`swatch ${family(type)}`} />{eventLabel(type)}
            </button>
          ))}
          {draft.types.length > 0 && <button type="button" className="ghost small" onClick={() => setDraft({ ...draft, types: [] })}>Clear types</button>}
        </div>
      </form>
      {(search.process || exactActive.length > 0) && (
        <div className="active-filters" aria-label="Active filters">
          {search.process && (
            <span className="filter-chip">
              <span>Process <b className="mono">{search.process}</b>{search.processContainer && <> in container <b>{search.processContainer}</b></>}{search.processPod ? <> of pod <b>{search.processPod}</b></> : ' on the host'}</span>
              <button type="button" onClick={clearProcess} aria-label="Remove process filter">✕</button>
            </span>
          )}
          {exactActive.map(key => (
            <span key={key} className="filter-chip">
              <span>{describe(key, search[key])}</span>
              <button type="button" onClick={() => apply({ [key]: '' })} aria-label={`Remove filter ${describe(key, search[key])}`}>✕</button>
            </span>
          ))}
          <button type="button" className="ghost small" onClick={clearAll}>Clear all</button>
        </div>
      )}
      <ErrorBanner error={error} retry={() => void load(page?.nextCursor && events.length ? page.nextCursor : undefined)} />
      {live && <Banner>Live tail: new events appear as they are stored (newest {liveLimit} kept).{skipped > 0 && ` ${skipped.toLocaleString()} events arrived faster than the live view shows; turn live tail off and search to see all of them.`}</Banner>}
      <div className="event-list card flush">
        <div className="ev-head" aria-hidden="true">
          <span>Time</span><span>Type</span><span>Source</span><span /><span>Destination</span><span>Details</span>
        </div>
        <ol aria-label="Events">
          {events.map(event => <EventRow key={event.ID} event={event} expanded={expanded === event.ID} onToggle={() => setExpanded(current => current === event.ID ? undefined : event.ID)} onFilter={onFilter} />)}
        </ol>
        {!events.length && (loading ? <Empty><Spinner /> Searching…</Empty> : page?.complete ? <Empty>No {filtered ? 'matching ' : ''}events between {dateTime(page.from)} and {dateTime(page.to)}.</Empty> : null)}
        <div ref={sentinel} />
        {paused && (
          <Banner tone="warn" action={<button onClick={() => void load(page!.nextCursor)} disabled={loading}>Continue search</button>}>
            Searched back to {dateTime(page!.searchedFrom)} of a window starting {dateTime(page!.from)}. Searches pause every few seconds to keep the server responsive.
          </Banner>
        )}
        <div className="table-foot">
          <span className="muted small" aria-live="polite">
            {events.length.toLocaleString()} shown
            {page && (page.complete && !page.nextCursor ? ' · whole window searched' : ` · back to ${dateTime(page.searchedFrom)}`)}
          </span>
          {loading && events.length > 0 && <span className="muted small"><Spinner /> Loading older events…</span>}
          {page?.nextCursor && !paused && !loading && !canAutoLoad && <button onClick={() => void load(page.nextCursor)}>Load older</button>}
        </div>
      </div>
    </>
  );
}
