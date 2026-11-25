import { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, getJSON, url, type EventsResponse, type HealthResponse, type NetworkEvent } from '../lib/api.ts';
import { setQuery, useResource } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { dateTime } from '../lib/format.ts';
import { addCondition, allOf, conditions, format, fromLegacy, legacyParams, tryParse, type Term } from '../lib/filter.ts';
import { Pacer } from '../lib/pacer.ts';
import { endProcesses } from '../lib/process.ts';
import { groupRecords, type Row } from '../lib/flows.ts';
import { Banner, Empty, ErrorBanner, Segmented, Spinner } from '../components/ui.tsx';
import { EventRow, FlowRow, RepeatRow } from '../components/EventRow.tsx';
import { FilterBar, type Suggestions } from '../components/FilterBar.tsx';
import { Icon } from '../components/icons.tsx';

const pageSize = 100;
const liveLimit = 300;
// Scrolling loads older pages automatically up to this many rows; beyond it a
// button keeps the browser responsive.
const autoLoadLimit = 3000;

/**
 * The search in the URL: the window (w) and the filter expression (f).
 * Links and bookmarks from before filters were expressions carry one-value
 * parameters; they are read into the filter.
 */
function readSearch(query: URLSearchParams): { window: string; text: string; legacy: boolean; view: View } {
  const window = query.get('w') ?? '24h';
  const raw = query.get('f') ?? '';
  const view: View = query.get('v') === 'records' ? 'records' : 'flows';
  const legacy = fromLegacy(query);
  if (!legacy.length) return { window, text: raw, legacy: false, view };
  const parsed = tryParse(raw);
  const text = parsed.error ? [format(allOf(legacy)), `(${raw})`].join(' and ') : format(allOf([...legacy, ...conditions(parsed.term)]));
  return { window, text, legacy: true, view };
}

/**
 * Flows: one row for what happened, from all its records (a flow's open,
 * updates and close on each node, a DNS lookup), and one for flows an opener
 * repeats to one destination. Records: every stored record as it is.
 */
type View = 'flows' | 'records';
const views: { value: View; label: string }[] = [{ value: 'flows', label: 'Flows' }, { value: 'records', label: 'Records' }];

/** Values seen in the loaded events, offered while adding a condition. */
function suggestionsFrom(events: NetworkEvent[], nodes: string[]): Suggestions {
  const sets: Record<string, Set<string>> = {};
  const add = (name: string, ...values: (string | number | undefined)[]) => {
    for (const value of values) if (value !== undefined && value !== '' && value !== 0) (sets[name] ??= new Set()).add(String(value));
  };
  add('node', ...nodes);
  for (const e of events.slice(0, 600)) {
    add('node', e.CollectorID);
    add('ns', e.SrcNamespace, e.DstNamespace);
    add('name', e.SrcName, e.DstName);
    add('workload', e.SrcWorkload, e.DstWorkload);
    add('ip', e.SrcIP, e.DstIP);
    add('port', e.DstPort);
    const ends = endProcesses(e);
    for (const end of ['src', 'dst'] as const) {
      const process = ends[end];
      if (!process) continue;
      add('process', process.command); add(`${end}.process`, process.command);
      add('process.pod', process.pod); add(`${end}.process.pod`, process.pod);
      add('process.container', process.container); add(`${end}.process.container`, process.container);
    }
    add('iface', e.Interface);
    add('domain', e.Hostname?.replace(/\.$/, ''), e.TLSSNI, e.DNSQuery?.replace(/\.$/, ''));
    add('rcode', e.DNSResponseCode);
    add('peer', e.TailnetPeerName, e.TailnetPeer);
  }
  return Object.fromEntries(Object.entries(sets).map(([name, values]) => [name, [...values].sort().slice(0, 60)]));
}

export function Events({ query }: { query: URLSearchParams }) {
  const search = readSearch(query);
  const key = `${search.window}|${search.text}`;
  const collectors = useResource<HealthResponse>('/api/collectors', 60_000);
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [page, setPage] = useState<EventsResponse>();
  const [range, setRange] = useState(() => windowRange(search.window));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error>();
  const [expanded, setExpanded] = useState<string>();
  const [openChild, setOpenChild] = useState<string>();
  const [live, setLive] = useState(false);
  const controller = useRef<AbortController>(undefined);
  const sentinel = useRef<HTMLDivElement>(null);

  // Older one-value links become the filter text in the URL.
  useEffect(() => {
    if (search.legacy) setQuery(['events'], { w: search.window, f: search.text || undefined, v: search.view === 'records' ? 'records' : undefined, ...Object.fromEntries(legacyParams.map(param => [param, undefined])) });
  }, [search.legacy, search.window, search.text, search.view]);

  const viewParam = (view: View) => (view === 'records' ? 'records' : undefined);
  const apply = (text: string, window = search.window) => setQuery(['events'], { w: window, f: text || undefined, v: viewParam(search.view) });
  const setView = (view: View) => { setExpanded(undefined); setOpenChild(undefined); setQuery(['events'], { w: search.window, f: search.text || undefined, v: viewParam(view) }); };
  const onFilter = (condition: Term) => {
    setExpanded(undefined);
    apply(format(addCondition(tryParse(search.text).term, condition)));
  };

  const load = async (cursor?: string, fixedRange = range) => {
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    setLoading(true);
    setError(undefined);
    try {
      const result = await getJSON<EventsResponse>(url('/api/events', { ...fixedRange, f: search.text, limit: pageSize, cursor }), abort.signal);
      setPage(result);
      const received = result.events ?? [];
      setEvents(previous => (cursor ? [...previous, ...received] : received));
    } catch (failure) {
      if (!abort.signal.aborted) setError(failure as Error);
    } finally {
      if (!abort.signal.aborted) setLoading(false);
    }
  };

  // A new search fixes its window so cursors stay valid while paging.
  useEffect(() => {
    if (search.legacy) return;
    const fixed = windowRange(search.window);
    setRange(fixed);
    setExpanded(undefined);
    setEvents([]);
    setPage(undefined);
    void load(undefined, fixed);
    return () => controller.current?.abort();
    // An older link is rewritten to the same filter text: search once the
    // URL no longer carries the older parameters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, search.legacy]);

  const liveTail = useLiveTail(live && !search.legacy, search.text, expanded !== undefined, setEvents);

  // Live rows were added above the search results and the oldest dropped, so
  // the page cursor no longer follows the list: search again when stopping.
  const wasLive = useRef(false);
  useEffect(() => {
    if (wasLive.current && !live) {
      const fixed = windowRange(search.window);
      setRange(fixed);
      void load(undefined, fixed);
    }
    wasLive.current = live;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

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

  const nodes = useMemo(() => (collectors.data?.collectors ?? []).map(collector => collector.CollectorID).filter(Boolean), [collectors.data]);
  const rows = useMemo<Row[]>(() => (search.view === 'flows' ? groupRecords(events)
    : events.map(event => ({ kind: 'record', key: `record|${event.ID}`, last: event.Timestamp, event }))), [events, search.view]);
  const toggle = (key: string) => { setOpenChild(undefined); setExpanded(current => (current === key ? undefined : key)); };
  const fresh = (row: Row) => (row.kind === 'record' ? liveTail.fresh.has(row.event.ID)
    : row.kind === 'flow' ? row.flow.records.some(record => liveTail.fresh.has(record.ID))
      : row.repeat.flows.some(flow => flow.records.some(record => liveTail.fresh.has(record.ID))));
  const suggestions = useMemo(() => suggestionsFrom(events, nodes), [events, nodes]);
  const filtered = search.text.trim() !== '';
  // The server checks values the browser does not (ports, prefixes, units):
  // its objection belongs beside the filter, and retrying cannot help.
  const filterError = error instanceof ApiError && error.status === 400 && error.message.startsWith('filter: ')
    ? error.message.replace(/^filter: /, '').replace(/ \(at \d+\)$/, '') : undefined;

  return (
    <>
      <div className="page-header">
        <div><h1>Events</h1><p>{search.view === 'flows'
          ? 'What happened, newest first: each flow or DNS lookup once, from all its records on every node; flows one process repeats to one destination together. Select a row for its details; select a tag to show only, or hide, what shares it.'
          : 'Every stored record, newest first. Select a row for its details; select a tag in a row to show only, or hide, events sharing it.'}</p></div>
        <div className="live-controls">
          <Segmented label="Show" value={search.view} options={views} onChange={setView} />
          {live && <button type="button" className="ghost small" onClick={liveTail.toggleHold} aria-pressed={liveTail.held}><Icon name={liveTail.held ? 'play' : 'pause'} size={12} />{liveTail.held ? 'Resume' : 'Pause'}</button>}
          <label className="switch"><input type="checkbox" checked={live} onChange={event => setLive(event.target.checked)} /><span>Live tail</span></label>
        </div>
      </div>
      <FilterBar text={search.text} window={search.window} onApply={apply} suggestions={suggestions} busy={loading} serverError={filterError} />
      <ErrorBanner error={filterError ? undefined : error} retry={() => void load(page?.nextCursor && events.length ? page.nextCursor : undefined)} />
      <div className="event-list card flush" onMouseEnter={() => liveTail.setHover(true)} onMouseLeave={() => liveTail.setHover(false)}>
        <div ref={liveTail.top} />
        <div className="ev-sticky">
          {live && <LiveStatus tail={liveTail} />}
          <div className="ev-head" aria-hidden="true">
            <span>Time</span><span>Type</span><span>Source</span><span /><span>Destination</span><span>Details</span>
          </div>
        </div>
        <ol aria-label="Events" aria-live={live ? 'off' : undefined}>
          {rows.map(row => row.kind === 'record'
            ? <EventRow key={row.key} event={row.event} fresh={fresh(row)} expanded={expanded === row.key} onToggle={() => toggle(row.key)} onFilter={onFilter} />
            : row.kind === 'flow'
              ? <FlowRow key={row.key} flow={row.flow} fresh={fresh(row)} expanded={expanded === row.key} onToggle={() => toggle(row.key)} onFilter={onFilter} />
              : <RepeatRow key={row.key} repeat={row.repeat} fresh={fresh(row)} expanded={expanded === row.key} onToggle={() => toggle(row.key)} onFilter={onFilter}
                openFlow={openChild} onToggleFlow={key => setOpenChild(current => (current === key ? undefined : key))} />)}
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
            {events.length.toLocaleString()} records shown{search.view === 'flows' ? ` as ${rows.length.toLocaleString()} row${rows.length === 1 ? '' : 's'}` : ''}
            {page && !live && (page.complete && !page.nextCursor ? ' · whole window searched' : ` · back to ${dateTime(page.searchedFrom)}`)}
          </span>
          {loading && events.length > 0 && <span className="muted small"><Spinner /> Loading older events…</span>}
          {page?.nextCursor && !paused && !loading && !canAutoLoad && !live && <button onClick={() => void load(page.nextCursor)}>Load older</button>}
        </div>
      </div>
    </>
  );
}

interface LiveTail {
  held: boolean;
  /** The server connection: lost connections are retried with backoff. */
  connection: 'connecting' | 'open' | 'retrying';
  /** Whether a connection dropped since the tail started; events stored in
   *  the meantime are only found by searching. */
  interrupted: boolean;
  /** Why rows are not being added: the reader's attention, or the button. */
  reason: string;
  pending: number;
  dropped: number;
  skipped: number;
  rate: number;
  fresh: Set<number>;
  top: React.RefObject<HTMLDivElement | null>;
  setHover: (hover: boolean) => void;
  toggleHold: () => void;
  showNow: () => void;
}

/**
 * The live tail: events matching the filter arrive from the server and are
 * added at a readable pace (lib/pacer.ts). Adding holds while the pointer is
 * over the list, a row is open or the list is scrolled down, so rows do not
 * move under the reader; held events are added on resuming.
 */
function useLiveTail(enabled: boolean, text: string, rowOpen: boolean, setEvents: React.Dispatch<React.SetStateAction<NetworkEvent[]>>): LiveTail {
  const pacer = useRef(new Pacer<NetworkEvent>());
  const fresh = useRef(new Set<number>());
  const top = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [manual, setManual] = useState(false);
  const [stats, setStats] = useState({ pending: 0, dropped: 0, skipped: 0, rate: 0 });
  const [connection, setConnection] = useState<LiveTail['connection']>('connecting');
  const [interrupted, setInterrupted] = useState(false);
  const reason = manual ? 'paused' : rowOpen ? 'a row is open' : scrolled ? 'the list is scrolled down' : hover ? 'the pointer is over the list' : '';
  const held = reason !== '';
  const holding = useRef(held);
  holding.current = held;

  const add = (shown: NetworkEvent[]) => {
    if (!shown.length) return;
    for (const event of shown) fresh.current.add(event.ID);
    if (fresh.current.size > 2 * liveLimit) fresh.current = new Set([...fresh.current].slice(-liveLimit));
    setEvents(previous => {
      const seen = new Set(previous.map(event => event.ID));
      return [...shown.filter(event => !seen.has(event.ID)).reverse(), ...previous].slice(0, liveLimit);
    });
  };

  useEffect(() => {
    const target = top.current;
    if (!enabled || !target || typeof IntersectionObserver === 'undefined') return;
    const observer = new IntersectionObserver(entries => setScrolled(!entries.some(entry => entry.isIntersecting)), { rootMargin: '120px 0px 0px 0px' });
    observer.observe(target);
    return () => observer.disconnect();
  }, [enabled]);

  useEffect(() => {
    if (!enabled) return;
    pacer.current = new Pacer<NetworkEvent>();
    fresh.current = new Set();
    setInterrupted(false);
    let skipped = 0;
    let socket: WebSocket | undefined;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    let stopped = false;
    const address = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${location.pathname.replace(/[^/]*$/, '')}api/ws${text ? `?f=${encodeURIComponent(text)}` : ''}`;
    const connect = () => {
      setConnection(failures ? 'retrying' : 'connecting');
      const current = new WebSocket(address);
      socket = current;
      current.onopen = () => {
        if (failures) setInterrupted(true);
        failures = 0;
        setConnection('open');
      };
      // A restarted server or a dropped network closes the socket; retry
      // with backoff (1 s doubling to 30 s) for as long as the tail is on.
      current.onclose = () => {
        if (stopped) return;
        failures++;
        setConnection('retrying');
        retry = setTimeout(connect, Math.min(30_000, 1000 * 2 ** (failures - 1)));
      };
      current.onmessage = onMessage;
    };
    const onMessage = (message: MessageEvent) => {
      // Messages queued together share a frame, one per line.
      const arrived: NetworkEvent[] = [];
      for (const line of String(message.data).split('\n')) {
        if (!line) continue;
        const data = JSON.parse(line) as { type: string; data?: NetworkEvent; count?: number };
        if (data.type === 'event' && data.data) arrived.push(data.data);
        if (data.type === 'skipped') skipped += data.count ?? 0;
      }
      arrived.sort((a, b) => a.Timestamp.localeCompare(b.Timestamp) || a.ID - b.ID);
      pacer.current.push(arrived, performance.now(), holding.current);
    };
    connect();
    const timer = setInterval(() => {
      const now = performance.now();
      add(pacer.current.take(now, holding.current));
      const next = { pending: pacer.current.pending, dropped: pacer.current.dropped, skipped, rate: Math.round(pacer.current.rate(now) * 10) / 10 };
      setStats(previous => (previous.pending === next.pending && previous.dropped === next.dropped && previous.skipped === next.skipped && previous.rate === next.rate ? previous : next));
    }, 100);
    return () => { stopped = true; socket?.close(); clearTimeout(retry); clearInterval(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, text]);

  return {
    held, connection, interrupted, reason, ...stats, fresh: fresh.current, top, setHover,
    toggleHold: () => setManual(value => !value),
    showNow: () => {
      add(pacer.current.flush());
      setManual(false);
      top.current?.scrollIntoView({ block: 'start', behavior: 'smooth' });
    },
  };
}

function LiveStatus({ tail }: { tail: LiveTail }) {
  const fast = tail.rate > 12;
  const down = tail.connection !== 'open';
  return (
    <div className={`live-status ${down ? 'down' : tail.held ? 'held' : ''}`} role="status">
      <span className="live-dot" aria-hidden="true" />
      {down
        ? <span>{tail.connection === 'connecting' ? 'Connecting to the live stream…' : 'Live stream disconnected; reconnecting…'}</span>
        : tail.held
        ? <span>Holding new rows while {tail.reason}{tail.pending > 0 && <> · <b>{tail.pending}</b> waiting</>}</span>
        : <span>Live · {tail.rate > 0 ? `${tail.rate.toLocaleString()} matching events/s` : 'waiting for matching events'}{fast && ' · showing about 12/s, newest kept'}</span>}
      {(tail.dropped > 0 || tail.skipped > 0) && (
        <span className="muted" title="The live view shows a readable sample of a fast stream; searching shows every stored event.">
          · {(tail.dropped + tail.skipped).toLocaleString()} not shown live; add conditions or search to see all
        </span>
      )}
      {tail.interrupted && <span className="muted" title="Events stored while the live stream was disconnected are not added here; turn off live tail to search them.">· reconnected after a break; search for events in between</span>}
      {tail.held && tail.pending > 0 && <button type="button" className="small" onClick={tail.showNow}>Show now</button>}
    </div>
  );
}
