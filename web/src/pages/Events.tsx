import { useEffect, useRef, useState, type FormEvent } from 'react';
import { getJSON, url, type EventsResponse, type NetworkEvent } from '../lib/api.ts';
import { setQuery } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { dateTime } from '../lib/format.ts';
import { eventLabel, family } from '../lib/network.ts';
import { Banner, Empty, ErrorBanner, Spinner, WindowSelect } from '../components/ui.tsx';
import { EventRow } from '../components/EventRow.tsx';

const eventTypes = ['TCP_START', 'TCP_END', 'UDP_START', 'UDP_END', 'DNS', 'TLS_SNI', 'ICMP', 'TIMEOUT', 'GAP'];
const pageSize = 100;
const liveLimit = 300;
// Scrolling loads older pages automatically up to this many rows; beyond it a
// button keeps the browser responsive.
const autoLoadLimit = 3000;

interface Search { window: string; types: string[]; src: string; dst: string; q: string }

function readSearch(query: URLSearchParams): Search {
  return { window: query.get('w') ?? '24h', types: (query.get('type') ?? '').split(',').filter(Boolean), src: query.get('src') ?? '', dst: query.get('dst') ?? '', q: query.get('q') ?? '' };
}

function matches(event: NetworkEvent, search: Search): boolean {
  const has = (value: string, needle: string) => !needle || value.includes(needle);
  return (!search.types.length || search.types.includes(event.EventType)) && has(event.SrcIP, search.src) && has(event.DstIP, search.dst)
    && (!search.q || [event.SrcIP, event.DstIP, event.Hostname, event.DNSQuery, event.TLSSNI, event.SrcName, event.DstName, event.SrcNamespace, event.DstNamespace, event.SrcWorkload, event.DstWorkload, event.ProcessCommand].some(value => value?.includes(search.q)));
}

export function Events({ query }: { query: URLSearchParams }) {
  const search = readSearch(query);
  const key = query.toString();
  const [draft, setDraft] = useState(search);
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
        ...fixedRange, limit: pageSize, cursor, eventType: search.types.join(','), srcIP: search.src, dstIP: search.dst, q: search.q,
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
    setQuery(['events'], { w: draft.window, type: draft.types.join(','), src: draft.src.trim(), dst: draft.dst.trim(), q: draft.q.trim() });
  };
  const toggleType = (type: string) => setDraft(previous => ({ ...previous, types: previous.types.includes(type) ? previous.types.filter(item => item !== type) : [...previous.types, type] }));
  const filtered = Boolean(search.q || search.src || search.dst || search.types.length);

  return (
    <>
      <div className="page-header">
        <div><h1>Events</h1><p>Every stored observation, newest first. Select a row for its source, destination and capture details.</p></div>
        <label className="switch"><input type="checkbox" checked={live} onChange={event => setLive(event.target.checked)} /><span>Live tail</span></label>
      </div>
      <form className="card filters" onSubmit={submit}>
        <label className="field grow">Search<input type="search" value={draft.q} onChange={event => setDraft({ ...draft, q: event.target.value })} placeholder="IP, DNS name, SNI, pod, namespace, workload or process" /></label>
        <label className="field">Window<WindowSelect value={draft.window} onChange={value => setDraft({ ...draft, window: value })} /></label>
        <label className="field">Source IP<input value={draft.src} onChange={event => setDraft({ ...draft, src: event.target.value })} placeholder="10.0.1." size={12} /></label>
        <label className="field">Destination IP<input value={draft.dst} onChange={event => setDraft({ ...draft, dst: event.target.value })} placeholder="any" size={12} /></label>
        <button className="primary" type="submit" disabled={loading}>Search</button>
        <div className="chips" role="group" aria-label="Event types">
          {eventTypes.map(type => (
            <button key={type} type="button" className="chip" aria-pressed={draft.types.includes(type)} onClick={() => toggleType(type)} title={type}>
              <span className={`swatch ${family(type)}`} />{eventLabel(type)}
            </button>
          ))}
          {draft.types.length > 0 && <button type="button" className="ghost small" onClick={() => setDraft({ ...draft, types: [] })}>Clear types</button>}
        </div>
      </form>
      <ErrorBanner error={error} retry={() => void load(page?.nextCursor && events.length ? page.nextCursor : undefined)} />
      {live && <Banner>Live tail: new events appear as they are stored (newest {liveLimit} kept).{skipped > 0 && ` ${skipped.toLocaleString()} events arrived faster than the live view shows; turn live tail off and search to see all of them.`}</Banner>}
      <div className="event-list card flush">
        <div className="ev-head" aria-hidden="true">
          <span>Time</span><span>Type</span><span>Source</span><span /><span>Destination</span><span>Details</span>
        </div>
        <ol aria-label="Events">
          {events.map(event => <EventRow key={event.ID} event={event} expanded={expanded === event.ID} onToggle={() => setExpanded(current => current === event.ID ? undefined : event.ID)} />)}
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
