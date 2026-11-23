import { useEffect, useRef, useState, type FormEvent } from 'react';
import { getJSON, url, type EventsResponse, type NetworkEvent } from '../lib/api.ts';
import { setQuery } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { dateTime } from '../lib/format.ts';
import { Banner, Empty, ErrorBanner, Spinner, WindowSelect } from '../components/ui.tsx';
import { EventRow } from '../components/EventRow.tsx';

const eventTypes = ['TCP_START', 'TCP_END', 'UDP_START', 'UDP_END', 'DNS', 'TLS_SNI', 'ICMP', 'TIMEOUT', 'GAP'];
const pageSize = 100;
const liveLimit = 300;

interface Search { window: string; types: string[]; src: string; dst: string; q: string }

function readSearch(query: URLSearchParams): Search {
  return { window: query.get('w') ?? '24h', types: (query.get('type') ?? '').split(',').filter(Boolean), src: query.get('src') ?? '', dst: query.get('dst') ?? '', q: query.get('q') ?? '' };
}

function matches(event: NetworkEvent, search: Search): boolean {
  const has = (value: string, needle: string) => !needle || value.includes(needle);
  return (!search.types.length || search.types.includes(event.EventType)) && has(event.SrcIP, search.src) && has(event.DstIP, search.dst)
    && (!search.q || [event.SrcIP, event.DstIP, event.Hostname, event.DNSQuery, event.TLSSNI].some(value => value.includes(search.q)));
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

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setQuery(['events'], { w: draft.window, type: draft.types.join(','), src: draft.src.trim(), dst: draft.dst.trim(), q: draft.q.trim() });
  };
  const toggleType = (type: string) => setDraft(previous => ({ ...previous, types: previous.types.includes(type) ? previous.types.filter(item => item !== type) : [...previous.types, type] }));
  const filtered = Boolean(search.q || search.src || search.dst);
  const paused = page && !page.complete && (page.events?.length ?? 0) < pageSize;

  return (
    <>
      <div className="page-header">
        <div><h1>Events</h1><p>Every stored observation, newest first</p></div>
        <label className="toolbar small"><input type="checkbox" checked={live} onChange={event => setLive(event.target.checked)} /> Live tail</label>
      </div>
      <form className="card toolbar" onSubmit={submit} style={{ alignItems: 'flex-end' }}>
        <label className="field">Window<WindowSelect value={draft.window} onChange={value => setDraft({ ...draft, window: value })} /></label>
        <label className="field">Source IP<input value={draft.src} onChange={event => setDraft({ ...draft, src: event.target.value })} placeholder="10.0.1." /></label>
        <label className="field">Destination IP<input value={draft.dst} onChange={event => setDraft({ ...draft, dst: event.target.value })} placeholder="any" /></label>
        <label className="field" style={{ flex: 1, minWidth: 200 }}>Search IP, hostname, DNS name or SNI<input value={draft.q} onChange={event => setDraft({ ...draft, q: event.target.value })} placeholder="example.com" /></label>
        <button className="primary" type="submit" disabled={loading}>Search</button>
        <div className="toolbar" role="group" aria-label="Event types" style={{ flexBasis: '100%' }}>
          {eventTypes.map(type => <button key={type} type="button" className="chip" aria-pressed={draft.types.includes(type)} onClick={() => toggleType(type)}>{type}</button>)}
        </div>
      </form>
      <ErrorBanner error={error} retry={() => void load()} />
      {live && <Banner>Live tail: showing new events as they are stored (up to {liveLimit}).{skipped > 0 && ` ${skipped.toLocaleString()} events arrived faster than the live view shows; use Search to see all of them.`}</Banner>}
      {paused && (
        <Banner tone="warn" action={<button onClick={() => void load(page!.nextCursor)} disabled={loading}>Continue search</button>}>
          Searched back to {dateTime(page!.searchedFrom)} of the window starting {dateTime(page!.from)}. The search pauses every few seconds to keep the server responsive; continue to search further back.
        </Banner>
      )}
      <div className="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Destination</th><th>Details</th><th>Captured by</th></tr></thead>
          <tbody>
            {events.map(event => <EventRow key={event.ID} event={event} expanded={expanded === event.ID} onToggle={() => setExpanded(current => current === event.ID ? undefined : event.ID)} />)}
          </tbody>
        </table>
        {!events.length && (loading ? <Empty><Spinner /> Searching…</Empty> : page?.complete ? <Empty>No {filtered || search.types.length ? 'matching ' : ''}events between {dateTime(page.from)} and {dateTime(page.to)}.</Empty> : null)}
        <div className="table-foot">
          <span className="muted small">
            {events.length.toLocaleString()} shown
            {page && (page.complete ? ' · whole window searched' : ` · searched back to ${dateTime(page.searchedFrom)}`)}
          </span>
          {page?.nextCursor && !paused && <button onClick={() => void load(page.nextCursor)} disabled={loading}>{loading ? 'Loading…' : 'Load older'}</button>}
        </div>
      </div>
    </>
  );
}
