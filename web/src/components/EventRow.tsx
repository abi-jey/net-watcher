import { useEffect, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import type { NetworkEvent } from '../lib/api.ts';
import { bytes, dateTime, endpoint, isSet } from '../lib/format.ts';
import { deviceName, eventLabel, family, interfaceRole, ipScope, rcodeName, routeInfo, scopeLabel, scopeTag } from '../lib/network.ts';
import { describe, is, negate, type Compare } from '../lib/filter.ts';
import { href } from '../lib/hooks.ts';
import { Attribution } from './ui.tsx';
import { Icon } from './icons.tsx';

interface Side { ip: string; port: number; kind: string; namespace: string; name: string; uid: string; workload: string; attribution: string }

const source = (event: NetworkEvent): Side => ({ ip: event.SrcIP, port: event.SrcPort, kind: event.SrcKind, namespace: event.SrcNamespace, name: event.SrcName, uid: event.SrcUID, workload: event.SrcWorkload, attribution: event.SrcAttribution });
const destination = (event: NetworkEvent): Side => ({ ip: event.DstIP, port: event.DstPort, kind: event.DstKind, namespace: event.DstNamespace, name: event.DstName, uid: event.DstUID, workload: event.DstWorkload, attribution: event.DstAttribution });

/** Called with a condition to add to the search: a tag's value, or its negation. */
export type OnFilter = ((condition: Compare) => void) | undefined;

/**
 * A tag that adds its value to the search. Selecting it offers "show only"
 * and "hide"; Alt-click hides at once. The menu is positioned on the page,
 * so a row's clipped cells do not cut it off.
 */
function Tag({ className, title, condition, onFilter, children }: { className: string; title: string; condition?: Compare; onFilter: OnFilter; children: ReactNode }) {
  const [at, setAt] = useState<{ left: number; top: number }>();
  const menu = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!at) return;
    const close = (event: Event) => { if (!menu.current?.contains(event.target as Node)) setAt(undefined); };
    const key = (event: KeyboardEvent) => { if (event.key === 'Escape') setAt(undefined); };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', key);
    window.addEventListener('scroll', close, true);
    menu.current?.querySelector('button')?.focus();
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', key); window.removeEventListener('scroll', close, true); };
  }, [at]);
  if (!condition || !onFilter) return <span className={className} title={title}>{children}</span>;
  const reading = describe(condition);
  const value = reading.values.join(', ');
  const pick = (chosen: Compare) => { setAt(undefined); onFilter(chosen); };
  const open = (event: MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    if (event.altKey) { onFilter(negate(condition) as Compare); return; }
    const box = event.currentTarget.getBoundingClientRect();
    setAt(current => (current ? undefined : { left: Math.min(box.left, window.innerWidth - 240), top: box.bottom + 4 }));
  };
  return (
    <>
      <button type="button" className={`${className} filterable`} title={`${title}. Select to filter by ${reading.field} ${value}; Alt-click hides it.`}
        aria-haspopup="menu" aria-expanded={Boolean(at)} onClick={open} onKeyDown={event => event.stopPropagation()}>
        {children}
      </button>
      {at && (
        <span className="tag-menu" role="menu" ref={menu} style={at} onClick={event => event.stopPropagation()} onKeyDown={event => event.stopPropagation()}>
          <span className="tag-menu-head">{reading.field} <b>{value}</b></span>
          <button type="button" role="menuitem" onClick={() => pick(condition)}><Icon name="check" size={12} />Show only this</button>
          <button type="button" role="menuitem" onClick={() => pick(negate(condition) as Compare)}><Icon name="close" size={12} />Hide this</button>
        </span>
      )}
    </>
  );
}

/** Name for the remote end when no cluster identity is known. */
function remoteName(event: NetworkEvent): string {
  if (event.EventType === 'TLS_SNI') return event.TLSSNI;
  return event.Hostname;
}

/** One end of the connection on one line: kind, name, namespace, address. */
function Endpoint({ side, which, name, event, onFilter }: { side: Side; which: 'src' | 'dst'; name?: string; event: NetworkEvent; onFilter: OnFilter }) {
  const address = endpoint(side.ip, side.port);
  const addressTag = side.ip
    ? <Tag className="ep-addr mono" title={`Address ${side.ip}`} condition={is(`${which}.ip`, side.ip)} onFilter={onFilter}>{address}</Tag>
    : null;
  if (side.kind) {
    const label = side.kind === 'pod' ? side.name : side.name || side.ip;
    return (
      <span className="ep">
        <Tag className={`tag k8s ${side.kind}`} title={`Kubernetes ${side.kind}`} condition={is(`${which}.kind`, side.kind)} onFilter={onFilter}>{side.kind}</Tag>
        {side.kind === 'pod' && side.uid
          ? <a href={href(['pods', 'uid', side.uid])} onClick={event => event.stopPropagation()} className="ep-name" title={`${label}${side.workload ? ` (${side.workload})` : ''}: open pod`}>{label}</a>
          : <span className="ep-name" title={label}>{label}</span>}
        {side.attribution && side.attribution !== 'exact' && side.kind === 'pod' && <Attribution value={side.attribution} />}
        {side.namespace && <Tag className="ns" title={`Namespace ${side.namespace}`} condition={is('ns', side.namespace)} onFilter={onFilter}>{side.namespace}</Tag>}
        {label !== side.ip && addressTag}
      </span>
    );
  }
  const scope = ipScope(side.ip);
  // The tailnet device this node forwarded for: named by MagicDNS when known.
  if (event.TailnetPeer && event.TailnetPeer === side.ip) {
    const device = event.TailnetPeerName ? deviceName(event.TailnetPeerName) : '';
    return (
      <span className="ep">
        <span className="tag scope tailscale" title="Tailnet device">tailnet</span>
        {device ? <Tag className="ep-name" title={event.TailnetPeerName} condition={is('peer', event.TailnetPeerName)} onFilter={onFilter}>{device}</Tag> : null}
        {addressTag}
      </span>
    );
  }
  return (
    <span className="ep">
      <span className={`tag scope ${scope}`} title={scopeLabel(scope)}>{scopeTag(scope)}</span>
      {name && <Tag className="ep-name" title={`Name ${name}`} condition={is('domain', name.replace(/\.$/, ''))} onFilter={onFilter}>{name}</Tag>}
      {addressTag}
    </span>
  );
}

function Details({ event, onFilter }: { event: NetworkEvent; onFilter: OnFilter }) {
  switch (event.EventType) {
    case 'GAP':
      return <span className="detail-main">{event.EventCount.toLocaleString()} lost · {event.Reason}</span>;
    case 'DNS': {
      const code = rcodeName(event.DNSResponseCode);
      const failed = code !== '' && code !== 'NOERROR';
      return <>
        {code && <Tag className={`ctx rcode ${failed ? 'failed' : ''}`} title={`DNS response code ${code}${code !== event.DNSResponseCode.trim() ? ` (${event.DNSResponseCode.trim()})` : ''}`} condition={is('rcode', code)} onFilter={onFilter}>{code}</Tag>}
        <span className="detail-main" title={event.DNSAnswers || undefined}>{event.DNSType === 'RESPONSE' ? '' : 'query '}<strong>{event.DNSQuery}</strong>{!failed && event.DNSAnswers ? <span className="muted"> → {event.DNSAnswers}</span> : null}</span>
      </>;
    }
    case 'TLS_SNI':
      return <span className="detail-main">SNI <strong>{event.TLSSNI}</strong></span>;
    case 'ICMP':
      return <span className="detail-main">{event.ICMPDesc}</span>;
  }
  const facts = [event.ByteCount ? bytes(event.ByteCount) : '', event.Duration ? duration(event.Duration) : '', event.Reason].filter(Boolean);
  return facts.length ? <span className="detail-main">{facts.join(' · ')}</span> : <span className="detail-main muted">{event.EventType.endsWith('_START') ? 'opened' : '—'}</span>;
}

function duration(milliseconds: number): string {
  if (milliseconds < 1000) return `${milliseconds} ms`;
  if (milliseconds < 120_000) return `${(milliseconds / 1000).toFixed(1)} s`;
  return `${Math.round(milliseconds / 60_000)} min`;
}

/** Time of day on today's rows, else the date and minute: rows stay narrow. */
function rowTime(value: string): string {
  const date = new Date(value);
  const today = date.toDateString() === new Date().toDateString();
  return date.toLocaleString(undefined, today
    ? { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }
    : { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
}

const rawSkip = new Set(['ID']);

export function EventRow({ event, expanded, onToggle, onFilter, fresh }: { event: NetworkEvent; expanded: boolean; onToggle: () => void; onFilter?: OnFilter; fresh?: boolean }) {
  const kind = family(event.EventType);
  const link = interfaceRole(event.Interface);
  const route = routeInfo(event.Route);
  const peer = event.TailnetPeerName ? deviceName(event.TailnetPeerName) : event.TailnetPeer;
  const src = source(event), dst = destination(event);
  return (
    <li className={`ev ${kind} ${expanded ? 'open' : ''} ${fresh ? 'fresh' : ''}`}>
      <div className="ev-row" role="button" tabIndex={0} aria-expanded={expanded} onClick={onToggle}
        onKeyDown={key => { if (key.key === 'Enter' || key.key === ' ') { key.preventDefault(); onToggle(); } }}>
        <span className="ev-time mono" title={dateTime(event.Timestamp)}>{rowTime(event.Timestamp)}</span>
        <span className="ev-type"><Tag className={`type ${kind}`} title={event.EventType} condition={is('type', event.EventType)} onFilter={onFilter}>{eventLabel(event.EventType)}</Tag></span>
        <span className="ev-src"><Endpoint side={src} which="src" event={event} onFilter={onFilter} /></span>
        <span className="ev-arrow" aria-label="to"><Icon name="arrow" size={14} /></span>
        <span className="ev-dst"><Endpoint side={dst} which="dst" name={dst.kind ? undefined : remoteName(event)} event={event} onFilter={onFilter} /></span>
        <span className="ev-detail">
          <Details event={event} onFilter={onFilter} />
          {route && <Tag className="ctx route" title={`${route.help}${event.TailnetPeer ? ` Device: ${event.TailnetPeerName || event.TailnetPeer}.` : ''}`} condition={is('route', event.Route)} onFilter={onFilter}>{route.label}{peer ? <span className="muted"> · {peer}</span> : null}</Tag>}
          {event.ProcessCommand && <Tag className="ctx process" title={processTitle(event)} condition={is('process', event.ProcessCommand)} onFilter={onFilter}>
            <Icon name="process" size={12} />{event.ProcessCommand}{event.ProcessContainer && event.ProcessContainer !== event.ProcessCommand ? <span className="muted"> · {event.ProcessContainer}</span> : null}
          </Tag>}
          <Tag className="ctx" title={`${event.Interface}: ${link.help}`} condition={link.id ? is('iface.type', link.id) : undefined} onFilter={onFilter}>{link.role}</Tag>
          <Tag className="ctx node" title="Collector (node) that captured the packet" condition={event.CollectorID ? is('node', event.CollectorID) : undefined} onFilter={onFilter}>{event.CollectorID || 'local'}</Tag>
        </span>
      </div>
      {expanded && <EventDetails event={event} />}
    </li>
  );
}

function processTitle(event: NetworkEvent): string {
  const role = event.ProcessSide === 'dst' ? 'accepted this connection (owns the destination socket)' : 'opened this connection (owns the source socket)';
  const where = event.ProcessPod ? ` in pod ${event.ProcessPod}${event.ProcessContainer ? `, container ${event.ProcessContainer}` : ''}` : ' on the node (outside any pod)';
  return `Process that ${role}${where}${event.ProcessPID ? `; host PID ${event.ProcessPID}` : '; identified by its socket owner, PID not readable'}`;
}

function ProcessFacts({ event }: { event: NetworkEvent }) {
  return <>
    <dt>Process</dt>
    <dd>
      <span className="mono">{event.ProcessCommand || 'unknown'}</span>
      {event.ProcessPID
        ? <span className="muted"> · host PID {event.ProcessPID}</span>
        : <span className="muted" title="The process runs as another user, so its descriptors are private; its socket's owner identifies one container and command."> · PID not readable</span>}
      <div className="muted small">{event.ProcessSide === 'dst' ? 'accepted' : 'opened'} this connection{event.ProcessContainer ? ` · container ${event.ProcessContainer}` : ''}{event.ProcessPod ? '' : ' · node process outside any pod'}</div>
    </dd>
  </>;
}

function SideFacts({ title, side, process, event }: { title: string; side: Side; process?: NetworkEvent; event: NetworkEvent }) {
  const scope = ipScope(side.ip);
  const peer = event.TailnetPeer === side.ip;
  return (
    <section>
      <h3>{title}</h3>
      <dl className="kv">
        <dt>Address</dt><dd className="mono">{endpoint(side.ip, side.port)}</dd>
        <dt>Network</dt><dd>{side.kind === 'node' && scope === 'public' ? `internet: a public address of node ${side.name || ''}` : scopeLabel(scope)}</dd>
        {peer && <><dt>Tailnet device</dt><dd>{event.TailnetPeerName || <span className="muted">name not resolved</span>}</dd></>}
        {side.kind ? <>
          <dt>Kubernetes</dt><dd>{side.kind}{side.namespace ? ` in ${side.namespace}` : ''}</dd>
          {side.name && <><dt>Name</dt><dd>{side.name}</dd></>}
          {side.workload && <><dt>Workload</dt><dd>{side.workload}</dd></>}
          {side.uid && <><dt>UID</dt><dd className="mono">{side.uid}</dd></>}
          <dt>Attribution</dt><dd><Attribution value={side.attribution || 'none'} /></dd>
        </> : <><dt>Kubernetes</dt><dd className="muted">{peer ? 'a tailnet device, outside the cluster' : 'not a known cluster address'}</dd></>}
        {process && <ProcessFacts event={process} />}
      </dl>
    </section>
  );
}

function EventDetails({ event }: { event: NetworkEvent }) {
  const link = interfaceRole(event.Interface);
  const fields = Object.entries(event).filter(([key, value]) => !rawSkip.has(key) && value !== '' && value !== 0 && value !== false && value !== null && (typeof value !== 'string' || isSet(value)));
  return (
    <div className="ev-details">
      <div className="facts">
        <SideFacts title="Source" side={source(event)} process={event.ProcessSide === 'src' ? event : undefined} event={event} />
        <SideFacts title="Destination" side={destination(event)} process={event.ProcessSide === 'dst' ? event : undefined} event={event} />
        <section>
          <h3>Capture</h3>
          <dl className="kv">
            <dt>Time</dt><dd>{dateTime(event.Timestamp)}</dd>
            {isSet(event.EndTime) && <><dt>Ended</dt><dd>{dateTime(event.EndTime)}</dd></>}
            <dt>Collector</dt><dd>{event.CollectorID || 'local'}</dd>
            <dt>Interface</dt><dd><span className="mono">{event.Interface || '—'}</span> · {link.role}<div className="muted small">{link.help}</div></dd>
            {routeInfo(event.Route) && <><dt>Tailscale</dt><dd>{routeInfo(event.Route)!.label}{event.TailnetPeer ? ` for ${event.TailnetPeerName || event.TailnetPeer}` : ''}<div className="muted small">{routeInfo(event.Route)!.help}</div></dd></>}
            <dt>Protocol</dt><dd>{[event.Protocol, event.IPVersion ? `IPv${event.IPVersion}` : ''].filter(Boolean).join(' · ') || '—'}</dd>
            {!event.ProcessSide && <><dt>Process</dt><dd>{event.ProcessCommand ? <>{event.ProcessCommand}{event.ProcessPID ? <span className="muted"> · host PID {event.ProcessPID}</span> : null}</> : (event.Route === 'exit-node' || event.Route === 'subnet-router')
              ? <span className="muted">none: forwarded for a tailnet device, not opened by a process on this node</span>
              : <span className="muted" title="See Processes for why some connections have no process">not attributed</span>}</dd></>}
            {event.ByteCount > 0 && <><dt>Bytes</dt><dd>{bytes(event.ByteCount)} <span className="muted small">both directions</span></dd></>}
          </dl>
        </section>
      </div>
      <details className="raw">
        <summary>All stored fields</summary>
        <dl className="kv">
          {fields.map(([key, value]) => (
            <div key={key} style={{ display: 'contents' }}><dt>{key}</dt><dd className="mono">{typeof value === 'string' && /Context$/.test(key) ? <pre>{JSON.stringify(JSON.parse(value || '{}'), null, 2)}</pre> : String(value)}</dd></div>
          ))}
        </dl>
      </details>
      <p className="muted small">Event #{event.ID}. Captured packets are observations; they do not show whether a policy allowed or denied the connection.</p>
    </div>
  );
}
