import type { KeyboardEvent, MouseEvent, ReactNode } from 'react';
import type { NetworkEvent } from '../lib/api.ts';
import { bytes, dateTime, endpoint, isSet, time } from '../lib/format.ts';
import { deviceName, eventLabel, family, interfaceRole, ipScope, routeInfo, scopeLabel, scopeTag } from '../lib/network.ts';
import { href } from '../lib/hooks.ts';
import { Attribution } from './ui.tsx';
import { Icon } from './icons.tsx';

interface Side { ip: string; port: number; kind: string; namespace: string; name: string; uid: string; workload: string; attribution: string }

const source = (event: NetworkEvent): Side => ({ ip: event.SrcIP, port: event.SrcPort, kind: event.SrcKind, namespace: event.SrcNamespace, name: event.SrcName, uid: event.SrcUID, workload: event.SrcWorkload, attribution: event.SrcAttribution });
const destination = (event: NetworkEvent): Side => ({ ip: event.DstIP, port: event.DstPort, kind: event.DstKind, namespace: event.DstNamespace, name: event.DstName, uid: event.DstUID, workload: event.DstWorkload, attribution: event.DstAttribution });

/** Query parameters a clicked tag adds to the events search. */
export type Filter = Record<string, string>;
type OnFilter = ((filter: Filter) => void) | undefined;

/** A tag that narrows the search to events sharing it, when clicked. */
function Tag({ className, title, filter, onFilter, children }: { className: string; title: string; filter?: Filter; onFilter: OnFilter; children: ReactNode }) {
  if (!filter || !onFilter) return <span className={className} title={title}>{children}</span>;
  const apply = (event: MouseEvent | KeyboardEvent) => { event.stopPropagation(); onFilter(filter); };
  return (
    <button type="button" className={`${className} filterable`} title={`${title}. Select to show only these events.`} onClick={apply}
      onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); apply(event); } }}>
      {children}
    </button>
  );
}

/** Name for the remote end when no cluster identity is known. */
function remoteName(event: NetworkEvent): string {
  if (event.EventType === 'TLS_SNI') return event.TLSSNI;
  return event.Hostname;
}

function Endpoint({ side, which, name, event, onFilter }: { side: Side; which: 'src' | 'dst'; name?: string; event: NetworkEvent; onFilter: OnFilter }) {
  const address = endpoint(side.ip, side.port);
  if (side.kind) {
    const label = side.kind === 'pod' ? side.name : side.name || side.ip;
    return (
      <div className="ep">
        <div className="ep-main">
          <Tag className={`tag k8s ${side.kind}`} title={`Kubernetes ${side.kind}`} filter={{ [`${which}Kind`]: side.kind }} onFilter={onFilter}>{side.kind}</Tag>
          {side.kind === 'pod' && side.uid ? <a href={href(['pods', 'uid', side.uid])} onClick={event => event.stopPropagation()} className="ep-name" title={`${label}: open pod`}>{label}</a> : <span className="ep-name" title={label}>{label}</span>}
          {side.attribution && side.attribution !== 'exact' && side.kind === 'pod' && <Attribution value={side.attribution} />}
        </div>
        <div className="ep-sub">
          <span className="mono">{address}</span>
          {side.namespace && <Tag className="ns" title={`Namespace ${side.namespace}`} filter={{ namespace: side.namespace }} onFilter={onFilter}>{side.namespace}</Tag>}
          {side.workload && <span title={side.workload}>{side.workload.replace(/^[^/]+\//, '')}</span>}
        </div>
      </div>
    );
  }
  const scope = ipScope(side.ip);
  // The tailnet device this node forwarded for: named by MagicDNS when known.
  if (event.TailnetPeer && event.TailnetPeer === side.ip) {
    const device = event.TailnetPeerName ? deviceName(event.TailnetPeerName) : '';
    return (
      <div className="ep">
        <div className="ep-main">
          <span className="tag scope tailscale" title="Tailnet device">tailnet</span>
          <span className={device ? 'ep-name' : 'ep-name mono'} title={event.TailnetPeerName || address}>{device || address}</span>
        </div>
        {device && <div className="ep-sub"><span className="mono">{address}</span></div>}
      </div>
    );
  }
  return (
    <div className="ep">
      <div className="ep-main">
        <span className={`tag scope ${scope}`} title={scopeLabel(scope)}>{scopeTag(scope)}</span>
        <span className={name ? 'ep-name' : 'ep-name mono'} title={name || address}>{name || address}</span>
      </div>
      {name && <div className="ep-sub"><span className="mono">{address}</span></div>}
    </div>
  );
}

function Details({ event }: { event: NetworkEvent }) {
  switch (event.EventType) {
    case 'GAP':
      return <span className="detail-main">{event.EventCount.toLocaleString()} lost · {event.Reason}</span>;
    case 'DNS':
      return (
        <>
          <span className="detail-main">{event.DNSType === 'RESPONSE' ? 'answer ' : 'query '}<strong>{event.DNSQuery}</strong></span>
          {(event.DNSAnswers || (event.DNSResponseCode && event.DNSResponseCode !== 'NOERROR')) && <span className="detail-sub mono">{event.DNSResponseCode && event.DNSResponseCode !== 'NOERROR' ? event.DNSResponseCode : event.DNSAnswers}</span>}
        </>
      );
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

const rawSkip = new Set(['ID']);

export function EventRow({ event, expanded, onToggle, onFilter }: { event: NetworkEvent; expanded: boolean; onToggle: () => void; onFilter?: (filter: Filter) => void }) {
  const kind = family(event.EventType);
  const link = interfaceRole(event.Interface);
  const route = routeInfo(event.Route);
  const peer = event.TailnetPeerName ? deviceName(event.TailnetPeerName) : event.TailnetPeer;
  const src = source(event), dst = destination(event);
  return (
    <li className={`ev ${kind} ${expanded ? 'open' : ''}`}>
      <div className="ev-row" role="button" tabIndex={0} aria-expanded={expanded} onClick={onToggle}
        onKeyDown={key => { if (key.key === 'Enter' || key.key === ' ') { key.preventDefault(); onToggle(); } }}>
        <div className="ev-time mono" title={dateTime(event.Timestamp)}>{time(event.Timestamp)}</div>
        <div className="ev-type"><span className={`type ${kind}`}>{eventLabel(event.EventType)}</span></div>
        <div className="ev-src"><Endpoint side={src} which="src" event={event} onFilter={onFilter} /></div>
        <div className="ev-arrow" aria-label="to"><Icon name="arrow" /></div>
        <div className="ev-dst"><Endpoint side={dst} which="dst" name={dst.kind ? undefined : remoteName(event)} event={event} onFilter={onFilter} /></div>
        <div className="ev-detail">
          <Details event={event} />
          <span className="ev-context">
            {route && <Tag className="ctx route" title={`${route.help}${event.TailnetPeer ? ` Device: ${event.TailnetPeerName || event.TailnetPeer}.` : ''}`} filter={{ route: event.Route }} onFilter={onFilter}>{route.label}{peer ? <span className="muted"> · {peer}</span> : null}</Tag>}
            {event.ProcessCommand && <Tag className="ctx process" title={processTitle(event)} onFilter={onFilter}
              filter={event.ProcessSide ? { process: event.ProcessCommand, processPod: event.ProcessPod, processContainer: event.ProcessContainer, collector: event.CollectorID } : undefined}>
              <Icon name="process" size={12} />{event.ProcessCommand}{event.ProcessContainer && event.ProcessContainer !== event.ProcessCommand ? <span className="muted"> · {event.ProcessContainer}</span> : null}
            </Tag>}
            <Tag className="ctx" title={`${event.Interface}: ${link.help}`} filter={link.id ? { ifaceRole: link.id } : undefined} onFilter={onFilter}><Icon name="network" size={12} />{link.role}</Tag>
            {event.IPVersion > 0 && <Tag className="ctx" title={`IPv${event.IPVersion}`} filter={{ ipVersion: String(event.IPVersion) }} onFilter={onFilter}>IPv{event.IPVersion}</Tag>}
            <Tag className="ctx" title="Collector (node) that captured the packet" filter={event.CollectorID ? { collector: event.CollectorID } : undefined} onFilter={onFilter}>{event.CollectorID || 'local'}</Tag>
          </span>
        </div>
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
            {!event.ProcessSide && <><dt>Process</dt><dd>{event.ProcessCommand ? <>{event.ProcessCommand}{event.ProcessPID ? <span className="muted"> · host PID {event.ProcessPID}</span> : null}</> : <span className="muted" title="See Processes for why some connections have no process">not attributed</span>}</dd></>}
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
