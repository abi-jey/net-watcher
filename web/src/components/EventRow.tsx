import type { NetworkEvent } from '../lib/api.ts';
import { bytes, dateTime, endpoint, isSet, time } from '../lib/format.ts';
import { eventLabel, family, interfaceRole, ipScope, scopeLabel } from '../lib/network.ts';
import { href } from '../lib/hooks.ts';
import { Attribution } from './ui.tsx';
import { Icon } from './icons.tsx';

interface Side { ip: string; port: number; kind: string; namespace: string; name: string; uid: string; workload: string; attribution: string }

const source = (event: NetworkEvent): Side => ({ ip: event.SrcIP, port: event.SrcPort, kind: event.SrcKind, namespace: event.SrcNamespace, name: event.SrcName, uid: event.SrcUID, workload: event.SrcWorkload, attribution: event.SrcAttribution });
const destination = (event: NetworkEvent): Side => ({ ip: event.DstIP, port: event.DstPort, kind: event.DstKind, namespace: event.DstNamespace, name: event.DstName, uid: event.DstUID, workload: event.DstWorkload, attribution: event.DstAttribution });

/** Name for the remote end when no cluster identity is known. */
function remoteName(event: NetworkEvent): string {
  if (event.EventType === 'TLS_SNI') return event.TLSSNI;
  return event.Hostname;
}

function Endpoint({ side, name }: { side: Side; name?: string }) {
  const address = endpoint(side.ip, side.port);
  if (side.kind) {
    const label = side.kind === 'pod' ? side.name : side.name || side.ip;
    return (
      <div className="ep">
        <div className="ep-main">
          <span className={`tag k8s ${side.kind}`} title={`Kubernetes ${side.kind}`}>{side.kind}</span>
          {side.kind === 'pod' && side.uid ? <a href={href(['pods', 'uid', side.uid])} onClick={event => event.stopPropagation()} className="ep-name">{label}</a> : <span className="ep-name">{label}</span>}
          {side.attribution && side.attribution !== 'exact' && side.kind === 'pod' && <Attribution value={side.attribution} />}
        </div>
        <div className="ep-sub">
          {side.namespace && <span>{side.namespace}</span>}
          {side.workload && <span>{side.workload.replace(/^[^/]+\//, '')}</span>}
          <span className="mono">{address}</span>
        </div>
      </div>
    );
  }
  const scope = ipScope(side.ip);
  return (
    <div className="ep">
      <div className="ep-main">
        <span className={`tag scope ${scope}`} title={side.attribution === 'node' ? 'Node or host-network address' : undefined}>{scopeLabel(scope)}</span>
        <span className={name ? 'ep-name' : 'ep-name mono'}>{name || address}</span>
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

export function EventRow({ event, expanded, onToggle }: { event: NetworkEvent; expanded: boolean; onToggle: () => void }) {
  const kind = family(event.EventType);
  const link = interfaceRole(event.Interface);
  const src = source(event), dst = destination(event);
  return (
    <li className={`ev ${kind} ${expanded ? 'open' : ''}`}>
      <div className="ev-row" role="button" tabIndex={0} aria-expanded={expanded} onClick={onToggle}
        onKeyDown={key => { if (key.key === 'Enter' || key.key === ' ') { key.preventDefault(); onToggle(); } }}>
        <div className="ev-time mono" title={dateTime(event.Timestamp)}>{time(event.Timestamp)}</div>
        <div className="ev-type"><span className={`type ${kind}`}>{eventLabel(event.EventType)}</span></div>
        <div className="ev-src"><Endpoint side={src} /></div>
        <div className="ev-arrow" aria-label="to"><Icon name="arrow" /></div>
        <div className="ev-dst"><Endpoint side={dst} name={dst.kind ? undefined : remoteName(event)} /></div>
        <div className="ev-detail">
          <Details event={event} />
          <span className="ev-context">
            {event.ProcessCommand && <span className="ctx process" title={`Process observed through procfs${event.ProcessPID ? `, host PID ${event.ProcessPID}` : ''}`}><Icon name="process" size={12} />{event.ProcessCommand}</span>}
            <span className="ctx" title={`${event.Interface}: ${link.help}`}><Icon name="network" size={12} />{link.role}</span>
            {event.IPVersion > 0 && <span className="ctx">IPv{event.IPVersion}</span>}
            <span className="ctx" title="Collector (node) that captured the packet">{event.CollectorID || 'local'}</span>
          </span>
        </div>
      </div>
      {expanded && <EventDetails event={event} />}
    </li>
  );
}

function SideFacts({ title, side }: { title: string; side: Side }) {
  const scope = ipScope(side.ip);
  return (
    <section>
      <h3>{title}</h3>
      <dl className="kv">
        <dt>Address</dt><dd className="mono">{endpoint(side.ip, side.port)}</dd>
        <dt>Network</dt><dd>{scopeLabel(scope)}</dd>
        {side.kind ? <>
          <dt>Kubernetes</dt><dd>{side.kind}{side.namespace ? ` in ${side.namespace}` : ''}</dd>
          {side.name && <><dt>Name</dt><dd>{side.name}</dd></>}
          {side.workload && <><dt>Workload</dt><dd>{side.workload}</dd></>}
          {side.uid && <><dt>UID</dt><dd className="mono">{side.uid}</dd></>}
          <dt>Attribution</dt><dd><Attribution value={side.attribution || 'none'} /></dd>
        </> : <><dt>Kubernetes</dt><dd className="muted">not a known cluster address</dd></>}
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
        <SideFacts title="Source" side={source(event)} />
        <SideFacts title="Destination" side={destination(event)} />
        <section>
          <h3>Capture</h3>
          <dl className="kv">
            <dt>Time</dt><dd>{dateTime(event.Timestamp)}</dd>
            {isSet(event.EndTime) && <><dt>Ended</dt><dd>{dateTime(event.EndTime)}</dd></>}
            <dt>Collector</dt><dd>{event.CollectorID || 'local'}</dd>
            <dt>Interface</dt><dd><span className="mono">{event.Interface || '—'}</span> · {link.role}<div className="muted small">{link.help}</div></dd>
            <dt>Protocol</dt><dd>{[event.Protocol, event.IPVersion ? `IPv${event.IPVersion}` : ''].filter(Boolean).join(' · ') || '—'}</dd>
            <dt>Process</dt><dd>{event.ProcessCommand ? <>{event.ProcessCommand}{event.ProcessPID ? <span className="muted"> · host PID {event.ProcessPID}</span> : null}</> : <span className="muted">not attributed</span>}</dd>
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
