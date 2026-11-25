import { useEffect, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import type { NetworkEvent } from '../lib/api.ts';
import { bytes, count, dateTime, endpoint, isSet } from '../lib/format.ts';
import { deviceName, eventLabel, family, interfaceRole, ipScope, rcodeName, routeInfo, scopeLabel, scopeTag } from '../lib/network.ts';
import { describe, is, negate, type Term } from '../lib/filter.ts';
import type { Flow, Repeat } from '../lib/flows.ts';
import { describeProbe, endProcesses, healthCheckEvidence, healthChecks, isHealthCheck, isKernel, kernelHelp, splitPod, type EndProcess } from '../lib/process.ts';
import { href } from '../lib/hooks.ts';
import { Attribution } from './ui.tsx';
import { Icon } from './icons.tsx';

interface Side { ip: string; port: number; kind: string; namespace: string; name: string; uid: string; workload: string; attribution: string }

const source = (event: NetworkEvent): Side => ({ ip: event.SrcIP, port: event.SrcPort, kind: event.SrcKind, namespace: event.SrcNamespace, name: event.SrcName, uid: event.SrcUID, workload: event.SrcWorkload, attribution: event.SrcAttribution });
const destination = (event: NetworkEvent): Side => ({ ip: event.DstIP, port: event.DstPort, kind: event.DstKind, namespace: event.DstNamespace, name: event.DstName, uid: event.DstUID, workload: event.DstWorkload, attribution: event.DstAttribution });

/** Called with a condition to add to the search: a tag's value, or its negation. */
export type OnFilter = ((condition: Term) => void) | undefined;

/**
 * A tag that adds its value to the search. Selecting it offers "show only"
 * and "hide"; Alt-click hides at once. The menu is positioned on the page,
 * so a row's clipped cells do not cut it off.
 */
function Tag({ className, title, condition, label, onFilter, children }: { className: string; title: string; condition?: Term; label?: string; onFilter: OnFilter; children: ReactNode }) {
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
  // What the condition selects: its label, or field and value ("is" left unsaid).
  const head = label ? <b>{label}</b> : <>{reading.field}{reading.op === 'is' ? '' : ` ${reading.op}`} <b>{value}</b></>;
  const what = label ?? `${reading.field}${reading.op === 'is' ? '' : ` ${reading.op}`} ${value}`;
  const pick = (chosen: Term) => { setAt(undefined); onFilter(chosen); };
  const open = (event: MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    if (event.altKey) { onFilter(negate(condition)); return; }
    const box = event.currentTarget.getBoundingClientRect();
    setAt(current => (current ? undefined : { left: Math.min(box.left, window.innerWidth - 240), top: box.bottom + 4 }));
  };
  return (
    <>
      <button type="button" className={`${className} filterable`} title={`${title.replace(/\.$/, '')}. Select to filter by ${what}; Alt-click hides it.`}
        aria-haspopup="menu" aria-expanded={Boolean(at)} onClick={open} onKeyDown={event => event.stopPropagation()}>
        {children}
      </button>
      {at && (
        <span className="tag-menu" role="menu" ref={menu} style={at} onClick={event => event.stopPropagation()} onKeyDown={event => event.stopPropagation()}>
          <span className="tag-menu-head">{head}</span>
          <button type="button" role="menuitem" onClick={() => pick(condition)}><Icon name="check" size={12} />Show only this</button>
          <button type="button" role="menuitem" onClick={() => pick(negate(condition))}><Icon name="close" size={12} />Hide this</button>
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

/** What a process did, where it runs and how it was identified. */
function processTitle(process: EndProcess, which: 'src' | 'dst'): string {
  if (isKernel(process)) return kernelHelp(which);
  const role = which === 'src' ? 'opened this connection (owns the source socket)' : 'accepted this connection (owns the destination socket)';
  const where = process.pod ? ` in pod ${process.pod}${process.container ? `, container ${process.container}` : ''}` : ' on the node, outside any pod';
  return `Process ${process.command} ${role}${where}; ${process.pid ? `host PID ${process.pid}` : 'identified by its socket owner, PID not readable'}`;
}

/** The process at one end. */
function ProcessTag({ process, which, onFilter }: { process: EndProcess; which: 'src' | 'dst'; onFilter: OnFilter }) {
  return (
    <Tag className="ep-process" title={processTitle(process, which)} condition={is(`${which}.process`, process.command)} onFilter={onFilter}>
      <Icon name="process" size={11} />{process.command || '?'}
    </Tag>
  );
}

/**
 * One end of the connection on one line: kind, name, namespace, the process
 * that owns its socket, and the address. A node's own traffic reads "kubelet
 * on abja"; a host-network pod, which uses its node's addresses, is named.
 */
function Endpoint({ side, which, name, process, event, onFilter }: { side: Side; which: 'src' | 'dst'; name?: string; process?: EndProcess; event: NetworkEvent; onFilter: OnFilter }) {
  const address = endpoint(side.ip, side.port);
  const addressTag = side.ip
    ? <Tag className="ep-addr mono" title={`Address ${side.ip}`} condition={is(`${which}.ip`, side.ip)} onFilter={onFilter}>{address}</Tag>
    : null;
  const processTag = process ? <ProcessTag process={process} which={which} onFilter={onFilter} /> : null;
  if (side.kind === 'node' && process) {
    const node = side.name || side.ip;
    if (process.pod) {
      const pod = splitPod(process.pod);
      return (
        <span className="ep">
          <Tag className="tag k8s pod hostnet" title={`Pod ${process.pod} on the host network of node ${node}: it uses the node's addresses`}
            condition={is(`${which}.process.pod`, process.pod)} onFilter={onFilter}>host-net pod</Tag>
          <span className="ep-name" title={`${process.pod}${process.container ? `, container ${process.container}` : ''}, on node ${node}`}>{pod.name}</span>
          {processTag}
          <span className="ep-on" title={`Node ${node}`}>on {node}</span>
          {addressTag}
        </span>
      );
    }
    return (
      <span className="ep">
        <Tag className="tag k8s node" title="Kubernetes node: a process on the node itself" condition={is(`${which}.kind`, 'node')} onFilter={onFilter}>node</Tag>
        {processTag}
        <span className="ep-on" title={`Node ${node}`}>on <b>{node}</b></span>
        {node !== side.ip && addressTag}
      </span>
    );
  }
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
        {processTag}
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
      {processTag}
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
  if (event.EventType.endsWith('_START')) return <span className="detail-main muted">opened</span>;
  const open = event.EventType.endsWith('_UPDATE');
  const facts = [directions(event) || (event.ByteCount ? bytes(event.ByteCount) : ''), event.Duration ? duration(event.Duration) : '', open ? 'open' : event.Reason].filter(Boolean);
  return facts.length ? <span className="detail-main" title={directionsHelp(event)}>{facts.join(' · ')}</span> : <span className="detail-main muted">—</span>;
}

/** "↑ 6.0 MB ↓ 2.9 KB": sent by the source, by the destination; empty when not counted. */
function directions(event: { SrcBytes?: number; DstBytes?: number }): string {
  return event.SrcBytes || event.DstBytes ? `↑ ${bytes(event.SrcBytes)} ↓ ${bytes(event.DstBytes)}` : '';
}

function directionsHelp(event: NetworkEvent): string | undefined {
  if (!event.SrcBytes && !event.DstBytes) return undefined;
  const since = event.EventType.endsWith('_UPDATE') || event.EventType.endsWith('_END') || event.EventType === 'TIMEOUT'
    ? ` This record accounts for ${bytes(event.ByteCount)} since the flow's previous record.` : '';
  return `↑ sent by the source (the end that opened the flow): ${bytes(event.SrcBytes)} in ${event.SrcPackets ?? 0} packets. ↓ sent by the destination: ${bytes(event.DstBytes)} in ${event.DstPackets ?? 0} packets.${since}`;
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
  const processes = endProcesses(event);
  return (
    <li className={`ev ${kind} ${expanded ? 'open' : ''} ${fresh ? 'fresh' : ''}`}>
      <div className="ev-row" role="button" tabIndex={0} aria-expanded={expanded} onClick={onToggle}
        onKeyDown={key => { if (key.key === 'Enter' || key.key === ' ') { key.preventDefault(); onToggle(); } }}>
        <span className="ev-time mono" title={dateTime(event.Timestamp)}>{rowTime(event.Timestamp)}</span>
        <span className="ev-type"><Tag className={`type ${kind}`} title={event.EventType} condition={is('type', event.EventType)} onFilter={onFilter}>{eventLabel(event.EventType)}</Tag></span>
        <span className="ev-src"><Endpoint side={src} which="src" process={processes.src} event={event} onFilter={onFilter} /></span>
        <span className="ev-arrow" aria-label="to"><Icon name="arrow" size={14} /></span>
        <span className="ev-dst"><Endpoint side={dst} which="dst" name={dst.kind ? undefined : remoteName(event)} process={processes.dst} event={event} onFilter={onFilter} /></span>
        <span className="ev-detail">
          {isHealthCheck(event) && <Tag className="ctx check" title={`Health check: ${describeProbe(event.Probe)}, port ${event.DstPort}. ${healthCheckEvidence(event)}`} condition={healthChecks} label="health checks" onFilter={onFilter}>health check</Tag>}
          <Details event={event} onFilter={onFilter} />
          {route && <Tag className="ctx route" title={`${route.help}${event.TailnetPeer ? ` Device: ${event.TailnetPeerName || event.TailnetPeer}.` : ''}`} condition={is('route', event.Route)} onFilter={onFilter}>{route.label}{peer ? <span className="muted"> · {peer}</span> : null}</Tag>}
          <Tag className="ctx" title={`${event.Interface}: ${link.help}`} condition={link.id ? is('iface.type', link.id) : undefined} onFilter={onFilter}>{link.role}</Tag>
          <Tag className="ctx node" title="Collector (node) that captured the packet" condition={event.CollectorID ? is('node', event.CollectorID) : undefined} onFilter={onFilter}>{event.CollectorID || 'local'}</Tag>
        </span>
      </div>
      {expanded && <EventDetails event={event} />}
    </li>
  );
}

function ProcessFacts({ process, which }: { process: EndProcess; which: 'src' | 'dst' }) {
  if (isKernel(process)) return <><dt>Process</dt><dd><span className="mono">kernel</span><div className="muted small">{kernelHelp(which)}</div></dd></>;
  return <>
    <dt>Process</dt>
    <dd>
      <span className="mono">{process.command || 'unknown'}</span>
      {process.pid
        ? <span className="muted"> · host PID {process.pid}</span>
        : <span className="muted" title="The process runs as another user, so its descriptors are private; its socket's owner identifies one container and command."> · PID not readable</span>}
      <div className="muted small">{which === 'src' ? 'opened' : 'accepted'} this connection{process.pod ? ` · pod ${process.pod}` : ' · node process outside any pod'}{process.container ? ` · container ${process.container}` : ''}</div>
    </dd>
  </>;
}

function SideFacts({ title, side, which, process, event }: { title: string; side: Side; which: 'src' | 'dst'; process?: EndProcess; event: NetworkEvent }) {
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
        {process && <ProcessFacts process={process} which={which} />}
      </dl>
    </section>
  );
}

function EventDetails({ event, records }: { event: NetworkEvent; records?: NetworkEvent[] }) {
  const link = interfaceRole(event.Interface);
  const processes = endProcesses(event);
  const fields = storedFields(event);
  return (
    <div className="ev-details">
      <div className="facts">
        <SideFacts title="Source" side={source(event)} which="src" process={processes.src} event={event} />
        <SideFacts title="Destination" side={destination(event)} which="dst" process={processes.dst} event={event} />
        <section>
          <h3>Capture</h3>
          <dl className="kv">
            <dt>Time</dt><dd>{dateTime(event.Timestamp)}</dd>
            {isSet(event.EndTime) && <><dt>Ended</dt><dd>{dateTime(event.EndTime)}</dd></>}
            <dt>Collector</dt><dd>{event.CollectorID || 'local'}</dd>
            <dt>Interface</dt><dd><span className="mono">{event.Interface || '—'}</span> · {link.role}<div className="muted small">{link.help}</div></dd>
            {routeInfo(event.Route) && <><dt>Tailscale</dt><dd>{routeInfo(event.Route)!.label}{event.TailnetPeer ? ` for ${event.TailnetPeerName || event.TailnetPeer}` : ''}<div className="muted small">{routeInfo(event.Route)!.help}</div></dd></>}
            {isHealthCheck(event) && <><dt>Purpose</dt><dd>Health check: {describeProbe(event.Probe)}, port {event.DstPort}<div className="muted small">{healthCheckEvidence(event)} The kubelet probes only pods on its own node, from the node's address.</div></dd></>}
            <dt>Protocol</dt><dd>{[event.Protocol, event.IPVersion ? `IPv${event.IPVersion}` : ''].filter(Boolean).join(' · ') || '—'}</dd>
            {!event.ProcessSide && <><dt>Process</dt><dd>{event.ProcessCommand ? <>{event.ProcessCommand}{event.ProcessPID ? <span className="muted"> · host PID {event.ProcessPID}</span> : null}</> : (event.Route === 'exit-node' || event.Route === 'subnet-router')
              ? <span className="muted">none: forwarded for a tailnet device, not opened by a process on this node</span>
              : <span className="muted" title="See Processes for why some connections have no process">not attributed</span>}</dd></>}
            {event.SrcBytes || event.DstBytes
              ? <><dt>Bytes</dt><dd>source sent {bytes(event.SrcBytes)} <span className="muted">({count(event.SrcPackets ?? 0)} packets)</span> · destination sent {bytes(event.DstBytes)} <span className="muted">({count(event.DstPackets ?? 0)} packets)</span>
                <div className="muted small">{records ? 'The flow\'s totals.' : event.EventType === 'DNS' ? 'The query and the response.' : `The flow's totals so far.${event.EventType.endsWith('_START') ? '' : ` This record accounts for ${bytes(event.ByteCount)} since the flow's previous record.`}`}</div></dd></>
              : event.ByteCount > 0 && <><dt>Bytes</dt><dd>{bytes(event.ByteCount)} <span className="muted small">both directions</span></dd></>}
          </dl>
        </section>
      </div>
      {records ? <Records records={records} /> : <StoredFields fields={fields} title="All stored fields" />}
      <p className="muted small">{records ? `${records.length} record${records.length === 1 ? '' : 's'}` : `Event #${event.ID}`}. Captured packets are observations; they do not show whether a policy allowed or denied the connection.</p>
    </div>
  );
}

function StoredFields({ fields, title }: { fields: [string, unknown][]; title: string }) {
  return (
    <details className="raw">
      <summary>{title}</summary>
      <dl className="kv">
        {fields.map(([key, value]) => (
          <div key={key} style={{ display: 'contents' }}><dt>{key}</dt><dd className="mono">{typeof value === 'string' && /Context$/.test(key) ? <pre>{JSON.stringify(JSON.parse(value || '{}'), null, 2)}</pre> : String(value)}</dd></div>
        ))}
      </dl>
    </details>
  );
}

function storedFields(event: NetworkEvent): [string, unknown][] {
  return Object.entries(event).filter(([key, value]) => !rawSkip.has(key) && value !== '' && value !== 0 && value !== false && value !== null && value !== undefined && (typeof value !== 'string' || isSet(value)));
}

/** The stored records a row stands for, oldest first, each with its fields. */
function Records({ records }: { records: NetworkEvent[] }) {
  return (
    <section className="flow-records">
      <h3>Records</h3>
      <ol>
        {[...records].reverse().map(record => (
          <li key={record.ID}>
            <details className="raw">
              <summary>
                <span className="mono">{dateTime(record.Timestamp)}</span> · {eventLabel(record.EventType)}{record.DNSType ? ` ${record.DNSType.toLowerCase()}` : ''} · {record.CollectorID || 'local'} <span className="mono">{record.Interface}</span>
                {(record.SrcBytes || record.DstBytes) ? <> · {directions(record)}</> : record.ByteCount ? <> · {bytes(record.ByteCount)}</> : null}
                <span className="muted"> · #{record.ID}</span>
              </summary>
              <StoredFields fields={storedFields(record)} title="Stored fields" />
            </details>
          </li>
        ))}
      </ol>
    </section>
  );
}

/** Filter for the flow's records on each node that recorded it. */
function flowCondition(flow: Flow): Term | undefined {
  const ids = [...new Set(flow.records.map(record => record.FlowID).filter((id): id is string => !!id))];
  return ids.length ? { kind: 'compare', field: 'flow', op: '=', values: ids } : undefined;
}

function nodesTag(nodes: string[], onFilter: OnFilter) {
  return (
    <Tag className="ctx node" title={nodes.length > 1 ? `Recorded by ${nodes.join(' and ')}: each node saw its end` : 'Collector (node) that captured the packets'}
      condition={nodes.length === 1 && nodes[0] !== 'local' ? is('node', nodes[0]) : undefined} onFilter={onFilter}>{nodes.join(' + ')}</Tag>
  );
}

function span(first: string, last: string): string {
  return `First record ${dateTime(first)}, last ${dateTime(last)}`;
}

/**
 * One flow, from all its records: its open, updates and close on every node
 * that saw it, or a DNS lookup's query and response.
 */
export function FlowRow({ flow, expanded, onToggle, onFilter, fresh }: { flow: Flow; expanded: boolean; onToggle: () => void; onFilter?: OnFilter; fresh?: boolean }) {
  const event = flow.merged;
  const kind = flow.kind === 'lookup' ? 'dns' : family(event.EventType);
  const processes = endProcesses(event);
  const link = interfaceRole(event.Interface);
  const route = routeInfo(event.Route);
  const label = flow.kind === 'lookup' ? 'DNS lookup' : `${kind.toUpperCase()} ${flow.open ? 'open' : 'flow'}`;
  const facts = [directions(event) || (event.ByteCount ? bytes(event.ByteCount) : ''), event.Duration ? duration(event.Duration) : '', flow.open ? 'open' : event.Reason].filter(Boolean);
  return (
    <li className={`ev ev-flow ${kind} ${expanded ? 'open' : ''} ${fresh ? 'fresh' : ''}`}>
      <div className="ev-row" role="button" tabIndex={0} aria-expanded={expanded} onClick={onToggle}
        onKeyDown={key => { if (key.key === 'Enter' || key.key === ' ') { key.preventDefault(); onToggle(); } }}>
        <span className="ev-time mono" title={span(flow.first, flow.last)}>{rowTime(flow.last)}</span>
        <span className="ev-type"><Tag className={`type ${kind}`} title={`${flow.records.length} record${flow.records.length === 1 ? '' : 's'} of one ${flow.kind === 'lookup' ? 'DNS lookup' : 'flow'}`} condition={flowCondition(flow)} label="this flow" onFilter={onFilter}>{label}</Tag></span>
        <span className="ev-src"><Endpoint side={source(event)} which="src" process={processes.src} event={event} onFilter={onFilter} /></span>
        <span className="ev-arrow" aria-label="to"><Icon name="arrow" size={14} /></span>
        <span className="ev-dst"><Endpoint side={destination(event)} which="dst" name={event.DstKind ? undefined : remoteName(event)} process={processes.dst} event={event} onFilter={onFilter} /></span>
        <span className="ev-detail">
          {isHealthCheck(event) && <Tag className="ctx check" title={`Health check: ${describeProbe(event.Probe)}, port ${event.DstPort}. ${healthCheckEvidence(event)}`} condition={healthChecks} label="health checks" onFilter={onFilter}>health check</Tag>}
          {flow.kind === 'lookup' ? <Details event={event} onFilter={onFilter} /> : <span className="detail-main" title={directionsHelp(event)}>{facts.join(' · ') || 'opened'}</span>}
          {route && <Tag className="ctx route" title={route.help} condition={is('route', event.Route)} onFilter={onFilter}>{route.label}</Tag>}
          <Tag className="ctx" title={`${event.Interface}: ${link.help}`} condition={link.id ? is('iface.type', link.id) : undefined} onFilter={onFilter}>{link.role}</Tag>
          {nodesTag(flow.nodes, onFilter)}
        </span>
      </div>
      {expanded && <EventDetails event={event} records={flow.records} />}
    </li>
  );
}

/**
 * Flows one opener made to one destination again and again: health checks,
 * a name looked up repeatedly, a port mapping renewed. Expands to the flows.
 */
export function RepeatRow({ repeat, expanded, onToggle, onFilter, fresh, openFlow, onToggleFlow }: {
  repeat: Repeat; expanded: boolean; onToggle: () => void; onFilter?: OnFilter; fresh?: boolean; openFlow?: string; onToggleFlow: (key: string) => void;
}) {
  const newest = repeat.flows[0];
  const peers = repeat.peers;
  const event = peers?.event ?? newest.merged;
  const lookup = newest.kind === 'lookup';
  const kind = lookup ? 'dns' : family(event.EventType);
  const processes = endProcesses(event);
  const n = repeat.flows.length;
  const nodes = [...new Set(repeat.flows.flatMap(flow => flow.nodes))].sort();
  const open = repeat.flows.filter(flow => flow.open).length;
  const facts = [`${n.toLocaleString()} ${lookup ? 'lookups' : 'flows'}${repeat.bursts < n ? ` in ${repeat.bursts.toLocaleString()} burst${repeat.bursts === 1 ? '' : 's'}` : ''}`, repeat.every ? `every ~${duration(repeat.every)}` : '',
    peers && peers.opened < n ? `${peers.opened.toLocaleString()} started by peers` : '',
    directions({ SrcBytes: repeat.sent, DstBytes: repeat.received }), open ? `${open.toLocaleString()} open` : ''].filter(Boolean);
  const typeHelp = peers
    ? `${n.toLocaleString()} flows between this port and ${peers.count.toLocaleString()} addresses outside the cluster, either side sending first; ↑ is what the peers sent, ↓ what the port sent. Select to list them`
    : `${n} ${lookup ? 'lookups of one name' : 'flows'} by one ${event.ProcessSide === 'src' ? 'process' : 'source'} to one destination; select to list them`;
  return (
    <li className={`ev ev-repeat ${kind} ${expanded ? 'open' : ''} ${fresh ? 'fresh' : ''}`}>
      <div className="ev-row" role="button" tabIndex={0} aria-expanded={expanded} onClick={onToggle}
        onKeyDown={key => { if (key.key === 'Enter' || key.key === ' ') { key.preventDefault(); onToggle(); } }}>
        <span className="ev-time mono" title={span(repeat.first, repeat.last)}>{rowTime(repeat.last)}</span>
        <span className="ev-type"><span className={`type ${kind}`} title={typeHelp}>{n.toLocaleString()}× {lookup ? 'DNS' : kind.toUpperCase()}</span></span>
        <span className="ev-src">{peers
          ? <span className="ep" title="Distinct addresses outside the cluster that exchanged traffic with this port"><span className="ep-name">{peers.count.toLocaleString()} peers</span><span className="ep-on">outside the cluster</span></span>
          : <Endpoint side={source(event)} which="src" process={processes.src} event={event} onFilter={onFilter} />}</span>
        <span className="ev-arrow" aria-label="to"><Icon name="arrow" size={14} /></span>
        <span className="ev-dst"><Endpoint side={destination(event)} which="dst" name={event.DstKind ? undefined : remoteName(event)} process={processes.dst} event={event} onFilter={onFilter} /></span>
        <span className="ev-detail">
          {isHealthCheck(event) && <Tag className="ctx check" title={`Health checks: ${describeProbe(event.Probe)}, port ${event.DstPort}. ${healthCheckEvidence(event)}`} condition={healthChecks} label="health checks" onFilter={onFilter}>health check</Tag>}
          {lookup && <span className="detail-main"><strong>{event.DNSQuery}</strong></span>}
          <span className="detail-main">{facts.join(' · ')}</span>
          {nodesTag(nodes, onFilter)}
        </span>
      </div>
      {expanded && (
        <ol className="ev-children" aria-label={`${n} ${lookup ? 'lookups' : 'flows'}`}>
          {repeat.flows.map(flow => <FlowRow key={flow.key} flow={flow} expanded={openFlow === flow.key} onToggle={() => onToggleFlow(flow.key)} onFilter={onFilter} />)}
        </ol>
      )}
    </li>
  );
}
