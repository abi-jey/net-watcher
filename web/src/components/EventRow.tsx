import type { NetworkEvent } from '../lib/api.ts';
import { bytes, dateTime, endpoint, isSet, time } from '../lib/format.ts';
import { Attribution, Badge, type Tone } from './ui.tsx';

const typeTones: Record<string, Tone> = { DNS: 'info', TLS_SNI: 'ok', TCP_START: 'muted', TCP_END: 'muted', UDP_START: 'muted', UDP_END: 'muted', ICMP: 'warn', TIMEOUT: 'warn', GAP: 'danger' };

function Side({ ip, port, kind, namespace, name, workload, attribution }: { ip: string; port: number; kind: string; namespace: string; name: string; workload: string; attribution: string }) {
  return (
    <>
      <div className="cell-main mono">{endpoint(ip, port)}</div>
      {kind && <div className="cell-sub">{kind === 'pod' ? `${namespace}/${name}` : `${kind}${name ? ` ${name}` : ''}`}{workload ? ` · ${workload}` : ''} {attribution && attribution !== 'exact' && <Attribution value={attribution} />}</div>}
    </>
  );
}

export function summary(event: NetworkEvent): string {
  if (event.EventType === 'GAP') return `${event.EventCount} observation(s) lost: ${event.Reason}`;
  if (event.EventType === 'DNS') return `${event.DNSType === 'RESPONSE' ? '←' : '→'} ${event.DNSQuery}${event.DNSAnswers ? ` = ${event.DNSAnswers}` : ''}${event.DNSResponseCode && event.DNSResponseCode !== 'NOERROR' ? ` (${event.DNSResponseCode})` : ''}`;
  if (event.EventType === 'TLS_SNI') return event.TLSSNI;
  if (event.EventType === 'ICMP') return event.ICMPDesc;
  const parts = [event.Hostname, event.ByteCount ? bytes(event.ByteCount) : '', event.Duration ? `${event.Duration} ms` : '', event.Reason].filter(Boolean);
  return parts.join(' · ');
}

export function EventRow({ event, expanded, onToggle }: { event: NetworkEvent; expanded: boolean; onToggle: () => void }) {
  return (
    <>
      <tr className={`clickable ${expanded ? 'selected' : ''}`} onClick={onToggle} onKeyDown={key => { if (key.key === 'Enter' || key.key === ' ') { key.preventDefault(); onToggle(); } }} tabIndex={0} aria-expanded={expanded}>
        <td className="nowrap mono small" title={dateTime(event.Timestamp)}>{time(event.Timestamp)}</td>
        <td><Badge tone={typeTones[event.EventType] ?? 'muted'}>{event.EventType}</Badge></td>
        <td><Side ip={event.SrcIP} port={event.SrcPort} kind={event.SrcKind} namespace={event.SrcNamespace} name={event.SrcName} workload={event.SrcWorkload} attribution={event.SrcAttribution} /></td>
        <td><Side ip={event.DstIP} port={event.DstPort} kind={event.DstKind} namespace={event.DstNamespace} name={event.DstName} workload={event.DstWorkload} attribution={event.DstAttribution} /></td>
        <td style={{ maxWidth: 360, overflowWrap: 'anywhere' }}>{summary(event)}</td>
        <td className="cell-sub nowrap">{event.CollectorID || 'local'} · {event.Interface}</td>
      </tr>
      {expanded && (
        <tr><td colSpan={6} className="details">
          <dl className="kv">
            {Object.entries(event).filter(([key, value]) => key !== 'ID' && value !== '' && value !== 0 && value !== false && value !== null && (typeof value !== 'string' || isSet(value))).map(([key, value]) => (
              <div key={key} style={{ display: 'contents' }}><dt>{key}</dt><dd className="mono">{typeof value === 'string' && /Context$/.test(key) ? <pre>{JSON.stringify(JSON.parse(value || '{}'), null, 2)}</pre> : String(value)}</dd></div>
            ))}
          </dl>
          <p className="muted small">Event #{event.ID}. Captured packets are observations; they do not show whether a policy allowed or denied the connection.</p>
        </td></tr>
      )}
    </>
  );
}
