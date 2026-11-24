import { Component, type ReactNode } from 'react';
import { ApiError } from '../lib/api.ts';
import { windows } from '../lib/window.ts';

export function Card({ title, actions, children, className = '' }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && <header>{typeof title === 'string' ? <h2>{title}</h2> : title}{actions && <div className="toolbar">{actions}</div>}</header>}
      {children}
    </section>
  );
}

export function Stat({ label, value, hint, href }: { label: string; value: ReactNode; hint?: ReactNode; href?: string }) {
  const body = <><span className="label">{label}</span><span className="value">{value}</span>{hint && <span className="hint">{hint}</span>}</>;
  return href ? <a className="card stat" href={href}>{body}</a> : <div className="card stat">{body}</div>;
}

export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'muted';

export function Badge({ tone = 'muted', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return <span className={`badge ${tone}`} title={title}>{children}</span>;
}

export function Banner({ tone = 'info', children, action }: { tone?: 'info' | 'warn' | 'danger'; children: ReactNode; action?: ReactNode }) {
  return <div className={`banner ${tone}`} role={tone === 'danger' ? 'alert' : 'status'}><div>{children}</div>{action}</div>;
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return <span className="spinner" role="status" aria-label={label} />;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/** Explains a failed request; keeps showing stale data is the caller's choice. */
export function ErrorBanner({ error, retry }: { error: Error | undefined; retry?: () => void }) {
  if (!error) return null;
  const status = error instanceof ApiError ? ` (HTTP ${error.status})` : '';
  return <Banner tone="danger" action={retry && <button onClick={retry}>Retry</button>}>Request failed{status}: {error.message}</Banner>;
}

export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: string }[]; onChange: (value: T) => void; label: string }) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map(option => <button key={option.value} type="button" aria-pressed={option.value === value} onClick={() => onChange(option.value)}>{option.label}</button>)}
    </div>
  );
}

export function WindowSelect({ value, onChange, allowed }: { value: string; onChange: (value: string) => void; allowed?: string[] }) {
  return (
    <select aria-label="Time window" value={value} onChange={event => onChange(event.target.value)}>
      {windows.filter(option => !allowed || allowed.includes(option.value)).map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
    </select>
  );
}

export function UpdatedAt({ at, loading }: { at: number | undefined; loading: boolean }) {
  return <span className="muted small" aria-live="polite">{loading ? <><Spinner /> Refreshing</> : at ? `Updated ${new Date(at).toLocaleTimeString()}` : ''}</span>;
}

const stateTones: Record<string, Tone> = { ok: 'ok', degraded: 'warn', backlog: 'warn', failing: 'danger', stale: 'danger' };
export function stateTone(state: string): Tone { return stateTones[state] ?? 'muted'; }

/** What each collector state means for the completeness of the record. */
export const stateHelp: Record<string, { summary: string; meaning: string }> = {
  ok: { summary: 'Capturing and delivering normally', meaning: 'Reports arrive every 30 seconds, nothing is waiting to be forwarded, and no loss was recorded in the last hour.' },
  degraded: { summary: 'Running, but the record has holes', meaning: 'Capture and delivery work, but something reduces completeness or attribution: packets dropped in the last hour, stale Kubernetes inventory, a disconnected pod watch, or nearly full local storage. Every loss is stored as a gap record so you can see exactly which periods are incomplete.' },
  backlog: { summary: 'Behind on forwarding', meaning: 'Events are captured and safely spooled on the node, but the oldest has waited more than 5 minutes to reach the ingester. The central view is incomplete for that period until they arrive; nothing is lost yet.' },
  failing: { summary: 'Cannot forward events', meaning: 'The last delivery attempts to the ingester failed. Events stay in the local spool and are sent in order once delivery recovers; they are discarded only if the spool reaches its size limit.' },
  stale: { summary: 'Not reporting', meaning: 'No report for more than 2 minutes: the collector, its node or its network path may be down. What it captures meanwhile is unknown until it reports again.' },
};

export function StateBadge({ state }: { state: string }) {
  const help = stateHelp[state];
  return <Badge tone={stateTone(state)} title={help ? `${help.summary}. ${help.meaning}` : undefined}>{state}</Badge>;
}

const severityTones: Record<string, 'danger' | 'warn' | 'info'> = { critical: 'danger', warning: 'warn', info: 'info' };
export function IssueList({ issues, compact = false }: { issues: { code: string; severity: string; title: string; detail: string; action?: string }[]; compact?: boolean }) {
  if (!issues.length) return null;
  return (
    <ul className="issues">
      {issues.map(issue => (
        <li key={issue.code} className={`issue ${severityTones[issue.severity] ?? 'info'}`}>
          <div className="issue-title"><Badge tone={severityTones[issue.severity] ?? 'info'}>{issue.severity}</Badge>{issue.title}</div>
          {!compact && <p>{issue.detail}</p>}
          {!compact && issue.action && <p className="issue-action"><strong>What to do:</strong> {issue.action}</p>}
        </li>
      ))}
    </ul>
  );
}

const attributionTones: Record<string, Tone> = { exact: 'ok', ambiguous: 'warn', stale: 'warn', node: 'info', service: 'info', legacy: 'muted', none: 'muted' };
const attributionHelp: Record<string, string> = {
  exact: 'One pod held this address at capture time and the inventory was current.',
  ambiguous: 'The address changed hands near capture time; the newest pod is shown.',
  stale: 'Best candidate, but the inventory had not refreshed for over 90 seconds.',
  node: 'Node or host-network address: the pod cannot be determined from the address.',
  service: 'Service virtual IP: the backend pod is not determined.',
  legacy: 'Captured before indexed attribution existed; only a JSON snapshot is available.',
  none: 'Not a known cluster address.',
};
export function Attribution({ value }: { value: string }) {
  return <Badge tone={attributionTones[value] ?? 'muted'} title={attributionHelp[value]}>{value}</Badge>;
}

/**
 * Keeps a failing page from blanking the whole app: shows what went wrong,
 * with a reload (most often a page of an older build after a deploy).
 */
export class PageBoundary extends Component<{ children: ReactNode }, { error?: Error }> {
  state: { error?: Error } = {};

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Banner tone="danger" action={<button onClick={() => location.reload()}>Reload</button>}>
        This page failed to load: {this.state.error.message}. If Net Watcher was just updated, reloading fetches the new version.
      </Banner>
    );
  }
}
