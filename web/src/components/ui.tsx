import type { ReactNode } from 'react';
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
