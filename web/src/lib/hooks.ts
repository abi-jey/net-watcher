import { useCallback, useEffect, useRef, useState } from 'react';
import { getJSON } from './api.ts';

export interface Resource<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  updatedAt: number | undefined;
  refresh: () => void;
}

function useVisible(): boolean {
  const [visible, setVisible] = useState(() => !document.hidden);
  useEffect(() => {
    const update = () => setVisible(!document.hidden);
    document.addEventListener('visibilitychange', update);
    return () => document.removeEventListener('visibilitychange', update);
  }, []);
  return visible;
}

/**
 * Fetches `path` and, with `intervalMs`, refreshes it. The next request is
 * scheduled only after the previous one finished, never while the tab is
 * hidden, and in-flight requests are aborted on change or unmount, so an open
 * page costs the server at most one request per interval. Data from the last
 * success is kept when a refresh fails. `getKey` makes `resolve` re-run (for
 * example to recompute a sliding time window) without changing `path`.
 */
export function useResource<T>(path: string | null, intervalMs?: number, resolve?: (path: string) => string): Resource<T> {
  const [state, setState] = useState<{ data?: T; error?: Error; loading: boolean; updatedAt?: number; path?: string }>({ loading: Boolean(path) });
  const [revision, setRevision] = useState(0);
  const visible = useVisible();
  const resolver = useRef(resolve);
  resolver.current = resolve;

  useEffect(() => {
    if (!path || !visible) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = async () => {
      setState(previous => ({ ...previous, loading: true, ...(previous.path !== path ? { data: undefined, error: undefined } : {}), path }));
      try {
        const data = await getJSON<T>(resolver.current ? resolver.current(path) : path, controller.signal);
        setState({ data, loading: false, updatedAt: Date.now(), path });
      } catch (error) {
        if (controller.signal.aborted) return;
        setState(previous => ({ ...previous, error: error as Error, loading: false }));
      }
      if (intervalMs && !controller.signal.aborted) timer = setTimeout(load, intervalMs);
    };
    void load();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [path, intervalMs, visible, revision]);

  const refresh = useCallback(() => setRevision(value => value + 1), []);
  const current = state.path === path;
  return { data: current ? state.data : undefined, error: current ? state.error : undefined, loading: state.loading || !current, updatedAt: state.updatedAt, refresh };
}

/** Hash routing: "#/pods/abc?x=1" → { path: ['pods', 'abc'], query }. */
export function useRoute(): { path: string[]; query: URLSearchParams } {
  const read = () => {
    const hash = window.location.hash.replace(/^#\/?/, '');
    const [path, query = ''] = hash.split('?');
    return { path: path.split('/').filter(Boolean).map(decodeURIComponent), query: new URLSearchParams(query) };
  };
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const update = () => setRoute(read());
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  return route;
}

export function href(path: (string | number)[], query?: Record<string, string | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) if (value) params.set(key, value);
  const encoded = params.toString();
  return `#/${path.map(part => encodeURIComponent(String(part))).join('/')}${encoded ? `?${encoded}` : ''}`;
}

/** Replaces the hash query without adding history entries for every keystroke. */
export function setQuery(path: string[], query: Record<string, string | undefined>) {
  window.history.replaceState(null, '', href(path, query));
  window.dispatchEvent(new HashChangeEvent('hashchange'));
}
