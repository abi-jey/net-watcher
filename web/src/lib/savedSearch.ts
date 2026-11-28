import { legacyParams } from './filter.ts';

/**
 * The Events search kept between visits when asked: its window (w), filter
 * (f) and view (v), in this browser's local storage. Nothing is sent to the
 * server, and another browser keeps its own.
 */
export interface SearchParams {
  w: string;
  f?: string;
  v?: 'records';
}

const storageKey = 'nw-events-search';

function local(): Storage | undefined {
  try {
    return typeof localStorage === 'undefined' ? undefined : localStorage;
  } catch {
    return undefined; // Storage disabled: nothing is kept.
  }
}

/** The kept search; none when remembering is off. */
export function savedSearch(storage = local()): SearchParams | undefined {
  try {
    const raw = storage?.getItem(storageKey);
    if (!raw) return undefined;
    const value = JSON.parse(raw) as Partial<Record<keyof SearchParams, unknown>>;
    if (typeof value.w !== 'string' || !value.w) return undefined;
    return { w: value.w, f: typeof value.f === 'string' && value.f ? value.f : undefined, v: value.v === 'records' ? 'records' : undefined };
  } catch {
    return undefined;
  }
}

export function saveSearch(search: SearchParams, storage = local()) {
  try {
    storage?.setItem(storageKey, JSON.stringify(search));
  } catch {
    // Full or disabled: the search is not kept.
  }
}

export function forgetSearch(storage = local()) {
  try {
    storage?.removeItem(storageKey);
  } catch {
    // Disabled: nothing was kept.
  }
}

/**
 * Whether an Events address names a search. One that does (a reload, a link
 * from another page) shows it; one that does not (the sidebar, a new tab)
 * opens the kept search.
 */
export function namesSearch(query: URLSearchParams): boolean {
  return ['w', 'f', 'v', ...legacyParams].some(param => query.has(param));
}

/** The kept search as an address's query. */
export function asQuery(search: SearchParams): URLSearchParams {
  const query = new URLSearchParams({ w: search.w });
  if (search.f) query.set('f', search.f);
  if (search.v) query.set('v', search.v);
  return query;
}
