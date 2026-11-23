// Time windows offered across pages. Windows longer than an hour start on a
// UTC hour boundary so the server answers from hourly summaries plus only the
// current partial hour, instead of scanning raw events at both edges.

export interface WindowOption { value: string; label: string; seconds: number }

export const windows: WindowOption[] = [
  { value: '15m', label: 'Last 15 minutes', seconds: 900 },
  { value: '1h', label: 'Last hour', seconds: 3600 },
  { value: '6h', label: 'Last 6 hours', seconds: 6 * 3600 },
  { value: '24h', label: 'Last 24 hours', seconds: 24 * 3600 },
  { value: '7d', label: 'Last 7 days', seconds: 7 * 24 * 3600 - 3600 },
];

export function windowOption(value: string): WindowOption {
  return windows.find(option => option.value === value) ?? windows[3];
}

export function windowRange(value: string, now = new Date()): { from: string; to: string } {
  const option = windowOption(value);
  let start = now.getTime() - option.seconds * 1000;
  if (option.seconds > 3600) start = Math.floor(start / 3_600_000) * 3_600_000;
  // Second precision keeps URLs stable between renders within the same second.
  const iso = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');
  return { from: iso(start), to: iso(now.getTime() + 1000) };
}
