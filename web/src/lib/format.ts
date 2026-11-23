const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];

export function bytes(value: number | undefined | null): string {
  if (!value) return '0 B';
  let index = 0;
  let amount = value;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
  return `${amount >= 100 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

export function count(value: number | undefined | null): string {
  if (value === undefined || value === null) return '—';
  if (Math.abs(value) < 10_000) return value.toLocaleString();
  const scaled = [[1e9, 'B'], [1e6, 'M'], [1e3, 'k']] as const;
  for (const [size, suffix] of scaled) {
    if (Math.abs(value) >= size) return `${(value / size).toFixed(value >= size * 100 ? 0 : 1)}${suffix}`;
  }
  return String(value);
}

/** Go zero time ("0001-01-01...") and empty strings mean "not recorded". */
export function isSet(value: string | undefined | null): value is string {
  return Boolean(value) && !value!.startsWith('0001-');
}

export function dateTime(value: string | undefined | null): string {
  if (!isSet(value)) return '—';
  return new Date(value).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function time(value: string | undefined | null): string {
  if (!isSet(value)) return '—';
  const date = new Date(value);
  const sameDay = date.toDateString() === new Date().toDateString();
  return date.toLocaleString(undefined, sameDay
    ? { hour: '2-digit', minute: '2-digit', second: '2-digit' }
    : { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function age(value: string | undefined | null, now = Date.now()): string {
  if (!isSet(value)) return 'never';
  return duration(Math.max(0, now - new Date(value).getTime()) / 1000) + ' ago';
}

export function duration(seconds: number): string {
  if (seconds < 1) return '<1 s';
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)} min`;
  if (seconds < 36 * 3600) return `${(seconds / 3600).toFixed(seconds < 10 * 3600 ? 1 : 0)} h`;
  return `${(seconds / 86400).toFixed(1)} d`;
}

export function endpoint(ip: string, port?: number): string {
  if (!port) return ip;
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}
