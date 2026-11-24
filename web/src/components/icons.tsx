// Stroke icons drawn on a 16px grid; they inherit currentColor.
const paths: Record<string, string> = {
  overview: 'M2.5 2.5h4.5v4.5h-4.5zM9 2.5h4.5v4.5h-4.5zM2.5 9h4.5v4.5h-4.5zM9 9h4.5v4.5h-4.5z',
  events: 'M2.5 4h11M2.5 8h11M2.5 12h7',
  pods: 'M8 1.8l5.5 3.1v6.2L8 14.2l-5.5-3.1V4.9zM8 8l5.5-3.1M8 8L2.5 4.9M8 8v6.2',
  processes: 'M4.5 4.5h7v7h-7zM6.5 1.8v2.7M9.5 1.8v2.7M6.5 11.5v2.7M9.5 11.5v2.7M1.8 6.5h2.7M1.8 9.5h2.7M11.5 6.5h2.7M11.5 9.5h2.7',
  map: 'M2.2 4.5a1.8 1.8 0 1 0 3.6 0a1.8 1.8 0 1 0-3.6 0M10.2 3.5a1.8 1.8 0 1 0 3.6 0a1.8 1.8 0 1 0-3.6 0M6.2 12.5a1.8 1.8 0 1 0 3.6 0a1.8 1.8 0 1 0-3.6 0M5.8 4.3l4.4-.6M4.9 6.1l2.3 4.7M11.3 5.2l-2.5 5.6',
  collectors: 'M2.5 3h11v4h-11zM2.5 9h11v4h-11zM5 5h.01M5 11h.01',
  arrow: 'M2.5 8h10M9 4.5L12.5 8 9 11.5',
  process: 'M3 4.5l3 3.5-3 3.5M7.5 11.5h5.5',
  network: 'M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2zM2 8h12M8 2c1.8 2 1.8 10 0 12M8 2c-1.8 2-1.8 10 0 12',
  check: 'M3 8.5l3 3 7-7',
  close: 'M4 4l8 8M12 4l-8 8',
  plus: 'M8 3v10M3 8h10',
  filter: 'M2.5 3h11l-4.2 5v4.5l-2.6-1.3V8z',
  pause: 'M5.5 3.5v9M10.5 3.5v9',
  play: 'M5 3.5l7 4.5-7 4.5z',
};

export function Icon({ name, size = 16, title }: { name: keyof typeof paths | string; size?: number; title?: string }) {
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden={title ? undefined : true} role={title ? 'img' : undefined}>
      {title && <title>{title}</title>}
      <path d={paths[name] ?? ''} />
    </svg>
  );
}
