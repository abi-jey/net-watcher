import type { TimelinePoint, HostTotal } from '../lib/api.ts';
import { bytes, count } from '../lib/format.ts';

/** Bar chart of events per bucket; each bar has an accessible title. */
export function TimelineChart({ points, metric }: { points: TimelinePoint[]; metric: 'eventCount' | 'bytes' }) {
  const width = 800, height = 180, left = 44, bottom = 22, top = 8;
  const values = points.map(point => metric === 'eventCount' ? point.eventCount : point.bytesIn + point.bytesOut);
  const peak = Math.max(1, ...values);
  const step = (width - left) / Math.max(1, points.length);
  const format = metric === 'eventCount' ? count : bytes;
  const labelEvery = Math.max(1, Math.ceil(points.length / 8));
  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={`${metric === 'eventCount' ? 'Events' : 'Traffic'} over time, peak ${format(peak)}`}>
      {[0, 0.5, 1].map(fraction => {
        const y = top + (height - top - bottom) * (1 - fraction);
        return <g key={fraction}><line className="grid-line" x1={left} x2={width} y1={y} y2={y} /><text className="axis" x={left - 6} y={y + 4} textAnchor="end">{format(peak * fraction)}</text></g>;
      })}
      {points.map((point, index) => {
        const value = values[index];
        const barHeight = (height - top - bottom) * (value / peak);
        const date = new Date(point.timestamp);
        return (
          <g key={point.timestamp}>
            <rect className="bar-rect" x={left + index * step + 1} y={height - bottom - barHeight} width={Math.max(1, step - 2)} height={barHeight}>
              <title>{`${date.toLocaleString()}: ${format(value)}`}</title>
            </rect>
            {index % labelEvery === 0 && <text className="axis" x={left + index * step + step / 2} y={height - 6} textAnchor="middle">{date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</text>}
          </g>
        );
      })}
    </svg>
  );
}

export function HostBars({ hosts, metric }: { hosts: HostTotal[]; metric: 'events' | 'traffic' }) {
  const value = (host: HostTotal) => metric === 'events' ? host.eventCount : host.byteCount;
  const peak = Math.max(1, ...hosts.map(value));
  return (
    <div className="hbar">
      {hosts.map(host => (
        <div key={host.host} style={{ display: 'contents' }}>
          <span className="name mono" title={host.host}>{host.host}</span>
          <span className="muted small">{metric === 'events' ? count(host.eventCount) : bytes(host.byteCount)}</span>
          <span className="track"><span style={{ width: `${(value(host) / peak) * 100}%` }} /></span>
        </div>
      ))}
    </div>
  );
}
