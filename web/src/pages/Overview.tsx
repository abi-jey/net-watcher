import { useState } from 'react';
import { url, type HealthResponse, type StatsResponse, type TimelineResponse, type TopHostsResponse } from '../lib/api.ts';
import { useResource } from '../lib/hooks.ts';
import { windowRange } from '../lib/window.ts';
import { age, bytes, count } from '../lib/format.ts';
import { Badge, Banner, Card, Empty, ErrorBanner, Segmented, Spinner, Stat, UpdatedAt, stateTone } from '../components/ui.tsx';
import { HostBars, TimelineChart } from '../components/charts.tsx';

export function Overview() {
  const [metric, setMetric] = useState<'eventCount' | 'bytes'>('eventCount');
  const stats = useResource<StatsResponse>('/api/stats', 60_000);
  const health = useResource<HealthResponse>('/api/collectors', 30_000);
  // Hour-aligned start: answered from hourly summaries plus the current hour.
  const timeline = useResource<TimelineResponse>('timeline:24h', 60_000, () => {
    const { from, to } = windowRange('24h');
    return url('/api/traffic-timeline', { start: from, end: to });
  });
  const hostnames = useResource<TopHostsResponse>(url('/api/top-hosts', { metric: 'events', type: 'hostname', hours: 24, limit: 8 }), 120_000);
  const destinations = useResource<TopHostsResponse>(url('/api/top-hosts', { metric: 'traffic', type: 'dstIP', hours: 24, limit: 8 }), 120_000);

  const collectors = health.data?.collectors ?? [];
  const gaps = health.data?.gaps ?? [];
  const lost = gaps.reduce((total, gap) => total + gap.lost, 0);
  const attention = collectors.filter(collector => collector.state !== 'ok');
  const warming = stats.data?.aggregation.enabled && !stats.data.aggregation.ready;

  return (
    <>
      <div className="page-header">
        <div><h1>Overview</h1><p>Captured network observations across all collectors</p></div>
        <UpdatedAt at={stats.updatedAt} loading={stats.loading} />
      </div>
      <ErrorBanner error={stats.error ?? health.error} retry={() => { stats.refresh(); health.refresh(); }} />
      {attention.length > 0 && (
        <Banner tone="warn" action={<a className="button" href="#/collectors">Details</a>}>
          {attention.map(collector => <div key={collector.CollectorID}><strong>{collector.CollectorID}</strong> is {collector.state}{collector.problems?.length ? `: ${collector.problems.join('; ')}` : ''}</div>)}
        </Banner>
      )}
      {warming && <Banner>Hourly summaries are being built ({count(stats.data!.aggregation.cursor)} of {count(stats.data!.aggregation.target)} events). Totals and charts are exact but slower until then.</Banner>}
      <div className="grid stats">
        <Stat label="Events retained" value={stats.data ? count(stats.data.totalEvents) : '—'} hint={stats.data?.firstEvent ? `since ${new Date(stats.data.firstEvent).toLocaleString()}` : undefined} href="#/events" />
        <Stat label="Last event" value={stats.data ? age(stats.data.lastEvent) : '—'} hint="Most recent observation stored" />
        <Stat label="Collectors" value={health.data ? (collectors.length ? `${collectors.length - attention.length}/${collectors.length}` : 'none') : '—'} hint={!collectors.length ? 'standalone capture' : attention.length ? `${attention.length} need attention` : 'all healthy'} href="#/collectors" />
        <Stat label="Known loss (24 h)" value={health.data ? count(lost) : '—'} hint={gaps.length ? `${gaps.length} gap record(s)` : 'no gaps recorded'} href="#/collectors" />
      </div>
      <Card title="Activity, last 24 hours" actions={<Segmented label="Chart metric" value={metric} onChange={setMetric} options={[{ value: 'eventCount', label: 'Events' }, { value: 'bytes', label: 'Bytes' }]} />}>
        {timeline.data?.data?.length ? <TimelineChart points={timeline.data.data} metric={metric} /> : timeline.loading ? <Spinner /> : <Empty>No activity in this window.</Empty>}
        {timeline.data && <p className="muted small">Bucket {timeline.data.bucketSize} · {bytes(timeline.data.totalIn)} in · {bytes(timeline.data.totalOut)} out</p>}
      </Card>
      <div className="grid two">
        <Card title="Top names (24 h, events)">
          {hostnames.data?.hosts?.length ? <HostBars hosts={hostnames.data.hosts} metric="events" /> : hostnames.loading ? <Spinner /> : <Empty>No names resolved.</Empty>}
        </Card>
        <Card title="Top destinations (24 h, bytes)">
          {destinations.data?.hosts?.length ? <HostBars hosts={destinations.data.hosts} metric="traffic" /> : destinations.loading ? <Spinner /> : <Empty>No traffic recorded.</Empty>}
        </Card>
      </div>
      <div className="grid two">
        <Card title="Event types">
          {stats.data ? (
            <div className="hbar">
              {Object.entries(stats.data.eventCounts ?? {}).sort((a, b) => b[1] - a[1]).map(([type, total]) => (
                <div key={type} style={{ display: 'contents' }}>
                  <a className="name" href={`#/events?type=${encodeURIComponent(type)}`}>{type}</a>
                  <span className="muted small">{count(total)}</span>
                  <span className="track"><span style={{ width: `${(total / Math.max(1, stats.data!.totalEvents)) * 100}%` }} /></span>
                </div>
              ))}
            </div>
          ) : <Spinner />}
        </Card>
        <Card title="Collectors">
          {collectors.length ? collectors.map(collector => (
            <div key={collector.CollectorID} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0' }}>
              <Badge tone={stateTone(collector.state)}>{collector.state}</Badge>
              <span className="cell-main">{collector.CollectorID}</span>
              <span className="muted small" style={{ marginLeft: 'auto' }}>reported {age(collector.ReportedAt)}</span>
            </div>
          )) : health.loading ? <Spinner /> : <Empty>No collectors have reported. In standalone mode this list is empty.</Empty>}
        </Card>
      </div>
    </>
  );
}
