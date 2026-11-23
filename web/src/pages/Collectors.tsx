import type { HealthResponse } from '../lib/api.ts';
import { useResource } from '../lib/hooks.ts';
import { age, bytes, count, dateTime, duration } from '../lib/format.ts';
import { Badge, Card, Empty, ErrorBanner, Spinner, UpdatedAt, stateTone } from '../components/ui.tsx';

export function Collectors() {
  const health = useResource<HealthResponse>('/api/collectors', 15_000);
  const collectors = health.data?.collectors ?? [];
  const gaps = health.data?.gaps ?? [];
  return (
    <>
      <div className="page-header">
        <div><h1>Collectors</h1><p>Delivery, storage and capture health reported by each node</p></div>
        <UpdatedAt at={health.updatedAt} loading={health.loading} />
      </div>
      <ErrorBanner error={health.error} retry={health.refresh} />
      {health.loading && !health.data && <Spinner />}
      {health.data && !collectors.length && <Empty>No collector has reported. Standalone installations capture locally and have no collectors.</Empty>}
      <div className="grid two">
        {collectors.map(collector => {
          const used = collector.StorageLimitBytes ? collector.StorageBytes / collector.StorageLimitBytes : 0;
          return (
            <Card key={collector.CollectorID} title={<div className="toolbar"><h2>{collector.CollectorID}</h2><Badge tone={stateTone(collector.state)}>{collector.state}</Badge></div>} actions={<span className="muted small">{collector.Version}</span>}>
              {!!collector.problems?.length && <ul style={{ margin: '0 0 12px', paddingLeft: 18 }}>{collector.problems.map(problem => <li key={problem}>{problem}</li>)}</ul>}
              <dl className="kv">
                <dt>Last report</dt><dd title={dateTime(collector.ReportedAt)}>{age(collector.ReportedAt)}</dd>
                <dt>Pending delivery</dt><dd>{count(collector.PendingEvents)} events{collector.PendingEvents > 0 && ` · oldest ${age(collector.OldestPendingAt)}`}</dd>
                <dt>Last acknowledged</dt><dd>{age(collector.LastAcknowledgedAt)}</dd>
                {collector.ConsecutiveFailures > 0 && <><dt>Failures</dt><dd>{collector.ConsecutiveFailures} in a row: {collector.LastError}</dd></>}
                <dt>Storage</dt>
                <dd>
                  {bytes(collector.StorageBytes)}{collector.StorageLimitBytes ? ` of ${bytes(collector.StorageLimitBytes)}` : ''}
                  {collector.StorageLimitBytes > 0 && <div className={`bar ${used > 0.9 ? 'danger' : used > 0.7 ? 'warn' : ''}`} style={{ marginTop: 4 }}><span style={{ width: `${Math.min(100, used * 100)}%` }} /></div>}
                </dd>
                <dt>Kernel capture drops</dt><dd>{count(collector.CaptureDrops)}</dd>
                <dt>Discarded (limits)</dt><dd>{count(collector.DiscardedEvents)}</dd>
                <dt>Missing DNS evidence</dt><dd>{count(collector.MissingEvidence)}</dd>
                <dt>Kubernetes</dt>
                <dd>{collector.InventoryAgeSeconds < 0 ? 'not enabled' : <>inventory {duration(collector.InventoryAgeSeconds)} old · pod watch {collector.PodWatch ? <Badge tone="ok">connected</Badge> : <Badge tone="warn">disconnected</Badge>}</>}</dd>
              </dl>
            </Card>
          );
        })}
      </div>
      <Card title={`Recorded gaps (last ${health.data?.windowHours ?? 24} h)`}>
        {gaps.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Collector</th><th>Reason</th><th className="num">Records</th><th className="num">Observations lost</th><th>Period</th></tr></thead>
              <tbody>
                {gaps.map(gap => (
                  <tr key={`${gap.collectorId}-${gap.reason}`}>
                    <td>{gap.collectorId || 'local'}</td><td>{gap.reason}</td><td className="num">{count(gap.events)}</td><td className="num">{count(gap.lost)}</td>
                    <td className="small">{dateTime(gap.first)} – {dateTime(gap.last)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty>No loss recorded. Gaps are written when packets are dropped by the kernel, a buffer overflows, the collector size limit discards events, or the ingester rejects an event.</Empty>}
      </Card>
    </>
  );
}
