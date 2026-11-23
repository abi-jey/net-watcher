import type { CollectorHealth, HealthResponse } from '../lib/api.ts';
import { useResource } from '../lib/hooks.ts';
import { age, bytes, count, dateTime, duration } from '../lib/format.ts';
import { Badge, Card, Empty, ErrorBanner, IssueList, Spinner, StateBadge, UpdatedAt, stateHelp } from '../components/ui.tsx';

const gapReasons: Record<string, { label: string; unit: string; help: string }> = {
  'capture-drops': { label: 'Kernel capture drops', unit: 'packets', help: 'The capture ring buffer was full during a burst; the kernel discarded packets before they were read.' },
  'collector-size-limit': { label: 'Storage limit reached', unit: 'events', help: 'The local spool hit its size limit while it could not forward; the oldest unforwarded events were deleted.' },
  'rejected-by-ingester': { label: 'Rejected by ingester', unit: 'events', help: 'Events failed validation at the ingester and were isolated.' },
  'write-buffer-overflow': { label: 'Write buffer overflow', unit: 'events', help: 'Events arrived faster than they could be written.' },
};

function issuesOf(collector: CollectorHealth) {
  return collector.issues ?? (collector.problems ?? []).map(problem => ({ code: problem, severity: 'warning', title: problem, detail: '' }));
}

export function Collectors() {
  const health = useResource<HealthResponse>('/api/collectors', 15_000);
  const collectors = health.data?.collectors ?? [];
  const gaps = health.data?.gaps ?? [];
  return (
    <>
      <div className="page-header">
        <div><h1>Collectors</h1><p>Delivery, storage and capture health reported by each node every 30 seconds</p></div>
        <UpdatedAt at={health.updatedAt} loading={health.loading} />
      </div>
      <ErrorBanner error={health.error} retry={health.refresh} />
      {health.loading && !health.data && <Spinner />}
      {health.data && !collectors.length && <Empty>No collector has reported. Standalone installations capture locally and have no collectors.</Empty>}
      <div className="grid two">
        {collectors.map(collector => {
          const used = collector.StorageLimitBytes ? collector.StorageBytes / collector.StorageLimitBytes : 0;
          const help = stateHelp[collector.state];
          const issues = issuesOf(collector);
          return (
            <Card key={collector.CollectorID} className={`collector ${collector.state}`} title={<div className="toolbar"><h2>{collector.CollectorID}</h2><StateBadge state={collector.state} /></div>} actions={<span className="muted small">{collector.Version}</span>}>
              {help && <p className="state-summary"><strong>{help.summary}.</strong> {collector.state !== 'ok' && help.meaning}</p>}
              <IssueList issues={issues} />
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
                <dt title="Cumulative since the collector process started">Capture drops</dt><dd>{count(collector.CaptureDrops)} packets <span className="muted small">since start</span></dd>
                <dt title="Cumulative since the collector process started">Discarded at limits</dt><dd>{count(collector.DiscardedEvents)} events <span className="muted small">since start</span></dd>
                <dt title="Connections to names whose DNS answer was not captured">Missing DNS evidence</dt><dd>{count(collector.MissingEvidence)}</dd>
                <dt>Kubernetes</dt>
                <dd>{collector.InventoryAgeSeconds < 0 ? 'not enabled' : <>inventory {duration(collector.InventoryAgeSeconds)} old · pod watch {collector.PodWatch ? <Badge tone="ok">connected</Badge> : <Badge tone="warn">disconnected</Badge>}</>}</dd>
              </dl>
            </Card>
          );
        })}
      </div>
      <Card title={`Recorded gaps (last ${health.data?.windowHours ?? 24} h)`}>
        <p className="muted small" style={{ marginTop: 0 }}>Every loss of observations is stored as a GAP event with its time span, so an audit can tell which periods are incomplete. Loss within the last hour marks a collector degraded; older loss is shown here for reference.</p>
        {gaps.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Collector</th><th>Reason</th><th className="num">Bursts</th><th className="num">Lost</th><th>Period</th></tr></thead>
              <tbody>
                {gaps.map(gap => {
                  const reason = gapReasons[gap.reason];
                  return (
                    <tr key={`${gap.collectorId}-${gap.reason}`}>
                      <td>{gap.collectorId || 'local'}</td>
                      <td><div className="cell-main">{reason?.label ?? gap.reason}</div>{reason && <div className="cell-sub">{reason.help}</div>}</td>
                      <td className="num">{count(gap.events)}</td>
                      <td className="num">{count(gap.lost)} <span className="muted small">{reason?.unit ?? 'observations'}</span></td>
                      <td className="small nowrap">{dateTime(gap.first)} –<br />{dateTime(gap.last)} <span className="muted">({age(gap.last)})</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <Empty>No loss recorded. Gaps are written when packets are dropped by the kernel, a buffer overflows, the collector size limit discards events, or the ingester rejects an event.</Empty>}
      </Card>
      <Card title="What the states mean">
        <dl className="states">
          {Object.entries(stateHelp).map(([state, help]) => (
            <div key={state} className="state-row"><dt><StateBadge state={state} /></dt><dd><strong>{help.summary}.</strong> {help.meaning}</dd></div>
          ))}
        </dl>
      </Card>
    </>
  );
}
