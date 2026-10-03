// Net Watcher - Dashboard Page

window.NetWatcher = window.NetWatcher || {};
window.NetWatcher.Pages = window.NetWatcher.Pages || {};

const { useState, useEffect, useCallback } = React;
const { CONFIG, Utils, Icon, UI, Layout } = NetWatcher;

/**
 * Toggle Button Group
 */
function ToggleGroup({ options, value, onChange }) {
    return (
        <div className="toggle-group">
            {options.map(opt => (
                <button
                    key={opt.value}
                    className={`toggle-btn ${value === opt.value ? 'active' : ''}`}
                    onClick={() => onChange(opt.value)}
                >
                    {opt.label}
                </button>
            ))}
        </div>
    );
}

/**
 * Horizontal Bar Chart Row
 */
function BarChartRow({ host, rank, maxValue, metric, totalCount }) {
    const value = metric === 'traffic' ? host.byteCount : host.eventCount;
    const percentage = maxValue > 0 ? (value / maxValue) * 100 : 0;
    
    const displayValue = metric === 'traffic' 
        ? Utils.formatBytes(host.byteCount)
        : Utils.formatNumber(host.eventCount);
    
    const secondaryValue = metric === 'traffic'
        ? `${Utils.formatNumber(host.eventCount)} events`
        : Utils.formatBytes(host.byteCount);

    // Color based on rank
    let colorClass;
    if (rank === 1) colorClass = 'rank-1';
    else if (rank === 2) colorClass = 'rank-2';
    else if (rank === 3) colorClass = 'rank-3';
    else if (rank <= totalCount / 2) colorClass = 'top-half';
    else colorClass = 'bottom-half';

    const rankClass = rank <= 3 ? `rank-${rank}` : 'other';

    return (
        <div className="bar-chart-row">
            <div className={`bar-chart-rank ${rankClass}`}>#{rank}</div>
            <div className="bar-chart-label" title={host.host}>
                {host.host || '(empty)'}
            </div>
            <div className="bar-chart-bar-wrapper">
                <div className="bar-chart-bar">
                    <div 
                        className={`bar-chart-fill ${colorClass}`}
                        style={{ width: `${Math.max(percentage, 8)}%` }}
                    >
                        <span className="bar-chart-value">{displayValue}</span>
                    </div>
                </div>
            </div>
            <div className="bar-chart-secondary">{secondaryValue}</div>
        </div>
    );
}

/**
 * Top Hosts Bar Chart
 */
function TopHostsBarChart({ hosts, metric }) {
    if (!hosts || hosts.length === 0) {
        return (
            <UI.EmptyState
                icon={Icon.BarChart}
                title="No data available"
                description="Start capturing network traffic to see top hosts"
            />
        );
    }

    const maxValue = metric === 'traffic' 
        ? Math.max(...hosts.map(h => h.byteCount))
        : Math.max(...hosts.map(h => h.eventCount));

    return (
        <div className="hosts-chart">
            {hosts.map((host, idx) => (
                <BarChartRow 
                    key={host.host || idx}
                    host={host}
                    rank={idx + 1}
                    maxValue={maxValue}
                    metric={metric}
                    totalCount={hosts.length}
                />
            ))}
        </div>
    );
}

/**
 * Stats Summary Cards
 */
function StatsSummary({ hosts, metric, hostType, total }) {
    const totalEvents = hosts.reduce((sum, h) => sum + h.eventCount, 0);
    const totalBytes = hosts.reduce((sum, h) => sum + h.byteCount, 0);
    const topHost = hosts[0];

    const cards = [
        { 
            label: 'Top ' + (hostType === 'hostname' ? 'Host' : 'IP'),
            value: topHost?.host || '-',
            isText: true
        },
        { 
            label: 'Events (Shown)',
            value: Utils.formatNumber(totalEvents)
        },
        { 
            label: 'Traffic (Shown)',
            value: Utils.formatBytes(totalBytes)
        },
        { 
            label: 'Total Unique',
            value: Utils.formatNumber(total)
        }
    ];

    return (
        <div className="dashboard-stats">
            {cards.map(card => (
                <div key={card.label} className="dashboard-stat-card">
                    <div className={`dashboard-stat-value ${card.isText ? 'text' : ''}`}>
                        {card.value}
                    </div>
                    <div className="dashboard-stat-label">{card.label}</div>
                </div>
            ))}
        </div>
    );
}

/**
 * Dashboard Page
 */
NetWatcher.Pages.DashboardPage = function() {
    const [hosts, setHosts] = useState([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [metric, setMetric] = useState('events'); // 'events' or 'traffic'
    const [hostType, setHostType] = useState('hostname'); // 'hostname', 'srcIP', 'dstIP'
    const [limit, setLimit] = useState(10);
    const [hours, setHours] = useState('24');
    const [warming, setWarming] = useState(true);
    const request = React.useRef(null);

    const fetchTopHosts = useCallback(async () => {
        if (request.current) return;
        const controller = new AbortController();
        request.current = controller;
        setLoading(true);
        try {
            const params = new URLSearchParams({
                metric,
                type: hostType,
                hours,
                limit: limit.toString()
            });
            const res = await fetch(`${CONFIG.API_BASE}/api/top-hosts?${params}`, { signal: controller.signal });
            if (!res.ok) throw new Error(`Top hosts request failed: ${res.status}`);
            const data = await res.json();
            if (controller.signal.aborted) return;
            setWarming(Boolean(data.aggregation?.enabled && !data.aggregation?.ready));
            setHosts(data.hosts || []);
            setTotal(data.total || 0);
        } catch (err) {
            if (err.name !== 'AbortError') console.error('Failed to fetch top hosts:', err);
        }
        if (!controller.signal.aborted) setLoading(false);
        if (request.current === controller) request.current = null;
    }, [metric, hostType, limit, hours]);

    useEffect(() => {
        fetchTopHosts();
        return () => { request.current?.abort(); request.current = null; };
    }, [fetchTopHosts]);

    // Auto-refresh
    useEffect(() => {
        const interval = setInterval(() => { if (!document.hidden) fetchTopHosts(); }, warming ? CONFIG.ANALYTICS_WARMUP_INTERVAL : CONFIG.AUTO_REFRESH_INTERVAL);
        const onVisible = () => { if (!document.hidden && !warming) fetchTopHosts(); };
        document.addEventListener('visibilitychange', onVisible);
        return () => { clearInterval(interval); document.removeEventListener('visibilitychange', onVisible); };
    }, [fetchTopHosts, warming]);

    const metricOptions = [
        { value: 'events', label: 'By Events' },
        { value: 'traffic', label: 'By Traffic' }
    ];

    const hostTypeOptions = [
        { value: 'hostname', label: 'Hostname' },
        { value: 'srcIP', label: 'Source IP' },
        { value: 'dstIP', label: 'Dest IP' }
    ];

    const limitOptions = [
        { value: 10, label: 'Top 10' },
        { value: 20, label: 'Top 20' },
        { value: 50, label: 'Top 50' }
    ];

    return (
        <>
            <header className="header">
                <div className="header-content">
                    <div className="header-title">
                        <div>
                            <h1>Dashboard</h1>
                            <p>Network activity overview</p>
                        </div>
                    </div>
                </div>
            </header>

            <div className="content">
                {/* Traffic Timeline Chart */}
                <NetWatcher.Components.TrafficChart />

                {/* Controls */}
                <div className="dashboard-controls">
                    <div className="control-group">
                        <label className="control-label">Time Range</label>
                        <ToggleGroup
                            options={[
                                { value: '1', label: '1 Hour' },
                                { value: '24', label: '24 Hours' },
                                { value: '168', label: '7 Days' },
                                { value: 'all', label: 'All Retained' }
                            ]}
                            value={hours}
                            onChange={setHours}
                        />
                    </div>
                    <div className="control-group">
                        <label className="control-label">Metric</label>
                        <ToggleGroup 
                            options={metricOptions} 
                            value={metric} 
                            onChange={setMetric} 
                        />
                    </div>
                    <div className="control-group">
                        <label className="control-label">Group By</label>
                        <ToggleGroup 
                            options={hostTypeOptions} 
                            value={hostType} 
                            onChange={setHostType} 
                        />
                    </div>
                    <div className="control-group">
                        <label className="control-label">Limit</label>
                        <ToggleGroup 
                            options={limitOptions} 
                            value={limit} 
                            onChange={setLimit} 
                        />
                    </div>
                </div>

                {/* Stats Summary */}
                {hosts.length > 0 && (
                    <StatsSummary hosts={hosts} metric={metric} hostType={hostType} total={total} />
                )}

                {/* Chart */}
                <div className="dashboard-card">
                    <div className="dashboard-card-header">
                        <h2>
                            Top {limit} {hostType === 'hostname' ? 'Hosts' : hostType === 'srcIP' ? 'Source IPs' : 'Destination IPs'}
                            <span className="dashboard-card-subtitle">
                                {metric === 'traffic' ? 'by Traffic Volume' : 'by Event Count'}
                                {loading && hosts.length > 0 ? ' · Updating…' : ''}
                                {warming ? ' · Historical summaries warming; refresh every 5 minutes' : ''}
                            </span>
                        </h2>
                    </div>
                    <div className="dashboard-card-content">
                        {loading && hosts.length === 0 ? (
                            <UI.LoadingState message="Loading top hosts..." />
                        ) : (
                            <TopHostsBarChart hosts={hosts} metric={metric} />
                        )}
                    </div>
                </div>
            </div>
        </>
    );
};
