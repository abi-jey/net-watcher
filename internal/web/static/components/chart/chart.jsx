// Net Watcher - Traffic Chart Component

window.NetWatcher = window.NetWatcher || {};
window.NetWatcher.Components = window.NetWatcher.Components || {};

const { useState, useEffect, useCallback, useRef, useMemo } = React;
const { CONFIG, Utils, Icon, UI } = NetWatcher;

/**
 * Format bytes for chart axis
 */
function formatAxisBytes(bytes) {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(0) + 'G';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(0) + 'M';
    if (bytes >= 1024) return (bytes / 1024).toFixed(0) + 'K';
    return bytes.toString();
}

/**
 * Format time for chart axis based on bucket size
 */
function formatAxisTime(date, bucketSize) {
    const d = new Date(date);
    switch (bucketSize) {
        case '5min':
        case '30min':
            return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        case '2hour':
        case '6hour':
            return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        case '1day':
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        case '1week':
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        default:
            return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    }
}

/**
 * Quick date range presets
 */
const QUICK_RANGES = [
    { label: '1H', value: 1, unit: 'hour' },
    { label: '4H', value: 4, unit: 'hour' },
    { label: '24H', value: 24, unit: 'hour' },
    { label: '7D', value: 7, unit: 'day' },
    { label: '30D', value: 30, unit: 'day' },
    { label: '90D', value: 90, unit: 'day' }
];

/**
 * Date Range Picker
 */
function DateRangePicker({ startDate, endDate, onStartChange, onEndChange, activeRange, onQuickRange }) {
    return (
        <div className="date-range-controls">
            <div className="date-input-group">
                <label>Start Date</label>
                <input
                    type="datetime-local"
                    className="date-input"
                    value={startDate}
                    onChange={(e) => onStartChange(e.target.value)}
                />
            </div>
            <div className="date-input-group">
                <label>End Date</label>
                <input
                    type="datetime-local"
                    className="date-input"
                    value={endDate}
                    onChange={(e) => onEndChange(e.target.value)}
                />
            </div>
            <div className="date-input-group">
                <label>Quick Select</label>
                <div className="quick-ranges">
                    {QUICK_RANGES.map(range => (
                        <button
                            key={range.label}
                            className={`quick-range-btn ${activeRange === range.label ? 'active' : ''}`}
                            onClick={() => onQuickRange(range)}
                        >
                            {range.label}
                        </button>
                    ))}
                </div>
            </div>
        </div>
    );
}

/**
 * SVG Area Chart
 */
function AreaChart({ data, bucketSize, width = 800, height = 240 }) {
    const [tooltip, setTooltip] = useState(null);
    const chartRef = useRef(null);

    const padding = { top: 20, right: 20, bottom: 40, left: 60 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    // Calculate scales
    const { xScale, yScale, maxY, yTicks, xTicks } = useMemo(() => {
        if (!data || data.length === 0) {
            return { xScale: () => 0, yScale: () => 0, maxY: 0, yTicks: [], xTicks: [] };
        }

        const maxBytes = Math.max(
            ...data.map(d => Math.max(d.bytesIn, d.bytesOut)),
            1
        );
        const maxY = maxBytes * 1.1; // 10% padding

        const xScale = (i) => (i / (data.length - 1 || 1)) * chartWidth;
        const yScale = (v) => chartHeight - (v / maxY) * chartHeight;

        // Generate Y ticks (5 ticks)
        const yTicks = [];
        for (let i = 0; i <= 4; i++) {
            yTicks.push((maxY / 4) * i);
        }

        // Generate X ticks (max 8 ticks)
        const xTicks = [];
        const step = Math.ceil(data.length / 8);
        for (let i = 0; i < data.length; i += step) {
            xTicks.push({ index: i, data: data[i] });
        }

        return { xScale, yScale, maxY, yTicks, xTicks };
    }, [data, chartWidth, chartHeight]);

    // Generate path for area
    const generateAreaPath = (key) => {
        if (!data || data.length === 0) return '';
        
        let path = `M ${xScale(0)} ${chartHeight}`;
        path += ` L ${xScale(0)} ${yScale(data[0][key])}`;
        
        for (let i = 1; i < data.length; i++) {
            path += ` L ${xScale(i)} ${yScale(data[i][key])}`;
        }
        
        path += ` L ${xScale(data.length - 1)} ${chartHeight}`;
        path += ' Z';
        
        return path;
    };

    // Generate path for line
    const generateLinePath = (key) => {
        if (!data || data.length === 0) return '';
        
        let path = `M ${xScale(0)} ${yScale(data[0][key])}`;
        
        for (let i = 1; i < data.length; i++) {
            path += ` L ${xScale(i)} ${yScale(data[i][key])}`;
        }
        
        return path;
    };

    const handleMouseMove = (e, point, index) => {
        const rect = chartRef.current.getBoundingClientRect();
        setTooltip({
            x: e.clientX - rect.left,
            y: e.clientY - rect.top,
            data: point,
            index
        });
    };

    const handleMouseLeave = () => {
        setTooltip(null);
    };

    if (!data || data.length === 0) {
        return (
            <div className="chart-area">
                <div className="chart-empty">
                    <Icon.BarChart />
                    <span>No data for selected range</span>
                </div>
            </div>
        );
    }

    return (
        <div className="chart-area" ref={chartRef}>
            <svg className="traffic-chart-svg" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
                <defs>
                    <linearGradient id="gradientIn" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stopColor="#0ea5e9" stopOpacity="0.6" />
                        <stop offset="100%" stopColor="#0ea5e9" stopOpacity="0.05" />
                    </linearGradient>
                    <linearGradient id="gradientOut" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stopColor="#6366f1" stopOpacity="0.6" />
                        <stop offset="100%" stopColor="#6366f1" stopOpacity="0.05" />
                    </linearGradient>
                </defs>

                <g transform={`translate(${padding.left}, ${padding.top})`}>
                    {/* Grid lines */}
                    {yTicks.map((tick, i) => (
                        <g key={i}>
                            <line
                                className="chart-grid-line"
                                x1={0}
                                y1={yScale(tick)}
                                x2={chartWidth}
                                y2={yScale(tick)}
                            />
                            <text
                                className="chart-axis-label y-axis"
                                x={-10}
                                y={yScale(tick) + 4}
                            >
                                {formatAxisBytes(tick)}
                            </text>
                        </g>
                    ))}

                    {/* X axis labels */}
                    {xTicks.map(({ index, data: d }) => (
                        <text
                            key={index}
                            className="chart-axis-label x-axis"
                            x={xScale(index)}
                            y={chartHeight + 25}
                        >
                            {formatAxisTime(d.timestamp, bucketSize)}
                        </text>
                    ))}

                    {/* Area fills */}
                    <path className="chart-area-out" d={generateAreaPath('bytesOut')} />
                    <path className="chart-area-in" d={generateAreaPath('bytesIn')} />

                    {/* Lines */}
                    <path className="chart-line-out" d={generateLinePath('bytesOut')} />
                    <path className="chart-line-in" d={generateLinePath('bytesIn')} />

                    {/* Data points (show fewer for performance) */}
                    {data.filter((_, i) => i % Math.max(1, Math.floor(data.length / 20)) === 0).map((point, i) => {
                        const actualIndex = i * Math.max(1, Math.floor(data.length / 20));
                        return (
                            <g key={actualIndex}>
                                <circle
                                    className="chart-point chart-point-out"
                                    cx={xScale(actualIndex)}
                                    cy={yScale(point.bytesOut)}
                                    onMouseMove={(e) => handleMouseMove(e, point, actualIndex)}
                                    onMouseLeave={handleMouseLeave}
                                />
                                <circle
                                    className="chart-point chart-point-in"
                                    cx={xScale(actualIndex)}
                                    cy={yScale(point.bytesIn)}
                                    onMouseMove={(e) => handleMouseMove(e, point, actualIndex)}
                                    onMouseLeave={handleMouseLeave}
                                />
                            </g>
                        );
                    })}
                </g>
            </svg>

            {/* Tooltip */}
            {tooltip && (
                <div
                    className="chart-tooltip"
                    style={{
                        left: Math.min(tooltip.x + 10, width - 170),
                        top: Math.max(tooltip.y - 80, 10)
                    }}
                >
                    <div className="tooltip-time">
                        {new Date(tooltip.data.timestamp).toLocaleString()}
                    </div>
                    <div className="tooltip-row">
                        <span className="tooltip-label">Traffic In:</span>
                        <span className="tooltip-value in">{Utils.formatBytes(tooltip.data.bytesIn)}</span>
                    </div>
                    <div className="tooltip-row">
                        <span className="tooltip-label">Traffic Out:</span>
                        <span className="tooltip-value out">{Utils.formatBytes(tooltip.data.bytesOut)}</span>
                    </div>
                    <div className="tooltip-row">
                        <span className="tooltip-label">Events:</span>
                        <span className="tooltip-value">{tooltip.data.eventCount}</span>
                    </div>
                </div>
            )}
        </div>
    );
}

/**
 * Traffic Timeline Chart - Main Component
 */
NetWatcher.Components.TrafficChart = function() {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [bucketSize, setBucketSize] = useState('30min');
    const [totalIn, setTotalIn] = useState(0);
    const [totalOut, setTotalOut] = useState(0);
    const [activeRange, setActiveRange] = useState('24H');
    
    // Date range state
    const now = new Date();
    const defaultStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const [startDate, setStartDate] = useState(defaultStart.toISOString().slice(0, 16));
    const [endDate, setEndDate] = useState(now.toISOString().slice(0, 16));

    const fetchData = useCallback(async () => {
        setLoading(true);
        try {
            const params = new URLSearchParams({
                start: new Date(startDate).toISOString(),
                end: new Date(endDate).toISOString()
            });
            const res = await fetch(`${CONFIG.API_BASE}/api/traffic-timeline?${params}`);
            const result = await res.json();
            setData(result.data || []);
            setBucketSize(result.bucketSize || '30min');
            setTotalIn(result.totalIn || 0);
            setTotalOut(result.totalOut || 0);
        } catch (err) {
            console.error('Failed to fetch traffic timeline:', err);
            setData([]);
        }
        setLoading(false);
    }, [startDate, endDate]);

    useEffect(() => {
        fetchData();
    }, [fetchData]);

    // Auto-refresh
    useEffect(() => {
        const interval = setInterval(fetchData, CONFIG.AUTO_REFRESH_INTERVAL);
        return () => clearInterval(interval);
    }, [fetchData]);

    const handleQuickRange = (range) => {
        const now = new Date();
        let start;
        
        if (range.unit === 'hour') {
            start = new Date(now.getTime() - range.value * 60 * 60 * 1000);
        } else {
            start = new Date(now.getTime() - range.value * 24 * 60 * 60 * 1000);
        }
        
        setStartDate(start.toISOString().slice(0, 16));
        setEndDate(now.toISOString().slice(0, 16));
        setActiveRange(range.label);
    };

    const handleStartChange = (value) => {
        setStartDate(value);
        setActiveRange(null);
    };

    const handleEndChange = (value) => {
        setEndDate(value);
        setActiveRange(null);
    };

    return (
        <div className="traffic-chart-container">
            <div className="dashboard-card">
                <div className="dashboard-card-header">
                    <h2>
                        Network Activity
                        <span className="dashboard-card-subtitle">
                            Traffic over time ({bucketSize} intervals)
                        </span>
                    </h2>
                </div>
                <div className="dashboard-card-content">
                    <DateRangePicker
                        startDate={startDate}
                        endDate={endDate}
                        onStartChange={handleStartChange}
                        onEndChange={handleEndChange}
                        activeRange={activeRange}
                        onQuickRange={handleQuickRange}
                    />

                    {loading ? (
                        <div className="chart-area">
                            <UI.LoadingState message="Loading chart data..." />
                        </div>
                    ) : (
                        <AreaChart data={data} bucketSize={bucketSize} />
                    )}

                    <div className="chart-legend">
                        <div className="legend-item">
                            <div className="legend-color in"></div>
                            <span>Traffic In (to local network)</span>
                        </div>
                        <div className="legend-item">
                            <div className="legend-color out"></div>
                            <span>Traffic Out (from local network)</span>
                        </div>
                    </div>

                    <div className="chart-stats">
                        <div className="chart-stat">
                            <div className="chart-stat-value in">{Utils.formatBytes(totalIn)}</div>
                            <div className="chart-stat-label">Total In</div>
                        </div>
                        <div className="chart-stat">
                            <div className="chart-stat-value out">{Utils.formatBytes(totalOut)}</div>
                            <div className="chart-stat-label">Total Out</div>
                        </div>
                        <div className="chart-stat">
                            <div className="chart-stat-value">{Utils.formatBytes(totalIn + totalOut)}</div>
                            <div className="chart-stat-label">Total Traffic</div>
                        </div>
                        <div className="chart-stat">
                            <div className="chart-stat-value">{data.length}</div>
                            <div className="chart-stat-label">Data Points</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};
