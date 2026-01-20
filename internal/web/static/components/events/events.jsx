// Net Watcher - Events Table Components

window.NetWatcher = window.NetWatcher || {};
window.NetWatcher.Components = window.NetWatcher.Components || {};

const { Icon, Utils, UI, CONFIG } = NetWatcher;

/**
 * Single Event Row
 */
NetWatcher.Components.EventRow = function({ event }) {
    const details = event.DNSQuery || event.TLSSNI || event.Reason || '-';
    const detailStyle = event.DNSQuery 
        ? { color: 'var(--secondary)' }
        : event.TLSSNI 
            ? { color: 'var(--primary-light)' }
            : { color: 'var(--text-muted)' };

    return (
        <tr>
            <td className="timestamp">{Utils.formatTimestamp(event.Timestamp)}</td>
            <td>
                <UI.Badge variant={Utils.getEventTypeClass(event.EventType)}>
                    {event.EventType}
                </UI.Badge>
            </td>
            <td>
                <div className="ip-address">
                    {event.SrcIP || '-'}{event.SrcPort ? `:${event.SrcPort}` : ''}
                </div>
            </td>
            <td>
                <div className="ip-address">
                    {event.DstIP || '-'}{event.DstPort ? `:${event.DstPort}` : ''}
                </div>
                {event.Hostname && <div className="hostname">{event.Hostname}</div>}
            </td>
            <td className="details-cell">
                <span style={detailStyle}>{details}</span>
            </td>
            <td>{Utils.formatDuration(event.Duration)}</td>
            <td>{Utils.formatBytes(event.ByteCount)}</td>
        </tr>
    );
};

/**
 * Events Data Table
 */
NetWatcher.Components.EventsTable = function({ events, loading }) {
    if (loading) {
        return <UI.LoadingState message="Loading events..." />;
    }

    if (events.length === 0) {
        return (
            <UI.EmptyState
                icon={Icon.Clock}
                title="No events found"
                description="Try adjusting your filters or wait for new network activity"
            />
        );
    }

    const columns = [
        { key: 'timestamp', label: 'Timestamp' },
        { key: 'type', label: 'Type' },
        { key: 'source', label: 'Source' },
        { key: 'destination', label: 'Destination' },
        { key: 'details', label: 'Details' },
        { key: 'duration', label: 'Duration' },
        { key: 'size', label: 'Size' }
    ];

    return (
        <div className="events-table-wrapper">
            <table className="events-table">
                <thead>
                    <tr>
                        {columns.map(col => (
                            <th key={col.key}>{col.label}</th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {events.map(event => (
                        <NetWatcher.Components.EventRow key={event.ID} event={event} />
                    ))}
                </tbody>
            </table>
        </div>
    );
};

/**
 * Pagination Controls
 */
NetWatcher.Components.Pagination = function({ page, totalPages, total, pageSize, onPageChange, onPageSizeChange }) {
    const renderPageNumbers = () => {
        const pages = [];
        const maxVisible = CONFIG.MAX_VISIBLE_PAGES;
        let start = Math.max(1, page - Math.floor(maxVisible / 2));
        let end = Math.min(totalPages, start + maxVisible - 1);

        if (end - start < maxVisible - 1) {
            start = Math.max(1, end - maxVisible + 1);
        }

        for (let i = start; i <= end; i++) {
            pages.push(
                <button
                    key={i}
                    className={`page-btn ${i === page ? 'active' : ''}`}
                    onClick={() => onPageChange(i)}
                >
                    {i}
                </button>
            );
        }

        return pages;
    };

    return (
        <div className="pagination">
            <div className="pagination-info">
                <span>Page {page} of {totalPages || 1}</span>
                <span className="pagination-separator">•</span>
                <span>{Utils.formatNumber(total)} events</span>
                <select 
                    className="page-size-select" 
                    value={pageSize}
                    onChange={(e) => onPageSizeChange(Number(e.target.value))}
                    aria-label="Items per page"
                >
                    {CONFIG.PAGE_SIZE_OPTIONS.map(size => (
                        <option key={size} value={size}>{size} / page</option>
                    ))}
                </select>
            </div>
            <div className="pagination-controls">
                <button
                    className="page-btn"
                    onClick={() => onPageChange(1)}
                    disabled={page <= 1}
                    title="First page"
                    aria-label="First page"
                >
                    <Icon.ChevronsLeft />
                </button>
                <button
                    className="page-btn"
                    onClick={() => onPageChange(page - 1)}
                    disabled={page <= 1}
                    title="Previous page"
                    aria-label="Previous page"
                >
                    <Icon.ChevronLeft />
                </button>
                {renderPageNumbers()}
                <button
                    className="page-btn"
                    onClick={() => onPageChange(page + 1)}
                    disabled={page >= totalPages}
                    title="Next page"
                    aria-label="Next page"
                >
                    <Icon.ChevronRight />
                </button>
                <button
                    className="page-btn"
                    onClick={() => onPageChange(totalPages)}
                    disabled={page >= totalPages}
                    title="Last page"
                    aria-label="Last page"
                >
                    <Icon.ChevronsRight />
                </button>
            </div>
        </div>
    );
};

/**
 * Events Card - Container for table and pagination
 */
NetWatcher.Components.EventsCard = function({ events, loading, total, page, totalPages, pageSize, onPageChange, onPageSizeChange, isSearching }) {
    return (
        <div className="events-card">
            <div className="events-header">
                <span className="events-title">Recent Events</span>
                <span className="events-count">
                    Showing {events.length} of {Utils.formatNumber(total)} events
                    {isSearching && <span className="searching-indicator"> • Searching...</span>}
                </span>
            </div>
            <NetWatcher.Components.EventsTable events={events} loading={loading} />
            {events.length > 0 && (
                <NetWatcher.Components.Pagination
                    page={page}
                    totalPages={totalPages}
                    total={total}
                    pageSize={pageSize}
                    onPageChange={onPageChange}
                    onPageSizeChange={onPageSizeChange}
                />
            )}
        </div>
    );
};
