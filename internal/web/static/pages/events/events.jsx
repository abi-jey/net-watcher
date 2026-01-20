// Net Watcher - Events Page

window.NetWatcher = window.NetWatcher || {};
window.NetWatcher.Pages = window.NetWatcher.Pages || {};

const { useState, useEffect, useCallback } = React;
const { CONFIG, Utils, useDebounce, useApp, Layout, Components } = NetWatcher;

/**
 * Events Page - Main events view
 */
NetWatcher.Pages.EventsPage = function() {
    const [events, setEvents] = useState([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(CONFIG.DEFAULT_PAGE_SIZE);
    const [totalPages, setTotalPages] = useState(0);
    const [loading, setLoading] = useState(true);
    const [stats, setStats] = useState(null);
    const [eventTypes, setEventTypes] = useState([]);
    const [filters, setFilters] = useState({
        q: '',
        eventTypes: [],
        srcIP: '',
        dstIP: ''
    });

    const { setVersion } = useApp();
    const debouncedFilters = useDebounce(filters);
    const isSearching = JSON.stringify(filters) !== JSON.stringify(debouncedFilters);

    // Fetch events
    const fetchEvents = useCallback(async () => {
        setLoading(true);
        const params = Utils.buildQueryParams({
            page,
            pageSize,
            q: debouncedFilters.q,
            srcIP: debouncedFilters.srcIP,
            dstIP: debouncedFilters.dstIP,
            eventType: debouncedFilters.eventTypes
        });

        try {
            const res = await fetch(`${CONFIG.API_BASE}/api/events?${params}`);
            const data = await res.json();
            setEvents(data.events || []);
            setTotal(data.total || 0);
            setTotalPages(data.totalPages || 0);
        } catch (err) {
            console.error('Failed to fetch events:', err);
            setEvents([]);
        }
        setLoading(false);
    }, [page, pageSize, debouncedFilters]);

    // Fetch stats
    const fetchStats = useCallback(async () => {
        try {
            const res = await fetch(`${CONFIG.API_BASE}/api/stats`);
            setStats(await res.json());
        } catch (err) {
            console.error('Failed to fetch stats:', err);
        }
    }, []);

    // Fetch event types
    const fetchEventTypes = useCallback(async () => {
        try {
            const res = await fetch(`${CONFIG.API_BASE}/api/event-types`);
            const types = await res.json();
            setEventTypes(types || []);
        } catch (err) {
            console.error('Failed to fetch event types:', err);
        }
    }, []);

    // Fetch version
    const fetchVersion = useCallback(async () => {
        try {
            const res = await fetch(`${CONFIG.API_BASE}/api/version`);
            const data = await res.json();
            setVersion(data.version ? `v${data.version}` : 'v1.0.0');
        } catch (err) {
            setVersion('v1.0.0');
        }
    }, [setVersion]);

    // Reset page when filters change
    useEffect(() => {
        setPage(1);
    }, [debouncedFilters]);

    // Fetch events when dependencies change
    useEffect(() => {
        fetchEvents();
    }, [fetchEvents]);

    // Initial data load
    useEffect(() => {
        fetchStats();
        fetchEventTypes();
        fetchVersion();
    }, [fetchStats, fetchEventTypes, fetchVersion]);

    // Auto-refresh stats
    useEffect(() => {
        const interval = setInterval(fetchStats, CONFIG.AUTO_REFRESH_INTERVAL);
        return () => clearInterval(interval);
    }, [fetchStats]);

    return (
        <>
            <Layout.Header stats={stats} />
            <div className="content">
                <Components.Filters
                    filters={filters}
                    onFiltersChange={setFilters}
                    eventTypes={eventTypes}
                    isSearching={isSearching}
                />
                <Components.EventsCard
                    events={events}
                    loading={loading}
                    total={total}
                    page={page}
                    totalPages={totalPages}
                    pageSize={pageSize}
                    onPageChange={setPage}
                    onPageSizeChange={setPageSize}
                    isSearching={isSearching}
                />
            </div>
        </>
    );
};
