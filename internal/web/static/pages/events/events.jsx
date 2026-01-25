// Net Watcher - Events Page

window.NetWatcher = window.NetWatcher || {};
window.NetWatcher.Pages = window.NetWatcher.Pages || {};

const { useState, useEffect, useCallback, useRef } = React;
const { CONFIG, Utils, useDebounce, useWebSocket, useApp, Layout, Components } = NetWatcher;

/**
 * Check if an event matches the current filters
 */
function eventMatchesFilters(event, filters) {
    // Check event type filter
    if (filters.eventTypes.length > 0 && !filters.eventTypes.includes(event.EventType)) {
        return false;
    }
    
    // Check source IP filter
    if (filters.srcIP && event.SrcIP && !event.SrcIP.includes(filters.srcIP)) {
        return false;
    }
    
    // Check destination IP filter
    if (filters.dstIP && event.DstIP && !event.DstIP.includes(filters.dstIP)) {
        return false;
    }
    
    // Check query filter (matches hostname, DNS query, TLS SNI, or IPs)
    if (filters.q) {
        const q = filters.q.toLowerCase();
        const searchFields = [
            event.Hostname,
            event.DNSQuery,
            event.TLSSNI,
            event.SrcIP,
            event.DstIP
        ].filter(Boolean).map(s => s.toLowerCase());
        
        if (!searchFields.some(field => field.includes(q))) {
            return false;
        }
    }
    
    return true;
}

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
    
    // Live updates state
    const [liveEnabled, setLiveEnabled] = useState(false);
    const [newEventsBuffer, setNewEventsBuffer] = useState([]);
    const filtersRef = useRef(filters);
    
    // Keep filters ref updated
    useEffect(() => {
        filtersRef.current = filters;
    }, [filters]);

    const { setVersion } = useApp();
    const debouncedFilters = useDebounce(filters);
    const isSearching = JSON.stringify(filters) !== JSON.stringify(debouncedFilters);

    // Handle incoming WebSocket events
    const handleNewEvent = useCallback((event) => {
        // Only add events that match current filters
        if (eventMatchesFilters(event, filtersRef.current)) {
            setNewEventsBuffer(prev => {
                // Keep only most recent 50 buffered events
                const updated = [event, ...prev].slice(0, 50);
                return updated;
            });
        }
    }, []);

    // WebSocket connection
    const { connected, eventCount } = useWebSocket(liveEnabled, handleNewEvent);

    // Merge new events into display when on page 1
    useEffect(() => {
        if (newEventsBuffer.length > 0 && page === 1) {
            setEvents(prev => {
                // Prepend new events and trim to page size
                const merged = [...newEventsBuffer, ...prev];
                // Remove duplicates by ID
                const seen = new Set();
                const unique = merged.filter(e => {
                    if (seen.has(e.ID)) return false;
                    seen.add(e.ID);
                    return true;
                });
                return unique.slice(0, pageSize);
            });
            setTotal(prev => prev + newEventsBuffer.length);
            setNewEventsBuffer([]);
        }
    }, [newEventsBuffer, page, pageSize]);

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
                    liveEnabled={liveEnabled}
                    onLiveToggle={() => setLiveEnabled(prev => !prev)}
                    liveConnected={connected}
                    liveEventCount={eventCount}
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
