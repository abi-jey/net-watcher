// Net Watcher - Main Application Entry Point

const { useState, useEffect } = React;
const { CONFIG, AppProvider, useApp, Layout, Pages } = NetWatcher;

/**
 * App Content - Main layout with routing
 */
function AppContent({ activeNav, onNavChange, totalEvents, stats }) {
    const { sidebarCollapsed } = useApp();

    // Render current page based on navigation
    const renderPage = () => {
        switch (activeNav) {
            case 'map':
                return <Pages.NetworkMapPage />;
            case 'stats':
                return <Pages.DashboardPage />;
            case 'events':
            default:
                return <Pages.EventsPage stats={stats} />;
        }
    };

    return (
        <>
            <Layout.Sidebar
                activeNav={activeNav}
                onNavChange={onNavChange}
                totalEvents={totalEvents}
            />
            <main className={`main-content ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
                {renderPage()}
            </main>
        </>
    );
}

/**
 * App - Root Component
 */
function App() {
    const [activeNav, setActiveNav] = useState(() => window.location.hash === '#map' ? 'map' : 'events');
    const [stats, setStats] = useState(null);

    // Update total events from stats
    useEffect(() => {
        let stopped = false;
        let pending = false;
        let warming = true;
        let timer;
        const controller = new AbortController();
        const fetchTotal = async () => {
            if (document.hidden || stopped || pending) return;
            pending = true;
            try {
                const res = await fetch(`${CONFIG.API_BASE}/api/stats`, { signal: controller.signal });
                if (!res.ok) throw new Error(`Statistics request failed: ${res.status}`);
                const data = await res.json();
                if (stopped) return;
                warming = Boolean(data.aggregation?.enabled && !data.aggregation?.ready);
                setStats(data);
            } catch (err) {
                if (err.name !== 'AbortError') console.error('Failed to fetch total:', err);
            } finally {
                pending = false;
            }
        };
        const tick = async () => {
            await fetchTotal();
            if (!stopped) timer = setTimeout(tick, warming ? CONFIG.ANALYTICS_WARMUP_INTERVAL : CONFIG.AUTO_REFRESH_INTERVAL);
        };
        tick();
        const onVisible = () => { if (!document.hidden && !warming) fetchTotal(); };
        document.addEventListener('visibilitychange', onVisible);
        return () => { stopped = true; controller.abort(); clearTimeout(timer); document.removeEventListener('visibilitychange', onVisible); };
    }, []);

    return (
        <AppProvider>
            <AppContent 
                activeNav={activeNav} 
                onNavChange={id => { setActiveNav(id); window.history.replaceState(null, '', `#${id}`); }}
                totalEvents={stats?.totalEvents || 0}
                stats={stats}
            />
        </AppProvider>
    );
}

// Initialize React application
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
