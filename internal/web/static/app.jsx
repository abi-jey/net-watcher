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
        const fetchTotal = async () => {
            if (document.hidden) return;
            try {
                const res = await fetch(`${CONFIG.API_BASE}/api/stats`);
                const data = await res.json();
                setStats(data);
            } catch (err) {
                console.error('Failed to fetch total:', err);
            }
        };
        fetchTotal();
        const interval = setInterval(fetchTotal, CONFIG.AUTO_REFRESH_INTERVAL);
        const onVisible = () => { if (!document.hidden) fetchTotal(); };
        document.addEventListener('visibilitychange', onVisible);
        return () => { clearInterval(interval); document.removeEventListener('visibilitychange', onVisible); };
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
