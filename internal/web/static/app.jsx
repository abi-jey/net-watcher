// Net Watcher - Main Application Entry Point

const { useState, useEffect } = React;
const { CONFIG, AppProvider, useApp, Layout, Pages } = NetWatcher;

/**
 * App Content - Main layout with routing
 */
function AppContent({ activeNav, onNavChange, totalEvents }) {
    const { sidebarCollapsed } = useApp();

    // Render current page based on navigation
    const renderPage = () => {
        switch (activeNav) {
            case 'stats':
                return <Pages.DashboardPage />;
            case 'events':
            default:
                return <Pages.EventsPage />;
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
    const [activeNav, setActiveNav] = useState('events');
    const [totalEvents, setTotalEvents] = useState(0);

    // Update total events from stats
    useEffect(() => {
        const fetchTotal = async () => {
            try {
                const res = await fetch(`${CONFIG.API_BASE}/api/stats`);
                const data = await res.json();
                setTotalEvents(data.totalEvents || 0);
            } catch (err) {
                console.error('Failed to fetch total:', err);
            }
        };
        fetchTotal();
        const interval = setInterval(fetchTotal, CONFIG.AUTO_REFRESH_INTERVAL);
        return () => clearInterval(interval);
    }, []);

    return (
        <AppProvider>
            <AppContent 
                activeNav={activeNav} 
                onNavChange={setActiveNav}
                totalEvents={totalEvents}
            />
        </AppProvider>
    );
}

// Initialize React application
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
