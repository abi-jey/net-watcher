// Net Watcher - Layout Components (Sidebar, Header)

window.NetWatcher = window.NetWatcher || {};
window.NetWatcher.Layout = window.NetWatcher.Layout || {};

const { Icon, Utils, useApp } = NetWatcher;

/**
 * Sidebar Navigation
 */
NetWatcher.Layout.Sidebar = function({ activeNav, onNavChange, totalEvents }) {
    const { sidebarCollapsed, setSidebarCollapsed, version } = useApp();

    const navItems = [
        { 
            section: 'Monitor',
            items: [
                { id: 'events', label: 'Events', icon: Icon.Activity, badge: Utils.formatNumber(totalEvents) },
                { id: 'stats', label: 'Dashboard', icon: Icon.BarChart }
            ]
        },
        {
            section: 'Analytics',
            items: [
                { id: 'connections', label: 'Connections', icon: Icon.Connection },
                { id: 'dns', label: 'DNS Queries', icon: Icon.Network },
                { id: 'hosts', label: 'Top Hosts', icon: Icon.Monitor }
            ]
        },
        {
            section: 'Settings',
            items: [
                { id: 'settings', label: 'Settings', icon: Icon.Settings }
            ]
        }
    ];

    return (
        <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
            <div className="sidebar-header">
                <a href="/" className="logo">
                    <div className="logo-icon">
                        <Icon.Globe />
                    </div>
                    <div className="logo-text-wrapper">
                        <div className="logo-text">Net Watcher</div>
                        <div className="logo-version">{version || 'v1.0.0'}</div>
                    </div>
                </a>
                <button 
                    className="collapse-btn" 
                    onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                    title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                    aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                >
                    {sidebarCollapsed ? <Icon.ChevronRight /> : <Icon.PanelLeftClose />}
                </button>
            </div>

            <nav className="sidebar-nav">
                {navItems.map(({ section, items }) => (
                    <div key={section} className="nav-section">
                        <div className="nav-section-title">{section}</div>
                        {items.map(({ id, label, icon: ItemIcon, badge }) => (
                            <a
                                key={id}
                                className={`nav-item ${activeNav === id ? 'active' : ''}`}
                                onClick={() => onNavChange(id)}
                                title={label}
                            >
                                <ItemIcon />
                                <span>{label}</span>
                                {badge && <span className="nav-badge">{badge}</span>}
                            </a>
                        ))}
                    </div>
                ))}
            </nav>

            <div className="sidebar-footer">
                <div className="status-indicator">
                    <span className="status-dot"></span>
                    <span>Database Connected</span>
                </div>
            </div>
        </aside>
    );
};

/**
 * Header with Stats
 */
NetWatcher.Layout.Header = function({ stats }) {
    const statCards = [
        { label: 'Total Events', value: stats?.totalEvents || 0 },
        { label: 'TCP', value: (stats?.eventCounts?.TCP || 0) + (stats?.eventCounts?.TCP_START || 0) },
        { label: 'DNS', value: stats?.eventCounts?.DNS || 0 },
        { label: 'TLS', value: stats?.eventCounts?.TLS_SNI || 0 }
    ];

    return (
        <header className="header">
            <div className="header-content">
                <div className="header-title">
                    <div>
                        <h1>Network Events</h1>
                        <p>Real-time network traffic monitoring</p>
                    </div>
                </div>
                <div className="header-stats">
                    {statCards.map(({ label, value }) => (
                        <div key={label} className="stat-card">
                            <div className="stat-value">{Utils.formatNumber(value)}</div>
                            <div className="stat-label">{label}</div>
                        </div>
                    ))}
                </div>
            </div>
        </header>
    );
};
