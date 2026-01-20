// Net Watcher - React Context for Global State

window.NetWatcher = window.NetWatcher || {};

const { useState, createContext, useContext, useMemo } = React;

// Create context
NetWatcher.AppContext = createContext(null);

/**
 * App Provider - Global state management
 */
NetWatcher.AppProvider = function({ children }) {
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
    const [version, setVersion] = useState('');

    const value = useMemo(() => ({
        sidebarCollapsed,
        setSidebarCollapsed,
        version,
        setVersion
    }), [sidebarCollapsed, version]);

    return (
        <NetWatcher.AppContext.Provider value={value}>
            {children}
        </NetWatcher.AppContext.Provider>
    );
};

/**
 * Hook to consume app context
 */
NetWatcher.useApp = function() {
    const context = useContext(NetWatcher.AppContext);
    if (!context) {
        throw new Error('useApp must be used within AppProvider');
    }
    return context;
};
