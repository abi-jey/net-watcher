// Net Watcher - Custom React Hooks

window.NetWatcher = window.NetWatcher || {};

const { useState, useEffect, useCallback, useRef } = React;
const { CONFIG } = NetWatcher;

/**
 * Debounce hook - delays value updates
 */
NetWatcher.useDebounce = function(value, delay = CONFIG.DEBOUNCE_DELAY) {
    const [debouncedValue, setDebouncedValue] = useState(value);

    useEffect(() => {
        const handler = setTimeout(() => setDebouncedValue(value), delay);
        return () => clearTimeout(handler);
    }, [value, delay]);

    return debouncedValue;
};

/**
 * Click outside hook - detects clicks outside a ref element
 */
NetWatcher.useClickOutside = function(ref, handler) {
    useEffect(() => {
        const listener = (event) => {
            if (!ref.current || ref.current.contains(event.target)) return;
            handler(event);
        };

        document.addEventListener('mousedown', listener);
        document.addEventListener('touchstart', listener);

        return () => {
            document.removeEventListener('mousedown', listener);
            document.removeEventListener('touchstart', listener);
        };
    }, [ref, handler]);
};

/**
 * API fetch hook with loading and error states
 */
NetWatcher.useApi = function(endpoint, options = {}) {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchData = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const res = await fetch(`${CONFIG.API_BASE}${endpoint}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const json = await res.json();
            setData(json);
        } catch (err) {
            setError(err.message);
            console.error(`API Error [${endpoint}]:`, err);
        } finally {
            setLoading(false);
        }
    }, [endpoint]);

    useEffect(() => {
        fetchData();
    }, [fetchData]);

    return { data, loading, error, refetch: fetchData };
};
