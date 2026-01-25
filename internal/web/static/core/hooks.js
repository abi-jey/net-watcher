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
 * WebSocket hook for real-time event streaming
 */
NetWatcher.useWebSocket = function(enabled, onEvent) {
    const wsRef = useRef(null);
    const [connected, setConnected] = useState(false);
    const [eventCount, setEventCount] = useState(0);
    const reconnectTimeoutRef = useRef(null);

    const connect = useCallback(() => {
        if (wsRef.current?.readyState === WebSocket.OPEN) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/ws`;
        
        console.log('[WS] Connecting to', wsUrl);
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log('[WS] Connected');
            setConnected(true);
        };

        ws.onmessage = (event) => {
            try {
                // Handle batched messages (newline separated)
                const messages = event.data.split('\n').filter(m => m.trim());
                messages.forEach(msg => {
                    const parsed = JSON.parse(msg);
                    if (parsed.type === 'event' && onEvent) {
                        onEvent(parsed.data);
                        setEventCount(c => c + 1);
                    }
                });
            } catch (err) {
                console.error('[WS] Failed to parse message:', err);
            }
        };

        ws.onclose = (event) => {
            console.log('[WS] Disconnected', event.code);
            setConnected(false);
            wsRef.current = null;

            // Reconnect if still enabled
            if (enabled && event.code !== 1000) {
                reconnectTimeoutRef.current = setTimeout(() => {
                    console.log('[WS] Reconnecting...');
                    connect();
                }, 3000);
            }
        };

        ws.onerror = (err) => {
            console.error('[WS] Error:', err);
        };

        wsRef.current = ws;
    }, [enabled, onEvent]);

    const disconnect = useCallback(() => {
        if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current);
            reconnectTimeoutRef.current = null;
        }
        if (wsRef.current) {
            wsRef.current.close(1000, 'User disconnected');
            wsRef.current = null;
        }
        setConnected(false);
    }, []);

    useEffect(() => {
        if (enabled) {
            connect();
        } else {
            disconnect();
        }

        return () => disconnect();
    }, [enabled, connect, disconnect]);

    return { connected, eventCount };
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
