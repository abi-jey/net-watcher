// Net Watcher - Utility Functions

window.NetWatcher = window.NetWatcher || {};

NetWatcher.Utils = {
    formatTimestamp(ts) {
        if (!ts) return '-';
        return new Date(ts).toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    },

    formatNumber(num) {
        if (!num) return '0';
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    },

    formatBytes(bytes) {
        if (!bytes) return '-';
        if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
        if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
        if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return bytes + ' B';
    },

    formatDuration(ms) {
        if (!ms) return '-';
        if (ms >= 60000) return (ms / 60000).toFixed(1) + 'm';
        if (ms >= 1000) return (ms / 1000).toFixed(1) + 's';
        return ms + 'ms';
    },

    getEventTypeClass(eventType) {
        const type = (eventType || '').toLowerCase();
        if (type.includes('tcp')) return 'tcp';
        if (type.includes('udp')) return 'udp';
        if (type.includes('dns')) return 'dns';
        if (type.includes('tls')) return 'tls';
        if (type.includes('icmp')) return 'icmp';
        return 'default';
    },

    buildQueryParams(params) {
        const searchParams = new URLSearchParams();
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined && value !== null && value !== '') {
                if (Array.isArray(value) && value.length > 0) {
                    searchParams.set(key, value.join(','));
                } else if (!Array.isArray(value)) {
                    searchParams.set(key, value.toString());
                }
            }
        });
        return searchParams.toString();
    }
};
