// Net Watcher - Filter Components

window.NetWatcher = window.NetWatcher || {};
window.NetWatcher.Components = window.NetWatcher.Components || {};

const { UI } = NetWatcher;

/**
 * Filter Controls
 */
NetWatcher.Components.Filters = function({ filters, onFiltersChange, eventTypes, isSearching }) {
    const updateFilter = (key, value) => {
        onFiltersChange({ ...filters, [key]: value });
    };

    const clearFilters = () => {
        onFiltersChange({
            q: '',
            eventTypes: [],
            srcIP: '',
            dstIP: ''
        });
    };

    return (
        <div className="filters">
            <div className="filters-row">
                <UI.Input
                    label="Search"
                    value={filters.q}
                    onChange={(value) => updateFilter('q', value)}
                    placeholder="IP, hostname, domain..."
                    isSearching={isSearching}
                />
                
                <div className="filter-group filter-group-multiselect">
                    <label className="filter-label">Event Types</label>
                    <UI.MultiSelect
                        options={eventTypes}
                        selected={filters.eventTypes}
                        onChange={(types) => updateFilter('eventTypes', types)}
                        placeholder="All Types"
                    />
                </div>

                <UI.Input
                    label="Source IP"
                    value={filters.srcIP}
                    onChange={(value) => updateFilter('srcIP', value)}
                    placeholder="e.g. 192.168.1.1"
                    isSearching={isSearching}
                />

                <UI.Input
                    label="Destination IP"
                    value={filters.dstIP}
                    onChange={(value) => updateFilter('dstIP', value)}
                    placeholder="e.g. 8.8.8.8"
                    isSearching={isSearching}
                />

                <div className="filter-group filter-group-actions">
                    <label className="filter-label">&nbsp;</label>
                    <UI.Button variant="secondary" onClick={clearFilters}>
                        Clear
                    </UI.Button>
                </div>
            </div>
        </div>
    );
};
