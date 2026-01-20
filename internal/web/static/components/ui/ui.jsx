// Net Watcher - Reusable UI Components

window.NetWatcher = window.NetWatcher || {};
window.NetWatcher.UI = window.NetWatcher.UI || {};

const { useState, useRef } = React;
const { Icon, Utils, useClickOutside } = NetWatcher;

/**
 * Button Component
 */
NetWatcher.UI.Button = function({ children, variant = 'primary', size = 'md', onClick, disabled, className = '', ...props }) {
    const classes = `btn btn-${variant} btn-${size} ${className}`.trim();
    return (
        <button className={classes} onClick={onClick} disabled={disabled} {...props}>
            {children}
        </button>
    );
};

/**
 * Input Component
 */
NetWatcher.UI.Input = function({ label, value, onChange, placeholder, className = '', isSearching = false, ...props }) {
    return (
        <div className="filter-group">
            {label && <label className="filter-label">{label}</label>}
            <input
                type="text"
                className={`filter-input ${isSearching ? 'searching' : ''} ${className}`.trim()}
                placeholder={placeholder}
                value={value}
                onChange={(e) => onChange(e.target.value)}
                {...props}
            />
        </div>
    );
};

/**
 * Badge Component
 */
NetWatcher.UI.Badge = function({ children, variant = 'default', className = '' }) {
    return (
        <span className={`event-type-badge ${variant} ${className}`.trim()}>
            {children}
        </span>
    );
};

/**
 * Spinner Component
 */
NetWatcher.UI.Spinner = function({ size = 'md' }) {
    return <div className={`spinner spinner-${size}`}></div>;
};

/**
 * Empty State Component
 */
NetWatcher.UI.EmptyState = function({ icon: IconComponent, title, description }) {
    return (
        <div className="empty-state">
            {IconComponent && <IconComponent />}
            <h3>{title}</h3>
            <p>{description}</p>
        </div>
    );
};

/**
 * Loading State Component
 */
NetWatcher.UI.LoadingState = function({ message = 'Loading...' }) {
    return (
        <div className="loading">
            <NetWatcher.UI.Spinner />
            <span>{message}</span>
        </div>
    );
};

/**
 * Multi-Select Component
 */
NetWatcher.UI.MultiSelect = function({ options, selected, onChange, placeholder = 'Select...' }) {
    const [isOpen, setIsOpen] = useState(false);
    const ref = useRef(null);

    useClickOutside(ref, () => setIsOpen(false));

    const toggleOption = (option) => {
        const newSelected = selected.includes(option)
            ? selected.filter(s => s !== option)
            : [...selected, option];
        onChange(newSelected);
    };

    const removeOption = (e, option) => {
        e.stopPropagation();
        onChange(selected.filter(s => s !== option));
    };

    return (
        <div className="multi-select-wrapper" ref={ref}>
            <div 
                className={`multi-select-trigger ${isOpen ? 'open' : ''}`}
                onClick={() => setIsOpen(!isOpen)}
            >
                <div className="multi-select-tags">
                    {selected.length === 0 ? (
                        <span className="multi-select-placeholder">{placeholder}</span>
                    ) : (
                        selected.map(item => (
                            <span key={item} className="multi-select-tag">
                                {item}
                                <button 
                                    type="button" 
                                    onClick={(e) => removeOption(e, item)}
                                    aria-label={`Remove ${item}`}
                                >
                                    ×
                                </button>
                            </span>
                        ))
                    )}
                </div>
                <span className="multi-select-arrow">
                    <Icon.ChevronDown />
                </span>
            </div>
            {isOpen && options.length > 0 && (
                <div className="multi-select-dropdown">
                    {options.map(option => (
                        <div
                            key={option}
                            className={`multi-select-option ${selected.includes(option) ? 'selected' : ''}`}
                            onClick={() => toggleOption(option)}
                        >
                            <div className="multi-select-checkbox">
                                {selected.includes(option) && <Icon.Check />}
                            </div>
                            <NetWatcher.UI.Badge variant={Utils.getEventTypeClass(option)}>{option}</NetWatcher.UI.Badge>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};
