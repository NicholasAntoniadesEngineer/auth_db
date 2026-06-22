/**
 * Logger Utility
 * Centralized logging with configurable levels
 * @module ui/utils/logger
 */

// IMMEDIATE LOG - This runs as soon as the file loads
console.log('===== LOGGER.JS FILE LOADING =====');
console.log('Location:', window.location.href);
console.log('Protocol:', window.location.protocol);
console.log('Hostname:', window.location.hostname);
console.log('==================================');

const Logger = {
    /**
     * Current log level
     * Levels: 'debug', 'info', 'warn', 'error', 'none'
     * @type {string}
     */
    level: 'info',

    /**
     * Log levels and their priorities
     * @private
     */
    _levels: {
        debug: 0,
        info: 1,
        warn: 2,
        error: 3,
        none: 4
    },

    /**
     * Initialize logger with appropriate level based on environment
     */
    init() {
        // Set log level based on environment
        const hostname = window.location.hostname;
        const protocol = window.location.protocol;

        // Enable debug logging for:
        // 1. localhost/127.0.0.1
        // 2. file:// protocol (for testing without server)
        // 3. Empty hostname (fallback for file:// protocol)
        if (hostname === 'localhost' ||
            hostname === '127.0.0.1' ||
            hostname === '' ||
            protocol === 'file:') {
            this.level = 'debug';
            console.log('[Logger] Debug logging enabled for local development');
        } else {
            this.level = 'error'; // Production: only show errors
            console.log('[Logger] Production mode - only errors will be logged');
        }

        // Allow override via localStorage for debugging production
        const override = localStorage.getItem('log_level');
        if (override && this._levels.hasOwnProperty(override)) {
            this.level = override;
            console.log('[Logger] Log level overridden to:', override);
        }

        console.log('[Logger] Final log level:', this.level, '| Protocol:', protocol, '| Hostname:', hostname || '(empty)');
    },

    /**
     * Check if a log level should be shown
     * @private
     * @param {string} level - Level to check
     * @returns {boolean}
     */
    _shouldLog(level) {
        return this._levels[level] >= this._levels[this.level];
    },

    /**
     * Format log message with timestamp and context
     * @private
     * @param {string} level - Log level
     * @param {Array} args - Arguments to log
     * @returns {Array}
     */
    _format(level, args) {
        const timestamp = new Date().toISOString().substr(11, 12);
        return [`[${timestamp}] [${level.toUpperCase()}]`, ...args];
    },

    /**
     * Debug level logging (most verbose)
     * @param {...any} args - Arguments to log
     */
    debug(...args) {
        if (this._shouldLog('debug')) {
            console.log(...this._format('debug', args));
        }
    },

    /**
     * Info level logging
     * @param {...any} args - Arguments to log
     */
    info(...args) {
        if (this._shouldLog('info')) {
            console.log(...this._format('info', args));
        }
    },

    /**
     * Warning level logging
     * @param {...any} args - Arguments to log
     */
    warn(...args) {
        if (this._shouldLog('warn')) {
            console.warn(...this._format('warn', args));
        }
    },

    /**
     * Error level logging
     * @param {...any} args - Arguments to log
     */
    error(...args) {
        if (this._shouldLog('error')) {
            console.error(...this._format('error', args));
        }
    },

    /**
     * Group logging (for collapsing related logs)
     * @param {string} label - Group label
     * @param {Function} fn - Function to execute within group
     */
    group(label, fn) {
        if (this._shouldLog('debug')) {
            console.group(label);
            try {
                fn();
            } finally {
                console.groupEnd();
            }
        } else {
            fn();
        }
    },

    /**
     * Set log level dynamically
     * @param {string} level - New log level
     */
    setLevel(level) {
        if (this._levels.hasOwnProperty(level)) {
            this.level = level;
            localStorage.setItem('log_level', level);
            console.log('[Logger] Log level set to:', level);
        } else {
            console.error('[Logger] Invalid log level:', level);
        }
    }
};

// Auto-initialize
Logger.init();

// Make available globally
if (typeof window !== 'undefined') {
    window.Logger = Logger;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Logger;
}
