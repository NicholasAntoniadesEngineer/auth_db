/**
 * Application Constants
 * Central location for all application-wide constants
 * @module ui/config/constants
 */

const Constants = {
    /**
     * Module names
     */
    MODULES: {
        AUTH: 'auth',
        MONTHLY_BUDGET: 'monthlyBudget',
        NOTIFICATIONS: 'notifications',
        POTS: 'pots',
        SETTINGS: 'settings',
        PAYMENTS: 'payments',
        MESSAGING: 'messaging'
    },

    /**
     * Common paths
     */
    PATHS: {
        UI_INDEX: 'landing/index.html',
        AUTH: 'auth/views/auth.html',
        MONTHLY_BUDGET: 'monthlyBudget/views/monthlyBudget.html',
        NOTIFICATIONS: 'notifications/views/notifications.html',
        POTS: 'pots/views/pots.html',
        SETTINGS: 'settings/views/settings.html',
        MESSENGER: 'messaging/views/messenger.html',
        PAYMENTS: 'payments/views/subscription.html'
    },

    /**
     * Session and storage keys
     */
    STORAGE_KEYS: {
        FONT_SCALE: 'money_tracker_fontScale',
        AUTH_REDIRECTING: 'auth_redirecting',
        AUTH_REDIRECT_TIMESTAMP: 'auth_redirect_timestamp'
    },

    /**
     * Timing constants (in milliseconds)
     */
    TIMING: {
        SESSION_CHECK_INTERVAL: 5 * 60 * 1000, // 5 minutes
        SESSION_VALIDATION_CACHE: 60000, // 1 minute
        NOTIFICATION_UPDATE_INTERVAL: 30000, // 30 seconds
        REDIRECT_DEBOUNCE: 2000, // 2 seconds
        USER_INACTIVITY_THRESHOLD: 5 * 60 * 1000 // 5 minutes
    },

    /**
     * UI constants
     */
    UI: {
        DEFAULT_FONT_SIZE: 16,
        MIN_FONT_SIZE: 12,
        MAX_FONT_SIZE: 24
    },

    /**
     * Validation constants
     */
    VALIDATION: {
        MIN_PASSWORD_LENGTH: 6,
        MIN_YEAR: 2000,
        MAX_YEAR: 2100,
        MIN_MONTH: 1,
        MAX_MONTH: 12
    }
};

// Make available globally
if (typeof window !== 'undefined') {
    window.Constants = Constants;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Constants;
}
