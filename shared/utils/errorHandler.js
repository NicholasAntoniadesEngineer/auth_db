/**
 * Error Handler Utility
 * Centralized error handling with logging and user notification
 * @module ui/utils/error-handler
 */

const ErrorHandler = {
    /**
     * Wrap an async function with error handling
     * @param {Function} fn - Async function to wrap
     * @param {string} context - Context for logging (e.g., 'AuthService.signIn')
     * @returns {Promise<any>} Result of the function or throws error
     */
    async wrap(fn, context = 'Unknown') {
        try {
            return await fn();
        } catch (error) {
            this.logError(error, context);
            throw error;
        }
    },

    /**
     * Handle errors with user feedback
     * @param {Error} error - Error object
     * @param {string} userMessage - User-friendly message to display
     * @param {string} context - Context for logging
     */
    handleUserError(error, userMessage = 'An error occurred. Please try again.', context = 'Unknown') {
        this.logError(error, context);
        alert(userMessage);
    },

    /**
     * Log error with context
     * @param {Error} error - Error object
     * @param {string} context - Context for logging
     */
    logError(error, context = 'Unknown') {
        if (window.Logger) {
            window.Logger.error(`[${context}] Error:`, {
                message: error.message,
                name: error.name,
                stack: error.stack
            });
        } else {
            console.error(`[${context}] Error:`, error);
        }
    },

    /**
     * Handle network errors specifically
     * @param {Error} error - Error object
     * @param {string} context - Context for logging
     */
    handleNetworkError(error, context = 'Network') {
        this.logError(error, context);

        if (!navigator.onLine) {
            alert('You appear to be offline. Please check your internet connection.');
        } else {
            alert('A network error occurred. Please check your connection and try again.');
        }
    },

    /**
     * Handle authentication errors
     * @param {Error} error - Error object
     * @param {string} context - Context for logging
     */
    handleAuthError(error, context = 'Authentication') {
        this.logError(error, context);

        const message = error.message || '';

        if (message.includes('email') && message.includes('confirm')) {
            alert('Please verify your email address before signing in.');
        } else if (message.includes('Invalid login credentials')) {
            alert('Invalid email or password. Please try again.');
        } else if (message.includes('session')) {
            alert('Your session has expired. Please sign in again.');
        } else {
            alert('Authentication failed. Please try again.');
        }
    },

    /**
     * Handle validation errors
     * @param {Object} validationErrors - Object with field names as keys and error messages as values
     * @returns {string} Combined error message
     */
    formatValidationErrors(validationErrors) {
        const errors = Object.entries(validationErrors)
            .map(([field, message]) => `${field}: ${message}`)
            .join('\n');
        return errors;
    },

    /**
     * Create a safe error object (for logging without sensitive data)
     * @param {Error} error - Error object
     * @returns {Object} Safe error object
     */
    createSafeError(error) {
        return {
            message: error.message,
            name: error.name,
            stack: error.stack ? error.stack.split('\n').slice(0, 3).join('\n') : undefined
        };
    },

    /**
     * Global error handler setup
     */
    setupGlobalHandler() {
        window.addEventListener('error', (event) => {
            this.logError(event.error, 'Global');
        });

        window.addEventListener('unhandledrejection', (event) => {
            this.logError(new Error(event.reason), 'Unhandled Promise');
        });
    }
};

// Setup global error handlers
ErrorHandler.setupGlobalHandler();

// Make available globally
if (typeof window !== 'undefined') {
    window.ErrorHandler = ErrorHandler;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ErrorHandler;
}
