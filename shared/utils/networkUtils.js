/**
 * Network Utilities
 * Provides retry logic with exponential backoff and offline detection
 * for improved resilience in network operations
 */

const NetworkUtils = {
    /**
     * Fetch with automatic retry and exponential backoff
     * @param {string} url - URL to fetch
     * @param {Object} options - Fetch options
     * @param {number} maxRetries - Maximum number of retry attempts (default: 3)
     * @param {number} baseDelay - Base delay in ms for exponential backoff (default: 1000)
     * @returns {Promise<Response>} Fetch response
     */
    async fetchWithRetry(url, options = {}, maxRetries = 3, baseDelay = 1000) {
        let lastError;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                // Check if we're offline before attempting
                if (!navigator.onLine && attempt > 0) {
                    console.warn('[NetworkUtils] Device is offline, skipping retry attempt', attempt);
                    throw new Error('Device is offline');
                }

                const response = await fetch(url, options);

                // If response is ok or it's a client error (4xx), don't retry
                if (response.ok || (response.status >= 400 && response.status < 500)) {
                    return response;
                }

                // Server errors (5xx) or network issues - retry
                lastError = new Error(`HTTP ${response.status}: ${response.statusText}`);
                console.warn(`[NetworkUtils] Request failed (attempt ${attempt + 1}/${maxRetries + 1}):`, lastError.message);

            } catch (error) {
                lastError = error;
                console.warn(`[NetworkUtils] Network error (attempt ${attempt + 1}/${maxRetries + 1}):`, error.message);
            }

            // If this wasn't the last attempt, wait before retrying
            if (attempt < maxRetries) {
                const delay = baseDelay * Math.pow(2, attempt); // Exponential backoff
                const jitter = Math.random() * 200; // Add jitter to prevent thundering herd
                const totalDelay = delay + jitter;

                console.log(`[NetworkUtils] Retrying in ${Math.round(totalDelay)}ms...`);
                await new Promise(resolve => setTimeout(resolve, totalDelay));
            }
        }

        // All retries exhausted
        console.error('[NetworkUtils] All retry attempts exhausted');
        throw lastError || new Error('Request failed after all retry attempts');
    },

    /**
     * Check if the device is online
     * @returns {boolean} True if online, false otherwise
     */
    isOnline() {
        return navigator.onLine;
    },

    /**
     * Wait for the device to come back online
     * @param {number} timeout - Maximum time to wait in ms (default: 30000)
     * @returns {Promise<boolean>} True if came back online, false if timeout
     */
    async waitForOnline(timeout = 30000) {
        if (navigator.onLine) {
            return true;
        }

        return new Promise((resolve) => {
            const startTime = Date.now();

            const checkOnline = () => {
                if (navigator.onLine) {
                    window.removeEventListener('online', checkOnline);
                    resolve(true);
                } else if (Date.now() - startTime > timeout) {
                    window.removeEventListener('online', checkOnline);
                    resolve(false);
                }
            };

            window.addEventListener('online', checkOnline);

            // Also check periodically
            const interval = setInterval(() => {
                if (Date.now() - startTime > timeout) {
                    clearInterval(interval);
                    window.removeEventListener('online', checkOnline);
                    resolve(false);
                }
            }, 1000);
        });
    },

    /**
     * Execute a function with automatic retry on network errors
     * @param {Function} fn - Async function to execute
     * @param {number} maxRetries - Maximum number of retry attempts (default: 3)
     * @param {number} baseDelay - Base delay in ms for exponential backoff (default: 1000)
     * @returns {Promise<any>} Result of the function
     */
    async withRetry(fn, maxRetries = 3, baseDelay = 1000) {
        let lastError;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                return await fn();
            } catch (error) {
                lastError = error;
                console.warn(`[NetworkUtils] Operation failed (attempt ${attempt + 1}/${maxRetries + 1}):`, error.message);

                // Don't retry if it's not a network error
                if (error.name !== 'TypeError' && !error.message.includes('network') && !error.message.includes('fetch')) {
                    throw error;
                }

                // If this wasn't the last attempt, wait before retrying
                if (attempt < maxRetries) {
                    const delay = baseDelay * Math.pow(2, attempt);
                    const jitter = Math.random() * 200;
                    const totalDelay = delay + jitter;

                    console.log(`[NetworkUtils] Retrying in ${Math.round(totalDelay)}ms...`);
                    await new Promise(resolve => setTimeout(resolve, totalDelay));
                }
            }
        }

        throw lastError || new Error('Operation failed after all retry attempts');
    }
};

// Make NetworkUtils available globally
if (typeof window !== 'undefined') {
    window.NetworkUtils = NetworkUtils;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = NetworkUtils;
}
