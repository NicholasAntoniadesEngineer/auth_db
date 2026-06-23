/**
 * Encryption Config Helper
 *
 * Utility functions for accessing encryption configuration.
 */

const EncryptionConfigHelper = {
    /**
     * Get table name from config
     * @param {Object} config - Encryption config
     * @param {string} key - Table key (e.g., 'identityKeys')
     * @returns {string} Table name
     */
    getTableName(config, key) {
        return config?.tables?.[key] || key;
    },

    /**
     * Get IndexedDB store name from config
     * @param {Object} config - Encryption config
     * @param {string} key - Store key (e.g., 'identityKeys')
     * @returns {string} Store name
     */
    getStoreName(config, key) {
        return config?.indexedDB?.stores?.[key] || key;
    },

    /**
     * Get crypto setting from config
     * @param {Object} config - Encryption config
     * @param {string} path - Dot-separated path (e.g., 'hkdf.hash')
     * @param {*} defaultValue - Default value if not found
     * @returns {*} Config value
     */
    getCryptoSetting(config, path, defaultValue) {
        const parts = path.split('.');
        let value = config?.crypto;

        for (const part of parts) {
            value = value?.[part];
            if (value === undefined) return defaultValue;
        }

        return value;
    },

    /**
     * Check if a feature is enabled
     * @param {Object} config - Encryption config
     * @param {string} feature - Feature name
     * @returns {boolean}
     */
    isFeatureEnabled(config, feature) {
        return config?.features?.[feature] !== false;
    },

    /**
     * Get logging prefix
     * @param {Object} config - Encryption config
     * @returns {string}
     */
    getLogPrefix(config) {
        return config?.logging?.prefix || '[Encryption]';
    },

    /**
     * Check if verbose logging is enabled
     * @param {Object} config - Encryption config
     * @returns {boolean}
     */
    isVerbose(config) {
        return config?.logging?.verbose === true;
    },

    /**
     * Get database service from config
     * @param {Object} config - Encryption config
     * @returns {Object|null}
     */
    getDatabase(config) {
        return config?.services?.database || null;
    },

    /**
     * Get auth service from config
     * @param {Object} config - Encryption config
     * @returns {Object|null}
     */
    getAuth(config) {
        return config?.services?.auth || null;
    },

    /**
     * Get subscription guard from config
     * @param {Object} config - Encryption config
     * @returns {Object|null}
     */
    getSubscriptionGuard(config) {
        return config?.services?.subscriptionGuard || null;
    }
};

if (typeof window !== 'undefined') {
    window.EncryptionConfigHelper = EncryptionConfigHelper;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = EncryptionConfigHelper;
}
