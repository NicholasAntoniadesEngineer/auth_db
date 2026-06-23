/**
 * Encryption Module Base Configuration
 * Base structure for encryption module configuration.
 * This allows the encryption module to be reusable across different projects
 * by providing a standardized interface for all dependencies and settings.
 */

const EncryptionConfigBase = {
    /**
     * Version of the config system
     */
    VERSION: '2.0.0',

    /**
     * Service Dependencies
     * These are the services that the encryption module depends on.
     * They should be provided by the host application.
     */
    services: {
        /**
         * Database Service
         * Must provide:
         * - querySelect(table, options)
         * - queryInsert(table, data)
         * - queryUpdate(table, id, updateData, filter)
         * - queryUpsert(table, data, options)
         * - queryDelete(table, options)
         */
        database: null,

        /**
         * Authentication Service
         * Must provide:
         * - isAuthenticated()
         * - getCurrentUser()
         * - getSession()
         */
        auth: null,

        /**
         * Subscription Guard Service
         * Must provide:
         * - hasTier(tierName)
         * - getCurrentTier()
         */
        subscriptionGuard: null
    },

    /**
     * Crypto Library Configuration
     */
    crypto: {
        /**
         * TweetNaCl.js — self-hosted (SM-11), no third-party CDN. Paths are relative to the page.
         */
        naclUrl: '../../shared/vendor/crypto/nacl-fast.min.js',
        naclUtilUrl: '../../shared/vendor/crypto/nacl-util.min.js',

        /**
         * Load timeout in milliseconds
         */
        loadTimeout: 15000,

        /**
         * HKDF configuration
         */
        hkdf: {
            hash: 'SHA-256',
            infoPrefix: 'MoneyTracker'
        },

        /**
         * PBKDF2 configuration for password-based encryption
         */
        pbkdf2: {
            hash: 'SHA-256',
            iterations: 600000, // OWASP 2023 recommendation
            keyLength: 256 // bits
        }
    },

    /**
     * IndexedDB Configuration
     */
    indexedDB: {
        name: 'MoneyTrackerEncryption',
        version: 2,
        stores: {
            identityKeys: 'identity_keys',
            sessionKeys: 'session_keys',
            historicalKeys: 'historical_keys',
            wrapKeys: 'wrap_keys',
            pinnedKeys: 'pinned_keys',
            recvCounters: 'recv_counters',
            // S4 (forward secrecy): Double Ratchet persistence. ADDED in v2,
            // never replaces the stores above (additive onupgradeneeded).
            ratchetStates: 'ratchet_states',
            skippedMessageKeys: 'skipped_message_keys',
            decryptedMessageKeys: 'decrypted_message_keys'
        }
    },

    /**
     * Database Table Names
     */
    tables: {
        identityKeys: 'identity_keys',
        publicKeyHistory: 'public_key_history',
        identityKeyBackups: 'identity_key_backups',
        conversationSessionKeys: 'conversation_session_keys',
        messages: 'messages',
        pairedDevices: 'paired_devices'
    },

    /**
     * Feature Gating Configuration
     */
    features: {
        /**
         * Required subscription tier for encryption
         * Set to null to disable tier checking (encryption always available)
         */
        requiredTier: null
    },

    /**
     * Application-specific Configuration
     */
    application: {
        /**
         * Application name (used in key derivation info strings)
         */
        name: 'MoneyTracker',

        /**
         * Safety number format (groups of digits)
         */
        safetyNumberGroups: 6,
        safetyNumberDigitsPerGroup: 5
    },

    /**
     * Key Rotation Configuration
     * Controls automatic identity-key rotation. When `enabled` is not false,
     * rotation is considered active (see getRotationStatus / initializeForUser).
     */
    keyRotation: {
        /**
         * Whether automatic key rotation is enabled
         */
        enabled: true,

        /**
         * Whether to check (and possibly rotate) on user initialization
         */
        checkOnInit: true,

        /**
         * Rotation interval in milliseconds (default: 24 hours)
         */
        intervalMs: 86400000
    },

    /**
     * Logging Configuration
     */
    logging: {
        /**
         * Enable verbose logging
         */
        verbose: false,

        /**
         * Log prefix for all encryption module logs
         */
        prefix: '[Encryption]'
    },

    /**
     * Validation
     * Validates that all required configuration is present
     * @returns {Object} { valid: boolean, errors: string[] }
     */
    validate() {
        const errors = [];

        if (!this.services.database) {
            errors.push('services.database is required');
        }

        if (!this.services.auth) {
            errors.push('services.auth is required');
        }

        if (!this.crypto.naclUrl) {
            errors.push('crypto.naclUrl is required');
        }

        if (!this.crypto.naclUtilUrl) {
            errors.push('crypto.naclUtilUrl is required');
        }

        if (!this.indexedDB.name) {
            errors.push('indexedDB.name is required');
        }

        if (!this.tables.identityKeys) {
            errors.push('tables.identityKeys is required');
        }

        if (!this.tables.messages) {
            errors.push('tables.messages is required');
        }

        return {
            valid: errors.length === 0,
            errors: errors
        };
    },

    /**
     * Prepare config with services injected from window globals
     * Call this before passing config to any encryption service
     * This is idempotent - safe to call multiple times
     * @returns {Object} This config (for chaining)
     */
    prepareWithServices() {
        if (typeof window !== 'undefined') {
            if (!this.services.database && window.DatabaseService) {
                this.services.database = window.DatabaseService;
            }
            if (!this.services.auth && window.AuthService) {
                this.services.auth = window.AuthService;
            }
            if (!this.services.subscriptionGuard && window.SubscriptionGuard) {
                this.services.subscriptionGuard = window.SubscriptionGuard;
            }
        }
        return this;
    },

    /**
     * Merge with another configuration object
     * @param {Object} config - Configuration to merge
     * @returns {Object} Merged configuration
     */
    merge(config) {
        const validateMethod = this.validate;
        const mergeMethod = this.merge;
        const prepareWithServicesMethod = this.prepareWithServices;

        const merged = {};

        // Copy all data properties
        merged.VERSION = this.VERSION;
        merged.services = { ...this.services };
        merged.crypto = {
            ...this.crypto,
            hkdf: { ...this.crypto.hkdf },
            pbkdf2: { ...this.crypto.pbkdf2 }
        };
        merged.indexedDB = {
            ...this.indexedDB,
            stores: { ...this.indexedDB.stores }
        };
        merged.tables = { ...this.tables };
        merged.features = { ...this.features };
        merged.application = { ...this.application };
        merged.keyRotation = { ...this.keyRotation };
        merged.logging = { ...this.logging };

        // Merge config properties
        if (config.services) {
            merged.services = { ...merged.services, ...config.services };
        }

        if (config.crypto) {
            merged.crypto = {
                ...merged.crypto,
                ...config.crypto,
                hkdf: { ...merged.crypto.hkdf, ...(config.crypto.hkdf || {}) },
                pbkdf2: { ...merged.crypto.pbkdf2, ...(config.crypto.pbkdf2 || {}) }
            };
        }

        if (config.indexedDB) {
            merged.indexedDB = {
                ...merged.indexedDB,
                ...config.indexedDB,
                stores: { ...merged.indexedDB.stores, ...(config.indexedDB.stores || {}) }
            };
        }

        if (config.tables) {
            merged.tables = { ...merged.tables, ...config.tables };
        }

        if (config.features) {
            merged.features = { ...merged.features, ...config.features };
        }

        if (config.application) {
            merged.application = { ...merged.application, ...config.application };
        }

        if (config.keyRotation) {
            merged.keyRotation = { ...merged.keyRotation, ...config.keyRotation };
        }

        if (config.logging) {
            merged.logging = { ...merged.logging, ...config.logging };
        }

        // Add methods
        if (typeof validateMethod === 'function') {
            merged.validate = function() {
                return validateMethod.call(merged);
            };
        }

        if (typeof mergeMethod === 'function') {
            merged.merge = function(newConfig) {
                return mergeMethod.call(merged, newConfig);
            };
        }

        if (typeof prepareWithServicesMethod === 'function') {
            merged.prepareWithServices = function() {
                return prepareWithServicesMethod.call(merged);
            };
        }

        return merged;
    }
};

if (typeof window !== 'undefined') {
    window.EncryptionConfigBase = EncryptionConfigBase;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = EncryptionConfigBase;
}
