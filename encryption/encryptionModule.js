/**
 * Encryption Module
 *
 * Central module initializer for the encryption system.
 * Encryption is required - there are no fallbacks.
 * If encryption fails to initialize, an error is thrown.
 */

const EncryptionModule = {
    /**
     * Module version
     */
    VERSION: '2.0.0',

    /**
     * Configuration
     */
    config: null,

    /**
     * Whether the module is initialized
     */
    initialized: false,

    /**
     * Whether encryption is enabled (always true when initialized)
     */
    enabled: false,

    /**
     * The encryption facade
     */
    _facade: null,

    /**
     * Current user ID
     */
    _userId: null,

    /**
     * Initialize the encryption module
     * @param {Object} config - Encryption config object
     * @returns {Promise<Object>} { success: boolean, enabled: boolean }
     * @throws {Error} If encryption fails to initialize
     */
    async initialize(config) {
        console.log(`[EncryptionModule] Initializing v${this.VERSION}...`);

        this.config = config;

        // Inject services from global scope if not provided
        if (!config.services.database && window.DatabaseService) {
            config.services.database = window.DatabaseService;
        }

        if (!config.services.auth && window.AuthService) {
            config.services.auth = window.AuthService;
        }

        if (!config.services.subscriptionGuard && window.SubscriptionGuard) {
            config.services.subscriptionGuard = window.SubscriptionGuard;
        }

        // Validate config
        const validation = config.validate();
        if (!validation.valid) {
            console.error('[EncryptionModule] Invalid config:', validation.errors);
            throw new Error(`Invalid encryption config: ${validation.errors.join(', ')}`);
        }

        // Check subscription tier if configured
        const requiredTier = config.features?.requiredTier;
        if (requiredTier && config.services.subscriptionGuard) {
            const hasTier = await config.services.subscriptionGuard.hasTier(requiredTier);
            if (!hasTier) {
                throw new Error(`[EncryptionModule] User does not have required subscription tier: ${requiredTier}`);
            }
        }

        // Initialize the crypto library loader with config
        CryptoLibraryLoader.initialize(config);

        // Load the crypto library - failure throws an error
        await CryptoLibraryLoader.load();

        this.enabled = true;
        // SM-37(a): the real-user facade is ALWAYS EncryptionFacade. The plaintext
        // NullEncryptionFacade is fenced off and is never selectable at runtime /
        // from a server-supplied flag. Encryption is required for everyone.
        this._facade = EncryptionFacade;
        this.initialized = true;

        console.log('[EncryptionModule] Encryption enabled');
        return { success: true, enabled: true };
    },

    /**
     * Initialize for a specific user
     * Call this after initialize() and after user authentication
     * @param {string} userId - User ID
     * @returns {Promise<Object>} Initialization result
     * @throws {Error} If module not initialized or user initialization fails
     */
    async initializeForUser(userId) {
        if (!this.initialized) {
            throw new Error('[EncryptionModule] Module not initialized. Call initialize() first.');
        }

        if (!this.enabled) {
            throw new Error('[EncryptionModule] Encryption not enabled. Cannot initialize for user.');
        }

        this._userId = userId;

        // Initialize the encryption facade for this user
        const result = await this._facade.initialize(this.config, userId);

        // Check for key rotation if configured and encryption is set up
        if (result.success && !result.needsSetup && !result.needsRestore) {
            const rotationConfig = this.config?.keyRotation || {};
            if (rotationConfig.enabled !== false && rotationConfig.checkOnInit !== false) {
                try {
                    const rotationResult = await this._facade.checkAndRotateIfNeeded();
                    if (rotationResult.rotated) {
                        console.log(`[EncryptionModule] Auto-rotated keys to epoch ${rotationResult.newEpoch}`);
                        result.keyRotation = rotationResult;
                    } else if (rotationResult.reason === 'not_due') {
                        console.log(`[EncryptionModule] Next key rotation in ${rotationResult.nextRotationHuman}`);
                    }
                } catch (error) {
                    console.warn('[EncryptionModule] Key rotation check failed:', error);
                    // Don't fail initialization due to rotation check failure
                }
            }
        }

        return result;
    },

    /**
     * Get the encryption facade
     * @returns {Object} EncryptionFacade
     * @throws {Error} If module not initialized or encryption not enabled
     */
    getFacade() {
        if (!this.initialized) {
            throw new Error('[EncryptionModule] Module not initialized. Call initialize() first.');
        }
        if (!this.enabled) {
            throw new Error('[EncryptionModule] Encryption not enabled.');
        }
        return this._facade;
    },

    /**
     * Check if encryption is enabled
     * @returns {boolean}
     */
    isEnabled() {
        return this.enabled;
    },

    /**
     * Check if the module is initialized
     * @returns {boolean}
     */
    isInitialized() {
        return this.initialized;
    },

    /**
     * Get module status
     * @returns {Object}
     */
    getStatus() {
        return {
            version: this.VERSION,
            initialized: this.initialized,
            enabled: this.enabled,
            userId: this._userId?.slice(0, 8) + '...',
            facade: 'EncryptionFacade',
            facadeStatus: this._facade?.getStatus?.() || null
        };
    },

    /**
     * Restore encryption keys from password backup
     * @param {string} password - User's encryption password
     * @returns {Promise<Object>} { success: boolean, error?: string }
     */
    async restoreFromPassword(password) {
        if (!this.initialized || !this._facade) {
            return { success: false, error: 'Module not initialized' };
        }
        console.log('[EncryptionModule] Restoring from password...');
        return await this._facade.restoreFromPassword(password);
    },

    /**
     * Clear all local encryption data
     */
    async clearLocalData() {
        if (this._facade?.clearLocalData) {
            await this._facade.clearLocalData();
        }
        this._userId = null;
    },

    /**
     * Reset the module (for testing or logout)
     */
    reset() {
        this.config = null;
        this.initialized = false;
        this.enabled = false;
        this._facade = null;
        this._userId = null;
    }
};

// Make available globally
if (typeof window !== 'undefined') {
    window.EncryptionModule = EncryptionModule;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = EncryptionModule;
}
