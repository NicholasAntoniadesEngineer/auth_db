/**
 * Encryption Initialization Script
 *
 * Bootstrap script for initializing the encryption module.
 * Include this script after all encryption service scripts.
 *
 * Usage:
 * 1. Include all encryption scripts in order
 * 2. Include this script last
 * 3. Call initEncryptionModule() after authentication
 */

/**
 * Initialize the encryption module with the Money Tracker config
 * @returns {Promise<Object>} Initialization result
 */
async function initEncryptionModule() {
    console.log('[InitEncryption] Starting encryption module initialization...');

    // Verify all dependencies are loaded
    const dependencies = [
        'EncryptionConfigBase',
        'MoneyTrackerEncryptionConfig',
        'CryptoLibraryLoader',
        'KeyDerivationService',
        'CryptoPrimitivesService',
        'KeyStorageService',
        'HistoricalKeysService',
        'PasswordCryptoService',
        'KeyBackupService',
        'KeyManagementService',
        'EncryptionFacade',
        // SM-37(a): NullEncryptionFacade is intentionally NOT a required dependency.
        // The plaintext path is fenced off; the module only ever selects
        // EncryptionFacade. A tiered build that needs the null facade must opt in
        // behind an explicit, server-independent build flag - never load it by default.
        'EncryptionModule'
    ];

    const missing = dependencies.filter(dep => typeof window[dep] === 'undefined');
    if (missing.length > 0) {
        console.error('[InitEncryption] Missing dependencies:', missing);
        throw new Error(`Missing encryption dependencies: ${missing.join(', ')}`);
    }

    // Initialize the module
    const result = await EncryptionModule.initialize(MoneyTrackerEncryptionConfig);

    console.log('[InitEncryption] Module initialized:', result);

    return result;
}

/**
 * Initialize encryption for the current user
 * Call this after authentication
 * @param {string} userId - User ID (optional, will use AuthService if not provided)
 * @returns {Promise<Object>} Initialization result
 */
async function initEncryptionForUser(userId) {
    // Get user ID from auth service if not provided
    if (!userId && window.AuthService) {
        const user = await AuthService.getCurrentUser();
        userId = user?.id;
    }

    if (!userId) {
        console.warn('[InitEncryption] No user ID - encryption not initialized for user');
        return { success: false, error: 'No user ID' };
    }

    console.log(`[InitEncryption] Initializing encryption for user ${userId.slice(0, 8)}...`);

    if (!EncryptionModule.isInitialized()) {
        await initEncryptionModule();
    }

    return await EncryptionModule.initializeForUser(userId);
}

/**
 * Get the encryption facade for use by other modules
 * @returns {Object} The active encryption facade
 */
function getEncryptionFacade() {
    return EncryptionModule.getFacade();
}

/**
 * Check if encryption is available for the current user
 * @returns {boolean}
 */
function isEncryptionAvailable() {
    return EncryptionModule.isEnabled();
}

// Make functions globally available
if (typeof window !== 'undefined') {
    window.initEncryptionModule = initEncryptionModule;
    window.initEncryptionForUser = initEncryptionForUser;
    window.getEncryptionFacade = getEncryptionFacade;
    window.isEncryptionAvailable = isEncryptionAvailable;
}

console.log('%c[InitEncryption] Encryption bootstrap ready', 'color: green; font-weight: bold');
