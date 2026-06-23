/**
 * Encryption Facade
 *
 * High-level API for encryption operations.
 * Used by premium users who have encryption enabled.
 *
 * This facade provides a simple interface to the underlying
 * key management and encryption services.
 */

const EncryptionFacade = {
    /**
     * Whether the facade is initialized
     */
    initialized: false,

    /**
     * Configuration reference
     */
    _config: null,

    /**
     * Current user ID
     */
    _userId: null,

    /**
     * Whether keys have been generated
     */
    _keysExist: false,

    /**
     * Initialize the encryption facade
     * @param {Object} config - Encryption config object
     * @param {string} userId - User ID
     * @returns {Promise<Object>} { success: boolean, needsSetup?: boolean, needsRestore?: boolean }
     */
    async initialize(config, userId) {
        this._config = config;
        this._userId = userId;

        console.log('[EncryptionFacade] Initializing...');

        const result = await KeyManagementService.initialize(userId, config);

        if (result.success) {
            this.initialized = true;
            this._keysExist = result.keysExist !== false;

            if (!this._keysExist) {
                console.log('[EncryptionFacade] Keys not yet generated - setup required');
                return { success: true, needsSetup: true };
            }

            console.log('[EncryptionFacade] Initialized successfully');
            return { success: true };
        }

        if (result.needsRestore) {
            console.log('[EncryptionFacade] Key restoration required');
            return { success: false, needsRestore: true, keyMismatch: result.keyMismatch, hasBackup: result.hasBackup };
        }

        return { success: false, error: result.error };
    },

    /**
     * Set up encryption for a new user (generate keys)
     * @param {string} password - Password for backup
     * @returns {Promise<Object>} { success: boolean, recoveryKey?: string }
     */
    async setupEncryption(password) {
        if (!this._userId) {
            throw new Error('[EncryptionFacade] Not initialized - call initialize first');
        }

        console.log('[EncryptionFacade] Setting up encryption...');

        const result = await KeyManagementService.generateKeys(password);

        if (result.success) {
            this._keysExist = true;
            this.initialized = true;
        }

        return result;
    },

    /**
     * Restore encryption keys from password
     * @param {string} password - Backup password
     * @returns {Promise<Object>} { success: boolean, error?: string }
     */
    async restoreFromPassword(password) {
        console.log('[EncryptionFacade] Restoring from password...');

        try {
            const result = await KeyManagementService.restoreFromPassword(password);
            if (result.success) {
                this._keysExist = true;
                this.initialized = true;
            }
            return result;
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    /**
     * Restore encryption keys from recovery key
     * @param {string} recoveryKey - Recovery key
     * @returns {Promise<Object>} { success: boolean, error?: string }
     */
    async restoreFromRecoveryKey(recoveryKey) {
        console.log('[EncryptionFacade] Restoring from recovery key...');

        try {
            const result = await KeyManagementService.restoreFromRecoveryKey(recoveryKey);
            if (result.success) {
                this._keysExist = true;
                this.initialized = true;
            }
            return result;
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    /**
     * Encrypt a message for a conversation
     * @param {number|string} conversationId - Conversation ID
     * @param {string} plaintext - Message to encrypt
     * @param {string} recipientId - Recipient's user ID
     * @returns {Promise<Object>} { ciphertext, nonce, counter, epoch, isEncrypted: true }
     */
    async encryptMessage(conversationId, plaintext, recipientId) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }

        // Establish session if needed
        await KeyManagementService.establishSession(conversationId, recipientId);

        // Encrypt
        const encrypted = await KeyManagementService.encryptMessage(conversationId, plaintext);

        return {
            ...encrypted,
            isEncrypted: true
        };
    },

    /**
     * Decrypt a message
     * @param {number|string} conversationId - Conversation ID
     * @param {Object} encryptedData - { ciphertext, nonce, counter, epoch }
     * @param {string} senderId - Sender's user ID
     * @param {string} recipientId - Recipient's user ID (needed for decrypting own messages)
     * @returns {Promise<string>} Decrypted plaintext
     */
    async decryptMessage(conversationId, encryptedData, senderId, recipientId = null) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }

        return await KeyManagementService.decryptMessage(conversationId, encryptedData, senderId, recipientId);
    },

    /**
     * Get safety number for verification
     * @param {string} otherUserId - Other user's ID
     * @returns {Promise<string>} Formatted safety number
     */
    async getSafetyNumber(otherUserId) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }

        return await KeyManagementService.getSafetyNumber(otherUserId);
    },

    /**
     * Regenerate identity keys
     * @returns {Promise<Object>} { success: boolean, newEpoch?: number }
     */
    async regenerateKeys() {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }

        return await KeyManagementService.regenerateKeys();
    },

    /**
     * Check and perform key rotation if due
     * @param {number|null} intervalMs - Optional custom interval in milliseconds
     * @returns {Promise<Object>} { rotated: boolean, reason: string, newEpoch?: number }
     */
    async checkAndRotateIfNeeded(intervalMs = null) {
        if (!this.initialized || !this._keysExist) {
            return { rotated: false, reason: 'not_set_up' };
        }
        return await KeyManagementService.checkAndRotateIfNeeded(intervalMs);
    },

    /**
     * Get key rotation status
     * @returns {Promise<Object>} Rotation status information
     */
    async getRotationStatus() {
        return await KeyManagementService.getRotationStatus();
    },

    /**
     * Get our public key fingerprint
     * @returns {Promise<string|null>} Fingerprint or null
     */
    async getOurFingerprint() {
        return await KeyManagementService.getOurFingerprint();
    },

    /**
     * Get current key epoch
     * @returns {number}
     */
    getCurrentEpoch() {
        return KeyManagementService.currentEpoch;
    },

    /**
     * Check if encryption is enabled
     * @returns {boolean}
     */
    isEncryptionEnabled() {
        return true;
    },

    /**
     * Check if keys are set up
     * @returns {boolean}
     */
    isSetUp() {
        return this.initialized && this._keysExist;
    },

    /**
     * Clear all local encryption data
     */
    async clearLocalData() {
        await KeyManagementService.clearLocalData();
        this.initialized = false;
        this._keysExist = false;
    },

    /**
     * Get encryption status
     * @returns {Object}
     */
    getStatus() {
        return {
            enabled: true,
            initialized: this.initialized,
            keysExist: this._keysExist,
            epoch: KeyManagementService.currentEpoch,
            userId: this._userId?.slice(0, 8) + '...'
        };
    }
};

if (typeof window !== 'undefined') {
    window.EncryptionFacade = EncryptionFacade;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = EncryptionFacade;
}
