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
     * P0-5: per-conversation stash of the sender-side per-message key from the LAST
     * encryptMessage call, kept INSIDE the facade so the raw 32-byte key is NEVER
     * surfaced on the public return object (it must not spread into messaging-layer
     * objects). Consumed once by archivePendingSentKey() after the DB insert returns
     * the message id (§5). { [conversationId]: Uint8Array }
     * @private
     */
    _pendingSentKeys: {},

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
     * @returns {Promise<Object>} { ciphertext, nonce, header, x3dhPreamble?, counter, epoch, isEncrypted: true }
     *          NOTE: the raw per-message key is deliberately NOT included (P0-5).
     *          After the DB insert, call archivePendingSentKey(conversationId, id)
     *          to archive the sender-side key for own-history re-render (§5).
     */
    async encryptMessage(conversationId, plaintext, recipientId) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }

        // Establish session if needed
        await KeyManagementService.establishSession(conversationId, recipientId);

        // Encrypt
        const encrypted = await KeyManagementService.encryptMessage(conversationId, plaintext);

        // P0-5: keep the raw 32-byte per-message key INSIDE the facade — stash it for
        // archivePendingSentKey() and strip it from the public return object so it
        // never spreads into messaging-layer objects.
        const { _messageKey, ...publicResult } = encrypted;
        if (_messageKey) {
            this._pendingSentKeys[String(conversationId)] = _messageKey;
        }

        return {
            ...publicResult,
            isEncrypted: true
        };
    },

    /**
     * Decrypt a message (Double Ratchet, FORWARD_SECRECY_DESIGN §5/§6).
     * @param {number|string} conversationId - Conversation ID
     * @param {Object} encryptedData - { ciphertext, nonce, id, header, x3dhPreamble?, _messageKey? }
     * @param {string} senderId - Sender's user ID
     * @param {string} recipientId - Recipient's user ID (needed for decrypting own messages)
     * @param {Object} [options] - { liveAdvance:boolean } true = realtime arrival
     *        (advance the live ratchet + mint the archive); false/omitted = batch
     *        history re-render (ARCHIVE-ONLY, never advances the ratchet).
     * @returns {Promise<string>} Decrypted plaintext (or the legacy/unavailable sentinel)
     */
    async decryptMessage(conversationId, encryptedData, senderId, recipientId = null, options = {}) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }

        return await KeyManagementService.decryptMessage(conversationId, encryptedData, senderId, recipientId, options);
    },

    /**
     * Publish (or rotate) this user's X3DH prekey bundle + replenish the OPK pool.
     * Idempotent; call after key setup / on login. Delegates to KeyManagementService.
     * @returns {Promise<Object>}
     */
    async publishPrekeys() {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }
        return await KeyManagementService.publishPrekeys();
    },

    /**
     * Archive a sender-side per-message key once the DB returns the message id (§5).
     * @param {number|string} conversationId
     * @param {number|string} messageId
     * @param {Uint8Array} messageKey
     */
    async archiveSentMessageKey(conversationId, messageId, messageKey) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }
        return await KeyManagementService.archiveSentMessageKey(conversationId, messageId, messageKey);
    },

    /**
     * P0-5: archive the sender-side per-message key stashed by the last
     * encryptMessage(conversationId) call, now that the DB insert has returned the
     * message id (§5). The raw key never left the facade. Consumes (clears) the
     * stash. No-op if nothing is stashed (e.g. a legacy/no-key send).
     * @param {number|string} conversationId
     * @param {number|string} messageId
     * @returns {Promise<boolean>} true if a key was archived
     */
    async archivePendingSentKey(conversationId, messageId) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }
        const key = String(conversationId);
        const mk = this._pendingSentKeys[key];
        if (!mk) return false;
        delete this._pendingSentKeys[key];
        await KeyManagementService.archiveSentMessageKey(conversationId, messageId, mk);
        return true;
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
     * Read a peer's PENDING (newly server-advertised) identity WITHOUT pinning it, so
     * the UI can show the NEW key's safety number to verify out-of-band before
     * accepting a pending identity change (P0-follow-up). getSafetyNumber throws while
     * a change is pending (fail-closed); this read-only method does not, and never
     * re-pins — a subsequent establishSession still fails closed until accept.
     * @param {string} otherUserId - Peer user id
     * @returns {Promise<{userId,changed,oldFingerprint,newFingerprint,oldSafetyNumber,newSafetyNumber}>}
     */
    async getPendingPeerIdentity(otherUserId) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }
        return await KeyManagementService.getPendingPeerIdentity(otherUserId);
    },

    /**
     * Adopt a CHANGED peer identity after the user has verified it out-of-band
     * (compared the safety number). Re-pins the peer's new X25519 IK + Ed25519
     * IK_sig, clearing the fail-closed PeerIdentityChangedError block so the next
     * send/decrypt proceeds. MUST be gated behind explicit user verification — never
     * call this automatically on a change notice. (P0-1/P0-2 accept path.)
     * @param {string} otherUserId - Peer whose identity change the user accepts
     * @returns {Promise<{accepted:boolean, identityFingerprint?:string, signFingerprint?:string}>}
     */
    async acceptPeerIdentityChange(otherUserId) {
        if (!this.initialized || !this._keysExist) {
            throw new Error('[EncryptionFacade] Encryption not set up');
        }
        return await KeyManagementService.acceptPeerIdentityChange(otherUserId);
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
