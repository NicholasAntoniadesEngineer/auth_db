/**
 * Key Management Service
 *
 * High-level orchestration of all encryption key operations.
 * Coordinates between:
 * - CryptoPrimitivesService (crypto operations)
 * - KeyStorageService (local IndexedDB)
 * - KeyBackupService (database backups)
 * - HistoricalKeysService (key history)
 * - KeyDerivationService (HKDF)
 */

const KeyManagementService = {
    /**
     * Current user ID
     */
    currentUserId: null,

    /**
     * Current key epoch
     */
    currentEpoch: 0,

    /**
     * Session backup key for encrypting session keys
     * This key is derived from the user's password and survives identity key rotation
     */
    _sessionBackupKey: null,

    /**
     * Key rotation lock state
     */
    _rotationInProgress: false,
    _rotationLockToken: null,

    /**
     * Whether the service is initialized
     */
    initialized: false,

    /**
     * Configuration (set during initialize)
     */
    _config: null,

    /**
     * Database service reference
     */
    _database: null,

    /**
     * Initialize the service for a user
     * @param {Object} config - Encryption config object
     * @param {string} userId - User ID
     * @returns {Promise<Object>} { success: boolean, needsRestore?: boolean, error?: string }
     */
    async initialize(userId, config) {
        this._config = config;
        this._database = config.services?.database;

        // Validate userId
        if (!userId || typeof userId !== 'string') {
            console.error('[KeyManagementService] Invalid userId provided:', userId, typeof userId);
            throw new Error('KeyManagementService.initialize requires a valid userId string');
        }

        this.currentUserId = userId;

        console.log('[KeyManagementService] Initializing for user');

        try {
            await CryptoPrimitivesService.initialize(config);
            await KeyStorageService.initialize(config);
            KeyDerivationService.initialize(config);
            HistoricalKeysService.initialize(config);
            KeyBackupService.initialize(config);
            PasswordCryptoService.initialize(config);

            let keys;
            try {
                keys = await KeyStorageService.getIdentityKeys(userId);
            } catch (identityError) {
                // The wrapped identity record physically exists but could not be
                // unwrapped this session (wrap key missing/unusable - e.g. Safari
                // evicted the CryptoKey, or the record was written under a different
                // wrap key). This is a same-device user WITH a local identity, not a
                // "no keys" situation. We must NOT silently force the recovery prompt
                // and we must NOT wipe the record (a future session may unwrap it).
                // Surface it deterministically so the caller can decide.
                if (identityError &&
                    (identityError.code === 'IDENTITY_UNWRAP_FAILED' ||
                     identityError.code === 'WRAP_KEY_UNAVAILABLE')) {
                    console.error('[KeyManagementService] Local identity present but unreadable this session:', identityError.code);
                    const hasBackup = await KeyBackupService.hasBackup(userId);
                    return {
                        success: false,
                        needsRestore: hasBackup,
                        hasBackup,
                        identityUnreadable: true,
                        error: identityError.code
                    };
                }
                throw identityError;
            }

            if (!keys) {
                const hasBackup = await KeyBackupService.hasBackup(userId);
                if (hasBackup) {
                    console.log('[KeyManagementService] No local keys, backup exists - restoration required');
                    return { success: false, needsRestore: true, hasBackup: true };
                }
                console.log('[KeyManagementService] No keys found - ready for generation');
                this.initialized = true;
                return { success: true, keysExist: false };
            }

            // Verify local keys match database.
            //
            // On the SAME device the local (successfully-unwrapped) identity key is
            // the source of truth: it is the private half we actually encrypt with.
            // A difference vs the server's published public key is almost always a
            // benign server lag (e.g. the server row was never updated after a
            // clean-break restore, or another device's epoch propagated). The old
            // behaviour - clearAll() + demand restore on ANY difference - is exactly
            // what asked a same-device user for the recovery key on every login.
            //
            // Correct behaviour: trust the working local key and RE-UPLOAD it to the
            // server (self-heal), instead of destroying it. We never wipe a valid
            // local identity here.
            const localPublicKeyB64 = CryptoPrimitivesService.serializeKey(keys.publicKey);
            const dbPublicKey = await HistoricalKeysService.getCurrentKey(userId);

            if (!dbPublicKey) {
                console.log('[KeyManagementService] Server key missing, uploading local key');
                await this._uploadPublicKeyToServer(userId, localPublicKeyB64);
            } else if (localPublicKeyB64 !== dbPublicKey) {
                console.log('[KeyManagementService] Local/server public key differ - re-publishing local key (no wipe)');
                await this._uploadPublicKeyToServer(userId, localPublicKeyB64);
            }

            await this._fetchCurrentEpoch(userId);
            if (this._sessionBackupKey) {
                await this._syncSessionKeys(userId);
            }
            await HistoricalKeysService.syncToLocal(userId);
            await this._syncConversationPartnerKeys(userId);

            this.initialized = true;
            console.log(`[KeyManagementService] Initialized with epoch ${this.currentEpoch}`);
            return { success: true, keysExist: true };
        } catch (error) {
            console.error('[KeyManagementService] Initialization failed:', error);
            return { success: false, error: error.message };
        }
    },

    /**
     * Generate and store identity keys without creating a backup
     * Used during device pairing when backup creation is a separate step
     * @param {string} userId - User ID to generate keys for
     * @returns {Promise<Object>} { success: boolean, publicKey: string }
     */
    async generateAndStoreIdentityKeys(userId) {
        if (!userId || typeof userId !== 'string') {
            throw new Error('[KeyManagementService] generateAndStoreIdentityKeys requires a valid userId');
        }

        // Set current user if not set
        if (!this.currentUserId) {
            this.currentUserId = userId;
        }

        // CRITICAL: Check if backup already exists - prevent overwriting keys from another device
        const hasExistingBackup = await KeyBackupService.hasBackup(userId);
        if (hasExistingBackup) {
            console.error('[KeyManagementService] ❌ BLOCKED: Cannot generate new keys - backup already exists!');
            console.error('[KeyManagementService] User must restore from password backup instead');
            throw new Error('Encryption keys already exist. Use "Restore from Another Device" to sync your keys.');
        }

        console.log('[KeyManagementService] Generating and storing identity keys...');

        // CRITICAL: Clear any old session keys from IndexedDB
        // Old sessions are invalid with new identity keys
        console.log('[KeyManagementService] Clearing old session keys...');
        await KeyStorageService.clearAll();

        // Generate new key pair
        const keys = CryptoPrimitivesService.generateKeyPair();
        const publicKeyB64 = CryptoPrimitivesService.serializeKey(keys.publicKey);

        // Store locally
        await KeyStorageService.storeIdentityKeys(userId, keys);

        // Store public key in database - CRITICAL for E2E encryption
        if (this._database) {
            const identityTable = this._config?.tables?.identityKeys || 'identity_keys';
            console.log(`[KeyManagementService] Storing public key in ${identityTable}`);

            try {
                const result = await this._database.queryUpsert(identityTable, {
                    user_id: userId,
                    public_key: publicKeyB64,
                    current_epoch: 0,
                    updated_at: new Date().toISOString()
                }, {
                    onConflict: 'user_id',
                    returning: true
                });

                if (result.error) {
                    console.error(`[KeyManagementService] CRITICAL: Failed to store public key in database:`, result.error);
                    throw new Error(`Failed to store identity key: ${result.error.message || result.error}`);
                }

                console.log(`[KeyManagementService] Public key stored in database successfully`);
            } catch (dbError) {
                console.error(`[KeyManagementService] CRITICAL: Database error storing public key:`, dbError);
                throw new Error(`Failed to store identity key in database: ${dbError.message}`);
            }
        } else {
            console.error(`[KeyManagementService] CRITICAL: No database service - public key NOT stored remotely!`);
            throw new Error('Database service not available - cannot store identity key');
        }

        // Store initial public key in history (epoch 0)
        await HistoricalKeysService.storeKey(userId, publicKeyB64, 0);

        this.currentEpoch = 0;

        // Sync historical keys for all conversation partners
        // This ensures we can decrypt messages from existing conversations
        await this._syncConversationPartnerKeys(userId);

        console.log('[KeyManagementService] Identity keys generated and stored');

        return {
            success: true,
            publicKey: publicKeyB64,
            fingerprint: CryptoPrimitivesService.getKeyFingerprint(keys.publicKey)
        };
    },

    /**
     * Create a dual backup (password + recovery key) for existing identity keys
     * Called after generateAndStoreIdentityKeys during device pairing
     * @param {string} password - Password for backup encryption
     * @param {string} recoveryKey - 24-word recovery key (generated by CryptoPrimitivesService.generateRecoveryKey)
     * @returns {Promise<Object>} { success: boolean }
     */
    async createDualBackup(password, recoveryKey) {
        if (!this.currentUserId) {
            throw new Error('[KeyManagementService] No user ID set - call generateAndStoreIdentityKeys first');
        }

        if (!password || typeof password !== 'string') {
            throw new Error('[KeyManagementService] createDualBackup requires a valid password');
        }

        if (!recoveryKey || typeof recoveryKey !== 'string') {
            throw new Error('[KeyManagementService] createDualBackup requires a valid recovery key');
        }

        console.log('[KeyManagementService] Creating dual backup...');

        // Get the identity keys from local storage
        const keys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!keys || !keys.secretKey) {
            throw new Error('[KeyManagementService] No identity keys found - generate keys first');
        }

        // Create encrypted backup with password and the provided recovery key
        // This generates a stable session backup key for multi-device support
        const backupResult = await KeyBackupService.createIdentityBackupWithRecoveryKey(
            this.currentUserId,
            keys.secretKey,
            password,
            recoveryKey
        );

        // Store the session backup key
        this._sessionBackupKey = backupResult.sessionBackupKey;

        if (!this._sessionBackupKey) {
            throw new Error('[KeyManagementService] Failed to create session backup key');
        }

        this.initialized = true;

        console.log('[KeyManagementService] Dual backup created successfully');

        return { success: true };
    },

    /**
     * Create a password-only backup for existing identity keys
     * Used after password reset to re-encrypt backup with new password
     * @param {string} password - User's new password
     * @returns {Promise<Object>} { success: boolean }
     */
    async createPasswordOnlyBackup(password) {
        if (!this.currentUserId) {
            throw new Error('[KeyManagementService] No user ID set');
        }
        if (!password || typeof password !== 'string') {
            throw new Error('[KeyManagementService] createPasswordOnlyBackup requires a valid password');
        }

        console.log('[KeyManagementService] Creating password-only backup...');

        const keys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!keys || !keys.secretKey) {
            throw new Error('[KeyManagementService] No identity keys found - generate keys first');
        }

        const backupResult = await KeyBackupService.createPasswordOnlyBackup(
            this.currentUserId,
            keys.secretKey,
            password
        );

        this._sessionBackupKey = backupResult.sessionBackupKey;
        if (!this._sessionBackupKey) {
            throw new Error('[KeyManagementService] Failed to create session backup key');
        }

        this.initialized = true;
        console.log('[KeyManagementService] Password-only backup created successfully');
        return { success: true };
    },

    /**
     * Generate new identity keys for the user
     * @param {string} password - Password for backup encryption
     * @returns {Promise<Object>} { success: boolean, recoveryKey?: string }
     */
    async generateKeys(password) {
        if (!this.currentUserId) {
            throw new Error('[KeyManagementService] No user ID set');
        }

        // CRITICAL: Check if backup already exists - prevent overwriting keys from another device
        const hasExistingBackup = await KeyBackupService.hasBackup(this.currentUserId);
        if (hasExistingBackup) {
            console.error('[KeyManagementService] ❌ BLOCKED: Cannot generate new keys - backup already exists!');
            console.error('[KeyManagementService] User must restore from password backup instead');
            throw new Error('Encryption keys already exist. Use "Restore from Another Device" to sync your keys.');
        }

        console.log('[KeyManagementService] Generating new identity keys...');

        // CRITICAL: Clear any old session keys from IndexedDB
        // Old sessions are invalid with new identity keys
        console.log('[KeyManagementService] Clearing old session keys...');
        await KeyStorageService.clearAll();

        // Generate new key pair
        const keys = CryptoPrimitivesService.generateKeyPair();
        const publicKeyB64 = CryptoPrimitivesService.serializeKey(keys.publicKey);

        // Store locally
        await KeyStorageService.storeIdentityKeys(this.currentUserId, keys);

        // Store public key in database - CRITICAL for E2E encryption
        if (this._database) {
            const identityTable = this._config?.tables?.identityKeys || 'identity_keys';
            console.log(`[KeyManagementService] Storing public key in ${identityTable}`);

            try {
                const result = await this._database.queryUpsert(identityTable, {
                    user_id: this.currentUserId,
                    public_key: publicKeyB64,
                    current_epoch: 0,
                    updated_at: new Date().toISOString()
                }, {
                    onConflict: 'user_id',
                    returning: true
                });

                if (result.error) {
                    console.error(`[KeyManagementService] CRITICAL: Failed to store public key in database:`, result.error);
                    throw new Error(`Failed to store identity key: ${result.error.message || result.error}`);
                }

                console.log(`[KeyManagementService] Public key stored in database successfully`);
            } catch (dbError) {
                console.error(`[KeyManagementService] CRITICAL: Database error storing public key:`, dbError);
                throw new Error(`Failed to store identity key in database: ${dbError.message}`);
            }
        } else {
            console.error(`[KeyManagementService] CRITICAL: No database service - public key NOT stored remotely!`);
            throw new Error('Database service not available - cannot store identity key');
        }

        // Create encrypted backup (this also generates the stable session backup key)
        const backupResult = await KeyBackupService.createIdentityBackup(
            this.currentUserId,
            keys.secretKey,
            password
        );

        // Store initial public key in history (epoch 0)
        await HistoricalKeysService.storeKey(this.currentUserId, publicKeyB64, 0);

        // Store the session backup key (required for multi-device sync)
        this._sessionBackupKey = backupResult.sessionBackupKey;

        if (!this._sessionBackupKey) {
            throw new Error('[KeyManagementService] Failed to create session backup key');
        }

        this.currentEpoch = 0;
        this.initialized = true;

        // Sync historical keys for all conversation partners
        // This ensures we can decrypt messages from existing conversations
        await this._syncConversationPartnerKeys(this.currentUserId);

        console.log('[KeyManagementService] Keys generated successfully');

        return {
            success: true,
            recoveryKey: backupResult.recoveryKey,
            publicKey: publicKeyB64,
            fingerprint: CryptoPrimitivesService.getKeyFingerprint(keys.publicKey)
        };
    },

    /**
     * Restore keys from password backup
     * @param {string} password - Backup password
     * @returns {Promise<Object>} { success: boolean }
     */
    async restoreFromPassword(password) {
        console.log('[KeyManagementService] Restoring from password...');

        // Validate the password by decrypting the backup BEFORE destroying local state,
        // so a wrong/stale password can never wipe a present-but-unreadable local identity
        // (the data-loss class the recent login fix addressed).
        const secretKey = await KeyBackupService.restoreFromPassword(this.currentUserId, password);
        await KeyStorageService.clearAll();

        // Derive public key from secret key to ensure cryptographic consistency
        const keyPair = CryptoPrimitivesService.keyPairFromSecretKey(secretKey);
        const publicKey = keyPair.publicKey;
        const derivedPublicKeyB64 = CryptoPrimitivesService.serializeKey(publicKey);

        // Verify against database and auto-repair if mismatched
        const dbPublicKeyB64 = await HistoricalKeysService.getCurrentKey(this.currentUserId);
        if (dbPublicKeyB64 && dbPublicKeyB64 !== derivedPublicKeyB64) {
            console.error('[KeyManagementService] Public key mismatch - updating database with derived key');
            await this._uploadPublicKeyToServer(this.currentUserId, derivedPublicKeyB64);
        }

        await KeyStorageService.storeIdentityKeys(this.currentUserId, { publicKey, secretKey });
        await this._fetchCurrentEpoch(this.currentUserId);

        // Restore session backup key
        this._sessionBackupKey = await KeyBackupService.restoreSessionBackupKey(this.currentUserId, password);
        if (!this._sessionBackupKey) {
            console.warn('[KeyManagementService] No session backup key - sessions will use ECDH');
        }

        await this._syncSessionKeys(this.currentUserId);
        await HistoricalKeysService.syncToLocal(this.currentUserId);
        await this._syncConversationPartnerKeys(this.currentUserId);

        this.initialized = true;
        console.log('[KeyManagementService] Restored successfully');
        return { success: true };
    },

    /**
     * Restore keys from recovery key
     * Note: Recovery key restores identity keys but not session keys.
     * After recovery, user must establish new sessions for conversations.
     * @param {string} recoveryKey - Recovery key
     * @returns {Promise<Object>} { success: boolean }
     */
    async restoreFromRecoveryKey(recoveryKey) {
        console.log('[KeyManagementService] Restoring from recovery key...');

        // Validate the recovery key by decrypting the backup BEFORE destroying local state.
        const secretKey = await KeyBackupService.restoreFromRecoveryKey(this.currentUserId, recoveryKey);
        await KeyStorageService.clearAll();

        const keyPair = CryptoPrimitivesService.keyPairFromSecretKey(secretKey);
        const publicKey = keyPair.publicKey;
        const derivedPublicKeyB64 = CryptoPrimitivesService.serializeKey(publicKey);

        // Verify against database and auto-repair if mismatched
        const dbPublicKeyB64 = await HistoricalKeysService.getCurrentKey(this.currentUserId);
        if (dbPublicKeyB64 && dbPublicKeyB64 !== derivedPublicKeyB64) {
            console.error('[KeyManagementService] Public key mismatch - updating database with derived key');
            await this._uploadPublicKeyToServer(this.currentUserId, derivedPublicKeyB64);
        }

        await KeyStorageService.storeIdentityKeys(this.currentUserId, { publicKey, secretKey });
        await this._fetchCurrentEpoch(this.currentUserId);

        // Recovery key cannot restore the session backup key - sessions will use ECDH
        this._sessionBackupKey = null;

        await HistoricalKeysService.syncToLocal(this.currentUserId);

        // Sync historical keys for all conversation partners
        await this._syncConversationPartnerKeys(this.currentUserId);

        this.initialized = true;
        console.log('[KeyManagementService] Restored successfully (identity keys only)');

        return { success: true, sessionKeysAvailable: false };
    },

    /**
     * Acquire a lock for key rotation
     * Prevents concurrent rotations across devices/tabs
     * @private
     * @returns {Promise<boolean>} True if lock acquired
     */
    async _acquireRotationLock() {
        // Check in-memory flag first
        if (this._rotationInProgress) {
            console.warn('[KeyManagementService] Rotation already in progress (in-memory lock)');
            return false;
        }

        this._rotationInProgress = true;
        this._rotationLockToken = crypto.randomUUID ? crypto.randomUUID() :
            `lock_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Try to acquire database lock
        if (this._database) {
            try {
                const lockTable = this._config?.tables?.keyRotationLocks || 'key_rotation_locks';
                const expiresAt = new Date(Date.now() + 60000).toISOString(); // 60 second lock

                await this._database.queryUpsert(lockTable, {
                    user_id: this.currentUserId,
                    lock_token: this._rotationLockToken,
                    locked_at: new Date().toISOString(),
                    expires_at: expiresAt
                }, {
                    onConflict: 'user_id',
                    returning: true
                });

                console.log('[KeyManagementService] Acquired rotation lock');
                return true;
            } catch (error) {
                console.error('[KeyManagementService] Failed to acquire database lock:', error);
                this._rotationInProgress = false;
                this._rotationLockToken = null;
                return false;
            }
        }

        return true;
    },

    /**
     * Release the key rotation lock
     * @private
     */
    async _releaseRotationLock() {
        if (this._database && this._rotationLockToken) {
            try {
                const lockTable = this._config?.tables?.keyRotationLocks || 'key_rotation_locks';
                await this._database.queryDelete(lockTable, {
                    filter: {
                        user_id: this.currentUserId,
                        lock_token: this._rotationLockToken
                    }
                });
                console.log('[KeyManagementService] Released rotation lock');
            } catch (error) {
                console.warn('[KeyManagementService] Failed to release database lock:', error);
            }
        }

        this._rotationInProgress = false;
        this._rotationLockToken = null;
    },

    /**
     * Regenerate identity keys (key rotation)
     * Uses locking to prevent concurrent rotations
     * @returns {Promise<Object>} { success: boolean, newEpoch: number }
     */
    async regenerateKeys() {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }

        // Acquire lock before rotation
        const lockAcquired = await this._acquireRotationLock();
        if (!lockAcquired) {
            throw new Error('[KeyManagementService] Key rotation already in progress - please wait');
        }

        try {
            console.log('[KeyManagementService] Regenerating keys...');

            const oldKeys = await KeyStorageService.getIdentityKeys(this.currentUserId);
            const oldEpoch = this.currentEpoch;

            // Archive old public key BEFORE generating new
            await HistoricalKeysService.storeKey(
                this.currentUserId,
                CryptoPrimitivesService.serializeKey(oldKeys.publicKey),
                oldEpoch
            );

            // Generate new keys
            const newKeys = CryptoPrimitivesService.generateKeyPair();
            const newPublicKeyB64 = CryptoPrimitivesService.serializeKey(newKeys.publicKey);
            const newEpoch = oldEpoch + 1;

            // Store new keys locally
            await KeyStorageService.storeIdentityKeys(this.currentUserId, newKeys);

            // Update database
            if (this._database) {
                const identityTable = this._config?.tables?.identityKeys || 'identity_keys';

                await this._database.queryUpdate(identityTable, {
                    public_key: newPublicKeyB64,
                    current_epoch: newEpoch,
                    updated_at: new Date().toISOString()
                }, {
                    user_id: this.currentUserId
                });
            }

            // Store new key in history
            await HistoricalKeysService.storeKey(this.currentUserId, newPublicKeyB64, newEpoch);

            // Update password backup with new rotated keys
            const password = window.PasswordManager?.retrieve();
            if (password) {
                console.log('[KeyManagementService] Updating backup with rotated keys...');
                await KeyBackupService.createPasswordOnlyBackup(this.currentUserId, newKeys.secretKey, password);
                console.log('[KeyManagementService] Backup updated with rotated keys');
            }

            this.currentEpoch = newEpoch;

            console.log(`[KeyManagementService] Keys regenerated. New epoch: ${newEpoch}`);

            return {
                success: true,
                newEpoch,
                fingerprint: CryptoPrimitivesService.getKeyFingerprint(newKeys.publicKey)
            };
        } finally {
            // Always release the lock
            await this._releaseRotationLock();
        }
    },

    /**
     * Check if key rotation is due and rotate if needed
     * @param {number|null} intervalMs - Custom interval (uses config if null)
     * @returns {Promise<Object>} { rotated: boolean, reason: string, newEpoch?: number }
     */
    async checkAndRotateIfNeeded() {
        // Auto-rotation disabled: ECDH session derivation uses identity keys,
        // so rotating them invalidates all existing sessions and breaks decryption
        // of messages encrypted with the old key pair.
        return { rotated: false, reason: 'auto_rotation_disabled' };
    },

    /**
     * Get rotation status
     * @returns {Promise<Object>} Current rotation status
     */
    async getRotationStatus() {
        if (!this._database || !this.currentUserId) {
            return { configured: false };
        }

        const rotationConfig = this._config?.keyRotation || {};
        const identityTable = this._config?.tables?.identityKeys || 'identity_keys';

        try {
            const result = await this._database.querySelect(identityTable, {
                filter: { user_id: this.currentUserId },
                limit: 1
            });

            const lastUpdated = result.data?.[0]?.updated_at;
            const now = Date.now();
            const lastRotationTime = lastUpdated ? new Date(lastUpdated).getTime() : null;
            const interval = rotationConfig.intervalMs || 86400000;

            return {
                configured: true,
                enabled: rotationConfig.enabled !== false,
                intervalMs: interval,
                intervalHuman: this._formatDuration(interval),
                lastRotation: lastUpdated,
                timeSinceLastRotation: lastRotationTime ? now - lastRotationTime : null,
                timeSinceHuman: lastRotationTime ? this._formatDuration(now - lastRotationTime) : null,
                currentEpoch: this.currentEpoch
            };
        } catch (error) {
            console.error('[KeyManagementService] Failed to get rotation status:', error);
            return { configured: false, error: error.message };
        }
    },

    /**
     * Format duration for human-readable output
     * @private
     * @param {number} ms - Duration in milliseconds
     * @returns {string} Human-readable duration
     */
    _formatDuration(ms) {
        const hours = Math.floor(ms / 3600000);
        const minutes = Math.floor((ms % 3600000) / 60000);
        if (hours > 24) {
            const days = Math.floor(hours / 24);
            return `${days}d ${hours % 24}h`;
        }
        return `${hours}h ${minutes}m`;
    },

    /**
     * Establish a session with another user for a conversation
     * @param {number|string} conversationId - Conversation ID
     * @param {string} otherUserId - Other user's ID
     * @returns {Promise<Object>} { sessionKey, epoch, counter }
     */
    async establishSession(conversationId, otherUserId) {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }

        // Always use epoch 0 - key rotation is disabled for reliability
        const epoch = 0;

        // Check if session already exists
        let session = await KeyStorageService.getSessionKey(conversationId, epoch);
        if (session) {
            console.log(`[KeyManagementService] establishSession: Using cached session for conv=${conversationId}`);
            return {
                sessionKey: session.sessionKey,
                epoch: epoch,
                counter: session.counter
            };
        }

        console.log(`[KeyManagementService] establishSession: Creating NEW session for conv=${conversationId}`);

        // Get other user's current public key (SM-01: through the TOFU pin chokepoint)
        const theirPublicKeyB64 = await this._getPinnedPeerKey(otherUserId);
        if (!theirPublicKeyB64) {
            throw new Error('Other user has no public key - they may not have set up encryption yet');
        }

        // Get our keys
        const ourKeys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!ourKeys) {
            throw new Error('No local identity keys - run device pairing first');
        }
        // ECDH key agreement
        const theirPublicKey = CryptoPrimitivesService.deserializeKey(theirPublicKeyB64);
        const sharedSecret = CryptoPrimitivesService.deriveSharedSecret(ourKeys.secretKey, theirPublicKey);

        // Derive session key (always epoch 0)
        const sessionKey = await KeyDerivationService.deriveSessionKey(sharedSecret, epoch);

        // Store locally
        await KeyStorageService.storeSessionKey(conversationId, epoch, sessionKey, 0);

        // Backup to database using the session backup key
        if (this._sessionBackupKey) {
            await KeyBackupService.backupSessionKey(
                this.currentUserId,
                conversationId,
                sessionKey,
                epoch,
                this._sessionBackupKey
            );
            console.log(`[KeyManagementService] establishSession: Session backed up to database`);
        } else {
            console.log(`[KeyManagementService] establishSession: No session backup key - session NOT backed up`);
        }

        console.log(`[KeyManagementService] establishSession: Session created for conv=${conversationId}`);

        return {
            sessionKey,
            epoch: epoch,
            counter: 0
        };
    },

    /**
     * Maximum safe counter value to prevent overflow
     * JavaScript's Number.MAX_SAFE_INTEGER is 2^53 - 1
     * We use a lower limit to leave headroom for any arithmetic
     */
    MAX_COUNTER: Number.MAX_SAFE_INTEGER - 1000,

    /**
     * Encrypt a message
     * @param {number|string} conversationId - Conversation ID
     * @param {string} plaintext - Message to encrypt
     * @returns {Promise<Object>} { ciphertext, nonce, counter, epoch }
     */
    async encryptMessage(conversationId, plaintext) {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }

        // Always use epoch 0
        const epoch = 0;
        const session = await KeyStorageService.getSessionKey(conversationId, epoch);
        if (!session) {
            throw new Error('No session - call establishSession first');
        }

        // Check for counter overflow
        if (session.counter >= this.MAX_COUNTER) {
            console.error(`[KeyManagementService] Counter overflow: ${session.counter}`);
            throw new Error('Message counter overflow');
        }

        // Derive message-specific key
        const messageKey = await KeyDerivationService.deriveMessageKey(
            session.sessionKey,
            epoch,
            session.counter
        );

        // Encrypt
        const encrypted = CryptoPrimitivesService.encrypt(plaintext, messageKey);
        const counter = session.counter;

        // Increment counter
        await KeyStorageService.incrementCounter(conversationId, epoch);

        // Update backup counter
        if (this._sessionBackupKey) {
            await KeyBackupService.updateSessionCounter(
                this.currentUserId,
                conversationId,
                epoch,
                counter + 1
            );
        }

        return {
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            counter: counter,
            epoch: epoch
        };
    },

    /**
     * Build a typed DecryptionError when the error class is available, otherwise
     * fall back to a plain Error so the failure still propagates loudly.
     * @private
     * @param {string} reason
     * @param {string} context
     * @returns {Error}
     */
    _decryptionError(reason, context) {
        const Cls = (typeof DecryptionError !== 'undefined')
            ? DecryptionError
            : (typeof window !== 'undefined' && window.DecryptionError) || null;
        return Cls ? new Cls(reason, context) : new Error(`${reason} while decrypting ${context}`);
    },

    /**
     * Decrypt a message
     * @param {number|string} conversationId - Conversation ID
     * @param {Object} encryptedData - { ciphertext, nonce, counter, epoch }
     * @param {string} senderId - Sender's user ID
     * @param {string} recipientId - Recipient's user ID (optional, for decrypting own messages)
     * @returns {Promise<string>} Decrypted plaintext
     */
    async decryptMessage(conversationId, encryptedData, senderId, recipientId = null) {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }

        const { ciphertext, nonce, counter } = encryptedData;
        const epoch = 0;

        if (typeof counter !== 'number' || counter < 0 || !Number.isInteger(counter)) {
            throw new Error(`Invalid counter value: ${counter}`);
        }

        // Determine other user for ECDH derivation
        const otherUserId = senderId === this.currentUserId ? recipientId : senderId;
        if (!otherUserId) {
            throw new Error('Cannot determine other user for ECDH - recipientId not provided');
        }

        // Get or derive session key
        let session = await KeyStorageService.getSessionKey(conversationId, epoch);
        let usedCachedSession = !!session;

        if (!session) {
            session = await this._deriveSessionFromHistory(conversationId, otherUserId);
        }
        if (!session) {
            throw new Error('Cannot decrypt - no session key available');
        }

        // Derive message key and attempt to decrypt
        const messageKey = await KeyDerivationService.deriveMessageKey(session.sessionKey, epoch, counter);

        let plaintext;
        try {
            plaintext = CryptoPrimitivesService.decrypt(ciphertext, nonce, messageKey);
        } catch (authFailure) {
            // SM-24: do NOT silently rebuild the session and swallow auth failures.
            // The single allowed retry is a genuine stale-cache repair: re-derive
            // ONCE from history (which routes through _getPinnedPeerKey, so a server
            // key swap has already been warned about) and retry ONLY if the freshly
            // derived session key actually differs from the cached one. Otherwise the
            // failure is real tampering/corruption and we throw a typed error.
            if (usedCachedSession) {
                const freshSession = await this._deriveSessionFromHistory(conversationId, otherUserId);

                const sessionKeyChanged = freshSession &&
                    !CryptoPrimitivesService.constantTimeEqual(freshSession.sessionKey, session.sessionKey);

                if (sessionKeyChanged) {
                    const retryKey = await KeyDerivationService.deriveMessageKey(freshSession.sessionKey, epoch, counter);
                    try {
                        plaintext = CryptoPrimitivesService.decrypt(ciphertext, nonce, retryKey);
                        // Adopt the repaired session for subsequent messages.
                        session = freshSession;
                    } catch (retryFailure) {
                        throw this._decryptionError('authentication failed', 'message');
                    }
                } else {
                    // No different session to try - real tamper/auth failure.
                    // Note: we do NOT delete the cached session here; deleting it was
                    // pure masking and forced a needless re-derive on every load.
                    throw this._decryptionError('authentication failed', 'message');
                }
            } else {
                throw this._decryptionError('authentication failed', 'message');
            }
        }

        // SM-10: replay high-water mark — ADVANCE-ONLY here (must not reject).
        // decryptMessage is invoked for FULL HISTORY re-decryption on every conversation
        // open (newest-first, in parallel via Promise.all). Rejecting counter < last would
        // therefore reject legitimate older history after the newest message advanced the
        // mark — breaking the round trip. So here we only track the per-sender high-water
        // mark (best-effort, never blocking). Strict at-most-once rejection of a freshly
        // REPLAYED message must be enforced on the realtime single-message arrival path,
        // not in batch history decryption (tracked as a follow-up).
        if (senderId !== this.currentUserId) {
            try {
                const last = await KeyStorageService.getLastCounter(conversationId, epoch, senderId);
                if (counter > last) {
                    await KeyStorageService.setLastCounter(conversationId, epoch, senderId, counter);
                }
            } catch (e) {
                // Counter bookkeeping must never block a successful decryption.
            }
        }

        return plaintext;
    },

    /**
     * SM-01: Fetch a peer's current public key through a TOFU (trust-on-first-use)
     * pin. This is the single chokepoint both ECDH derivation sites use instead of
     * calling HistoricalKeysService.getCurrentKey directly.
     *
     * Policy (non-blocking, smooth-UX):
     *  - First contact: pin the fetched key, return it.
     *  - Unchanged key (common case): return it verbatim - byte-identical to today.
     *  - Changed key: dispatch a one-shot `peerKeyChanged` event (warn, do NOT
     *    block), then adopt + re-pin the new key so the conversation keeps working.
     *    We only warn once per distinct new fingerprint.
     *
     * @private
     * @param {string} otherUserId - Peer user ID
     * @returns {Promise<string|null>} Base64 public key or null
     */
    async _getPinnedPeerKey(otherUserId) {
        const fetched = await HistoricalKeysService.getCurrentKey(otherUserId);
        if (!fetched) {
            return null;
        }

        const fp = CryptoPrimitivesService.getKeyFingerprint(
            CryptoPrimitivesService.deserializeKey(fetched)
        );
        const pinned = await KeyStorageService.getPinnedKey(otherUserId);

        if (!pinned) {
            // First contact - trust on first use.
            await KeyStorageService.pinKey(otherUserId, fetched, fp);
            return fetched;
        }

        if (pinned.publicKey === fetched) {
            // Unchanged - normal case.
            return fetched;
        }

        // Key changed: WARN (one-shot per distinct new key), do not block.
        if (pinned.lastWarnedFingerprint !== fp) {
            if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
                window.dispatchEvent(new CustomEvent('peerKeyChanged', {
                    detail: {
                        userId: otherUserId,
                        oldFingerprint: pinned.fingerprint,
                        newFingerprint: fp
                    }
                }));
            }
            await KeyStorageService.updatePinnedWarn(otherUserId, fp);
        }

        // Clean-break / smooth-UX: adopt + re-pin the new key (pinKey preserves
        // lastWarnedFingerprint), so we keep working and only warn once.
        await KeyStorageService.pinKey(otherUserId, fetched, fp);
        return fetched;
    },

    /**
     * Get a sender's current epoch from the database
     * Used to validate message epochs aren't from the "future"
     * @private
     * @param {string} senderId - Sender's user ID
     * @returns {Promise<number|null>} Current epoch or null if not found
     */
    async _getSenderCurrentEpoch(senderId) {
        if (!this._database) {
            return null;
        }

        try {
            const identityTable = this._config?.tables?.identityKeys || 'identity_keys';
            const result = await this._database.querySelect(identityTable, {
                filter: { user_id: senderId },
                limit: 1
            });

            return result.data?.[0]?.current_epoch ?? null;
        } catch (error) {
            console.warn(`[KeyManagementService] Could not fetch sender's epoch:`, error.message);
            return null;
        }
    },

    /**
     * Get the session key for a conversation
     * Used by AttachmentService for file encryption
     * @param {number|string} conversationId - Conversation ID
     * @returns {Promise<Uint8Array|null>} Session key or null if not available
     */
    async getSessionKey(conversationId) {
        if (!this.initialized) {
            console.error('[KeyManagementService] getSessionKey: Service not initialized');
            return null;
        }

        // Always use epoch 0
        const epoch = 0;
        const session = await KeyStorageService.getSessionKey(conversationId, epoch);

        if (session && session.sessionKey) {
            return session.sessionKey;
        }

        console.warn(`[KeyManagementService] getSessionKey: No session found for conversation ${conversationId}`);
        return null;
    },

    /**
     * Get safety number for a conversation
     * @param {string} otherUserId - Other user's ID
     * @returns {Promise<string>} Formatted safety number
     */
    async getSafetyNumber(otherUserId) {
        const ourKeys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!ourKeys) {
            throw new Error('No local identity keys');
        }

        // Route through the TOFU chokepoint so the safety number reflects the PINNED
        // key (what we actually encrypt to), not an un-pinned fresh server fetch.
        const theirPublicKeyB64 = await this._getPinnedPeerKey(otherUserId);
        if (!theirPublicKeyB64) {
            throw new Error('Other user has no public key');
        }

        const theirPublicKey = CryptoPrimitivesService.deserializeKey(theirPublicKeyB64);

        return CryptoPrimitivesService.generateSafetyNumber(ourKeys.publicKey, theirPublicKey);
    },

    /**
     * Get our public key fingerprint
     * @returns {Promise<string>} Hex fingerprint
     */
    async getOurFingerprint() {
        const keys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!keys) {
            return null;
        }
        return CryptoPrimitivesService.getKeyFingerprint(keys.publicKey);
    },

    /**
     * Upload public key to server (auto-repair for missing keys)
     * @private
     * @param {string} userId - User ID
     * @param {string} publicKeyB64 - Base64 encoded public key
     */
    async _uploadPublicKeyToServer(userId, publicKeyB64) {
        if (!this._database) {
            console.error('[KeyManagementService] AUTO-REPAIR FAILED: No database service');
            return;
        }

        const identityTable = this._config?.tables?.identityKeys || 'identity_keys';

        try {
            const result = await this._database.queryUpsert(identityTable, {
                user_id: userId,
                public_key: publicKeyB64,
                current_epoch: this.currentEpoch || 0,
                updated_at: new Date().toISOString()
            }, {
                onConflict: 'user_id',
                returning: true
            });

            if (result.error) {
                console.error('[KeyManagementService] AUTO-REPAIR FAILED:', result.error);
                return;
            }

            // Also store in public_key_history for ECDH
            await HistoricalKeysService.storeKey(userId, publicKeyB64, this.currentEpoch || 0);

            console.log('[KeyManagementService] AUTO-REPAIR SUCCESS: Public key uploaded to server');
        } catch (error) {
            console.error('[KeyManagementService] AUTO-REPAIR FAILED:', error);
        }
    },

    /**
     * Fetch current epoch from database
     * @private
     * @param {string} userId - User ID
     */
    async _fetchCurrentEpoch(userId) {
        if (!this._database) {
            this.currentEpoch = 0;
            return;
        }

        const identityTable = this._config?.tables?.identityKeys || 'identity_keys';

        try {
            const result = await this._database.querySelect(identityTable, {
                filter: { user_id: userId },
                limit: 1
            });

            this.currentEpoch = result.data?.[0]?.current_epoch || 0;
            console.log(`[KeyManagementService] Current epoch: ${this.currentEpoch}`);
        } catch (error) {
            console.error('[KeyManagementService] Failed to fetch epoch:', error);
            this.currentEpoch = 0;
        }
    },

    /**
     * Get the session backup key for session encryption
     * @private
     * @returns {Uint8Array|null}
     */
    _getSessionBackupKey() {
        return this._sessionBackupKey;
    },

    /**
     * Export the material a NEW device needs to read ALL existing data: the identity
     * secret (so ECDH sessions re-derive) AND the session backup key (so stored
     * session keys restore). Used ONLY by the device-pairing flow, which wraps this
     * bundle under a high-entropy, single-use, expiring code (PBKDF2 + AES-GCM)
     * before it ever touches the server. The raw secret never leaves unprotected.
     * @returns {Promise<{v:number, identitySecretB64:string, sessionBackupKeyB64:(string|null)}>}
     */
    async exportPairingBundle() {
        if (!this.currentUserId) throw new Error('[KeyManagementService] Not initialized');
        const keys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!keys || !keys.secretKey) throw new Error('No local identity keys to share');
        return {
            v: 1,
            identitySecretB64: CryptoPrimitivesService.serializeKey(keys.secretKey),
            sessionBackupKeyB64: this._sessionBackupKey
                ? CryptoPrimitivesService.serializeKey(this._sessionBackupKey)
                : null
        };
    },

    /**
     * Install a pairing bundle on a NEW device: derive the public key from the
     * transferred secret, store the identity locally (wrapped at rest, SM-02), adopt
     * the session backup key, then sync sessions + partner keys so existing history
     * is readable. Mirrors restoreFromPassword's post-restore sync.
     * @param {Object} bundle - from exportPairingBundle on the other device
     * @returns {Promise<{success:boolean}>}
     */
    async importPairingBundle(bundle) {
        if (!this.currentUserId) throw new Error('[KeyManagementService] Not initialized');
        if (!bundle || !bundle.identitySecretB64) throw new Error('Invalid pairing bundle');

        const secretKey = CryptoPrimitivesService.deserializeKey(bundle.identitySecretB64);
        const keyPair = CryptoPrimitivesService.keyPairFromSecretKey(secretKey);
        const publicKey = keyPair.publicKey;

        // Self-heal: if the server's published key differs, re-publish the derived one.
        const derivedPublicKeyB64 = CryptoPrimitivesService.serializeKey(publicKey);
        const dbPublicKeyB64 = await HistoricalKeysService.getCurrentKey(this.currentUserId);
        if (dbPublicKeyB64 && dbPublicKeyB64 !== derivedPublicKeyB64) {
            await this._uploadPublicKeyToServer(this.currentUserId, derivedPublicKeyB64);
        }

        await KeyStorageService.storeIdentityKeys(this.currentUserId, { publicKey, secretKey });

        this._sessionBackupKey = bundle.sessionBackupKeyB64
            ? CryptoPrimitivesService.deserializeKey(bundle.sessionBackupKeyB64)
            : null;

        await this._fetchCurrentEpoch(this.currentUserId);
        if (this._sessionBackupKey) {
            await this._syncSessionKeys(this.currentUserId);
        }
        await HistoricalKeysService.syncToLocal(this.currentUserId);
        await this._syncConversationPartnerKeys(this.currentUserId);

        this.initialized = true;
        console.log('[KeyManagementService] Pairing bundle imported');
        return { success: true };
    },

    /**
     * Sync session keys from database to local
     * Requires session backup key to be available
     * @private
     * @param {string} userId - User ID
     */
    async _syncSessionKeys(userId) {
        if (!this._sessionBackupKey) {
            return;
        }

        let sessions = [];
        try {
            sessions = await KeyBackupService.restoreSessionKeys(userId, this._sessionBackupKey);
        } catch (error) {
            console.error('[KeyManagementService] Failed to restore sessions:', error.message);
            throw new Error(`Failed to restore session keys: ${error.message}`);
        }

        for (const session of sessions) {
            await KeyStorageService.storeSessionKey(
                session.conversationId, session.epoch, session.sessionKey, session.counter
            );
        }

        console.log(`[KeyManagementService] Synced ${sessions.length} session keys`);
    },

    /**
     * Sync historical keys for all conversation partners
     * This is critical for decrypting messages on new devices
     * @private
     * @param {string} userId - User ID
     */
    async _syncConversationPartnerKeys(userId) {
        if (!this._database) {
            console.warn('[KeyManagementService] No database - cannot sync partner keys');
            return;
        }

        console.log('[KeyManagementService] Syncing conversation partner keys...');

        try {
            // Get all conversations where this user is a participant
            const conversationsTable = this._config?.tables?.conversations || 'conversations';

            // Query for conversations where user is user1
            const result1 = await this._database.querySelect(conversationsTable, {
                filter: { user1_id: userId }
            });

            // Query for conversations where user is user2
            const result2 = await this._database.querySelect(conversationsTable, {
                filter: { user2_id: userId }
            });

            // Collect unique partner IDs
            const partnerIds = new Set();

            for (const conv of result1.data || []) {
                if (conv.user2_id && conv.user2_id !== userId) {
                    partnerIds.add(conv.user2_id);
                }
            }

            for (const conv of result2.data || []) {
                if (conv.user1_id && conv.user1_id !== userId) {
                    partnerIds.add(conv.user1_id);
                }
            }

            console.log(`[KeyManagementService] Found ${partnerIds.size} conversation partners`);

            // Sync historical keys for each partner
            for (const partnerId of partnerIds) {
                try {
                    await HistoricalKeysService.syncToLocal(partnerId);
                } catch (error) {
                    console.warn('[KeyManagementService] Failed to sync keys for a partner:', error.message);
                }
            }

            console.log('[KeyManagementService] Partner key sync complete');
        } catch (error) {
            console.error('[KeyManagementService] Failed to sync partner keys:', error);
        }
    },

    /**
     * Derive session key from historical public key
     * @private
     * @param {number|string} conversationId - Conversation ID
     * @param {string} otherUserId - Other user's ID
     * @returns {Promise<Object|null>} { sessionKey, epoch, counter } or null
     */
    async _deriveSessionFromHistory(conversationId, otherUserId) {
        console.log(`[KeyManagementService] Deriving session for conv=${conversationId}`);

        // SM-01: resolve the peer key through the TOFU pin chokepoint.
        const theirPublicKeyB64 = await this._getPinnedPeerKey(otherUserId);
        if (!theirPublicKeyB64) {
            console.error('[KeyManagementService] No public key for peer');
            return null;
        }

        const ourKeys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!ourKeys) {
            console.error('[KeyManagementService] No local identity keys available');
            return null;
        }

        // ECDH key agreement
        const theirPublicKey = CryptoPrimitivesService.deserializeKey(theirPublicKeyB64);
        const sharedSecret = CryptoPrimitivesService.deriveSharedSecret(ourKeys.secretKey, theirPublicKey);
        const sessionKey = await KeyDerivationService.deriveSessionKey(sharedSecret, 0);

        // Cache for future use
        await KeyStorageService.storeSessionKey(conversationId, 0, sessionKey, 0);
        console.log(`[KeyManagementService] Session derived and cached for conv=${conversationId}`);

        return { sessionKey, epoch: 0, counter: 0 };
    },

    /**
     * Clear all local encryption data
     */
    async clearLocalData() {
        console.log('[KeyManagementService] Clearing local data...');
        await KeyStorageService.clearAll();
        this.initialized = false;
        this.currentUserId = null;
        this.currentEpoch = 0;
        this._sessionBackupKey = null;
    }
};

if (typeof window !== 'undefined') {
    window.KeyManagementService = KeyManagementService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = KeyManagementService;
}
