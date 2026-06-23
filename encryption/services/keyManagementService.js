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
        // RETIRED (FORWARD_SECRECY_DESIGN §4.2): identity-key rotation is replaced
        // by the Double Ratchet, which provides forward secrecy + post-compromise
        // security per message without rotating the long-term identity. Rotating the
        // identity now would orphan every live ratchet (their X3DH roots were derived
        // from the OLD identity) and break decryption. To re-key, the user re-pairs /
        // re-publishes prekeys (a clean break), which re-bootstraps sessions via X3DH.
        throw new Error('[KeyManagementService] regenerateKeys is retired — the Double Ratchet supersedes identity-key rotation (see FORWARD_SECRECY_DESIGN §4.2)');
    },

    /**
     * @deprecated retired with regenerateKeys; kept only so the old lock helper is
     * not dead-referenced. (No call path reaches it.)
     */
    async _regenerateKeysLegacy() {
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

                const result = await this._database.queryUpdate(identityTable, null, {
                    public_key: newPublicKeyB64,
                    current_epoch: newEpoch,
                    updated_at: new Date().toISOString()
                }, {
                    user_id: this.currentUserId
                });

                if (result && result.error) {
                    throw new Error(`queryUpdate failed: ${result.error.message}`);
                }
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

    // ====================================================================
    // X3DH PREKEY LIFECYCLE (S5, FORWARD_SECRECY_DESIGN §2)
    // ====================================================================

    /**
     * How many one-time prekeys to keep in the published pool. When the
     * unconsumed count drops below OPK_LOW_WATER, we top back up to OPK_POOL_SIZE.
     */
    OPK_POOL_SIZE: 20,
    OPK_LOW_WATER: 5,

    /**
     * Signed-prekey (SPK) rotation policy (P2-1, FORWARD_SECRECY_DESIGN §2.3).
     *
     *  SPK_ROTATION_MS — mint+publish a FRESH SPK once the current one is older than
     *    this (default 7 days). Periodic rotation limits the window in which a single
     *    compromised SPK secret can be used to bootstrap responder sessions.
     *
     *  SPK_GRACE_MS — keep a PREVIOUS (rotated-out) SPK secret locally for this long
     *    AFTER it stops being the advertised one (default 2 days) so an in-flight
     *    INITIATOR that already fetched the OLD SPK (the server advertises only the
     *    latest) can still bootstrap: the responder looks up its SPK secret by the
     *    spk_id named in the preamble, and multiple stored SPKs are supported.
     *
     *  No createdAt-relative subtlety leaks into the API: an SPK created at T was the
     *  active/advertised one until ~T+SPK_ROTATION_MS (when the next rotation fires),
     *  so its grace expires at ~T+SPK_ROTATION_MS+SPK_GRACE_MS. _pruneExpiredSignedPrekeys
     *  therefore prunes a NON-current SPK once its CREATION age exceeds
     *  (SPK_ROTATION_MS + SPK_GRACE_MS) — i.e. grace measured from when it was retired,
     *  not from when it was minted (otherwise a just-rotated SPK, already older than the
     *  rotation interval, would be pruned instantly and the grace would be a no-op).
     *
     *  Server holds only the latest SPK row (no schema change); old secrets stay local.
     */
    SPK_ROTATION_MS: 7 * 24 * 60 * 60 * 1000,
    SPK_GRACE_MS: 2 * 24 * 60 * 60 * 1000,

    /**
     * HKDF info that derives the Ed25519 IK_sig SEED from the X25519 identity
     * secret. A SEPARATE keypair (Ed25519, for signing) is required — the X25519
     * box key cannot sign — but deriving its seed deterministically from the
     * already-persisted+wrapped identity secret means: (a) it is never reused as
     * the box key, (b) it is effectively "persisted wrapped" (regenerable from the
     * wrapped X25519 secret), and (c) it travels with the existing pairing bundle
     * automatically (the X25519 secret already does), so no bundle-version bump is
     * needed here (the explicit v:2 carry is the S7 concern). Resolved ambiguity:
     * the design said "separate nacl.sign keypair, persisted wrapped" — derivation
     * from the wrapped secret satisfies both the separateness and the persistence.
     * @private
     */
    _IK_SIGN_INFO: 'MoneyTracker:IK_sign:v1',

    /**
     * Derive the user's Ed25519 identity-signing keypair (IK_sig) from their
     * X25519 identity secret. Deterministic + separate from the box key.
     * @private
     * @returns {Promise<{publicKey:Uint8Array(32), secretKey:Uint8Array(64)}>}
     */
    async _getIdentitySignKeyPair() {
        const ourKeys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!ourKeys || !ourKeys.secretKey) {
            throw new Error('[KeyManagementService] No local identity keys - cannot derive IK_sig');
        }
        // 32-byte Ed25519 seed = HKDF(identity secret, IK_sign info).
        const seed = await KeyDerivationService._hkdf(
            ourKeys.secretKey, this._IK_SIGN_INFO, 32,
            // explicit non-empty salt = our own X25519 public, so the seed binds to
            // this identity; bypasses the context-salt fallback deterministically.
            ourKeys.publicKey
        );
        return CryptoPrimitivesService.signKeyPairFromSeed(seed);
    },

    /**
     * Publish (or rotate) the caller's X3DH prekey bundle and replenish the
     * one-time-prekey pool. Idempotent + safe to call on every register/login.
     *
     *  - prekeys row: Ed25519 IK_sig pub + a fresh X25519 signed prekey (SPK) +
     *    Ed25519 signature over the SPK pub + spk_id (upsert, one row per user).
     *  - one_time_prekeys: top the unconsumed pool back up to OPK_POOL_SIZE.
     *
     * The SPK + OPK SECRETS are persisted locally (wrapped at rest) keyed by their
     * id, so the responder side can recompute the X3DH DHs when an inbound
     * bootstrap names them. Only PUBLIC material is published to the server.
     *
     * @returns {Promise<{success:boolean, spkId:number, opkPublished:number}>}
     */
    async publishPrekeys() {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }
        if (!this._database) {
            console.warn('[KeyManagementService] publishPrekeys: no database service - skipping');
            return { success: false, error: 'no database' };
        }

        const prekeysTable = this._config?.tables?.prekeys || 'prekeys';
        const opkTable = this._config?.tables?.oneTimePrekeys || 'one_time_prekeys';

        const signKeys = await this._getIdentitySignKeyPair();
        const identitySignPubB64 = CryptoPrimitivesService.serializeKey(signKeys.publicKey);

        // --- Signed prekey (SPK): fresh X25519 keypair, signed by IK_sig. ---
        // PERIODIC rotation with a grace window (P2-1). Mint a NEW SPK when:
        //   (1) none exists yet, OR
        //   (2) the local secret for the current id is gone, OR
        //   (3) the current SPK is OLDER than SPK_ROTATION_MS (age-based rotation).
        // Otherwise reuse it (don't rotate on every login). Multiple SPK secrets are
        // kept locally during grace so an in-flight initiator that fetched the OLD
        // SPK can still bootstrap; secrets past SPK_GRACE_MS are pruned afterwards.
        const now = Date.now();
        const spkMeta = await KeyStorageService.getSignedPrekeyMeta(this.currentUserId); // newest-first
        const current = spkMeta.length ? spkMeta[0] : null;

        let spkId = current ? current.keyId : null;
        let needNewSpk = (spkId === null || spkId === undefined);
        if (!needNewSpk) {
            // Verify the local SPK secret is still present (else mint a new one).
            const localSpk = await KeyStorageService.getSignedPrekey(this.currentUserId, spkId);
            if (!localSpk) {
                needNewSpk = true;
            } else if (current.createdAt) {
                // Age-based rotation: rotate once the current SPK exceeds the interval.
                const ageMs = now - Date.parse(current.createdAt);
                if (Number.isFinite(ageMs) && ageMs >= this.SPK_ROTATION_MS) {
                    needNewSpk = true;
                    console.log(`[KeyManagementService] SPK age ${Math.round(ageMs / 86400000)}d >= rotation interval — rotating`);
                }
            }
        }

        if (needNewSpk) {
            spkId = now & 0x7fffffff; // monotonic-ish 31-bit rotation id
            const spk = CryptoPrimitivesService.generateKeyPair();
            const spkSig = CryptoPrimitivesService.signDetached(spk.publicKey, signKeys.secretKey);

            // Persist the SPK SECRET locally (wrapped) keyed by spkId. The PREVIOUS
            // SPK secret(s) are intentionally NOT deleted here — they remain valid for
            // in-flight initiators until the grace prune below removes the truly-old ones.
            await KeyStorageService.putSignedPrekey(this.currentUserId, spkId, spk);

            const spkPubB64 = CryptoPrimitivesService.serializeKey(spk.publicKey);
            const spkSigB64 = CryptoPrimitivesService.serializeKey(spkSig);

            // Server advertises ONLY the latest SPK (one row per user; no schema change).
            const result = await this._database.queryUpsert(prekeysTable, {
                user_id: this.currentUserId,
                identity_sign_pub: identitySignPubB64,
                signed_prekey_pub: spkPubB64,
                signed_prekey_sig: spkSigB64,
                spk_id: spkId
            }, { onConflict: 'user_id', returning: true });

            if (result.error) {
                throw new Error(`[KeyManagementService] Failed to publish prekey bundle: ${result.error.message || result.error}`);
            }
            console.log(`[KeyManagementService] Published signed prekey spk_id=${spkId}`);
        }

        // --- Grace-window prune: drop SPK secrets older than SPK_GRACE_MS, but NEVER
        // the current (just-published / still-advertised) one. Keeps the retained-secret
        // window bounded while letting an in-flight initiator on the OLD SPK still mate.
        await this._pruneExpiredSignedPrekeys(spkId, now);

        // --- One-time prekeys (OPK) pool replenishment. ---
        const opkPublished = await this._replenishOneTimePrekeys();

        return { success: true, spkId, opkPublished };
    },

    /**
     * Prune locally-stored signed-prekey SECRETS older than SPK_GRACE_MS, EXCEPT the
     * currently-advertised one (P2-1). The grace window keeps a just-rotated old SPK
     * usable by an in-flight initiator that already fetched it; once a secret is older
     * than the window it can no longer correspond to a reasonably in-flight bootstrap,
     * so deleting it bounds the retained-secret exposure. Best-effort + idempotent:
     * pruning failures never block publishPrekeys. Returns the count pruned.
     * @private
     * @param {number} currentSpkId - the id to ALWAYS keep (current/advertised SPK)
     * @param {number} [nowMs] - clock (injectable for tests)
     * @returns {Promise<number>}
     */
    async _pruneExpiredSignedPrekeys(currentSpkId, nowMs) {
        const now = (typeof nowMs === 'number') ? nowMs : Date.now();
        // Grace measured from RETIREMENT, not minting: a non-current SPK is kept until
        // its creation age exceeds (rotation interval + grace), since it remained the
        // advertised one for ~rotation interval before being rotated out.
        const pruneAfterMs = this.SPK_ROTATION_MS + this.SPK_GRACE_MS;
        let pruned = 0;
        try {
            const meta = await KeyStorageService.getSignedPrekeyMeta(this.currentUserId);
            for (const m of meta) {
                if (m.keyId === (currentSpkId | 0)) continue; // never prune the current SPK
                if (!m.createdAt) continue;                   // no timestamp -> keep (be safe)
                const ageMs = now - Date.parse(m.createdAt);
                if (Number.isFinite(ageMs) && ageMs >= pruneAfterMs) {
                    await KeyStorageService.deleteSignedPrekey(this.currentUserId, m.keyId);
                    pruned += 1;
                    console.log(`[KeyManagementService] Pruned expired SPK secret spk_id=${m.keyId} (age ${Math.round(ageMs / 86400000)}d > rotation+grace)`);
                }
            }
        } catch (e) {
            console.warn('[KeyManagementService] SPK grace prune failed (non-fatal):', e.message);
        }
        return pruned;
    },

    /**
     * Top up the published one-time-prekey pool to OPK_POOL_SIZE. Counts the
     * UNCONSUMED rows on the server; if below the low-water mark, mints new OPKs,
     * persists their SECRETS locally (wrapped) and publishes only the publics.
     * @private
     * @returns {Promise<number>} number of OPKs newly published this call
     */
    async _replenishOneTimePrekeys() {
        const opkTable = this._config?.tables?.oneTimePrekeys || 'one_time_prekeys';

        let unconsumed = 0;
        try {
            const res = await this._database.querySelect(opkTable, {
                select: 'key_id',
                filter: { user_id: this.currentUserId, consumed: false }
            });
            unconsumed = Array.isArray(res.data) ? res.data.length : 0;
        } catch (e) {
            console.warn('[KeyManagementService] Could not count OPK pool:', e.message);
        }

        if (unconsumed >= this.OPK_LOW_WATER) {
            return 0;
        }

        const toCreate = this.OPK_POOL_SIZE - unconsumed;
        const rows = [];
        // Base the new key ids off the current max to avoid UNIQUE(user_id,key_id)
        // collisions across replenishment rounds.
        let nextId = await KeyStorageService.getMaxOneTimePrekeyId(this.currentUserId);
        for (let i = 0; i < toCreate; i++) {
            nextId += 1;
            const opk = CryptoPrimitivesService.generateKeyPair();
            await KeyStorageService.putOneTimePrekey(this.currentUserId, nextId, opk);
            rows.push({
                user_id: this.currentUserId,
                key_id: nextId,
                prekey_pub: CryptoPrimitivesService.serializeKey(opk.publicKey)
            });
        }

        if (rows.length > 0) {
            const result = await this._database.queryInsert(opkTable, rows);
            if (result.error) {
                throw new Error(`[KeyManagementService] Failed to publish one-time prekeys: ${result.error.message || result.error}`);
            }
            console.log(`[KeyManagementService] Published ${rows.length} one-time prekeys (pool now ~${unconsumed + rows.length})`);
        }
        return rows.length;
    },

    /**
     * Claim a peer's prekey bundle to bootstrap a NEW session as the initiator.
     * Atomically pops one OPK server-side (claim_one_time_prekey RPC) and fetches
     * the peer's X25519 identity key through the TOFU pin chokepoint.
     * @private
     * @param {string} peerId
     * @returns {Promise<Object>} peerBundle shaped for x3dhService.deriveInitiatorRoot
     */
    async _claimPeerBundle(peerId) {
        // Peer X25519 identity key via the TOFU pin (SM-01).
        const theirIkB64 = await this._getPinnedPeerKey(peerId);
        if (!theirIkB64) {
            throw new Error('Other user has no public key - they may not have set up encryption yet');
        }

        const rpc = await this._database.queryRpc('claim_one_time_prekey', { target_user_id: peerId });
        if (rpc.error) {
            throw new Error(`[KeyManagementService] claim_one_time_prekey failed: ${rpc.error.message || rpc.error}`);
        }
        const bundle = Array.isArray(rpc.data) ? rpc.data[0] : rpc.data;
        if (!bundle || bundle.success === false) {
            throw new Error(`[KeyManagementService] No prekey bundle for peer: ${bundle && bundle.error}`);
        }

        const hasOpk = bundle.opk_id !== null && bundle.opk_id !== undefined && bundle.opk_pub;
        return {
            identityKeyPub:   CryptoPrimitivesService.deserializeKey(theirIkB64),
            identitySignPub:  CryptoPrimitivesService.deserializeKey(bundle.identity_sign_pub),
            signedPrekeyPub:  CryptoPrimitivesService.deserializeKey(bundle.signed_prekey_pub),
            signedPrekeySig:  CryptoPrimitivesService.deserializeKey(bundle.signed_prekey_sig),
            spkId:            bundle.spk_id,
            oneTimePrekeyPub: hasOpk ? CryptoPrimitivesService.deserializeKey(bundle.opk_pub) : undefined,
            oneTimePrekeyId:  hasOpk ? bundle.opk_id : undefined,
            // also keep the peer's Ed25519 signing pub for TOFU pinning
            _identitySignPubB64: bundle.identity_sign_pub
        };
    },

    /**
     * Establish a Double Ratchet session for a conversation (FORWARD_SECRECY_DESIGN
     * §2/§3). Replaces the old static-static ECDH session.
     *
     *  - Cached: if a ratchet_states record exists, return immediately.
     *  - INITIATOR (we send first, no inbound bootstrap): claim the peer's bundle,
     *    verify the SPK signature (fail closed, inside x3dhService), derive the
     *    X3DH root, ratchetInitAlice, persist state, and STASH the X3DH preamble so
     *    encryptMessage attaches it to the FIRST outbound message.
     *  - RESPONDER (an inbound first message carried an X3DH preamble): derive the
     *    responder root from our local SPK/OPK secrets + the preamble, ratchetInitBob,
     *    persist state.
     *
     * @param {number|string} conversationId
     * @param {string} otherUserId
     * @param {Object} [inboundPreamble] - X3DH preamble from a first inbound message
     *        { ikPub, ikSignPub, ekPub, spkId, opkId } (base64 strings). Present =>
     *        responder bootstrap. Absent => initiator bootstrap.
     * @returns {Promise<Object>} { ratchetReady:true, role, x3dhPreamble? }
     */
    async establishSession(conversationId, otherUserId, inboundPreamble = null) {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }

        // Cached ratchet -> done. (No epoch; the ratchet IS the session.)
        const existing = await KeyStorageService.getRatchetState(conversationId);
        if (existing) {
            return { ratchetReady: true, role: 'cached' };
        }

        const ourKeys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!ourKeys) {
            throw new Error('No local identity keys - run device pairing first');
        }

        if (inboundPreamble) {
            // ---------- RESPONDER (Bob) ----------
            console.log(`[KeyManagementService] establishSession: RESPONDER bootstrap conv=${conversationId}`);

            // H-1 (fail-closed): resolve + AUTHENTICATE the initiator's X25519 IK
            // BEFORE any DH. Returns the TRUSTED X25519 ikPub (pinned/published, NOT
            // the raw wire value) and atomically co-pins (X25519 IK, Ed25519 IK_sig)
            // on genuine first contact. THROWS PeerIdentityChangedError on a swapped
            // ikPub (or a pinned-IK_sig-with-unpinned/mismatched-ikPub bootstrap), so
            // NO SK is derived and NO ratchet is persisted against a forged identity.
            const trustedIkPubB64 = await this._resolveResponderPeerIdentity(
                otherUserId, inboundPreamble.ikPub, inboundPreamble.ikSignPub
            );

            // Our SPK keypair (Bob's first ratchet keypair IS his SPK keypair).
            const spkId = inboundPreamble.spkId;
            const spk = await KeyStorageService.getSignedPrekey(this.currentUserId, spkId);
            if (!spk) {
                throw new Error(`[KeyManagementService] No local signed prekey for spk_id=${spkId} - cannot bootstrap responder session`);
            }

            // OPK only if the initiator named one.
            let opk = null;
            if (inboundPreamble.opkId !== null && inboundPreamble.opkId !== undefined) {
                opk = await KeyStorageService.getOneTimePrekey(this.currentUserId, inboundPreamble.opkId);
                if (!opk) {
                    throw new Error(`[KeyManagementService] No local one-time prekey for opk_id=${inboundPreamble.opkId}`);
                }
            }

            const respRoot = await X3DHService.deriveResponderRoot({
                identityKeyPair: ourKeys,
                signedPrekeyPair: spk,
                oneTimePrekeyPair: opk || undefined,
                preamble: {
                    // Use the TRUSTED (pinned/published) X25519 IK, NEVER the raw wire
                    // value, so both the DH and the AD (IK_a||IK_b) bind the AUTHENTIC
                    // initiator identity. trustedIkPubB64 == inboundPreamble.ikPub here
                    // (it was byte-equal-checked above) — this is belt-and-suspenders.
                    ikPub: trustedIkPubB64,
                    ekPub: inboundPreamble.ekPub,
                    opkId: (inboundPreamble.opkId !== undefined ? inboundPreamble.opkId : null)
                }
            });

            const state = await DoubleRatchetService.ratchetInitBob(respRoot.SK, spk);
            await KeyStorageService.putRatchetState(conversationId, state);

            // Stash the X3DH AD (IK_a||IK_b) so the FIRST inbound message decrypt can
            // bind the same AD the initiator used. Consumed by decryptMessage once.
            this._pendingResponderAD = this._pendingResponderAD || {};
            this._pendingResponderAD[String(conversationId)] = respRoot.associatedData;

            // Consume the OPK locally (one-time use): delete its secret + best-effort
            // delete the published public row (own-row DELETE is allowed by RLS).
            if (opk && inboundPreamble.opkId !== null && inboundPreamble.opkId !== undefined) {
                await KeyStorageService.deleteOneTimePrekey(this.currentUserId, inboundPreamble.opkId);
                this._deletePublishedOpk(inboundPreamble.opkId).catch(() => {});
                // Top the pool back up if it ran low.
                this._replenishOneTimePrekeys().catch((e) =>
                    console.warn('[KeyManagementService] OPK replenish after consume failed:', e.message));
            }

            return { ratchetReady: true, role: 'responder' };
        }

        // ---------- INITIATOR (Alice) ----------
        console.log(`[KeyManagementService] establishSession: INITIATOR bootstrap conv=${conversationId}`);

        // _claimPeerBundle resolves the peer's X25519 IK through _getPinnedPeerKey,
        // which THROWS PeerIdentityChangedError fail-closed if the pinned X25519 IK
        // changed (P0-2) — so a swapped identity key aborts here before any SK.
        const peerBundle = await this._claimPeerBundle(otherUserId);

        // P0-1 (fail-closed) + ORDERING: resolve the TRUSTED Ed25519 IK_sig BEFORE
        // verifying the SPK signature, and reject a CHANGED pinned IK_sig up front
        // with the typed PeerIdentityChangedError. _pinPeerSignKey:
        //   - first contact -> pins the bundle's IK_sig (TOFU); we then verify the
        //     SPK against that freshly-pinned key.
        //   - unchanged -> no-op.
        //   - CHANGED -> THROWS PeerIdentityChangedError (no SK, no re-pin).
        // This never trusts/re-pins a changed key before verification — a change
        // throws; only first-contact pins, and the SPK is then verified against the
        // PINNED IK_sig (so a swapped-then-re-signed bundle is rejected as a changed
        // identity, not silently adopted).
        await this._pinPeerSignKey(otherUserId, peerBundle._identitySignPubB64);

        const signPinId = this._signPinId(otherUserId);
        const pinnedSign = await KeyStorageService.getPinnedKey(signPinId);
        const trustedSignPubB64 = pinnedSign ? pinnedSign.publicKey : peerBundle._identitySignPubB64;

        // deriveInitiatorRoot verifies the SPK signature FIRST (fail closed), bound
        // to the PINNED IK_sig (never the raw bundle value once a pin exists).
        const init = await X3DHService.deriveInitiatorRoot({
            identityKeyPair: ourKeys,
            peerBundle,
            trustedIdentitySignPub: CryptoPrimitivesService.deserializeKey(trustedSignPubB64)
        });

        const state = await DoubleRatchetService.ratchetInitAlice(init.SK, peerBundle.signedPrekeyPub);
        await KeyStorageService.putRatchetState(conversationId, state);

        // Build the on-the-wire X3DH preamble for the FIRST message. x3dhService
        // returns ikSignPub:null (initiator doesn't sign in X3DH); fill our OWN
        // Ed25519 signing pub so the responder can TOFU-pin it (§2.4).
        const signKeys = await this._getIdentitySignKeyPair();
        const x3dhPreamble = {
            ikPub:     init.preamble.ikPub,
            ikSignPub: CryptoPrimitivesService.serializeKey(signKeys.publicKey),
            ekPub:     init.preamble.ekPub,
            spkId:     init.preamble.spkId,
            opkId:     init.preamble.opkId
        };

        // Stash the preamble + the X3DH associated data (IK_a||IK_b) so
        // encryptMessage attaches the preamble to message 0 only and binds the
        // SAME AD the responder will recompute.
        this._pendingX3dhPreamble = this._pendingX3dhPreamble || {};
        this._pendingX3dhPreamble[String(conversationId)] = x3dhPreamble;
        this._pendingX3dhAD = this._pendingX3dhAD || {};
        this._pendingX3dhAD[String(conversationId)] = init.associatedData;

        return { ratchetReady: true, role: 'initiator', x3dhPreamble };
    },

    /**
     * Namespaced pinned_keys id for a peer's Ed25519 IK_sig signing key (kept
     * distinct from the X25519 identity pin, which uses the bare userId).
     * @private
     */
    _signPinId(otherUserId) { return 'sign:' + otherUserId; },

    /**
     * Pin (TOFU) a peer's Ed25519 IK_sig signing key — FAIL CLOSED (P0-1, roadmap #4).
     *
     *  - First contact (no existing pin): pin it (TOFU). No change event.
     *  - Unchanged key: no-op.
     *  - CHANGED key: do NOT auto-adopt/re-pin. THROW PeerIdentityChangedError so
     *    establishSession aborts before any SK is derived. Legitimate rotation /
     *    re-pair is adopted only via acceptPeerIdentityChange() after the user
     *    verifies the safety number.
     *
     * (A genuinely paired device presents the SAME IK_sig — it is HKDF-derived from
     * the shared X25519 identity — so pairing does NOT trip this. SPK rotation does
     * not change IK_sig either.)
     *
     * @private
     * @throws {PeerIdentityChangedError} when the pinned IK_sig has changed
     */
    async _pinPeerSignKey(otherUserId, signPubB64) {
        if (!signPubB64) return;
        const pinId = this._signPinId(otherUserId);
        const fp = CryptoPrimitivesService.getKeyFingerprint(
            CryptoPrimitivesService.deserializeKey(signPubB64)
        );
        const pinned = await KeyStorageService.getPinnedKey(pinId);
        if (!pinned) {
            // First contact - trust on first use.
            await KeyStorageService.pinKey(pinId, signPubB64, fp);
            return;
        }
        if (pinned.publicKey === signPubB64) {
            // Unchanged - normal case.
            return;
        }
        // CHANGED: fail closed. Warn once (for any UI listener), then THROW so no
        // session is derived against the new signing key.
        if (pinned.lastWarnedFingerprint !== fp) {
            if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
                window.dispatchEvent(new CustomEvent('peerSignKeyChanged', {
                    detail: { userId: otherUserId, oldFingerprint: pinned.fingerprint, newFingerprint: fp }
                }));
            }
            await KeyStorageService.updatePinnedWarn(pinId, fp);
        }
        throw this._peerIdentityChangedError({
            userId: otherUserId,
            oldFingerprint: pinned.fingerprint,
            newFingerprint: fp,
            keyType: 'sign'
        });
    },

    /**
     * H-1 (HIGH) — RESPONDER-side X25519 identity authentication + atomic IK↔IK_sig
     * co-pinning. Closes the peer-impersonation hole where the responder branch
     * trusted an UNPINNED, UNSIGNED initiator X25519 IK from the wire while pinning
     * only the Ed25519 IK_sig — letting a hostile server/peer plant a bootstrap with
     * Alice's genuine IK_sig + an attacker X25519 ikPub and derive a working session
     * "from Alice".
     *
     * Policy (FAIL CLOSED — no SK derived / no ratchet persisted on any rejection):
     *
     *  1. Resolve the peer's AUTHENTIC X25519 IK via _getPinnedPeerKey(otherUserId)
     *     (TOFU chokepoint; it already THROWS PeerIdentityChangedError if the peer's
     *     PUBLISHED X25519 key diverged from a prior pin).
     *
     *  2. If a pin/published X25519 IK exists, REQUIRE the wire ikPub to byte-equal
     *     it. A mismatch is the swapped-IK attack -> throw keyType:'identity'.
     *
     *  3. Already-pinned-IK_sig variant: the IK↔IK_sig pins are BOUND. IK_sig is the
     *     deterministic IK_sign for the X25519 secret (HKDF(secret, info, salt=pub))
     *     and CANNOT be recomputed from the public X25519 alone — so the soundest
     *     binding is to require the SAME (ikPub, ikSignPub) PAIR to be pinned
     *     together: if an IK_sig is already pinned for this peer, an X25519 IK pin
     *     MUST also exist and the wire ikPub MUST match it. This rejects a bootstrap
     *     that presents a pinned IK_sig with a non-matching / unpinned ikPub even if
     *     the published X25519 key were unavailable.
     *
     *  4. Genuine first contact (no pin, no published key): TOFU-pin the WIRE ikPub
     *     as the X25519 IK so the safety number reflects what was actually bound.
     *
     *  5. ATOMIC co-pin: the X25519 IK pin and the Ed25519 IK_sig pin are only ever
     *     established TOGETHER. We refuse to set one without the other — _pinPeerSignKey
     *     (which may THROW on a changed IK_sig) is called FIRST so a sign-key change
     *     aborts before any X25519 pin is written; the X25519 pin is written LAST,
     *     only after every check (incl. IK_sig) has passed.
     *
     * @private
     * @param {string} otherUserId - peer (sender) user id
     * @param {string} wireIkPubB64 - the initiator X25519 IK from inboundPreamble.ikPub
     * @param {string} [wireIkSignPubB64] - the initiator Ed25519 IK_sig from inboundPreamble.ikSignPub
     * @returns {Promise<string>} the TRUSTED X25519 ikPub (b64) to bind into DH + AD
     * @throws {PeerIdentityChangedError} on a swapped/forged identity (no SK, no ratchet)
     */
    async _resolveResponderPeerIdentity(otherUserId, wireIkPubB64, wireIkSignPubB64) {
        if (!wireIkPubB64) {
            throw new Error('[KeyManagementService] responder bootstrap missing initiator X25519 ikPub');
        }

        // Existing pins (X25519 IK + Ed25519 IK_sig) for this peer.
        const pinnedIk = await KeyStorageService.getPinnedKey(otherUserId);
        const signPinId = this._signPinId(otherUserId);
        const pinnedSign = await KeyStorageService.getPinnedKey(signPinId);

        const fpOf = (b64) => CryptoPrimitivesService.getKeyFingerprint(
            CryptoPrimitivesService.deserializeKey(b64)
        );

        // (3) BOUND-PAIR check FIRST: a pinned IK_sig with NO pinned X25519 IK means
        // the two pins are not co-set — refuse rather than trust the wire ikPub.
        // (Normal operation always co-pins, so this only fires on tampering.)
        if (pinnedSign && !pinnedIk) {
            throw this._peerIdentityChangedError({
                userId: otherUserId,
                oldFingerprint: pinnedSign.fingerprint,
                newFingerprint: fpOf(wireIkPubB64),
                keyType: 'identity'
            });
        }

        // (2) If the X25519 IK is already pinned, the wire ikPub MUST match it byte
        // for byte. This is the core H-1 check — it blocks the swapped-ikPub attack
        // even when the attacker supplies Alice's genuine IK_sig.
        if (pinnedIk && pinnedIk.publicKey !== wireIkPubB64) {
            throw this._peerIdentityChangedError({
                userId: otherUserId,
                oldFingerprint: pinnedIk.fingerprint,
                newFingerprint: fpOf(wireIkPubB64),
                keyType: 'identity'
            });
        }

        // (1) Cross-check against the PUBLISHED X25519 IK through the TOFU chokepoint.
        // _getPinnedPeerKey THROWS if the published key diverged from a prior pin, and
        // on genuine first contact it pins the published key. It returns null only
        // when the peer has published no X25519 key at all.
        const publishedIk = await this._getPinnedPeerKey(otherUserId);
        if (publishedIk && publishedIk !== wireIkPubB64) {
            // The wire ikPub disagrees with the peer's authentic published key.
            throw this._peerIdentityChangedError({
                userId: otherUserId,
                oldFingerprint: fpOf(publishedIk),
                newFingerprint: fpOf(wireIkPubB64),
                keyType: 'identity'
            });
        }

        // ----- All identity checks passed; ATOMIC co-pin (5) -----
        // IK_sig FIRST: a CHANGED IK_sig throws here (before we write any X25519 pin),
        // and first-contact pins it (TOFU). Refuse to proceed without an IK_sig so the
        // two pins are never set independently.
        if (!wireIkSignPubB64) {
            throw new Error('[KeyManagementService] responder bootstrap missing initiator Ed25519 ikSignPub (cannot atomically bind identity)');
        }
        await this._pinPeerSignKey(otherUserId, wireIkSignPubB64);

        // X25519 IK LAST: if _getPinnedPeerKey already pinned it (published-key path),
        // pinnedIk-or-published covers it; otherwise this is the pure-first-contact
        // path with no published key — TOFU-pin the wire ikPub so the safety number
        // reflects what was actually bound (4).
        if (!pinnedIk && !publishedIk) {
            await KeyStorageService.pinKey(otherUserId, wireIkPubB64, fpOf(wireIkPubB64));
        }

        return wireIkPubB64;
    },

    /**
     * Best-effort delete of a consumed OPK's published public row. The claim RPC
     * already marks it consumed server-side (so it can't be re-claimed); this is
     * housekeeping. Failure is non-fatal.
     * @private
     */
    async _deletePublishedOpk(keyId) {
        const opkTable = this._config?.tables?.oneTimePrekeys || 'one_time_prekeys';
        try {
            await this._database.queryDelete(opkTable, { user_id: this.currentUserId, key_id: keyId });
        } catch (e) { /* non-fatal */ }
    },

    /**
     * Maximum safe counter value to prevent overflow
     * JavaScript's Number.MAX_SAFE_INTEGER is 2^53 - 1
     * We use a lower limit to leave headroom for any arithmetic
     */
    MAX_COUNTER: Number.MAX_SAFE_INTEGER - 1000,

    /**
     * Encrypt a message via the Double Ratchet (FORWARD_SECRECY_DESIGN §3.4).
     *
     * Advances the SENDING chain, persists the advanced ratchet state atomically,
     * and emits the ratchet header (ratchet_pub / prev_chain_len / msg_num). On the
     * FIRST outbound message of an initiator-bootstrapped conversation it also emits
     * the X3DH preamble (consumed once, then cleared) and binds AD = IK_a||IK_b into
     * the AEAD.
     *
     * The per-message key is returned (`_messageKey`) so the caller can ARCHIVE it
     * keyed by the message id once the insert returns that id (§5). It is NOT
     * persisted here because the id is unknown until after the DB insert.
     *
     * @param {number|string} conversationId
     * @param {string} plaintext
     * @returns {Promise<Object>} {
     *   ciphertext, nonce,
     *   header:{ ratchet_pub, prev_chain_len, msg_num },
     *   x3dhPreamble?:{ ikPub, ikSignPub, ekPub, spkId, opkId },
     *   _messageKey: Uint8Array,        // for the sender-side archive
     *   counter, epoch                  // vestigial back-compat (counter = msg_num)
     * }
     */
    async encryptMessage(conversationId, plaintext) {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }

        const state = await KeyStorageService.getRatchetState(conversationId);
        if (!state) {
            throw new Error('No ratchet session - call establishSession first');
        }

        // Attach the X3DH preamble ONLY on the first message of an initiator
        // conversation (msg_num 0 in the very first sending chain).
        const convKey = String(conversationId);
        const pending = this._pendingX3dhPreamble && this._pendingX3dhPreamble[convKey];
        const isFirst = !!pending && state.Ns === 0 && state.PN === 0;

        // On the first message, bind AD = IK_a_pub || IK_b_pub (matches the X3DH AD)
        // so a tampered identity in the preamble fails the AEAD. The AD was computed
        // by x3dhService.deriveInitiatorRoot and stashed in establishSession.
        let adBytes;
        if (isFirst) {
            adBytes = this._pendingX3dhAD && this._pendingX3dhAD[convKey];
        }

        const plaintextBytes = CryptoPrimitivesService.encodeUTF8(plaintext);
        const enc = await DoubleRatchetService.ratchetEncrypt(state, plaintextBytes, adBytes);

        // Persist the advanced state atomically (chain advanced, MK consumed).
        await KeyStorageService.putRatchetState(conversationId, enc.newState);

        const result = {
            ciphertext: enc.ciphertext,
            nonce: enc.nonce,
            header: {
                ratchet_pub: enc.wireHeader.dh,
                prev_chain_len: enc.wireHeader.pn,
                msg_num: enc.wireHeader.n
            },
            _messageKey: enc.messageKey,
            // Vestigial back-compat fields so any caller reading .counter/.epoch
            // still gets a sane value (counter == msg_num within the chain).
            counter: enc.wireHeader.n,
            epoch: 0
        };

        if (isFirst) {
            result.x3dhPreamble = pending;
            // Consume the stashed preamble + AD (only message 0 carries them).
            delete this._pendingX3dhPreamble[convKey];
            if (this._pendingX3dhAD) delete this._pendingX3dhAD[convKey];
        }

        return result;
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
     * Build a typed PeerIdentityChangedError (FAIL-CLOSED on a TOFU pin change).
     * Falls back to a plain Error carrying the same fields + a `code` so callers
     * that match on `err.code === 'PEER_IDENTITY_CHANGED'` still work if the typed
     * class is unavailable.
     * @private
     * @param {{userId:string, oldFingerprint:string, newFingerprint:string, keyType:string}} details
     * @returns {Error}
     */
    _peerIdentityChangedError(details) {
        const Cls = (typeof PeerIdentityChangedError !== 'undefined')
            ? PeerIdentityChangedError
            : (typeof window !== 'undefined' && window.PeerIdentityChangedError) || null;
        if (Cls) return new Cls(details);
        const e = new Error(`Peer identity key changed (${details.keyType})`);
        e.name = 'PeerIdentityChangedError';
        e.code = 'PEER_IDENTITY_CHANGED';
        e.userId = details.userId;
        e.oldFingerprint = details.oldFingerprint;
        e.newFingerprint = details.newFingerprint;
        e.keyType = details.keyType;
        return e;
    },

    /**
     * Sentinel rendered for a pre-cutover (static-ECDH) message that carries no
     * ratchet header. Clean break (FORWARD_SECRECY_DESIGN §7): such rows are
     * UNAVAILABLE, not an error.
     */
    LEGACY_MESSAGE_SENTINEL: '[Message from a previous encryption version — unavailable]',

    /**
     * Decrypt a message via the Double Ratchet (FORWARD_SECRECY_DESIGN §5/§6).
     *
     * TWO PATHS, one entry point:
     *   - HISTORY RE-RENDER (batch getMessages, options.liveAdvance !== true):
     *     ARCHIVE-ONLY. Look up the per-message key by msg id and open directly;
     *     NEVER advance the live ratchet (the ratchet is strictly ordered and its
     *     keys are deleted after use, so replaying it over history is impossible).
     *     A miss returns the unavailable sentinel rather than corrupting the ratchet.
     *   - REALTIME ARRIVAL (options.liveAdvance === true): advance the live ratchet
     *     (ratchetDecrypt, which also consumes/handles skipped keys), persist the
     *     advanced state, then ARCHIVE the consumed key by msg id so all later
     *     history renders read it from the archive.
     *
     * Responder bootstrap: when there is no ratchet yet AND the message header
     * carries an X3DH preamble, establishSession (responder) is run first.
     *
     * Clean break: a message with no ratchet header (pre-cutover) renders the
     * LEGACY_MESSAGE_SENTINEL, never throws.
     *
     * @param {number|string} conversationId
     * @param {Object} encryptedData - {
     *     ciphertext, nonce, id,
     *     header:{ ratchet_pub, prev_chain_len, msg_num },
     *     x3dhPreamble?:{ ikPub, ikSignPub, ekPub, spkId, opkId },
     *     _messageKey?  // sender-side archive shortcut (own outbound message)
     *   }
     * @param {string} senderId
     * @param {string} recipientId
     * @param {Object} [options] - { liveAdvance:boolean } (true = realtime path)
     * @returns {Promise<string>} plaintext (or the legacy sentinel)
     */
    async decryptMessage(conversationId, encryptedData, senderId, recipientId = null, options = {}) {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }

        const { ciphertext, nonce, id: messageId, header, x3dhPreamble } = encryptedData;
        const liveAdvance = options && options.liveAdvance === true;

        // ---------- 1) ARCHIVE-FIRST (order-independent, parallel-safe) ----------
        // Both paths consult the archive first; the batch path NEVER goes past it.
        if (messageId !== undefined && messageId !== null) {
            const archivedKey = await KeyStorageService.getDecryptedMessageKey(messageId);
            if (archivedKey) {
                return await this._openWithMessageKey(ciphertext, nonce, header, x3dhPreamble, archivedKey, conversationId, senderId, recipientId);
            }
        }

        // ---------- 2) Clean break: no ratchet header => legacy row ----------
        if (!header || !header.ratchet_pub) {
            return this.LEGACY_MESSAGE_SENTINEL;
        }

        // ---------- 3) Sender-side own message archive shortcut ----------
        // When WE sent this message, encryptMessage handed us the message key; the
        // caller passes it back as _messageKey so we archive + render without
        // touching the receive ratchet (we never decrypt our own send chain).
        if (encryptedData._messageKey) {
            const mk = encryptedData._messageKey;
            const pt = await this._openWithMessageKey(ciphertext, nonce, header, x3dhPreamble, mk, conversationId, senderId, recipientId);
            if (messageId !== undefined && messageId !== null) {
                await KeyStorageService.putDecryptedMessageKey(messageId, mk, conversationId);
            }
            return pt;
        }

        // ---------- 4) BATCH path on an archive miss: do NOT advance the ratchet ----------
        if (!liveAdvance) {
            // Order-/parallel-unsafe to advance here. Surface as unavailable; the
            // realtime path is responsible for the first (ratchet-ordered) mint.
            return '[Cannot decrypt - sign out and sign back in to restore keys]';
        }

        // ---------- 5) REALTIME path: advance the live ratchet ----------
        const otherUserId = senderId === this.currentUserId ? recipientId : senderId;
        if (!otherUserId) {
            throw new Error('Cannot determine other user - recipientId not provided');
        }

        // Responder bootstrap on the FIRST inbound message carrying an X3DH preamble.
        let state = await KeyStorageService.getRatchetState(conversationId);
        if (!state) {
            if (!x3dhPreamble) {
                // No ratchet and no bootstrap header — cannot establish a session.
                throw this._decryptionError('no session', 'message');
            }
            await this.establishSession(conversationId, otherUserId, x3dhPreamble);
            state = await KeyStorageService.getRatchetState(conversationId);
        }

        // AD for the first inbound (bootstrap) message: bind IK_a||IK_b exactly as
        // the initiator did. For all later messages AD is undefined.
        //
        // P0-4 (reload-safe): RECOMPUTE the AD DETERMINISTICALLY from the persisted
        // X3DH preamble + our own (responder) identity via _reconstructAD — the SAME
        // method the archive-hit path uses — instead of reading the in-memory
        // _pendingResponderAD field. The in-memory field is lost on a reload that
        // happens after the responder ratchet was persisted but before msg0 was
        // archived; reading it then would leave AD undefined and make msg0
        // permanently undecryptable on the batch path. _reconstructAD needs nothing
        // beyond the preamble's ikPub and our local identity, both persisted.
        let adBytes;
        if (x3dhPreamble) {
            adBytes = await this._reconstructAD(x3dhPreamble, senderId, recipientId);
        }

        const wireHeader = {
            dh: header.ratchet_pub,
            pn: header.prev_chain_len | 0,
            n: header.msg_num | 0
        };

        let dec;
        try {
            dec = await DoubleRatchetService.ratchetDecrypt(state, wireHeader, nonce, ciphertext, adBytes);
        } catch (authFailure) {
            throw this._decryptionError('authentication failed', 'message');
        }

        // Persist the advanced ratchet state (chain advanced, skipped keys updated).
        await KeyStorageService.putRatchetState(conversationId, dec.newState);

        // Consume the one-shot responder AD now that the bootstrap message decrypted.
        if (x3dhPreamble && this._pendingResponderAD) {
            delete this._pendingResponderAD[String(conversationId)];
        }

        // ARCHIVE the consumed key by message id (§5) so history re-renders read it
        // from the archive and never advance the live ratchet again.
        if (messageId !== undefined && messageId !== null) {
            await KeyStorageService.putDecryptedMessageKey(messageId, dec.messageKey, conversationId);
        }

        // SM-10: best-effort replay high-water mark (never blocks a decrypt).
        if (senderId !== this.currentUserId) {
            try {
                const last = await KeyStorageService.getLastCounter(conversationId, 0, senderId);
                if (wireHeader.n > last) {
                    await KeyStorageService.setLastCounter(conversationId, 0, senderId, wireHeader.n);
                }
            } catch (e) { /* bookkeeping must not block */ }
        }

        return CryptoPrimitivesService.decodeUTF8(dec.plaintext);
    },

    /**
     * Archive a SENDER-side per-message key once the message id is known (§5).
     * Called by messagingService.sendMessage right after the insert returns the id.
     * Lets OUR OWN getMessages history re-render read the message from the archive
     * (we never run the receive ratchet over our own send chain).
     * @param {number|string} conversationId
     * @param {number|string} messageId
     * @param {Uint8Array} messageKey
     */
    async archiveSentMessageKey(conversationId, messageId, messageKey) {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }
        await KeyStorageService.putDecryptedMessageKey(messageId, messageKey, conversationId);
    },

    /**
     * Open a ciphertext with a known message key, reconstructing the same AEAD
     * header/AD binding DoubleRatchetService used at encrypt time. Used by the
     * archive-hit path (history re-render) and the sender-side own-message path,
     * neither of which touches the live ratchet.
     * @private
     */
    async _openWithMessageKey(ciphertext, nonce, header, x3dhPreamble, messageKey, conversationId, senderId, recipientId) {
        const wireHeader = {
            dh: header.ratchet_pub,
            pn: header.prev_chain_len | 0,
            n: header.msg_num | 0
        };
        const drHeader = { dh: CryptoPrimitivesService.deserializeKey(wireHeader.dh), pn: wireHeader.pn, n: wireHeader.n };

        // Reconstruct AD only for a bootstrap (first) message. The AD is IK_a||IK_b;
        // recompute it from the preamble's ikPub + our/peer identity as appropriate.
        let adBytes;
        if (x3dhPreamble) {
            adBytes = await this._reconstructAD(x3dhPreamble, senderId, recipientId);
        }

        const encKey = await DoubleRatchetService.deriveAeadKey(messageKey, drHeader, adBytes);
        const ct = CryptoPrimitivesService.deserializeKey(ciphertext);
        const nn = CryptoPrimitivesService.deserializeKey(nonce);
        const pt = CryptoPrimitivesService.nacl.secretbox.open(ct, nn, encKey);
        if (!pt) {
            throw this._decryptionError('authentication failed', 'message');
        }
        return CryptoPrimitivesService.decodeUTF8(pt);
    },

    /**
     * Reconstruct AD = IK_a_pub || IK_b_pub for a bootstrap message, where IK_a is
     * the INITIATOR identity (preamble.ikPub) and IK_b is the RESPONDER identity.
     * We resolve which side is which from senderId: the sender of a bootstrap
     * message is always the initiator (IK_a = preamble.ikPub), and the responder
     * (IK_b) is the OTHER party's pinned X25519 identity key.
     * @private
     */
    async _reconstructAD(x3dhPreamble, senderId, recipientId) {
        // H-1 (responder path): AD = IK_a||IK_b must bind the AUTHENTIC initiator
        // identity, NOT the raw wire ikPub. When we are the responder, resolve IK_a
        // (the sender's X25519 IK) through the pin chokepoint and require the wire
        // ikPub to match it (fail-closed) before building AD; only fall back to the
        // wire value on genuine first contact (no pin, no published key), exactly as
        // _resolveResponderPeerIdentity does at bootstrap.
        const weAreResponder = (recipientId === this.currentUserId || senderId !== this.currentUserId);

        let ikAb64 = x3dhPreamble.ikPub; // initiator IK (wire value by default)
        let ikBb64;
        if (weAreResponder) {
            // We are the responder (recipient) — authenticate the sender's IK_a, and
            // IK_b is OUR own identity public.
            ikAb64 = await this._resolveADInitiatorKey(senderId, x3dhPreamble.ikPub);
            const ourKeys = await KeyStorageService.getIdentityKeys(this.currentUserId);
            ikBb64 = CryptoPrimitivesService.serializeKey(ourKeys.publicKey);
        } else {
            // We are the initiator re-rendering our own sent bootstrap — IK_a is our
            // own preamble value (already authentic), IK_b is the peer (recipient)
            // pinned key.
            ikBb64 = await this._getPinnedPeerKey(recipientId);
        }
        const ikA = CryptoPrimitivesService.deserializeKey(ikAb64); // initiator IK
        const ikB = CryptoPrimitivesService.deserializeKey(ikBb64);
        const ad = new Uint8Array(ikA.length + ikB.length);
        ad.set(ikA, 0);
        ad.set(ikB, ikA.length);
        return ad;
    },

    /**
     * H-1 (responder AD path) — resolve the AUTHENTIC initiator (sender) X25519 IK
     * for AD reconstruction and require the wire ikPub to match it. READ-ONLY: it
     * never pins/re-pins (this runs on the archive/history re-render path too, where
     * a legitimately accepted rotation must still re-render and we must not re-trip
     * the fail-closed pin logic). Mirrors _resolveResponderPeerIdentity's matching
     * rules without the bootstrap-time mutations.
     *
     *  - If the sender's X25519 IK is pinned: require wireIkPub == pinned, else THROW
     *    (the swapped-IK forgery). Use the pinned value for AD.
     *  - Else, cross-check the PUBLISHED X25519 IK (read-only): if present and it
     *    disagrees with the wire ikPub, THROW.
     *  - Genuine first contact (no pin, no published key): fall back to the wire ikPub
     *    (this is the same value bootstrap TOFU-pinned, so AD stays consistent).
     *
     * @private
     * @param {string} senderId - the bootstrap message sender (the initiator)
     * @param {string} wireIkPubB64 - x3dhPreamble.ikPub from the wire
     * @returns {Promise<string>} the TRUSTED initiator X25519 ikPub (b64)
     * @throws {PeerIdentityChangedError} on a mismatch (forged AD identity)
     */
    async _resolveADInitiatorKey(senderId, wireIkPubB64) {
        const fpOf = (b64) => CryptoPrimitivesService.getKeyFingerprint(
            CryptoPrimitivesService.deserializeKey(b64)
        );

        const pinnedIk = await KeyStorageService.getPinnedKey(senderId);
        if (pinnedIk) {
            if (pinnedIk.publicKey !== wireIkPubB64) {
                throw this._peerIdentityChangedError({
                    userId: senderId,
                    oldFingerprint: pinnedIk.fingerprint,
                    newFingerprint: fpOf(wireIkPubB64),
                    keyType: 'identity'
                });
            }
            return pinnedIk.publicKey;
        }

        // No pin yet — cross-check the published key WITHOUT mutating any pin.
        let publishedIk = null;
        try {
            publishedIk = await HistoricalKeysService.getCurrentKey(senderId);
        } catch (e) { /* read-only best effort */ }
        if (publishedIk && publishedIk !== wireIkPubB64) {
            throw this._peerIdentityChangedError({
                userId: senderId,
                oldFingerprint: fpOf(publishedIk),
                newFingerprint: fpOf(wireIkPubB64),
                keyType: 'identity'
            });
        }
        // First contact: the wire ikPub is what bootstrap TOFU-pinned.
        return wireIkPubB64;
    },

    /**
     * SM-01: Fetch a peer's current X25519 identity public key through a TOFU
     * (trust-on-first-use) pin. Single chokepoint both ECDH/X3DH sites use instead
     * of calling HistoricalKeysService.getCurrentKey directly.
     *
     * Policy — FAIL CLOSED (P0-2, roadmap #4):
     *  - First contact: pin the fetched key, return it (TOFU).
     *  - Unchanged key (common case): return it verbatim — byte-identical to today.
     *  - CHANGED key: do NOT auto-adopt/re-pin. THROW PeerIdentityChangedError so
     *    establishSession aborts and NO SK is derived against the new key. A change
     *    is the active-MITM / hostile-server signal; the pin only enforces if it
     *    blocks. Legitimate rotation / re-pair is adopted via
     *    acceptPeerIdentityChange() after the user verifies the safety number.
     *
     * @private
     * @param {string} otherUserId - Peer user ID
     * @returns {Promise<string|null>} Base64 public key or null
     * @throws {PeerIdentityChangedError} when the pinned X25519 IK has changed
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

        // CHANGED: fail closed. Warn once (for any UI listener), then THROW so no
        // session key is ever derived against an unverified new identity key.
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

        throw this._peerIdentityChangedError({
            userId: otherUserId,
            oldFingerprint: pinned.fingerprint,
            newFingerprint: fp,
            keyType: 'identity'
        });
    },

    /**
     * Adopt a CHANGED peer identity — to be called ONLY after the user has verified
     * the new identity out-of-band (e.g. compared the safety number via
     * getSafetyNumber). Re-pins BOTH the X25519 identity key and the Ed25519 IK_sig
     * to whatever the server currently publishes, clearing the fail-closed block so
     * the next establishSession proceeds. This is how legitimate key rotation /
     * device re-pair is accepted.
     *
     * Covers BOTH key types in one call (the common case: a re-paired peer presents
     * a new IK + new IK_sig together). It is idempotent and tolerant of a peer that
     * only changed one of the two.
     *
     * SECURITY: never call this automatically on a change event — that would restore
     * the old fail-open behavior. It must be gated behind explicit user verification.
     *
     * @param {string} otherUserId - Peer user id whose identity the user accepts
     * @returns {Promise<{accepted:boolean, identityFingerprint?:string, signFingerprint?:string}>}
     */
    async acceptPeerIdentityChange(otherUserId) {
        if (!this.initialized) {
            throw new Error('[KeyManagementService] Not initialized');
        }
        if (!otherUserId) {
            throw new Error('[KeyManagementService] acceptPeerIdentityChange requires a userId');
        }

        const out = { accepted: false };

        // 1) X25519 identity key — re-pin to the currently published value.
        const fetched = await HistoricalKeysService.getCurrentKey(otherUserId);
        if (fetched) {
            const fp = CryptoPrimitivesService.getKeyFingerprint(
                CryptoPrimitivesService.deserializeKey(fetched)
            );
            await KeyStorageService.pinKey(otherUserId, fetched, fp);
            out.identityFingerprint = fp;
            out.accepted = true;
        }

        // 2) Ed25519 IK_sig — re-pin from the peer's published prekey bundle row.
        try {
            const preTable = this._config?.tables?.prekeys || 'prekeys';
            const res = await this._database.querySelect(preTable, { filter: { user_id: otherUserId } });
            const row = res && res.data && res.data[0];
            if (row && row.identity_sign_pub) {
                const signPinId = this._signPinId(otherUserId);
                const signFp = CryptoPrimitivesService.getKeyFingerprint(
                    CryptoPrimitivesService.deserializeKey(row.identity_sign_pub)
                );
                await KeyStorageService.pinKey(signPinId, row.identity_sign_pub, signFp);
                out.signFingerprint = signFp;
                out.accepted = true;
            }
        } catch (e) {
            console.warn('[KeyManagementService] acceptPeerIdentityChange: could not re-pin IK_sig:', e.message);
        }

        return out;
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
     * Get a per-conversation symmetric key for ATTACHMENT file-key wrapping.
     * Used by AttachmentService (_encryptFileKey / _decryptFileKey).
     *
     * W3-2 FIX — RATCHET-INVARIANT ROOT + CONTEXT BINDING:
     * The attachment KEK MUST be derived from a secret that does NOT advance with the
     * Double Ratchet. The previous implementation derived it from the live root key
     * `state.RK`, which rotates on every DH-ratchet step — so an attachment wrapped
     * before a step became permanently undecryptable (a peer could force this with a
     * single message). We now derive from `state.AK0`, the INVARIANT attachment root
     * minted once at X3DH bootstrap from the shared secret SK (see
     * DoubleRatchetService.ratchetInit*). Both parties feed the same SK in, so both
     * derive the same AK0, and AK0 never changes for the life of the conversation ->
     * encrypt-time and decrypt-time derivation are always over the same input.
     *
     * CONTEXT BINDING (AAD-equivalent): secretbox (XSalsa20-Poly1305) takes no AAD,
     * so we bind context by folding it into the HKDF `info`. When `context` is given
     * we mix the conversation id and a stable per-attachment identifier (the storage
     * path — known at upload, persisted, and re-read at download) into the derived
     * key, so a wrapped key cannot be lifted onto another row/conversation: a key
     * wrapped for (convA, pathA) will not unwrap under (convA, pathB).
     *
     * BACK-COMPAT: existing attachments were wrapped under the legacy RK-based key
     * with NO context. To keep them decryptable we fall back to the legacy derivation
     * when AK0 is absent OR when no context is supplied (the legacy code path called
     * getSessionKey(conversationId) with one argument). New writes always pass a
     * context, so they get the invariant+bound key; reads of legacy rows that lack a
     * context still resolve via the legacy path. See attachmentService for how the
     * reader tries the bound key first and falls back to the legacy key.
     *
     * @param {number|string} conversationId - Conversation ID
     * @param {{attachmentPath?: string}} [context] - optional context to bind
     *        (attachmentPath = the storage_path of the attachment). When omitted,
     *        the LEGACY (unbound, RK-rooted) key is returned for back-compat.
     * @returns {Promise<Uint8Array|null>} 32-byte attachment key or null
     */
    async getSessionKey(conversationId, context = null) {
        if (!this.initialized) {
            console.error('[KeyManagementService] getSessionKey: Service not initialized');
            return null;
        }

        const state = await KeyStorageService.getRatchetState(conversationId);
        if (!state || !state.RK) {
            console.warn(`[KeyManagementService] getSessionKey: No ratchet session for conversation ${conversationId}`);
            return null;
        }

        // LEGACY PATH (back-compat): no context, or this session predates W3-2 and has
        // no invariant AK0 -> reproduce the original RK-rooted derivation exactly so
        // attachments wrapped under the old scheme stay decryptable. NOTE: this path
        // remains ratchet-DEPENDENT by construction (that is the bug being retired for
        // new uploads); it exists ONLY to read pre-W3-2 rows.
        if (!context || !state.AK0) {
            return await KeyDerivationService._hkdf(
                state.RK, 'MoneyTracker:Attachment:v1', 32, state.RK
            );
        }

        // W3-2 PATH: invariant root AK0 + bound context. The info string carries the
        // domain tag, the conversation id, and the per-attachment storage path so the
        // derived KEK is unique per (conversation, attachment) and cannot be reused on
        // another row. AK0 is the explicit non-empty salt (bypasses the context-salt
        // fallback deterministically). AK0 never advances -> derivation is invariant.
        const info = `MoneyTracker:Attachment:v2|conv=${conversationId}|path=${context.attachmentPath || ''}`;
        return await KeyDerivationService._hkdf(
            state.AK0, info, 32, state.AK0
        );
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
     * Read a peer's CURRENTLY server-advertised X25519 identity WITHOUT pinning it,
     * so the UI can show the user the NEW key's safety number to verify out-of-band
     * BEFORE accepting a pending identity change (P0-follow-up).
     *
     * After the fail-closed fix, getSafetyNumber -> _getPinnedPeerKey THROWS while a
     * change is pending (the whole point: never derive against an unverified key). But
     * the user still needs to SEE the new safety number to compare it. This method is
     * the read-only escape hatch: it fetches the fresh server key directly (NOT through
     * the pinning chokepoint), computes its fingerprint + safety number, and reports
     * whether it differs from the pinned key. It NEVER writes the pin — a subsequent
     * establishSession STILL fails closed until acceptPeerIdentityChange() is called.
     *
     * @param {string} otherUserId - Peer user id
     * @returns {Promise<{
     *   userId:string, changed:boolean,
     *   oldFingerprint:string|null, newFingerprint:string|null,
     *   oldSafetyNumber:string|null, newSafetyNumber:string|null
     * }>}
     */
    async getPendingPeerIdentity(otherUserId) {
        if (!otherUserId) {
            throw new Error('[KeyManagementService] getPendingPeerIdentity requires a userId');
        }
        const ourKeys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!ourKeys) {
            throw new Error('No local identity keys');
        }

        // NEW key: fetch DIRECTLY from the server (bypass _getPinnedPeerKey so this is
        // a pure read that never throws on a change and never re-pins).
        const fetchedB64 = await HistoricalKeysService.getCurrentKey(otherUserId);

        // OLD key: whatever we currently have pinned (what we actually encrypt to).
        const pinned = await KeyStorageService.getPinnedKey(otherUserId);

        const fpOf = (b64) => CryptoPrimitivesService.getKeyFingerprint(
            CryptoPrimitivesService.deserializeKey(b64)
        );
        const safetyOf = (b64) => CryptoPrimitivesService.generateSafetyNumber(
            ourKeys.publicKey, CryptoPrimitivesService.deserializeKey(b64)
        );

        const oldFingerprint = pinned ? pinned.fingerprint : null;
        const oldSafetyNumber = pinned ? safetyOf(pinned.publicKey) : null;
        const newFingerprint = fetchedB64 ? fpOf(fetchedB64) : null;
        const newSafetyNumber = fetchedB64 ? safetyOf(fetchedB64) : null;

        const changed = !!(pinned && fetchedB64 && pinned.publicKey !== fetchedB64);

        return {
            userId: otherUserId,
            changed,
            oldFingerprint,
            newFingerprint,
            oldSafetyNumber,
            newSafetyNumber
        };
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
     * Current pairing-bundle format version. v2 (FORWARD_SECRECY_DESIGN §6) adds the
     * Double Ratchet WORLD SNAPSHOT so a newly paired device can read history AND
     * continue conversations seamlessly (sequential device hand-off). v1 bundles
     * (identity secret + session backup key only) still import (fresh-ratchet path).
     */
    PAIRING_BUNDLE_VERSION: 2,

    /**
     * Export the material a NEW device needs to read ALL existing data AND continue
     * the conversation (FORWARD_SECRECY_DESIGN §6 — bundle v2):
     *
     *   - identitySecretB64    : X25519 identity secret (reused; ratchet roots + IK).
     *   - identitySignSecretB64: Ed25519 IK_sig secret (§6 explicit carry). It is
     *     ALSO deterministically derivable from the X25519 secret via HKDF
     *     (_getIdentitySignKeyPair), so it is belt-and-suspenders — included so a
     *     future change to the IK_sig derivation can't strand a paired device, and to
     *     match §6's listed contents faithfully.
     *   - sessionBackupKeyB64  : legacy session-backup key (still carried, unchanged).
     *   - ratchetSnapshot      : the §6 ratchet WORLD — every ratchet_states record,
     *     the §5 decrypted_message_keys archive (read history), skipped_message_keys,
     *     and prekey_secrets (SPK/OPK). Every secret is unwrapped from this device's
     *     local (non-extractable, per-device) wrap key and emitted as base64; the new
     *     device RE-WRAPS them under its own wrap key on import. Raw plaintext secrets
     *     NEVER touch the server: the WHOLE bundle (snapshot included) is encrypted by
     *     the existing pairing TRANSPORT crypto (devicePairingService ->
     *     PasswordCryptoService PBKDF2-600k + AES-256-GCM under the single-use code)
     *     before it leaves the device — the same envelope the identity secret already
     *     travels in.
     *
     * MULTI-DEVICE LIMITATION (documented, not half-built — §6): this snapshot enables
     * SEQUENTIAL device use — pair, then CONTINUE on the new device. It does NOT
     * support TWO devices active at once on the same identity: both would advance the
     * SAME live ratchet chain and permanently desync (single active ratchet per
     * identity). TRUE simultaneous multi-device (per-device identities / sender-key
     * fan-out, Sesame-style) is OUT OF SCOPE; it requires multiple identity/prekey
     * rows per user (a schema rethink). The clean-break + single-active-device usage
     * makes this acceptable.
     *
     * @returns {Promise<{v:number, identitySecretB64:string, identitySignSecretB64:string, sessionBackupKeyB64:(string|null), ratchetSnapshot:Object}>}
     */
    async exportPairingBundle() {
        if (!this.currentUserId) throw new Error('[KeyManagementService] Not initialized');
        const keys = await KeyStorageService.getIdentityKeys(this.currentUserId);
        if (!keys || !keys.secretKey) throw new Error('No local identity keys to share');

        // Ed25519 IK_sig secret (deterministic from the X25519 secret; carried per §6).
        let identitySignSecretB64 = null;
        try {
            const signKeys = await this._getIdentitySignKeyPair();
            identitySignSecretB64 = CryptoPrimitivesService.serializeKey(signKeys.secretKey);
        } catch (e) {
            console.warn('[KeyManagementService] exportPairingBundle: could not derive IK_sig secret:', e.message);
        }

        // The ratchet world (states + archive + skipped + prekey secrets). Secrets are
        // unwrapped here; the pairing transport layer re-encrypts the whole bundle.
        const ratchetSnapshot = await KeyStorageService.exportRatchetSnapshot(this.currentUserId);

        return {
            v: this.PAIRING_BUNDLE_VERSION,
            identitySecretB64: CryptoPrimitivesService.serializeKey(keys.secretKey),
            identitySignSecretB64,
            sessionBackupKeyB64: this._sessionBackupKey
                ? CryptoPrimitivesService.serializeKey(this._sessionBackupKey)
                : null,
            ratchetSnapshot
        };
    },

    /**
     * Install a pairing bundle on a NEW device (FORWARD_SECRECY_DESIGN §6).
     *
     * Always (v1 and v2):
     *   - derive the public key from the transferred X25519 secret, store the identity
     *     locally (wrapped at rest, SM-02), adopt the session backup key, self-heal the
     *     server's published key, sync partner keys (mirrors restoreFromPassword).
     *
     * v2 only (bundle.v >= 2 with a ratchetSnapshot):
     *   - restore the ratchet WORLD (states + §5 archive + skipped + prekey secrets),
     *     RE-WRAPPED under THIS device's wrap key. ADDITIVE + IDEMPOTENT: an existing
     *     local ratchet state for a conversation is NOT clobbered (a live local state
     *     is authoritative — overwriting it with a possibly-older snapshot would
     *     desync the conversation; §6). The archive/skipped/prekey stores are keyed by
     *     identity-stable ids and safely upserted. After this the new device can read
     *     HISTORY (archive) and CONTINUE conversations (restored live state).
     *
     * BACKWARD-COMPAT (v1 bundle, no ratchetSnapshot):
     *   - imports fine — the new device just has its identity + backup key and NO
     *     ratchet state. It will start FRESH ratchets via X3DH on the next message
     *     and re-publish its own prekeys (caller drives publishPrekeys / the next
     *     establishSession). History encrypted under the prior ratchet is NOT readable
     *     on this device for a v1 bundle (no archive transferred) — that is the cost of
     *     an old-format bundle and is the clean-break-permitted behavior.
     *
     * MULTI-DEVICE LIMITATION: SEQUENTIAL hand-off only (see exportPairingBundle).
     * Two devices active on one identity will desync the live ratchet; simultaneous
     * multi-device is OUT OF SCOPE.
     *
     * @param {Object} bundle - from exportPairingBundle on the other device
     * @returns {Promise<{success:boolean, v:number, ratchetSnapshotRestored:boolean, snapshotStats?:Object, notes:string[]}>}
     */
    async importPairingBundle(bundle) {
        if (!this.currentUserId) throw new Error('[KeyManagementService] Not initialized');
        if (!bundle || !bundle.identitySecretB64) throw new Error('Invalid pairing bundle');

        const bundleVersion = bundle.v || 1;
        const notes = [];

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

        // NOTE on IK_sig: bundle.identitySignSecretB64 is carried (§6) but NOT written
        // separately — the IK_sig keypair is regenerated deterministically from the
        // X25519 identity secret on demand (_getIdentitySignKeyPair), and that secret
        // is now stored above. We deliberately do not persist a second copy (single
        // source of truth). The carried field is forward-compat insurance only.

        // ---- v2: restore the ratchet world snapshot (additive, no-clobber) ----
        let ratchetSnapshotRestored = false;
        let snapshotStats;
        if (bundleVersion >= 2 && bundle.ratchetSnapshot) {
            snapshotStats = await KeyStorageService.importRatchetSnapshot(
                this.currentUserId, bundle.ratchetSnapshot
            );
            ratchetSnapshotRestored = true;
            notes.push(
                `Ratchet snapshot restored: ${snapshotStats.ratchetStates} conversation state(s) ` +
                `(${snapshotStats.ratchetStatesSkipped} left untouched as already-present), ` +
                `${snapshotStats.decryptedMessageKeys} archived history key(s), ` +
                `${snapshotStats.skippedMessageKeys} skipped-key(s), ` +
                `${snapshotStats.prekeySecrets} prekey secret(s). ` +
                `This device can now READ HISTORY and CONTINUE these conversations.`
            );
            notes.push(
                'SEQUENTIAL device hand-off only: if the OTHER device keeps sending on the ' +
                'same ratchet, the two devices will desync (single active ratchet per identity). ' +
                'Simultaneous multi-device is OUT OF SCOPE (FORWARD_SECRECY_DESIGN §6).'
            );
        } else {
            notes.push(
                `v${bundleVersion} bundle (no ratchet snapshot): this device starts FRESH ratchets. ` +
                'Existing conversations re-bootstrap via X3DH on the next message; the caller should ' +
                're-publish prekeys (publishPrekeys). History encrypted under the prior ratchet is ' +
                'NOT readable here (no archive transferred) — clean-break behavior.'
            );
        }

        // The new device must republish ITS prekey pool so peers can keep starting
        // sessions against this shared identity. Best-effort (needs a DB); never fatal
        // to pairing — a v1 path or a DB-less context still completes the import.
        let prekeysRepublished = false;
        try {
            if (this._database) {
                await this.publishPrekeys();
                prekeysRepublished = true;
                notes.push('Republished this device\'s SPK + OPK pool to the server.');
            }
        } catch (e) {
            console.warn('[KeyManagementService] importPairingBundle: publishPrekeys after pairing failed (non-fatal):', e.message);
            notes.push('publishPrekeys after pairing failed (non-fatal): ' + e.message);
        }

        this.initialized = true;
        console.log(`[KeyManagementService] Pairing bundle v${bundleVersion} imported (snapshot=${ratchetSnapshotRestored}, prekeys=${prekeysRepublished})`);
        return {
            success: true,
            v: bundleVersion,
            ratchetSnapshotRestored,
            snapshotStats,
            notes
        };
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
