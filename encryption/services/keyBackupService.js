/**
 * Key Backup Service
 *
 * Manages encrypted backups of identity keys and session keys.
 * Enables multi-device support by storing encrypted backups in the database.
 *
 * Backup Types:
 * - Identity Key Backup: Password-encrypted private key stored in database
 * - Session Key Backup: Backup-key encrypted session keys for each conversation
 */

const KeyBackupService = {
    /**
     * Configuration (set during initialize)
     */
    _config: null,

    /**
     * Database service reference
     */
    _database: null,

    /**
     * Whether the service is initialized
     */
    initialized: false,

    /**
     * Initialize the service
     * @param {Object} config - Encryption config object
     */
    initialize(config) {
        this._config = config;
        this._database = config.services?.database;

        if (!this._database) {
            console.warn('[KeyBackupService] No database service - backups disabled');
        }

        this.initialized = true;
        console.log('[KeyBackupService] Initialized');
    },

    /**
     * Get table name for identity key backups
     * @private
     * @returns {string}
     */
    _getBackupTableName() {
        return this._config?.tables?.identityKeyBackups || 'identity_key_backups';
    },

    /**
     * Get table name for session key backups
     * @private
     * @returns {string}
     */
    _getSessionTableName() {
        return this._config?.tables?.conversationSessionKeys || 'conversation_session_keys';
    },

    // ==================== Identity Key Backups ====================

    /**
     * Create an encrypted backup of identity keys
     * Also generates a stable session backup key that survives key rotation
     * @param {string} userId - User ID
     * @param {Uint8Array} secretKey - The secret key to backup
     * @param {string} password - User's backup password
     * @returns {Promise<Object>} { success: boolean, recoveryKey?: string, sessionBackupKey?: Uint8Array }
     */
    async createIdentityBackup(userId, secretKey, password) {
        if (!this._database) {
            throw new Error('[KeyBackupService] No database - cannot create backup');
        }

        console.log('[KeyBackupService] Creating identity key backup...');

        // Encrypt identity key with password
        const passwordEncrypted = await PasswordCryptoService.encryptToBase64(secretKey, password);

        // Generate and encrypt recovery key
        const recoveryKey = PasswordCryptoService.generateRecoveryKey();
        const recoveryEncrypted = await PasswordCryptoService.encryptToBase64(secretKey, recoveryKey);

        // Generate a STABLE session backup key that will be used for all session backups
        // This key survives identity key rotation, ensuring multi-device sync always works
        const sessionBackupKey = CryptoPrimitivesService.randomBytes(32);

        // Encrypt the session backup key with the password (so it can be restored on new devices)
        const sessionKeyEncrypted = await PasswordCryptoService.encryptToBase64(sessionBackupKey, password);

        // Store in database
        try {
            await this._database.queryUpsert(this._getBackupTableName(), {
                user_id: userId,
                password_encrypted_data: passwordEncrypted.encryptedData,
                password_salt: passwordEncrypted.salt,
                password_iv: passwordEncrypted.iv,
                recovery_encrypted_data: recoveryEncrypted.encryptedData,
                recovery_salt: recoveryEncrypted.salt,
                recovery_iv: recoveryEncrypted.iv,
                // New: stable session backup key encrypted with password
                session_backup_key_encrypted: sessionKeyEncrypted.encryptedData,
                session_backup_key_salt: sessionKeyEncrypted.salt,
                session_backup_key_iv: sessionKeyEncrypted.iv,
                updated_at: new Date().toISOString()
            }, {
                onConflict: 'user_id',
                returning: true
            });

            console.log('[KeyBackupService] Identity backup created with stable session backup key');

            return {
                success: true,
                recoveryKey: PasswordCryptoService.formatRecoveryKey(recoveryKey),
                sessionBackupKey: sessionBackupKey
            };
        } catch (error) {
            console.error('[KeyBackupService] Failed to create backup:', error);
            throw error;
        }
    },

    /**
     * Create an encrypted backup of identity keys with a provided recovery key
     * Used during device pairing when the recovery key is generated externally
     * @param {string} userId - User ID
     * @param {Uint8Array} secretKey - The secret key to backup
     * @param {string} password - User's backup password
     * @param {string} recoveryKey - Externally generated recovery key (24-word mnemonic or formatted)
     * @returns {Promise<Object>} { success: boolean, sessionBackupKey?: Uint8Array }
     */
    async createIdentityBackupWithRecoveryKey(userId, secretKey, password, recoveryKey) {
        if (!this._database) {
            throw new Error('[KeyBackupService] No database - cannot create backup');
        }

        console.log('[KeyBackupService] Creating identity key backup with provided recovery key...');

        // Encrypt identity key with password
        const passwordEncrypted = await PasswordCryptoService.encryptToBase64(secretKey, password);

        // Encrypt identity key with the provided recovery key
        // The recovery key may be formatted (with dashes) or raw
        const recoveryEncrypted = await PasswordCryptoService.encryptToBase64(secretKey, recoveryKey);

        // Generate a STABLE session backup key that will be used for all session backups
        // This key survives identity key rotation, ensuring multi-device sync always works
        const sessionBackupKey = CryptoPrimitivesService.randomBytes(32);

        // Encrypt the session backup key with the password (so it can be restored on new devices)
        const sessionKeyEncrypted = await PasswordCryptoService.encryptToBase64(sessionBackupKey, password);

        // Store in database
        try {
            await this._database.queryUpsert(this._getBackupTableName(), {
                user_id: userId,
                password_encrypted_data: passwordEncrypted.encryptedData,
                password_salt: passwordEncrypted.salt,
                password_iv: passwordEncrypted.iv,
                recovery_encrypted_data: recoveryEncrypted.encryptedData,
                recovery_salt: recoveryEncrypted.salt,
                recovery_iv: recoveryEncrypted.iv,
                // Stable session backup key encrypted with password
                session_backup_key_encrypted: sessionKeyEncrypted.encryptedData,
                session_backup_key_salt: sessionKeyEncrypted.salt,
                session_backup_key_iv: sessionKeyEncrypted.iv,
                updated_at: new Date().toISOString()
            }, {
                onConflict: 'user_id',
                returning: true
            });

            console.log('[KeyBackupService] Identity backup created with provided recovery key');

            return {
                success: true,
                sessionBackupKey: sessionBackupKey
            };
        } catch (error) {
            console.error('[KeyBackupService] Failed to create backup:', error);
            throw error;
        }
    },

    /**
     * Create a password-only backup of identity keys (no recovery key)
     * Used for re-encrypting backups after password reset
     * @param {string} userId - User ID
     * @param {Uint8Array} secretKey - The secret key to backup
     * @param {string} password - User's password
     * @returns {Promise<Object>} { success: boolean, sessionBackupKey?: Uint8Array }
     */
    async createPasswordOnlyBackup(userId, secretKey, password) {
        if (!this._database) {
            throw new Error('[KeyBackupService] No database - cannot create backup');
        }

        console.log('[KeyBackupService] Creating password-only identity key backup...');

        const passwordEncrypted = await PasswordCryptoService.encryptToBase64(secretKey, password);

        const sessionBackupKey = CryptoPrimitivesService.randomBytes(32);
        const sessionKeyEncrypted = await PasswordCryptoService.encryptToBase64(sessionBackupKey, password);

        try {
            await this._database.queryUpsert(this._getBackupTableName(), {
                user_id: userId,
                password_encrypted_data: passwordEncrypted.encryptedData,
                password_salt: passwordEncrypted.salt,
                password_iv: passwordEncrypted.iv,
                recovery_encrypted_data: null,
                recovery_salt: null,
                recovery_iv: null,
                session_backup_key_encrypted: sessionKeyEncrypted.encryptedData,
                session_backup_key_salt: sessionKeyEncrypted.salt,
                session_backup_key_iv: sessionKeyEncrypted.iv,
                updated_at: new Date().toISOString()
            }, {
                onConflict: 'user_id',
                returning: true
            });

            console.log('[KeyBackupService] Password-only backup created');
            return { success: true, sessionBackupKey: sessionBackupKey };
        } catch (error) {
            console.error('[KeyBackupService] Failed to create password-only backup:', error);
            throw error;
        }
    },

    /**
     * Restore identity keys from password backup
     * @param {string} userId - User ID
     * @param {string} password - User's backup password
     * @returns {Promise<Uint8Array>} The decrypted secret key
     */
    async restoreFromPassword(userId, password) {
        if (!this._database) {
            throw new Error('[KeyBackupService] No database - cannot restore');
        }

        console.log('[KeyBackupService] Restoring from password backup...');

        const result = await this._database.querySelect(this._getBackupTableName(), {
            filter: { user_id: userId },
            limit: 1
        });

        if (!result.data?.[0]) {
            throw new Error('No backup found for user');
        }

        const backup = result.data[0];

        try {
            const secretKey = await PasswordCryptoService.decryptFromBase64(
                backup.password_encrypted_data,
                password,
                backup.password_salt,
                backup.password_iv
            );

            console.log('[KeyBackupService] Successfully restored from password');
            return secretKey;
        } catch (error) {
            console.error('[KeyBackupService] Password decryption failed:', error);
            throw new Error('Incorrect password');
        }
    },

    /**
     * Restore identity keys from recovery key
     * @param {string} userId - User ID
     * @param {string} recoveryKey - Recovery key (formatted or raw)
     * @returns {Promise<Uint8Array>} The decrypted secret key
     */
    async restoreFromRecoveryKey(userId, recoveryKey) {
        if (!this._database) {
            throw new Error('[KeyBackupService] No database - cannot restore');
        }

        console.log('[KeyBackupService] Restoring from recovery key...');

        const result = await this._database.querySelect(this._getBackupTableName(), {
            filter: { user_id: userId },
            limit: 1
        });

        if (!result.data?.[0]) {
            throw new Error('No backup found for user');
        }

        const backup = result.data[0];

        // Parse the formatted recovery key back to base64
        // The recovery key was stored as base64, then formatted as Base32 for display
        let recoveryKeyB64;
        try {
            recoveryKeyB64 = PasswordCryptoService.parseRecoveryKey(recoveryKey);
        } catch (parseError) {
            console.error('[KeyBackupService] Failed to parse recovery key format:', parseError);
            throw new Error('Invalid recovery key format');
        }

        try {
            const secretKey = await PasswordCryptoService.decryptFromBase64(
                backup.recovery_encrypted_data,
                recoveryKeyB64,
                backup.recovery_salt,
                backup.recovery_iv
            );

            console.log('[KeyBackupService] Successfully restored from recovery key');
            return secretKey;
        } catch (error) {
            console.error('[KeyBackupService] Recovery key decryption failed:', error);
            throw new Error('Invalid recovery key');
        }
    },

    /**
     * Check if a backup exists for a user
     * @param {string} userId - User ID
     * @returns {Promise<boolean>}
     */
    async hasBackup(userId) {
        if (!this._database) {
            return false;
        }

        try {
            const result = await this._database.querySelect(this._getBackupTableName(), {
                filter: { user_id: userId },
                limit: 1
            });
            return !!(result.data?.[0]);
        } catch (error) {
            console.error('[KeyBackupService] Error checking backup:', error);
            return false;
        }
    },

    /**
     * Restore the stable session backup key from password backup
     * This key is used for encrypting/decrypting session keys across all devices
     * @param {string} userId - User ID
     * @param {string} password - User's backup password
     * @returns {Promise<Uint8Array>} The session backup key
     */
    async restoreSessionBackupKey(userId, password) {
        if (!this._database) {
            throw new Error('[KeyBackupService] No database - cannot restore');
        }

        console.log('[KeyBackupService] Restoring session backup key...');

        const result = await this._database.querySelect(this._getBackupTableName(), {
            filter: { user_id: userId },
            limit: 1
        });

        if (!result.data?.[0]) {
            throw new Error('No backup found for user');
        }

        const backup = result.data[0];

        // Check if session backup key exists (may not exist for old backups)
        if (!backup.session_backup_key_encrypted) {
            console.log('[KeyBackupService] No session backup key in backup - will need to generate one');
            return null;
        }

        try {
            const sessionBackupKey = await PasswordCryptoService.decryptFromBase64(
                backup.session_backup_key_encrypted,
                password,
                backup.session_backup_key_salt,
                backup.session_backup_key_iv
            );

            console.log('[KeyBackupService] Successfully restored session backup key');
            return sessionBackupKey;
        } catch (error) {
            console.error('[KeyBackupService] Session backup key decryption failed:', error);
            throw new Error('Failed to restore session backup key - incorrect password');
        }
    },

    /**
     * Add a session backup key to an existing backup (for migration)
     * @param {string} userId - User ID
     * @param {string} password - User's backup password
     * @returns {Promise<Uint8Array>} The new session backup key
     */
    async addSessionBackupKeyToExistingBackup(userId, password) {
        if (!this._database) {
            throw new Error('[KeyBackupService] No database - cannot update backup');
        }

        console.log('[KeyBackupService] Adding session backup key to existing backup...');

        // Generate new session backup key
        const sessionBackupKey = CryptoPrimitivesService.randomBytes(32);

        // Encrypt with password
        const sessionKeyEncrypted = await PasswordCryptoService.encryptToBase64(sessionBackupKey, password);

        // Update the backup
        try {
            await this._database.queryUpdate(this._getBackupTableName(), {
                session_backup_key_encrypted: sessionKeyEncrypted.encryptedData,
                session_backup_key_salt: sessionKeyEncrypted.salt,
                session_backup_key_iv: sessionKeyEncrypted.iv,
                updated_at: new Date().toISOString()
            }, {
                user_id: userId
            });

            console.log('[KeyBackupService] Session backup key added to existing backup');
            return sessionBackupKey;
        } catch (error) {
            console.error('[KeyBackupService] Failed to add session backup key:', error);
            throw error;
        }
    },

    /**
     * Update backup password (re-encrypt with new password)
     * @param {string} userId - User ID
     * @param {string} oldPassword - Current password
     * @param {string} newPassword - New password
     */
    async updatePassword(userId, oldPassword, newPassword) {
        // First restore the key using old password
        const secretKey = await this.restoreFromPassword(userId, oldPassword);

        // Then create new backup with new password
        // Note: This generates a new recovery key
        return await this.createIdentityBackup(userId, secretKey, newPassword);
    },

    // ==================== Session Key Backups ====================

    /**
     * Backup a session key to the database
     * Session keys are encrypted with a key derived from the identity key
     * @param {string} userId - User ID
     * @param {number|string} conversationId - Conversation ID
     * @param {Uint8Array} sessionKey - The session key to backup
     * @param {number} epoch - Key epoch
     * @param {Uint8Array} backupKey - Key to encrypt the backup (derived from identity)
     */
    async backupSessionKey(userId, conversationId, sessionKey, epoch, backupKey) {
        if (!this._database) {
            console.warn('[KeyBackupService] No database - session backup skipped');
            return;
        }

        console.log(`[KeyBackupService] Backing up session key: conv=${conversationId}, epoch=${epoch}`);

        // Encrypt session key
        const encrypted = CryptoPrimitivesService.encrypt(
            CryptoPrimitivesService.serializeKey(sessionKey),
            backupKey
        );

        try {
            await this._database.queryUpsert(this._getSessionTableName(), {
                user_id: userId,
                conversation_id: conversationId,
                encrypted_session_key: encrypted.ciphertext,
                encryption_nonce: encrypted.nonce,
                key_epoch: epoch,
                message_counter: 0,
                updated_at: new Date().toISOString()
            }, {
                onConflict: 'user_id,conversation_id,key_epoch',
                returning: true
            });

            console.log('[KeyBackupService] Session key backed up');
        } catch (error) {
            console.error('[KeyBackupService] Failed to backup session key:', error);
            throw error;
        }
    },

    /**
     * Restore session keys from backup
     * Reports failures explicitly instead of silently skipping
     * @param {string} userId - User ID
     * @param {Uint8Array} backupKey - Key to decrypt the backups
     * @returns {Promise<Array>} Array of { conversationId, epoch, sessionKey, counter }
     */
    async restoreSessionKeys(userId, backupKey) {
        if (!this._database) {
            return [];
        }

        console.log('[KeyBackupService] Restoring session keys...');

        try {
            const result = await this._database.querySelect(this._getSessionTableName(), {
                filter: { user_id: userId }
            });

            const sessions = [];
            const failures = [];

            for (const row of result.data || []) {
                try {
                    const decrypted = CryptoPrimitivesService.decrypt(
                        row.encrypted_session_key,
                        row.encryption_nonce,
                        backupKey
                    );

                    sessions.push({
                        conversationId: row.conversation_id,
                        epoch: row.key_epoch,
                        sessionKey: CryptoPrimitivesService.deserializeKey(decrypted),
                        counter: row.message_counter
                    });
                } catch (decryptError) {
                    // Track failures instead of silently skipping
                    failures.push({
                        conversationId: row.conversation_id,
                        epoch: row.key_epoch,
                        error: decryptError.message
                    });
                    console.warn(`[KeyBackupService] Failed to decrypt session for conv=${row.conversation_id}, epoch=${row.key_epoch}:`, decryptError.message);
                }
            }

            // Report failures to allow for debugging and user notification
            if (failures.length > 0) {
                console.error(`[KeyBackupService] Session restore failures: ${failures.length} of ${(result.data || []).length} sessions failed`);
                console.error('[KeyBackupService] Failed sessions:', JSON.stringify(failures, null, 2));

                // Emit event for UI to handle
                if (typeof window !== 'undefined') {
                    window.dispatchEvent(new CustomEvent('sessionRestoreFailures', {
                        detail: {
                            failures: failures,
                            successCount: sessions.length,
                            totalCount: (result.data || []).length
                        }
                    }));
                }
            }

            console.log(`[KeyBackupService] Restored ${sessions.length} session keys (${failures.length} failures)`);
            return sessions;
        } catch (error) {
            console.error('[KeyBackupService] Failed to restore session keys:', error);
            return [];
        }
    },

    /**
     * Update message counter for a session backup
     * @param {string} userId - User ID
     * @param {number|string} conversationId - Conversation ID
     * @param {number} epoch - Key epoch
     * @param {number} counter - New counter value
     */
    async updateSessionCounter(userId, conversationId, epoch, counter) {
        if (!this._database) {
            return;
        }

        try {
            await this._database.queryUpdate(this._getSessionTableName(), {
                message_counter: counter,
                updated_at: new Date().toISOString()
            }, {
                user_id: userId,
                conversation_id: conversationId,
                key_epoch: epoch
            });
        } catch (error) {
            console.warn('[KeyBackupService] Failed to update session counter:', error);
        }
    },

    /**
     * Re-encrypt all session backups with a new key
     * Called when identity keys are regenerated
     * @param {string} userId - User ID
     * @param {Uint8Array} oldBackupKey - Old backup key
     * @param {Uint8Array} newBackupKey - New backup key
     */
    async reEncryptSessionBackups(userId, oldBackupKey, newBackupKey) {
        console.log('[KeyBackupService] Re-encrypting session backups...');

        // Restore all sessions with old key
        const sessions = await this.restoreSessionKeys(userId, oldBackupKey);

        // Re-encrypt each with new key
        for (const session of sessions) {
            await this.backupSessionKey(
                userId,
                session.conversationId,
                session.sessionKey,
                session.epoch,
                newBackupKey
            );
        }

        console.log(`[KeyBackupService] Re-encrypted ${sessions.length} session backups`);
    },

    /**
     * Delete all backups for a user
     * @param {string} userId - User ID
     */
    async deleteAllBackups(userId) {
        if (!this._database) {
            return;
        }

        console.log('[KeyBackupService] Deleting all backups...');

        try {
            await this._database.queryDelete(this._getBackupTableName(), {
                filter: { user_id: userId }
            });

            await this._database.queryDelete(this._getSessionTableName(), {
                filter: { user_id: userId }
            });

            console.log('[KeyBackupService] All backups deleted');
        } catch (error) {
            console.error('[KeyBackupService] Failed to delete backups:', error);
        }
    }
};

if (typeof window !== 'undefined') {
    window.KeyBackupService = KeyBackupService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = KeyBackupService;
}
