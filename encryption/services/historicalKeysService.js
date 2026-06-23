/**
 * Historical Keys Service
 *
 * Manages storage and retrieval of historical public keys.
 * When a user regenerates their identity keys, the old public key
 * is archived here to allow decryption of old messages.
 *
 * Storage locations:
 * - Database: public_key_history table (authoritative)
 * - IndexedDB: historical_keys store (local cache)
 */

const HistoricalKeysService = {
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
            console.warn('[HistoricalKeysService] No database service provided - remote storage disabled');
        }

        this.initialized = true;
        console.log('[HistoricalKeysService] Initialized');
    },

    /**
     * Get table name from config
     * @private
     * @returns {string}
     */
    _getTableName() {
        return this._config?.tables?.publicKeyHistory || 'public_key_history';
    },

    /**
     * Store a public key in history
     * Called when regenerating keys - archives the old public key
     * @param {string} userId - User ID
     * @param {string} publicKeyB64 - Base64-encoded public key
     * @param {number} epoch - Key epoch
     */
    async storeKey(userId, publicKeyB64, epoch) {
        console.log(`[HistoricalKeysService] Storing key: epoch=${epoch}`);

        // Store in database (authoritative)
        if (this._database) {
            try {
                await this._database.queryInsert(this._getTableName(), {
                    user_id: userId,
                    public_key: publicKeyB64,
                    epoch: epoch
                });
                console.log('[HistoricalKeysService] Key stored in database');
            } catch (error) {
                // Unique constraint violation is OK - key already exists
                if (!error.message?.includes('duplicate') && !error.message?.includes('unique')) {
                    console.error('[HistoricalKeysService] Failed to store in database:', error);
                    throw error;
                }
                console.log('[HistoricalKeysService] Key already exists in database');
            }
        }

        // Also cache in IndexedDB for offline access
        try {
            await KeyStorageService.storeHistoricalKey(userId, publicKeyB64, epoch);
            console.log('[HistoricalKeysService] Key cached in IndexedDB');
        } catch (error) {
            console.warn('[HistoricalKeysService] Failed to cache in IndexedDB:', error);
        }
    },

    /**
     * Get a public key for a specific user and epoch
     * @param {string} userId - User ID
     * @param {number} epoch - Key epoch
     * @returns {Promise<string|null>} Base64-encoded public key or null
     */
    async getKeyForEpoch(userId, epoch) {
        console.log(`[HistoricalKeysService] Getting key: epoch=${epoch}`);

        // Try IndexedDB cache first (faster)
        try {
            const cachedKey = await KeyStorageService.getHistoricalKey(userId, epoch);
            if (cachedKey) {
                console.log('[HistoricalKeysService] Found key in IndexedDB cache');
                return cachedKey;
            }
        } catch (error) {
            console.warn('[HistoricalKeysService] IndexedDB lookup failed:', error);
        }

        // Fall back to database
        if (this._database) {
            try {
                const tableName = this._getTableName();
                console.log(`[HistoricalKeysService] Querying database table: ${tableName}`);
                const result = await this._database.querySelect(tableName, {
                    filter: { user_id: userId, epoch: epoch },
                    limit: 1
                });
                console.log(`[HistoricalKeysService] Database query result:`, {
                    hasData: !!result.data,
                    dataLength: result.data?.length || 0,
                    error: result.error
                });

                if (result.data?.[0]) {
                    const publicKey = result.data[0].public_key;

                    // Cache in IndexedDB for next time
                    try {
                        await KeyStorageService.storeHistoricalKey(userId, publicKey, epoch);
                    } catch (cacheError) {
                        console.warn('[HistoricalKeysService] Failed to cache key:', cacheError);
                    }

                    console.log('[HistoricalKeysService] Found key in database');
                    return publicKey;
                } else {
                    console.warn(`[HistoricalKeysService] No key found in ${tableName} for epoch=${epoch}`);
                }
            } catch (error) {
                console.error('[HistoricalKeysService] Database lookup failed:', error);
            }
        }

        console.log('[HistoricalKeysService] Key not found');
        return null;
    },

    /**
     * Get the current public key for a user (from identity_keys table)
     * @param {string} userId - User ID
     * @returns {Promise<string|null>} Base64-encoded public key or null
     */
    async getCurrentKey(userId) {
        if (!this._database) {
            console.warn('[HistoricalKeysService] No database - cannot get current key');
            return null;
        }

        const identityTable = this._config?.tables?.identityKeys || 'identity_keys';

        try {
            const result = await this._database.querySelect(identityTable, {
                filter: { user_id: userId },
                limit: 1
            });

            const publicKey = result.data?.[0]?.public_key || null;
            const returnedUserId = result.data?.[0]?.user_id;

            if (publicKey) {
                // SAFETY CHECK: Verify we got the right user's key. (Do not log the
                // public key or user-id prefixes - SM-07/SM-48 metadata hygiene.)
                if (returnedUserId && returnedUserId !== userId) {
                    console.error('[HistoricalKeysService] getCurrentKey: DATA MISMATCH - returned user does not match requested user');
                }
            } else {
                console.warn('[HistoricalKeysService] getCurrentKey: No key found for requested user');
            }

            return publicKey;
        } catch (error) {
            console.error('[HistoricalKeysService] Failed to get current key:', error);
            return null;
        }
    },

    /**
     * Get all historical keys for a user
     * @param {string} userId - User ID
     * @returns {Promise<Array>} Array of { epoch, publicKey } objects, sorted by epoch
     */
    async getAllKeysForUser(userId) {
        const keys = [];

        // Get from database
        if (this._database) {
            try {
                const result = await this._database.querySelect(this._getTableName(), {
                    filter: { user_id: userId },
                    order: [{ column: 'epoch', ascending: true }]
                });

                if (result.data) {
                    for (const row of result.data) {
                        keys.push({
                            epoch: row.epoch,
                            publicKey: row.public_key
                        });
                    }
                }
            } catch (error) {
                console.error('[HistoricalKeysService] Failed to get keys from database:', error);
            }
        }

        // Also check IndexedDB for any keys not in database
        try {
            const localKeys = await KeyStorageService.getHistoricalKeysForUser(userId);
            for (const localKey of localKeys) {
                const exists = keys.some(k => k.epoch === localKey.epoch);
                if (!exists) {
                    keys.push(localKey);
                }
            }
        } catch (error) {
            console.warn('[HistoricalKeysService] Failed to get keys from IndexedDB:', error);
        }

        // Sort by epoch
        keys.sort((a, b) => a.epoch - b.epoch);

        return keys;
    },

    /**
     * Sync historical keys from database to IndexedDB
     * Call this on initialization or when reconnecting
     * @param {string} userId - User ID
     */
    async syncToLocal(userId) {
        if (!this._database) {
            console.warn('[HistoricalKeysService] No database - cannot sync');
            return;
        }

        console.log('[HistoricalKeysService] Syncing historical keys to local...');

        try {
            const result = await this._database.querySelect(this._getTableName(), {
                filter: { user_id: userId }
            });

            if (result.data) {
                for (const row of result.data) {
                    await KeyStorageService.storeHistoricalKey(userId, row.public_key, row.epoch);
                }
                console.log(`[HistoricalKeysService] Synced ${result.data.length} keys`);
            }
        } catch (error) {
            console.error('[HistoricalKeysService] Sync failed:', error);
        }
    }
};

if (typeof window !== 'undefined') {
    window.HistoricalKeysService = HistoricalKeysService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = HistoricalKeysService;
}
