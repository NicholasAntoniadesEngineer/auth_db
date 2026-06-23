/**
 * Key Storage Service
 *
 * Manages local key storage using IndexedDB.
 * Stores:
 * - Identity keys (public + secret key pair)
 * - Session keys (per conversation + epoch)
 * - Historical public keys (for decrypting old messages)
 */

const KeyStorageService = {
    /**
     * The IndexedDB database instance
     */
    db: null,

    /**
     * Whether the service is initialized
     */
    initialized: false,

    /**
     * Configuration (set during initialize)
     */
    _config: null,

    /**
     * Initialize the service and open IndexedDB
     * @param {Object} config - Encryption config object
     */
    async initialize(config) {
        this._config = config;

        const dbName = config?.indexedDB?.name || 'MoneyTrackerEncryption';
        const dbVersion = config?.indexedDB?.version || 1;

        console.log(`[KeyStorageService] Opening IndexedDB: ${dbName} v${dbVersion}`);

        this.db = await this._openDatabase(dbName, dbVersion);
        this.initialized = true;

        console.log('[KeyStorageService] Initialized');
    },

    /**
     * Open the IndexedDB database
     * @private
     * @param {string} name - Database name
     * @param {number} version - Database version
     * @returns {Promise<IDBDatabase>}
     */
    _openDatabase(name, version) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(name, version);

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to open database:', request.error);
                reject(request.error);
            };

            request.onsuccess = () => {
                console.log('[KeyStorageService] Database opened successfully');
                resolve(request.result);
            };

            request.onupgradeneeded = (event) => {
                console.log('[KeyStorageService] Upgrading database schema...');
                const db = event.target.result;

                // Identity keys store. Record shape changed at v2: the secret is now
                // stored as AES-GCM ciphertext (wrappedSecret + wrapIv), never as
                // plaintext base64. The keyPath is unchanged so legacy v1 rows remain
                // physically present until getIdentityKeys detects + disposes them
                // (clean-break migration).
                if (!db.objectStoreNames.contains('identity_keys')) {
                    db.createObjectStore('identity_keys', { keyPath: 'userId' });
                    console.log('[KeyStorageService] Created identity_keys store');
                }

                // Session keys store (compound key: conversationId + epoch)
                if (!db.objectStoreNames.contains('session_keys')) {
                    const sessionStore = db.createObjectStore('session_keys', {
                        keyPath: ['conversationId', 'epoch']
                    });
                    sessionStore.createIndex('conversationId', 'conversationId', { unique: false });
                    sessionStore.createIndex('epoch', 'epoch', { unique: false });
                    console.log('[KeyStorageService] Created session_keys store');
                }

                // Historical keys store (compound key: userId + epoch)
                if (!db.objectStoreNames.contains('historical_keys')) {
                    const historyStore = db.createObjectStore('historical_keys', {
                        keyPath: ['userId', 'epoch']
                    });
                    historyStore.createIndex('userId', 'userId', { unique: false });
                    console.log('[KeyStorageService] Created historical_keys store');
                }

                // SM-02: Wrap-key store. Holds the non-extractable AES-GCM CryptoKey
                // used to wrap the identity secret at rest. IndexedDB persists a
                // CryptoKey via structured clone WITHOUT exposing raw bytes, and an
                // extractable:false key round-trips while remaining non-extractable.
                if (!db.objectStoreNames.contains('wrap_keys')) {
                    db.createObjectStore('wrap_keys', { keyPath: 'id' });
                    console.log('[KeyStorageService] Created wrap_keys store');
                }

                // SM-01: TOFU pin store. One pinned peer public key per userId.
                if (!db.objectStoreNames.contains('pinned_keys')) {
                    db.createObjectStore('pinned_keys', { keyPath: 'userId' });
                    console.log('[KeyStorageService] Created pinned_keys store');
                }

                // SM-10: Replay high-water marks, keyed per (conversationId, epoch, senderId).
                if (!db.objectStoreNames.contains('recv_counters')) {
                    db.createObjectStore('recv_counters', {
                        keyPath: ['conversationId', 'epoch', 'senderId']
                    });
                    console.log('[KeyStorageService] Created recv_counters store');
                }

                console.log('[KeyStorageService] Database schema upgrade complete');
            };
        });
    },

    /**
     * Ensure the service is initialized
     * @private
     */
    _ensureInitialized() {
        if (!this.initialized || !this.db) {
            throw new Error('[KeyStorageService] Service not initialized. Call initialize() first.');
        }
    },

    // ==================== Identity Secret Wrapping (SM-02) ====================

    /**
     * Fixed id of the singleton identity-wrap key record.
     * @private
     */
    _WRAP_KEY_ID: 'identity-wrap-v1',

    /**
     * Get (or lazily create) the non-extractable AES-GCM key used to wrap the
     * identity secret at rest. Generated once per browser profile and reused for
     * all identity writes. The key never exposes raw bytes: it is created with
     * extractable:false and persisted via IndexedDB structured clone.
     * @private
     * @returns {Promise<CryptoKey>}
     */
    async _getOrCreateWrapKey() {
        this._ensureInitialized();

        if (typeof crypto === 'undefined' || !crypto.subtle) {
            throw new Error('[KeyStorageService] WebCrypto SubtleCrypto unavailable - cannot wrap identity secret');
        }

        const existing = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('wrap_keys', 'readonly');
            const store = tx.objectStore('wrap_keys');
            const request = store.get(this._WRAP_KEY_ID);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });

        if (existing && existing.key) {
            return existing.key;
        }

        const key = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false, // non-extractable: raw bytes can never leave the browser
            ['encrypt', 'decrypt']
        );

        await new Promise((resolve, reject) => {
            const tx = this.db.transaction('wrap_keys', 'readwrite');
            const store = tx.objectStore('wrap_keys');
            const request = store.put({ id: this._WRAP_KEY_ID, key });
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });

        console.log('[KeyStorageService] Generated identity wrap key');
        return key;
    },

    // ==================== Identity Keys ====================

    /**
     * Store identity keys for a user.
     * SM-02: the raw secret bytes are NEVER persisted. We encrypt them with the
     * non-extractable AES-GCM wrap key and store only the ciphertext + IV. The
     * public key stays plaintext base64 (it is not secret).
     * @param {string} userId - User ID
     * @param {Object} keys - { publicKey: Uint8Array, secretKey: Uint8Array }
     */
    async storeIdentityKeys(userId, keys) {
        this._ensureInitialized();

        const wrapKey = await this._getOrCreateWrapKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // keys.secretKey is a raw Uint8Array that exists only in the JS heap.
        const wrappedSecret = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            wrapKey,
            keys.secretKey
        );

        const record = {
            userId,
            publicKey: CryptoPrimitivesService.serializeKey(keys.publicKey),
            wrappedSecret, // ArrayBuffer of AES-GCM ciphertext
            wrapIv: iv,    // Uint8Array(12)
            createdAt: new Date().toISOString()
        };

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('identity_keys', 'readwrite');
            const store = tx.objectStore('identity_keys');
            const request = store.put(record);

            request.onsuccess = () => {
                console.log('[KeyStorageService] Identity keys stored (secret wrapped)');
                resolve();
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to store identity keys:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Get identity keys for a user.
     * SM-02: unwraps the stored AES-GCM ciphertext with the non-extractable wrap
     * key and returns the same { publicKey, secretKey } Uint8Array shape callers
     * expect, so the ECDH derivation chain is byte-identical.
     *
     * Clean-break migration: a legacy v1 plaintext record (has `secretKey`, no
     * `wrappedSecret`) is intentionally disposable - we wipe local state and
     * return null so the caller falls into its existing restore-or-generate path.
     * @param {string} userId - User ID
     * @returns {Promise<Object|null>} { publicKey: Uint8Array, secretKey: Uint8Array } or null
     */
    async getIdentityKeys(userId) {
        this._ensureInitialized();

        const record = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('identity_keys', 'readonly');
            const store = tx.objectStore('identity_keys');
            const request = store.get(userId);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to get identity keys:', request.error);
                reject(request.error);
            };
        });

        if (!record) {
            return null;
        }

        // Clean-break migration: legacy plaintext record present.
        if (record.secretKey && !record.wrappedSecret) {
            console.warn('[KeyStorageService] Legacy plaintext identity record found - disposing (clean break)');
            await this.clearAll();
            return null;
        }

        if (!record.wrappedSecret || !record.wrapIv) {
            console.error('[KeyStorageService] Identity record missing wrapped secret');
            return null;
        }

        // A wrapped identity record IS present. From here on, "no usable key" and
        // "key present but currently unreadable" are DIFFERENT outcomes and must
        // not collapse to the same null. Returning null here would push a
        // same-device user (who has a perfectly good wrapped key) into the
        // restore / recovery-key flow on every login. Instead, an unwrap failure
        // throws a typed, identifiable error so callers can decide deliberately.
        let wrapKey;
        try {
            wrapKey = await this._getOrCreateWrapKey();
        } catch (wrapKeyError) {
            const err = new Error('[KeyStorageService] Identity wrap key unavailable - cannot unwrap stored secret');
            err.code = 'WRAP_KEY_UNAVAILABLE';
            err.cause = wrapKeyError;
            throw err;
        }

        let secretBuffer;
        try {
            secretBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: record.wrapIv },
                wrapKey,
                record.wrappedSecret
            );
        } catch (decryptError) {
            // The wrapped secret exists but this wrap key cannot open it (e.g. the
            // CryptoKey was regenerated, or the record was written under a different
            // key). This is NOT "no keys" - surface it distinctly so the caller does
            // not silently loop into recovery. We deliberately do NOT clearAll() here:
            // wiping a present-but-unreadable record is what produced the
            // recovery-prompt-every-login regression.
            console.error('[KeyStorageService] Failed to unwrap identity secret:', decryptError);
            const err = new Error('[KeyStorageService] Stored identity secret could not be unwrapped');
            err.code = 'IDENTITY_UNWRAP_FAILED';
            err.cause = decryptError;
            throw err;
        }

        return {
            publicKey: CryptoPrimitivesService.deserializeKey(record.publicKey),
            secretKey: new Uint8Array(secretBuffer),
            createdAt: record.createdAt
        };
    },

    /**
     * Whether a wrapped identity record physically exists for this user,
     * regardless of whether it can currently be unwrapped. Lets callers tell
     * "this device has a local identity (be careful before wiping)" apart from
     * "genuinely no local identity (safe to restore/generate)".
     * @param {string} userId - User ID
     * @returns {Promise<boolean>}
     */
    async hasWrappedIdentity(userId) {
        this._ensureInitialized();

        const record = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('identity_keys', 'readonly');
            const store = tx.objectStore('identity_keys');
            const request = store.get(userId);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });

        return !!(record && record.wrappedSecret && record.wrapIv);
    },

    /**
     * Delete identity keys for a user
     * @param {string} userId - User ID
     */
    async deleteIdentityKeys(userId) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('identity_keys', 'readwrite');
            const store = tx.objectStore('identity_keys');
            const request = store.delete(userId);

            request.onsuccess = () => {
                console.log('[KeyStorageService] Identity keys deleted');
                resolve();
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to delete identity keys:', request.error);
                reject(request.error);
            };
        });
    },

    // ==================== Session Keys ====================

    /**
     * Store a session key for a conversation
     * @param {number|string} conversationId - Conversation ID
     * @param {number} epoch - Key epoch
     * @param {Uint8Array} sessionKey - The session key
     * @param {number} counter - Message counter (default 0)
     */
    async storeSessionKey(conversationId, epoch, sessionKey, counter = 0) {
        this._ensureInitialized();

        const serialized = {
            conversationId: String(conversationId),
            epoch,
            sessionKey: CryptoPrimitivesService.serializeKey(sessionKey),
            counter,
            createdAt: new Date().toISOString()
        };

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('session_keys', 'readwrite');
            const store = tx.objectStore('session_keys');
            const request = store.put(serialized);

            request.onsuccess = () => {
                console.log(`[KeyStorageService] Session key stored: conv=${conversationId}, epoch=${epoch}`);
                resolve();
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to store session key:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Get a session key for a conversation and epoch
     * @param {number|string} conversationId - Conversation ID
     * @param {number} epoch - Key epoch
     * @returns {Promise<Object|null>} { sessionKey: Uint8Array, counter: number } or null
     */
    async getSessionKey(conversationId, epoch) {
        this._ensureInitialized();

        // Validate inputs to prevent IndexedDB errors
        if (conversationId === undefined || conversationId === null) {
            console.error('[KeyStorageService] getSessionKey: conversationId is required');
            return null;
        }
        if (epoch === undefined || epoch === null || typeof epoch !== 'number') {
            console.error('[KeyStorageService] getSessionKey: epoch must be a number, got:', typeof epoch, epoch);
            return null;
        }

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('session_keys', 'readonly');
            const store = tx.objectStore('session_keys');
            const request = store.get([String(conversationId), epoch]);

            request.onsuccess = () => {
                const result = request.result;
                if (!result) {
                    resolve(null);
                    return;
                }

                resolve({
                    sessionKey: CryptoPrimitivesService.deserializeKey(result.sessionKey),
                    counter: result.counter,
                    epoch: result.epoch
                });
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to get session key:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Get all session keys for a conversation
     * @param {number|string} conversationId - Conversation ID
     * @returns {Promise<Array>} Array of session key objects
     */
    async getSessionKeysForConversation(conversationId) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('session_keys', 'readonly');
            const store = tx.objectStore('session_keys');
            const index = store.index('conversationId');
            const request = index.getAll(String(conversationId));

            request.onsuccess = () => {
                const results = request.result.map(r => ({
                    sessionKey: CryptoPrimitivesService.deserializeKey(r.sessionKey),
                    counter: r.counter,
                    epoch: r.epoch
                }));
                resolve(results);
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to get session keys:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Increment the message counter for a session
     * @param {number|string} conversationId - Conversation ID
     * @param {number} epoch - Key epoch
     * @returns {Promise<number>} The new counter value
     */
    async incrementCounter(conversationId, epoch) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('session_keys', 'readwrite');
            const store = tx.objectStore('session_keys');
            const getRequest = store.get([String(conversationId), epoch]);

            getRequest.onsuccess = () => {
                const result = getRequest.result;
                if (!result) {
                    reject(new Error(`No session key found for conv=${conversationId}, epoch=${epoch}`));
                    return;
                }

                result.counter++;
                const putRequest = store.put(result);

                putRequest.onsuccess = () => {
                    resolve(result.counter);
                };

                putRequest.onerror = () => {
                    reject(putRequest.error);
                };
            };

            getRequest.onerror = () => {
                reject(getRequest.error);
            };
        });
    },

    /**
     * Delete all session keys for a conversation
     * @param {number|string} conversationId - Conversation ID
     */
    async deleteSessionKeysForConversation(conversationId) {
        this._ensureInitialized();

        const sessions = await this.getSessionKeysForConversation(conversationId);

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('session_keys', 'readwrite');
            const store = tx.objectStore('session_keys');

            let deleted = 0;
            sessions.forEach(s => {
                const request = store.delete([String(conversationId), s.epoch]);
                request.onsuccess = () => {
                    deleted++;
                    if (deleted === sessions.length) {
                        resolve();
                    }
                };
            });

            if (sessions.length === 0) {
                resolve();
            }

            tx.onerror = () => {
                reject(tx.error);
            };
        });
    },

    // ==================== Historical Keys ====================

    /**
     * Store a historical public key
     * @param {string} userId - User ID
     * @param {string} publicKeyB64 - Base64-encoded public key
     * @param {number} epoch - Key epoch
     */
    async storeHistoricalKey(userId, publicKeyB64, epoch) {
        this._ensureInitialized();

        const data = {
            userId,
            epoch,
            publicKey: publicKeyB64,
            createdAt: new Date().toISOString()
        };

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('historical_keys', 'readwrite');
            const store = tx.objectStore('historical_keys');
            const request = store.put(data);

            request.onsuccess = () => {
                console.log(`[KeyStorageService] Historical key stored: user=${userId.slice(0, 8)}..., epoch=${epoch}`);
                resolve();
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to store historical key:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Get a historical public key for a user at a specific epoch
     * @param {string} userId - User ID
     * @param {number} epoch - Key epoch
     * @returns {Promise<string|null>} Base64-encoded public key or null
     */
    async getHistoricalKey(userId, epoch) {
        this._ensureInitialized();

        // Validate inputs to prevent IndexedDB errors
        if (!userId || typeof userId !== 'string') {
            console.error('[KeyStorageService] getHistoricalKey: userId must be a string');
            return null;
        }
        if (epoch === undefined || epoch === null || typeof epoch !== 'number') {
            console.error('[KeyStorageService] getHistoricalKey: epoch must be a number, got:', typeof epoch, epoch);
            return null;
        }

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('historical_keys', 'readonly');
            const store = tx.objectStore('historical_keys');
            const request = store.get([userId, epoch]);

            request.onsuccess = () => {
                const result = request.result;
                resolve(result ? result.publicKey : null);
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to get historical key:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Get all historical keys for a user
     * @param {string} userId - User ID
     * @returns {Promise<Array>} Array of { epoch, publicKey } objects
     */
    async getHistoricalKeysForUser(userId) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('historical_keys', 'readonly');
            const store = tx.objectStore('historical_keys');
            const index = store.index('userId');
            const request = index.getAll(userId);

            request.onsuccess = () => {
                const results = request.result.map(r => ({
                    epoch: r.epoch,
                    publicKey: r.publicKey
                }));
                resolve(results);
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to get historical keys:', request.error);
                reject(request.error);
            };
        });
    },

    // ==================== Pinned Keys (TOFU - SM-01) ====================

    /**
     * Get the pinned public key record for a peer.
     * @param {string} userId - Peer user ID
     * @returns {Promise<Object|null>} { userId, publicKey, fingerprint, pinnedAt, lastWarnedFingerprint } or null
     */
    async getPinnedKey(userId) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('pinned_keys', 'readonly');
            const store = tx.objectStore('pinned_keys');
            const request = store.get(userId);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to get pinned key:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Pin (or re-pin) a peer's public key. Preserves an existing
     * lastWarnedFingerprint so we only warn once per distinct new key.
     * @param {string} userId - Peer user ID
     * @param {string} publicKeyB64 - Base64 public key
     * @param {string} fingerprint - Key fingerprint
     */
    async pinKey(userId, publicKeyB64, fingerprint) {
        this._ensureInitialized();

        const existing = await this.getPinnedKey(userId);
        const record = {
            userId,
            publicKey: publicKeyB64,
            fingerprint,
            pinnedAt: new Date().toISOString(),
            lastWarnedFingerprint: existing ? existing.lastWarnedFingerprint || null : null
        };

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('pinned_keys', 'readwrite');
            const store = tx.objectStore('pinned_keys');
            const request = store.put(record);
            request.onsuccess = () => resolve();
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to pin key:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Record that we have already warned the user about a given new fingerprint
     * for this peer, so the warning is one-shot per distinct new key.
     * @param {string} userId - Peer user ID
     * @param {string} fingerprint - The new fingerprint we warned about
     */
    async updatePinnedWarn(userId, fingerprint) {
        this._ensureInitialized();

        const existing = await this.getPinnedKey(userId);
        if (!existing) {
            return;
        }
        existing.lastWarnedFingerprint = fingerprint;

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('pinned_keys', 'readwrite');
            const store = tx.objectStore('pinned_keys');
            const request = store.put(existing);
            request.onsuccess = () => resolve();
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to update pinned warn:', request.error);
                reject(request.error);
            };
        });
    },

    // ==================== Replay Counters (SM-10) ====================

    /**
     * Get the last accepted message counter for a (conversation, epoch, sender).
     * @param {number|string} conversationId - Conversation ID
     * @param {number} epoch - Key epoch
     * @param {string} senderId - Sender user ID
     * @returns {Promise<number>} Last counter, or -1 if none recorded
     */
    async getLastCounter(conversationId, epoch, senderId) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('recv_counters', 'readonly');
            const store = tx.objectStore('recv_counters');
            const request = store.get([String(conversationId), epoch, senderId]);
            request.onsuccess = () => {
                const result = request.result;
                resolve(result ? result.lastCounter : -1);
            };
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to get last counter:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Persist the high-water counter for a (conversation, epoch, sender).
     * @param {number|string} conversationId - Conversation ID
     * @param {number} epoch - Key epoch
     * @param {string} senderId - Sender user ID
     * @param {number} n - The counter to record as the new high-water mark
     */
    async setLastCounter(conversationId, epoch, senderId, n) {
        this._ensureInitialized();

        const record = {
            conversationId: String(conversationId),
            epoch,
            senderId,
            lastCounter: n,
            updatedAt: new Date().toISOString()
        };

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('recv_counters', 'readwrite');
            const store = tx.objectStore('recv_counters');
            const request = store.put(record);
            request.onsuccess = () => resolve();
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to set last counter:', request.error);
                reject(request.error);
            };
        });
    },

    // ==================== Database Management ====================

    /**
     * Clear all data from all stores.
     * NOTE: the wrap_keys store is intentionally preserved - the non-extractable
     * AES-GCM wrap key is per-browser-profile and reused across identity
     * re-generation / restore. pinned_keys and recv_counters are local caches
     * that safely rebuild (TOFU re-pins, counters default to -1).
     */
    async clearAll() {
        this._ensureInitialized();

        const stores = ['identity_keys', 'session_keys', 'historical_keys', 'pinned_keys', 'recv_counters'];

        for (const storeName of stores) {
            await new Promise((resolve, reject) => {
                const tx = this.db.transaction(storeName, 'readwrite');
                const store = tx.objectStore(storeName);
                const request = store.clear();

                request.onsuccess = () => {
                    console.log(`[KeyStorageService] Cleared ${storeName}`);
                    resolve();
                };

                request.onerror = () => {
                    reject(request.error);
                };
            });
        }

        console.log('[KeyStorageService] All stores cleared');
    },

    /**
     * Delete the entire database
     */
    async deleteDatabase() {
        if (this.db) {
            this.db.close();
            this.db = null;
        }

        const dbName = this._config?.indexedDB?.name || 'MoneyTrackerEncryption';

        return new Promise((resolve, reject) => {
            const request = indexedDB.deleteDatabase(dbName);

            request.onsuccess = () => {
                console.log('[KeyStorageService] Database deleted');
                this.initialized = false;
                resolve();
            };

            request.onerror = () => {
                console.error('[KeyStorageService] Failed to delete database:', request.error);
                reject(request.error);
            };

            request.onblocked = () => {
                console.warn('[KeyStorageService] Database deletion blocked - close all connections');
            };
        });
    },

    /**
     * Check if IndexedDB is available
     * @returns {boolean}
     */
    isAvailable() {
        return typeof indexedDB !== 'undefined';
    }
};

if (typeof window !== 'undefined') {
    window.KeyStorageService = KeyStorageService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = KeyStorageService;
}
