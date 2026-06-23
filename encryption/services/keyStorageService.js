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
        // Default bumped to 3 (S5): the X3DH prekey-secret store ships at v3, on top
        // of the v2 ratchet-persistence stores. onupgradeneeded is strictly ADDITIVE
        // (every createObjectStore is guarded by `if (!contains)`), so an existing
        // v1/v2 DB upgrades in place without dropping identity_keys / session_keys /
        // ratchet_states / etc.
        const dbVersion = config?.indexedDB?.version || 3;

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

                // ===== S4: Double Ratchet persistence (FORWARD_SECRECY_DESIGN §4.5) =====
                // All three are ADDED here without touching the stores above. Every
                // secret-bearing field is WRAPPED with the same SM-02 wrap_keys
                // AES-GCM key before it lands in IndexedDB (see _wrapSecret).

                // ratchet_states — one serialized Double Ratchet state per
                // conversation (RK, CKs/CKr chain keys, DHs keypair, DHr, counters,
                // PN, MKSKIPPED). The whole serialized blob is wrapped at rest.
                if (!db.objectStoreNames.contains('ratchet_states')) {
                    db.createObjectStore('ratchet_states', { keyPath: 'conversationId' });
                    console.log('[KeyStorageService] Created ratchet_states store');
                }

                // skipped_message_keys — bounded store of
                // (conversationId, ratchetPub, msgNum) -> message key, for
                // out-of-order / skipped delivery (the persisted MKSKIPPED map).
                // Compound keyPath + a conversationId index for bulk eviction.
                if (!db.objectStoreNames.contains('skipped_message_keys')) {
                    const skippedStore = db.createObjectStore('skipped_message_keys', {
                        keyPath: ['conversationId', 'ratchetPub', 'msgNum']
                    });
                    skippedStore.createIndex('conversationId', 'conversationId', { unique: false });
                    console.log('[KeyStorageService] Created skipped_message_keys store');
                }

                // decrypted_message_keys — the per-message-key ARCHIVE (§5): the
                // message key actually used to decrypt each message, keyed by
                // message id. getMessages re-renders history via ARCHIVE LOOKUP,
                // never by replaying the live ratchet. Wrapped at rest.
                if (!db.objectStoreNames.contains('decrypted_message_keys')) {
                    const archiveStore = db.createObjectStore('decrypted_message_keys', {
                        keyPath: 'messageId'
                    });
                    archiveStore.createIndex('conversationId', 'conversationId', { unique: false });
                    console.log('[KeyStorageService] Created decrypted_message_keys store');
                }

                // ===== S5: X3DH prekey SECRETS (FORWARD_SECRECY_DESIGN §2) =====
                // The signed-prekey (SPK) and one-time-prekey (OPK) SECRET keypairs
                // the responder needs to recompute the X3DH DHs when an inbound
                // bootstrap names a given spk_id / opk_id. Only PUBLIC material is
                // published to the server; these secrets stay local, WRAPPED at rest.
                // keyPath ['userId','kind','keyId'] -> kind is 'spk' | 'opk'.
                if (!db.objectStoreNames.contains('prekey_secrets')) {
                    const prekeyStore = db.createObjectStore('prekey_secrets', {
                        keyPath: ['userId', 'kind', 'keyId']
                    });
                    prekeyStore.createIndex('userKind', ['userId', 'kind'], { unique: false });
                    console.log('[KeyStorageService] Created prekey_secrets store');
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

    /**
     * Wrap raw secret bytes at rest with the singleton non-extractable AES-GCM
     * wrap key (SM-02). This is the SAME mechanism storeIdentityKeys uses for the
     * identity secret, factored out so ratchet secrets (chain keys, ratchet
     * secret key, archived message keys) are wrapped byte-identically: a fresh
     * random 12-byte IV per call + AES-GCM encrypt under the wrap key.
     *
     * @private
     * @param {Uint8Array} secretBytes - raw bytes to protect (lives only in JS heap)
     * @returns {Promise<{wrapped: ArrayBuffer, iv: Uint8Array}>} ciphertext + IV
     */
    async _wrapSecret(secretBytes) {
        this._ensureInitialized();

        const wrapKey = await this._getOrCreateWrapKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const wrapped = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            wrapKey,
            secretBytes
        );
        return { wrapped, iv };
    },

    /**
     * Inverse of _wrapSecret: unwrap AES-GCM ciphertext back to raw bytes using
     * the same non-extractable wrap key. Mirrors getIdentityKeys' unwrap path,
     * including the typed-error discipline (WRAP_KEY_UNAVAILABLE vs UNWRAP_FAILED)
     * so callers can tell "wrap key gone" from "ciphertext can't be opened" and
     * never silently treat a present-but-unreadable secret as "no data".
     *
     * @private
     * @param {ArrayBuffer|Uint8Array} wrapped - AES-GCM ciphertext from _wrapSecret
     * @param {Uint8Array} iv - the 12-byte IV from _wrapSecret
     * @returns {Promise<Uint8Array>} the recovered raw secret bytes
     */
    async _unwrapSecret(wrapped, iv) {
        this._ensureInitialized();

        let wrapKey;
        try {
            wrapKey = await this._getOrCreateWrapKey();
        } catch (wrapKeyError) {
            const err = new Error('[KeyStorageService] Wrap key unavailable - cannot unwrap stored secret');
            err.code = 'WRAP_KEY_UNAVAILABLE';
            err.cause = wrapKeyError;
            throw err;
        }

        let buffer;
        try {
            buffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrapKey, wrapped);
        } catch (decryptError) {
            const err = new Error('[KeyStorageService] Stored secret could not be unwrapped');
            err.code = 'SECRET_UNWRAP_FAILED';
            err.cause = decryptError;
            throw err;
        }

        return new Uint8Array(buffer);
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

    // ==================== Ratchet State Persistence (S4) ====================
    //
    // FORWARD_SECRECY_DESIGN §4.5 + §5. Three stores, all secret-bearing fields
    // wrapped at rest with the SM-02 wrap key (via _wrapSecret/_unwrapSecret):
    //   ratchet_states         -> the serialized Double Ratchet state per convo
    //   skipped_message_keys   -> (peer ratchet pub, msg num) -> MK, bounded
    //   decrypted_message_keys -> per-message-key ARCHIVE, message id -> MK
    //
    // NOTE: these helpers only persist/serialize. They do NOT advance the ratchet
    // and are NOT yet wired into encrypt/decrypt (that is S5/S6).

    /**
     * Upper bound on persisted skipped message keys per conversation. Mirrors the
     * DoubleRatchetService MAX_SKIP bound (FORWARD_SECRECY_DESIGN §3) so the
     * on-disk store cannot be grown unboundedly by a malicious peer. Enforced in
     * putSkippedMessageKey.
     */
    MAX_SKIPPED_KEYS_PER_CONVERSATION: 1000,

    /**
     * Serialize a live DoubleRatchetService state object (Uint8Arrays + a DHs
     * keypair + a MKSKIPPED Map) into a lossless, JSON-safe plain object using the
     * codebase's base64 convention (CryptoPrimitivesService.serializeKey). The
     * inverse is deserializeRatchetState; round-tripping is byte-identical.
     *
     * Shape in / out (see doubleRatchetService.js):
     *   { RK, CKs, CKr, DHs:{publicKey,secretKey}, DHr, Ns, Nr, PN, MKSKIPPED:Map }
     *
     * @param {Object} state - live ratchet state
     * @returns {Object} JSON-safe serialized form (all bytes -> base64 strings)
     */
    serializeRatchetState(state) {
        const ser = (b) => (b ? CryptoPrimitivesService.serializeKey(b) : null);

        // MKSKIPPED is a Map "<dhPubB64>|<n>" -> Uint8Array(MK). Persist it as an
        // array of {k, mk} so JSON.stringify is stable and lossless.
        const skipped = [];
        if (state.MKSKIPPED && typeof state.MKSKIPPED.forEach === 'function') {
            state.MKSKIPPED.forEach((mk, k) => {
                skipped.push({ k, mk: ser(mk) });
            });
        }

        return {
            RK: ser(state.RK),
            CKs: ser(state.CKs),
            CKr: ser(state.CKr),
            DHs: state.DHs ? {
                publicKey: ser(state.DHs.publicKey),
                secretKey: ser(state.DHs.secretKey) // the ratchet SECRET — wrapped with the rest
            } : null,
            DHr: ser(state.DHr),
            Ns: state.Ns | 0,
            Nr: state.Nr | 0,
            PN: state.PN | 0,
            MKSKIPPED: skipped
        };
    },

    /**
     * Inverse of serializeRatchetState: rebuild a live ratchet state object
     * (Uint8Arrays + DHs keypair + MKSKIPPED Map) from the serialized form.
     *
     * @param {Object} obj - serialized form from serializeRatchetState
     * @returns {Object} live ratchet state ready for DoubleRatchetService
     */
    deserializeRatchetState(obj) {
        const de = (s) => (s ? CryptoPrimitivesService.deserializeKey(s) : null);

        const MKSKIPPED = new Map();
        if (Array.isArray(obj.MKSKIPPED)) {
            for (const entry of obj.MKSKIPPED) {
                MKSKIPPED.set(entry.k, de(entry.mk));
            }
        }

        return {
            RK: de(obj.RK),
            CKs: de(obj.CKs),
            CKr: de(obj.CKr),
            DHs: obj.DHs ? {
                publicKey: de(obj.DHs.publicKey),
                secretKey: de(obj.DHs.secretKey)
            } : null,
            DHr: de(obj.DHr),
            Ns: obj.Ns | 0,
            Nr: obj.Nr | 0,
            PN: obj.PN | 0,
            MKSKIPPED
        };
    },

    /**
     * Persist a Double Ratchet state for a conversation. The ENTIRE serialized
     * state (root key, both chain keys, the ratchet secret key, and every skipped
     * message key) is wrapped as a single AES-GCM blob at rest — so no secret
     * field ever touches IndexedDB in the clear. Only the conversationId key and a
     * format version sit outside the wrapped blob.
     *
     * @param {number|string} conversationId
     * @param {Object} state - live DoubleRatchetService state
     */
    async putRatchetState(conversationId, state) {
        this._ensureInitialized();

        const serialized = this.serializeRatchetState(state);
        const plaintextBytes = CryptoPrimitivesService.encodeUTF8(JSON.stringify(serialized));
        const { wrapped, iv } = await this._wrapSecret(plaintextBytes);

        const record = {
            conversationId: String(conversationId),
            wrappedState: wrapped, // ArrayBuffer of AES-GCM ciphertext
            wrapIv: iv,            // Uint8Array(12)
            version: 2,
            updatedAt: new Date().toISOString()
        };

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('ratchet_states', 'readwrite');
            const store = tx.objectStore('ratchet_states');
            const request = store.put(record);
            request.onsuccess = () => resolve();
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to put ratchet state:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Load + unwrap a Double Ratchet state for a conversation.
     * @param {number|string} conversationId
     * @returns {Promise<Object|null>} live ratchet state, or null if none stored
     */
    async getRatchetState(conversationId) {
        this._ensureInitialized();

        const record = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('ratchet_states', 'readonly');
            const store = tx.objectStore('ratchet_states');
            const request = store.get(String(conversationId));
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });

        if (!record) {
            return null;
        }
        if (!record.wrappedState || !record.wrapIv) {
            console.error('[KeyStorageService] Ratchet state record missing wrapped blob');
            return null;
        }

        const plaintextBytes = await this._unwrapSecret(record.wrappedState, record.wrapIv);
        const obj = JSON.parse(CryptoPrimitivesService.decodeUTF8(plaintextBytes));
        return this.deserializeRatchetState(obj);
    },

    /**
     * Delete the persisted ratchet state for a conversation.
     * @param {number|string} conversationId
     */
    async deleteRatchetState(conversationId) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('ratchet_states', 'readwrite');
            const store = tx.objectStore('ratchet_states');
            const request = store.delete(String(conversationId));
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },

    // -------- Skipped message keys (bounded MKSKIPPED store) --------

    /**
     * Count persisted skipped keys for a conversation (for the MAX_SKIP bound).
     * @private
     */
    _countSkippedMessageKeys(conversationId) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('skipped_message_keys', 'readonly');
            const index = tx.objectStore('skipped_message_keys').index('conversationId');
            const request = index.count(IDBKeyRange.only(String(conversationId)));
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    },

    /**
     * Persist a single skipped/out-of-order message key, wrapped at rest.
     * Enforces a MAX_SKIPPED_KEYS_PER_CONVERSATION bound (fail closed): if the
     * conversation is already at the cap and this (ratchetPub,msgNum) is new, the
     * write is REFUSED with a typed error rather than silently overwriting — the
     * caller (S6) decides how to surface it, mirroring the ratchet's MAX_SKIP throw.
     *
     * @param {number|string} conversationId
     * @param {string} ratchetPub - base64 sender ratchet public key (header.dh)
     * @param {number} msgNum - message number within that chain (header.n)
     * @param {Uint8Array} messageKey - the 32-byte skipped message key
     */
    async putSkippedMessageKey(conversationId, ratchetPub, msgNum, messageKey) {
        this._ensureInitialized();

        const convId = String(conversationId);
        const msgN = msgNum | 0;

        const existing = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('skipped_message_keys', 'readonly');
            const store = tx.objectStore('skipped_message_keys');
            const request = store.get([convId, ratchetPub, msgN]);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });

        if (!existing) {
            const count = await this._countSkippedMessageKeys(convId);
            if (count >= this.MAX_SKIPPED_KEYS_PER_CONVERSATION) {
                const err = new Error(
                    `[KeyStorageService] Skipped-key bound exceeded for conversation (max ${this.MAX_SKIPPED_KEYS_PER_CONVERSATION})`
                );
                err.code = 'MAX_SKIP_EXCEEDED';
                throw err;
            }
        }

        const { wrapped, iv } = await this._wrapSecret(messageKey);
        const record = {
            conversationId: convId,
            ratchetPub,
            msgNum: msgN,
            wrappedKey: wrapped,
            wrapIv: iv,
            createdAt: new Date().toISOString()
        };

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('skipped_message_keys', 'readwrite');
            const store = tx.objectStore('skipped_message_keys');
            const request = store.put(record);
            request.onsuccess = () => resolve();
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to put skipped message key:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Load + unwrap a single skipped message key.
     * @param {number|string} conversationId
     * @param {string} ratchetPub - base64 sender ratchet public key
     * @param {number} msgNum
     * @returns {Promise<Uint8Array|null>} the 32-byte message key, or null
     */
    async getSkippedMessageKey(conversationId, ratchetPub, msgNum) {
        this._ensureInitialized();

        const record = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('skipped_message_keys', 'readonly');
            const store = tx.objectStore('skipped_message_keys');
            const request = store.get([String(conversationId), ratchetPub, msgNum | 0]);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });

        if (!record || !record.wrappedKey || !record.wrapIv) {
            return null;
        }
        return await this._unwrapSecret(record.wrappedKey, record.wrapIv);
    },

    /**
     * Delete a single skipped message key (consume-once: after the out-of-order
     * message arrives and is decrypted, its key is removed).
     * @param {number|string} conversationId
     * @param {string} ratchetPub
     * @param {number} msgNum
     */
    async deleteSkippedMessageKey(conversationId, ratchetPub, msgNum) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('skipped_message_keys', 'readwrite');
            const store = tx.objectStore('skipped_message_keys');
            const request = store.delete([String(conversationId), ratchetPub, msgNum | 0]);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },

    // -------- Decrypted-message-key archive (§5, the load-bearing piece) --------

    /**
     * Archive the per-message key actually used to decrypt a message, keyed by
     * message id, wrapped at rest. This is the §5 reconciliation: getMessages
     * re-renders FULL history by ARCHIVE LOOKUP here (getDecryptedMessageKey),
     * never by replaying the advancing live ratchet — which is order-independent
     * and parallel-safe, so the existing Promise.all newest-first batch path keeps
     * working unchanged. The first mint happens on the realtime single-message
     * path (in ratchet order) at S6; this is the storage primitive it calls.
     *
     * @param {string} messageId - the message's id (archive key)
     * @param {Uint8Array} messageKey - the 32-byte key used to decrypt it
     * @param {number|string} [conversationId] - for bulk eviction on conversation delete
     */
    async putDecryptedMessageKey(messageId, messageKey, conversationId) {
        this._ensureInitialized();

        const { wrapped, iv } = await this._wrapSecret(messageKey);
        const record = {
            messageId: String(messageId),
            conversationId: conversationId !== undefined && conversationId !== null
                ? String(conversationId) : null,
            wrappedKey: wrapped,
            wrapIv: iv,
            createdAt: new Date().toISOString()
        };

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('decrypted_message_keys', 'readwrite');
            const store = tx.objectStore('decrypted_message_keys');
            const request = store.put(record);
            request.onsuccess = () => resolve();
            request.onerror = () => {
                console.error('[KeyStorageService] Failed to archive message key:', request.error);
                reject(request.error);
            };
        });
    },

    /**
     * Look up + unwrap the archived key for a message id (the history re-render
     * path). Returns null on a miss (a brand-new realtime message that must go
     * through the live ratchet instead, at S6).
     * @param {string} messageId
     * @returns {Promise<Uint8Array|null>} the 32-byte message key, or null
     */
    async getDecryptedMessageKey(messageId) {
        this._ensureInitialized();

        const record = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('decrypted_message_keys', 'readonly');
            const store = tx.objectStore('decrypted_message_keys');
            const request = store.get(String(messageId));
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });

        if (!record || !record.wrappedKey || !record.wrapIv) {
            return null;
        }
        return await this._unwrapSecret(record.wrappedKey, record.wrapIv);
    },

    /**
     * Delete an archived message key (e.g. message deleted).
     * @param {string} messageId
     */
    async deleteDecryptedMessageKey(messageId) {
        this._ensureInitialized();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('decrypted_message_keys', 'readwrite');
            const store = tx.objectStore('decrypted_message_keys');
            const request = store.delete(String(messageId));
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },

    // ==================== Prekey Secrets (S5, X3DH §2) ====================
    //
    // SPK + OPK SECRET keypairs, WRAPPED at rest with the SM-02 wrap key. Only the
    // PUBLIC material is published to the server; these never leave the device in
    // the clear. The responder reads these by id when an inbound X3DH bootstrap
    // names a spk_id / opk_id.

    /**
     * Persist a prekey keypair secret (wrapped) keyed by (userId, kind, keyId).
     * @private
     * @param {string} userId
     * @param {'spk'|'opk'} kind
     * @param {number} keyId
     * @param {{publicKey:Uint8Array, secretKey:Uint8Array}} keyPair
     */
    async _putPrekeySecret(userId, kind, keyId, keyPair) {
        this._ensureInitialized();
        // Wrap publicKey||secretKey as one blob; both are X25519 32-byte halves.
        const pub = keyPair.publicKey;
        const sec = keyPair.secretKey;
        const joined = new Uint8Array(pub.length + sec.length);
        joined.set(pub, 0);
        joined.set(sec, pub.length);
        const { wrapped, iv } = await this._wrapSecret(joined);
        const record = {
            userId, kind, keyId: keyId | 0,
            pubLen: pub.length,
            wrappedKeyPair: wrapped,
            wrapIv: iv,
            createdAt: new Date().toISOString()
        };
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('prekey_secrets', 'readwrite');
            const store = tx.objectStore('prekey_secrets');
            const request = store.put(record);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },

    /**
     * Load + unwrap a prekey keypair secret.
     * @private
     * @returns {Promise<{publicKey:Uint8Array, secretKey:Uint8Array}|null>}
     */
    async _getPrekeySecret(userId, kind, keyId) {
        this._ensureInitialized();
        const record = await new Promise((resolve, reject) => {
            const tx = this.db.transaction('prekey_secrets', 'readonly');
            const store = tx.objectStore('prekey_secrets');
            const request = store.get([userId, kind, keyId | 0]);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });
        if (!record || !record.wrappedKeyPair || !record.wrapIv) {
            return null;
        }
        const joined = await this._unwrapSecret(record.wrappedKeyPair, record.wrapIv);
        const pubLen = record.pubLen || 32;
        return {
            publicKey: joined.slice(0, pubLen),
            secretKey: joined.slice(pubLen)
        };
    },

    /** Persist the user's signed-prekey secret keyed by spkId. */
    async putSignedPrekey(userId, spkId, keyPair) {
        return this._putPrekeySecret(userId, 'spk', spkId, keyPair);
    },

    /** Load the user's signed-prekey secret by spkId (or null). */
    async getSignedPrekey(userId, spkId) {
        return this._getPrekeySecret(userId, 'spk', spkId);
    },

    /**
     * The id of the most-recently-stored signed prekey for the user, or null.
     * (Used to avoid re-minting an SPK on every login.)
     */
    async getCurrentSignedPrekeyId(userId) {
        this._ensureInitialized();
        const rows = await this._getPrekeySecretsByKind(userId, 'spk');
        if (!rows.length) return null;
        return rows.reduce((max, r) => (r.keyId > max ? r.keyId : max), rows[0].keyId);
    },

    /** Persist a one-time-prekey secret keyed by keyId. */
    async putOneTimePrekey(userId, keyId, keyPair) {
        return this._putPrekeySecret(userId, 'opk', keyId, keyPair);
    },

    /** Load a one-time-prekey secret by keyId (or null). */
    async getOneTimePrekey(userId, keyId) {
        return this._getPrekeySecret(userId, 'opk', keyId);
    },

    /** Delete a one-time-prekey secret (consume-once after a session bootstrap). */
    async deleteOneTimePrekey(userId, keyId) {
        this._ensureInitialized();
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('prekey_secrets', 'readwrite');
            const store = tx.objectStore('prekey_secrets');
            const request = store.delete([userId, 'opk', keyId | 0]);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },

    /** The current max OPK keyId for the user (0 if none) — for id assignment. */
    async getMaxOneTimePrekeyId(userId) {
        const rows = await this._getPrekeySecretsByKind(userId, 'opk');
        if (!rows.length) return 0;
        return rows.reduce((max, r) => (r.keyId > max ? r.keyId : max), 0);
    },

    /**
     * All prekey-secret records of a given kind for a user (raw records).
     * @private
     */
    async _getPrekeySecretsByKind(userId, kind) {
        this._ensureInitialized();
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('prekey_secrets', 'readonly');
            const index = tx.objectStore('prekey_secrets').index('userKind');
            const request = index.getAll([userId, kind]);
            request.onsuccess = () => resolve(request.result || []);
            request.onerror = () => reject(request.error);
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

        // S4: also wipe the ratchet-persistence stores (still preserving
        // wrap_keys — the per-profile wrap key is reused across re-init/restore).
        const stores = [
            'identity_keys', 'session_keys', 'historical_keys', 'pinned_keys', 'recv_counters',
            'ratchet_states', 'skipped_message_keys', 'decrypted_message_keys',
            'prekey_secrets'
        ];

        for (const storeName of stores) {
            // Guard: tolerate a DB that predates a store (e.g. opened at an older
            // version) so clearAll never throws on a missing object store.
            if (!this.db.objectStoreNames.contains(storeName)) {
                continue;
            }
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
