/**
 * Key Derivation Service
 *
 * Implements HKDF (HMAC-based Key Derivation Function) as per RFC 5869.
 * Uses Web Crypto API for cryptographic operations.
 *
 * Key Derivation Hierarchy:
 * - Session Key: HKDF(sharedSecret, "SessionKey:{epoch}")
 * - Message Key: HKDF(sessionKey, "MessageKey:{epoch}:{counter}")
 * - Backup Key: HKDF(masterSecret, "BackupKey", userSalt)
 */

const KeyDerivationService = {
    /**
     * Configuration (set during initialize)
     */
    _config: null,

    /**
     * Initialize with configuration
     * @param {Object} config - Encryption config object
     */
    initialize(config) {
        this._config = config;
    },

    /**
     * Get the hash algorithm from config
     * @private
     * @returns {string} Hash algorithm name
     */
    _getHash() {
        return this._config?.crypto?.hkdf?.hash || 'SHA-256';
    },

    /**
     * Get the info prefix from config
     * @private
     * @returns {string} Info prefix
     */
    _getInfoPrefix() {
        return this._config?.crypto?.hkdf?.infoPrefix || 'MoneyTracker';
    },

    /**
     * Derive a session key from shared secret and epoch
     * @param {Uint8Array} sharedSecret - The ECDH shared secret
     * @param {number} epoch - The key epoch
     * @returns {Promise<Uint8Array>} 32-byte session key
     */
    async deriveSessionKey(sharedSecret, epoch) {
        const info = `${this._getInfoPrefix()}:SessionKey:${epoch}`;
        return await this._hkdf(sharedSecret, info, 32);
    },

    /**
     * Derive a message-specific key from session key
     * @param {Uint8Array} sessionKey - The session key
     * @param {number} epoch - The key epoch
     * @param {number} counter - The message counter
     * @returns {Promise<Uint8Array>} 32-byte message key
     */
    async deriveMessageKey(sessionKey, epoch, counter) {
        const info = `${this._getInfoPrefix()}:MessageKey:${epoch}:${counter}`;
        return await this._hkdf(sessionKey, info, 32);
    },

    /**
     * Derive a backup key from master secret and user salt
     * @param {Uint8Array} masterSecret - The master secret (identity secret key)
     * @param {Uint8Array} userSalt - User-specific salt
     * @returns {Promise<Uint8Array>} 32-byte backup key
     */
    async deriveBackupKey(masterSecret, userSalt) {
        const info = `${this._getInfoPrefix()}:BackupKey`;
        return await this._hkdf(masterSecret, info, 32, userSalt);
    },

    /**
     * Derive a device-specific key
     * @param {Uint8Array} masterSecret - The master secret
     * @param {string} deviceId - Device identifier
     * @returns {Promise<Uint8Array>} 32-byte device key
     */
    async deriveDeviceKey(masterSecret, deviceId) {
        const info = `${this._getInfoPrefix()}:DeviceKey:${deviceId}`;
        return await this._hkdf(masterSecret, info, 32);
    },

    /**
     * Perform HKDF key derivation using Web Crypto API
     * @private
     * @param {Uint8Array} keyMaterial - Input key material
     * @param {string} info - Context and application specific info
     * @param {number} length - Output key length in bytes
     * @param {Uint8Array|null} salt - Optional salt
     * @returns {Promise<Uint8Array>} Derived key
     */
    async _hkdf(keyMaterial, info, length, salt = null) {
        const hash = this._getHash();

        // Import the key material
        const baseKey = await crypto.subtle.importKey(
            'raw',
            keyMaterial,
            'HKDF',
            false,
            ['deriveBits']
        );

        // Determine effective salt
        // SECURITY: Never use all-zeros salt - derive context-specific salt if not provided
        let effectiveSalt;
        if (salt && salt.length > 0) {
            effectiveSalt = salt;
        } else {
            // Derive a deterministic but unique salt from the info string
            // This ensures different contexts get different salts
            effectiveSalt = await this._deriveContextSalt(info);
        }

        // Derive bits using HKDF
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: hash,
                salt: effectiveSalt,
                info: new TextEncoder().encode(info)
            },
            baseKey,
            length * 8 // Convert bytes to bits
        );

        return new Uint8Array(derivedBits);
    },

    /**
     * Derive a context-specific salt from an info string
     * Creates a deterministic but unique salt for each context
     * @private
     * @param {string} info - The context info string
     * @returns {Promise<Uint8Array>} 32-byte salt
     */
    async _deriveContextSalt(info) {
        const encoder = new TextEncoder();
        const saltInput = encoder.encode(`${this._getInfoPrefix()}:ContextSalt:${info}`);
        const hashBuffer = await crypto.subtle.digest('SHA-256', saltInput);
        return new Uint8Array(hashBuffer);
    },

    /**
     * Generate a random salt
     * @param {number} length - Salt length in bytes (default 32)
     * @returns {Uint8Array} Random salt
     */
    generateSalt(length = 32) {
        return crypto.getRandomValues(new Uint8Array(length));
    },

    /**
     * Convert a string to bytes for use as info
     * @param {string} str - String to convert
     * @returns {Uint8Array} UTF-8 bytes
     */
    stringToBytes(str) {
        return new TextEncoder().encode(str);
    },

    /**
     * Convert bytes to a hex string (for debugging)
     * @param {Uint8Array} bytes - Bytes to convert
     * @returns {string} Hex string
     */
    bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
};

if (typeof window !== 'undefined') {
    window.KeyDerivationService = KeyDerivationService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = KeyDerivationService;
}
