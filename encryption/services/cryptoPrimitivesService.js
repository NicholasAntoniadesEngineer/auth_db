/**
 * Crypto Primitives Service
 *
 * Core cryptographic operations using TweetNaCl.js
 *
 * Algorithms:
 * - Key Generation: X25519 (Curve25519)
 * - Key Agreement: ECDH (Elliptic Curve Diffie-Hellman)
 * - Encryption: XSalsa20-Poly1305 (authenticated encryption)
 * - Hashing: SHA-512 (for safety numbers)
 */

const CryptoPrimitivesService = {
    /**
     * The nacl library instance
     */
    nacl: null,

    /**
     * Whether the service is initialized
     */
    initialized: false,

    /**
     * Configuration (set during initialize)
     */
    _config: null,

    /**
     * Initialize the service
     * @param {Object} config - Encryption config object
     */
    async initialize(config) {
        this._config = config;

        // Load the crypto library
        await CryptoLibraryLoader.load();
        this.nacl = CryptoLibraryLoader.getNacl();

        if (!this.nacl) {
            throw new Error('[CryptoPrimitivesService] Failed to load TweetNaCl library');
        }

        this.initialized = true;
        console.log('[CryptoPrimitivesService] Initialized');
    },

    /**
     * Ensure the service is initialized
     * @private
     */
    _ensureInitialized() {
        if (!this.initialized || !this.nacl) {
            throw new Error('[CryptoPrimitivesService] Service not initialized. Call initialize() first.');
        }
    },

    // ==================== Key Generation ====================

    /**
     * Generate a new X25519 key pair
     * @returns {Object} { publicKey: Uint8Array, secretKey: Uint8Array }
     */
    generateKeyPair() {
        this._ensureInitialized();
        return this.nacl.box.keyPair();
    },

    /**
     * Derive a key pair from an existing secret key
     * Uses nacl.box.keyPair.fromSecretKey to derive the matching public key
     * @param {Uint8Array} secretKey - 32-byte secret key
     * @returns {Object} { publicKey: Uint8Array, secretKey: Uint8Array }
     */
    keyPairFromSecretKey(secretKey) {
        this._ensureInitialized();
        return this.nacl.box.keyPair.fromSecretKey(secretKey);
    },

    /**
     * Generate random bytes
     * @param {number} length - Number of bytes
     * @returns {Uint8Array} Random bytes
     */
    randomBytes(length) {
        this._ensureInitialized();
        return this.nacl.randomBytes(length);
    },

    // ==================== Key Agreement ====================

    /**
     * Derive shared secret using ECDH
     * @param {Uint8Array} ourSecretKey - Our secret key
     * @param {Uint8Array} theirPublicKey - Their public key
     * @returns {Uint8Array} 32-byte shared secret
     */
    deriveSharedSecret(ourSecretKey, theirPublicKey) {
        this._ensureInitialized();
        return this.nacl.box.before(theirPublicKey, ourSecretKey);
    },

    // ==================== Authenticated Encryption ====================

    /**
     * Encrypt plaintext with authenticated encryption (XSalsa20-Poly1305)
     * @param {string} plaintext - The message to encrypt
     * @param {Uint8Array} key - 32-byte encryption key
     * @returns {Object} { ciphertext: string (base64), nonce: string (base64) }
     */
    encrypt(plaintext, key) {
        this._ensureInitialized();

        const nonce = this.nacl.randomBytes(24);
        const message = this.nacl.util.decodeUTF8(plaintext);
        const ciphertext = this.nacl.secretbox(message, nonce, key);

        return {
            ciphertext: this.nacl.util.encodeBase64(ciphertext),
            nonce: this.nacl.util.encodeBase64(nonce)
        };
    },

    /**
     * Decrypt ciphertext with authenticated encryption
     * @param {string} ciphertextB64 - Base64-encoded ciphertext
     * @param {string} nonceB64 - Base64-encoded nonce
     * @param {Uint8Array} key - 32-byte decryption key
     * @returns {string} Decrypted plaintext
     * @throws {Error} If decryption or authentication fails
     */
    decrypt(ciphertextB64, nonceB64, key) {
        this._ensureInitialized();

        const ciphertext = this.nacl.util.decodeBase64(ciphertextB64);
        const nonce = this.nacl.util.decodeBase64(nonceB64);
        const plaintext = this.nacl.secretbox.open(ciphertext, nonce, key);

        if (!plaintext) {
            throw new Error('Decryption failed - authentication check failed');
        }

        return this.nacl.util.encodeUTF8(plaintext);
    },

    /**
     * Encrypt with raw bytes input
     * @param {Uint8Array} message - The message bytes to encrypt
     * @param {Uint8Array} key - 32-byte encryption key
     * @returns {Object} { ciphertext: Uint8Array, nonce: Uint8Array }
     */
    encryptBytes(message, key) {
        this._ensureInitialized();

        const nonce = this.nacl.randomBytes(24);
        const ciphertext = this.nacl.secretbox(message, nonce, key);

        return { ciphertext, nonce };
    },

    /**
     * Decrypt with raw bytes output
     * @param {Uint8Array} ciphertext - The ciphertext bytes
     * @param {Uint8Array} nonce - The 24-byte nonce
     * @param {Uint8Array} key - 32-byte decryption key
     * @returns {Uint8Array} Decrypted message bytes
     * @throws {Error} If decryption or authentication fails
     */
    decryptBytes(ciphertext, nonce, key) {
        this._ensureInitialized();

        const plaintext = this.nacl.secretbox.open(ciphertext, nonce, key);

        if (!plaintext) {
            throw new Error('Decryption failed - authentication check failed');
        }

        return plaintext;
    },

    // ==================== Serialization ====================

    /**
     * Serialize a key to base64
     * @param {Uint8Array} key - Key bytes
     * @returns {string} Base64-encoded key
     */
    serializeKey(key) {
        this._ensureInitialized();
        return this.nacl.util.encodeBase64(key);
    },

    /**
     * Deserialize a key from base64
     * @param {string} b64 - Base64-encoded key
     * @returns {Uint8Array} Key bytes
     */
    deserializeKey(b64) {
        this._ensureInitialized();
        return this.nacl.util.decodeBase64(b64);
    },

    /**
     * Encode a string to bytes
     * @param {string} str - String to encode
     * @returns {Uint8Array} UTF-8 bytes
     */
    encodeUTF8(str) {
        this._ensureInitialized();
        return this.nacl.util.decodeUTF8(str);
    },

    /**
     * Decode bytes to string
     * @param {Uint8Array} bytes - UTF-8 bytes
     * @returns {string} Decoded string
     */
    decodeUTF8(bytes) {
        this._ensureInitialized();
        return this.nacl.util.encodeUTF8(bytes);
    },

    // ==================== Safety Numbers ====================

    /**
     * Generate a safety number from two public keys
     * Safety numbers allow users to verify they have the correct keys
     * @param {Uint8Array} publicKey1 - First public key
     * @param {Uint8Array} publicKey2 - Second public key
     * @returns {string} Formatted safety number (e.g., "12345 67890 12345...")
     */
    generateSafetyNumber(publicKey1, publicKey2) {
        this._ensureInitialized();

        // Sort keys for consistency (same result regardless of order)
        const key1B64 = this.serializeKey(publicKey1);
        const key2B64 = this.serializeKey(publicKey2);
        const sorted = [key1B64, key2B64].sort();

        // Combine sorted keys
        const combined = new Uint8Array([
            ...this.deserializeKey(sorted[0]),
            ...this.deserializeKey(sorted[1])
        ]);

        // Hash the combined keys
        const hash = this.nacl.hash(combined);

        // Get config for formatting
        const groups = this._config?.application?.safetyNumberGroups || 6;
        const digitsPerGroup = this._config?.application?.safetyNumberDigitsPerGroup || 5;
        const totalDigits = groups * digitsPerGroup;

        // Convert first bytes to decimal digits
        const digits = Array.from(hash.slice(0, totalDigits))
            .map(b => (b % 10).toString())
            .join('');

        // Format as groups
        const formatted = [];
        for (let i = 0; i < digits.length; i += digitsPerGroup) {
            formatted.push(digits.slice(i, i + digitsPerGroup));
        }

        return formatted.join(' ');
    },

    // ==================== Utilities ====================

    /**
     * Constant-time comparison of two byte arrays
     * @param {Uint8Array} a - First array
     * @param {Uint8Array} b - Second array
     * @returns {boolean} True if arrays are equal
     */
    constantTimeEqual(a, b) {
        this._ensureInitialized();
        return this.nacl.verify(a, b);
    },

    /**
     * Hash data using SHA-512
     * @param {Uint8Array} data - Data to hash
     * @returns {Uint8Array} 64-byte hash
     */
    hash(data) {
        this._ensureInitialized();
        return this.nacl.hash(data);
    },

    /**
     * Get a fingerprint of a public key (first 8 bytes of hash, hex encoded)
     * @param {Uint8Array} publicKey - Public key
     * @returns {string} 16-character hex fingerprint
     */
    getKeyFingerprint(publicKey) {
        this._ensureInitialized();
        const hash = this.nacl.hash(publicKey);
        return Array.from(hash.slice(0, 8))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
};

if (typeof window !== 'undefined') {
    window.CryptoPrimitivesService = CryptoPrimitivesService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoPrimitivesService;
}
