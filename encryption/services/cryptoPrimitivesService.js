/**
 * Crypto Primitives Service
 *
 * Core cryptographic operations using TweetNaCl.js
 *
 * Algorithms:
 * - Key Generation: X25519 (Curve25519)
 * - Key Agreement: ECDH (Elliptic Curve Diffie-Hellman)
 * - Raw DH: X25519 scalar multiplication (for ratchet / X3DH) -- see dhRaw()
 * - Signatures: Ed25519 (for signed prekeys) -- see signKeyPair/signDetached/verifyDetached()
 * - Encryption: XSalsa20-Poly1305 (authenticated encryption)
 * - Hashing: SHA-512 (for safety numbers)
 *
 * SEEDABLE RNG SEAM (S0):
 *   All randomness used by ephemeral key generation and the 24-byte secretbox
 *   nonce is routed through a single module-level source so that tests can
 *   inject a deterministic generator (frozen-seed gates for FS/PCS proofs).
 *   Production default is crypto-secure (nacl.randomBytes). Override only in
 *   tests via setRandomBytesSource()/resetRandomBytesSource().
 */

// Module-level, overridable random-bytes source. `null` => use the secure
// default (nacl.randomBytes). A test may set this to a deterministic generator.
let _randomBytesSource = null;

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
     * Generate a new X25519 key pair.
     *
     * Routed through the seedable RNG seam (randomBytes -> keyPairFromSecretKey)
     * rather than nacl.box.keyPair(), so that ephemeral ratchet keys are
     * deterministic under an injected RNG source in tests. X25519 clamps the
     * scalar internally, so any 32 random bytes are a valid secret key.
     *
     * @returns {Object} { publicKey: Uint8Array, secretKey: Uint8Array }
     */
    generateKeyPair() {
        this._ensureInitialized();
        const secretKey = this.randomBytes(32);
        return this.nacl.box.keyPair.fromSecretKey(secretKey);
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
     * Generate random bytes.
     *
     * Routes through the seedable RNG seam: if a deterministic source has been
     * installed via setRandomBytesSource() it is used, otherwise the secure
     * default (nacl.randomBytes) is used. This is the single choke-point for ALL
     * randomness in the encryption stack (ephemeral keygen + secretbox nonces),
     * which is what makes the ratchet's FS/PCS test gates deterministic.
     *
     * @param {number} length - Number of bytes
     * @returns {Uint8Array} Random bytes (length `length`)
     */
    randomBytes(length) {
        if (_randomBytesSource) {
            const out = _randomBytesSource(length);
            if (!(out instanceof Uint8Array) || out.length !== length) {
                throw new Error(
                    `[CryptoPrimitivesService] Injected randomBytes source returned ` +
                    `${out && out.length} bytes, expected ${length}`
                );
            }
            return out;
        }
        this._ensureInitialized();
        return this.nacl.randomBytes(length);
    },

    /**
     * Install a deterministic random-bytes source (TEST ONLY).
     *
     * Production code must never call this. When set, every randomBytes() call
     * (and therefore every ephemeral keypair and every secretbox nonce that
     * goes through this service) becomes deterministic, enabling frozen-seed
     * test vectors and the forward-secrecy / PCS proof gates.
     *
     * @param {function(number): Uint8Array} fn - generator: length -> bytes
     */
    setRandomBytesSource(fn) {
        if (typeof fn !== 'function') {
            throw new Error('[CryptoPrimitivesService] setRandomBytesSource requires a function');
        }
        _randomBytesSource = fn;
    },

    /**
     * Restore the secure default random-bytes source (TEST ONLY).
     */
    resetRandomBytesSource() {
        _randomBytesSource = null;
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

    /**
     * Raw X25519 Diffie-Hellman (scalar multiplication).
     *
     * This is the bare DH the Double Ratchet / X3DH specs assume: the 32-byte
     * shared curve point with NO further keying applied. It is DISTINCT from
     * deriveSharedSecret() above, which uses nacl.box.before -- that variant
     * additionally runs HSalsa20 over the point (a keyed PRF), which is NOT the
     * spec's DH() output. The ratchet feeds dhRaw()'s result strictly as HKDF
     * IKM, so we must use the raw scalarMult here.
     *
     * @param {Uint8Array} ourSecretKey - Our 32-byte X25519 secret key
     * @param {Uint8Array} theirPublicKey - Their 32-byte X25519 public key
     * @returns {Uint8Array} 32-byte raw shared point (HKDF IKM only)
     */
    dhRaw(ourSecretKey, theirPublicKey) {
        this._ensureInitialized();
        return this.nacl.scalarMult(ourSecretKey, theirPublicKey);
    },

    // ==================== Ed25519 Signatures (signed prekeys) ====================
    //
    // A SEPARATE keypair from the X25519 box/identity key. The X25519 box key
    // can NOT sign; we never reuse it for signing. Used for X3DH signed prekeys.

    /**
     * Generate a new Ed25519 signing key pair.
     * @returns {Object} { publicKey: Uint8Array(32), secretKey: Uint8Array(64) }
     */
    signKeyPair() {
        this._ensureInitialized();
        // Route the 32-byte seed through the seedable RNG seam so signing keys
        // are deterministic under an injected RNG source in tests.
        const seed = this.randomBytes(32);
        return this.nacl.sign.keyPair.fromSeed(seed);
    },

    /**
     * Derive an Ed25519 signing key pair from a 32-byte seed (deterministic).
     * @param {Uint8Array} seed - 32-byte seed
     * @returns {Object} { publicKey: Uint8Array(32), secretKey: Uint8Array(64) }
     */
    signKeyPairFromSeed(seed) {
        this._ensureInitialized();
        return this.nacl.sign.keyPair.fromSeed(seed);
    },

    /**
     * Produce a detached Ed25519 signature over a message.
     * @param {Uint8Array} message - Bytes to sign
     * @param {Uint8Array} signingSecretKey - 64-byte Ed25519 secret key
     * @returns {Uint8Array} 64-byte detached signature
     */
    signDetached(message, signingSecretKey) {
        this._ensureInitialized();
        return this.nacl.sign.detached(message, signingSecretKey);
    },

    /**
     * Verify a detached Ed25519 signature (constant-time inside nacl).
     * @param {Uint8Array} message - Bytes that were signed
     * @param {Uint8Array} signature - 64-byte detached signature
     * @param {Uint8Array} signingPublicKey - 32-byte Ed25519 public key
     * @returns {boolean} True iff the signature is valid
     */
    verifyDetached(message, signature, signingPublicKey) {
        this._ensureInitialized();
        return this.nacl.sign.detached.verify(message, signature, signingPublicKey);
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

        // Route the 24-byte nonce through the seedable RNG seam (deterministic in tests).
        const nonce = this.randomBytes(24);
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

        // Route the 24-byte nonce through the seedable RNG seam (deterministic in tests).
        const nonce = this.randomBytes(24);
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
