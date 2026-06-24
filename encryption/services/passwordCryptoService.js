/**
 * Password Crypto Service
 *
 * Handles password-based encryption using Web Crypto API.
 * Used for:
 * - Encrypting identity key backups with user password
 * - Encrypting recovery keys
 *
 * Algorithms:
 * - Key Derivation: PBKDF2-SHA256 (600,000 iterations - OWASP 2023)
 * - Encryption: AES-256-GCM
 */

const PasswordCryptoService = {
    /**
     * Configuration (set during initialize)
     */
    _config: null,

    /**
     * Initialize the service
     * @param {Object} config - Encryption config object
     */
    initialize(config) {
        this._config = config;
        console.log('[PasswordCryptoService] Initialized');
    },

    /**
     * Get PBKDF2 iterations from config
     * @private
     * @returns {number}
     */
    _getIterations() {
        return this._config?.crypto?.pbkdf2?.iterations || 600000;
    },

    /**
     * Get key length from config
     * @private
     * @returns {number} Key length in bits
     */
    _getKeyLength() {
        return this._config?.crypto?.pbkdf2?.keyLength || 256;
    },

    /**
     * Derive an encryption key from a password
     * @param {string} password - User password
     * @param {Uint8Array} salt - Salt (should be random, stored with ciphertext)
     * @returns {Promise<CryptoKey>} AES-GCM key
     */
    async deriveKeyFromPassword(password, salt) {
        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);

        // Import password as key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBytes,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Derive AES key using PBKDF2
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this._getIterations(),
                hash: 'SHA-256'
            },
            keyMaterial,
            {
                name: 'AES-GCM',
                length: this._getKeyLength()
            },
            false,
            ['encrypt', 'decrypt']
        );

        return key;
    },

    /**
     * Encrypt data with a password
     * @param {Uint8Array} data - Data to encrypt
     * @param {string} password - User password
     * @returns {Promise<Object>} { ciphertext: Uint8Array, salt: Uint8Array, iv: Uint8Array }
     */
    async encryptWithPassword(data, password) {
        // Generate random salt and IV
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM

        // Derive key from password
        const key = await this.deriveKeyFromPassword(password, salt);

        // Encrypt with AES-GCM
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            data
        );

        return {
            ciphertext: new Uint8Array(ciphertext),
            salt: salt,
            iv: iv
        };
    },

    /**
     * Decrypt data with a password
     * @param {Uint8Array} ciphertext - Encrypted data
     * @param {string} password - User password
     * @param {Uint8Array} salt - Salt used during encryption
     * @param {Uint8Array} iv - IV used during encryption
     * @returns {Promise<Uint8Array>} Decrypted data
     * @throws {Error} If decryption fails (wrong password or tampered data)
     */
    async decryptWithPassword(ciphertext, password, salt, iv) {
        // Derive key from password
        const key = await this.deriveKeyFromPassword(password, salt);

        try {
            // Decrypt with AES-GCM
            const plaintext = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                ciphertext
            );

            return new Uint8Array(plaintext);
        } catch (error) {
            throw new Error('Decryption failed - incorrect password or corrupted data');
        }
    },

    /**
     * Encrypt data and return base64-encoded strings
     * @param {Uint8Array} data - Data to encrypt
     * @param {string} password - User password
     * @returns {Promise<Object>} { encryptedData: string, salt: string, iv: string }
     */
    async encryptToBase64(data, password) {
        const result = await this.encryptWithPassword(data, password);

        return {
            encryptedData: this._arrayToBase64(result.ciphertext),
            salt: this._arrayToBase64(result.salt),
            iv: this._arrayToBase64(result.iv)
        };
    },

    /**
     * Decrypt base64-encoded data
     * @param {string} encryptedDataB64 - Base64-encoded ciphertext
     * @param {string} password - User password
     * @param {string} saltB64 - Base64-encoded salt
     * @param {string} ivB64 - Base64-encoded IV
     * @returns {Promise<Uint8Array>} Decrypted data
     */
    async decryptFromBase64(encryptedDataB64, password, saltB64, ivB64) {
        const ciphertext = this._base64ToArray(encryptedDataB64);
        const salt = this._base64ToArray(saltB64);
        const iv = this._base64ToArray(ivB64);

        return await this.decryptWithPassword(ciphertext, password, salt, iv);
    },

    /**
     * Generate a random recovery key (256-bit)
     * @returns {string} Base64-encoded recovery key
     */
    // ------------------------------------------------------------------------
    // TESTING VALUE (20 bytes / 8 elements). MUST be 32 before production/pentest
    // — see prod-readiness guard.
    // ------------------------------------------------------------------------
    // Recovery key shortened to 8 display groups (20 bytes / 160-bit) so it is
    // easier to type during multi-device testing. formatRecoveryKey groups Base32
    // by 4 chars, so 20 bytes -> 32 chars -> 8 groups ("8 elements"). For
    // PRODUCTION set this back to 32 (full 256-bit) — a one-line revert that is
    // GATED by encryption/tests/prod_readiness_check.js (run before release; it
    // is EXPECTED to fail until this is 32 and is intentionally NOT part of the
    // normal S0-S13 dev suite). See SECURITY_AUDIT.md §5 and KNOWN_ACCEPTED_RISKS.md.
    RECOVERY_KEY_BYTES: 20,

    generateRecoveryKey() {
        const key = crypto.getRandomValues(new Uint8Array(this.RECOVERY_KEY_BYTES));
        return this._arrayToBase64(key);
    },

    /**
     * Format a recovery key for display using proper RFC 4648 Base32 encoding
     * This preserves full entropy by processing bits correctly (5 bits per character)
     * @param {string} recoveryKeyB64 - Base64 recovery key
     * @returns {string} Formatted key (e.g., "ABCD-EFGH-IJKL-...")
     */
    formatRecoveryKey(recoveryKeyB64) {
        const bytes = this._base64ToArray(recoveryKeyB64);
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // RFC 4648 Base32

        // Proper Base32 encoding - processes 5 bits at a time
        // 8 bytes input -> 5 bits * 8 = 40 bits -> 8 characters output
        let result = '';
        let buffer = 0;
        let bitsInBuffer = 0;

        for (let i = 0; i < bytes.length; i++) {
            // Add byte to buffer
            buffer = (buffer << 8) | bytes[i];
            bitsInBuffer += 8;

            // Extract 5-bit groups while we have enough bits
            while (bitsInBuffer >= 5) {
                bitsInBuffer -= 5;
                result += alphabet[(buffer >> bitsInBuffer) & 0x1f];
            }
        }

        // Handle remaining bits (if any) by padding with zeros
        if (bitsInBuffer > 0) {
            result += alphabet[(buffer << (5 - bitsInBuffer)) & 0x1f];
        }

        // Format as groups of 4 characters for readability
        return result.match(/.{1,4}/g).join('-');
    },

    /**
     * Parse a formatted recovery key back to Base64
     * Reverses the Base32 encoding to restore original bytes
     * @param {string} formattedKey - Recovery key with dashes (e.g., "ABCD-EFGH-...")
     * @returns {string} Base64-encoded recovery key
     */
    parseRecoveryKey(formattedKey) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const cleanKey = formattedKey.replace(/-/g, '').toUpperCase();

        // Proper Base32 decoding - extracts 5 bits per character
        let buffer = 0;
        let bitsInBuffer = 0;
        const bytes = [];

        for (let i = 0; i < cleanKey.length; i++) {
            const char = cleanKey[i];
            const value = alphabet.indexOf(char);

            if (value === -1) {
                throw new Error(`Invalid character in recovery key: ${char}`);
            }

            // Add 5 bits to buffer
            buffer = (buffer << 5) | value;
            bitsInBuffer += 5;

            // Extract bytes when we have 8+ bits
            if (bitsInBuffer >= 8) {
                bitsInBuffer -= 8;
                bytes.push((buffer >> bitsInBuffer) & 0xff);
            }
        }

        return this._arrayToBase64(new Uint8Array(bytes));
    },

    /**
     * Minimum account-password length.
     *
     * This password encrypts the at-rest identity-key backup
     * (PBKDF2-SHA256 600k + AES-256-GCM, see encryptToBase64 / KeyBackupService).
     * A weak password makes a leaked/at-rest backup offline-brute-forceable,
     * which is a total E2E break (SECURITY_AUDIT.md finding H-2). Raised from 8
     * to 12 as the load-bearing mitigation; this is the single source of truth
     * for the minimum length and is consumed by validatePasswordStrength /
     * enforcePasswordStrength.
     */
    MIN_PASSWORD_LENGTH: 12,

    /**
     * Number of distinct character classes (lower / upper / digit / symbol)
     * a password must contain to be considered strong.
     */
    MIN_CHARACTER_CLASSES: 3,

    /**
     * Validate password strength.
     *
     * Policy (H-2): a password is valid only if it is at least
     * MIN_PASSWORD_LENGTH characters AND draws on at least
     * MIN_CHARACTER_CLASSES of the four character classes
     * (lowercase, uppercase, digit, symbol).
     *
     * TODO (H-2 deeper hardening, not yet implemented): integrate a strength
     * estimator (e.g. zxcvbn) and a breached-password (k-anonymity / HIBP)
     * check so high-frequency-but-policy-passing passwords are also rejected.
     *
     * @param {string} password - Password to validate
     * @returns {Object} { valid: boolean, score: number, feedback: string[] }
     */
    validatePasswordStrength(password) {
        const feedback = [];
        let score = 0;

        password = typeof password === 'string' ? password : '';

        const minLength = this.MIN_PASSWORD_LENGTH;

        if (password.length >= minLength) score++;
        else feedback.push(`Password should be at least ${minLength} characters`);

        // Reward extra length for the strength score (does not gate validity).
        if (password.length >= minLength + 4) score++;

        let characterClasses = 0;

        if (/[a-z]/.test(password)) { score++; characterClasses++; }
        else feedback.push('Add lowercase letters');

        if (/[A-Z]/.test(password)) { score++; characterClasses++; }
        else feedback.push('Add uppercase letters');

        if (/[0-9]/.test(password)) { score++; characterClasses++; }
        else feedback.push('Add numbers');

        if (/[^a-zA-Z0-9]/.test(password)) { score++; characterClasses++; }
        else feedback.push('Add special characters');

        return {
            valid: password.length >= minLength && characterClasses >= this.MIN_CHARACTER_CLASSES,
            score: score,
            characterClasses: characterClasses,
            feedback: feedback
        };
    },

    /**
     * Enforce password strength requirements.
     *
     * This is the SINGLE SOURCE OF TRUTH for the account-password policy and
     * MUST be called before the password-encrypted identity backup is created
     * (signup) and whenever the account password changes (reset). Throws if the
     * password is too weak so the caller never derives a backup key from it.
     *
     * SECURITY_AUDIT.md finding H-2 / L-3 — deeper hardening still TODO. The
     * concrete MIGRATION PLAN below is intentionally NOT implemented here:
     * swapping the KDF is a larger, data-format-versioned change (it has to
     * dual-read existing PBKDF2 backups during rollout). This scaffold exists so
     * the plan is actionable and not forgotten. See deriveKeyFromPassword /
     * encryptToBase64 in this file (the KDF + seal sites the plan touches) and
     * KeyBackupService.createIdentityBackup (the consumer).
     *
     * ============================ MIGRATION PLAN (L-3) ======================
     * Goal: move the password-encrypted identity/recovery/session backups from
     * PBKDF2-SHA256(600k) to memory-hard Argon2id + a server-unknown pepper,
     * WITHOUT locking out users whose backups were minted under PBKDF2.
     *
     * 1. VERSIONED KDF FIELD (data format).
     *    - Add a `kdf_version` (SMALLINT) column to the backup tables
     *      (identity_key_backups + conversation_session_keys) and a matching
     *      `kdfVersion` field on every persisted blob written by KeyBackupService.
     *      kdf_version = 1  => legacy PBKDF2-SHA256(600k) + AES-256-GCM (today).
     *      kdf_version = 2  => Argon2id + AES-256-GCM (target).
     *    - Persist the Argon2id parameters per-row (memKiB, iterations/timeCost,
     *      parallelism, saltLen) alongside the salt so a future parameter bump is
     *      itself forward/backward compatible. NEVER infer params from version
     *      alone — store them.
     *
     * 2. ARGON2id PARAMS (starting point; tune to ~250-500ms on a low-end
     *    target device, then pin):
     *      - memory:      64 MiB  (m = 65536 KiB)  — the memory-hardness is the
     *                     point; do not drop below 19 MiB (OWASP floor).
     *      - iterations:  3 (timeCost)
     *      - parallelism: 1 (lanes) — WASM single-thread friendly.
     *      - hashLen:     32 bytes (AES-256 key) ; saltLen 16 bytes (random).
     *      Library: a vendored, SRI-pinned argon2 WASM build loaded the same way
     *      as TweetNaCl (CryptoLibraryLoader), with a startup KAT self-test
     *      (fail-closed) before use — mirror L-6's nacl hardening.
     *
     * 3. SERVER-UNKNOWN PEPPER.
     *    - Mix a high-entropy pepper that the server never stores into the KDF
     *      input (e.g. HKDF(password, salt) XOR pepper, or feed pepper as Argon2
     *      `secret`/associated data). Candidate pepper sources, in order:
     *        (a) the user's high-entropy recovery key (preferred once
     *            RECOVERY_KEY_BYTES is restored to 32 — see prod-readiness guard),
     *        (b) a device-held secret synced out-of-band via pairing.
     *      The pepper must be reconstructable on legitimate restore but absent
     *      from any single at-rest/leaked DB read, so a stolen DB alone cannot
     *      mount the offline brute force H-2 describes.
     *
     * 4. DUAL-READ DURING MIGRATION (no flag-day).
     *    - WRITE path: new/rotated backups are written at kdf_version = 2.
     *    - READ path (restoreFromPassword / restoreFromRecoveryKey /
     *      restoreSessionBackupKey): branch on the stored kdf_version —
     *        v1 -> deriveKeyFromPassword (existing PBKDF2) ;
     *        v2 -> deriveKeyFromPasswordArgon2id (new).
     *    - LAZY RE-ENCRYPT: on a successful v1 restore, transparently re-seal the
     *      recovered secret at v2 and upsert (opportunistic upgrade on next login;
     *      reuse the updatePassword re-mint path). No mass re-encryption required.
     *    - Keep v1 read support until telemetry shows ~0 remaining v1 rows, then
     *      schedule removal behind a deprecation window.
     *
     * 5. REGRESSION GATES (add to the S-suite when implemented):
     *    - a v1 blob still decrypts (back-compat) ; a v2 round-trips ; a v1 blob
     *      is upgraded to v2 after one successful restore ; a v2 blob does NOT
     *      decrypt without the pepper.
     * =======================================================================
     *
     * @param {string} password - Password to validate
     * @throws {Error} If password is too weak
     * @returns {Object} The validation result when the password is acceptable
     */
    enforcePasswordStrength(password) {
        const validation = this.validatePasswordStrength(password);

        if (!validation.valid) {
            const issues = validation.feedback.join('; ');
            throw new Error(`Password does not meet security requirements: ${issues}`);
        }

        return validation;
    },

    /**
     * Convert Uint8Array to base64
     * @private
     * @param {Uint8Array} array
     * @returns {string}
     */
    _arrayToBase64(array) {
        // Build the binary string in chunks. Calling
        // String.fromCharCode.apply(null, array) in one shot throws a RangeError
        // on large buffers (too many function arguments), so process a fixed-size
        // window at a time. The resulting string is byte-for-byte identical to the
        // single-call form, so btoa() produces the same Base64 as before.
        const CHUNK_SIZE = 8192; // 8KB per chunk
        let binary = '';
        for (let i = 0; i < array.length; i += CHUNK_SIZE) {
            const chunk = array.subarray(i, i + CHUNK_SIZE);
            binary += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binary);
    },

    /**
     * Convert base64 to Uint8Array
     * @private
     * @param {string} base64
     * @returns {Uint8Array}
     */
    _base64ToArray(base64) {
        const binary = atob(base64);
        const array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            array[i] = binary.charCodeAt(i);
        }
        return array;
    }
};

if (typeof window !== 'undefined') {
    window.PasswordCryptoService = PasswordCryptoService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = PasswordCryptoService;
}
