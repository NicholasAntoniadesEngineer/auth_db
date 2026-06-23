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
    // TESTING: recovery key shortened to 8 display groups (20 bytes / 160-bit) so it
    // is easier to type during multi-device testing. formatRecoveryKey groups Base32
    // by 4 chars, so 20 bytes -> 32 chars -> 8 groups ("8 elements"). For PRODUCTION
    // set this back to 32 (full 256-bit). One-line revert.
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
     * Validate password strength
     * @param {string} password - Password to validate
     * @returns {Object} { valid: boolean, score: number, feedback: string[] }
     */
    validatePasswordStrength(password) {
        const feedback = [];
        let score = 0;

        if (password.length >= 8) score++;
        else feedback.push('Password should be at least 8 characters');

        if (password.length >= 12) score++;

        if (/[a-z]/.test(password)) score++;
        else feedback.push('Add lowercase letters');

        if (/[A-Z]/.test(password)) score++;
        else feedback.push('Add uppercase letters');

        if (/[0-9]/.test(password)) score++;
        else feedback.push('Add numbers');

        if (/[^a-zA-Z0-9]/.test(password)) score++;
        else feedback.push('Add special characters');

        return {
            valid: score >= 4 && password.length >= 8,
            score: score,
            feedback: feedback
        };
    },

    /**
     * Enforce password strength requirements
     * Throws an error if password does not meet minimum requirements
     * @param {string} password - Password to validate
     * @throws {Error} If password is too weak
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
        return btoa(String.fromCharCode.apply(null, array));
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
