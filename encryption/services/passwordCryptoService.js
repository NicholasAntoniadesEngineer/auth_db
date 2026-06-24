/**
 * Password Crypto Service
 *
 * Handles password-based encryption using Web Crypto API.
 * Used for:
 * - Encrypting identity key backups with user password
 * - Encrypting recovery keys
 *
 * Algorithms:
 * - Key Derivation (WRITE, current): Argon2id (memory-hard, OWASP-recommended)
 * - Key Derivation (READ, legacy):   PBKDF2-SHA256 (600,000 iterations) — kept
 *                                     forever so OLD backups stay readable.
 * - Encryption: AES-256-GCM
 *
 * ===========================================================================
 * KDF MIGRATION (L-3 / CRYPTO_DEEP_REVIEW HIGH) — Argon2id at rest
 * ===========================================================================
 * The at-rest password/recovery/session-backup wrap key was historically
 * derived with PBKDF2-SHA256(600k). PBKDF2 is NOT memory-hard, so a leaked
 * at-rest backup is cheap to brute-force on GPUs/ASICs. This service now writes
 * new backups with Argon2id (memory-hard) while still READING legacy PBKDF2
 * backups verbatim, and transparently upgrades a legacy backup to Argon2id the
 * next time it is successfully unlocked.
 *
 * NO-LOCKOUT INVARIANT: the legacy PBKDF2 read path below is preserved EXACTLY
 * (same math, same defaults) and is selected whenever a stored envelope is
 * tagged `pbkdf2-sha256-600k` OR carries no kdf tag at all (a bare base64
 * salt). Breaking it would permanently lock out every existing user, so it is
 * never altered.
 *
 * VERSIONED ENVELOPE (no DB schema change required):
 *   The on-disk envelope is { encryptedData, salt, iv } (3 base64 strings,
 *   stored as 3 columns). To carry the KDF descriptor + Argon2id parameters
 *   WITHOUT adding columns, the `salt` field is made self-describing:
 *     - LEGACY  : `salt` is a bare base64 string (e.g. "Yhk2...="). No kdf tag
 *                 present => treated as 'pbkdf2-sha256-600k' (back-compat).
 *     - ARGON2id: `salt` is a JSON object string, e.g.
 *                 {"kdf":"argon2id-m65536-t3-p1","salt":"<b64>"}.
 *   A base64 string can never begin with '{', so the two forms are
 *   unambiguous: the reader simply checks whether the salt field parses as the
 *   tagged JSON envelope; if not, it is legacy PBKDF2. `encryptedData` and `iv`
 *   are unchanged (always bare base64) in both forms.
 *
 * Argon2id PARAMS (OWASP "Password Storage" minimums; see _getArgon2Params):
 *   memory m = 65536 KiB (64 MiB), iterations t = 3, parallelism p = 1,
 *   hashLength = 32 bytes (AES-256 key), salt = 16 random bytes.
 *   Rationale + browser timing tradeoff documented at _getArgon2Params.
 * ===========================================================================
 */

// ---------------------------------------------------------------------------
// Vendored Argon2id (hash-wasm 4.12.0, MIT). Single-file UMD with the WASM
// embedded as base64 — runs in BOTH the browser (window.hashwasm via <script>)
// and node (CommonJS require / vm host-realm load). See
// shared/vendor/hash-wasm/. We NEVER hand-roll Argon2id.
//
// Browser <script> include needed once per page that performs a backup
// wrap/unwrap (relative to the page, mirroring the nacl includes):
//     <script src="../../shared/vendor/hash-wasm/argon2.umd.min.js"></script>
// (exposes window.hashwasm.argon2id). No npm runtime dependency is added.
// ---------------------------------------------------------------------------

const PasswordCryptoService = {
    /**
     * Configuration (set during initialize)
     */
    _config: null,

    /**
     * Resolved hash-wasm handle (the object exposing .argon2id). Set lazily by
     * _getHashWasm() the first time Argon2id is needed; cached thereafter.
     * @private
     */
    _hashwasm: null,

    /**
     * Initialize the service
     * @param {Object} config - Encryption config object
     */
    initialize(config) {
        this._config = config;
        console.log('[PasswordCryptoService] Initialized');
    },

    /**
     * Allow a host (test harness, or a future explicit browser loader) to inject
     * the hash-wasm handle directly. Keeps node tests independent of <script>.
     * @param {Object} hashwasm - object exposing async argon2id(...)
     */
    setHashWasm(hashwasm) {
        this._hashwasm = hashwasm;
    },

    /**
     * Stable KDF descriptor tags.
     * @private
     */
    KDF_LEGACY_PBKDF2: 'pbkdf2-sha256-600k',

    /**
     * Argon2id parameters (OWASP "Password Storage Cheat Sheet" guidance).
     *
     * Chosen values: m = 65536 KiB (64 MiB), t = 3, p = 1, hashLength = 32.
     *
     * Why these:
     *   - OWASP floor for Argon2id is m >= 19 MiB, t >= 2, p = 1. We exceed the
     *     memory floor substantially (64 MiB) because memory-hardness is the
     *     entire point of moving off PBKDF2 — it is what makes a leaked at-rest
     *     backup expensive to brute-force on GPUs/ASICs.
     *   - p = 1 (single lane) is the WASM single-thread-friendly choice and is
     *     OWASP's recommended parallelism for this use.
     *
     * Browser timing tradeoff: 64 MiB / t=3 / p=1 runs in roughly ~0.3-0.6 s on
     * a typical 2020+ laptop and ~1-2 s on a low-end mobile device — acceptable
     * for an interactive unlock/backup operation that happens at most a few
     * times per session. If a deployment finds this too slow on its low-end
     * target it may LOWER memory toward (but never below) the 19 MiB OWASP floor
     * via config.crypto.argon2; the params are persisted IN the envelope, so any
     * future change stays forward/backward compatible (old blobs decode with the
     * params they were written with). NEVER drop below the OWASP floor.
     *
     * @private
     * @returns {{memorySize:number, iterations:number, parallelism:number, hashLength:number, saltLen:number}}
     */
    _getArgon2Params() {
        const a = this._config?.crypto?.argon2 || {};
        const OWASP_MIN_MEMORY_KIB = 19 * 1024; // 19 MiB floor
        const params = {
            memorySize: a.memorySize || 65536, // KiB (64 MiB)
            iterations: a.iterations || 3,
            parallelism: a.parallelism || 1,
            hashLength: a.hashLength || 32,     // bytes => AES-256 key
            saltLen: a.saltLen || 16            // bytes
        };
        // Fail-closed guard: never derive below the OWASP minimums.
        if (params.memorySize < OWASP_MIN_MEMORY_KIB) {
            throw new Error(
                `[PasswordCryptoService] Argon2id memory ${params.memorySize} KiB is below the ` +
                `OWASP floor (${OWASP_MIN_MEMORY_KIB} KiB / 19 MiB)`);
        }
        if (params.iterations < 2) {
            throw new Error('[PasswordCryptoService] Argon2id iterations must be >= 2 (OWASP floor)');
        }
        if (params.parallelism < 1) {
            throw new Error('[PasswordCryptoService] Argon2id parallelism must be >= 1');
        }
        return params;
    },

    /**
     * Build the kdf descriptor tag for a given Argon2id param set.
     * Format: argon2id-m<KiB>-t<iters>-p<par>  (e.g. argon2id-m65536-t3-p1)
     * @private
     */
    _argon2Tag(params) {
        return `argon2id-m${params.memorySize}-t${params.iterations}-p${params.parallelism}`;
    },

    /**
     * Parse an argon2id-m<KiB>-t<iters>-p<par> tag back to params (memory/iters/
     * parallelism). hashLength is fixed at 32 (the only length we ever write; an
     * AES-256 key) and is NOT encoded in the tag.
     * @private
     * @param {string} tag
     * @returns {{memorySize:number, iterations:number, parallelism:number, hashLength:number}|null}
     */
    _parseArgon2Tag(tag) {
        const m = /^argon2id-m(\d+)-t(\d+)-p(\d+)$/.exec(tag || '');
        if (!m) return null;
        return {
            memorySize: parseInt(m[1], 10),
            iterations: parseInt(m[2], 10),
            parallelism: parseInt(m[3], 10),
            hashLength: 32
        };
    },

    /**
     * Resolve the hash-wasm handle exposing argon2id, fail-closed if absent.
     *
     * Resolution order:
     *   1. an explicitly injected handle (setHashWasm — used by node tests),
     *   2. window.hashwasm (the vendored UMD loaded via <script> in the browser),
     *   3. a node `require` of the vendored UMD (server-side / tooling).
     *
     * @private
     * @returns {Object} object exposing async argon2id(...)
     */
    _getHashWasm() {
        if (this._hashwasm && typeof this._hashwasm.argon2id === 'function') {
            return this._hashwasm;
        }
        if (typeof window !== 'undefined' && window.hashwasm
            && typeof window.hashwasm.argon2id === 'function') {
            this._hashwasm = window.hashwasm;
            return this._hashwasm;
        }
        // Node fallback (tests / server tooling). Guarded so the browser bundle
        // never tries to require().
        if (typeof require !== 'undefined') {
            try {
                // eslint-disable-next-line global-require
                const hw = require('../../shared/vendor/hash-wasm/argon2.umd.min.js');
                if (hw && typeof hw.argon2id === 'function') {
                    this._hashwasm = hw;
                    return this._hashwasm;
                }
            } catch (e) { /* fall through to the hard error below */ }
        }
        throw new Error(
            '[PasswordCryptoService] Argon2id library (hash-wasm) is not available. ' +
            'In the browser, include ' +
            '<script src="../../shared/vendor/hash-wasm/argon2.umd.min.js"></script> ' +
            'before performing a backup, or call PasswordCryptoService.setHashWasm(...).');
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
     * Derive an encryption key from a password (LEGACY PBKDF2 — READ PATH).
     *
     * PRESERVED VERBATIM. This is the no-lockout read path for every backup
     * minted before the Argon2id migration. Its math (PBKDF2-SHA256, 600k iters,
     * 256-bit AES key) MUST NOT change, or existing users are locked out.
     *
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
     * Derive an encryption key from a password using Argon2id (CURRENT — WRITE
     * PATH, and the READ path for argon2id-tagged envelopes).
     *
     * Produces a raw 32-byte key via the vendored hash-wasm Argon2id, then
     * imports it as a non-extractable AES-256-GCM CryptoKey. The raw bytes are
     * zeroed after import.
     *
     * @param {string} password - User password
     * @param {Uint8Array} salt - Salt (random per backup, stored with ciphertext)
     * @param {{memorySize:number, iterations:number, parallelism:number, hashLength:number}} params
     * @returns {Promise<CryptoKey>} AES-GCM key
     */
    async deriveKeyFromPasswordArgon2id(password, salt, params) {
        const hashwasm = this._getHashWasm();
        // hash-wasm accepts password as a string or Uint8Array; pass the string
        // so it applies its own UTF-8 encoding (matches the KAT vectors).
        const raw = await hashwasm.argon2id({
            password: password,
            salt: salt,
            parallelism: params.parallelism,
            iterations: params.iterations,
            memorySize: params.memorySize,
            hashLength: params.hashLength,
            outputType: 'binary' // Uint8Array of length hashLength
        });

        try {
            const key = await crypto.subtle.importKey(
                'raw',
                raw,
                { name: 'AES-GCM', length: this._getKeyLength() },
                false,
                ['encrypt', 'decrypt']
            );
            return key;
        } finally {
            // Best-effort wipe of the raw key material.
            if (raw && raw.fill) raw.fill(0);
        }
    },

    /**
     * Encrypt data with a password
     * @param {Uint8Array} data - Data to encrypt
     * @param {string} password - User password
     * @returns {Promise<Object>} { ciphertext: Uint8Array, salt: Uint8Array, iv: Uint8Array }
     */
    async encryptWithPassword(data, password) {
        // WRITE PATH: always Argon2id (memory-hard) for new backups.
        const params = this._getArgon2Params();
        const salt = crypto.getRandomValues(new Uint8Array(params.saltLen));
        const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM

        const key = await this.deriveKeyFromPasswordArgon2id(password, salt, params);

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
            iv: iv,
            kdf: this._argon2Tag(params)
        };
    },

    /**
     * Decrypt data with a password, dispatching on the KDF descriptor.
     *
     * @param {Uint8Array} ciphertext - Encrypted data
     * @param {string} password - User password
     * @param {Uint8Array} salt - Salt used during encryption
     * @param {Uint8Array} iv - IV used during encryption
     * @param {string} [kdf] - KDF descriptor tag. Defaults to the LEGACY PBKDF2
     *        tag when omitted (back-compat: an untagged backup is PBKDF2-600k).
     * @returns {Promise<Uint8Array>} Decrypted data
     * @throws {Error} If decryption fails (wrong password or tampered data)
     */
    async decryptWithPassword(ciphertext, password, salt, iv, kdf) {
        const tag = kdf || this.KDF_LEGACY_PBKDF2;

        let key;
        if (tag === this.KDF_LEGACY_PBKDF2) {
            // LEGACY READ PATH — preserved verbatim. No-lockout invariant.
            key = await this.deriveKeyFromPassword(password, salt);
        } else {
            const params = this._parseArgon2Tag(tag);
            if (!params) {
                throw new Error(`Decryption failed - unknown KDF descriptor "${tag}"`);
            }
            key = await this.deriveKeyFromPasswordArgon2id(password, salt, params);
        }

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

    // ------------------------------------------------------------------------
    // Versioned envelope (salt field is self-describing). See the file header.
    //   LEGACY  : salt = bare base64 (no kdf tag) -> pbkdf2-sha256-600k
    //   ARGON2id: salt = {"kdf":"argon2id-m..-t..-p..","salt":"<b64>"}
    // A base64 string never starts with '{', so the forms are unambiguous.
    // ------------------------------------------------------------------------

    /**
     * Encode the salt field for storage given a kdf tag + raw salt bytes.
     * @private
     */
    _encodeSaltField(kdf, saltBytes) {
        const saltB64 = this._arrayToBase64(saltBytes);
        if (!kdf || kdf === this.KDF_LEGACY_PBKDF2) {
            // Legacy form: bare base64 (no behavioural change for PBKDF2 writes,
            // though the WRITE path no longer produces these).
            return saltB64;
        }
        return JSON.stringify({ kdf: kdf, salt: saltB64 });
    },

    /**
     * Decode a stored salt field into { kdf, salt:Uint8Array }.
     * An untagged (bare base64) value decodes to the LEGACY PBKDF2 tag.
     * @private
     */
    _decodeSaltField(saltField) {
        if (typeof saltField === 'string'
            && saltField.length > 0
            && saltField.charAt(0) === '{') {
            let parsed;
            try {
                parsed = JSON.parse(saltField);
            } catch (e) {
                // Malformed tagged envelope — fail closed rather than silently
                // mis-reading it as a legacy salt.
                throw new Error('Corrupted backup salt envelope (invalid JSON)');
            }
            if (!parsed || typeof parsed.kdf !== 'string' || typeof parsed.salt !== 'string') {
                throw new Error('Corrupted backup salt envelope (missing kdf/salt)');
            }
            return { kdf: parsed.kdf, salt: this._base64ToArray(parsed.salt) };
        }
        // Legacy / untagged: bare base64 salt -> PBKDF2-600k.
        return { kdf: this.KDF_LEGACY_PBKDF2, salt: this._base64ToArray(saltField) };
    },

    /**
     * Encrypt data and return base64-encoded strings (WRITE path: Argon2id).
     *
     * The returned `salt` is the SELF-DESCRIBING envelope (tagged JSON for
     * Argon2id). `encryptedData` and `iv` are bare base64 as before. The
     * returned object stays shape-compatible with callers/columns
     * (encryptedData / salt / iv); `kdf` is additionally surfaced for callers
     * that want to record/inspect it.
     *
     * @param {Uint8Array} data - Data to encrypt
     * @param {string} password - User password
     * @returns {Promise<Object>} { encryptedData: string, salt: string, iv: string, kdf: string }
     */
    async encryptToBase64(data, password) {
        const result = await this.encryptWithPassword(data, password);

        return {
            encryptedData: this._arrayToBase64(result.ciphertext),
            salt: this._encodeSaltField(result.kdf, result.salt),
            iv: this._arrayToBase64(result.iv),
            kdf: result.kdf
        };
    },

    /**
     * Decrypt base64-encoded data (READ path: dispatch on the stored kdf tag).
     *
     * @param {string} encryptedDataB64 - Base64-encoded ciphertext
     * @param {string} password - User password
     * @param {string} saltField - Stored salt field (bare base64 = legacy
     *        PBKDF2, or the tagged JSON envelope = Argon2id)
     * @param {string} ivB64 - Base64-encoded IV
     * @returns {Promise<Uint8Array>} Decrypted data
     */
    async decryptFromBase64(encryptedDataB64, password, saltField, ivB64) {
        const ciphertext = this._base64ToArray(encryptedDataB64);
        const { kdf, salt } = this._decodeSaltField(saltField);
        const iv = this._base64ToArray(ivB64);

        return await this.decryptWithPassword(ciphertext, password, salt, iv, kdf);
    },

    /**
     * Inspect a stored salt field and report which KDF it was minted with,
     * WITHOUT attempting to decrypt. Used by the transparent-upgrade path to
     * decide whether a successfully-unlocked backup needs re-wrapping.
     * @param {string} saltField - Stored salt field
     * @returns {string} the kdf descriptor tag
     */
    kdfOf(saltField) {
        return this._decodeSaltField(saltField).kdf;
    },

    /**
     * True when a stored salt field is a LEGACY (PBKDF2) backup that should be
     * transparently upgraded to Argon2id on next successful unlock.
     * @param {string} saltField - Stored salt field
     * @returns {boolean}
     */
    isLegacyBackup(saltField) {
        return this.kdfOf(saltField) === this.KDF_LEGACY_PBKDF2;
    },

    /**
     * Generate a random recovery key (256-bit)
     * @returns {string} Base64-encoded recovery key
     */
    // ------------------------------------------------------------------------
    // TESTING VALUE (20 bytes / 8 elements). MUST be 32 before production/pentest
    // — see prod-readiness guard.
    // ------------------------------------------------------------------------
    // Recovery key at the FULL 32 bytes (256-bit) for production / external
    // pentest. formatRecoveryKey groups Base32 by 4 chars (52 chars -> 13 groups).
    // NOTE: during multi-device testing this was temporarily 20 bytes / 160-bit
    // for easier typing; flipped to 32 before the pentest (2026-06-24). The flip
    // is GATED by encryption/tests/prod_readiness_check.js, which now PASSES this
    // check. See SECURITY_AUDIT.md §5 and KNOWN_ACCEPTED_RISKS.md.
    RECOVERY_KEY_BYTES: 32,

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
     * SECURITY_AUDIT.md finding H-2 / L-3.
     *
     * STATUS (2026-06-24): the KDF half of this plan is IMPLEMENTED. New backups
     * WRITE with memory-hard Argon2id; legacy PBKDF2 backups stay readable
     * forever and are transparently re-wrapped to Argon2id on next unlock. See
     * the "KDF MIGRATION (L-3)" header at the top of this file and
     * deriveKeyFromPasswordArgon2id / encryptToBase64 / decryptFromBase64 here,
     * plus KeyBackupService._maybeUpgradeLegacyBackup (the upgrade consumer) and
     * encryption/tests/a18_argon2id_kdf.test.js (the gate).
     *
     * The original plan below is kept VERBATIM for history. Differences from
     * what shipped: (1) the kdf descriptor is carried in a self-describing SALT
     * envelope rather than a separate `kdf_version` column (no DB schema change);
     * (2) the server-unknown PEPPER (step 3) is NOT yet implemented and remains a
     * follow-up (Argon2id memory-hardness is the shipped control).
     *
     * ===================== ORIGINAL MIGRATION PLAN (L-3) ====================
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
