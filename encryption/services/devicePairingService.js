/**
 * Device Pairing Service — SECURE re-implementation
 *
 * Lets device 1 hand its E2E keys to device 2 via a one-time code, so the new
 * device can read all existing data without re-deriving anything.
 *
 * Why this is safe (the previous version was disabled for SM-06/16/31/47 — a
 * 6-digit code + unsalted SHA-256 + no rate limit + secret stored in clear):
 *   - HIGH-ENTROPY code: PAIRING_CODE_BYTES random bytes (default 80-bit), shown
 *     Base32-grouped. NOT a guessable PIN.
 *   - The transferred bundle (identity secret + session backup key) is wrapped with
 *     PBKDF2-SHA256 (600k, salted) + AES-256-GCM under the code BEFORE it touches the
 *     server — same protection as the password/recovery backups. The raw secret is
 *     never stored or transmitted in the clear.
 *   - The pairing row lives in `pairing_requests`, RLS-scoped to the owner, so only a
 *     caller already authenticated AS the user can fetch it (no anonymous exposure).
 *   - SINGLE-USE (deleted on success), short EXPIRY, and an attempt LIMIT (row is
 *     destroyed after MAX_ATTEMPTS) — so the code cannot be brute-forced.
 *
 * Falls back to the recovery-key / password restore flow when pairing isn't used.
 */

const DevicePairingService = {
    PAIRING_TABLE: 'pairing_requests',
    CODE_EXPIRY_MS: 5 * 60 * 1000, // 5 minutes
    MAX_ATTEMPTS: 5,
    // 10 bytes = 80-bit code -> 16 Base32 chars -> 4 display groups. Ephemeral +
    // rate-limited + expiring, so 80 bits is ample; raise for more margin.
    PAIRING_CODE_BYTES: 10,

    _db() {
        if (!window.DatabaseService) throw new Error('DatabaseService unavailable');
        return window.DatabaseService;
    },

    async _userId() {
        return await this._db()._getCurrentUserId();
    },

    /** Normalize a user-typed code to the canonical password (Base32 chars, no dashes). */
    _normalizeCode(code) {
        return String(code || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    },

    /**
     * DEVICE 1: create a one-time pairing request. Wraps {identity secret, session
     * backup key} under a fresh high-entropy code and stores the ciphertext.
     * @returns {Promise<{success:boolean, code:(string|null), expiresAt:(string|null), error?:string}>}
     */
    async createPairingRequest() {
        try {
            const db = this._db();
            const userId = await this._userId();
            if (!userId) return { success: false, code: null, expiresAt: null, error: 'Not signed in' };

            // Gather the keys the new device needs (identity secret + session backup key).
            const bundle = await window.KeyManagementService.exportPairingBundle();
            const bundleBytes = new TextEncoder().encode(JSON.stringify(bundle));

            // Fresh high-entropy code; the canonical (dash-free) form is the AES password.
            const codeBytes = crypto.getRandomValues(new Uint8Array(this.PAIRING_CODE_BYTES));
            const codeB64 = window.PasswordCryptoService._arrayToBase64(codeBytes);
            const displayCode = window.PasswordCryptoService.formatRecoveryKey(codeB64);
            const password = this._normalizeCode(displayCode);

            const enc = await window.PasswordCryptoService.encryptToBase64(bundleBytes, password);
            const expiresAt = new Date(Date.now() + this.CODE_EXPIRY_MS).toISOString();

            // One active request per user — clear any prior ones first.
            await db.queryDelete(this.PAIRING_TABLE, { user_id: userId });
            const ins = await db.queryInsert(this.PAIRING_TABLE, {
                user_id: userId,
                encrypted_data: enc.encryptedData,
                salt: enc.salt,
                iv: enc.iv,
                attempts: 0,
                expires_at: expiresAt
            });
            if (ins.error) return { success: false, code: null, expiresAt: null, error: 'Could not create pairing request' };

            return { success: true, code: displayCode, expiresAt };
        } catch (e) {
            console.error('[DevicePairingService] createPairingRequest failed:', e.message);
            return { success: false, code: null, expiresAt: null, error: 'Could not create pairing request' };
        }
    },

    /**
     * DEVICE 2: redeem a pairing code. Fetches the caller's own pending request,
     * decrypts the bundle with the code, installs the keys, and consumes the request.
     * Enforces expiry + attempt limit (fail-closed).
     * @param {string} inputCode
     * @returns {Promise<{success:boolean, error?:string}>}
     */
    async verifyPairingCode(inputCode) {
        try {
            const db = this._db();
            const userId = await this._userId();
            if (!userId) return { success: false, error: 'Not signed in' };

            const password = this._normalizeCode(inputCode);
            if (!password) return { success: false, error: 'Enter the pairing code' };

            const res = await db.querySelect(this.PAIRING_TABLE, {
                filter: { user_id: userId },
                order: [{ column: 'created_at', ascending: false }],
                limit: 1
            });
            const row = res.data && res.data[0];
            if (!row) return { success: false, error: 'No active pairing request — generate one on your other device' };

            // Expiry (fail-closed): destroy and refuse.
            if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
                await db.queryDelete(this.PAIRING_TABLE, { id: row.id });
                return { success: false, error: 'Pairing code expired — generate a new one' };
            }

            // Attempt limit (fail-closed): destroy after too many wrong tries.
            if ((row.attempts || 0) >= this.MAX_ATTEMPTS) {
                await db.queryDelete(this.PAIRING_TABLE, { id: row.id });
                return { success: false, error: 'Too many attempts — generate a new code' };
            }

            let bundleBytes;
            try {
                bundleBytes = await window.PasswordCryptoService.decryptFromBase64(
                    row.encrypted_data, password, row.salt, row.iv
                );
            } catch (_) {
                const attempts = (row.attempts || 0) + 1;
                if (attempts >= this.MAX_ATTEMPTS) {
                    await db.queryDelete(this.PAIRING_TABLE, { id: row.id });
                } else {
                    await db.queryUpdate(this.PAIRING_TABLE, row.id, { attempts });
                }
                return { success: false, error: 'Incorrect pairing code' };
            }

            const bundle = JSON.parse(new TextDecoder().decode(bundleBytes));
            await window.KeyManagementService.importPairingBundle(bundle);

            // Single-use: consume the request.
            await db.queryDelete(this.PAIRING_TABLE, { id: row.id });
            return { success: true };
        } catch (e) {
            console.error('[DevicePairingService] verifyPairingCode failed:', e.message);
            return { success: false, error: 'Pairing failed' };
        }
    },

    /** Delete the caller's own expired/pending pairing rows. */
    async cleanupExpiredRequests() {
        try {
            const userId = await this._userId();
            if (userId) await this._db().queryDelete(this.PAIRING_TABLE, { user_id: userId });
        } catch (_) { /* best effort */ }
    },

    /** Human-readable device label for UI (no secrets). */
    getDeviceName() {
        const ua = (typeof navigator !== 'undefined' && navigator.userAgent) ? navigator.userAgent : '';
        let browser = 'Unknown Browser';
        let os = 'Unknown OS';
        if (ua.includes('Edg')) browser = 'Edge';
        else if (ua.includes('Chrome')) browser = 'Chrome';
        else if (ua.includes('Firefox')) browser = 'Firefox';
        else if (ua.includes('Safari')) browser = 'Safari';
        if (ua.includes('Win')) os = 'Windows';
        else if (ua.includes('Mac')) os = 'macOS';
        else if (ua.includes('Android')) os = 'Android';
        else if (ua.includes('iPhone') || ua.includes('iPad') || ua.includes('iOS')) os = 'iOS';
        else if (ua.includes('Linux')) os = 'Linux';
        return `${browser} on ${os}`;
    }
};

// Make available globally (HTML references it).
window.DevicePairingService = DevicePairingService;
