/**
 * A18 — Argon2id at-rest KDF migration (L-3 / CRYPTO_DEEP_REVIEW HIGH).
 *
 * NO-LOCKOUT-CRITICAL gate. Proves that:
 *   (a) Argon2id KAT — the vendored hash-wasm reproduces a known answer test
 *       vector exactly (the crypto is real, not hand-rolled / not subtly wrong).
 *   (b) New-backup round-trip — wrap with Argon2id, unwrap, identical bytes.
 *   (c) BACK-COMPAT — a backup wrapped with the LEGACY PBKDF2 path (simulated as
 *       it is actually stored: bare base64 salt, no kdf tag) STILL unwraps. This
 *       is the no-lockout invariant.
 *   (d) Wrong password fails closed on BOTH the Argon2id and the PBKDF2 paths.
 *   (e) The kdf descriptor is parsed/dispatched correctly (tag detection,
 *       legacy default for untagged, unknown-tag fail-closed, param parsing).
 *   (f) Transparent upgrade — restoreFromPassword on a stored LEGACY backup
 *       re-wraps it to Argon2id and persists; the upgraded blob still unwraps;
 *       a failed persist is non-fatal (the unlock still returns the key).
 *
 * Runs under node via the gate runner (hash-wasm runs in node and the browser).
 */

const H = require('./_harness.js');

// WebCrypto global for PBKDF2 / AES-GCM (the harness also sets this, but a18
// does not call loadServices(), so set it explicitly).
if (typeof global.crypto === 'undefined') {
    global.crypto = require('crypto').webcrypto;
}

const PCS = require('../services/passwordCryptoService.js');

// Load the vendored hash-wasm exactly the way the browser/node service does, and
// inject it (the service's own node-require fallback resolves the same file, but
// injecting makes the dependency explicit + lets us KAT it directly).
const hashwasm = require('../../shared/vendor/hash-wasm/argon2.umd.min.js');
PCS.setHashWasm(hashwasm);
PCS.initialize({}); // defaults: Argon2id m=65536,t=3,p=1

// KeyBackupService (used in gate (f)) references PasswordCryptoService as a
// browser-style global; expose it the way the other S-suite tests do.
global.PasswordCryptoService = PCS;

const enc = new TextEncoder();

// A strong password that passes the H-2 policy (>=12 chars, >=3 classes).
const PASSWORD = 'CorrectHorseBattery9!';
const WRONG_PASSWORD = 'WrongHorseBattery9!';

/**
 * Build a LEGACY PBKDF2 envelope EXACTLY as it is stored on disk for an old
 * backup: ciphertext via PBKDF2-SHA256(600k)+AES-256-GCM, and a BARE base64
 * salt (no kdf tag). This is what restoreFromPassword sees for a pre-migration
 * user. We deliberately go through the service's own preserved legacy derive so
 * the test exercises the real read path.
 */
async function makeLegacyEnvelope(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(32)); // legacy used 32B salt
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await PCS.deriveKeyFromPassword(password, salt); // PRESERVED PBKDF2 path
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return {
        encryptedData: PCS._arrayToBase64(new Uint8Array(ct)),
        salt: PCS._arrayToBase64(salt), // BARE base64 => untagged => PBKDF2 default
        iv: PCS._arrayToBase64(iv)
    };
}

(async () => {
    // =====================================================================
    await H.gate('A18 (a) Argon2id KAT — vendored hash-wasm matches known vectors', async () => {
        // hash-wasm's own published KATs (verified against the Argon2 C reference).
        const v1 = await hashwasm.argon2id({
            password: 'a', salt: enc.encode('abcdefgh'),
            parallelism: 1, iterations: 2, memorySize: 16, hashLength: 16,
            outputType: 'hex'
        });
        H.assertEqual(v1, 'f94aa50873d67fdd589d6774b87c0634', 'Argon2id KAT vector 1 (a/abcdefgh)');

        const v2 = await hashwasm.argon2id({
            password: 'abc', salt: enc.encode('1234567812345678'),
            parallelism: 1, iterations: 1, memorySize: 8, hashLength: 4,
            outputType: 'hex'
        });
        H.assertEqual(v2, 'ffde3f6a', 'Argon2id KAT vector 2 (abc/1234567812345678)');

        // Determinism: same inputs => same output (proves no hidden randomness).
        const v1b = await hashwasm.argon2id({
            password: 'a', salt: enc.encode('abcdefgh'),
            parallelism: 1, iterations: 2, memorySize: 16, hashLength: 16,
            outputType: 'hex'
        });
        H.assertEqual(v1b, v1, 'Argon2id is deterministic for fixed inputs');
    });

    // =====================================================================
    await H.gate('A18 (b) New-backup round-trip — Argon2id wrap/unwrap is identity', async () => {
        const secret = crypto.getRandomValues(new Uint8Array(32)); // identity secret key
        const env = await PCS.encryptToBase64(secret, PASSWORD);

        H.assertEqual(env.kdf, 'argon2id-m65536-t3-p1', 'WRITE path uses Argon2id with the chosen params');
        H.assert(env.salt.charAt(0) === '{', 'Argon2id salt field is the tagged JSON envelope');

        const back = await PCS.decryptFromBase64(env.encryptedData, PASSWORD, env.salt, env.iv);
        H.assertBytesEqual(back, secret, 'Argon2id round-trip returns identical key material');
    });

    // =====================================================================
    await H.gate('A18 (c) BACK-COMPAT — a LEGACY PBKDF2 backup still unwraps (no-lockout)', async () => {
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const legacy = await makeLegacyEnvelope(secret, PASSWORD);

        // Sanity: the simulated legacy envelope really is untagged/legacy.
        H.assert(legacy.salt.charAt(0) !== '{', 'legacy salt is bare base64 (untagged)');
        H.assertEqual(PCS.kdfOf(legacy.salt), PCS.KDF_LEGACY_PBKDF2,
            'untagged salt is classified as legacy PBKDF2');
        H.assert(PCS.isLegacyBackup(legacy.salt) === true, 'isLegacyBackup true for legacy salt');

        // The new reader MUST still decrypt the legacy blob.
        const back = await PCS.decryptFromBase64(legacy.encryptedData, PASSWORD, legacy.salt, legacy.iv);
        H.assertBytesEqual(back, secret, 'legacy PBKDF2 backup unwraps to identical key material');
    });

    // =====================================================================
    await H.gate('A18 (d) Wrong password fails closed on BOTH paths', async () => {
        const secret = crypto.getRandomValues(new Uint8Array(32));

        // Argon2id path
        const argonEnv = await PCS.encryptToBase64(secret, PASSWORD);
        let argonFailed = false;
        try {
            await PCS.decryptFromBase64(argonEnv.encryptedData, WRONG_PASSWORD, argonEnv.salt, argonEnv.iv);
        } catch (e) { argonFailed = true; }
        H.assert(argonFailed, 'Argon2id path rejects the wrong password (AEAD fail-closed)');

        // PBKDF2 (legacy) path
        const legacy = await makeLegacyEnvelope(secret, PASSWORD);
        let legacyFailed = false;
        try {
            await PCS.decryptFromBase64(legacy.encryptedData, WRONG_PASSWORD, legacy.salt, legacy.iv);
        } catch (e) { legacyFailed = true; }
        H.assert(legacyFailed, 'PBKDF2 path rejects the wrong password (AEAD fail-closed)');
    });

    // =====================================================================
    await H.gate('A18 (e) kdf descriptor is parsed/dispatched correctly', async () => {
        // Tag <-> params round-trip.
        const params = PCS._getArgon2Params();
        const tag = PCS._argon2Tag(params);
        H.assertEqual(tag, 'argon2id-m65536-t3-p1', 'tag encodes m/t/p');
        const parsed = PCS._parseArgon2Tag(tag);
        H.assertEqual(parsed.memorySize, 65536, 'tag parse: memory');
        H.assertEqual(parsed.iterations, 3, 'tag parse: iterations');
        H.assertEqual(parsed.parallelism, 1, 'tag parse: parallelism');
        H.assertEqual(parsed.hashLength, 32, 'tag parse: hashLength fixed at 32');

        // Untagged salt => legacy default.
        const bare = PCS._arrayToBase64(crypto.getRandomValues(new Uint8Array(32)));
        H.assertEqual(PCS.kdfOf(bare), PCS.KDF_LEGACY_PBKDF2, 'untagged => legacy PBKDF2 default');

        // Unknown / malformed tag fails closed (does NOT silently fall back to a
        // wrong KDF). decryptWithPassword is the dispatcher.
        let unknownThrew = false;
        try {
            await PCS.decryptWithPassword(
                new Uint8Array([0]), PASSWORD,
                new Uint8Array(16), new Uint8Array(12),
                'argon2id-BOGUS'
            );
        } catch (e) { unknownThrew = true; }
        H.assert(unknownThrew, 'unknown kdf descriptor fails closed');

        // A corrupted tagged envelope (JSON-looking but invalid) fails closed.
        let corruptThrew = false;
        try { PCS.kdfOf('{not valid json'); } catch (e) { corruptThrew = true; }
        H.assert(corruptThrew, 'corrupted tagged salt envelope fails closed');

        // _getArgon2Params enforces the OWASP floor (fail-closed on weak config).
        const weak = Object.create(PCS);
        weak._config = { crypto: { argon2: { memorySize: 1024 } } }; // 1 MiB << 19 MiB
        let floorThrew = false;
        try { weak._getArgon2Params(); } catch (e) { floorThrew = true; }
        H.assert(floorThrew, 'Argon2id params below the OWASP memory floor are rejected');
    });

    // =====================================================================
    await H.gate('A18 (f) Transparent upgrade — legacy backup re-wrapped to Argon2id on unlock', async () => {
        const KeyBackupService = require('../services/keyBackupService.js');

        // Minimal in-memory DB mock exposing the methods KeyBackupService uses.
        function makeDb(rows) {
            return {
                rows,
                async querySelect(table, opts) {
                    const uid = opts.filter.user_id;
                    return { data: this.rows.filter(r => r.user_id === uid) };
                },
                async queryUpdate(table, _x, patch, where) {
                    const row = this.rows.find(r => r.user_id === where.user_id);
                    if (!row) return { error: { message: 'no row' } };
                    Object.assign(row, patch);
                    return { error: null };
                }
            };
        }

        const userId = 'user-legacy-1';
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const legacyPw = await makeLegacyEnvelope(secret, PASSWORD);

        const row = {
            user_id: userId,
            password_encrypted_data: legacyPw.encryptedData,
            password_salt: legacyPw.salt,
            password_iv: legacyPw.iv,
            session_backup_key_encrypted: null,
            session_backup_key_salt: null,
            session_backup_key_iv: null
        };
        const db = makeDb([row]);
        KeyBackupService.initialize({ services: { database: db } });

        // Pre-condition: stored row is legacy.
        H.assert(PCS.isLegacyBackup(row.password_salt), 'pre: row is legacy PBKDF2');

        const restored = await KeyBackupService.restoreFromPassword(userId, PASSWORD);
        H.assertBytesEqual(restored, secret, 'restoreFromPassword returns the correct key for a legacy row');

        // The upgrade is fire-and-forget in production; await the tracked
        // promise deterministically (re-derive is intentionally slow @ 64 MiB).
        await KeyBackupService._lastUpgrade;

        // Post-condition: the persisted row is now Argon2id...
        H.assert(!PCS.isLegacyBackup(row.password_salt), 'post: row upgraded to Argon2id');
        H.assertEqual(PCS.kdfOf(row.password_salt), 'argon2id-m65536-t3-p1', 'post: tag is Argon2id');

        // ...and the upgraded blob still unwraps to the same secret.
        const back2 = await PCS.decryptFromBase64(row.password_encrypted_data, PASSWORD, row.password_salt, row.password_iv);
        H.assertBytesEqual(back2, secret, 'upgraded Argon2id blob unwraps to identical key material');

        // Idempotent: a second unlock does not change the (already Argon2id) row.
        const saltBefore = row.password_salt;
        const restored2 = await KeyBackupService.restoreFromPassword(userId, PASSWORD);
        H.assertBytesEqual(restored2, secret, 'second unlock still returns the key');
        await KeyBackupService._lastUpgrade;
        H.assertEqual(row.password_salt, saltBefore, 'upgrade is idempotent (no churn once Argon2id)');

        // Non-fatal upgrade: even if persistence FAILS, the unlock still returns
        // the key (no-lockout). Use a fresh legacy row + a DB whose update errors.
        const userId2 = 'user-legacy-2';
        const secret2 = crypto.getRandomValues(new Uint8Array(32));
        const legacyPw2 = await makeLegacyEnvelope(secret2, PASSWORD);
        const row2 = {
            user_id: userId2,
            password_encrypted_data: legacyPw2.encryptedData,
            password_salt: legacyPw2.salt,
            password_iv: legacyPw2.iv,
            session_backup_key_encrypted: null
        };
        const failingDb = {
            rows: [row2],
            async querySelect(t, opts) { return { data: this.rows.filter(r => r.user_id === opts.filter.user_id) }; },
            async queryUpdate() { return { error: { message: 'simulated persist failure' } }; }
        };
        KeyBackupService.initialize({ services: { database: failingDb } });
        const restored3 = await KeyBackupService.restoreFromPassword(userId2, PASSWORD);
        H.assertBytesEqual(restored3, secret2, 'unlock succeeds even when the upgrade persist fails (non-fatal)');
        await KeyBackupService._lastUpgrade;
        H.assert(PCS.isLegacyBackup(row2.password_salt), 'row stays legacy after a failed upgrade (no partial corruption)');
    });

    H.summary();
})().catch((e) => {
    process.stdout.write('UNCAUGHT: ' + (e && e.stack || e) + '\n');
    process.exit(1);
});
