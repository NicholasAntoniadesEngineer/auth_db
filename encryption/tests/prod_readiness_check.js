/**
 * PROD-READINESS GUARD — release gate (NOT part of the normal S0-S13 suite).
 *
 * Run:  node encryption/tests/prod_readiness_check.js
 * Exit: 0 only when EVERY checked prod-revert item is in its production value;
 *       NON-ZERO (1) otherwise — and it is EXPECTED to FAIL right now.
 *
 * -------------------------------------------------------------------------
 * WHY THIS EXISTS / HOW TO USE IT
 * -------------------------------------------------------------------------
 * The dev build ships a small number of deliberate TESTING weakenings (see
 * SECURITY_AUDIT.md §5 "Testing-Only Weakenings That MUST Revert for
 * Production"). The headline one is:
 *
 *     PasswordCryptoService.RECOVERY_KEY_BYTES === 20   (testing, 8 elements)
 *
 * which MUST become 32 (full 256-bit) before the external pentest. The user
 * keeps it at 20 for multi-device testing on purpose, so this guard is
 * INTENTIONALLY SEPARATE from the normal/dev S0-S13 crypto suite — adding it
 * there would break the everyday `node encryption/tests/s*.test.js` run. It is
 * a DELIBERATE release gate: run it once, immediately before cutting the
 * pentest build. It WILL fail today, and that failure is the point — it tells
 * you the single one-line revert (RECOVERY_KEY_BYTES 20 -> 32) has not yet
 * been performed.
 *
 *     # before the pentest:
 *     node encryption/tests/prod_readiness_check.js   # must exit 0
 *
 * The action it gates: flip RECOVERY_KEY_BYTES from 20 to 32 in
 * encryption/services/passwordCryptoService.js (and re-mint any backups minted
 * under the 20-byte value). When that is done (and the other JS-checkable
 * revert items below hold) this guard exits 0.
 *
 * SCOPE: this guard only checks the items observable from the client crypto
 * JS layer. The remaining §5 items live outside JS and are checked elsewhere /
 * by inspection (recorded here so they are not forgotten):
 *   - pg_cron reapers (pairing-expiry, trial-downgrade) shipped in-schema  -> SQL
 *   - CSP `script-src 'unsafe-inline'` removed                              -> *.html
 * Those are listed in KNOWN_ACCEPTED_RISKS.md and SECURITY_AUDIT.md §5.
 */

// Some services assign to `window.*` at module load (browser globals). Provide a
// minimal stub so this node-run guard can require them without a DOM. This only
// affects loading; it does not influence any value the guard asserts.
if (typeof global.window === 'undefined') {
    global.window = global;
}

// WebCrypto + hash-wasm are needed for the Argon2id WRITE-path check below.
if (typeof global.crypto === 'undefined') {
    global.crypto = require('crypto').webcrypto;
}

const PasswordCryptoService = require('../services/passwordCryptoService.js');
// devicePairingService.js publishes only via `window.DevicePairingService`
// (no module.exports), so after requiring it we read it off the window stub.
require('../services/devicePairingService.js');
const DevicePairingService = global.window.DevicePairingService;

const RECOVERY_KEY_BYTES_PROD = 32; // 256-bit — the value the pentest build requires
const MIN_PASSWORD_LENGTH_PROD = 12; // H-2 load-bearing floor
const PAIRING_CODE_BYTES_FLOOR = 10; // 80-bit floor (§5 item 4)

const failures = [];
const passes = [];

function check(ok, label, detail) {
    if (ok) {
        passes.push(label);
        process.stdout.write(`  [OK]   ${label}\n`);
    } else {
        failures.push(`${label} — ${detail}`);
        process.stdout.write(`  [FAIL] ${label} — ${detail}\n`);
    }
}

process.stdout.write('\n=== PROD-READINESS GUARD (release gate; NOT the S0-S13 suite) ===\n\n');

// --- §5 item 1: the headline gated revert -----------------------------------
check(
    PasswordCryptoService.RECOVERY_KEY_BYTES === RECOVERY_KEY_BYTES_PROD,
    'RECOVERY_KEY_BYTES is the production value (32 / 256-bit)',
    `is ${PasswordCryptoService.RECOVERY_KEY_BYTES} (testing value); flip 20 -> 32 in ` +
    `encryption/services/passwordCryptoService.js and re-mint affected backups`
);

// --- §5 item 2: strong-password policy enforced (load-bearing for H-2) -------
check(
    PasswordCryptoService.MIN_PASSWORD_LENGTH >= MIN_PASSWORD_LENGTH_PROD,
    'MIN_PASSWORD_LENGTH meets the production floor (>= 12)',
    `is ${PasswordCryptoService.MIN_PASSWORD_LENGTH}; raise to >= ${MIN_PASSWORD_LENGTH_PROD}`
);
check(
    typeof PasswordCryptoService.enforcePasswordStrength === 'function',
    'enforcePasswordStrength exists (wired into signup/reset)',
    'missing — the strong-password policy is not enforceable'
);
// The policy must actually reject a weak password (proves the gate is live).
let rejectsWeak = false;
try { PasswordCryptoService.enforcePasswordStrength('weak'); } catch (e) { rejectsWeak = true; }
check(
    rejectsWeak,
    'enforcePasswordStrength rejects a weak password',
    'a weak password was accepted — the H-2 gate is not effective'
);

// --- §5 item 4: pairing-code entropy floor ----------------------------------
check(
    DevicePairingService.PAIRING_CODE_BYTES >= PAIRING_CODE_BYTES_FLOOR,
    'PAIRING_CODE_BYTES holds the 80-bit floor (>= 10)',
    `is ${DevicePairingService.PAIRING_CODE_BYTES}; must be >= ${PAIRING_CODE_BYTES_FLOOR}`
);

// --- L-3 / CRYPTO_DEEP_REVIEW HIGH: at-rest KDF is Argon2id on WRITE ---------
// The backup-wrap WRITE path must mint Argon2id (memory-hard), NOT PBKDF2. Prove
// it by actually wrapping a probe and inspecting the produced kdf descriptor +
// the self-describing salt envelope. (Legacy PBKDF2 READ stays supported — that
// is the no-lockout invariant verified by encryption/tests/a18_argon2id_kdf.)
async function checkArgon2idWritePath() {
    let env = null;
    let err = null;
    try {
        // hash-wasm self-resolves via the service's node fallback; no injection.
        env = await PasswordCryptoService.encryptToBase64(
            new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
            'CorrectHorseBattery9!' // passes the H-2 policy
        );
    } catch (e) { err = e; }

    check(
        !!env && typeof env.kdf === 'string' && /^argon2id-m\d+-t\d+-p\d+$/.test(env.kdf),
        'backup WRITE path uses Argon2id (not PBKDF2)',
        err ? `wrap threw: ${err.message}` : `kdf descriptor was "${env && env.kdf}" (expected argon2id-*)`
    );

    // Param floor: memory >= 19 MiB (OWASP), iterations >= 2.
    let mem = 0, iters = 0;
    if (env && env.kdf) {
        const m = /^argon2id-m(\d+)-t(\d+)-p(\d+)$/.exec(env.kdf);
        if (m) { mem = parseInt(m[1], 10); iters = parseInt(m[2], 10); }
    }
    check(
        mem >= 19 * 1024 && iters >= 2,
        'Argon2id params meet the OWASP floor (m >= 19 MiB, t >= 2)',
        `m=${mem} KiB, t=${iters}`
    );

    // The salt field must be the self-describing tagged envelope (so the kdf
    // travels with the blob and the READ path can dispatch).
    check(
        !!env && typeof env.salt === 'string' && env.salt.charAt(0) === '{',
        'Argon2id backups store the self-describing (tagged) salt envelope',
        `salt field did not start with '{' (was "${env && env.salt && env.salt.slice(0, 12)}...")`
    );
}

// --- summary ----------------------------------------------------------------
(async () => {
    await checkArgon2idWritePath();

    process.stdout.write('\n----------------------------------------------------------------\n');
    if (failures.length === 0) {
        process.stdout.write(`PROD-READINESS: PASS (${passes.length} checks). Safe to cut the pentest build.\n`);
        process.exit(0);
    } else {
        process.stdout.write(
            `PROD-READINESS: FAIL (${failures.length} of ${passes.length + failures.length} checks failed).\n` +
            'This is EXPECTED until the testing values are reverted for production:\n  - ' +
            failures.join('\n  - ') + '\n\n' +
            'NOTE: a non-zero exit here is the gate working as designed. Do NOT add this\n' +
            'script to the default/dev test runner — it is run intentionally before release.\n'
        );
        process.exit(1);
    }
})();
