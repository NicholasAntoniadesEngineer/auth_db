/**
 * S10 GATES -- account-password strength policy (SECURITY_AUDIT.md H-2).
 *
 * Run: node encryption/tests/s10_password_policy.test.js
 *
 * Context: the account password encrypts the at-rest identity-key backup
 * (PBKDF2-SHA256 600k + AES-256-GCM). A weak password makes a leaked/at-rest
 * backup offline-brute-forceable -> total E2E break. Finding H-2 was that
 * enforcePasswordStrength / validatePasswordStrength existed but had ZERO call
 * sites and the only gate was length>=8. These gates lock in the policy:
 *
 *   (1) minimum length is 12 (raised from 8); shorter passwords are rejected
 *       by both validate (valid=false) and enforce (throws).
 *   (2) character-class requirement: a long but single-class password is weak.
 *   (3) a strong password (>=12 chars + >=3 classes) is accepted; enforce
 *       returns the validation object and does not throw.
 *   (4) enforce throws a descriptive Error on weak input (so callers can fail
 *       closed before any identity backup is created).
 *
 * No new deps: PasswordCryptoService's policy methods are pure and require only
 * `require()` of the service (no nacl, no DB, no WebCrypto).
 */

const H = require('./_harness.js');
const PCS = require('../services/passwordCryptoService.js');

async function main() {
    // =====================================================================
    await H.gate('S10 (1) minimum length raised to 12', async () => {
        H.assertEqual(PCS.MIN_PASSWORD_LENGTH, 12, 'MIN_PASSWORD_LENGTH is 12');

        // 11 chars, all classes present -> still too short -> invalid.
        const tooShort = 'Aa1!Aa1!Aa1'; // length 11
        H.assertEqual(tooShort.length, 11, 'fixture length is 11');
        H.assertEqual(PCS.validatePasswordStrength(tooShort).valid, false,
            '11-char password is rejected even with all character classes');
        H.assertThrows(() => PCS.enforcePasswordStrength(tooShort),
            'enforce throws on an 11-char password');

        // The old 8-char minimum must no longer pass.
        H.assertEqual(PCS.validatePasswordStrength('Aa1!Aa1!').valid, false,
            'legacy 8-char password is now rejected');
    });

    // =====================================================================
    await H.gate('S10 (2) character-class requirement', async () => {
        // 16 chars but a single class (all lowercase) -> weak.
        const oneClass = 'abcdefghijklmnop';
        H.assertEqual(oneClass.length >= 12, true, 'fixture is long enough');
        H.assertEqual(PCS.validatePasswordStrength(oneClass).valid, false,
            'long single-class password is rejected');
        H.assertThrows(() => PCS.enforcePasswordStrength(oneClass),
            'enforce throws on a long single-class password');

        // 13 chars, two classes (lower + digit) -> still below MIN_CHARACTER_CLASSES (3).
        const twoClasses = 'abcdefghij123';
        H.assertEqual(PCS.validatePasswordStrength(twoClasses).valid, false,
            'two-class password is rejected (needs >=3 classes)');
    });

    // =====================================================================
    await H.gate('S10 (3) strong password accepted', async () => {
        // 12+ chars, 4 classes.
        const strong = 'Sunset!Harbor7';
        H.assertEqual(strong.length >= 12, true, 'fixture is long enough');
        const v = PCS.validatePasswordStrength(strong);
        H.assertEqual(v.valid, true, 'strong password is valid');
        H.assert(v.characterClasses >= PCS.MIN_CHARACTER_CLASSES,
            'strong password meets the character-class floor');

        // enforce must NOT throw and must return the validation object.
        let returned = null;
        let threw = false;
        try { returned = PCS.enforcePasswordStrength(strong); } catch (e) { threw = true; }
        H.assertEqual(threw, false, 'enforce does not throw on a strong password');
        H.assert(returned && returned.valid === true, 'enforce returns the validation result');

        // A 12-char, 3-class password (no symbol) is also accepted.
        const strong3 = 'GreenTrain42'; // 12 chars: upper+lower+digit
        H.assertEqual(PCS.validatePasswordStrength(strong3).valid, true,
            '12-char 3-class password is accepted');
    });

    // =====================================================================
    await H.gate('S10 (4) enforce throws a descriptive Error', async () => {
        let err = null;
        try { PCS.enforcePasswordStrength('weak'); } catch (e) { err = e; }
        H.assert(err instanceof Error, 'enforce throws an Error instance');
        H.assert(/security requirements/i.test(err.message),
            'error message mentions security requirements');
        H.assert(/12 characters/.test(err.message),
            'error feedback cites the raised 12-character minimum');

        // Non-string input must not pass and must not crash validate.
        H.assertEqual(PCS.validatePasswordStrength(undefined).valid, false,
            'undefined password is invalid (no crash)');
        H.assertEqual(PCS.validatePasswordStrength(null).valid, false,
            'null password is invalid (no crash)');
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nUNCAUGHT: ' + e.stack + '\n');
    process.exitCode = 1;
});
