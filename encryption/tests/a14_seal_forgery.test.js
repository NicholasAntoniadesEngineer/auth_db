/**
 * A14 GATE -- H-4 AUTHENTICATED CONTEXT-BOUND DEK SEAL: forgery / tamper locks.
 *
 * Run: node encryption/tests/a14_seal_forgery.test.js
 *
 * Regression lock for the SEC-H4 hardened cross-user share seal in
 * money_tracker/shared/services/budgetCryptoService.js
 * (sealDEKToRecipient / unsealDEK). These are NEGATIVE tests: they assert the
 * REAL committed fail-closed behavior, not aspirations.
 *
 * The seal is an authenticated static+ephemeral box (X3DH-flavoured) whose wrap
 * key is bound to a canonical context:
 *     info = (ownerIK, recipientIK, owner_id, recipient_id, dek_version, share_id)
 * so any tampered bound value derives a DIFFERENT key and secretbox.open returns
 * null -> decryptBytes THROWS (Poly1305 auth failure). The recipient also pins
 * the bound owner IK against the expected (TOFU) sender key.
 *
 * Gates:
 *   (1) a legacy ANONYMOUS / pre-v2 seal (no wrap_owner_ik) is REJECTED.
 *   (2) a seal whose bound context is tampered (wrong owner_id / recipient_id /
 *       dek_version / share_id) FAILS to unseal.
 *   (3) a valid seal for recipient A cannot be unsealed by recipient B.
 *   (4) a happy-path round-trip still succeeds.
 *
 * Determinism: the seal ephemeral keygen + nonce route through the RNG seam, but
 * we do NOT need a frozen seed here -- these tests assert pass/fail behavior, not
 * byte-stable envelopes, so production randomness is fine.
 */

const H = require('./_harness.js');

// Load nacl + WebCrypto + the pure primitives via the existing harness. This
// wires CryptoPrimitivesService + KeyDerivationService onto global, which is
// exactly how BudgetCryptoService._cp() / _kdf() resolve them.
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;

// The H-4 service under test. budgetCryptoService.js is authored as CommonJS
// (`module.exports = BudgetCryptoService`) but lives under money_tracker whose
// package.json declares `"type": "module"`, so a bare require() loads it through
// the ESM interop and returns an EMPTY namespace (the CJS module.exports guard is
// ignored). Load it the same way the harness loads the vendored UMD libs: read
// the source and evaluate it in a real CommonJS wrapper so its module.exports
// runtime branch executes against the globals wired above. This exercises the
// EXACT committed source, just under a CJS realm.
function loadCjsModule(absPath) {
    const fs = require('fs');
    const vm = require('vm');
    const src = fs.readFileSync(absPath, 'utf8');
    const m = { exports: {} };
    const wrapper = '(function(module, exports, require, __dirname, __filename){' + src + '\n})';
    const fn = vm.runInThisContext(wrapper, { filename: absPath });
    fn(m, m.exports, require, require('path').dirname(absPath), absPath);
    return m.exports;
}
const BudgetCryptoService = loadCjsModule(
    require('path').resolve(__dirname, '../../../money_tracker/shared/services/budgetCryptoService.js')
);

// --- fixtures --------------------------------------------------------------
// Three X25519 identities: the owner (sender) + two recipients A and B.
const owner = CP.generateKeyPair();
const recipientA = CP.generateKeyPair();
const recipientB = CP.generateKeyPair();

const OWNER_ID = 'owner-1001';
const RECIP_A_ID = 'recipient-2002';
const RECIP_B_ID = 'recipient-3003';
const DEK_VERSION = 7;
const SHARE_ID = 909;

const ownerPubB64 = CP.serializeKey(owner.publicKey);

// The DEK that the owner shares.
const DEK = BudgetCryptoService.generateDEK();

// Build the canonical "good" seal for recipient A.
function sealForA() {
    return BudgetCryptoService.sealDEKToRecipient(DEK, recipientA.publicKey, {
        ownerSecretKey: owner.secretKey,
        ownerPublicKey: owner.publicKey,
        ownerId: OWNER_ID,
        recipientId: RECIP_A_ID,
        dekVersion: DEK_VERSION,
        shareId: SHARE_ID,
    });
}

// The verification opts recipient A would INDEPENDENTLY know from the share row.
function unsealOptsA(overrides = {}) {
    return Object.assign({
        expectedOwnerPublicKey: owner.publicKey,
        ownerId: OWNER_ID,
        recipientId: RECIP_A_ID,
        dekVersion: DEK_VERSION,
        shareId: SHARE_ID,
    }, overrides);
}

function bytesEqual(a, b) {
    return Buffer.from(a).equals(Buffer.from(b));
}

async function main() {

    // =====================================================================
    // (4) HAPPY PATH -- a valid seal round-trips. (Run first as the control so
    // every later negative test is meaningful: we know the seal CAN open.)
    // =====================================================================
    await H.gate('A14 (4) happy-path: valid seal for A round-trips to the same DEK', async () => {
        const sealed = sealForA();

        // The seal columns are well-formed for the v2-auth construction.
        H.assertEqual(sealed.wrap_alg, BudgetCryptoService.SEAL_ALG, 'seal carries the v2-auth alg tag');
        H.assertEqual(sealed.wrap_owner_ik, ownerPubB64, 'seal binds the owner identity public key');
        H.assert(typeof sealed.wrap_eph_pub === 'string' && sealed.wrap_eph_pub.length > 0, 'seal carries an ephemeral public key');
        H.assertEqual(sealed.dek_version, DEK_VERSION, 'seal carries the dek_version');

        const recovered = BudgetCryptoService.unsealDEK(sealed, recipientA.secretKey, unsealOptsA());
        H.assert(recovered instanceof Uint8Array && recovered.length === 32, 'unseal returns a 32-byte DEK');
        H.assert(bytesEqual(recovered, DEK), 'recovered DEK byte-equals the original (round-trip)');
        process.stdout.write('  valid seal opened by A -> identical DEK.\n');
    });

    // =====================================================================
    // (1) LEGACY / ANONYMOUS seal -> REJECTED fail-closed. The v1 anonymous box
    // had no bound owner IK; unsealDEK must refuse it (no silent accept) so an
    // unauthenticated seal can never be honoured.
    // =====================================================================
    await H.gate('A14 (1) a legacy/anonymous seal (no wrap_owner_ik) is REJECTED fail-closed', async () => {
        const sealed = sealForA();

        // (1a) wrap_owner_ik entirely absent (pre-v2 anonymous shape).
        const anon = { ...sealed };
        delete anon.wrap_owner_ik;
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(anon, recipientA.secretKey, unsealOptsA()),
            'a seal with NO wrap_owner_ik is rejected (legacy/anonymous, fail closed)'
        );

        // (1b) wrap_owner_ik present but empty string -> still rejected.
        const anonEmpty = { ...sealed, wrap_owner_ik: '' };
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(anonEmpty, recipientA.secretKey, unsealOptsA()),
            'a seal with an EMPTY wrap_owner_ik is rejected (legacy/anonymous, fail closed)'
        );

        // (1c) wrong wrap_alg tag with no owner IK is still refused -- there is no
        // code path that silently accepts an unauthenticated seal.
        const anonV1 = { ...sealed, wrap_alg: 'v1' };
        delete anonV1.wrap_owner_ik;
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(anonV1, recipientA.secretKey, unsealOptsA()),
            'a v1-tagged anonymous seal is rejected (no silent legacy accept)'
        );
        process.stdout.write('  anonymous / pre-v2 seals all rejected; no silent accept.\n');
    });

    // =====================================================================
    // (2) TAMPERED BOUND CONTEXT -> FAILS to unseal. Each bound value is part of
    // the HKDF info; flipping it on the verifier side (the recipient's claimed
    // share-row values) derives a different wrap key -> secretbox.open fails.
    // The owner IK is verified against the pin BEFORE the DH, so we tamper the
    // verifier opts (what the share row says), which is the realistic attack:
    // a lifted seal whose row IDs disagree with the seal's true context.
    // =====================================================================
    await H.gate('A14 (2) a tampered bound context (owner_id / recipient_id / dek_version / share_id) FAILS to unseal', async () => {
        const sealed = sealForA();

        // wrong owner_id
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(sealed, recipientA.secretKey, unsealOptsA({ ownerId: 'owner-EVIL' })),
            'wrong owner_id -> unseal FAILS (context binding holds)'
        );

        // wrong recipient_id
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(sealed, recipientA.secretKey, unsealOptsA({ recipientId: RECIP_B_ID })),
            'wrong recipient_id -> unseal FAILS (context binding holds)'
        );

        // wrong dek_version
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(sealed, recipientA.secretKey, unsealOptsA({ dekVersion: DEK_VERSION + 1 })),
            'wrong dek_version -> unseal FAILS (context binding holds)'
        );

        // wrong share_id
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(sealed, recipientA.secretKey, unsealOptsA({ shareId: SHARE_ID + 1 })),
            'wrong share_id -> unseal FAILS (context binding holds)'
        );

        // ALSO: a substituted/forged bound owner IK that does NOT match the pin is
        // rejected up front (key-substitution defense). Forge a different IK into
        // the seal blob; the pin check (wrap_owner_ik === expectedOwnerPublicKey)
        // must fail closed before any DH.
        const forgedOwner = CP.generateKeyPair();
        const tamperedIk = { ...sealed, wrap_owner_ik: CP.serializeKey(forgedOwner.publicKey) };
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(tamperedIk, recipientA.secretKey, unsealOptsA()),
            'a substituted bound owner IK (!= pinned sender key) -> unseal FAILS (key-substitution defense)'
        );

        // ALSO: a flipped ciphertext byte (raw tamper) -> Poly1305 auth failure.
        const ctBytes = CP.deserializeKey(sealed.wrapped_dek);
        ctBytes[3] ^= 0x40;
        const tamperedCt = { ...sealed, wrapped_dek: CP.serializeKey(ctBytes) };
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(tamperedCt, recipientA.secretKey, unsealOptsA()),
            'a flipped ciphertext byte -> unseal FAILS (Poly1305 auth)'
        );

        // CONTROL: the untouched seal with the correct context still opens, so the
        // failures above are due to the tamper, not a broken fixture.
        const ok = BudgetCryptoService.unsealDEK(sealed, recipientA.secretKey, unsealOptsA());
        H.assert(bytesEqual(ok, DEK), 'control: the untouched seal still opens with the correct context');
        process.stdout.write('  every tampered bound value + forged IK + flipped CT rejected; control opens.\n');
    });

    // =====================================================================
    // (3) CROSS-RECIPIENT -> a seal for A cannot be opened by B. B's secret key
    // recomputes a different DH_ss/DH_es (the seal DH'd against A's pubkey) AND a
    // different recipientIK in the context -> wrong wrap key -> fail closed. Try
    // both the honest opts and B-claimed opts; neither should open.
    // =====================================================================
    await H.gate('A14 (3) a seal for recipient A cannot be unsealed by recipient B (cross-recipient)', async () => {
        const sealed = sealForA();

        // B uses A's share-row opts (the seal's true context) but B's own secret.
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(sealed, recipientB.secretKey, unsealOptsA()),
            'recipient B (with A\'s context) cannot open A\'s seal'
        );

        // B uses its OWN claimed identity in the opts too -- still fails (the seal
        // was DH-bound to A's pubkey, and recipientIK in info is recomputed from B).
        H.assertThrows(
            () => BudgetCryptoService.unsealDEK(sealed, recipientB.secretKey, unsealOptsA({ recipientId: RECIP_B_ID })),
            'recipient B (claiming itself as recipient) still cannot open A\'s seal'
        );

        // CONTROL: A still opens it.
        const ok = BudgetCryptoService.unsealDEK(sealed, recipientA.secretKey, unsealOptsA());
        H.assert(bytesEqual(ok, DEK), 'control: recipient A still opens the seal');
        process.stdout.write('  B cannot open A\'s seal under any opts; A still can.\n');
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
