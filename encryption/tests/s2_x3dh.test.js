/**
 * S2 GATES -- pure X3DH key agreement.
 *
 * Run: node encryption/tests/s2_x3dh.test.js
 *
 * Gates (per FORWARD_SECRECY_DESIGN sections 2 + 8, mapped to the S2 ask):
 *   (a) X3DH KAT        -- initiator-derived SK == responder-derived SK, and it
 *                          is byte-stable for fixed seeds. BOTH the with-OPK and
 *                          without-OPK (DH4 omitted) paths are exercised, and the
 *                          two paths produce DIFFERENT SKs (DH4 actually mixes in).
 *   (b) signature check -- a tampered / invalid / wrong-key SPK signature is
 *                          REJECTED (fail closed): no SK is derived.
 *   (c) S1 handoff      -- feed the X3DH SK into ratchetInitAlice / ratchetInitBob
 *                          and confirm the first ratchet message round-trips,
 *                          proving the SK + Bob's-SPK-as-ratchet-key contract.
 *
 * All randomness is frozen via the S0 RNG seam so SK is reproducible.
 */

const H = require('./_harness.js');
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;
const DR = svc.DoubleRatchetService;
const X3DH = require('../services/x3dhService.js');

function enc(str) { return new TextEncoder().encode(str); }
function dec(bytes) { return new TextDecoder().decode(bytes); }

/**
 * Deterministically build Bob's published prekey bundle + the matching secrets,
 * and Alice's identity keypair. Everything is frozen by `seed`.
 *
 * @param {string} seed
 * @param {boolean} withOpk  include a one-time prekey (DH4) or not
 */
function buildKeys(seed, withOpk) {
    CP.setRandomBytesSource(H.makeDeterministicRng(seed));

    // Alice's long-term X25519 identity key.
    const aliceIK = CP.generateKeyPair();

    // Bob's long-term X25519 identity key.
    const bobIK = CP.generateKeyPair();
    // Bob's Ed25519 identity SIGNING key (separate from the box key).
    const bobIKSign = CP.signKeyPair();
    // Bob's signed prekey (X25519) -- also doubles as his ratchet keypair.
    const bobSPK = CP.generateKeyPair();
    // Bob signs the SPK public with his Ed25519 signing secret.
    const spkSig = CP.signDetached(bobSPK.publicKey, bobIKSign.secretKey);

    // Bob's one-time prekey pool (one entry) -- optional.
    let bobOPK = null;
    if (withOpk) bobOPK = CP.generateKeyPair();

    CP.resetRandomBytesSource();

    // Bob's PUBLISHED bundle (what Alice fetches).
    const peerBundle = {
        identityKeyPub:  bobIK.publicKey,
        identitySignPub: bobIKSign.publicKey,
        signedPrekeyPub: bobSPK.publicKey,
        signedPrekeySig: spkSig,
        spkId: 7,
    };
    if (withOpk) {
        peerBundle.oneTimePrekeyPub = bobOPK.publicKey;
        peerBundle.oneTimePrekeyId = 42;
    }

    return { aliceIK, bobIK, bobIKSign, bobSPK, bobOPK, spkSig, peerBundle };
}

/**
 * Run a full initiator+responder X3DH for the given seed/path and return both
 * SKs (as hex) plus the initiator result (for the S1 handoff).
 */
async function runX3DH(seed, withOpk) {
    const k = buildKeys(seed, withOpk);

    // Alice (initiator). Freeze her ephemeral too.
    CP.setRandomBytesSource(H.makeDeterministicRng(seed + '|alice-ephemeral'));
    const init = await X3DH.deriveInitiatorRoot({
        identityKeyPair: k.aliceIK,
        peerBundle: k.peerBundle,
    });
    CP.resetRandomBytesSource();

    // Bob (responder) recomputes SK from his local secrets + Alice's preamble.
    const resp = await X3DH.deriveResponderRoot({
        identityKeyPair: k.bobIK,
        signedPrekeyPair: k.bobSPK,
        oneTimePrekeyPair: withOpk ? k.bobOPK : undefined,
        preamble: init.preamble,
    });

    return {
        keys: k,
        init: init,
        resp: resp,
        skInitHex: H.toHex(init.SK),
        skRespHex: H.toHex(resp.SK),
    };
}

async function main() {
    // =====================================================================
    await H.gate('S2 (a) X3DH KAT -- initiator SK == responder SK, byte-stable, with-OPK & without-OPK', async () => {
        // --- WITH one-time prekey (full 4-DH) ---
        const withOpk1 = await runX3DH('x3dh-KAT-seed-1', true);
        H.assertEqual(withOpk1.skInitHex, withOpk1.skRespHex,
            'WITH-OPK: initiator SK == responder SK');
        H.assertEqual(withOpk1.init.SK.length, 32, 'WITH-OPK: SK is 32 bytes');
        // The preamble records that OPK 42 was used.
        H.assertEqual(withOpk1.init.preamble.opkId, 42, 'WITH-OPK: preamble records opkId=42');
        H.assertEqual(withOpk1.init.preamble.spkId, 7, 'WITH-OPK: preamble records spkId=7');

        // Byte-stable across an independent re-run with the SAME seed.
        const withOpk2 = await runX3DH('x3dh-KAT-seed-1', true);
        H.assertEqual(withOpk2.skInitHex, withOpk1.skInitHex,
            'WITH-OPK: SK byte-stable across runs (frozen seed)');

        // --- WITHOUT one-time prekey (DH4 omitted, 3-DH) ---
        const noOpk1 = await runX3DH('x3dh-KAT-seed-1', false);
        H.assertEqual(noOpk1.skInitHex, noOpk1.skRespHex,
            'NO-OPK: initiator SK == responder SK');
        H.assertEqual(noOpk1.init.preamble.opkId, null, 'NO-OPK: preamble opkId is null');

        const noOpk2 = await runX3DH('x3dh-KAT-seed-1', false);
        H.assertEqual(noOpk2.skInitHex, noOpk1.skInitHex,
            'NO-OPK: SK byte-stable across runs (frozen seed)');

        // DH4 actually matters: with-OPK and without-OPK SKs MUST differ.
        H.assert(withOpk1.skInitHex !== noOpk1.skInitHex,
            'OPK changes the SK (DH4 is mixed in, not ignored)');

        // Associated data agrees on both sides (IK_a || IK_b).
        H.assertBytesEqual(withOpk1.init.associatedData, withOpk1.resp.associatedData,
            'WITH-OPK: AD (IK_a||IK_b) matches on both sides');
        H.assertBytesEqual(noOpk1.init.associatedData, noOpk1.resp.associatedData,
            'NO-OPK: AD (IK_a||IK_b) matches on both sides');
        H.assertEqual(withOpk1.init.associatedData.length, 64, 'AD is 64 bytes (two 32B pubkeys)');

        // Print the frozen vectors.
        process.stdout.write('  frozen SK (with-OPK)   : ' + withOpk1.skInitHex + '\n');
        process.stdout.write('  frozen SK (without-OPK): ' + noOpk1.skInitHex + '\n');
    });

    // =====================================================================
    await H.gate('S2 (b) signature check -- tampered / invalid / wrong-key SPK signature is REJECTED (fail closed)', async () => {
        const k = buildKeys('x3dh-sig-seed', true);

        // Sanity: the good bundle verifies and derives an SK.
        const good = await X3DH.deriveInitiatorRoot({
            identityKeyPair: k.aliceIK,
            peerBundle: k.peerBundle,
        });
        H.assertEqual(good.SK.length, 32, 'baseline good bundle derives a 32-byte SK');

        // 1) Flip one byte of the SPK signature -> reject, no SK.
        const tamperedSig = Uint8Array.from(k.peerBundle.signedPrekeySig);
        tamperedSig[0] ^= 0x01;
        let rejected1 = false;
        try {
            await X3DH.deriveInitiatorRoot({
                identityKeyPair: k.aliceIK,
                peerBundle: Object.assign({}, k.peerBundle, { signedPrekeySig: tamperedSig }),
            });
        } catch (e) { rejected1 = /signature/i.test(e.message); }
        H.assert(rejected1, 'tampered SPK signature (1 bit flipped) is rejected (fail closed)');

        // 2) Tamper the SIGNED MESSAGE instead (flip an SPK pubkey byte): the
        //    original signature no longer matches -> reject.
        const tamperedSpk = Uint8Array.from(k.peerBundle.signedPrekeyPub);
        tamperedSpk[5] ^= 0x80;
        let rejected2 = false;
        try {
            await X3DH.deriveInitiatorRoot({
                identityKeyPair: k.aliceIK,
                peerBundle: Object.assign({}, k.peerBundle, { signedPrekeyPub: tamperedSpk }),
            });
        } catch (e) { rejected2 = true; }
        H.assert(rejected2, 'tampered SPK public (signature no longer matches) is rejected');

        // 3) Verify against the WRONG Ed25519 key (attacker substitutes their own
        //    signing identity): a freshly-minted signing key -> reject.
        CP.setRandomBytesSource(H.makeDeterministicRng('attacker-sign-key'));
        const attacker = CP.signKeyPair();
        CP.resetRandomBytesSource();
        let rejected3 = false;
        try {
            await X3DH.deriveInitiatorRoot({
                identityKeyPair: k.aliceIK,
                peerBundle: Object.assign({}, k.peerBundle, { identitySignPub: attacker.publicKey }),
            });
        } catch (e) { rejected3 = /signature/i.test(e.message); }
        H.assert(rejected3, 'verifying against the wrong Ed25519 key is rejected');

        // 4) Malformed signature length -> reject (defensive, fail closed).
        let rejected4 = false;
        try {
            X3DH.verifySignedPrekey(k.peerBundle.signedPrekeyPub, new Uint8Array(10), k.peerBundle.identitySignPub);
        } catch (e) { rejected4 = true; }
        H.assert(rejected4, 'malformed (short) signature is rejected');
    });

    // =====================================================================
    await H.gate('S2 (c) S1 handoff -- X3DH SK feeds ratchetInitAlice/Bob and the first message round-trips', async () => {
        // Use the WITH-OPK path; Bob's ratchet keypair IS his signed-prekey pair.
        const k = buildKeys('x3dh-handoff-seed', true);

        // Alice runs X3DH.
        CP.setRandomBytesSource(H.makeDeterministicRng('x3dh-handoff-seed|alice-ephemeral'));
        const init = await X3DH.deriveInitiatorRoot({
            identityKeyPair: k.aliceIK,
            peerBundle: k.peerBundle,
        });
        CP.resetRandomBytesSource();

        // Bob recomputes SK.
        const resp = await X3DH.deriveResponderRoot({
            identityKeyPair: k.bobIK,
            signedPrekeyPair: k.bobSPK,
            oneTimePrekeyPair: k.bobOPK,
            preamble: init.preamble,
        });
        H.assertBytesEqual(init.SK, resp.SK, 'handoff: both sides agree on SK before ratchet init');

        // --- Hand SK to the Double Ratchet (S1). ---
        // Alice inits with SK + Bob's ratchet pub (= Bob's SPK public).
        // Freeze her ratchet ephemeral too.
        CP.setRandomBytesSource(H.makeDeterministicRng('x3dh-handoff-seed|alice-ratchet'));
        let alice = await DR.ratchetInitAlice(init.SK, k.bobSPK.publicKey);
        CP.resetRandomBytesSource();

        // Bob inits with SK + his SPK keypair as the initial ratchet keypair.
        let bob = await DR.ratchetInitBob(resp.SK, k.bobSPK);

        // First ratchet message: Alice -> Bob. Bind the X3DH AD into the AEAD
        // (this is what S5/S6 will do for message 0).
        const ad = init.associatedData;
        const msg = await DR.ratchetEncrypt(alice, enc('hello-after-x3dh'), ad);
        alice = msg.newState;

        const got = await DR.ratchetDecrypt(bob, msg.wireHeader, msg.nonce, msg.ciphertext, ad);
        bob = got.newState;
        H.assertEqual(dec(got.plaintext), 'hello-after-x3dh',
            'first ratchet message round-trips end-to-end (X3DH SK -> ratchet -> decrypt)');

        // And a reply the other direction works too (proves Bob can send,
        // exercising the direction change off the shared root).
        const reply = await DR.ratchetEncrypt(bob, enc('ack'));
        bob = reply.newState;
        const gotReply = await DR.ratchetDecrypt(alice, reply.wireHeader, reply.nonce, reply.ciphertext);
        alice = gotReply.newState;
        H.assertEqual(dec(gotReply.plaintext), 'ack', 'reply round-trips across the direction change');

        // Negative: a WRONG SK (e.g. failed X3DH) must NOT decrypt -- proves the
        // handoff actually depends on the agreed SK, not on luck.
        CP.setRandomBytesSource(H.makeDeterministicRng('wrong-sk'));
        const wrongSK = CP.randomBytes(32);
        let bobWrong = await DR.ratchetInitBob(wrongSK, k.bobSPK);
        CP.resetRandomBytesSource();
        // Re-encrypt a fresh first message from a clean Alice so state lines up.
        CP.setRandomBytesSource(H.makeDeterministicRng('x3dh-handoff-seed|alice-ratchet'));
        let alice2 = await DR.ratchetInitAlice(init.SK, k.bobSPK.publicKey);
        CP.resetRandomBytesSource();
        const m2 = await DR.ratchetEncrypt(alice2, enc('should-not-open'), ad);
        let wrongFailed = false;
        try {
            await DR.ratchetDecrypt(bobWrong, m2.wireHeader, m2.nonce, m2.ciphertext, ad);
        } catch (e) { wrongFailed = true; }
        H.assert(wrongFailed, 'a mismatched SK cannot decrypt (handoff depends on the agreed SK)');
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
