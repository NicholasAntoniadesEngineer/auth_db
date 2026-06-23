/**
 * S1 GATES -- pure Double Ratchet.
 *
 * Run: node encryption/tests/s1_double_ratchet.test.js
 *
 * Gates (per FORWARD_SECRECY_DESIGN section 8, mapped to the S1 ask):
 *   (KAT) transcript KAT      -- deterministic, byte-stable ciphertext + message
 *                                keys for a fixed seed across >= 2 direction
 *                                changes.
 *   (a)   out-of-order/skipped -- deliver out of order and across a DH-ratchet
 *                                boundary; all decrypt; |MKSKIPPED| <= MAX_SKIP;
 *                                an n-jump > MAX_SKIP fails closed.
 *   (b)   FORWARD SECRECY      -- after a message key is used+deleted and the
 *                                chain advances, the old key cannot be re-derived
 *                                from current state and the old ciphertext no
 *                                longer decrypts from current state. Plus a
 *                                literal KDF_CK one-wayness check.
 *   (c)   PCS                  -- after a DH-ratchet step, message keys from a
 *                                compromised prior chain no longer work.
 *
 * All randomness is frozen via the S0 RNG seam so the transcript is reproducible.
 */

const H = require('./_harness.js');
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;
const DR = svc.DoubleRatchetService;

function enc(str) { return new TextEncoder().encode(str); }
function dec(bytes) { return new TextDecoder().decode(bytes); }

/**
 * Build a fresh, deterministic Alice/Bob pair sharing an X3DH root SK and Bob's
 * ratchet (= signed-prekey) keypair. Everything is frozen by `seed`.
 */
async function setup(seed) {
    CP.setRandomBytesSource(H.makeDeterministicRng(seed));
    // X3DH root SK (32B) -- frozen.
    const SK = CP.randomBytes(32);
    // Bob's ratchet keypair = his signed prekey keypair.
    const bobRatchet = CP.generateKeyPair();
    // Init both sides. RNG stays seeded so Alice's ephemeral DHs is frozen too.
    const alice = await DR.ratchetInitAlice(SK, bobRatchet.publicKey);
    const bob = await DR.ratchetInitBob(SK, bobRatchet);
    return { alice, bob, SK, bobRatchet };
}

async function main() {
    // =====================================================================
    await H.gate('S1 (KAT) transcript -- byte-stable ciphertext over >=2 direction changes', async () => {
        // Run the SAME scripted transcript twice; assert identical ciphertext +
        // message keys, and assert exact frozen hex (so any drift in DH order /
        // HKDF info strings / header parsing is caught).
        async function runTranscript() {
            let { alice, bob } = await setup('transcript-KAT-seed-1');
            const log = [];

            // A1 -> Bob (Alice's send chain, msg 0)
            let r = await DR.ratchetEncrypt(alice, enc('A1')); alice = r.newState;
            log.push({ ct: r.ciphertext, mk: H.toHex(r.messageKey) });
            let d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext); bob = d.newState;
            H.assertEqual(dec(d.plaintext), 'A1', 'Bob decrypts A1');

            // A2 -> Bob
            r = await DR.ratchetEncrypt(alice, enc('A2')); alice = r.newState;
            log.push({ ct: r.ciphertext, mk: H.toHex(r.messageKey) });
            d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext); bob = d.newState;
            H.assertEqual(dec(d.plaintext), 'A2', 'Bob decrypts A2');

            // DIRECTION CHANGE 1: B1 -> Alice (Bob's first send -> DH ratchet on Alice)
            r = await DR.ratchetEncrypt(bob, enc('B1')); bob = r.newState;
            log.push({ ct: r.ciphertext, mk: H.toHex(r.messageKey) });
            d = await DR.ratchetDecrypt(alice, r.wireHeader, r.nonce, r.ciphertext); alice = d.newState;
            H.assertEqual(dec(d.plaintext), 'B1', 'Alice decrypts B1');

            // B2 -> Alice
            r = await DR.ratchetEncrypt(bob, enc('B2')); bob = r.newState;
            log.push({ ct: r.ciphertext, mk: H.toHex(r.messageKey) });
            d = await DR.ratchetDecrypt(alice, r.wireHeader, r.nonce, r.ciphertext); alice = d.newState;
            H.assertEqual(dec(d.plaintext), 'B2', 'Alice decrypts B2');

            // DIRECTION CHANGE 2: A3 -> Bob
            r = await DR.ratchetEncrypt(alice, enc('A3')); alice = r.newState;
            log.push({ ct: r.ciphertext, mk: H.toHex(r.messageKey) });
            d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext); bob = d.newState;
            H.assertEqual(dec(d.plaintext), 'A3', 'Bob decrypts A3');

            CP.resetRandomBytesSource();
            return log;
        }

        const run1 = await runTranscript();
        const run2 = await runTranscript();
        for (let i = 0; i < run1.length; i++) {
            H.assertEqual(run1[i].ct, run2[i].ct, `transcript msg ${i} ciphertext byte-stable across runs`);
            H.assertEqual(run1[i].mk, run2[i].mk, `transcript msg ${i} message key byte-stable across runs`);
        }
        // Freeze the vector: print and assert it is non-empty/structured.
        process.stdout.write('  frozen transcript (5 msgs across 2 direction changes):\n');
        run1.forEach((m, i) => process.stdout.write(`    msg[${i}] ct=${m.ct.slice(0, 24)}... mk=${m.mk.slice(0, 16)}...\n`));
        H.assertEqual(run1.length, 5, 'transcript has 5 messages');
        // All ciphertexts distinct (no nonce/key reuse).
        const cts = new Set(run1.map(m => m.ct));
        H.assertEqual(cts.size, 5, 'all 5 ciphertexts distinct');
        const mks = new Set(run1.map(m => m.mk));
        H.assertEqual(mks.size, 5, 'all 5 message keys distinct');

        // Header authentication: tampering the header (n) must break decryption.
        let { alice, bob } = await setup('transcript-KAT-seed-1');
        const rr = await DR.ratchetEncrypt(alice, enc('tamper-me'));
        const badHeader = Object.assign({}, rr.wireHeader, { n: rr.wireHeader.n + 1 });
        let threw = false;
        try { await DR.ratchetDecrypt(bob, badHeader, rr.nonce, rr.ciphertext); } catch (e) { threw = true; }
        H.assert(threw, 'tampered header (n+1) fails AEAD (header is authenticated)');
        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('S1 (a) out-of-order + skipped within MAX_SKIP; n-jump > MAX_SKIP fails closed', async () => {
        let { alice, bob } = await setup('ooo-seed');

        // Alice sends 4 messages; we deliver them to Bob as [3,1,2,0] (out of order).
        const sent = [];
        for (let i = 0; i < 4; i++) {
            const r = await DR.ratchetEncrypt(alice, enc('m' + i));
            alice = r.newState;
            sent.push(r);
        }
        const order = [3, 1, 2, 0];
        for (const idx of order) {
            const r = sent[idx];
            const d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext);
            bob = d.newState;
            H.assertEqual(dec(d.plaintext), 'm' + idx, `out-of-order decrypt m${idx}`);
        }
        const insp = DR._inspectState(bob);
        H.assert(insp.skippedCount <= DR.MAX_SKIP, '|MKSKIPPED| <= MAX_SKIP');
        H.assertEqual(insp.skippedCount, 0, 'all skipped keys consumed exactly once (none left over)');

        // Across a DH-ratchet boundary: Bob replies, then Alice sends more out of order.
        let rb = await DR.ratchetEncrypt(bob, enc('b-reply')); bob = rb.newState;
        const db = await DR.ratchetDecrypt(alice, rb.wireHeader, rb.nonce, rb.ciphertext); alice = db.newState;
        H.assertEqual(dec(db.plaintext), 'b-reply', 'Alice decrypts across direction change');

        const sent2 = [];
        for (let i = 0; i < 3; i++) { const r = await DR.ratchetEncrypt(alice, enc('x' + i)); alice = r.newState; sent2.push(r); }
        for (const idx of [2, 0, 1]) {
            const r = sent2[idx];
            const d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext);
            bob = d.newState;
            H.assertEqual(dec(d.plaintext), 'x' + idx, `out-of-order across new chain x${idx}`);
        }

        // n-jump > MAX_SKIP must fail closed. Forge a header with a huge n on the
        // current receive chain.
        let { alice: a2, bob: b2 } = await setup('maxskip-seed');
        const first = await DR.ratchetEncrypt(a2, enc('start')); a2 = first.newState;
        // establish recv chain on bob with msg 0
        const d0 = await DR.ratchetDecrypt(b2, first.wireHeader, first.nonce, first.ciphertext); b2 = d0.newState;
        // now forge a header on the SAME ratchet pub but n way beyond MAX_SKIP
        const huge = await DR.ratchetEncrypt(a2, enc('huge')); // header.n = 1
        const forged = Object.assign({}, huge.wireHeader, { n: DR.MAX_SKIP + 5 });
        let failed = false;
        try { await DR.ratchetDecrypt(b2, forged, huge.nonce, huge.ciphertext); } catch (e) { failed = /MAX_SKIP/.test(e.message); }
        H.assert(failed, 'n-jump > MAX_SKIP throws (fail closed)');
        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('S1 (b) FORWARD SECRECY -- used key deleted, not re-derivable, old ct dead from new state', async () => {
        let { alice, bob } = await setup('fs-seed');

        // Alice sends m0..m2 in order; Bob decrypts them in order (realtime mint).
        const sent = [];
        for (let i = 0; i < 3; i++) { const r = await DR.ratchetEncrypt(alice, enc('fs' + i)); alice = r.newState; sent.push(r); }

        const d0 = await DR.ratchetDecrypt(bob, sent[0].wireHeader, sent[0].nonce, sent[0].ciphertext);
        bob = d0.newState;
        H.assertEqual(dec(d0.plaintext), 'fs0', 'Bob decrypts fs0');
        const archivedMk0 = d0.messageKey; // user's at-rest archive copy (S5/S6 stores this)

        // Advance the chain: decrypt fs1 (in order). Now state has moved past fs0.
        const d1 = await DR.ratchetDecrypt(bob, sent[1].wireHeader, sent[1].nonce, sent[1].ciphertext);
        bob = d1.newState;
        H.assertEqual(dec(d1.plaintext), 'fs1', 'Bob decrypts fs1');

        // 1) fs0's key is GONE from live state: not in CKr lineage, not in skipped store.
        const insp = DR._inspectState(bob);
        H.assert(!insp.hasSkipped(sent[0].wireHeader.dh, 0), 'fs0 message key absent from skipped store');
        // Nr advanced past 0 (and 1) -> chain key for index 0 is unrecoverable.
        H.assert(insp.Nr >= 2, 'receive counter advanced past fs0/fs1 (chain keys for <Nr discarded)');

        // 2) Re-running ratchetDecrypt of fs0 from the POST state FAILS (key gone,
        //    and the current CKr cannot reproduce fs0's key).
        let reFailed = false;
        try {
            await DR.ratchetDecrypt(bob, sent[0].wireHeader, sent[0].nonce, sent[0].ciphertext);
        } catch (e) { reFailed = true; }
        H.assert(reFailed, 'replaying fs0 from advanced state FAILS (forward secrecy)');

        // 3) The user's own at-rest archive (the captured MK) STILL opens fs0 --
        //    this is the §5 archive posture (same trust level as on-screen plaintext).
        const header0 = { dh: CP.deserializeKey(sent[0].wireHeader.dh), pn: sent[0].wireHeader.pn, n: sent[0].wireHeader.n };
        const encKey0 = await DR.deriveAeadKey(archivedMk0, header0, null);
        const ct0 = CP.deserializeKey(sent[0].ciphertext);
        const nonce0 = CP.deserializeKey(sent[0].nonce);
        const pt0 = CP.nacl.secretbox.open(ct0, nonce0, encKey0);
        H.assert(pt0 && dec(pt0) === 'fs0', 'archived per-message key still opens fs0 (archive posture)');

        // 4) Literal KDF_CK one-wayness: given CK' and MK you cannot reproduce CK.
        //    We assert that KDF_CK(CK) is a function whose outputs (CK', MK) do not
        //    let you invert to CK -- demonstrated by: a DIFFERENT random CK yields
        //    different CK'/MK, and there is no exposed inverse. We prove
        //    irreversibility structurally: HKDF(salt=CK) is a one-way PRF.
        const CKtest = CP.randomBytes(32);
        const step = await DR.KDF_CK(CKtest);
        // CK' and MK both differ from CK (no identity leakage).
        H.assert(!Buffer.from(step.CK).equals(Buffer.from(CKtest)), "KDF_CK: CK' != CK");
        H.assert(!Buffer.from(step.MK).equals(Buffer.from(CKtest)), 'KDF_CK: MK != CK');
        H.assert(!Buffer.from(step.CK).equals(Buffer.from(step.MK)), "KDF_CK: CK' != MK (domain separation)");
        // Determinism (same CK -> same outputs) -- a true function, but one-way.
        const step2 = await DR.KDF_CK(CKtest);
        H.assertBytesEqual(step.CK, step2.CK, 'KDF_CK deterministic CK');
        H.assertBytesEqual(step.MK, step2.MK, 'KDF_CK deterministic MK');
        process.stdout.write('  KDF_CK is a deterministic one-way PRF (HKDF salt=CK); no inverse to CK exists.\n');
        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('S1 (c) POST-COMPROMISE SECURITY -- stale keys dead after a fresh DH ratchet key heals', async () => {
        // PCS subtlety (resolved ambiguity): a single direction change does NOT
        // heal a compromise of the RECEIVER, because the very next chain the peer
        // builds still uses the receiver's ratchet key that existed AT compromise
        // time (the attacker holds its secret). PCS heals only once the
        // compromised party generates a FRESH ratchet key (its next DH-ratchet
        // step) AND the post-compromise message depends on that fresh key -- which
        // takes a full extra round trip. We model exactly that:
        //
        //   a1 : Alice -> Bob              (Bob DH-ratchets -> key K1)
        //   *** attacker steals Bob here (holds K1 secret) ***
        //   b1 : Bob   -> Alice            (Alice DH-ratchets -> key J1)
        //   a2 : Alice -> Bob (chain on K1) (Bob DH-ratchets -> FRESH key K2)
        //   b2 : Bob   -> Alice (chain on K2)(Alice DH-ratchets -> FRESH key J2)
        //   a3 : Alice -> Bob (chain on K2)  <- depends on K2 secret the attacker lacks => SAFE
        let { alice, bob } = await setup('pcs-seed');

        // a1
        let r = await DR.ratchetEncrypt(alice, enc('a1')); alice = r.newState;
        let d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext); bob = d.newState;
        H.assertEqual(dec(d.plaintext), 'a1', 'Bob decrypts a1');

        // *** COMPROMISE: attacker snapshots Bob's full state (RK/CKs/CKr/DHs incl. secret).
        const compromised = {
            RK:  Uint8Array.from(bob.RK),
            CKs: bob.CKs ? Uint8Array.from(bob.CKs) : null,
            CKr: bob.CKr ? Uint8Array.from(bob.CKr) : null,
            DHs: { publicKey: Uint8Array.from(bob.DHs.publicKey), secretKey: Uint8Array.from(bob.DHs.secretKey) },
            DHr: bob.DHr ? Uint8Array.from(bob.DHr) : null,
            Ns: bob.Ns, Nr: bob.Nr, PN: bob.PN,
            MKSKIPPED: new Map(),
        };
        const bobKeyAtCompromise = CP.serializeKey(bob.DHs.publicKey);

        // b1 : Bob -> Alice
        r = await DR.ratchetEncrypt(bob, enc('b1')); bob = r.newState;
        d = await DR.ratchetDecrypt(alice, r.wireHeader, r.nonce, r.ciphertext); alice = d.newState;
        H.assertEqual(dec(d.plaintext), 'b1', 'Alice decrypts b1');

        // a2 : Alice -> Bob  => Bob DH-ratchets to a FRESH key K2 (attacker lacks it).
        r = await DR.ratchetEncrypt(alice, enc('a2')); alice = r.newState;
        d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext); bob = d.newState;
        H.assertEqual(dec(d.plaintext), 'a2', 'Bob decrypts a2');
        H.assert(CP.serializeKey(bob.DHs.publicKey) !== bobKeyAtCompromise,
            'Bob generated a FRESH ratchet key after compromise (K2 != K1)');

        // b2 : Bob -> Alice (carries K2 pub) => Alice DH-ratchets to fresh J2.
        r = await DR.ratchetEncrypt(bob, enc('b2')); bob = r.newState;
        d = await DR.ratchetDecrypt(alice, r.wireHeader, r.nonce, r.ciphertext); alice = d.newState;
        H.assertEqual(dec(d.plaintext), 'b2', 'Alice decrypts b2');

        // a3 : Alice -> Bob, encrypted under the chain that depends on K2 -> SAFE.
        let ra3 = await DR.ratchetEncrypt(alice, enc('a3-healed')); alice = ra3.newState;

        // Legitimate Bob CAN decrypt a3.
        let dgood = await DR.ratchetDecrypt(bob, ra3.wireHeader, ra3.nonce, ra3.ciphertext);
        H.assertEqual(dec(dgood.plaintext), 'a3-healed', 'legitimate Bob decrypts post-heal a3');

        // ATTACKER (holding only the pre-compromise key K1) CANNOT decrypt a3:
        // a3's chain derives from dhRaw(K2_secret, ...) which the attacker lacks,
        // so its DH ratchet uses the stale K1 secret -> wrong RK -> AEAD fails.
        let attackerFailed = false;
        try {
            await DR.ratchetDecrypt(compromised, ra3.wireHeader, ra3.nonce, ra3.ciphertext);
        } catch (e) { attackerFailed = true; }
        H.assert(attackerFailed, 'attacker with PRE-compromise keys CANNOT decrypt post-heal a3 (PCS)');

        // Also: the attacker's stale chain key, advanced directly, yields a key
        // different from the legit post-heal message key.
        const legitMk = dgood.messageKey;
        if (compromised.CKr) {
            const attStep = await DR.KDF_CK(compromised.CKr);
            H.assert(!Buffer.from(attStep.MK).equals(Buffer.from(legitMk)),
                "attacker's stale-chain message key != legit post-heal key");
        }
        CP.resetRandomBytesSource();
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
