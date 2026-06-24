/**
 * A16 GATES -- Double Ratchet REPLAY / REORDER integrity (regression locks).
 *
 * Run: node encryption/tests/a16_replay_reorder.test.js
 *
 * Complements s1_double_ratchet.test.js (which locks the transcript KAT, basic
 * out-of-order, MAX_SKIP fail-closed, forward secrecy, PCS). This file pins the
 * REPLAY/REORDER attack surface specifically, against the REAL committed
 * doubleRatchetService.js behavior:
 *
 *   (a) REPLAY of an already-decrypted in-order message is rejected -- the chain
 *       advanced past it, the key is gone, and re-delivery fails closed (AEAD
 *       auth failure). The replay does NOT yield the plaintext a second time.
 *
 *   (b) REPLAY of an already-consumed SKIPPED (out-of-order) message key is
 *       rejected -- skipped keys are consume-once (deleted on first use), so a
 *       captured-and-replayed out-of-order frame fails closed. Other genuinely
 *       still-skipped keys remain deliverable (replay rejection is targeted, not
 *       a denial of the whole chain).
 *
 *   (c) The per-advance skip bound (MAX_SKIP) is ENFORCED: a header demanding
 *       more skips than the cap is REJECTED with NO allocation (the skipped map
 *       does not grow) -- guards against unbounded-allocation DoS via a forged n.
 *
 *   (d) The TOTAL live-skipped-key cap (MAX_SKIPPED_TOTAL) is ENFORCED across
 *       multiple DH-ratchet steps: skipped keys accumulate across chains but the
 *       map is bounded by eviction of the OLDEST entries -- it never exceeds the
 *       cap, so a long-lived conversation cannot grow the state blob unbounded.
 *
 *   (e) Legitimate in-order delivery AND bounded out-of-order delivery (a few
 *       reordered frames within MAX_SKIP) still decrypt correctly -- the replay
 *       hardening does not break honest reorder tolerance.
 *
 * These are REGRESSION LOCKS on committed behavior, not aspirational asserts.
 * All randomness is frozen via the S0 RNG seam so the runs are reproducible.
 */

const H = require('./_harness.js');
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;
const DR = svc.DoubleRatchetService;

function enc(str) { return new TextEncoder().encode(str); }
function dec(bytes) { return new TextDecoder().decode(bytes); }

/**
 * Fresh, deterministic Alice/Bob pair sharing an X3DH root SK and Bob's ratchet
 * (= signed-prekey) keypair. Everything frozen by `seed` (mirrors s1's setup).
 */
async function setup(seed) {
    CP.setRandomBytesSource(H.makeDeterministicRng(seed));
    const SK = CP.randomBytes(32);
    const bobRatchet = CP.generateKeyPair();
    const alice = await DR.ratchetInitAlice(SK, bobRatchet.publicKey);
    const bob = await DR.ratchetInitBob(SK, bobRatchet);
    return { alice, bob };
}

async function main() {
    // =====================================================================
    await H.gate('A16 (a) REPLAY of an in-order message is rejected (key gone, fail closed)', async () => {
        let { alice, bob } = await setup('a16-replay-inorder');

        const r0 = await DR.ratchetEncrypt(alice, enc('secret-0')); alice = r0.newState;
        const r1 = await DR.ratchetEncrypt(alice, enc('secret-1')); alice = r1.newState;

        // First legitimate decrypt succeeds.
        const d0 = await DR.ratchetDecrypt(bob, r0.wireHeader, r0.nonce, r0.ciphertext);
        bob = d0.newState;
        H.assertEqual(dec(d0.plaintext), 'secret-0', 'first decrypt of msg 0 yields plaintext');

        // Advance the chain past msg 0 (decrypt msg 1 in order).
        const d1 = await DR.ratchetDecrypt(bob, r1.wireHeader, r1.nonce, r1.ciphertext);
        bob = d1.newState;
        H.assertEqual(dec(d1.plaintext), 'secret-1', 'in-order decrypt of msg 1 yields plaintext');

        // Msg 0's key is NOT retained in the skipped store (it was consumed in
        // order, never skipped) and Nr advanced past it -> unrecoverable.
        const insp = DR._inspectState(bob);
        H.assert(!insp.hasSkipped(r0.wireHeader.dh, 0), 'msg 0 key absent from skipped store after in-order consume');
        H.assert(insp.Nr >= 2, 'receive counter advanced past msg 0 and msg 1');

        // REPLAY msg 0 from the advanced state: must FAIL and must NOT return plaintext.
        let replayThrew = false;
        let leaked = null;
        try {
            const dr = await DR.ratchetDecrypt(bob, r0.wireHeader, r0.nonce, r0.ciphertext);
            leaked = dec(dr.plaintext);
        } catch (e) { replayThrew = true; }
        H.assert(replayThrew, 'replaying already-consumed in-order msg 0 throws (fail closed)');
        H.assert(leaked === null, 'replay did NOT yield the plaintext a second time');

        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('A16 (b) REPLAY of a consumed SKIPPED key is rejected; other skipped keys survive', async () => {
        let { alice, bob } = await setup('a16-replay-skipped');

        // Alice sends m0,m1,m2 in order; Bob will receive m1 FIRST (skips m0).
        const sent = [];
        for (let i = 0; i < 3; i++) {
            const r = await DR.ratchetEncrypt(alice, enc('m' + i));
            alice = r.newState;
            sent.push(r);
        }

        // Deliver m1 out of order -> m0's key is stored as a skipped key.
        const dm1 = await DR.ratchetDecrypt(bob, sent[1].wireHeader, sent[1].nonce, sent[1].ciphertext);
        bob = dm1.newState;
        H.assertEqual(dec(dm1.plaintext), 'm1', 'out-of-order decrypt of m1');

        // m1's own key was consumed (it was the live chain head when delivered),
        // and m0's key is now skipped/stored.
        const insp1 = DR._inspectState(bob);
        H.assert(insp1.hasSkipped(sent[0].wireHeader.dh, 0), 'm0 key stored as skipped after m1 delivered first');

        // REPLAY m1: the skipped store does not contain m1 (it was consumed in the
        // live chain) and Nr advanced past it -> fails closed, no plaintext.
        let replay1Threw = false;
        let leaked1 = null;
        try {
            const dr = await DR.ratchetDecrypt(bob, sent[1].wireHeader, sent[1].nonce, sent[1].ciphertext);
            leaked1 = dec(dr.plaintext);
        } catch (e) { replay1Threw = true; }
        H.assert(replay1Threw, 'replaying m1 throws (fail closed)');
        H.assert(leaked1 === null, 'replayed m1 did NOT yield plaintext again');

        // The GENUINELY still-skipped m0 is unaffected -- targeted rejection, not
        // a whole-chain denial.
        const dm0 = await DR.ratchetDecrypt(bob, sent[0].wireHeader, sent[0].nonce, sent[0].ciphertext);
        bob = dm0.newState;
        H.assertEqual(dec(dm0.plaintext), 'm0', 'still-skipped m0 decrypts after the m1 replay attempt');

        // m0 is consume-once too: replaying it now (already consumed from the
        // skipped store) fails closed.
        let replay0Threw = false;
        let leaked0 = null;
        try {
            const dr = await DR.ratchetDecrypt(bob, sent[0].wireHeader, sent[0].nonce, sent[0].ciphertext);
            leaked0 = dec(dr.plaintext);
        } catch (e) { replay0Threw = true; }
        H.assert(replay0Threw, 'replaying the now-consumed skipped m0 throws (consume-once)');
        H.assert(leaked0 === null, 'replayed m0 did NOT yield plaintext again');

        const insp2 = DR._inspectState(bob);
        H.assert(!insp2.hasSkipped(sent[0].wireHeader.dh, 0), 'm0 key deleted from skipped store after its single use');

        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('A16 (c) header demanding > MAX_SKIP is REJECTED with NO allocation', async () => {
        let { alice, bob } = await setup('a16-maxskip');

        // Establish a receive chain on Bob (msg 0).
        const first = await DR.ratchetEncrypt(alice, enc('start')); alice = first.newState;
        const d0 = await DR.ratchetDecrypt(bob, first.wireHeader, first.nonce, first.ciphertext);
        bob = d0.newState;

        const sizeBefore = DR._inspectState(bob).skippedCount;

        // Forge a header on the SAME ratchet pub with n far beyond MAX_SKIP.
        const nxt = await DR.ratchetEncrypt(alice, enc('forged')); // real n = 1
        const forged = Object.assign({}, nxt.wireHeader, { n: DR.MAX_SKIP + 5 });

        let rejected = false;
        let maxSkipMsg = false;
        try {
            await DR.ratchetDecrypt(bob, forged, nxt.nonce, nxt.ciphertext);
        } catch (e) {
            rejected = true;
            maxSkipMsg = /MAX_SKIP/.test(e.message);
        }
        H.assert(rejected, 'header with n > MAX_SKIP is rejected (fail closed)');
        H.assert(maxSkipMsg, 'rejection cites MAX_SKIP (refused before allocating skipped keys)');

        // The skipped map did NOT grow -- no unbounded allocation from a forged n.
        const sizeAfter = DR._inspectState(bob).skippedCount;
        H.assertEqual(sizeAfter, sizeBefore, 'skipped map did NOT grow on the rejected over-cap header');

        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('A16 (d) MAX_SKIPPED_TOTAL bounds the live skipped map across DH ratchets', async () => {
        // Accumulate skipped keys across multiple DH-ratchet steps. Each chain we
        // make Alice skip a large block of Bob's messages (< MAX_SKIP per chain),
        // then flip direction (a DH ratchet) and repeat. Without the TOTAL cap the
        // map would grow without bound; with it, the map is held at MAX_SKIPPED_TOTAL
        // by evicting the OLDEST entries.
        H.assert(DR.MAX_SKIPPED_TOTAL > DR.MAX_SKIP,
            'MAX_SKIPPED_TOTAL > MAX_SKIP (total cap is reachable only by accumulating across chains)');

        let { alice, bob } = await setup('a16-totalcap');

        // Bootstrap a receive chain on Alice (Bob must send first so Alice has CKr).
        let m = await DR.ratchetEncrypt(alice, enc('a-hello')); alice = m.newState;
        let dd = await DR.ratchetDecrypt(bob, m.wireHeader, m.nonce, m.ciphertext); bob = dd.newState;

        const PER_CHAIN = 800; // < MAX_SKIP (1000) so each chain advance is legal
        const CHAINS = 4;      // 4 * 800 = 3200 attempted skips >> 2000 cap

        let maxSeen = 0;
        for (let chain = 0; chain < CHAINS; chain++) {
            // Bob sends PER_CHAIN messages; Alice receives only the LAST one,
            // forcing PER_CHAIN-1 skips on the current receive chain.
            let last = null;
            for (let i = 0; i < PER_CHAIN; i++) {
                const e = await DR.ratchetEncrypt(bob, enc('b' + chain + '_' + i));
                bob = e.newState;
                if (i === PER_CHAIN - 1) last = e;
            }
            const dr = await DR.ratchetDecrypt(alice, last.wireHeader, last.nonce, last.ciphertext);
            alice = dr.newState;

            const insp = DR._inspectState(alice);
            maxSeen = Math.max(maxSeen, insp.skippedCount);
            H.assert(insp.skippedCount <= DR.MAX_SKIPPED_TOTAL,
                `after chain ${chain}: skippedCount (${insp.skippedCount}) <= MAX_SKIPPED_TOTAL`);

            // Flip direction: Alice replies, Bob receives -> next round is a fresh
            // DH ratchet (new chain), so skipped entries accumulate across chains.
            const ar = await DR.ratchetEncrypt(alice, enc('a-reply' + chain)); alice = ar.newState;
            const bdr = await DR.ratchetDecrypt(bob, ar.wireHeader, ar.nonce, ar.ciphertext); bob = bdr.newState;
        }

        // The cap was actually exercised: the map reached MAX_SKIPPED_TOTAL and was
        // held there (it did not blow past it across 3200 attempted skips).
        H.assertEqual(maxSeen, DR.MAX_SKIPPED_TOTAL,
            'live skipped map reaches exactly MAX_SKIPPED_TOTAL and is bounded there (eviction enforced)');

        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('A16 (e) legitimate in-order + bounded out-of-order still decrypts', async () => {
        let { alice, bob } = await setup('a16-legit');

        // Pure in-order delivery: every message decrypts.
        const inorder = [];
        for (let i = 0; i < 5; i++) {
            const r = await DR.ratchetEncrypt(alice, enc('io' + i));
            alice = r.newState;
            inorder.push(r);
        }
        for (let i = 0; i < 5; i++) {
            const d = await DR.ratchetDecrypt(bob, inorder[i].wireHeader, inorder[i].nonce, inorder[i].ciphertext);
            bob = d.newState;
            H.assertEqual(dec(d.plaintext), 'io' + i, `in-order decrypt io${i}`);
        }
        H.assertEqual(DR._inspectState(bob).skippedCount, 0, 'no skipped keys after pure in-order delivery');

        // Bounded out-of-order across a DH-ratchet boundary: Bob replies (direction
        // change -> DH ratchet on Alice), then Alice sends a small batch delivered
        // reordered. All decrypt; skipped keys are all consumed (none left over).
        const rb = await DR.ratchetEncrypt(bob, enc('b-reply')); bob = rb.newState;
        const db = await DR.ratchetDecrypt(alice, rb.wireHeader, rb.nonce, rb.ciphertext); alice = db.newState;
        H.assertEqual(dec(db.plaintext), 'b-reply', 'Alice decrypts across direction change');

        const batch = [];
        for (let i = 0; i < 4; i++) {
            const r = await DR.ratchetEncrypt(alice, enc('ooo' + i));
            alice = r.newState;
            batch.push(r);
        }
        // Deliver reordered (bounded: a handful of frames within MAX_SKIP).
        for (const idx of [2, 0, 3, 1]) {
            const d = await DR.ratchetDecrypt(bob, batch[idx].wireHeader, batch[idx].nonce, batch[idx].ciphertext);
            bob = d.newState;
            H.assertEqual(dec(d.plaintext), 'ooo' + idx, `bounded out-of-order decrypt ooo${idx}`);
        }
        const insp = DR._inspectState(bob);
        H.assert(insp.skippedCount <= DR.MAX_SKIP, '|MKSKIPPED| within MAX_SKIP during bounded reorder');
        H.assertEqual(insp.skippedCount, 0, 'all skipped keys consumed exactly once after bounded reorder');

        CP.resetRandomBytesSource();
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
