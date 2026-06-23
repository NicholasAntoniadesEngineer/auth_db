/**
 * S12 GATES -- ATTACHMENT KEY RATCHET-INVARIANCE + CONTEXT BINDING (audit W3-2).
 *
 * Run: node encryption/tests/s12_attachment_key_invariance.test.js
 *
 * Background (the bug being fixed): the attachment file-key was wrapped under a KEK
 * derived from the LIVE ratchet root key `state.RK`. RK rotates on every DH-ratchet
 * step, so an attachment wrapped before a step became permanently undecryptable
 * (a peer could force this with a single message). The fix re-roots the attachment
 * KEK on `state.AK0` -- an INVARIANT secret minted once at X3DH bootstrap from the
 * shared secret SK (DoubleRatchetService.ratchetInit*), carried unchanged through
 * every clone/serialize, and never advanced by the ratchet. Context (conversation id
 * + storage path) is bound by folding it into the HKDF `info` (secretbox takes no
 * AAD), so a wrapped key cannot be lifted onto another attachment row.
 *
 * Gates:
 *   (1) AK0 is minted identically on BOTH sides at bootstrap (interop) and is
 *       present + 32 bytes.
 *   (2) INVARIANCE: the AK0-rooted attachment KEK derived BEFORE a DH-ratchet step
 *       equals the one derived AFTER the step -> the W3-2 break is closed. AND the
 *       legacy RK-rooted KEK DIFFERS across the step (proves the original defect and
 *       that the new key is genuinely ratchet-independent).
 *   (3) END-TO-END: a file key wrapped at "upload time" (t0) still unwraps after the
 *       ratchet has advanced (t1) using the recipient's post-step state.
 *   (4) CONTEXT BINDING: keys bound to different (conversation, path) contexts differ,
 *       and a file key wrapped under context A fails to unwrap under context B.
 *
 * All randomness frozen via the S0 RNG seam.
 */

const H = require('./_harness.js');
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;
const KDF = svc.KeyDerivationService;
const DR = svc.DoubleRatchetService;

function enc(str) { return new TextEncoder().encode(str); }

// Mirror of KeyManagementService.getSessionKey's TWO derivations so the gate proves
// the exact algorithm the production code uses (kept in lockstep with that method).
async function attachmentKEK_v2(state, conversationId, attachmentPath) {
    const info = `MoneyTracker:Attachment:v2|conv=${conversationId}|path=${attachmentPath}`;
    return await KDF._hkdf(state.AK0, info, 32, state.AK0);
}
async function attachmentKEK_legacy(state) {
    return await KDF._hkdf(state.RK, 'MoneyTracker:Attachment:v1', 32, state.RK);
}

async function setup(seed) {
    CP.setRandomBytesSource(H.makeDeterministicRng(seed));
    const SK = CP.randomBytes(32);
    const bobRatchet = CP.generateKeyPair();
    let alice = await DR.ratchetInitAlice(SK, bobRatchet.publicKey);
    let bob = await DR.ratchetInitBob(SK, bobRatchet);
    return { alice, bob, SK, bobRatchet };
}

async function main() {
    // =====================================================================
    await H.gate('S12 (1) AK0 minted identically on both sides at bootstrap', async () => {
        const { alice, bob } = await setup('ak0-bootstrap-seed');
        H.assert(alice.AK0 instanceof Uint8Array && alice.AK0.length === 32, 'Alice AK0 is 32 bytes');
        H.assert(bob.AK0 instanceof Uint8Array && bob.AK0.length === 32, 'Bob AK0 is 32 bytes');
        H.assertBytesEqual(alice.AK0, bob.AK0, 'AK0 identical on both sides (interop)');
        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('S12 (2) INVARIANCE across a DH-ratchet step (AK0 stable, RK rotates)', async () => {
        let { alice, bob } = await setup('ak0-invariance-seed');
        const conv = 4242;
        const path = `${conv}/1700000000-abc123`;

        // t0: "upload time" -- derive the KEK from the current state.
        const akBefore = await attachmentKEK_v2(alice, conv, path);
        const rkBefore = await attachmentKEK_legacy(alice);
        const rk0 = Uint8Array.from(alice.RK);

        // Drive a FULL DH-ratchet step: Alice sends, Bob receives (Bob DH-ratchets),
        // then Bob sends and Alice receives (Alice DH-ratchets) -> both RKs advance.
        let r = await DR.ratchetEncrypt(alice, enc('A1')); alice = r.newState;
        let d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext); bob = d.newState;
        r = await DR.ratchetEncrypt(bob, enc('B1')); bob = r.newState;
        d = await DR.ratchetDecrypt(alice, r.wireHeader, r.nonce, r.ciphertext); alice = d.newState;

        // Precondition: RK actually rotated (otherwise the gate proves nothing).
        H.assert(!Buffer.from(alice.RK).equals(Buffer.from(rk0)), 'precondition: RK advanced after the ratchet step');

        // t1: "download time" -- re-derive from the ADVANCED state.
        const akAfter = await attachmentKEK_v2(alice, conv, path);
        const rkAfter = await attachmentKEK_legacy(alice);

        // THE FIX: AK0-rooted KEK is invariant across the step.
        H.assertBytesEqual(akBefore, akAfter, 'AK0-rooted attachment KEK is INVARIANT across the ratchet step');
        // THE BUG (legacy): RK-rooted KEK changed -> would have lost the attachment.
        H.assert(!Buffer.from(rkBefore).equals(Buffer.from(rkAfter)),
            'legacy RK-rooted KEK CHANGED across the step (the W3-2 defect we retired)');
        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('S12 (3) END-TO-END: file key wrapped at t0 unwraps after the ratchet advances', async () => {
        let { alice, bob } = await setup('ak0-e2e-seed');
        const conv = 77;
        const path = `${conv}/1700000001-def456`;

        // Alice "uploads": random file key wrapped under the t0 AK0-rooted KEK.
        const fileKey = CP.randomBytes(32);
        const kekUpload = await attachmentKEK_v2(alice, conv, path);
        const { ciphertext, nonce } = CP.encryptBytes(fileKey, kekUpload);

        // A ratchet step happens between upload and download (peer forces it).
        let r = await DR.ratchetEncrypt(alice, enc('m')); alice = r.newState;
        let d = await DR.ratchetDecrypt(bob, r.wireHeader, r.nonce, r.ciphertext); bob = d.newState;
        r = await DR.ratchetEncrypt(bob, enc('n')); bob = r.newState;
        d = await DR.ratchetDecrypt(alice, r.wireHeader, r.nonce, r.ciphertext); alice = d.newState;

        // Bob "downloads" using HIS post-step state -> must still recover the file key.
        const kekDownload = await attachmentKEK_v2(bob, conv, path);
        const recovered = CP.decryptBytes(ciphertext, nonce, kekDownload);
        H.assertBytesEqual(recovered, fileKey, 'recipient recovers the file key AFTER a ratchet step');
        CP.resetRandomBytesSource();
    });

    // =====================================================================
    await H.gate('S12 (4) CONTEXT BINDING: a wrapped key does not transfer to another row', async () => {
        const { alice } = await setup('ak0-binding-seed');
        const conv = 9;
        const pathA = `${conv}/1700000002-aaaa`;
        const pathB = `${conv}/1700000003-bbbb`;

        const kekA = await attachmentKEK_v2(alice, conv, pathA);
        const kekB = await attachmentKEK_v2(alice, conv, pathB);
        const kekOtherConv = await attachmentKEK_v2(alice, conv + 1, pathA);

        H.assert(!Buffer.from(kekA).equals(Buffer.from(kekB)), 'different storage paths -> different KEK');
        H.assert(!Buffer.from(kekA).equals(Buffer.from(kekOtherConv)), 'different conversation -> different KEK');

        // A file key wrapped under context A must NOT unwrap under context B.
        const fileKey = CP.randomBytes(32);
        const { ciphertext, nonce } = CP.encryptBytes(fileKey, kekA);
        H.assertThrows(() => CP.decryptBytes(ciphertext, nonce, kekB),
            'file key wrapped for path A fails to unwrap under path B (context binding holds)');
        // ...but unwraps fine under the matching context.
        const ok = CP.decryptBytes(ciphertext, nonce, kekA);
        H.assertBytesEqual(ok, fileKey, 'matching context unwraps the file key');
        CP.resetRandomBytesSource();
    });

    H.summary();
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
