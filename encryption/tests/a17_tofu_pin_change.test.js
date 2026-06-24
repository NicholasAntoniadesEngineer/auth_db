/**
 * A17 GATE -- FAIL-CLOSED TOFU PINNING LIFECYCLE.
 *
 * Run: node encryption/tests/a17_tofu_pin_change.test.js
 *
 * Locks the trust-on-first-use (TOFU) pin chokepoint in keyManagementService.js
 * at the _getPinnedPeerKey level directly (the single site both ECDH/X3DH paths
 * route through), plus the getPendingPeerIdentity conflict surface and the
 * acceptPeerIdentityChange escape hatch. This is COMPLEMENTARY to s8_fail_closed
 * (which drives the full two-party handshake under forged/swapped keys): here we
 * isolate the pin-store state machine itself so the fail-closed contract is
 * regression-locked at its source.
 *
 * Gates:
 *   (1) FIRST CONTACT pins the peer's published X25519 IK (TOFU) and returns it.
 *   (2) An UNCHANGED published key on a later call returns verbatim, pin untouched.
 *   (3) A SUBSEQUENT DIFFERENT published identity for the SAME peer is REJECTED
 *       fail-closed: _getPinnedPeerKey THROWS PeerIdentityChangedError and does
 *       NOT silently re-pin (the pinned value stays the ORIGINAL).
 *   (4) getPendingPeerIdentity surfaces the conflict (changed:true, old != new
 *       fingerprints + safety numbers) WITHOUT mutating the pin and WITHOUT
 *       throwing — and the chokepoint STILL throws afterwards (read-only escape).
 *   (5) acceptPeerIdentityChange is the ONLY way forward: after it re-pins to the
 *       currently-published key, the chokepoint returns the new key cleanly and
 *       getPendingPeerIdentity reports changed:false.
 *   (6) A peer with no published key at all returns null (no pin written).
 *
 * Determinism: identity keypair generation is routed through the seedable RNG.
 */

const H = require('./_harness.js');
const { makeFakeIndexedDB } = require('./_idb_shim.js');

// Install the IndexedDB globals BEFORE loading KeyStorageService.
const { indexedDB, IDBKeyRange } = makeFakeIndexedDB();
global.indexedDB = indexedDB;
global.IDBKeyRange = IDBKeyRange;

// Load nacl + WebCrypto + pure services via the existing harness.
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;

// Typed error class resolvable as a bare global (KMS references it unqualified).
const EncryptionErrors = require('../utils/encryptionErrors.js');
global.PeerIdentityChangedError = EncryptionErrors.PeerIdentityChangedError;
global.DecryptionError = EncryptionErrors.DecryptionError;

const KeyStorageService = require('../services/keyStorageService.js');
const KeyManagementService = require('../services/keyManagementService.js');
global.KeyStorageService = KeyStorageService;
global.KeyManagementService = KeyManagementService;

const ALICE_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; // us (pin owner)
const BOB_ID   = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'; // peer being pinned
const GHOST_ID = 'cccccccc-cccc-cccc-cccc-cccccccccccc'; // peer with no published key

// ---------------------------------------------------------------------------
// Mutable in-memory "server" for the peer's CURRENTLY published X25519 IK.
// HistoricalKeysService.getCurrentKey is the source _getPinnedPeerKey /
// getPendingPeerIdentity / acceptPeerIdentityChange read through. Flipping this
// map simulates a hostile server (or legitimate re-pair) changing the peer key.
// ---------------------------------------------------------------------------
const publishedKeys = new Map(); // userId -> base64 X25519 pub
global.HistoricalKeysService = {
    async getCurrentKey(uid) {
        return publishedKeys.get(uid) || null;
    }
};

function b64Of(keyPair) { return CP.serializeKey(keyPair.publicKey); }
function fpOf(b64) {
    return CP.getKeyFingerprint(CP.deserializeKey(b64));
}

async function main() {
    // --- our own identity (needed for getPendingPeerIdentity safety numbers) ---
    CP.setRandomBytesSource(H.makeDeterministicRng('identity|alice'));
    const aliceKeys = CP.generateKeyPair();
    CP.resetRandomBytesSource();

    // --- Bob's two distinct identities (original + a swapped/rotated one) ---
    CP.setRandomBytesSource(H.makeDeterministicRng('identity|bob-orig'));
    const bobOrig = CP.generateKeyPair();
    CP.resetRandomBytesSource();
    CP.setRandomBytesSource(H.makeDeterministicRng('identity|bob-new'));
    const bobNew = CP.generateKeyPair();
    CP.resetRandomBytesSource();

    const bobOrigB64 = b64Of(bobOrig);
    const bobNewB64 = b64Of(bobNew);
    H.assert(bobOrigB64 !== bobNewB64, 'precondition: two DISTINCT Bob identities');

    // --- per-test KeyStorageService instance (own IndexedDB) ---
    const storage = Object.create(KeyStorageService);
    storage.db = null; storage.initialized = false;
    await storage.initialize({ indexedDB: { name: 'A17-alice', version: 3 } });
    await storage.storeIdentityKeys(ALICE_ID, aliceKeys);
    global.KeyStorageService = storage;

    // --- KMS instance pinned to Alice as the local user ---
    const kms = Object.create(KeyManagementService);
    kms.currentUserId = ALICE_ID;
    kms.initialized = true;
    kms._database = {
        // acceptPeerIdentityChange re-pins IK_sig from the prekeys row; none here,
        // so it logs a benign warning and just re-pins the X25519 IK. That is the
        // path we lock (the IK_sig re-pin is covered by s8).
        async querySelect() { return { data: [], error: null }; }
    };
    kms._config = { tables: { prekeys: 'prekeys', identityKeys: 'identity_keys', publicKeyHistory: 'public_key_history' } };

    // =====================================================================
    // (1) FIRST CONTACT -> TOFU pin.
    // =====================================================================
    await H.gate('A17 (1) first contact pins the peer key (TOFU)', async () => {
        publishedKeys.set(BOB_ID, bobOrigB64);

        const before = await storage.getPinnedKey(BOB_ID);
        H.assert(!before, 'no pin exists before first contact');

        const got = await kms._getPinnedPeerKey(BOB_ID);
        H.assertEqual(got, bobOrigB64, 'first contact returns the published key');

        const pin = await storage.getPinnedKey(BOB_ID);
        H.assert(!!pin, 'a pin was written on first contact');
        H.assertEqual(pin.publicKey, bobOrigB64, 'pinned value == Bob original IK');
        H.assertEqual(pin.fingerprint, fpOf(bobOrigB64), 'pin fingerprint matches the key');
        process.stdout.write('  first contact -> TOFU-pinned Bob original IK.\n');
    });

    // =====================================================================
    // (2) UNCHANGED key on a later call -> verbatim, pin untouched.
    // =====================================================================
    await H.gate('A17 (2) unchanged published key returns verbatim, no re-pin churn', async () => {
        const pinBefore = await storage.getPinnedKey(BOB_ID);
        const got = await kms._getPinnedPeerKey(BOB_ID);
        H.assertEqual(got, bobOrigB64, 'unchanged key returned verbatim');
        const pinAfter = await storage.getPinnedKey(BOB_ID);
        H.assertEqual(pinAfter.publicKey, pinBefore.publicKey, 'pin value unchanged');
        H.assertEqual(pinAfter.fingerprint, pinBefore.fingerprint, 'pin fingerprint unchanged');
    });

    // =====================================================================
    // (3) SUBSEQUENT DIFFERENT identity -> REJECTED fail-closed, NOT re-pinned.
    // =====================================================================
    await H.gate('A17 (3) a changed peer identity is REJECTED fail-closed (not silently re-pinned)', async () => {
        // Hostile server swaps Bob's published key to a different identity.
        publishedKeys.set(BOB_ID, bobNewB64);

        let err = null;
        try { await kms._getPinnedPeerKey(BOB_ID); } catch (e) { err = e; }

        H.assert(!!err, '_getPinnedPeerKey THREW on a changed identity');
        H.assertEqual(err.name, 'PeerIdentityChangedError', 'error is PeerIdentityChangedError');
        H.assertEqual(err.code, 'PEER_IDENTITY_CHANGED', 'error carries PEER_IDENTITY_CHANGED code');
        H.assertEqual(err.keyType, 'identity', 'keyType is identity (X25519 IK)');
        H.assertEqual(err.userId, BOB_ID, 'error carries the peer userId');
        H.assertEqual(err.oldFingerprint, fpOf(bobOrigB64), 'oldFingerprint == original key');
        H.assertEqual(err.newFingerprint, fpOf(bobNewB64), 'newFingerprint == swapped key');
        H.assert(err.oldFingerprint !== err.newFingerprint, 'old != new fingerprint');

        // The pin was NOT silently advanced to the new (unverified) key.
        const pin = await storage.getPinnedKey(BOB_ID);
        H.assertEqual(pin.publicKey, bobOrigB64, 'pinned key is STILL the original (no silent re-pin)');
        H.assertEqual(pin.fingerprint, fpOf(bobOrigB64), 'pin fingerprint still the original');

        // It keeps throwing on repeat calls (the block is durable, one-shot warn aside).
        let again = null;
        try { await kms._getPinnedPeerKey(BOB_ID); } catch (e) { again = e; }
        H.assertEqual(again && again.code, 'PEER_IDENTITY_CHANGED', 'still fails closed on repeat');
        const pinStill = await storage.getPinnedKey(BOB_ID);
        H.assertEqual(pinStill.publicKey, bobOrigB64, 'pin STILL original after repeated throw');
        process.stdout.write('  changed identity -> PeerIdentityChangedError; pin unchanged.\n');
    });

    // =====================================================================
    // (4) getPendingPeerIdentity surfaces the conflict WITHOUT mutating/throwing,
    //     and the chokepoint STILL fails closed afterwards.
    // =====================================================================
    await H.gate('A17 (4) getPendingPeerIdentity surfaces the conflict (read-only, no re-pin)', async () => {
        const pending = await kms.getPendingPeerIdentity(BOB_ID);
        H.assertEqual(pending.userId, BOB_ID, 'pending report is for Bob');
        H.assert(pending.changed === true, 'pending.changed is true');
        H.assertEqual(pending.oldFingerprint, fpOf(bobOrigB64), 'pending oldFingerprint == pinned original');
        H.assertEqual(pending.newFingerprint, fpOf(bobNewB64), 'pending newFingerprint == published new');
        H.assert(!!pending.oldSafetyNumber && !!pending.newSafetyNumber, 'pending carries old + new safety numbers');
        H.assert(pending.oldSafetyNumber !== pending.newSafetyNumber, 'safety numbers differ');

        // Pure read: the pin was NOT mutated by surfacing the conflict.
        const pin = await storage.getPinnedKey(BOB_ID);
        H.assertEqual(pin.publicKey, bobOrigB64, 'getPendingPeerIdentity did NOT re-pin');

        // ...and the chokepoint STILL throws (surfacing != accepting).
        let stillBlocked = null;
        try { await kms._getPinnedPeerKey(BOB_ID); } catch (e) { stillBlocked = e; }
        H.assertEqual(stillBlocked && stillBlocked.code, 'PEER_IDENTITY_CHANGED', 'chokepoint still fails closed after surfacing');
        process.stdout.write('  conflict surfaced (old != new safety #); pin untouched; still fail-closed.\n');
    });

    // =====================================================================
    // (5) acceptPeerIdentityChange is the ONLY way forward.
    // =====================================================================
    await H.gate('A17 (5) acceptPeerIdentityChange is the ONLY way to unblock', async () => {
        const acc = await kms.acceptPeerIdentityChange(BOB_ID);
        H.assert(acc.accepted === true, 'acceptPeerIdentityChange reports accepted');
        H.assertEqual(acc.identityFingerprint, fpOf(bobNewB64), 'accept re-pinned to the new X25519 IK');

        // Pin now points at the new (verified) key.
        const pin = await storage.getPinnedKey(BOB_ID);
        H.assertEqual(pin.publicKey, bobNewB64, 'pin advanced to the new key after accept');
        H.assertEqual(pin.fingerprint, fpOf(bobNewB64), 'pin fingerprint == new key');

        // Chokepoint now returns the new key cleanly (no throw).
        const got = await kms._getPinnedPeerKey(BOB_ID);
        H.assertEqual(got, bobNewB64, 'chokepoint returns the new key cleanly post-accept');

        // getPendingPeerIdentity now reports no pending change.
        const pending = await kms.getPendingPeerIdentity(BOB_ID);
        H.assert(pending.changed === false, 'no pending change after accept');
        H.assertEqual(pending.oldFingerprint, fpOf(bobNewB64), 'pending old == new (converged)');
        H.assertEqual(pending.newFingerprint, fpOf(bobNewB64), 'pending new == published');
        process.stdout.write('  accept -> pin advanced -> chokepoint clears; no other path unblocked it.\n');
    });

    // =====================================================================
    // (6) A peer with NO published key -> null, no pin written.
    // =====================================================================
    await H.gate('A17 (6) a peer with no published key returns null (no pin)', async () => {
        H.assert(!publishedKeys.has(GHOST_ID), 'ghost peer has no published key');
        const got = await kms._getPinnedPeerKey(GHOST_ID);
        H.assertEqual(got, null, '_getPinnedPeerKey returns null for an unpublished peer');
        const pin = await storage.getPinnedKey(GHOST_ID);
        H.assert(!pin, 'no pin written for an unpublished peer');
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\n*** A17 SUITE CRASHED: ' + (e && e.stack || e) + '\n');
    process.exitCode = 1;
});
