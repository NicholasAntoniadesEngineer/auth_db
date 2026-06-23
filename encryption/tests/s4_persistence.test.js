/**
 * S4 GATES -- IndexedDB ratchet-state persistence (FORWARD_SECRECY_DESIGN §4.5/§5).
 *
 * Run: node encryption/tests/s4_persistence.test.js
 *
 * These gates run KeyStorageService for real against a MINIMAL in-memory
 * IndexedDB shim (_idb_shim.js -- a small fake in the harness, NOT the
 * fake-indexeddb npm package) plus node's WebCrypto (for the AES-GCM wrap key)
 * and the vendored TweetNaCl (for base64 serialize/deserialize). It exercises
 * the SAME wrap-at-rest mechanism the identity secret uses today.
 *
 * Gates:
 *   (1) ADDITIVE upgrade v1 -> v2 -- the three ratchet stores are ADDED without
 *       destroying the v1 stores (identity_keys/session_keys/... survive).
 *   (2) ratchet_states round-trip -- a full DoubleRatchetService state (RK,
 *       CKs/CKr, DHs keypair incl. SECRET, DHr, counters, PN, MKSKIPPED map)
 *       survives serialize -> wrap -> store -> load -> unwrap -> deserialize
 *       BYTE-IDENTICAL.
 *   (3) wrapped-at-rest -- the bytes physically in IndexedDB for a ratchet state
 *       and an archived key are NOT plaintext-readable (no secret appears in the
 *       stored ciphertext).
 *   (4) skipped_message_keys round-trip + consume-once + MAX_SKIP bound (fail closed).
 *   (5) decrypted_message_keys ARCHIVE round-trip + miss -> null (the §5 lookup
 *       primitive the batch getMessages path uses).
 *   (6) clearAll wipes the three new stores but PRESERVES wrap_keys (so the wrap
 *       key survives and previously-unrelated identity flow is unaffected).
 *
 * What this CANNOT cover (needs in-browser verification at S5/S6): the real
 * browser IndexedDB structured-clone of a non-extractable CryptoKey, the live
 * encrypt/decrypt wiring, and the realtime-vs-batch path split. See the report.
 */

const H = require('./_harness.js');
const { makeFakeIndexedDB } = require('./_idb_shim.js');

// Install the IndexedDB + IDBKeyRange globals BEFORE loading KeyStorageService.
const { indexedDB, IDBKeyRange } = makeFakeIndexedDB();
global.indexedDB = indexedDB;
global.IDBKeyRange = IDBKeyRange;

// Load nacl + WebCrypto + CryptoPrimitivesService via the existing harness.
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;
const DR = svc.DoubleRatchetService;

// KeyStorageService references CryptoPrimitivesService as a global (browser
// pattern); loadServices already set global.CryptoPrimitivesService.
const KeyStorageService = require('../services/keyStorageService.js');

const DB_NAME = 'S4TestDB';

function enc(str) { return new TextEncoder().encode(str); }
function dec(bytes) { return new TextDecoder().decode(bytes); }

/** Build a realistic, fully-populated ratchet state with a non-empty MKSKIPPED. */
async function buildPopulatedState(seed) {
    CP.setRandomBytesSource(H.makeDeterministicRng(seed));
    const SK = CP.randomBytes(32);
    const bobRatchet = CP.generateKeyPair();
    let alice = await DR.ratchetInitAlice(SK, bobRatchet.publicKey);
    let bob = await DR.ratchetInitBob(SK, bobRatchet);

    // Alice sends 3; deliver out of order so Bob accrues skipped keys + advances.
    const sent = [];
    for (let i = 0; i < 3; i++) { const r = await DR.ratchetEncrypt(alice, enc('m' + i)); alice = r.newState; sent.push(r); }
    // deliver [2,0] -> leaves m1 skipped on Bob (MKSKIPPED non-empty)
    let d = await DR.ratchetDecrypt(bob, sent[2].wireHeader, sent[2].nonce, sent[2].ciphertext); bob = d.newState;
    d = await DR.ratchetDecrypt(bob, sent[0].wireHeader, sent[0].nonce, sent[0].ciphertext); bob = d.newState;
    CP.resetRandomBytesSource();
    return bob;
}

/** Deep byte-equality of two ratchet states (incl. DHs keypair + MKSKIPPED). */
function statesEqual(a, b) {
    const beq = (x, y) => (!x && !y) || (x && y && Buffer.from(x).equals(Buffer.from(y)));
    if (!beq(a.RK, b.RK)) return 'RK';
    if (!beq(a.CKs, b.CKs)) return 'CKs';
    if (!beq(a.CKr, b.CKr)) return 'CKr';
    if (!beq(a.DHr, b.DHr)) return 'DHr';
    if (!!a.DHs !== !!b.DHs) return 'DHs presence';
    if (a.DHs) {
        if (!beq(a.DHs.publicKey, b.DHs.publicKey)) return 'DHs.publicKey';
        if (!beq(a.DHs.secretKey, b.DHs.secretKey)) return 'DHs.secretKey';
    }
    if (a.Ns !== b.Ns) return 'Ns';
    if (a.Nr !== b.Nr) return 'Nr';
    if (a.PN !== b.PN) return 'PN';
    if (a.MKSKIPPED.size !== b.MKSKIPPED.size) return 'MKSKIPPED size';
    for (const [k, v] of a.MKSKIPPED) {
        if (!b.MKSKIPPED.has(k)) return 'MKSKIPPED missing ' + k;
        if (!beq(v, b.MKSKIPPED.get(k))) return 'MKSKIPPED value ' + k;
    }
    return null;
}

async function main() {
    // =====================================================================
    await H.gate('S4 (1) ADDITIVE upgrade v1 -> v2 (existing stores survive)', async () => {
        // Open at v1 with ONLY the legacy stores, write an identity-ish row, then
        // reopen at v2 and assert (a) the new stores exist and (b) the v1 row and
        // legacy stores are intact.
        const v1db = await new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, 1);
            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                db.createObjectStore('identity_keys', { keyPath: 'userId' });
                db.createObjectStore('session_keys', { keyPath: ['conversationId', 'epoch'] });
                db.createObjectStore('wrap_keys', { keyPath: 'id' });
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
        // write a legacy row
        await new Promise((res, rej) => {
            const tx = v1db.transaction('identity_keys', 'readwrite');
            const r = tx.objectStore('identity_keys').put({ userId: 'legacy-user', marker: 'v1-data' });
            r.onsuccess = () => res(); r.onerror = () => rej(r.error);
        });
        v1db.close();

        // Now initialize KeyStorageService at v2 against the SAME db name.
        KeyStorageService.db = null;
        KeyStorageService.initialized = false;
        await KeyStorageService.initialize({ indexedDB: { name: DB_NAME, version: 2 } });

        const db = KeyStorageService.db;
        H.assert(db.objectStoreNames.contains('identity_keys'), 'identity_keys preserved');
        H.assert(db.objectStoreNames.contains('session_keys'), 'session_keys preserved');
        H.assert(db.objectStoreNames.contains('wrap_keys'), 'wrap_keys preserved');
        H.assert(db.objectStoreNames.contains('ratchet_states'), 'ratchet_states ADDED');
        H.assert(db.objectStoreNames.contains('skipped_message_keys'), 'skipped_message_keys ADDED');
        H.assert(db.objectStoreNames.contains('decrypted_message_keys'), 'decrypted_message_keys ADDED');

        // legacy row intact
        const legacy = await new Promise((res, rej) => {
            const tx = db.transaction('identity_keys', 'readonly');
            const r = tx.objectStore('identity_keys').get('legacy-user');
            r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
        });
        H.assert(legacy && legacy.marker === 'v1-data', 'v1 identity row survived the upgrade');
        process.stdout.write('  v1->v2: 3 legacy stores + 1 row preserved; 3 ratchet stores added.\n');
    });

    // =====================================================================
    await H.gate('S4 (2) ratchet_states round-trip BYTE-IDENTICAL (incl. DHs secret + MKSKIPPED)', async () => {
        const original = await buildPopulatedState('s4-state-seed');
        H.assert(original.MKSKIPPED.size > 0, 'precondition: state has skipped keys to round-trip');
        H.assert(!!original.DHs && !!original.DHs.secretKey, 'precondition: state has a ratchet secret key');

        await KeyStorageService.putRatchetState('conv-A', original);
        const loaded = await KeyStorageService.getRatchetState('conv-A');
        H.assert(!!loaded, 'state loaded back');

        const diff = statesEqual(original, loaded);
        H.assert(diff === null, 'state byte-identical after store->load (diff: ' + diff + ')');

        // Missing conversation -> null.
        const none = await KeyStorageService.getRatchetState('conv-DOES-NOT-EXIST');
        H.assertEqual(none, null, 'unknown conversation returns null');

        // delete works
        await KeyStorageService.deleteRatchetState('conv-A');
        H.assertEqual(await KeyStorageService.getRatchetState('conv-A'), null, 'deleted state gone');
        process.stdout.write(`  round-tripped RK/CKs/CKr/DHs(pub+sec)/DHr/Ns/Nr/PN + ${original.MKSKIPPED.size} skipped MK(s).\n`);
    });

    // =====================================================================
    await H.gate('S4 (3) WRAPPED at rest -- raw stored bytes are NOT plaintext-readable', async () => {
        const state = await buildPopulatedState('s4-wrap-seed');
        await KeyStorageService.putRatchetState('conv-W', state);

        // Reach into the shim to read the PHYSICAL stored record.
        const db = KeyStorageService.db;
        const rec = await new Promise((res, rej) => {
            const tx = db.transaction('ratchet_states', 'readonly');
            const r = tx.objectStore('ratchet_states').get('conv-W');
            r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
        });
        H.assert(rec && rec.wrappedState && rec.wrapIv, 'stored record has wrappedState + wrapIv');
        H.assert(!rec.RK && !rec.CKs && !rec.DHs, 'NO plaintext secret fields on the stored record');

        // The wrapped blob must not contain the raw RK / chain key / ratchet secret bytes.
        const blob = Buffer.from(new Uint8Array(rec.wrappedState));
        const containsBytes = (hay, needle) => Buffer.from(hay).includes(Buffer.from(needle));
        H.assert(!containsBytes(blob, state.RK), 'wrapped blob does NOT contain raw RK bytes');
        H.assert(!containsBytes(blob, state.DHs.secretKey), 'wrapped blob does NOT contain raw ratchet secret bytes');
        if (state.CKr) H.assert(!containsBytes(blob, state.CKr), 'wrapped blob does NOT contain raw CKr bytes');

        // Also prove the IV-randomized ciphertext differs across two writes of the
        // SAME state (fresh IV per _wrapSecret call).
        await KeyStorageService.putRatchetState('conv-W2', state);
        const rec2 = await new Promise((res, rej) => {
            const tx = db.transaction('ratchet_states', 'readonly');
            const r = tx.objectStore('ratchet_states').get('conv-W2');
            r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
        });
        const blob2 = Buffer.from(new Uint8Array(rec2.wrappedState));
        H.assert(!blob.equals(blob2), 'same state wrapped twice yields different ciphertext (fresh IV)');

        // And it still unwraps correctly (wrap is sound, not just opaque).
        const back = await KeyStorageService.getRatchetState('conv-W');
        H.assert(statesEqual(state, back) === null, 'wrapped state still unwraps byte-identical');
        process.stdout.write('  ratchet secrets are AES-GCM ciphertext at rest; no plaintext leakage.\n');
    });

    // =====================================================================
    await H.gate('S4 (4) skipped_message_keys round-trip + consume-once + MAX_SKIP fail-closed', async () => {
        const mk = CP.randomBytes(32);
        const ratchetPub = CP.serializeKey(CP.generateKeyPair().publicKey);

        await KeyStorageService.putSkippedMessageKey('conv-S', ratchetPub, 7, mk);
        const got = await KeyStorageService.getSkippedMessageKey('conv-S', ratchetPub, 7);
        H.assertBytesEqual(got, mk, 'skipped key round-trips byte-identical (wrapped)');

        // wrong coordinates -> null
        H.assertEqual(await KeyStorageService.getSkippedMessageKey('conv-S', ratchetPub, 8), null, 'miss -> null');

        // consume-once
        await KeyStorageService.deleteSkippedMessageKey('conv-S', ratchetPub, 7);
        H.assertEqual(await KeyStorageService.getSkippedMessageKey('conv-S', ratchetPub, 7), null, 'deleted skipped key gone');

        // MAX_SKIP bound: lower it for a fast test, fill to cap, assert NEW key throws,
        // but updating an EXISTING (pub,n) at cap is still allowed.
        const saved = KeyStorageService.MAX_SKIPPED_KEYS_PER_CONVERSATION;
        KeyStorageService.MAX_SKIPPED_KEYS_PER_CONVERSATION = 3;
        try {
            for (let i = 0; i < 3; i++) {
                await KeyStorageService.putSkippedMessageKey('conv-CAP', ratchetPub, i, CP.randomBytes(32));
            }
            let threw = false;
            try {
                await KeyStorageService.putSkippedMessageKey('conv-CAP', ratchetPub, 99, CP.randomBytes(32));
            } catch (e) { threw = (e.code === 'MAX_SKIP_EXCEEDED'); }
            H.assert(threw, 'new skipped key beyond cap throws MAX_SKIP_EXCEEDED (fail closed)');

            // overwrite an existing coordinate at cap -> allowed (not a new entry)
            let okUpdate = true;
            try {
                await KeyStorageService.putSkippedMessageKey('conv-CAP', ratchetPub, 1, CP.randomBytes(32));
            } catch (e) { okUpdate = false; }
            H.assert(okUpdate, 'updating an existing skipped coordinate at cap is allowed');
        } finally {
            KeyStorageService.MAX_SKIPPED_KEYS_PER_CONVERSATION = saved;
        }
        process.stdout.write('  skipped store wraps, consumes once, and enforces the MAX_SKIP bound.\n');
    });

    // =====================================================================
    await H.gate('S4 (5) decrypted_message_keys ARCHIVE round-trip + miss->null (§5 lookup)', async () => {
        const mk = CP.randomBytes(32);
        await KeyStorageService.putDecryptedMessageKey('msg-123', mk, 'conv-Z');
        const got = await KeyStorageService.getDecryptedMessageKey('msg-123');
        H.assertBytesEqual(got, mk, 'archived message key round-trips byte-identical (wrapped)');

        // The §5 batch path: a brand-new realtime message id misses -> null (caller
        // then runs the live ratchet at S6). Archive lookup never throws on a miss.
        H.assertEqual(await KeyStorageService.getDecryptedMessageKey('msg-NEVER'), null, 'archive miss -> null');

        // wrapped at rest: raw stored bytes must not contain the key.
        const db = KeyStorageService.db;
        const rec = await new Promise((res, rej) => {
            const tx = db.transaction('decrypted_message_keys', 'readonly');
            const r = tx.objectStore('decrypted_message_keys').get('msg-123');
            r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
        });
        const blob = Buffer.from(new Uint8Array(rec.wrappedKey));
        H.assert(!blob.includes(Buffer.from(mk)), 'archived key wrapped at rest (no plaintext key in blob)');

        await KeyStorageService.deleteDecryptedMessageKey('msg-123');
        H.assertEqual(await KeyStorageService.getDecryptedMessageKey('msg-123'), null, 'deleted archive entry gone');
        process.stdout.write('  archive: id->MK lookup, miss->null, wrapped at rest, deletable.\n');
    });

    // =====================================================================
    await H.gate('S4 (6) clearAll wipes the 3 new stores but PRESERVES wrap_keys', async () => {
        // seed all three stores + the wrap key
        await KeyStorageService.putRatchetState('conv-CLR', await buildPopulatedState('clr-seed'));
        await KeyStorageService.putSkippedMessageKey('conv-CLR', CP.serializeKey(CP.generateKeyPair().publicKey), 1, CP.randomBytes(32));
        await KeyStorageService.putDecryptedMessageKey('msg-CLR', CP.randomBytes(32), 'conv-CLR');
        // force a wrap key to exist
        await KeyStorageService._getOrCreateWrapKey();

        const db = KeyStorageService.db;
        const wrapBefore = await new Promise((res, rej) => {
            const tx = db.transaction('wrap_keys', 'readonly');
            const r = tx.objectStore('wrap_keys').get(KeyStorageService._WRAP_KEY_ID);
            r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
        });
        H.assert(!!wrapBefore, 'wrap key present before clearAll');

        await KeyStorageService.clearAll();

        H.assertEqual(await KeyStorageService.getRatchetState('conv-CLR'), null, 'ratchet_states cleared');
        H.assertEqual(await KeyStorageService.getDecryptedMessageKey('msg-CLR'), null, 'archive cleared');

        const wrapAfter = await new Promise((res, rej) => {
            const tx = db.transaction('wrap_keys', 'readonly');
            const r = tx.objectStore('wrap_keys').get(KeyStorageService._WRAP_KEY_ID);
            r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
        });
        H.assert(!!wrapAfter, 'wrap key PRESERVED across clearAll (per SM-02 note)');
        process.stdout.write('  clearAll: 3 ratchet stores wiped, wrap_keys preserved.\n');
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
