/**
 * S8 GATE -- P0 FAIL-CLOSED TOFU + RELOAD-SAFE BOOTSTRAP + HEADER-TAMPER.
 *
 * Run: node encryption/tests/s8_fail_closed.test.js
 *
 * Proves the P0 security fixes on the REAL wired keyManagementService path, using
 * the SAME two-party deterministic simulation as s5_s6 (separate KeyStorageService
 * / IndexedDB / KMS instance per party, shared in-memory mock server).
 *
 * Gates:
 *   (a) A CHANGED peer Ed25519 IK_sig is REJECTED fail-closed (no SK / no ratchet).
 *   (b) A CHANGED peer X25519 IK is REJECTED fail-closed (no SK / no ratchet).
 *   (c) After acceptPeerIdentityChange(), the next handshake proceeds + decrypts.
 *   (d) Reload-mid-bootstrap: persist responder ratchet, DROP in-memory pending
 *       state, then BATCH-decrypt msg0 successfully via the recomputed AD (P0-4).
 *   (e) Header-tamper: flip one header byte -> decrypt FAILS (P0-3 header binding),
 *       plus deriveAeadKey rejects an empty/0-length header salt.
 *
 * Determinism: all randomness routed through CryptoPrimitivesService's seedable RNG.
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

// Wire remaining services as globals (browser pattern) so KMS resolves them.
const X3DHService = require('../services/x3dhService.js');
const DoubleRatchetService = svc.DoubleRatchetService;
global.X3DHService = X3DHService;
global.DoubleRatchetService = DoubleRatchetService;

// Make the typed error class resolvable as a bare global (KMS references it).
const EncryptionErrors = require('../utils/encryptionErrors.js');
global.PeerIdentityChangedError = EncryptionErrors.PeerIdentityChangedError;
global.DecryptionError = EncryptionErrors.DecryptionError;

const KeyStorageService = require('../services/keyStorageService.js');
const KeyManagementService = require('../services/keyManagementService.js');
global.KeyStorageService = KeyStorageService;
global.KeyManagementService = KeyManagementService;

// =====================================================================
// In-memory mock of the SERVER tables + claim RPC (mirrors complete-setup.sql).
// Identical shape to s5_s6_e2e.test.js. public_key_history is the X25519 IK source
// that _getPinnedPeerKey reads through HistoricalKeysService.getCurrentKey.
// =====================================================================
function makeMockDatabase() {
    const tables = {
        prekeys: new Map(),
        one_time_prekeys: [],
        identity_keys: new Map(),
        public_key_history: new Map(),
        messages: []
    };
    let _opkSeq = 0;
    let _msgSeq = 0;

    return {
        _tables: tables,
        async querySelect(table, options = {}) {
            const filter = options.filter || {};
            if (table === 'one_time_prekeys') {
                const rows = tables.one_time_prekeys.filter(r =>
                    (filter.user_id === undefined || r.user_id === filter.user_id) &&
                    (filter.consumed === undefined || r.consumed === filter.consumed));
                return { data: rows.map(r => ({ key_id: r.key_id })), error: null };
            }
            if (table === 'identity_keys') {
                const row = tables.identity_keys.get(filter.user_id);
                return { data: row ? [row] : [], error: null };
            }
            if (table === 'prekeys') {
                const row = tables.prekeys.get(filter.user_id);
                return { data: row ? [row] : [], error: null };
            }
            if (table === 'public_key_history') {
                const pk = tables.public_key_history.get(filter.user_id);
                return { data: pk ? [{ public_key: pk }] : [], error: null };
            }
            return { data: [], error: null };
        },
        async queryUpsert(table, data) {
            if (table === 'prekeys') { tables.prekeys.set(data.user_id, { ...data }); return { data: [data], error: null }; }
            if (table === 'identity_keys') {
                tables.identity_keys.set(data.user_id, { ...data });
                if (data.public_key) tables.public_key_history.set(data.user_id, data.public_key);
                return { data: [data], error: null };
            }
            return { data: [data], error: null };
        },
        async queryInsert(table, data) {
            const rows = Array.isArray(data) ? data : [data];
            if (table === 'one_time_prekeys') {
                const inserted = rows.map(r => { const row = { id: ++_opkSeq, consumed: false, ...r }; tables.one_time_prekeys.push(row); return row; });
                return { data: inserted, error: null };
            }
            if (table === 'messages') {
                const inserted = rows.map(r => { const row = { id: ++_msgSeq, created_at: new Date().toISOString(), ...r }; tables.messages.push(row); return row; });
                return { data: inserted, error: null };
            }
            return { data: rows, error: null };
        },
        async queryDelete(table, filter) {
            if (table === 'one_time_prekeys') {
                tables.one_time_prekeys = tables.one_time_prekeys.filter(r => !(r.user_id === filter.user_id && r.key_id === filter.key_id));
            }
            return { data: [], error: null };
        },
        async queryRpc(fnName, params) {
            if (fnName !== 'claim_one_time_prekey') return { data: null, error: { message: 'unknown rpc ' + fnName } };
            const target = params.target_user_id;
            const pre = tables.prekeys.get(target);
            if (!pre) return { data: { success: false, error: 'no prekey bundle for target' }, error: null };
            const opk = tables.one_time_prekeys.find(r => r.user_id === target && r.consumed === false);
            if (opk) opk.consumed = true;
            return {
                data: {
                    success: true, target_user_id: target,
                    identity_sign_pub: pre.identity_sign_pub,
                    signed_prekey_pub: pre.signed_prekey_pub,
                    signed_prekey_sig: pre.signed_prekey_sig,
                    spk_id: pre.spk_id,
                    opk_id: opk ? opk.key_id : null,
                    opk_pub: opk ? opk.prekey_pub : null
                },
                error: null
            };
        }
    };
}

async function makeParty(name, userId, mockDb) {
    const storage = Object.create(KeyStorageService);
    storage.db = null; storage.initialized = false;
    await storage.initialize({ indexedDB: { name: 'S8-' + name, version: 3 } });

    const kms = Object.create(KeyManagementService);
    kms.currentUserId = userId;
    kms.initialized = true;
    kms._database = mockDb;
    kms._config = {
        tables: {
            prekeys: 'prekeys', oneTimePrekeys: 'one_time_prekeys',
            identityKeys: 'identity_keys', messages: 'messages',
            publicKeyHistory: 'public_key_history'
        }
    };
    kms._sessionBackupKey = null;
    kms._pendingX3dhPreamble = {};
    kms._pendingX3dhAD = {};
    kms._pendingResponderAD = {};
    return { name, userId, storage, kms };
}

async function asParty(party, fn) {
    global.KeyStorageService = party.storage;
    global.HistoricalKeysService = {
        async getCurrentKey(uid) {
            const res = await party.kms._database.querySelect('public_key_history', { filter: { user_id: uid } });
            return res.data?.[0]?.public_key || null;
        }
    };
    try { return await fn(); }
    finally { global.KeyStorageService = KeyStorageService; }
}

async function setupIdentity(party) {
    await asParty(party, async () => {
        CP.setRandomBytesSource(H.makeDeterministicRng('identity|' + party.name));
        const keys = CP.generateKeyPair();
        CP.resetRandomBytesSource();
        await party.storage.storeIdentityKeys(party.userId, keys);
        const pubB64 = CP.serializeKey(keys.publicKey);
        await party.kms._database.queryUpsert('identity_keys', { user_id: party.userId, public_key: pubB64 });
    });
}

function buildEncryptedData(row) {
    const d = {
        id: row.id,
        ciphertext: row.encrypted_content,
        nonce: row.encryption_nonce,
        counter: row.message_counter,
        epoch: row.key_epoch || 0,
        header: {
            ratchet_pub: row.ratchet_pub ?? null,
            prev_chain_len: row.prev_chain_len ?? null,
            msg_num: row.msg_num ?? null
        }
    };
    if (row.x3dh_ik) {
        d.x3dhPreamble = {
            ikPub: row.x3dh_ik, ikSignPub: row.x3dh_ik_sign ?? null,
            ekPub: row.x3dh_ek, spkId: row.x3dh_spk_id ?? null, opkId: row.x3dh_opk_id ?? null
        };
    }
    return d;
}

async function publish(party) {
    await asParty(party, async () => {
        CP.setRandomBytesSource(H.makeDeterministicRng('prekeys|' + party.name));
        const r = await party.kms.publishPrekeys();
        CP.resetRandomBytesSource();
        H.assert(r.success, party.name + ' publishPrekeys success');
    });
}

// Initiator SEND helper: returns { row, encrypted } (or throws fail-closed).
async function send(fromParty, toParty, conversationId, text) {
    return await asParty(fromParty, async () => {
        CP.setRandomBytesSource(H.makeDeterministicRng('send|' + fromParty.name + '|' + text));
        try {
            await fromParty.kms.establishSession(conversationId, toParty.userId);
            const encrypted = await fromParty.kms.encryptMessage(conversationId, text);
            const pre = encrypted.x3dhPreamble || null;
            const ins = await fromParty.kms._database.queryInsert('messages', {
                conversation_id: conversationId, sender_id: fromParty.userId, recipient_id: toParty.userId,
                encrypted_content: encrypted.ciphertext, encryption_nonce: encrypted.nonce,
                message_counter: encrypted.counter, key_epoch: 0,
                ratchet_pub: encrypted.header.ratchet_pub, prev_chain_len: encrypted.header.prev_chain_len,
                msg_num: encrypted.header.msg_num,
                x3dh_ik: pre ? pre.ikPub : null, x3dh_ik_sign: pre ? pre.ikSignPub : null,
                x3dh_ek: pre ? pre.ekPub : null, x3dh_spk_id: pre ? pre.spkId : null,
                x3dh_opk_id: pre ? pre.opkId : null, is_encrypted: true
            });
            const row = ins.data[0];
            if (encrypted._messageKey) await fromParty.kms.archiveSentMessageKey(conversationId, row.id, encrypted._messageKey);
            return { row, encrypted };
        } finally {
            CP.resetRandomBytesSource();
        }
    });
}

async function recvRealtime(party, conversationId, row) {
    return await asParty(party, async () => {
        return await party.kms.decryptMessage(conversationId, buildEncryptedData(row), row.sender_id, party.userId, { liveAdvance: true });
    });
}

async function main() {
    const mockDb = makeMockDatabase();
    const ALICE_ID = '11111111-1111-1111-1111-111111111111';
    const BOB_ID   = '22222222-2222-2222-2222-222222222222';
    const MALLORY_ID = '33333333-3333-3333-3333-333333333333'; // attacker identity (for swapped keys)

    const alice = await makeParty('alice', ALICE_ID, mockDb);
    const bob   = await makeParty('bob', BOB_ID, mockDb);
    await setupIdentity(alice);
    await setupIdentity(bob);
    await publish(alice);
    await publish(bob);

    const CONV = 5151;

    // First, establish a NORMAL session + pin both of Bob's keys on Alice's device
    // (TOFU first-contact). Alice is the INITIATOR (she claims Bob's bundle), which
    // pins Bob's X25519 IK (via _getPinnedPeerKey in _claimPeerBundle) AND his
    // Ed25519 IK_sig (via _pinPeerSignKey) in Alice's pinned_keys store. Bob then
    // bootstraps as responder + decrypts.
    await H.gate('S8 (0) baseline: Alice INITIATES, pins Bob IK + IK_sig (TOFU first contact)', async () => {
        const { row } = await send(alice, bob, CONV, 'hi bob (bootstrap)');
        const pt = await recvRealtime(bob, CONV, row);
        H.assertEqual(pt, 'hi bob (bootstrap)', 'Bob decrypts Alice bootstrap (first contact)');

        await asParty(alice, async () => {
            const pinIk = await alice.storage.getPinnedKey(BOB_ID);
            const pinSig = await alice.storage.getPinnedKey('sign:' + BOB_ID);
            H.assert(!!pinIk, 'Alice pinned Bob X25519 IK on first contact (initiator)');
            H.assert(!!pinSig, 'Alice pinned Bob Ed25519 IK_sig on first contact (initiator)');
        });
        process.stdout.write('  baseline session established (Alice initiator); both of Bob\'s identity keys pinned.\n');
    });

    // =====================================================================
    // (a) CHANGED Ed25519 IK_sig -> REJECTED fail-closed.
    //
    // Simulate a hostile server swapping Bob's published IK_sig (and re-signing the
    // SPK with the matching new signing key, the strongest attack). Alice, as a
    // FRESH initiator on a NEW conversation, must REJECT: no SK derived, no ratchet.
    // =====================================================================
    await H.gate('S8 (a) a CHANGED peer Ed25519 IK_sig is REJECTED fail-closed', async () => {
        // Attacker forges a brand-new Ed25519 signing keypair + re-signs Bob's SPK.
        const forgedSign = CP.signKeyPair();
        const bobBundle = mockDb._tables.prekeys.get(BOB_ID);
        const origSignPub = bobBundle.identity_sign_pub;
        const origSig = bobBundle.signed_prekey_sig;

        const spkPub = CP.deserializeKey(bobBundle.signed_prekey_pub);
        const forgedSig = CP.signDetached(spkPub, forgedSign.secretKey);
        bobBundle.identity_sign_pub = CP.serializeKey(forgedSign.publicKey);
        bobBundle.signed_prekey_sig = CP.serializeKey(forgedSig);

        const CONV_ATTACK = 5152;
        let err = null;
        await asParty(alice, async () => {
            try {
                CP.setRandomBytesSource(H.makeDeterministicRng('attack-sig|alice'));
                await alice.kms.establishSession(CONV_ATTACK, BOB_ID);
            } catch (e) { err = e; }
            finally { CP.resetRandomBytesSource(); }
        });

        H.assert(!!err, 'establishSession THREW on a changed IK_sig');
        H.assertEqual(err.name, 'PeerIdentityChangedError', 'error is PeerIdentityChangedError');
        H.assertEqual(err.code, 'PEER_IDENTITY_CHANGED', 'error carries PEER_IDENTITY_CHANGED code');
        H.assertEqual(err.keyType, 'sign', 'keyType is sign (Ed25519 IK_sig)');
        H.assertEqual(err.userId, BOB_ID, 'error carries the peer userId');
        H.assert(!!err.oldFingerprint && !!err.newFingerprint, 'error carries old + new fingerprints');
        H.assert(err.oldFingerprint !== err.newFingerprint, 'old != new fingerprint');

        // NO ratchet state was created for the attacked conversation (no SK derived).
        await asParty(alice, async () => {
            const st = await alice.storage.getRatchetState(CONV_ATTACK);
            H.assert(!st, 'NO ratchet state derived for the attacked conversation (fail closed)');
            // The pinned IK_sig is UNCHANGED (we did not re-pin the forged key).
            const pin = await alice.storage.getPinnedKey('sign:' + BOB_ID);
            H.assertEqual(pin.publicKey, origSignPub, 'pinned IK_sig was NOT overwritten by the forged key');
        });

        // restore the honest bundle
        bobBundle.identity_sign_pub = origSignPub;
        bobBundle.signed_prekey_sig = origSig;
        process.stdout.write('  forged IK_sig + re-signed SPK -> rejected; no SK, no re-pin.\n');
    });

    // =====================================================================
    // (b) CHANGED X25519 IK -> REJECTED fail-closed.
    //
    // Hostile server swaps Bob's published X25519 identity public key. Alice as a
    // fresh initiator must reject before any DH (the X3DH bundle claim routes Bob's
    // IK through _getPinnedPeerKey).
    // =====================================================================
    await H.gate('S8 (b) a CHANGED peer X25519 IK is REJECTED fail-closed', async () => {
        const origIk = mockDb._tables.public_key_history.get(BOB_ID);
        // Swap to a totally different X25519 public key (attacker-controlled).
        const forgedIk = CP.generateKeyPair();
        mockDb._tables.public_key_history.set(BOB_ID, CP.serializeKey(forgedIk.publicKey));

        const CONV_ATTACK2 = 5153;
        let err = null;
        await asParty(alice, async () => {
            try {
                CP.setRandomBytesSource(H.makeDeterministicRng('attack-ik|alice'));
                await alice.kms.establishSession(CONV_ATTACK2, BOB_ID);
            } catch (e) { err = e; }
            finally { CP.resetRandomBytesSource(); }
        });

        H.assert(!!err, 'establishSession THREW on a changed X25519 IK');
        H.assertEqual(err.name, 'PeerIdentityChangedError', 'error is PeerIdentityChangedError');
        H.assertEqual(err.keyType, 'identity', 'keyType is identity (X25519 IK)');
        H.assertEqual(err.userId, BOB_ID, 'error carries the peer userId');

        await asParty(alice, async () => {
            const st = await alice.storage.getRatchetState(CONV_ATTACK2);
            H.assert(!st, 'NO ratchet state derived for the X25519-attacked conversation (fail closed)');
            const pin = await alice.storage.getPinnedKey(BOB_ID);
            H.assertEqual(pin.publicKey, origIk, 'pinned X25519 IK was NOT overwritten by the forged key');
        });

        // restore the honest IK
        mockDb._tables.public_key_history.set(BOB_ID, origIk);
        process.stdout.write('  forged X25519 IK -> rejected; no SK, no re-pin.\n');
    });

    // =====================================================================
    // (c) After acceptPeerIdentityChange(), the next handshake proceeds.
    //
    // LEGITIMATE rotation: Bob genuinely re-pairs -> new X25519 IK + new Ed25519
    // IK_sig published. Alice first REJECTS (fail closed); after the user verifies +
    // calls acceptPeerIdentityChange(BOB), the next handshake succeeds end-to-end.
    // =====================================================================
    await H.gate('S8 (c) acceptPeerIdentityChange unblocks the next handshake', async () => {
        // LEGITIMATE re-pair: Bob rotates his X25519 identity on his device, which
        // (per design) deterministically re-derives a NEW Ed25519 IK_sig, then
        // republishes a consistent bundle. This is the faithful "new identity" event.
        const newIk = CP.generateKeyPair();
        await asParty(bob, async () => {
            await bob.storage.storeIdentityKeys(BOB_ID, newIk);
            await bob.kms._database.queryUpsert('identity_keys', { user_id: BOB_ID, public_key: CP.serializeKey(newIk.publicKey) });
            // Force a fresh SPK under the new identity + republish the bundle.
            CP.setRandomBytesSource(H.makeDeterministicRng('repair|bob'));
            const r = await bob.kms.publishPrekeys();
            CP.resetRandomBytesSource();
            H.assert(r.success, 'Bob republished a consistent bundle under his new identity');
        });
        const newSignPubB64 = mockDb._tables.prekeys.get(BOB_ID).identity_sign_pub;

        const CONV_ROT = 5154;

        // 1) Alice STILL rejects (change not yet accepted) -- the X25519 IK changed.
        let rejected = false;
        await asParty(alice, async () => {
            try {
                CP.setRandomBytesSource(H.makeDeterministicRng('rot-reject|alice'));
                await alice.kms.establishSession(CONV_ROT, BOB_ID);
            } catch (e) { rejected = (e.code === 'PEER_IDENTITY_CHANGED'); }
            finally { CP.resetRandomBytesSource(); }
        });
        H.assert(rejected, 'pre-accept: rotated identity is still rejected fail-closed');

        // 2) User verifies + accepts -> re-pins BOTH keys.
        const acc = await asParty(alice, async () => alice.kms.acceptPeerIdentityChange(BOB_ID));
        H.assert(acc.accepted, 'acceptPeerIdentityChange reports accepted');
        H.assert(!!acc.identityFingerprint, 'accept re-pinned the X25519 IK');
        H.assert(!!acc.signFingerprint, 'accept re-pinned the Ed25519 IK_sig');

        await asParty(alice, async () => {
            const pinIk = await alice.storage.getPinnedKey(BOB_ID);
            const pinSig = await alice.storage.getPinnedKey('sign:' + BOB_ID);
            H.assertEqual(pinIk.publicKey, CP.serializeKey(newIk.publicKey), 'X25519 IK re-pinned to the new key');
            H.assertEqual(pinSig.publicKey, newSignPubB64, 'IK_sig re-pinned to the new derived key');
        });

        // 3) The next handshake now PROCEEDS + the message round-trips.
        const { row } = await send(alice, bob, CONV_ROT, 'hello rotated bob');
        H.assert(!!row.ratchet_pub, 'post-accept handshake produced a ratchet header (SK derived)');
        const pt = await recvRealtime(bob, CONV_ROT, row);
        H.assertEqual(pt, 'hello rotated bob', 'rotated Bob decrypts the post-accept message');
        process.stdout.write('  reject -> accept (verify) -> next handshake proceeds end-to-end.\n');
    });

    // =====================================================================
    // (d) RELOAD-MID-BOOTSTRAP (P0-4): the responder ratchet was ALREADY persisted
    // in a prior session, so a re-decrypt of msg0 takes the CACHED-ratchet path —
    // establishSession returns early and does NOT re-stash the in-memory AD. After a
    // reload that ALSO dropped the in-memory _pendingResponderAD AND the msg0 archive
    // entry, the bootstrap msg0's AD must be RECOMPUTED deterministically from the
    // persisted preamble + Dave's own identity (P0-4). Under the OLD in-memory-only
    // read the AD would be undefined here -> AEAD fail -> msg0 permanently
    // undecryptable on the batch path.
    //
    // Carol = initiator, Dave = responder.
    // =====================================================================
    await H.gate('S8 (d) reload-mid-bootstrap: persisted ratchet + dropped in-memory AD -> msg0 still decrypts via recomputed AD (P0-4)', async () => {
        const CAROL_ID = '44444444-4444-4444-4444-444444444444';
        const DAVE_ID  = '55555555-5555-5555-5555-555555555555';
        const carol = await makeParty('carol', CAROL_ID, mockDb);
        const dave  = await makeParty('dave', DAVE_ID, mockDb);
        await setupIdentity(carol); await setupIdentity(dave);
        await publish(carol); await publish(dave);

        const CONV_D = 5160;

        // 1) Carol (initiator) sends msg0 with the X3DH preamble.
        const { row: msg0 } = await send(carol, dave, CONV_D, 'reload-safe bootstrap message');
        H.assert(!!msg0.x3dh_ik, 'msg0 carries the X3DH preamble');

        // 2) Dave BOOTSTRAPS his responder ratchet from the preamble (establishSession
        //    PERSISTS the fresh ratchet at Nr=0) -- but the reload happens BEFORE msg0
        //    is decrypted/archived. This is the exact P0-4 window: the ratchet is
        //    durable, msg0 is not yet archived.
        const pre = buildEncryptedData(msg0).x3dhPreamble;
        await asParty(dave, async () => {
            await dave.kms.establishSession(CONV_D, CAROL_ID, pre);
            const st = await dave.storage.getRatchetState(CONV_D);
            H.assert(!!st, 'responder ratchet persisted by establishSession (Nr=0, msg0 not yet consumed)');
            const arch = await dave.storage.getDecryptedMessageKey(msg0.id);
            H.assert(!arch, 'msg0 not yet archived (reload window)');
        });

        // 3) RELOAD: drop ALL in-memory pending state (the _pendingResponderAD that
        //    the OLD realtime path read lives ONLY in memory). The persisted ratchet
        //    survives in IndexedDB.
        dave.kms._pendingResponderAD = {};
        dave.kms._pendingX3dhAD = {};
        dave.kms._pendingX3dhPreamble = {};

        // 4) Decrypt msg0 (realtime). establishSession now sees the CACHED ratchet and
        //    returns early WITHOUT re-stashing the AD, so the bootstrap AD must be
        //    RECOMPUTED from the persisted preamble + Dave's own identity (P0-4). With
        //    the OLD in-memory read, adBytes would be undefined here -> AEAD fail ->
        //    msg0 permanently undecryptable. The ratchet is still at Nr=0, so msg0's
        //    key is freshly derived (not a consumed/forward-secret key).
        const reloaded = await asParty(dave, async () => {
            return await dave.kms.decryptMessage(CONV_D, buildEncryptedData(msg0), msg0.sender_id, DAVE_ID, { liveAdvance: true });
        });
        H.assertEqual(reloaded, 'reload-safe bootstrap message', 'post-reload: msg0 decrypts via RECOMPUTED AD (not the lost in-memory field)');

        // 5) The BATCH path (archive-only) now reads the minted archive entry, with
        //    all in-memory pending state still empty (proves no in-memory dependency).
        dave.kms._pendingResponderAD = {};
        dave.kms._pendingX3dhAD = {};
        const batch = await asParty(dave, async () => {
            return await dave.kms.decryptMessage(CONV_D, buildEncryptedData(msg0), msg0.sender_id, DAVE_ID /* batch: no liveAdvance */);
        });
        H.assertEqual(batch, 'reload-safe bootstrap message', 'post-reload: msg0 batch-decrypts via the archive (AD recomputed on the archive-hit path)');
        process.stdout.write('  reload dropped in-memory AD; cached ratchet + recomputed AD decrypt msg0; batch path reads it.\n');
    });

    // =====================================================================
    // (e) HEADER-TAMPER -> decrypt FAILS (P0-3 header binding) + empty-salt guard.
    // =====================================================================
    await H.gate('S8 (e) header tamper -> decrypt FAILS; deriveAeadKey rejects empty salt', async () => {
        const EVE_ID  = '66666666-6666-6666-6666-666666666666';
        const FAY_ID  = '77777777-7777-7777-7777-777777777777';
        const eve = await makeParty('eve', EVE_ID, mockDb);
        const fay = await makeParty('fay', FAY_ID, mockDb);
        await setupIdentity(eve); await setupIdentity(fay);
        await publish(eve); await publish(fay);

        const CONV_E = 5170;
        const { row: m0 } = await send(eve, fay, CONV_E, 'header authenticated message');

        // First the genuine message decrypts realtime (mints the archive). This also
        // leaves Fay's ratchet advanced, so subsequent checks use the archive path.
        const ok = await recvRealtime(fay, CONV_E, m0);
        H.assertEqual(ok, 'header authenticated message', 'the genuine header decrypts');

        // TAMPER the prev_chain_len (header.pn). pn is folded into the AEAD key via
        // serializeHeaderBytes but does NOT change ratchet routing — so this isolates
        // the AEAD HEADER BINDING (P0-3): the only thing that can reject it is the
        // header being mixed into the key. Decrypt via the archive-hit path
        // (_openWithMessageKey -> deriveAeadKey), which re-derives the AEAD key from
        // the stored MK + the (tampered) header. A correct binding => open FAILS.
        const tamperedPn = { ...m0, prev_chain_len: (m0.prev_chain_len | 0) ^ 0x55 };
        let pnFailed = false;
        await asParty(fay, async () => {
            try {
                await fay.kms.decryptMessage(CONV_E, buildEncryptedData(tamperedPn), m0.sender_id, FAY_ID);
            } catch (e) { pnFailed = true; }
        });
        H.assert(pnFailed, 'a tampered prev_chain_len (pn) -> archive-path decrypt FAILS (AEAD header binding holds)');

        // Also tamper msg_num (header.n) on the archive path -> must fail.
        const tamperedN = { ...m0, msg_num: (m0.msg_num | 0) ^ 0x33 };
        let nFailed = false;
        await asParty(fay, async () => {
            try {
                await fay.kms.decryptMessage(CONV_E, buildEncryptedData(tamperedN), m0.sender_id, FAY_ID);
            } catch (e) { nFailed = true; }
        });
        H.assert(nFailed, 'a tampered msg_num (n) -> archive-path decrypt FAILS (AEAD header binding holds)');

        // And the GENUINE header still opens from the archive (control).
        const archived = await asParty(fay, async () => {
            return await fay.kms.decryptMessage(CONV_E, buildEncryptedData(m0), m0.sender_id, FAY_ID);
        });
        H.assertEqual(archived, 'header authenticated message', 'the genuine header still opens from the archive (control)');

        // Direct ratchet-routing tamper: flipping header.dh reroutes the ratchet and
        // also fails (defense in depth) on the live path.
        const dhBytes = CP.deserializeKey(m0.ratchet_pub); dhBytes[5] ^= 0x80;
        const tamperedDh = { ...m0, id: 999001, ratchet_pub: CP.serializeKey(dhBytes) };
        let dhFailed = false;
        await asParty(fay, async () => {
            try {
                await fay.kms.decryptMessage(CONV_E, buildEncryptedData(tamperedDh), m0.sender_id, FAY_ID, { liveAdvance: true });
            } catch (e) { dhFailed = true; }
        });
        H.assert(dhFailed, 'a flipped ratchet_pub (dh) -> decrypt FAILS (defense in depth)');

        // deriveAeadKey directly rejects an empty-salt / bad header (the un-auth path).
        let guard1 = false, guard2 = false;
        try {
            await DoubleRatchetService.deriveAeadKey(new Uint8Array(32), { dh: null, pn: 0, n: 0 });
        } catch (e) { guard1 = true; }
        try {
            await DoubleRatchetService.deriveAeadKey(new Uint8Array(32), { dh: new Uint8Array(0), pn: 0, n: 0 });
        } catch (e) { guard2 = true; }
        H.assert(guard1, 'deriveAeadKey rejects a null header.dh (no empty-salt context substitution)');
        H.assert(guard2, 'deriveAeadKey rejects an empty header.dh (no empty-salt context substitution)');
        process.stdout.write('  flipped header byte rejected; empty-salt header binding guarded.\n');
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
