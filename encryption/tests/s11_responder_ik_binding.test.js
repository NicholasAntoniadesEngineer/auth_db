/**
 * S11 GATE -- H-1 (+ M-1): RESPONDER X3DH IK BINDING / PEER-IMPERSONATION CLOSURE.
 *
 * Run: node encryption/tests/s11_responder_ik_binding.test.js
 *
 * Proves the H-1 fix on the REAL wired keyManagementService responder path, using
 * the SAME two-party deterministic simulation as s5_s6 / s8 (separate
 * KeyStorageService / IndexedDB / KMS instance per party, shared in-memory mock
 * server). H-1: the responder branch of establishSession used to pin ONLY the
 * Ed25519 IK_sig and feed the wire X25519 ikPub straight into deriveResponderRoot
 * WITHOUT authenticating it against the TOFU pin -> a hostile server/peer plants a
 * bootstrap (sender_id=Alice) carrying Alice's GENUINE Ed25519 IK_sig + an ATTACKER
 * X25519 ikPub, and Bob derives a working session attributed to Alice.
 *
 * Gates:
 *   (a) responder bootstrap with ikPub != the peer's pinned/published X25519 IK is
 *       REJECTED with PeerIdentityChangedError AND persists NO ratchet state.
 *   (b) the already-pinned-IK_sig + swapped-ikPub attack (the serious variant:
 *       Alice's genuine IK_sig, attacker's X25519 ikPub) is REJECTED.
 *   (c) a legit first-contact responder bootstrap still works and atomically pins
 *       BOTH the X25519 IK and the Ed25519 IK_sig.
 *   (d) acceptPeerIdentityChange still allows a real rotation through afterward.
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
// In-memory mock of the SERVER tables + claim RPC (identical to s5_s6 / s8).
// public_key_history is the X25519 IK source _getPinnedPeerKey reads through
// HistoricalKeysService.getCurrentKey.
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
    await storage.initialize({ indexedDB: { name: 'S11-' + name, version: 3 } });

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
        CP.setRandomBytesSource(H.makeDeterministicRng('send|' + fromParty.name + '|' + conversationId + '|' + text));
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

// Build a PLANTED bootstrap row: Mallory runs a genuine initiator handshake against
// Bob (so EK/SPK/OPK + the AD are self-consistent with MALLORY's X25519 ikPub), then
// the hostile server REWRITES the row's sender_id to the impersonated victim and (for
// the "already-pinned" variant) swaps x3dh_ik_sign to the victim's GENUINE IK_sig.
// The X25519 x3dh_ik stays MALLORY's — that is the unchecked field H-1 exploited.
async function plantImpersonationBootstrap(mallory, bob, victimId, opts = {}) {
    const CONV = opts.conv;
    const { row } = await send(mallory, bob, CONV, opts.text || 'planted bootstrap');
    H.assert(!!row.x3dh_ik, 'planted bootstrap carries a preamble (Mallory ran a real X3DH against Bob)');
    // The hostile server controls the plaintext columns: attribute it to the victim.
    row.sender_id = victimId;
    if (opts.victimIkSignPub) {
        // The serious variant: present the victim's GENUINE Ed25519 IK_sig while
        // leaving the X25519 ikPub = Mallory's (the field the responder never checked).
        row.x3dh_ik_sign = opts.victimIkSignPub;
    }
    return row;
}

async function main() {
    const mockDb = makeMockDatabase();
    const ALICE_ID   = '11111111-1111-1111-1111-111111111111';
    const BOB_ID     = '22222222-2222-2222-2222-222222222222';
    const MALLORY_ID = '33333333-3333-3333-3333-333333333333'; // attacker

    const alice   = await makeParty('alice', ALICE_ID, mockDb);
    const bob     = await makeParty('bob', BOB_ID, mockDb);
    const mallory = await makeParty('mallory', MALLORY_ID, mockDb);
    await setupIdentity(alice);
    await setupIdentity(bob);
    await setupIdentity(mallory);
    await publish(alice);
    await publish(bob);
    await publish(mallory);

    // Alice's genuine published material (used by the attacker for the serious variant
    // and by us to assert what Bob must trust).
    const aliceRealIkB64    = mockDb._tables.public_key_history.get(ALICE_ID);
    const aliceRealSignB64  = mockDb._tables.prekeys.get(ALICE_ID).identity_sign_pub;
    const malloryRealIkB64  = mockDb._tables.public_key_history.get(MALLORY_ID);

    // =====================================================================
    // (a) Responder bootstrap with ikPub != the peer's pinned/published X25519 IK is
    //     REJECTED with PeerIdentityChangedError AND persists NO ratchet state.
    //
    //     Bob has Alice PINNED already (from a legit prior session where Alice
    //     initiated to Bob). The attacker plants a bootstrap "from Alice" whose
    //     x3dh_ik is MALLORY's X25519 IK (and, here, Mallory's own IK_sig).
    // =====================================================================
    await H.gate('S11 (a) responder bootstrap with wrong X25519 ikPub -> PeerIdentityChangedError, NO ratchet', async () => {
        // First, a LEGIT Alice->Bob session so Bob pins Alice's real IK + IK_sig.
        const CONV_LEGIT = 6101;
        const { row: legit } = await send(alice, bob, CONV_LEGIT, 'hi bob, this is really alice');
        const pt = await recvRealtime(bob, CONV_LEGIT, legit);
        H.assertEqual(pt, 'hi bob, this is really alice', 'legit Alice->Bob bootstrap decrypts (Bob pins Alice)');
        await asParty(bob, async () => {
            const pin = await bob.storage.getPinnedKey(ALICE_ID);
            // H-1: the RESPONDER must pin the peer's X25519 IK on first contact (the
            // pre-fix responder pinned ONLY the Ed25519 IK_sig -> this is null and the
            // mutation check trips HERE, proving the gate detects the missing pin).
            H.assert(!!pin, 'Bob pinned Alice X25519 IK on the RESPONDER path (atomic co-pin)');
            H.assertEqual(pin.publicKey, aliceRealIkB64, 'Bob pinned Alice REAL X25519 IK on first contact');
        });

        // Attacker plants a NEW-conversation bootstrap "from Alice" carrying Mallory's
        // X25519 ikPub (and Mallory's own IK_sig — i.e. wholly attacker keys).
        const CONV_ATTACK = 6102;
        const planted = await plantImpersonationBootstrap(mallory, bob, ALICE_ID, { conv: CONV_ATTACK });
        H.assert(planted.x3dh_ik !== aliceRealIkB64, 'planted x3dh_ik is NOT Alice real IK (it is Mallory)');
        H.assertEqual(planted.x3dh_ik, malloryRealIkB64, 'planted x3dh_ik IS Mallory X25519 IK');

        // Bob tries to bootstrap as responder for the planted "Alice" conversation.
        let err = null;
        await asParty(bob, async () => {
            try {
                await bob.kms.establishSession(CONV_ATTACK, ALICE_ID, buildEncryptedData(planted).x3dhPreamble);
            } catch (e) { err = e; }
        });
        H.assert(!!err, 'responder establishSession THREW on a swapped X25519 ikPub');
        H.assertEqual(err.name, 'PeerIdentityChangedError', 'error is PeerIdentityChangedError');
        H.assertEqual(err.code, 'PEER_IDENTITY_CHANGED', 'error carries PEER_IDENTITY_CHANGED code');
        H.assertEqual(err.keyType, 'identity', 'keyType is identity (X25519 IK)');
        H.assertEqual(err.userId, ALICE_ID, 'error carries the impersonated victim id');

        // NO ratchet state was persisted for the attacked conversation.
        await asParty(bob, async () => {
            const st = await bob.storage.getRatchetState(CONV_ATTACK);
            H.assert(!st, 'NO ratchet state persisted for the attacked conversation (fail closed)');
            // Alice pin UNCHANGED (no silent re-pin to Mallory).
            const pin = await bob.storage.getPinnedKey(ALICE_ID);
            H.assertEqual(pin.publicKey, aliceRealIkB64, 'Alice X25519 pin was NOT overwritten by the attack');
        });
        process.stdout.write('  swapped X25519 ikPub -> rejected; no SK, no ratchet, no re-pin.\n');
    });

    // =====================================================================
    // (b) The serious variant: attacker presents Alice's GENUINE Ed25519 IK_sig
    //     (passes the IK_sig pin unchanged) while swapping ONLY the X25519 ikPub to
    //     Mallory's. Pre-fix, the X25519 IK was never consulted -> session derived.
    //     Post-fix the BOUND-PAIR / byte-equal check rejects it.
    // =====================================================================
    await H.gate('S11 (b) already-pinned IK_sig + swapped ikPub (Alice IK_sig, Mallory IK) -> REJECTED', async () => {
        const CONV_ATTACK2 = 6103;
        const planted = await plantImpersonationBootstrap(mallory, bob, ALICE_ID, {
            conv: CONV_ATTACK2,
            victimIkSignPub: aliceRealSignB64   // Alice's GENUINE IK_sig (the dangerous bit)
        });
        H.assertEqual(planted.x3dh_ik_sign, aliceRealSignB64, 'planted bootstrap carries Alice GENUINE Ed25519 IK_sig');
        H.assert(planted.x3dh_ik !== aliceRealIkB64, 'but the X25519 ikPub is swapped to Mallory');
        H.assertEqual(planted.x3dh_ik, malloryRealIkB64, 'swapped x3dh_ik IS Mallory X25519 IK');

        let err = null;
        await asParty(bob, async () => {
            try {
                await bob.kms.establishSession(CONV_ATTACK2, ALICE_ID, buildEncryptedData(planted).x3dhPreamble);
            } catch (e) { err = e; }
        });
        H.assert(!!err, 'responder establishSession THREW on genuine-IK_sig + swapped-ikPub');
        H.assertEqual(err.name, 'PeerIdentityChangedError', 'error is PeerIdentityChangedError');
        H.assertEqual(err.keyType, 'identity', 'rejection is on the X25519 identity binding (not the sign key)');

        await asParty(bob, async () => {
            const st = await bob.storage.getRatchetState(CONV_ATTACK2);
            H.assert(!st, 'NO ratchet state persisted (fail closed) for the serious variant');
            const pinSig = await bob.storage.getPinnedKey('sign:' + ALICE_ID);
            H.assertEqual(pinSig.publicKey, aliceRealSignB64, 'Alice IK_sig pin unchanged (genuine IK_sig did not let the attack through)');
            const pinIk = await bob.storage.getPinnedKey(ALICE_ID);
            H.assertEqual(pinIk.publicKey, aliceRealIkB64, 'Alice X25519 pin unchanged');
        });
        process.stdout.write('  Alice genuine IK_sig + Mallory X25519 IK -> rejected by the IK byte-equal binding.\n');
    });

    // =====================================================================
    // (c) A legit FIRST-CONTACT responder bootstrap still works AND atomically pins
    //     BOTH the X25519 IK and the Ed25519 IK_sig.
    //
    //     Carol (initiator) -> Dave (responder, first contact, no prior pin).
    // =====================================================================
    await H.gate('S11 (c) legit first-contact responder bootstrap works + atomically pins BOTH keys', async () => {
        const CAROL_ID = '44444444-4444-4444-4444-444444444444';
        const DAVE_ID  = '55555555-5555-5555-5555-555555555555';
        const carol = await makeParty('carol', CAROL_ID, mockDb);
        const dave  = await makeParty('dave', DAVE_ID, mockDb);
        await setupIdentity(carol); await setupIdentity(dave);
        await publish(carol); await publish(dave);

        const carolRealIkB64   = mockDb._tables.public_key_history.get(CAROL_ID);
        const carolRealSignB64 = mockDb._tables.prekeys.get(CAROL_ID).identity_sign_pub;

        const CONV_C = 6104;
        const { row } = await send(carol, dave, CONV_C, 'hello dave, first contact');
        H.assert(!!row.x3dh_ik, 'Carol bootstrap carries the X3DH preamble');

        // Dave has NO prior pin for Carol — pure first contact.
        await asParty(dave, async () => {
            const before = await dave.storage.getPinnedKey(CAROL_ID);
            H.assert(!before, 'Dave has no Carol pin before first contact');
        });

        const pt = await recvRealtime(dave, CONV_C, row);
        H.assertEqual(pt, 'hello dave, first contact', 'first-contact responder bootstrap decrypts');

        await asParty(dave, async () => {
            const st = await dave.storage.getRatchetState(CONV_C);
            H.assert(!!st, 'Dave has a live ratchet after the legit bootstrap');
            const pinIk = await dave.storage.getPinnedKey(CAROL_ID);
            const pinSig = await dave.storage.getPinnedKey('sign:' + CAROL_ID);
            H.assert(!!pinIk, 'Dave pinned Carol X25519 IK (atomic co-pin)');
            H.assert(!!pinSig, 'Dave pinned Carol Ed25519 IK_sig (atomic co-pin)');
            H.assertEqual(pinIk.publicKey, carolRealIkB64, 'pinned X25519 IK == what was bound (safety number reflects it)');
            H.assertEqual(pinSig.publicKey, carolRealSignB64, 'pinned IK_sig == Carol genuine IK_sig');
        });
        process.stdout.write('  legit first contact -> session works; BOTH IK + IK_sig pinned atomically.\n');

        // ---- (d) acceptPeerIdentityChange still allows a real rotation through. ----
        // Carol legitimately re-pairs: new X25519 IK -> new deterministic IK_sig,
        // republishes a consistent bundle. Dave first REJECTS the rotated bootstrap
        // (fail closed); after acceptPeerIdentityChange(Carol) a new bootstrap works.
        await H.gate('S11 (d) acceptPeerIdentityChange still allows a real rotation', async () => {
            const newIk = CP.generateKeyPair();
            await asParty(carol, async () => {
                await carol.storage.storeIdentityKeys(CAROL_ID, newIk);
                await carol.kms._database.queryUpsert('identity_keys', { user_id: CAROL_ID, public_key: CP.serializeKey(newIk.publicKey) });
                // Faithful re-pair: a re-paired device has NO carried-over SPK secret,
                // so publishPrekeys MINTS a fresh SPK signed by the NEW IK_sig and
                // re-writes the bundle row (identity_sign_pub) consistently with the new
                // identity. (Without this, publishPrekeys reuses the recent SPK and the
                // bundle keeps the OLD IK_sig — a stale-bundle artifact, not the H-1 path.)
                const meta = await carol.storage.getSignedPrekeyMeta(CAROL_ID);
                for (const m of meta) await carol.storage.deleteSignedPrekey(CAROL_ID, m.keyId);
                CP.setRandomBytesSource(H.makeDeterministicRng('repair|carol'));
                const r = await carol.kms.publishPrekeys();
                CP.resetRandomBytesSource();
                H.assert(r.success, 'Carol republished a consistent bundle under her new identity');
            });
            const newCarolIkB64   = mockDb._tables.public_key_history.get(CAROL_ID);
            const newCarolSignB64 = mockDb._tables.prekeys.get(CAROL_ID).identity_sign_pub;
            H.assert(newCarolIkB64 !== carolRealIkB64, 'Carol X25519 IK genuinely rotated');
            H.assert(newCarolSignB64 !== carolRealSignB64, 'Carol IK_sig genuinely rotated (fresh SPK signed by new IK_sig)');

            // Carol sends a NEW bootstrap under the rotated identity (fresh conversation).
            const CONV_ROT = 6105;
            const { row: rotRow } = await send(carol, dave, CONV_ROT, 'hello dave, rotated carol');

            // 1) Dave STILL rejects (rotation not yet accepted; the pinned IK changed).
            let rejected = false;
            await asParty(dave, async () => {
                try {
                    await dave.kms.establishSession(CONV_ROT, CAROL_ID, buildEncryptedData(rotRow).x3dhPreamble);
                } catch (e) { rejected = (e.code === 'PEER_IDENTITY_CHANGED'); }
            });
            H.assert(rejected, 'pre-accept: rotated Carol identity is rejected fail-closed on the responder path');
            await asParty(dave, async () => {
                const st = await dave.storage.getRatchetState(CONV_ROT);
                H.assert(!st, 'no ratchet persisted while rotation is unaccepted');
            });

            // 2) Dave verifies out-of-band + accepts -> re-pins BOTH keys.
            const acc = await asParty(dave, async () => dave.kms.acceptPeerIdentityChange(CAROL_ID));
            H.assert(acc.accepted, 'acceptPeerIdentityChange reports accepted');
            H.assert(!!acc.identityFingerprint && !!acc.signFingerprint, 'accept re-pinned BOTH X25519 IK and IK_sig');
            await asParty(dave, async () => {
                const pinIk = await dave.storage.getPinnedKey(CAROL_ID);
                const pinSig = await dave.storage.getPinnedKey('sign:' + CAROL_ID);
                H.assertEqual(pinIk.publicKey, newCarolIkB64, 'X25519 IK re-pinned to the rotated key');
                H.assertEqual(pinSig.publicKey, newCarolSignB64, 'IK_sig re-pinned to the rotated derived key');
            });

            // 3) A FRESH rotated bootstrap now PROCEEDS + round-trips.
            const CONV_ROT2 = 6106;
            const { row: rotRow2 } = await send(carol, dave, CONV_ROT2, 'rotation accepted, hi again');
            const ptRot = await recvRealtime(dave, CONV_ROT2, rotRow2);
            H.assertEqual(ptRot, 'rotation accepted, hi again', 'post-accept rotated responder bootstrap decrypts');
            await asParty(dave, async () => {
                const st = await dave.storage.getRatchetState(CONV_ROT2);
                H.assert(!!st, 'Dave has a live ratchet after accepting the rotation');
            });
            process.stdout.write('  rotation: reject -> accept (verify) -> next responder bootstrap proceeds.\n');
        });
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
