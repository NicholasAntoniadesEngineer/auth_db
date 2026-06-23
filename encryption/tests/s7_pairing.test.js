/**
 * S7 GATE -- DEVICE PAIRING / MULTI-DEVICE (FORWARD_SECRECY_DESIGN §6).
 *
 * Run: node encryption/tests/s7_pairing.test.js
 *
 * Deterministic, node-runnable simulation (LAW-0: the gate is the arbiter, no
 * messenger runtime) of the bundle-v2 sequential device hand-off. Reuses the SAME
 * infrastructure as the S5/S6 e2e gate: the _idb_shim in-memory IndexedDB (one DB
 * per DEVICE), the in-memory mock of the prekeys / one_time_prekeys / messages
 * tables + claim_one_time_prekey RPC, and the seedable RNG seam.
 *
 * Parties / devices:
 *   - BOB  : the peer (one device).
 *   - A1   : Alice's FIRST device. Establishes a ratchet with Bob, exchanges
 *            messages, builds the §5 history archive.
 *   - A2   : Alice's SECOND (newly paired) device — same identity, fresh storage
 *            (own IndexedDB + own non-extractable wrap key).
 *
 * Scenario:
 *   1. Everyone publishes prekeys. Bob INITIATES a session with Alice (A1) and
 *      they exchange several messages across direction changes -> A1 has a live
 *      ratchet + a full decrypted_message_keys archive.
 *   2. A1.exportPairingBundle() -> a v2 bundle carrying the ratchet WORLD snapshot.
 *   3. The bundle is piped through the REAL pairing TRANSPORT crypto
 *      (PasswordCryptoService.encryptToBase64/decryptFromBase64 under a high-entropy
 *      code) exactly like devicePairingService does — proving no plaintext secret is
 *      on the wire AND that the snapshot survives the transport envelope.
 *   4. A2.importPairingBundle(bundle) -> restores identity + ratchet world onto A2.
 *
 * Assertions:
 *   (1) A2 can decrypt Alice's full message HISTORY via the transferred §5 archive
 *       (batch / archive-only path), byte-for-byte against ground truth.
 *   (2) A2 can CONTINUE the conversation: it receives a NEW message Bob sends AND
 *       sends a NEW message Bob decrypts, on the RESTORED ratchet state.
 *   (3) The v2 bundle actually carried a non-empty ratchet snapshot, and the
 *       transport envelope contains NO plaintext identity/ratchet secret.
 *   (4) A v1 bundle (no ratchet snapshot) still imports — fresh-start path: identity
 *       installed, no ratchet state, import reports the fresh-start note.
 *   (5) No-clobber safety: importing a snapshot over an EXISTING local ratchet state
 *       does NOT overwrite it (sequential-device desync guard, §6).
 */

const H = require('./_harness.js');
const { makeFakeIndexedDB } = require('./_idb_shim.js');

// Install the IndexedDB globals BEFORE loading KeyStorageService.
const { indexedDB, IDBKeyRange } = makeFakeIndexedDB();
global.indexedDB = indexedDB;
global.IDBKeyRange = IDBKeyRange;

// Load nacl + WebCrypto + the pure services via the existing harness.
const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;

const X3DHService = require('../services/x3dhService.js');
const DoubleRatchetService = svc.DoubleRatchetService;
global.X3DHService = X3DHService;
global.DoubleRatchetService = DoubleRatchetService;

const KeyStorageService = require('../services/keyStorageService.js');
const KeyManagementService = require('../services/keyManagementService.js');
const PasswordCryptoService = require('../services/passwordCryptoService.js');
global.KeyStorageService = KeyStorageService;
global.KeyManagementService = KeyManagementService;
global.PasswordCryptoService = PasswordCryptoService;

// =====================================================================
// In-memory mock of the SERVER tables + claim RPC (same as the S5/S6 gate).
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
                }, error: null
            };
        }
    };
}

// =====================================================================
// Device harness: each DEVICE gets its own KeyStorageService (own DB + own
// non-extractable wrap key) + its own KMS instance, sharing the mock server DB.
// =====================================================================
async function makeDevice(name, userId, mockDb) {
    const storage = Object.create(KeyStorageService);
    storage.db = null;
    storage.initialized = false;
    await storage.initialize({ indexedDB: { name: 'S7-' + name, version: 3 } });

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

async function asDevice(device, fn) {
    global.KeyStorageService = device.storage;
    global.HistoricalKeysService = {
        async getCurrentKey(uid) {
            const res = await device.kms._database.querySelect('public_key_history', { filter: { user_id: uid } });
            return res.data?.[0]?.public_key || null;
        },
        async syncToLocal() { /* no-op for the gate */ }
    };
    try {
        return await fn();
    } finally {
        global.KeyStorageService = KeyStorageService;
    }
}

async function setupIdentity(device, seedLabel) {
    return await asDevice(device, async () => {
        CP.setRandomBytesSource(H.makeDeterministicRng('identity|' + seedLabel));
        const keys = CP.generateKeyPair();
        CP.resetRandomBytesSource();
        await device.storage.storeIdentityKeys(device.userId, keys);
        const pubB64 = CP.serializeKey(keys.publicKey);
        await device.kms._database.queryUpsert('identity_keys', { user_id: device.userId, public_key: pubB64 });
        return keys;
    });
}

// Mirror of MessagingService.buildEncryptedData (inlined; same mapping as S5/S6).
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

async function main() {
    const mockDb = makeMockDatabase();
    const transcript = [];

    const ALICE_ID = '11111111-1111-1111-1111-111111111111';
    const BOB_ID = '22222222-2222-2222-2222-222222222222';

    const bob = await makeDevice('bob', BOB_ID, mockDb);
    const a1 = await makeDevice('alice1', ALICE_ID, mockDb);

    // A1 + Bob each get a (separately-seeded) identity. A2 will INHERIT A1's identity
    // via the pairing bundle (it is the SAME Alice), so we don't seed it here.
    const aliceIdentity = await setupIdentity(a1, 'alice');
    await setupIdentity(bob, 'bob');

    const CONV = 4242;

    // send: `from` device sends to `to` device's user; inserts into mock messages and
    // archives the sender-side key (so the sender's own history re-render works).
    async function send(fromDev, toUserId, text) {
        return await asDevice(fromDev, async () => {
            CP.setRandomBytesSource(H.makeDeterministicRng('send|' + fromDev.name + '|' + text));
            await fromDev.kms.establishSession(CONV, toUserId);
            const encrypted = await fromDev.kms.encryptMessage(CONV, text);
            CP.resetRandomBytesSource();
            const pre = encrypted.x3dhPreamble || null;
            const ins = await fromDev.kms._database.queryInsert('messages', {
                conversation_id: CONV, sender_id: fromDev.userId, recipient_id: toUserId,
                encrypted_content: encrypted.ciphertext, encryption_nonce: encrypted.nonce,
                message_counter: encrypted.counter, key_epoch: 0,
                ratchet_pub: encrypted.header.ratchet_pub,
                prev_chain_len: encrypted.header.prev_chain_len,
                msg_num: encrypted.header.msg_num,
                x3dh_ik: pre ? pre.ikPub : null, x3dh_ik_sign: pre ? pre.ikSignPub : null,
                x3dh_ek: pre ? pre.ekPub : null, x3dh_spk_id: pre ? pre.spkId : null,
                x3dh_opk_id: pre ? pre.opkId : null, is_encrypted: true
            });
            const row = ins.data[0];
            if (encrypted._messageKey) {
                await fromDev.kms.archiveSentMessageKey(CONV, row.id, encrypted._messageKey);
            }
            transcript.push({ row, plaintext: text, from: fromDev.name });
            return row;
        });
    }

    async function recvRealtime(dev, row) {
        return await asDevice(dev, async () => {
            return await dev.kms.decryptMessage(CONV, buildEncryptedData(row), row.sender_id, dev.userId, { liveAdvance: true });
        });
    }

    // =====================================================================
    await H.gate('S7 (0) build the conversation on Alice device 1 (A1) <-> Bob', async () => {
        await asDevice(a1, async () => { CP.setRandomBytesSource(H.makeDeterministicRng('prekeys|alice1')); await a1.kms.publishPrekeys(); CP.resetRandomBytesSource(); });
        await asDevice(bob, async () => { CP.setRandomBytesSource(H.makeDeterministicRng('prekeys|bob')); await bob.kms.publishPrekeys(); CP.resetRandomBytesSource(); });

        // Bob initiates; A1 responds. Several messages across direction changes.
        const m1 = await send(bob, ALICE_ID, 'hello alice (device 1)');
        H.assertEqual(await recvRealtime(a1, m1), 'hello alice (device 1)', 'A1 decrypts Bob msg1 (responder bootstrap)');

        const m2 = await send(a1, BOB_ID, 'hi bob from device 1');
        H.assertEqual(await recvRealtime(bob, m2), 'hi bob from device 1', 'Bob decrypts A1 reply');

        const m3 = await send(bob, ALICE_ID, 'how is device 1 treating you');
        H.assertEqual(await recvRealtime(a1, m3), 'how is device 1 treating you', 'A1 decrypts Bob msg2');

        const m4 = await send(a1, BOB_ID, 'all good, archive building up');
        H.assertEqual(await recvRealtime(bob, m4), 'all good, archive building up', 'Bob decrypts A1 msg2');

        // A1 has a live ratchet + a 4-entry archive.
        await asDevice(a1, async () => {
            const st = await a1.storage.getRatchetState(CONV);
            H.assert(!!st, 'A1 has a live ratchet state');
            const archive = await a1.storage._getAllRecords('decrypted_message_keys');
            H.assertEqual(archive.length, 4, 'A1 archive holds all 4 messages');
        });
        process.stdout.write('  A1<->Bob exchanged 4 messages across direction changes; A1 archive built.\n');
    });

    // =====================================================================
    let v2Bundle, transportEnvelope, pairingPassword;
    await H.gate('S7 (1) A1 exports a v2 pairing bundle carrying the ratchet WORLD snapshot', async () => {
        v2Bundle = await asDevice(a1, async () => await a1.kms.exportPairingBundle());

        H.assertEqual(v2Bundle.v, 2, 'bundle version is 2');
        H.assert(!!v2Bundle.identitySecretB64, 'bundle carries the X25519 identity secret');
        H.assert(!!v2Bundle.identitySignSecretB64, 'bundle carries the Ed25519 IK_sig secret (§6 explicit carry)');
        H.assert(!!v2Bundle.ratchetSnapshot, 'bundle carries a ratchetSnapshot');

        const snap = v2Bundle.ratchetSnapshot;
        H.assert(snap.ratchetStates.length >= 1, 'snapshot carries at least one ratchet state');
        H.assertEqual(snap.decryptedMessageKeys.length, 4, 'snapshot carries the 4-message history archive');
        H.assert(snap.prekeySecrets.length >= 1, 'snapshot carries prekey secrets (SPK/OPK)');

        // IK_sig secret in the bundle matches the deterministically-derived one.
        await asDevice(a1, async () => {
            const sk = await a1.kms._getIdentitySignKeyPair();
            H.assertEqual(v2Bundle.identitySignSecretB64, CP.serializeKey(sk.secretKey), 'carried IK_sig secret == derived IK_sig secret');
        });
        process.stdout.write(`  v2 bundle: ${snap.ratchetStates.length} state(s), ${snap.decryptedMessageKeys.length} archive key(s), ${snap.prekeySecrets.length} prekey secret(s).\n`);
    });

    // =====================================================================
    await H.gate('S7 (2) bundle survives the REAL pairing transport crypto; NO plaintext secret on the wire', async () => {
        // Mirror devicePairingService: high-entropy code -> normalized password ->
        // PBKDF2+AES-GCM encrypt the JSON bundle. The ciphertext is what hits the server.
        const codeBytes = H.makeDeterministicRng('pairing-code')(10);
        const codeB64 = PasswordCryptoService._arrayToBase64(codeBytes);
        pairingPassword = String(PasswordCryptoService.formatRecoveryKey(codeB64)).replace(/[^A-Za-z0-9]/g, '').toUpperCase();

        const bundleBytes = new TextEncoder().encode(JSON.stringify(v2Bundle));
        transportEnvelope = await PasswordCryptoService.encryptToBase64(bundleBytes, pairingPassword);

        H.assert(!!transportEnvelope.encryptedData && !!transportEnvelope.salt && !!transportEnvelope.iv, 'transport envelope has ciphertext+salt+iv');

        // The on-the-wire ciphertext must NOT contain the raw identity/ratchet secrets.
        const wire = transportEnvelope.encryptedData;
        H.assert(!wire.includes(v2Bundle.identitySecretB64), 'identity secret is NOT present in the transport ciphertext');
        const anyArchiveMk = v2Bundle.ratchetSnapshot.decryptedMessageKeys[0].mk;
        H.assert(!wire.includes(anyArchiveMk), 'an archived message key is NOT present in the transport ciphertext');

        // Decrypt back (device 2 side of the transport) -> identical bundle JSON.
        const back = await PasswordCryptoService.decryptFromBase64(transportEnvelope.encryptedData, pairingPassword, transportEnvelope.salt, transportEnvelope.iv);
        const roundTripped = JSON.parse(new TextDecoder().decode(back));
        H.assertEqual(JSON.stringify(roundTripped), JSON.stringify(v2Bundle), 'bundle round-trips byte-identical through the transport envelope');
        process.stdout.write('  bundle encrypted under the pairing code; no plaintext secret in the ciphertext; round-trips exactly.\n');
    });

    // =====================================================================
    let a2;
    await H.gate('S7 (3) A2 (new device) imports the v2 bundle -> identity + ratchet world restored', async () => {
        a2 = await makeDevice('alice2', ALICE_ID, mockDb);

        // A2 receives the transport envelope and decrypts it with the code (device-2 transport side).
        const back = await PasswordCryptoService.decryptFromBase64(transportEnvelope.encryptedData, pairingPassword, transportEnvelope.salt, transportEnvelope.iv);
        const received = JSON.parse(new TextDecoder().decode(back));

        const result = await asDevice(a2, async () => {
            CP.setRandomBytesSource(H.makeDeterministicRng('prekeys|alice2-import'));
            const r = await a2.kms.importPairingBundle(received);
            CP.resetRandomBytesSource();
            return r;
        });

        H.assert(result.success, 'importPairingBundle succeeded');
        H.assertEqual(result.v, 2, 'import reports v2');
        H.assert(result.ratchetSnapshotRestored, 'import restored the ratchet snapshot');
        H.assertEqual(result.snapshotStats.decryptedMessageKeys, 4, 'import restored the 4 archive keys');
        H.assert(result.snapshotStats.ratchetStates >= 1, 'import restored at least one ratchet state');
        H.assert(Array.isArray(result.notes) && result.notes.length > 0, 'import returns notes (incl. the multi-device limitation)');
        const limitationNoted = result.notes.some(n => /sequential|out of scope|desync/i.test(n));
        H.assert(limitationNoted, 'import notes document the SEQUENTIAL / out-of-scope multi-device limitation');

        // A2 now has Alice's identity + a live ratchet state (re-wrapped under A2's wrap key).
        await asDevice(a2, async () => {
            const idk = await a2.storage.getIdentityKeys(ALICE_ID);
            H.assert(!!idk && CP.serializeKey(idk.publicKey) === CP.serializeKey(aliceIdentity.publicKey), 'A2 has Alice\'s identity public key');
            const st = await a2.storage.getRatchetState(CONV);
            H.assert(!!st && !!st.RK, 'A2 has a restored live ratchet state for the conversation');
        });
        process.stdout.write('  A2 imported the v2 bundle; identity + ratchet state present (re-wrapped under A2\'s wrap key).\n');
    });

    // =====================================================================
    await H.gate('S7 (4) ASSERT (1): A2 reads Alice\'s full message HISTORY via the transferred archive', async () => {
        // Batch / archive-only re-render (no liveAdvance), newest-first in parallel —
        // exactly the getMessages path. Must return every plaintext from the archive.
        const aliceVisible = mockDb._tables.messages
            .filter(m => m.conversation_id === CONV)
            .slice().sort((x, y) => y.id - x.id);

        const rendered = await asDevice(a2, async () => {
            return await Promise.all(aliceVisible.map(async (row) => {
                const content = await a2.kms.decryptMessage(CONV, buildEncryptedData(row), row.sender_id, row.recipient_id);
                return { id: row.id, content };
            }));
        });

        const truth = new Map(transcript.map(t => [t.row.id, t.plaintext]));
        let allMatch = true;
        for (const r of rendered) {
            if (truth.get(r.id) !== r.content) {
                allMatch = false;
                process.stdout.write(`    MISMATCH id=${r.id}: got "${r.content}" want "${truth.get(r.id)}"\n`);
            }
        }
        H.assert(allMatch, 'A2 re-renders every historical message to its exact plaintext from the transferred archive');
        H.assertEqual(rendered.length, 4, 'A2 rendered all 4 historical messages');
        process.stdout.write(`  A2 read all ${rendered.length} historical messages from the transferred archive.\n`);
    });

    // =====================================================================
    await H.gate('S7 (5) ASSERT (2): A2 CONTINUES the conversation on the restored ratchet', async () => {
        // (a) Bob sends a NEW message; A2 decrypts it on the restored live ratchet.
        const newFromBob = await send(bob, ALICE_ID, 'new message after Alice paired device 2');
        const got = await recvRealtime(a2, newFromBob);
        H.assertEqual(got, 'new message after Alice paired device 2', 'A2 decrypts a NEW Bob message on the restored ratchet (continue, recv)');

        // (b) A2 sends a NEW message; Bob decrypts it (continue, send — DH ratchet on Bob's recv).
        const newFromA2 = await send(a2, BOB_ID, 'reply from Alice device 2');
        const bobGot = await recvRealtime(bob, newFromA2);
        H.assertEqual(bobGot, 'reply from Alice device 2', 'Bob decrypts a NEW A2 message (continue, send)');
        process.stdout.write('  A2 continued the conversation: received a new Bob message AND sent one Bob decrypted.\n');
    });

    // =====================================================================
    await H.gate('S7 (6) BACKWARD-COMPAT: a v1 bundle (no snapshot) still imports (fresh-start path)', async () => {
        // A brand-new device imports a v1-shaped bundle (identity + backup key only).
        const a3 = await makeDevice('alice3-v1', ALICE_ID, mockDb);
        const v1Bundle = {
            v: 1,
            identitySecretB64: CP.serializeKey(aliceIdentity.secretKey),
            sessionBackupKeyB64: null
            // NO identitySignSecretB64, NO ratchetSnapshot — exactly an old client's output.
        };

        const result = await asDevice(a3, async () => {
            CP.setRandomBytesSource(H.makeDeterministicRng('prekeys|alice3-v1'));
            const r = await a3.kms.importPairingBundle(v1Bundle);
            CP.resetRandomBytesSource();
            return r;
        });

        H.assert(result.success, 'v1 bundle import succeeded');
        H.assertEqual(result.v, 1, 'import reports v1');
        H.assert(!result.ratchetSnapshotRestored, 'no ratchet snapshot restored for a v1 bundle');
        const freshNote = result.notes.some(n => /fresh|no ratchet snapshot/i.test(n));
        H.assert(freshNote, 'v1 import notes the fresh-ratchet start');

        await asDevice(a3, async () => {
            const idk = await a3.storage.getIdentityKeys(ALICE_ID);
            H.assert(!!idk, 'A3 has the identity installed from the v1 bundle');
            const st = await a3.storage.getRatchetState(CONV);
            H.assert(!st, 'A3 has NO ratchet state (fresh start) from a v1 bundle');
        });

        // And A3 can still bootstrap a FRESH session via X3DH (it republished prekeys
        // on import; here it INITIATES a brand-new conversation with Bob).
        const FRESH_CONV = 5151;
        const freshRow = await asDevice(a3, async () => {
            CP.setRandomBytesSource(H.makeDeterministicRng('a3-fresh-send'));
            await a3.kms.establishSession(FRESH_CONV, BOB_ID);
            const enc = await a3.kms.encryptMessage(FRESH_CONV, 'fresh session from a v1-imported device');
            CP.resetRandomBytesSource();
            const pre = enc.x3dhPreamble;
            const ins = await a3.kms._database.queryInsert('messages', {
                conversation_id: FRESH_CONV, sender_id: ALICE_ID, recipient_id: BOB_ID,
                encrypted_content: enc.ciphertext, encryption_nonce: enc.nonce,
                message_counter: enc.counter, key_epoch: 0,
                ratchet_pub: enc.header.ratchet_pub, prev_chain_len: enc.header.prev_chain_len, msg_num: enc.header.msg_num,
                x3dh_ik: pre ? pre.ikPub : null, x3dh_ik_sign: pre ? pre.ikSignPub : null,
                x3dh_ek: pre ? pre.ekPub : null, x3dh_spk_id: pre ? pre.spkId : null, x3dh_opk_id: pre ? pre.opkId : null,
                is_encrypted: true
            });
            return ins.data[0];
        });
        const bobReadsFresh = await asDevice(bob, async () => {
            return await bob.kms.decryptMessage(FRESH_CONV, buildEncryptedData(freshRow), ALICE_ID, BOB_ID, { liveAdvance: true });
        });
        H.assertEqual(bobReadsFresh, 'fresh session from a v1-imported device', 'a v1-imported device can start a FRESH X3DH session');
        process.stdout.write('  v1 bundle imported (identity only, no ratchet state); fresh X3DH session works.\n');
    });

    // =====================================================================
    await H.gate('S7 (7) NO-CLOBBER safety: snapshot import does NOT overwrite an existing local ratchet (§6)', async () => {
        // A device that ALREADY has a live ratchet for a conversation must not have it
        // clobbered by an imported snapshot (would desync the live conversation).
        // Re-import the v2 snapshot onto A2 (which already has a live, possibly-advanced
        // ratchet for CONV after step 5) and assert the local state is untouched.
        let beforeJson;
        await asDevice(a2, async () => {
            const st = await a2.storage.getRatchetState(CONV);
            beforeJson = JSON.stringify(a2.storage.serializeRatchetState(st));
        });

        const stats = await asDevice(a2, async () => {
            return await a2.storage.importRatchetSnapshot(ALICE_ID, v2Bundle.ratchetSnapshot);
        });
        H.assert(stats.ratchetStatesSkipped >= 1, 'the existing CONV ratchet state was SKIPPED (not clobbered)');
        H.assertEqual(stats.ratchetStates, 0, 'no ratchet state was overwritten on re-import');

        let afterJson;
        await asDevice(a2, async () => {
            const st = await a2.storage.getRatchetState(CONV);
            afterJson = JSON.stringify(a2.storage.serializeRatchetState(st));
        });
        H.assert(beforeJson === afterJson, 'A2\'s live ratchet state is UNCHANGED after a re-import (no-clobber)');

        // And the conversation still works after the (no-op) re-import.
        const after = await send(bob, ALICE_ID, 'message after a no-clobber re-import');
        H.assertEqual(await recvRealtime(a2, after), 'message after a no-clobber re-import', 'conversation still continues after a no-clobber re-import');
        process.stdout.write('  re-import skipped the existing ratchet state; live state untouched; conversation still works.\n');
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
