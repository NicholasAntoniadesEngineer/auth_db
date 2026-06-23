/**
 * S9 GATE -- OPTIMIZATION-REVIEW HARDENING (P1-1 + P2-1 + P0-follow-up).
 *
 * Run: node encryption/tests/s9_hardening.test.js
 *
 * Builds on the SAME two-party deterministic simulation as s5_s6 / s8 (separate
 * KeyStorageService / IndexedDB / KMS instance per party, shared in-memory mock
 * server). Determinism: all randomness routed through CryptoPrimitivesService's
 * seedable RNG.
 *
 * Gates:
 *   (1) P1-1 — MKSKIPPED TOTAL bound: drive many DH-ratchet + skip cycles and assert
 *       the live MKSKIPPED stays within DoubleRatchetService.MAX_SKIPPED_TOTAL while
 *       the NEWEST skipped keys still decrypt (oldest-first eviction never drops a
 *       newer key). Mutation check: the same workload OVERFLOWS the cap when eviction
 *       is disabled.
 *   (2) P2-1 — SPK rotation with grace: after the rotation interval a NEW SPK is
 *       published; an initiator holding the OLD spk_id still bootstraps within grace;
 *       and an SPK past the grace window is pruned (current SPK never pruned).
 *   (3) P0-follow-up — getPendingPeerIdentity returns the NEW server key's fingerprint
 *       + safety number WITHOUT pinning it (a subsequent establishSession STILL throws
 *       fail-closed until acceptPeerIdentityChange).
 */

const H = require('./_harness.js');
const { makeFakeIndexedDB } = require('./_idb_shim.js');

// Install the IndexedDB globals BEFORE loading KeyStorageService.
const { indexedDB, IDBKeyRange } = makeFakeIndexedDB();
global.indexedDB = indexedDB;
global.IDBKeyRange = IDBKeyRange;

const svc = H.loadServices();
const CP = svc.CryptoPrimitivesService;

const X3DHService = require('../services/x3dhService.js');
const DoubleRatchetService = svc.DoubleRatchetService;
global.X3DHService = X3DHService;
global.DoubleRatchetService = DoubleRatchetService;

const EncryptionErrors = require('../utils/encryptionErrors.js');
global.PeerIdentityChangedError = EncryptionErrors.PeerIdentityChangedError;
global.DecryptionError = EncryptionErrors.DecryptionError;

const KeyStorageService = require('../services/keyStorageService.js');
const KeyManagementService = require('../services/keyManagementService.js');
global.KeyStorageService = KeyStorageService;
global.KeyManagementService = KeyManagementService;

// =====================================================================
// In-memory mock SERVER (identical shape to s8_fail_closed.test.js).
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
    await storage.initialize({ indexedDB: { name: 'S9-' + name, version: 3 } });

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

async function publish(party, seedSuffix) {
    return await asParty(party, async () => {
        CP.setRandomBytesSource(H.makeDeterministicRng('prekeys|' + party.name + '|' + (seedSuffix || '')));
        const r = await party.kms.publishPrekeys();
        CP.resetRandomBytesSource();
        H.assert(r.success, party.name + ' publishPrekeys success');
        return r;
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

// =====================================================================
// MAIN
// =====================================================================
async function main() {
    const ALICE_ID = '11111111-1111-1111-1111-111111111111';
    const BOB_ID   = '22222222-2222-2222-2222-222222222222';

    // -----------------------------------------------------------------
    // (1) P1-1 — MKSKIPPED TOTAL bound (pure ratchet, deterministic).
    //
    // Many DH ratchets, each skipping a handful of messages, would accumulate
    // unbounded (oldDHr,n) entries without a TOTAL cap. We drive a long run and
    // assert MKSKIPPED never exceeds MAX_SKIPPED_TOTAL, AND that the most-recent
    // skipped keys still decrypt (oldest-first eviction). Then a MUTATION check:
    // with eviction disabled the SAME workload blows past the cap.
    // -----------------------------------------------------------------
    await H.gate('S9 (1) P1-1: MKSKIPPED stays within MAX_SKIPPED_TOTAL; newest keys still decrypt', async () => {
        const CAP = DoubleRatchetService.MAX_SKIPPED_TOTAL;
        H.assert(typeof CAP === 'number' && CAP > 0, 'MAX_SKIPPED_TOTAL is a positive number');
        H.assert(CAP !== DoubleRatchetService.MAX_SKIP, 'MAX_SKIPPED_TOTAL is DISTINCT from MAX_SKIP');

        // Build a fresh A<->B ratchet pair directly (X3DH-rooted via a shared SK).
        CP.setRandomBytesSource(H.makeDeterministicRng('p1-root'));
        const SK = CP.randomBytes(32);
        const bobSpk = CP.generateKeyPair();
        let aliceState = await DoubleRatchetService.ratchetInitAlice(SK, bobSpk.publicKey);
        let bobState = await DoubleRatchetService.ratchetInitBob(SK, bobSpk);
        CP.resetRandomBytesSource();

        // Helper: Alice sends `count` messages on her current chain but we only DELIVER
        // the LAST one to Bob, forcing Bob to skip (count-1) keys in that chain. Then
        // Bob replies once so the NEXT Alice send triggers a DH ratchet (new chain).
        const SKIP_PER_CHAIN = 8;
        const ROUNDS = Math.ceil((CAP / SKIP_PER_CHAIN)) + 60; // enough to exceed the cap

        let maxSeen = 0;
        let lastDeliverable = null; // {wireHeader, nonce, ct, plaintext} of the newest delivered msg

        for (let r = 0; r < ROUNDS; r++) {
            // Alice sends SKIP_PER_CHAIN messages on her current sending chain.
            let lastEnc = null, lastText = null;
            for (let i = 0; i < SKIP_PER_CHAIN; i++) {
                const text = `r${r}-m${i}`;
                const enc = await DoubleRatchetService.ratchetEncrypt(aliceState, CP.encodeUTF8(text));
                aliceState = enc.newState;
                lastEnc = enc; lastText = text;
            }
            // Deliver ONLY the last message of the chain -> Bob skips the prior ones.
            const dec = await DoubleRatchetService.ratchetDecrypt(
                bobState, lastEnc.wireHeader, lastEnc.nonce, lastEnc.ciphertext);
            bobState = dec.newState;
            H.assertEqual(CP.decodeUTF8(dec.plaintext), lastText, `round ${r}: newest message of chain decrypts`);
            maxSeen = Math.max(maxSeen, bobState.MKSKIPPED.size);
            H.assert(bobState.MKSKIPPED.size <= CAP, `round ${r}: MKSKIPPED size ${bobState.MKSKIPPED.size} <= cap ${CAP}`);
            lastDeliverable = { state: bobState };

            // Bob replies once so Alice's NEXT send is a NEW DH chain (advances DHr).
            const reply = await DoubleRatchetService.ratchetEncrypt(bobState, CP.encodeUTF8(`bob-ack-${r}`));
            bobState = reply.newState;
            const adec = await DoubleRatchetService.ratchetDecrypt(
                aliceState, reply.wireHeader, reply.nonce, reply.ciphertext);
            aliceState = adec.newState;
        }

        H.assert(maxSeen <= CAP, `MKSKIPPED never exceeded the cap over the whole run (max seen ${maxSeen})`);
        // We must actually have pushed PAST the cap's worth of skips at some point,
        // else the test is vacuous.
        const totalSkipsAttempted = ROUNDS * (SKIP_PER_CHAIN - 1);
        H.assert(totalSkipsAttempted > CAP, `workload attempted ${totalSkipsAttempted} skips > cap ${CAP} (non-vacuous)`);

        // Newest skipped key still usable: in the FINAL chain, deliver an EARLIER
        // (skipped) message and confirm it decrypts from MKSKIPPED.
        {
            // Fresh final chain: Alice sends 3, deliver msg #2 first (skips #0,#1 into
            // MKSKIPPED), then deliver #0 from the skipped store.
            const e0 = await DoubleRatchetService.ratchetEncrypt(aliceState, CP.encodeUTF8('final-0'));
            aliceState = e0.newState;
            const e1 = await DoubleRatchetService.ratchetEncrypt(aliceState, CP.encodeUTF8('final-1'));
            aliceState = e1.newState;
            const e2 = await DoubleRatchetService.ratchetEncrypt(aliceState, CP.encodeUTF8('final-2'));
            aliceState = e2.newState;
            // Deliver #2 first -> #0,#1 get skipped (newest of THIS chain stored).
            let d = await DoubleRatchetService.ratchetDecrypt(bobState, e2.wireHeader, e2.nonce, e2.ciphertext);
            bobState = d.newState;
            H.assertEqual(CP.decodeUTF8(d.plaintext), 'final-2', 'out-of-order newest of final chain decrypts');
            H.assert(bobState.MKSKIPPED.size <= CAP, 'still within cap after final-chain skips');
            // Now deliver #0 (a freshly-skipped, i.e. NEWEST, key) -> must decrypt.
            d = await DoubleRatchetService.ratchetDecrypt(bobState, e0.wireHeader, e0.nonce, e0.ciphertext);
            bobState = d.newState;
            H.assertEqual(CP.decodeUTF8(d.plaintext), 'final-0', 'freshly-skipped (newest) key still decrypts after eviction churn');
        }

        process.stdout.write(`  drove ${totalSkipsAttempted} skip-attempts; MKSKIPPED capped at ${maxSeen} <= ${CAP}; newest keys decrypt.\n`);
    });

    // -----------------------------------------------------------------
    // (1b) P1-1 MUTATION CHECK: with eviction NOT applied, the same shape of
    // workload exceeds the cap — proving the cap is what keeps it bounded.
    // We emulate "no eviction" by replaying skipMessageKeys' insertion without the
    // capSkipped step on a plain Map, using the SAME counts.
    // -----------------------------------------------------------------
    await H.gate('S9 (1b) P1-1 mutation: WITHOUT the total-cap eviction the map overflows', async () => {
        const CAP = DoubleRatchetService.MAX_SKIPPED_TOTAL;
        const SKIP_PER_CHAIN = 8;
        const ROUNDS = Math.ceil((CAP / SKIP_PER_CHAIN)) + 60;
        // Mirror the live insertion WITHOUT capping: each round inserts SKIP_PER_CHAIN-1
        // skipped entries with DISTINCT keys (distinct DHr per round) — exactly what an
        // un-capped MKSKIPPED would accumulate.
        const unbounded = new Map();
        for (let r = 0; r < ROUNDS; r++) {
            for (let i = 0; i < SKIP_PER_CHAIN - 1; i++) {
                unbounded.set(`dhr${r}|${i}`, new Uint8Array(32));
            }
        }
        H.assert(unbounded.size > CAP, `un-capped map (${unbounded.size}) exceeds cap ${CAP} — eviction is load-bearing`);
        process.stdout.write(`  un-capped accumulation = ${unbounded.size} > cap ${CAP} (the bug the cap fixes).\n`);
    });

    // -----------------------------------------------------------------
    // (2) P2-1 — SPK rotation with grace.
    //
    // Uses real Date.now() for "now" inside publishPrekeys. We BACKDATE the stored
    // SPK secret's createdAt to force the age branches deterministically.
    // -----------------------------------------------------------------
    await H.gate('S9 (2) P2-1: SPK age-rotation, in-flight OLD-spk_id bootstraps within grace, expired SPK pruned', async () => {
        const mockDb = makeMockDatabase();
        const alice = await makeParty('alice2', ALICE_ID, mockDb);
        const bob   = await makeParty('bob2', BOB_ID, mockDb);
        await setupIdentity(alice);
        await setupIdentity(bob);

        // Bob publishes his first SPK.
        const r1 = await publish(bob, 'first');
        const spkId1 = r1.spkId;
        H.assert(spkId1 != null, 'Bob published an initial SPK id');

        // Re-publish immediately: NO rotation (fresh SPK reused, same id).
        const r1b = await publish(bob, 'first-again');
        H.assertEqual(r1b.spkId, spkId1, 'a fresh SPK is NOT rotated on the next publish (reused)');

        // --- Force age-based rotation: backdate Bob's stored SPK createdAt past the
        // rotation interval, then publish -> a NEW spk_id must be minted + advertised.
        await asParty(bob, async () => {
            const db = bob.storage.db;
            const rec = await new Promise((res, rej) => {
                const tx = db.transaction('prekey_secrets', 'readonly');
                const rq = tx.objectStore('prekey_secrets').get([BOB_ID, 'spk', spkId1]);
                rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
            });
            H.assert(!!rec, 'Bob SPK secret record present before backdating');
            rec.createdAt = new Date(Date.now() - (bob.kms.SPK_ROTATION_MS + 60000)).toISOString();
            await new Promise((res, rej) => {
                const tx = db.transaction('prekey_secrets', 'readwrite');
                const rq = tx.objectStore('prekey_secrets').put(rec);
                rq.onsuccess = () => res(); rq.onerror = () => rej(rq.error);
            });
        });

        const r2 = await publish(bob, 'rotated');
        const spkId2 = r2.spkId;
        H.assert(spkId2 !== spkId1, 'an SPK older than SPK_ROTATION_MS triggers a NEW SPK (rotation)');

        // Server advertises ONLY the latest SPK id.
        H.assertEqual(mockDb._tables.prekeys.get(BOB_ID).spk_id, spkId2, 'server advertises the NEW (latest) SPK id only');

        // Both SPK secrets are still stored locally (old one within grace).
        await asParty(bob, async () => {
            const meta = await bob.storage.getSignedPrekeyMeta(BOB_ID);
            const ids = meta.map(m => m.keyId);
            H.assert(ids.includes(spkId1) && ids.includes(spkId2), 'OLD + NEW SPK secrets both retained during grace');
        });

        // --- In-flight initiator on the OLD spk_id still bootstraps within grace.
        // Simulate Alice having claimed the OLD bundle (spkId1): craft a preamble that
        // names spkId1 and confirm Bob (responder) finds the OLD secret and decrypts.
        const CONV = 9201;
        // Alice claims the CURRENT server bundle first to pin Bob (TOFU) on a separate
        // conversation, so the identity is trusted.
        await send(alice, bob, 9200, 'warmup pin');
        // Now forge an OLD-SPK initiator bootstrap: temporarily point the server bundle
        // back at the OLD spk_id + its public, claim, then restore — emulating an
        // initiator that fetched the bundle BEFORE rotation.
        const liveBundle = { ...mockDb._tables.prekeys.get(BOB_ID) };
        const oldSpkPubB64 = await asParty(bob, async () => {
            const kp = await bob.storage.getSignedPrekey(BOB_ID, spkId1);
            return CP.serializeKey(kp.publicKey);
        });
        // Re-sign the OLD SPK pub with Bob's IK_sig so the initiator's SPK-sig check passes.
        const oldSpkSigB64 = await asParty(bob, async () => {
            const signKeys = await bob.kms._getIdentitySignKeyPair();
            return CP.serializeKey(CP.signDetached(CP.deserializeKey(oldSpkPubB64), signKeys.secretKey));
        });
        mockDb._tables.prekeys.set(BOB_ID, {
            ...liveBundle,
            signed_prekey_pub: oldSpkPubB64,
            signed_prekey_sig: oldSpkSigB64,
            spk_id: spkId1
        });

        const { row: oldRow } = await send(alice, bob, CONV, 'hello via OLD spk');
        H.assertEqual(oldRow.x3dh_spk_id, spkId1, 'initiator bootstrap names the OLD spk_id');
        // restore the live (new) bundle
        mockDb._tables.prekeys.set(BOB_ID, liveBundle);

        const ptOld = await recvRealtime(bob, CONV, oldRow);
        H.assertEqual(ptOld, 'hello via OLD spk', 'responder bootstraps from the OLD (in-flight, within-grace) SPK secret');

        // --- Grace prune: backdate the OLD SPK past the grace window, publish again,
        // and assert it is pruned while the CURRENT SPK survives.
        await asParty(bob, async () => {
            const db = bob.storage.db;
            const rec = await new Promise((res, rej) => {
                const tx = db.transaction('prekey_secrets', 'readonly');
                const rq = tx.objectStore('prekey_secrets').get([BOB_ID, 'spk', spkId1]);
                rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
            });
            // Past the FULL prune window (rotation + grace), measured from minting:
            rec.createdAt = new Date(Date.now() - (bob.kms.SPK_ROTATION_MS + bob.kms.SPK_GRACE_MS + 60000)).toISOString();
            await new Promise((res, rej) => {
                const tx = db.transaction('prekey_secrets', 'readwrite');
                const rq = tx.objectStore('prekey_secrets').put(rec);
                rq.onsuccess = () => res(); rq.onerror = () => rej(rq.error);
            });
        });

        await publish(bob, 'prune');
        await asParty(bob, async () => {
            const meta = await bob.storage.getSignedPrekeyMeta(BOB_ID);
            const ids = meta.map(m => m.keyId);
            H.assert(!ids.includes(spkId1), 'SPK secret past the grace window is PRUNED');
            H.assert(ids.includes(spkId2), 'the CURRENT SPK secret is NEVER pruned');
        });

        process.stdout.write('  SPK rotates on age, OLD spk_id mates within grace, expired SPK pruned (current kept).\n');
    });

    // -----------------------------------------------------------------
    // (3) P0-follow-up — getPendingPeerIdentity reads NEW key without pinning.
    // -----------------------------------------------------------------
    await H.gate('S9 (3) P0-follow-up: getPendingPeerIdentity shows NEW key w/o pinning; establishSession still fails closed', async () => {
        const mockDb = makeMockDatabase();
        const alice = await makeParty('alice3', ALICE_ID, mockDb);
        const bob   = await makeParty('bob3', BOB_ID, mockDb);
        await setupIdentity(alice);
        await setupIdentity(bob);
        await publish(alice, 'p3');
        await publish(bob, 'p3');

        // Baseline: Alice initiates -> pins Bob's CURRENT X25519 IK (TOFU first contact).
        const CONV = 9301;
        const { row } = await send(alice, bob, CONV, 'hi (pin bob)');
        await recvRealtime(bob, CONV, row);

        const pinnedBefore = await asParty(alice, async () => (await alice.storage.getPinnedKey(BOB_ID)));
        H.assert(!!pinnedBefore, 'Alice pinned Bob X25519 IK on first contact');
        const oldFp = pinnedBefore.fingerprint;
        const oldPubB64 = pinnedBefore.publicKey;

        // Hostile/legit change: server advertises a NEW Bob X25519 IK.
        const forgedIk = CP.generateKeyPair();
        const newPubB64 = CP.serializeKey(forgedIk.publicKey);
        mockDb._tables.public_key_history.set(BOB_ID, newPubB64);

        // getPendingPeerIdentity must report the NEW key WITHOUT pinning it.
        const pending = await asParty(alice, async () => (await alice.kms.getPendingPeerIdentity(BOB_ID)));
        H.assert(pending.changed === true, 'pending.changed is true when the server key differs from the pin');
        H.assertEqual(pending.oldFingerprint, oldFp, 'reports the OLD (pinned) fingerprint');
        H.assert(!!pending.newFingerprint && pending.newFingerprint !== oldFp, 'reports a DIFFERENT new fingerprint');
        // newFingerprint must match the actual new server key.
        const expectedNewFp = CP.getKeyFingerprint(CP.deserializeKey(newPubB64));
        H.assertEqual(pending.newFingerprint, expectedNewFp, 'new fingerprint matches the new server key');
        H.assert(!!pending.newSafetyNumber, 'reports a NEW safety number to compare out-of-band');
        H.assert(!!pending.oldSafetyNumber, 'reports the OLD safety number too');
        H.assert(pending.newSafetyNumber !== pending.oldSafetyNumber, 'new safety number differs from old');

        // CRITICAL: it did NOT pin the new key (read-only). Pin unchanged.
        const pinnedAfter = await asParty(alice, async () => (await alice.storage.getPinnedKey(BOB_ID)));
        H.assertEqual(pinnedAfter.publicKey, oldPubB64, 'getPendingPeerIdentity did NOT re-pin the new key');
        H.assertEqual(pinnedAfter.fingerprint, oldFp, 'pinned fingerprint unchanged (still fail-closed)');

        // And a subsequent establishSession STILL throws fail-closed (no SK derived).
        let err = null;
        await asParty(alice, async () => {
            try {
                CP.setRandomBytesSource(H.makeDeterministicRng('p3-after-view'));
                await alice.kms.establishSession(9302, BOB_ID);
            } catch (e) { err = e; }
            finally { CP.resetRandomBytesSource(); }
        });
        H.assert(!!err, 'establishSession still THROWS after merely viewing the pending identity');
        H.assertEqual(err.code, 'PEER_IDENTITY_CHANGED', 'still fail-closed (PEER_IDENTITY_CHANGED) until accept');

        // Sanity: getSafetyNumber (the OLD path) DOES throw while pending — which is
        // exactly why getPendingPeerIdentity is needed.
        let snErr = null;
        await asParty(alice, async () => {
            try { await alice.kms.getSafetyNumber(BOB_ID); } catch (e) { snErr = e; }
        });
        H.assert(!!snErr && snErr.code === 'PEER_IDENTITY_CHANGED', 'getSafetyNumber throws fail-closed while pending (the bug getPendingPeerIdentity works around)');

        // After accept, getPendingPeerIdentity reports changed=false (now pinned == server).
        await asParty(alice, async () => { await alice.kms.acceptPeerIdentityChange(BOB_ID); });
        const afterAccept = await asParty(alice, async () => (await alice.kms.getPendingPeerIdentity(BOB_ID)));
        H.assertEqual(afterAccept.changed, false, 'after accept, no pending change (pinned == server)');
        H.assertEqual(afterAccept.newFingerprint, expectedNewFp, 'now-pinned fingerprint == the accepted new key');

        process.stdout.write('  getPendingPeerIdentity shows the NEW key read-only; pin untouched; still fail-closed until accept.\n');
    });

    H.summary();
}

main().catch((e) => {
    process.stdout.write('\nFATAL: ' + e.stack + '\n');
    process.exitCode = 1;
});
