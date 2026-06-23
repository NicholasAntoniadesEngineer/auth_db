/**
 * Double Ratchet Service (Signal Double Ratchet) -- PURE, offline.
 *
 * Implements the Signal Double Ratchet (Perrin/Marlinspike) on top of the
 * project's existing primitives:
 *   - DH                : X25519 raw scalar mult  (CryptoPrimitivesService.dhRaw)
 *   - KDF               : HKDF-SHA256             (KeyDerivationService._hkdf)
 *   - AEAD              : XSalsa20-Poly1305       (CryptoPrimitivesService secretbox)
 *   - RNG               : seedable seam           (CryptoPrimitivesService.randomBytes/generateKeyPair)
 *
 * This module is PURE: no IndexedDB, no DB, no network. All state is passed in
 * and returned out (immutably -- each operation returns a NEW state object), and
 * all randomness is routed through CryptoPrimitivesService so the FS/PCS proof
 * gates are deterministic under an injected RNG. Wiring into the live
 * encrypt/decrypt path is S5/S6, NOT here.
 *
 * --- KDFs (per FORWARD_SECRECY_DESIGN section 3.2) ---
 *   KDF_RK(RK, dh_out): out = HKDF(ikm=dh_out, salt=RK, info="MoneyTracker:RK:v1", 64)
 *                       => RK' = out[0:32], CK = out[32:64]
 *   KDF_CK(CK)        : MK  = HKDF(ikm=0x01, salt=CK, info="MoneyTracker:MK:v1", 32)
 *                       CK' = HKDF(ikm=0x02, salt=CK, info="MoneyTracker:CK:v1", 32)
 *   Passing salt = chain key (NOT the context-salt fallback) is what makes the
 *   ratchet IRREVERSIBLE: you cannot recover CK from CK' or MK. That is the
 *   forward-secrecy property gate (c) proves.
 *
 * --- Header binding (resolved ambiguity) ---
 *   secretbox (XSalsa20-Poly1305) takes NO additional authenticated data. The
 *   design permits "include the header in the HKDF info". We therefore derive
 *   the actual AEAD key from MK, mixing the serialized header (and, on message 0,
 *   the optional X3DH associated data) into the HKDF info:
 *       encKey = HKDF(ikm=MK, salt=<32 zero bytes>,
 *                     info = "MoneyTracker:MsgAEAD:v1" || serialize(header) [|| AD], 32)
 *   Any tampering with the header (ratchet pub / pn / n) changes encKey, so
 *   secretbox.open fails -> the header is authenticated. The salt here is the
 *   all-zero string passed EXPLICITLY (we control the salt; this derivation is
 *   not a chain step so irreversibility is not required), which deliberately
 *   bypasses keyDerivationService's context-salt fallback.
 */

(function () {
    'use strict';

    const MAX_SKIP = 1000;

    // Info strings (domain separation). Frozen -- changing these breaks the KAT.
    const INFO_RK   = 'MoneyTracker:RK:v1';
    const INFO_MK   = 'MoneyTracker:MK:v1';
    const INFO_CK   = 'MoneyTracker:CK:v1';
    const INFO_AEAD = 'MoneyTracker:MsgAEAD:v1';

    // ---- dependency resolution (browser globals or node require) ----------
    function _cp() {
        const CP = (typeof window !== 'undefined' && window.CryptoPrimitivesService) ||
                   (typeof global !== 'undefined' && global.CryptoPrimitivesService) ||
                   (typeof CryptoPrimitivesService !== 'undefined' ? CryptoPrimitivesService : null);
        if (!CP) throw new Error('[DoubleRatchetService] CryptoPrimitivesService unavailable');
        return CP;
    }
    function _kdf() {
        const K = (typeof window !== 'undefined' && window.KeyDerivationService) ||
                  (typeof global !== 'undefined' && global.KeyDerivationService) ||
                  (typeof KeyDerivationService !== 'undefined' ? KeyDerivationService : null);
        if (!K) throw new Error('[DoubleRatchetService] KeyDerivationService unavailable');
        return K;
    }

    // ---- byte helpers -----------------------------------------------------
    function b64(bytes) { return _cp().serializeKey(bytes); }
    function unb64(s) { return _cp().deserializeKey(s); }
    function concatBytes() {
        let total = 0;
        for (const a of arguments) total += a.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const a of arguments) { out.set(a, off); off += a.length; }
        return out;
    }
    function bytesEqual(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    // ---- KDFs -------------------------------------------------------------
    // HKDF with EXPLICIT salt -- we always pass salt so keyDerivationService's
    // context-salt fallback is never hit (info is passed as the bytes->string
    // boundary; _hkdf re-encodes the string via TextEncoder, so we keep info ASCII).

    async function KDF_RK(RK, dhOut) {
        // 64-byte output split into RK' || CK.
        const out = await _kdf()._hkdf(dhOut, INFO_RK, 64, RK);
        return { RK: out.slice(0, 32), CK: out.slice(32, 64) };
    }

    async function KDF_CK(CK) {
        // Single-byte ikm constants give MK vs CK separation; salt = CK keeps the
        // chain irreversible.
        const MK = await _kdf()._hkdf(new Uint8Array([0x01]), INFO_MK, 32, CK);
        const CKnext = await _kdf()._hkdf(new Uint8Array([0x02]), INFO_CK, 32, CK);
        return { CK: CKnext, MK: MK };
    }

    // ---- Header (de)serialization -----------------------------------------
    // Header = { dh: <ratchet pub bytes>, pn: int, n: int }. Serialized
    // canonically so the SAME header always yields the SAME AEAD info, and any
    // tamper changes the bytes.
    function headerToWire(header) {
        return { dh: b64(header.dh), pn: header.pn, n: header.n };
    }
    function headerFromWire(wire) {
        return { dh: unb64(wire.dh), pn: wire.pn | 0, n: wire.n | 0 };
    }
    function serializeHeaderBytes(header) {
        // 32-byte dh pub || 4-byte pn (BE) || 4-byte n (BE).
        const buf = new Uint8Array(40);
        buf.set(header.dh, 0);
        const dv = new DataView(buf.buffer);
        dv.setUint32(32, header.pn >>> 0, false);
        dv.setUint32(36, header.n >>> 0, false);
        return buf;
    }

    // Derive the per-message AEAD key from MK, binding the header (+ optional AD).
    //
    // secretbox has no AAD slot, so we authenticate the header by mixing it into
    // the key derivation: encKey = HKDF(ikm=MK, salt=headerBytes[||AD],
    // info=INFO_AEAD). _hkdf takes `info` as a string (re-encoded via TextEncoder)
    // but accepts `salt` as raw bytes, so we carry the variable-length binding
    // bytes (serialized header, plus optional X3DH AD on msg 0) through the salt
    // parameter. Folding into the salt authenticates the header just as well as
    // folding into info: any tamper changes encKey, so secretbox.open fails.
    async function deriveAeadKey(MK, header, adBytes) {
        let saltBytes = serializeHeaderBytes(header);
        if (adBytes && adBytes.length) saltBytes = concatBytes(saltBytes, adBytes);
        return await _kdf()._hkdf(MK, INFO_AEAD, 32, saltBytes);
    }

    // ---- AEAD (secretbox) with header binding -----------------------------
    async function aeadEncrypt(MK, header, plaintextBytes, adBytes) {
        const CP = _cp();
        const encKey = await deriveAeadKey(MK, header, adBytes);
        const { ciphertext, nonce } = CP.encryptBytes(plaintextBytes, encKey);
        return { ciphertext: b64(ciphertext), nonce: b64(nonce) };
    }

    async function aeadDecrypt(MK, header, ciphertextB64, nonceB64, adBytes) {
        const CP = _cp();
        const encKey = await deriveAeadKey(MK, header, adBytes);
        const ct = unb64(ciphertextB64);
        const nonce = unb64(nonceB64);
        const pt = CP.nacl.secretbox.open(ct, nonce, encKey);
        if (!pt) throw new Error('[DoubleRatchetService] AEAD authentication failed (bad key/header/ciphertext)');
        return pt;
    }

    // ---- State helpers ----------------------------------------------------
    // State is plain JS with Uint8Array fields; MKSKIPPED is a Map keyed by
    // "<dh_pub_b64>|<n>" -> message key bytes. We clone on each op (immutable).
    function cloneState(s) {
        const copy = {
            RK:  s.RK ? Uint8Array.from(s.RK) : null,
            CKs: s.CKs ? Uint8Array.from(s.CKs) : null,
            CKr: s.CKr ? Uint8Array.from(s.CKr) : null,
            DHs: s.DHs ? { publicKey: Uint8Array.from(s.DHs.publicKey), secretKey: Uint8Array.from(s.DHs.secretKey) } : null,
            DHr: s.DHr ? Uint8Array.from(s.DHr) : null,
            Ns: s.Ns | 0,
            Nr: s.Nr | 0,
            PN: s.PN | 0,
            MKSKIPPED: new Map(),
        };
        for (const [k, v] of s.MKSKIPPED) copy.MKSKIPPED.set(k, Uint8Array.from(v));
        return copy;
    }
    function skipKey(dhPub, n) { return b64(dhPub) + '|' + n; }

    // =======================================================================
    // INIT
    // =======================================================================

    /**
     * Alice (initiator) init. Alice already holds Bob's ratchet public key
     * (= Bob's signed prekey public). SK is the X3DH root.
     */
    async function ratchetInitAlice(SK, DHr_bob) {
        const CP = _cp();
        const DHs = CP.generateKeyPair();
        const dhOut = CP.dhRaw(DHs.secretKey, DHr_bob);
        const { RK, CK } = await KDF_RK(SK, dhOut);
        return {
            RK: RK,
            CKs: CK,
            CKr: null,
            DHs: DHs,
            DHr: Uint8Array.from(DHr_bob),
            Ns: 0, Nr: 0, PN: 0,
            MKSKIPPED: new Map(),
        };
    }

    /**
     * Bob (responder) init. Bob's initial ratchet keypair IS his signed-prekey
     * keypair (so Alice's DH(EK/DHs, SPK) lines up without a second round-trip).
     * SK is the X3DH root.
     */
    async function ratchetInitBob(SK, DHs_bob) {
        return {
            RK: Uint8Array.from(SK),
            CKs: null,
            CKr: null,
            DHs: { publicKey: Uint8Array.from(DHs_bob.publicKey), secretKey: Uint8Array.from(DHs_bob.secretKey) },
            DHr: null,
            Ns: 0, Nr: 0, PN: 0,
            MKSKIPPED: new Map(),
        };
    }

    // =======================================================================
    // ENCRYPT
    // =======================================================================

    /**
     * @param {object}     state         current ratchet state (not mutated)
     * @param {Uint8Array} plaintextBytes
     * @param {Uint8Array} [adBytes]     optional associated data (e.g. X3DH AD on msg 0)
     * @returns {Promise<{header, wireHeader, nonce, ciphertext, messageKey, newState}>}
     */
    async function ratchetEncrypt(state, plaintextBytes, adBytes) {
        const s = cloneState(state);
        if (!s.CKs) throw new Error('[DoubleRatchetService] no sending chain (cannot encrypt before a send chain exists)');
        const { CK, MK } = await KDF_CK(s.CKs);
        s.CKs = CK;
        const header = { dh: Uint8Array.from(s.DHs.publicKey), pn: s.PN, n: s.Ns };
        s.Ns += 1;
        const { ciphertext, nonce } = await aeadEncrypt(MK, header, plaintextBytes, adBytes);
        return {
            header: header,
            wireHeader: headerToWire(header),
            nonce: nonce,
            ciphertext: ciphertext,
            messageKey: MK,          // exposed for the transcript KAT only
            newState: s,
        };
    }

    // =======================================================================
    // DECRYPT (+ DH ratchet)
    // =======================================================================

    /**
     * Try to consume a previously-skipped message key (out-of-order delivery).
     * On hit, DELETES the entry (consume-once) and returns { mk, newState }.
     */
    function trySkipped(s, header) {
        const key = skipKey(header.dh, header.n);
        if (s.MKSKIPPED.has(key)) {
            const mk = s.MKSKIPPED.get(key);
            s.MKSKIPPED.delete(key);
            return mk;
        }
        return null;
    }

    /**
     * Advance CKr up to `until`, storing each (DHr, n) -> MK into MKSKIPPED.
     * Refuses to exceed MAX_SKIP (fail closed against a malicious huge n).
     */
    async function skipMessageKeys(s, until) {
        if (s.Nr + MAX_SKIP < until) {
            throw new Error('[DoubleRatchetService] MAX_SKIP exceeded (refusing to skip ' + (until - s.Nr) + ' messages)');
        }
        if (!s.CKr) return; // no receive chain yet -> nothing to skip
        while (s.Nr < until) {
            const { CK, MK } = await KDF_CK(s.CKr);
            s.CKr = CK;
            s.MKSKIPPED.set(skipKey(s.DHr, s.Nr), MK);
            s.Nr += 1;
        }
    }

    /**
     * Perform a DH ratchet step on receiving a new ratchet public key.
     */
    async function dhRatchet(s, header) {
        const CP = _cp();
        s.PN = s.Ns;
        s.Ns = 0;
        s.Nr = 0;
        s.DHr = Uint8Array.from(header.dh);
        // step 1: advance receive chain with DH(our current sec, their new pub)
        let res = await KDF_RK(s.RK, CP.dhRaw(s.DHs.secretKey, s.DHr));
        s.RK = res.RK; s.CKr = res.CK;
        // fresh ratchet keypair
        s.DHs = CP.generateKeyPair();
        // step 2: advance send chain with DH(our NEW sec, their new pub) -- PCS heals here
        res = await KDF_RK(s.RK, CP.dhRaw(s.DHs.secretKey, s.DHr));
        s.RK = res.RK; s.CKs = res.CK;
    }

    /**
     * @param {object} state
     * @param {object} wireHeader  { dh:b64, pn:int, n:int }
     * @param {string} nonceB64
     * @param {string} ciphertextB64
     * @param {Uint8Array} [adBytes]
     * @returns {Promise<{plaintext:Uint8Array, messageKey:Uint8Array, newState}>}
     */
    async function ratchetDecrypt(state, wireHeader, nonceB64, ciphertextB64, adBytes) {
        const s = cloneState(state);
        const header = headerFromWire(wireHeader);

        // 1) previously-skipped / out-of-order?
        const skippedMk = trySkipped(s, header);
        if (skippedMk) {
            const pt = await aeadDecrypt(skippedMk, header, ciphertextB64, nonceB64, adBytes);
            return { plaintext: pt, messageKey: skippedMk, newState: s };
        }

        // 2) new ratchet public key -> DH ratchet step
        if (!s.DHr || !bytesEqual(header.dh, s.DHr)) {
            await skipMessageKeys(s, header.pn); // finish old recv chain up to PN
            await dhRatchet(s, header);
        }

        // 3) catch up within the current recv chain (out-of-order within chain)
        await skipMessageKeys(s, header.n);

        // 4) derive THIS message's key and advance
        const { CK, MK } = await KDF_CK(s.CKr);
        s.CKr = CK;
        s.Nr += 1;

        const pt = await aeadDecrypt(MK, header, ciphertextB64, nonceB64, adBytes);
        return { plaintext: pt, messageKey: MK, newState: s };
    }

    // =======================================================================
    // TEST-ONLY introspection (for the FS gate). Returns shallow copies.
    // =======================================================================
    function _inspectState(s) {
        return {
            RK: s.RK ? b64(s.RK) : null,
            CKs: s.CKs ? b64(s.CKs) : null,
            CKr: s.CKr ? b64(s.CKr) : null,
            DHs_pub: s.DHs ? b64(s.DHs.publicKey) : null,
            DHr: s.DHr ? b64(s.DHr) : null,
            Ns: s.Ns, Nr: s.Nr, PN: s.PN,
            skippedKeys: Array.from(s.MKSKIPPED.keys()),
            skippedCount: s.MKSKIPPED.size,
            hasSkipped: function (dhPubB64, n) { return s.MKSKIPPED.has(dhPubB64 + '|' + n); },
        };
    }

    const DoubleRatchetService = {
        MAX_SKIP: MAX_SKIP,
        ratchetInitAlice: ratchetInitAlice,
        ratchetInitBob: ratchetInitBob,
        ratchetEncrypt: ratchetEncrypt,
        ratchetDecrypt: ratchetDecrypt,
        // exposed primitives (useful for X3DH / gates)
        KDF_RK: KDF_RK,
        KDF_CK: KDF_CK,
        deriveAeadKey: deriveAeadKey,
        // test-only
        _inspectState: _inspectState,
        _headerToWire: headerToWire,
        _serializeHeaderBytes: serializeHeaderBytes,
    };

    if (typeof window !== 'undefined') {
        window.DoubleRatchetService = DoubleRatchetService;
    }
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = DoubleRatchetService;
    }
})();
