/**
 * X3DH Key Agreement Service (Extended Triple Diffie-Hellman) -- PURE, offline.
 *
 * Implements the X3DH async handshake (Marlinspike/Perrin) on top of the
 * project's existing primitives, per FORWARD_SECRECY_DESIGN section 2:
 *   - DH          : X25519 raw scalar mult  (CryptoPrimitivesService.dhRaw)  <- NOT box.before
 *   - KDF         : HKDF-SHA256             (KeyDerivationService._hkdf)
 *   - Signatures  : Ed25519                 (CryptoPrimitivesService verifyDetached / signDetached)
 *
 * This module is PURE: no IndexedDB, no DB, no network. It is the S2 stage --
 * it produces the X3DH shared secret SK (the initial root key) plus the bytes
 * the responder needs (initiator IK pub, ephemeral EK pub, which prekeys were
 * used). It does NOT run the Double Ratchet: the SK output is handed to
 * DoubleRatchetService.ratchetInitAlice / ratchetInitBob (S1). Keeping that
 * boundary clean is deliberate (design section 4.1).
 *
 * --- The four DHs (design section 2.3) ---
 *   Sender = Alice (initiator), Recipient = Bob (offline). Alice makes an
 *   ephemeral X25519 keypair EK_a.
 *
 *     DH1 = DH(IK_a,  SPK_b)     // bind Alice's long-term identity to Bob's SPK
 *     DH2 = DH(EK_a,  IK_b)      // bind Alice's ephemeral to Bob's identity
 *     DH3 = DH(EK_a,  SPK_b)     // bind Alice's ephemeral to Bob's SPK
 *     DH4 = DH(EK_a,  OPK_b)     // OPTIONAL -- omitted if Bob's OPK pool is empty
 *
 *     SK  = HKDF-SHA256(
 *             ikm  = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4],
 *             salt = 32 zero bytes,
 *             info = "MoneyTracker:X3DH:v1",
 *             len  = 32 )
 *
 *   The 0xFF*32 prefix is the X3DH-spec domain separator (F = 0xFF repeated
 *   `curve-key-length` times for X25519). DH() = dhRaw = nacl.scalarMult.
 *
 * --- Signed-prekey verification (fail closed) ---
 *   Before ANY DH, the initiator verifies Bob's published signed_prekey_sig
 *   (Ed25519 detached signature over the SPK public bytes) against Bob's
 *   published Ed25519 identity signing key (IK_sig). A bad/absent/tampered
 *   signature REJECTS the handshake (throws) -- we never derive SK from an
 *   unverified prekey. The Ed25519 key itself is pinned via TOFU at a higher
 *   layer (design section 2.4); that pinning is S6 wiring, not S2.
 *
 * --- Resolved ambiguities (see RETURN notes) ---
 *   1) HKDF salt: the X3DH spec uses an all-zero salt (HKDF default) together
 *      with the 0xFF*32 IKM prefix. keyDerivationService._hkdf substitutes a
 *      derived "context salt" when salt is null/empty (a security default for
 *      other call sites), so we pass an EXPLICIT 32-byte zero salt to get the
 *      true spec behavior. Same technique the ratchet uses for its AEAD key.
 *   2) AD (associated data) = IK_a_pub || IK_b_pub is returned for the caller to
 *      bind into the first-message AEAD (design 2.3). X3DH itself does not need
 *      it to derive SK; we surface it so S5/S6 can pass it to ratchetEncrypt.
 *   3) Bob's ratchet keypair IS his SPK keypair (design 3.3), so the SK +
 *      Bob's SPK secret are exactly what ratchetInitBob/Alice consume.
 */

(function () {
    'use strict';

    // Domain separators. Frozen -- changing these breaks the X3DH KAT.
    const INFO_X3DH = 'MoneyTracker:X3DH:v1';
    const F_PREFIX_LEN = 32;          // 0xFF repeated curve-key-length (32 for X25519)
    const ZERO_SALT_LEN = 32;         // explicit all-zero HKDF salt (spec default)

    // ---- dependency resolution (browser globals or node require) ----------
    function _cp() {
        const CP = (typeof window !== 'undefined' && window.CryptoPrimitivesService) ||
                   (typeof global !== 'undefined' && global.CryptoPrimitivesService) ||
                   (typeof CryptoPrimitivesService !== 'undefined' ? CryptoPrimitivesService : null);
        if (!CP) throw new Error('[X3DHService] CryptoPrimitivesService unavailable');
        return CP;
    }
    function _kdf() {
        const K = (typeof window !== 'undefined' && window.KeyDerivationService) ||
                  (typeof global !== 'undefined' && global.KeyDerivationService) ||
                  (typeof KeyDerivationService !== 'undefined' ? KeyDerivationService : null);
        if (!K) throw new Error('[X3DHService] KeyDerivationService unavailable');
        return K;
    }

    // ---- byte helpers -----------------------------------------------------
    function concatBytes() {
        let total = 0;
        for (const a of arguments) total += a.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const a of arguments) { out.set(a, off); off += a.length; }
        return out;
    }
    function filled(len, value) {
        const out = new Uint8Array(len);
        out.fill(value);
        return out;
    }

    /**
     * Core SK derivation, shared by both sides so they are byte-for-byte
     * identical by construction. Order of the DHs is FIXED (DH1..DH4) per spec.
     *
     * @param {Uint8Array} dh1
     * @param {Uint8Array} dh2
     * @param {Uint8Array} dh3
     * @param {Uint8Array|null} dh4  -- omitted (null) when no one-time prekey
     * @returns {Promise<Uint8Array>} 32-byte shared secret SK
     */
    async function _deriveSK(dh1, dh2, dh3, dh4) {
        const F = filled(F_PREFIX_LEN, 0xFF);     // X3DH domain-separation prefix
        const ikm = dh4
            ? concatBytes(F, dh1, dh2, dh3, dh4)
            : concatBytes(F, dh1, dh2, dh3);
        // Explicit zero salt => true HKDF default (bypasses the context-salt
        // fallback in keyDerivationService, which is not what X3DH wants).
        const salt = filled(ZERO_SALT_LEN, 0x00);
        return await _kdf()._hkdf(ikm, INFO_X3DH, 32, salt);
    }

    /**
     * Verify Bob's signed-prekey signature. FAIL CLOSED on any problem.
     *
     * @param {Uint8Array} spkPub          Bob's X25519 SPK public (the signed bytes)
     * @param {Uint8Array} spkSig          Ed25519 detached signature over spkPub
     * @param {Uint8Array} identitySignPub Bob's Ed25519 IK_sig public
     * @throws if the signature is missing/malformed/invalid
     */
    function verifySignedPrekey(spkPub, spkSig, identitySignPub) {
        const CP = _cp();
        if (!(spkPub instanceof Uint8Array) || spkPub.length !== 32) {
            throw new Error('[X3DHService] invalid SPK public key');
        }
        if (!(spkSig instanceof Uint8Array) || spkSig.length !== 64) {
            throw new Error('[X3DHService] invalid SPK signature (expected 64-byte Ed25519 detached sig)');
        }
        if (!(identitySignPub instanceof Uint8Array) || identitySignPub.length !== 32) {
            throw new Error('[X3DHService] invalid Ed25519 identity signing public key');
        }
        const ok = CP.verifyDetached(spkPub, spkSig, identitySignPub);
        if (!ok) {
            throw new Error('[X3DHService] SPK signature verification FAILED -- rejecting handshake (fail closed)');
        }
        return true;
    }

    // =======================================================================
    // INITIATOR (Alice)
    // =======================================================================

    /**
     * Initiator-side X3DH. Alice derives SK from Bob's published prekey bundle.
     *
     * Verifies Bob's SPK signature FIRST (rejects on bad sig), generates a fresh
     * ephemeral EK_a (through the seedable RNG seam), computes the four DHs with
     * dhRaw, and derives SK. DH4 is included iff a one-time prekey is supplied.
     *
     * @param {Object} args
     * @param {Object} args.identityKeyPair    Alice's X25519 IK { publicKey, secretKey }
     * @param {Object} args.peerBundle         Bob's published bundle:
     *        {
     *          identityKeyPub:     Uint8Array(32)  // Bob IK_b (X25519) public
     *          identitySignPub:    Uint8Array(32)  // Bob IK_sig (Ed25519) public
     *          signedPrekeyPub:    Uint8Array(32)  // Bob SPK_b (X25519) public
     *          signedPrekeySig:    Uint8Array(64)  // Ed25519 sig over signedPrekeyPub
     *          spkId:              number          // SPK rotation id (passed through)
     *          oneTimePrekeyPub?:  Uint8Array(32)  // OPK_b public (optional)
     *          oneTimePrekeyId?:   number          // OPK id (optional, passed through)
     *        }
     * @param {Uint8Array} [args.trustedIdentitySignPub]  Ed25519 IK_sig to verify the
     *        SPK signature against. When the caller has a TOFU-pinned IK_sig, it
     *        passes the PINNED value here so a swapped-and-re-signed bundle is
     *        rejected (fail closed). Omitted on first contact -> falls back to the
     *        bundle's own identitySignPub (TOFU).
     * @returns {Promise<{ SK, preamble, ephemeralKeyPair, associatedData }>}
     *   - SK              : 32-byte shared secret (feed to ratchetInitAlice)
     *   - preamble        : the bytes Bob needs (all base64 via serializeKey),
     *                       { ikPub, ikSignPub, ekPub, spkId, opkId|null }
     *   - ephemeralKeyPair: Alice's EK_a { publicKey, secretKey } (raw bytes)
     *   - associatedData  : IK_a_pub || IK_b_pub (for first-message AEAD binding)
     */
    async function deriveInitiatorRoot(args) {
        const CP = _cp();
        const ik = args && args.identityKeyPair;
        const b = args && args.peerBundle;
        if (!ik || !ik.secretKey || !ik.publicKey) {
            throw new Error('[X3DHService] deriveInitiatorRoot: missing initiator identityKeyPair');
        }
        if (!b) throw new Error('[X3DHService] deriveInitiatorRoot: missing peerBundle');

        // 1) Verify Bob's SPK signature BEFORE any DH (fail closed). Bind the check
        //    to the caller's TRUSTED (TOFU-pinned) IK_sig when provided; otherwise
        //    fall back to the bundle's own IK_sig (first-contact TOFU). Verifying
        //    against a pinned key means a swapped-then-re-signed bundle is rejected.
        const trustedSignPub = (args.trustedIdentitySignPub instanceof Uint8Array)
            ? args.trustedIdentitySignPub
            : b.identitySignPub;
        verifySignedPrekey(b.signedPrekeyPub, b.signedPrekeySig, trustedSignPub);

        // 2) Fresh ephemeral EK_a (deterministic under an injected RNG in tests).
        const EK = CP.generateKeyPair();

        // 3) The four DHs (fixed order, dhRaw = scalarMult).
        const hasOpk = !!b.oneTimePrekeyPub;
        const dh1 = CP.dhRaw(ik.secretKey, b.signedPrekeyPub);    // DH(IK_a, SPK_b)
        const dh2 = CP.dhRaw(EK.secretKey, b.identityKeyPub);     // DH(EK_a, IK_b)
        const dh3 = CP.dhRaw(EK.secretKey, b.signedPrekeyPub);    // DH(EK_a, SPK_b)
        const dh4 = hasOpk ? CP.dhRaw(EK.secretKey, b.oneTimePrekeyPub) : null; // DH(EK_a, OPK_b)

        const SK = await _deriveSK(dh1, dh2, dh3, dh4);

        // AD = IK_a_pub || IK_b_pub (caller binds into first-message AEAD).
        const associatedData = concatBytes(ik.publicKey, b.identityKeyPub);

        return {
            SK: SK,
            preamble: {
                ikPub:     CP.serializeKey(ik.publicKey),
                ikSignPub: null, // initiator does not sign in X3DH; filled by caller if pinning its own IK_sig
                ekPub:     CP.serializeKey(EK.publicKey),
                spkId:     (b.spkId !== undefined && b.spkId !== null) ? (b.spkId | 0) : null,
                opkId:     hasOpk
                    ? ((b.oneTimePrekeyId !== undefined && b.oneTimePrekeyId !== null) ? (b.oneTimePrekeyId | 0) : null)
                    : null,
            },
            ephemeralKeyPair: EK,
            associatedData: associatedData,
        };
    }

    // =======================================================================
    // RESPONDER (Bob)
    // =======================================================================

    /**
     * Responder-side X3DH. Bob recomputes the identical SK from his local
     * secrets + the preamble Alice attached to the first message.
     *
     * Bob trusts his own SPK (he published it), so there is no signature check
     * here -- the signature check is the INITIATOR's job (Bob verifying his own
     * signature would be pointless). The deletion of the consumed OPK is the
     * caller's responsibility (S4 persistence); this pure module just consumes
     * the matching OPK secret it is handed.
     *
     * @param {Object} args
     * @param {Object} args.identityKeyPair  Bob's X25519 IK_b { publicKey, secretKey }
     * @param {Object} args.signedPrekeyPair Bob's X25519 SPK_b { publicKey, secretKey }
     * @param {Object} [args.oneTimePrekeyPair] Bob's matching OPK { publicKey, secretKey }
     *        -- REQUIRED iff the preamble carries opkId (i.e. Alice used an OPK).
     * @param {Object} args.preamble         Alice's preamble (from deriveInitiatorRoot):
     *        { ikPub, ekPub, opkId|null, ... } (base64 strings for the key fields)
     * @returns {Promise<{ SK, associatedData }>}
     *   - SK             : 32-byte shared secret (== initiator's SK)
     *   - associatedData : IK_a_pub || IK_b_pub (matches the initiator's AD)
     */
    async function deriveResponderRoot(args) {
        const CP = _cp();
        const ik = args && args.identityKeyPair;
        const spk = args && args.signedPrekeyPair;
        const opk = args && args.oneTimePrekeyPair;
        const p = args && args.preamble;
        if (!ik || !ik.secretKey) throw new Error('[X3DHService] deriveResponderRoot: missing Bob identityKeyPair');
        if (!spk || !spk.secretKey) throw new Error('[X3DHService] deriveResponderRoot: missing Bob signedPrekeyPair');
        if (!p) throw new Error('[X3DHService] deriveResponderRoot: missing preamble');

        const ikA  = CP.deserializeKey(p.ikPub);   // Alice IK_a public
        const ekA  = CP.deserializeKey(p.ekPub);   // Alice EK_a public

        const usedOpk = (p.opkId !== undefined && p.opkId !== null);
        if (usedOpk && (!opk || !opk.secretKey)) {
            throw new Error('[X3DHService] preamble references opkId ' + p.opkId +
                ' but no matching one-time prekey secret was provided');
        }

        // Recompute the four DHs from BOB's side. Each mirrors the initiator:
        //   DH1 = DH(IK_a, SPK_b)  <=>  DH(SPK_b.sec, IK_a.pub)
        //   DH2 = DH(EK_a, IK_b)   <=>  DH(IK_b.sec,  EK_a.pub)
        //   DH3 = DH(EK_a, SPK_b)  <=>  DH(SPK_b.sec, EK_a.pub)
        //   DH4 = DH(EK_a, OPK_b)  <=>  DH(OPK_b.sec, EK_a.pub)
        const dh1 = CP.dhRaw(spk.secretKey, ikA);
        const dh2 = CP.dhRaw(ik.secretKey,  ekA);
        const dh3 = CP.dhRaw(spk.secretKey, ekA);
        const dh4 = usedOpk ? CP.dhRaw(opk.secretKey, ekA) : null;

        const SK = await _deriveSK(dh1, dh2, dh3, dh4);

        // AD must match the initiator's: IK_a_pub || IK_b_pub.
        const associatedData = concatBytes(ikA, ik.publicKey);

        return { SK: SK, associatedData: associatedData };
    }

    const X3DHService = {
        INFO_X3DH: INFO_X3DH,
        deriveInitiatorRoot: deriveInitiatorRoot,
        deriveResponderRoot: deriveResponderRoot,
        verifySignedPrekey: verifySignedPrekey,
        // exposed for gates / higher layers
        _deriveSK: _deriveSK,
    };

    if (typeof window !== 'undefined') {
        window.X3DHService = X3DHService;
    }
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = X3DHService;
    }
})();
