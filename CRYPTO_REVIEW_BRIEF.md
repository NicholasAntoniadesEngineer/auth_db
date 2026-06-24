# Cryptographic Review Brief — bespoke E2E protocol

**Date:** 2026-06-24
**Audience:** an external **human cryptographer** (or to scope a **libsignal**
migration).
**Why this exists:** the messaging E2E and the budget-sharing seal are
**hand-rolled** on TweetNaCl primitives. Internal review proved the
implementation is *self-consistent* (the S0–S13 suite round-trips and fails
closed) but **no cryptographer has validated the protocol composition, and there
are no cross-tests against a reference implementation.** This is, by our own
assessment, the single highest residual risk on the platform
(`RESIDUAL_RISKS.md` §b). Please be adversarial.

All citations are to the canonical (non-`/lib/` mirror) files.

---

## 0. Primitive layer (trusted as-is)

- **Library:** TweetNaCl `1.0.3` + nacl-util `0.15.1`, vendored/self-hosted
  (`auth_db/encryption/config/moneyTrackerEncryptionConfig.js:22`;
  `shared/vendor/crypto/nacl-fast.min.js`). No CDN. Verify the vendored bytes
  match upstream 1.0.3.
- **Wrapper:** `auth_db/encryption/services/cryptoPrimitivesService.js`
  - X25519 DH: `deriveSharedSecret()` → `nacl.box.before` (X25519 + HSalsa20),
    `:161`. Raw scalar mult helper `dhRaw()` used by X3DH.
  - Keypairs: `nacl.box.keyPair` / `keyPairFromSecretKey` (`:86`, `:97`).
  - AEAD: `encryptBytes`/`decryptBytes` and `encrypt`/`decrypt` →
    `nacl.secretbox` (XSalsa20-Poly1305), 24-byte nonce.
  - Ed25519: detached sign/verify (`verifyDetached`).
  - **RNG seam:** `randomBytes()` routes through a seam (`:112`) so tests can make
    it deterministic. **Cryptographer note:** confirm production builds CANNOT
    select the seeded/deterministic RNG (a deterministic nonce path is
    catastrophic for secretbox). See §6.

---

## 1. X3DH handshake

**File:** `auth_db/encryption/services/x3dhService.js`

- **Public API:** `deriveInitiatorRoot` (`:177`), `deriveResponderRoot` (`:251`),
  `verifySignedPrekey` (`:124`), `_deriveSK` (`:105`), `INFO_X3DH` (`:289`).
- **DH legs** (`:21-24`):
  - `DH1 = DH(IK_a, SPK_b)`, `DH2 = DH(EK_a, IK_b)`, `DH3 = DH(EK_a, SPK_b)`,
    `DH4 = DH(EK_a, OPK_b)` (optional).
- **SK derivation** (`_deriveSK`, `:105-113`):
  - `IKM = F || DH1 || DH2 || DH3 [|| DH4]` where `F = 0xFF × 32` (the X25519 X3DH
    curve domain prefix), concatenated at `:108-109`.
  - `SK = HKDF-SHA256(IKM, salt = 0x00 × 32, info = "MoneyTracker:X3DH:v1", L=32)`
    (zero-salt at `:112`, info constant at `:60`/`:289`).
- **Signed-prekey signature:** `verifySignedPrekey` (`:124-140`) verifies the
  Ed25519 detached signature over the SPK public bytes against the peer's
  published Ed25519 identity-signing key; **fail-closed** (throws on
  missing/invalid).
- **Responder identity pin (TOFU):** initiator path takes
  `args.trustedIdentitySignPub` (`:190-192`) — if a TOFU pin exists it is used for
  verification (rejects a bundle swap + re-sign); first contact falls back to the
  bundle's own `identitySignPub`.
- **OPK fallback:** `hasOpk = !!b.oneTimePrekeyPub` (`:199`); `dh4 = hasOpk ? … :
  null` (`:203`); `_deriveSK` drops DH4 when null (spec-permitted SPK-only X3DH).
- **Associated data:** `AD = IK_a_pub || IK_b_pub` is **returned** (`:49-50`) for
  the caller to bind into the *first-message AEAD* (it is not folded into SK
  itself). The Double Ratchet's `deriveAeadKey` consumes it (see §2).

### Claims to verify (X3DH)
1. **The `0xFF×32` prefix + zero-salt HKDF** is the intended X3DH-on-X25519 KDF
   and provides adequate domain separation from the ratchet KDFs (§2 uses the
   same HKDF with different info strings).
2. **Responder IK is actually pinned** in practice: confirm the *caller* always
   supplies `trustedIdentitySignPub` after first contact (the pin store /
   `_getPinnedPeerKey` chokepoint, SM-01), so a malicious server cannot swap
   `IK_b`/SPK on a *subsequent* session and MITM. First-contact TOFU is the
   inherent trust gap — confirm the safety-number/fingerprint UX exists.
3. **DH4-drop is safe:** an attacker cannot *force* the SPK-only path to weaken FS
   (the OPK pool exhaustion is server-observable). Confirm SPK-only sessions still
   get FS from the ratchet, and that the consumed-OPK id is authenticated.
4. **Identity-key separation:** there are TWO identity keys per user — an X25519
   `identity_keys.public_key` (DH) and an Ed25519 `prekeys.identity_sign_pub`
   (signatures). Confirm they are independently generated and that the TOFU pin
   covers the **signing** key that authenticates the bundle.

---

## 2. Double Ratchet

**File:** `auth_db/encryption/services/doubleRatchetService.js`

- **Public API:** `ratchetInitAlice` (`:247`), `ratchetInitBob` (`:271`),
  `ratchetEncrypt` (`:296`), `ratchetDecrypt` (`:380`), `KDF_RK` (`:117`),
  `KDF_CK` (`:123`), `deriveAeadKey` (`:160`), `deriveAttachmentRoot` (`:74`).
- **Root KDF** (`KDF_RK`, `:117-120`):
  `out = HKDF(IKM = dh_out, salt = RK, info = "MoneyTracker:RK:v1", L=64)`;
  `RK' = out[0:32]`, `CK = out[32:64]`. Info `:58`.
- **Chain KDF** (`KDF_CK`, `:123-128`):
  `MK  = HKDF(IKM = 0x01, salt = CK, info = "MoneyTracker:MK:v1", L=32)`;
  `CK' = HKDF(IKM = 0x02, salt = CK, info = "MoneyTracker:CK:v1", L=32)`.
  Single-byte IKM constants `0x01`/`0x02` separate MK vs next-CK. Info `:59`/`:60`.
- **AEAD key + header authentication** (`deriveAeadKey`, `:160-178`):
  `encKey = HKDF(IKM = MK, salt = serializeHeader(header) [|| AD],
  info = "MoneyTracker:MsgAEAD:v1", L=32)`. Header serialization (`:141-148`) =
  `ratchet_pub(32) || PN(4 BE) || N(4 BE)` = 40 bytes. Tampering with the header
  changes the key → AEAD open fails (header is authenticated *by key derivation*,
  not by a separate MAC over header). **Explicit empty-salt guard** (`:172-176`)
  refuses to let an empty salt fall back to the KDF's context-salt path (which
  would un-authenticate the header). Info `:61`.
- **DH ratchet** (`:356-370`): saves `PN=Ns`, resets counters, sets `DHr`,
  advances receive chain via `KDF_RK`, generates a fresh sending keypair, advances
  send chain via a second `KDF_RK` (PCS heals here).
- **Skipped keys:** `MKSKIPPED` map keyed `"<dh_pub_b64>|<n>"` (`:221`);
  `MAX_SKIP = 1000` per chain (`:54`, enforced `:337-338`),
  `MAX_SKIPPED_TOTAL = 2000` live cap (`:55`, oldest-evicted `:230-236`);
  consume-once delete on hit (`:322-329`).
- **Attachment root (W3-2):** `deriveAttachmentRoot(SK)` →
  `HKDF(SK, info = "MoneyTracker:AttachmentRoot:v1", …)` (`:68`), stored as `AK0`
  in state, **invariant across ratchet steps** so an attachment KEK stays
  decryptable.
- **Nonce:** per-message random nonce from `CP.encryptBytes` (secretbox 24-byte),
  `:185-186`. No counter; relies entirely on RNG quality (see §6).

### Claims to verify (Double Ratchet)
1. **FS (forward secrecy):** compromise of current state must not reveal past
   message keys — confirm CK/RK are one-way (salt=CK / salt=RK) and that MKs are
   deleted after use, and that `MKSKIPPED` does not retain MKs longer than
   necessary (the 2000 cap retains *recovery* keys — is that an FS regression
   window?).
2. **PCS (post-compromise security):** confirm a single DH ratchet step actually
   heals after state compromise (the two `KDF_RK` calls + fresh keypair at
   `:356-370`), and that an attacker who learns one MK cannot ratchet forward.
3. **Header authentication via key derivation** (no separate AEAD AAD): is mixing
   the header into the *HKDF salt* a sound substitute for passing it as secretbox
   AAD? (secretbox has no AAD; the design routes header+AD into salt.) Confirm
   there is no truncation/canonicalization ambiguity in the 40-byte header
   serialization (`:141-148`) and that `AD` (X3DH `IK_a||IK_b`) is bound on the
   first message and consistently absent afterward.
4. **Skipped-key DoS / memory:** `MAX_SKIP=1000`, `MAX_SKIPPED_TOTAL=2000` —
   confirm these bounds prevent an attacker forcing unbounded key derivation or
   evicting a victim's legitimately-skipped keys (oldest-eviction at `:230-236`).
5. **Domain separation across the KDF family:** `X3DH:v1`, `RK:v1`, `MK:v1`,
   `CK:v1`, `MsgAEAD:v1`, `AttachmentRoot:v1`, `BudgetDEK:v1`,
   `BudgetShareSeal:v2` (§3) — confirm no two contexts can collide on the same
   `(IKM, salt)` input and that `KeyDerivationService._hkdf`'s context-salt
   auto-derivation (`auth_db/encryption/services/keyDerivationService.js:112-146`)
   does not undermine the explicit-salt callers.

---

## 3. Budget DEK + the v2 share seal

**Files:** `money_tracker/shared/services/budgetCryptoService.js`,
`budgetKeyService.js`.

- **Budget DEK at rest** (`budgetCryptoService.js`):
  - DEK = 32 random bytes; `wrapKey = HKDF(identitySecret,
    "MoneyTracker:BudgetDEK:v1", 32)` (`:178`, `wrapDEK :194`, `unwrapDEK :217`);
    `secretbox(DEK, nonce, wrapKey)`. Stored in `budget_dek` as base64
    `wrapped_dek`/`wrap_nonce`. The wrap key is a **pure function of the identity
    secret**, so every paired device re-derives it (no key distribution).
  - Budget blobs: `secretbox(JSON, dek)` per row → `enc_payload`/`enc_nonce`
    (`encryptBlob :119`, `decryptBlob :155`), `enc_version=1`.
- **v2 share seal (SEC-H4)** — sealing the owner DEK to a recipient
  (`sealDEKToRecipient :321`, `unsealDEK :393`, `_sealInfo :283`):
  - `DH_ss = DH(ownerSecret, recipientPub)` (static-static → sender auth),
    `DH_es = DH(ephSecret, recipientPub)` (ephemeral-static → freshness)
    (`:356-357`).
  - `info = "MoneyTracker:BudgetShareSeal:v2" | ownerIK=… | recipientIK=… |
    owner=<id> | recipient=<id> | dekVersion=<v> | shareId=<id>`
    (pipe-delimited, `_sealInfo :291-299`; prefix `:275`).
  - `wrapKey = HKDF(DH_ss || DH_es, info, 32)` (`_deriveSealKey`, called `:358`);
    `secretbox(DEK, nonce, wrapKey)` (`:360`). Emits
    `wrapped_dek/wrap_nonce/wrap_eph_pub/wrap_owner_ik/wrap_alg='v2-auth'/dek_version`.
  - **Unseal verification** (`:408-440+`): refuse legacy/anonymous seals (no
    `wrap_owner_ik`); the bound owner IK MUST equal the **pinned** sender key
    (`opts.expectedOwnerPublicKey`) — catches recipient-key substitution and
    forged shares; the context `info` is rebuilt from what the recipient
    *independently* knows (share row + own IK), NOT from the seal blob, so a
    lifted/forged seal with mismatched ids derives a different key and fails
    closed.

### Claims to verify (DEK + seal)
1. **Static-static authentication is sound:** does binding `DH_ss = DH(ownerSK,
   recipientPK)` actually authenticate the owner to the recipient without a KCI
   weakness (recipient-key-compromise impersonation)? Compare to the
   X3DH/Noise `K`/`X` patterns.
2. **Context binding completeness:** the `info` binds owner/recipient ids + both
   IKs + `dek_version` + `share_id`. Confirm this prevents seal replay across
   shares/versions AND that `dek_version` cannot be downgraded
   (`data_shares.dek_version` is client-supplied via the `update_share_grants`
   path / column grant — verify a recipient/owner cannot rebind a seal to a stale
   DEK generation).
3. **Pinned-owner-key dependency:** the whole authentication rests on
   `expectedOwnerPublicKey` being a *trustworthy* pin. Confirm the pin source
   (TOFU store, SM-01) and the first-contact gap, and that a server cannot feed a
   recipient a wrong "expected" owner key.
4. **DEK wrap reuse:** the at-rest `BudgetDEK:v1` wrap and the `BudgetShareSeal:v2`
   seal both protect the same DEK under different keys — confirm no nonce/key reuse
   across the two and that the DEK itself is not exposed by combining a wrap + a
   seal.

---

## 4. Wrap-at-rest, password/recovery backups, pairing

**Files:** `auth_db/encryption/services/keyStorageService.js`,
`passwordCryptoService.js`, `keyBackupService.js`, `devicePairingService.js`.

- **IndexedDB wrap-at-rest (SM-02):** identity secret is stored only as AES-GCM
  ciphertext under a **non-extractable** WebCrypto key
  (`keyStorageService.js`: `_getOrCreateWrapKey` `:228` —
  `generateKey({AES-GCM,256}, extractable=false)`; `_wrapSecret` `:257`,
  `_unwrapSecret` `:282`, `storeIdentityKeys` `:318`, `getIdentityKeys` `:368`).
  12-byte IV. Raw key bytes can never leave the browser.
- **Password / recovery / session-backup-key backups** (`passwordCryptoService.js`):
  - KDF = **PBKDF2-SHA256, 600,000 iters** (`:35`), salt 32B (`:94`), IV 12B
    (`:95`), AES-256-GCM (`:76`). `encryptToBase64`/`decryptFromBase64` (`:153`/
    `:171`). The identity secret, recovery-encrypted copy, and the stable session
    backup key are all wrapped this way (`keyBackupService.js createIdentityBackup
    :98`).
  - **Recovery key:** `RECOVERY_KEY_BYTES = 20` (`:194`) → 160 bits, Base32
    alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567` (`:209`), grouped 4-char display.
    **Comment `:184`: "MUST be 32 before production/pentest."** The recovery key is
    used directly as the PBKDF2 *password* (no separate KDF).
- **Device pairing** (`devicePairingService.js`): one-time code =
  `PAIRING_CODE_BYTES = 10` → 80 bits (`:29`), Base32-formatted; the bundle
  `{identity secret, session backup key}` is wrapped via the same
  `encryptToBase64` (PBKDF2-600k + AES-GCM). 5-minute expiry (`:25`/`:67`),
  5-attempt limit then row-delete (`:26`/`:119-135`), single-use delete on success
  (`:143`).

### Claims to verify (at-rest / backups / pairing)
1. **Recovery-key entropy:** 20 bytes is a **testing value** that must be 32
   before the pentest build (gated by
   `auth_db/encryption/tests/prod_readiness_check.js`). Confirm 160 bits behind
   PBKDF2-600k is genuinely non-brute-forceable for the *online* threat model, and
   confirm the prod build ships 32. (`KNOWN_ACCEPTED_RISKS.md` §B.)
2. **PBKDF2 → Argon2id (L-3):** the at-rest backup KDF HIGH is now **ADDRESSED
   (2026-06-24)**. The WRITE path mints memory-hard **Argon2id** (vendored
   hash-wasm 4.12.0, MIT; m=64 MiB, t=3, p=1) + AES-256-GCM, carried in a
   versioned, self-describing salt envelope; the legacy PBKDF2-SHA256(600k) READ
   path is preserved verbatim (no-lockout) and legacy backups are transparently
   re-wrapped to Argon2id on next unlock. See
   `encryption/services/passwordCryptoService.js`,
   `encryption/services/keyBackupService.js`, and the gate
   `encryption/tests/a18_argon2id_kdf.test.js` (KAT + round-trip + back-compat +
   fail-closed + upgrade); `prod_readiness_check.js` now asserts the WRITE path is
   Argon2id at ≥ OWASP params. *Remaining (not in this change):* the
   server-unknown **pepper** is still unimplemented — assess whether Argon2id
   (memory-hard) alone is a sufficient offline-brute-force control for a stolen
   `identity_key_backups` row given the enforced 12-char password policy, or
   whether the pepper follow-up should be prioritised.
3. **Pairing one-time-code entropy:** 80 bits behind PBKDF2-600k, with 5 attempts
   + 5-min expiry + single-use. Confirm the online brute-force is infeasible and
   that the wrapped bundle is reaped at rest (the **pairing_requests reaper is
   operator-set, not installer-created** — `LIVE_CONFIG_CHECKS.sql` §e3; an
   un-reaped expired row keeps an 80-bit-protected identity-secret bundle at rest).
4. **Non-extractable wrap key scope:** confirm the WebCrypto wrap key cannot be
   exfiltrated by XSS (it can be *used* in place — that is the accepted residual)
   and that logout/wipe (SM-13) actually destroys it.

---

## 5. Known design decisions & rationale (why bespoke, not libsignal — yet)

- **Why bespoke:** the apps are dependency-light vanilla JS on GitHub Pages with
  no build step on the crypto path; TweetNaCl is small, audited at the primitive
  level, and self-hostable. The team built X3DH + Double Ratchet directly on it to
  avoid a WASM dependency and keep the bundle inspectable. **This brief exists
  precisely because that choice trades a vetted protocol library for our own
  composition.**
- **TOFU, not a directory/PKI:** peer identity is trust-on-first-use with a pin
  store (SM-01). First-contact MITM by a malicious server is the inherent gap;
  safety-numbers are the intended human check.
- **Messaging is free; sharing is Premium:** no crypto consequence, but note the
  `is_premium_active` gate sits on `data_shares` INSERT, not on the crypto.
- **Per-row envelopes, not per-field:** budget blobs and pots are sealed per row
  (`enc_payload`), accepting that the server learns row counts and coarse sizes.

---

## 6. Top questions for the cryptographer (ranked)

1. **Is the protocol composition sound end-to-end?** Specifically: does the
   X3DH→Double-Ratchet handoff (`ratchetInitAlice/Bob` seeded by the X3DH `SK`)
   correctly establish FS+PCS, and is the responder-IK pin enforced on every
   session after first contact (no server-driven re-MITM)?
2. **Is mixing header+AD into the HKDF *salt* a valid replacement for AEAD AAD**
   (secretbox has no AAD)? Any canonicalization/truncation attack on the 40-byte
   header serialization?
3. **Nonce safety:** can the production build EVER use the seedable/deterministic
   RNG seam on a secretbox nonce path (X3DH ephemeral, ratchet message nonce, seal
   ephemeral+nonce, wrap nonce)? A repeated XSalsa20 nonce under a reused key is
   catastrophic — confirm every nonce is fresh CSPRNG in prod.
4. **Is the v2 seal's static-static leg free of KCI** and does the context binding
   (`_sealInfo`) fully prevent seal replay / `dek_version` downgrade?
5. **Domain separation:** are the eight `MoneyTracker:*` HKDF contexts provably
   non-colliding, and does the context-salt auto-derivation in
   `keyDerivationService.js` ever shadow an explicit-salt caller?
6. **Skipped-key bounds (1000/2000):** correct trade-off, or an FS-retention /
   DoS / eviction-griefing problem?
7. **Recovery (20→32) + PBKDF2→Argon2id:** sign off the interim parameters for the
   pentest, and confirm the prod-readiness gate covers the must-flip constants.
8. **Migration recommendation:** is this composition close enough to spec to
   *harden in place*, or should the messaging layer move to **libsignal**
   (`libsignal-client` WASM) to replace our X3DH/Ratchet with a vetted library?
   (The budget seal would likely remain bespoke either way.)

---

## Where bespoke crypto is riskiest (our honest self-assessment)

1. **The X3DH→Ratchet composition and the responder-IK pin** — the FS/PCS and
   anti-MITM guarantees rest entirely on our own glue + TOFU.
2. **Nonce management under the RNG seam** — a single prod path reaching the
   deterministic RNG breaks secretbox.
3. **The v2 seal's authentication model** — novel static+ephemeral construction
   with hand-built context binding; KCI / downgrade / pin-source are the soft
   spots.
4. **At-rest KDF strength** — PBKDF2 (not memory-hard) + the still-shipped 20-byte
   recovery key (must be 32 for the pentest).
