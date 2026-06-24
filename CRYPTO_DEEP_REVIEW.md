# Cryptographer-Grade Deep Review — Bespoke E2E Crypto Stack

**Date:** 2026-06-24
**Reviewer:** Opus 4.8 (same-model self-review — see caveat §5)
**Scope:** Hand-rolled X3DH + Double Ratchet + context-bound DEK seal + wrap-at-rest + device pairing + recovery, on TweetNaCl (X25519 / Ed25519 / XSalsa20-Poly1305) + WebCrypto (HKDF-SHA256 / AES-GCM / PBKDF2).
**Method:** Line-by-line read of the actual source for all 11 files plus the load-bearing `keyManagementService` wiring (`_resolveResponderPeerIdentity`, `_reconstructAD`, `_resolveADInitiatorKey`, `_getIdentitySignKeyPair`) and `keyStorageService._getOrCreateWrapKey`/`_wrapSecret`. Every claim below was checked against the code at the cited line, not taken on faith.

Files reviewed:
- `auth_db/encryption/services/cryptoPrimitivesService.js`
- `auth_db/encryption/services/doubleRatchetService.js`
- `auth_db/encryption/services/x3dhService.js`
- `auth_db/encryption/services/keyManagementService.js`
- `auth_db/encryption/services/keyStorageService.js`
- `auth_db/encryption/services/keyDerivationService.js`
- `auth_db/encryption/services/passwordCryptoService.js`
- `auth_db/encryption/services/keyBackupService.js`
- `auth_db/encryption/services/devicePairingService.js`
- `auth_db/encryption/services/historicalKeysService.js`
- `money_tracker/shared/services/budgetCryptoService.js`

---

## 1. Overall verdict

**The bespoke crypto is SOUND enough to take into an external pentest.** The protocol cores are faithful to the published Signal X3DH and Double Ratchet specifications, and the bespoke additions (context-bound DEK seal, wrap-at-rest, device pairing, recovery) are built on the right primitives with correct domain separation and fail-closed error handling.

I found **no CRITICAL and no exploitable HIGH break in the protocol engines** (X3DH, Double Ratchet, the DEK seal, the at-rest wrap, pairing, recovery key). The randomness hygiene is genuinely strong (every nonce/IV/ephemeral is fresh CSPRNG output; the deterministic RNG seam is test-only and unreachable from production). The KDF domain-separation matrix has no cross-context key-reuse collision.

The **one genuinely material weakness is not in the bespoke protocol at all — it is the choice of PBKDF2-SHA256 (not memory-hard) as the backup/recovery/pairing KDF (HIGH).** This gates the codebase's own named #1 residual risk (H-2): a leaked at-rest identity backup is offline-brute-forceable against a weak-but-policy-passing password. The recovery-key lane (256-bit) and pairing lane (80-bit + rate-limited) are safe; the password lane is the weak link. The migration to Argon2id is fully designed in-code but not yet implemented.

Everything else is LOW/INFO — defense-in-depth nits, documentation/code mismatches, and theoretical NIST-bound observations that are not reachable at realistic volumes.

**Net:** A pentester will not find a protocol-level confidentiality/integrity break in the bespoke X3DH/ratchet/seal. The realistic attack surface is the PBKDF2 backup KDF under a stolen DB plus a weak password, and the latent footguns listed in §4.

---

## 2. KDF domain-separation matrix

All live derivations, with their full (IKM | salt | info) triple and output. No two distinct purposes share the full triple, and no info string is a prefix of another (the `:vN` terminator + unique purpose token rules out prefix ambiguity).

| # | Purpose | IKM | Salt | Info / context | Output | Site |
|---|---------|-----|------|----------------|--------|------|
| 1 | X3DH root SK | `0xFF*32 \|\| DH1\|\|DH2\|\|DH3[\|\|DH4]` | 32 zero bytes (explicit) | `MoneyTracker:X3DH:v1` | 32B SK | `x3dhService.js:105-113` |
| 2 | Ratchet KDF_RK | `dh_out` (raw X25519) | `RK` | `MoneyTracker:RK:v1` | 64B → RK'‖CK | `doubleRatchetService.js:117-121` |
| 3 | Ratchet KDF_CK → MK | `0x01` | `CK` | `MoneyTracker:MK:v1` | 32B message key | `doubleRatchetService.js:126` |
| 4 | Ratchet KDF_CK → CK' | `0x02` | `CK` | `MoneyTracker:CK:v1` | 32B next chain key | `doubleRatchetService.js:127` |
| 5 | Per-msg AEAD key | `MK` | `serialize(header)[\|\|X3DH-AD]` | `MoneyTracker:MsgAEAD:v1` | 32B secretbox key (header binding) | `doubleRatchetService.js:160-178` |
| 6 | Attachment root AK0 | `SK` | `SK` | `MoneyTracker:AttachmentRoot:v1` | 32B invariant KEK | `doubleRatchetService.js:74-76` |
| 7 | Identity Ed25519 IK_sig seed | X25519 identity secret | X25519 identity public | `MoneyTracker:IK_sign:v1` | 32B Ed25519 seed | `keyManagementService.js:810-815` |
| 8 | Budget DEK wrap key | X25519 identity secret | (none → `SHA256("MoneyTracker:ContextSalt:MoneyTracker:BudgetDEK:v1")`) | `MoneyTracker:BudgetDEK:v1` | 32B DEK wrap key | `budgetCryptoService.js:174-178` |
| 9 | Budget share-seal key | `DH_ss \|\| DH_es` | (n/a — not HKDF) | `SHA-512("MoneyTracker:BudgetShareSeal:HKDF:v2\|" ‖ DH_ss ‖ DH_es ‖ "\|"+info)[0:32]`, where `info` binds ownerIK, recipientIK, ownerId, recipientId, dekVersion, shareId | 32B seal key | `budgetCryptoService.js:475-491` |

**Non-HKDF / PBKDF2 contexts** (independent random salt per blob — no shared-key reuse by construction):
- Password / recovery / session-backup: `passwordCryptoService.deriveKeyFromPassword` (PBKDF2-SHA256, 600k) — fresh 32B salt + 12B IV per `encryptWithPassword` call (`passwordCryptoService.js:92-115`).
- Device-pairing transport: same PBKDF2+AES-GCM under the 80-bit code (`devicePairingService.js:61-66`).

**Dead code (not on any live path):** `keyDerivationService.deriveSessionKey / deriveMessageKey / deriveBackupKey / deriveDeviceKey` (`keyDerivationService.js:51-88`) — referenced only in design docs/comments. Their epoch-/counter-/deviceId-in-info patterns pose no current risk.

**Collision-hunt result:** No exploitable cross-context collision.
- The X25519 identity secret is IKM for BOTH the IK_sig seed (#7) and the BudgetDEK wrap key (#8), but they differ in BOTH info AND salt → distinct PRK, no collision.
- SK is IKM for AK0 (#6) and the *salt* for KDF_RK (#2) — different roles, no overlap.
- The `_deriveContextSalt` fallback (`keyDerivationService.js:113-119,144-149`) makes salt a deterministic public function of `info` (RFC 5869 permits a non-secret salt), so two no-salt call sites collide only if they share the same info — i.e. a deliberate same-purpose derivation. Only one live no-salt site exists (#8).
- No info field is attacker-influenceable: the seal info is rebuilt on unseal from the recipient's OWN values + the share row, NOT from the seal blob (`budgetCryptoService.js:429-442`).

---

## 3. Confirmed-sound properties (what HOLDS, and why)

### X3DH (`x3dhService.js`)
- **DH set + order correct:** DH1=DH(IK_a,SPK_b), DH2=DH(EK_a,IK_b), DH3=DH(EK_a,SPK_b), DH4=DH(EK_a,OPK_b) — exactly the spec order (`:200-203`); responder mirror is byte-identical by X25519 symmetry (`:275-278`).
- **KDF F-prefix + zero salt + frozen info:** IKM is prefixed with F=`0xFF*32`, salt is an explicit 32-zero-byte string (bypasses the context-salt fallback to get true spec behavior), info=`MoneyTracker:X3DH:v1` (`:105-113`).
- **DH4 included iff OPK present**, symmetrically on both sides; responder hard-errors if opkId is present but no OPK secret is supplied (`:264-268`). No DH leg silently dropped.
- **SPK signature verified BEFORE any DH, fail-closed**, against the *pinned* IK_sig when supplied (`:190-193`); `verifySignedPrekey` hard-throws on missing/malformed/invalid sig and wrong key sizes (`:124-140`).
- **AD = IK_a‖IK_b** computed identically on both sides (`:208`, `:283`); both halves are fixed 32-byte keys so the concatenation is unambiguous.
- **Responder correctly does NOT re-verify its own SPK signature** (Bob trusts his own SPK).
- **`dhRaw` uses raw `nacl.scalarMult`** (`cryptoPrimitivesService.js:178-181`), not `box.before` — the bare curve point the spec assumes. The HSalsa20-applying `deriveSharedSecret` is correctly reserved for the budget seal where it is used consistently on both sides.
- **Ed25519 signing key is a separate keypair** from the X25519 DH key — no cross-protocol key reuse.
- **Responder binds the AUTHENTIC initiator IK, not the wire value:** `_resolveResponderPeerIdentity` (`keyManagementService.js:1303-1374`) feeds the TOFU-pinned/published-cross-checked X25519 ikPub into both the DH legs and the AD, with a fail-closed `PeerIdentityChangedError` on any mismatch (`:1332-1339`, `:1346-1354`). This closes the H-1 swapped-ikPub impersonation.

### Double Ratchet (`doubleRatchetService.js`)
- **KDF_RK correct:** `HKDF(ikm=dh_out, salt=RK, info=RK:v1, 64)` split 32/32 — the Signal construction with RK as HMAC-extract salt (`:117-121`).
- **KDF_CK has no constant collision:** MK uses ikm=`0x01`/info=`MK:v1`, CK' uses ikm=`0x02`/info=`CK:v1` — domain-separated twice over (`:126-127`).
- **Chain irreversibility / forward secrecy:** salt=CK with a public constant IKM ⇒ HKDF-Extract = HMAC(CK, const); recovering CK from MK/CK' requires inverting HMAC-SHA256.
- **No message-key reuse:** each MK comes from exactly one KDF_CK advance at one counter; skipped keys stored once keyed by `(dhPub_b64|n)` and consumed-once via delete (`:322-330`, `:344`).
- **No nonce reuse:** secretbox nonce is fresh 24 random bytes per encryption (`cryptoPrimitivesService.js:287`), and each MK→encKey is itself unique.
- **Full header (dh,pn,n) cryptographically bound:** 40-byte canonical serialization folded into the HKDF salt that derives encKey (`:141-149`, `:170-178`); any tamper changes encKey ⇒ `secretbox.open` returns null ⇒ throw (`:189-197`). The empty-salt fallback that would un-bind the header is provably unreachable due to the 32-byte-dh + non-empty-salt guards (`:167-177`).
- **DH-ratchet step spec-correct:** finishes the OLD recv chain up to PN while DHr is still old, then two-step root-chain advance with PCS healing on the second KDF_RK (`:356-370`, `:392-395`).
- **MAX_SKIP per-advance bound fail-closed** (`:337-339`); **authentication failure cannot corrupt state** — all work is on an immutable clone returned only on success (`:381`, `:388`, `:406`).

### DEK seal / wrap-at-rest (`budgetCryptoService.js`)
- **2-DH authenticated static+ephemeral box:** DH_ss=DH(ownerStatic,recipientPub) authenticates the owner; DH_es adds per-seal freshness (`:356-358`); DH symmetry holds on unseal (`:450-451`).
- **Context binding complete + unambiguous:** `_sealInfo` requires and pipe-delimits ownerIK, recipientIK, ownerId, recipientId, dekVersion, shareId; `|`/`=` cannot appear in base64/UUID/int (`:283-300`).
- **Pinned-owner (TOFU) check enforced BEFORE key derivation** (`:425-427`); recipient IK in the rebuilt context comes from the recipient's OWN secret, not the blob (`:432-435`); anonymous/legacy seals (missing `wrap_owner_ik`) are hard-rejected (`:410-412`).
- **Fresh ephemeral per seal** (`:354`); AEAD fail-closed; recovered DEK length re-checked == 32.
- **At-rest DEK wrap sound:** wrapKey = HKDF(identitySecret, BudgetDEK:v1) via real RFC-5869 `_hkdf`; secretbox over the 32-byte DEK; unwrap fail-closed (`:174-234`). Pure function of the identity secret ⇒ multi-device works without extra key distribution.
- **KCI exposure is the standard, accepted X3DH property** — no extra surface introduced.

### At-rest wrap / pairing / recovery (`keyStorageService.js`, `devicePairingService.js`, `passwordCryptoService.js`, `keyBackupService.js`)
- **Wrap key is genuinely non-extractable:** `generateKey({AES-GCM,256}, false, ...)`, persisted as a CryptoKey via IndexedDB structured clone, never exported/wrapKey'd (`keyStorageService.js:228-243`). An at-rest reader gets an opaque handle, not bytes.
- **Per-record IVs fresh 96-bit random** at every wrap site (`:257-268`, `:321-329`); PBKDF2 path uses fresh 32B salt + 12B IV per call.
- **Pairing code = 80-bit CSPRNG**, lossless through Base32+normalize, single-use + 5-min expiry + 5-attempt cap, RLS-scoped to the owner (`devicePairingService.js:50-149`).
- **Pairing bundle sealed (PBKDF2-600k + AES-256-GCM) BEFORE it touches the server** (`:66`); raw secret never stored/transmitted in clear.
- **Recovery key = 256-bit CSPRNG**, lossless Base32 round-trip; GCM backstops integrity (`passwordCryptoService.js:193-272`).
- **Backup password gated** by `enforcePasswordStrength` (≥12 chars, ≥3 classes) on every backup-create path (`passwordCryptoService.js:420-429`) — the load-bearing mitigation while the KDF stays PBKDF2.
- **`RECOVERY_KEY_BYTES` confirmed flipped to 32** (`passwordCryptoService.js:193`) — the testing-time 20-byte value is no longer present.

### Randomness (`cryptoPrimitivesService.js`)
- **Production RNG is the CSPRNG; the seam is test-only.** `_randomBytesSource` defaults null → `nacl.randomBytes` (`:24`, `:112-125`). `setRandomBytesSource` is the only injection point and (verified earlier by cross-repo grep) has zero production callers. No production path can install a deterministic RNG.
- All ephemerals (X3DH EK, DH-ratchet keypair, seal ephemeral) and all nonces/IVs route through the CSPRNG; decrypt paths read the stored nonce back rather than regenerating.

---

## 4. Verified-real concerns by severity

> All four per-area analyses returned **zero CRITICAL and zero exploitable-HIGH protocol breaks**, which my line-by-line read corroborates. The items below are the real residual issues, each verified at the cited line.

### HIGH

**H-1. Backup/recovery/pairing KDF is PBKDF2-SHA256, not memory-hard — a leaked at-rest backup is offline-brute-forceable.**
- **File:** `auth_db/encryption/services/passwordCryptoService.js:34-83` (`deriveKeyFromPassword` + `_getIterations`); consumers `keyBackupService.js` create/restore paths.
- **Deviation:** Current OWASP/NIST guidance is a memory-hard KDF (Argon2id, or scrypt) for password-derived keys protecting long-lived secrets. PBKDF2-SHA256(600k) meets the legacy floor but offers no GPU/ASIC resistance. The Argon2id migration is fully designed in-code (`:360-414`) but **not implemented**.
- **Consequence / attacker model:** An adversary who obtains the `identity_key_backups` row (SQLi, backup leak, malicious/compromised server, insider). `password_encrypted_data` is AES-256-GCM over the X25519 identity secret keyed by PBKDF2(password). PBKDF2-SHA256 is cheap on GPU, so a weak-but-policy-passing password is recoverable offline. Recovering the identity secret is a **total E2E break** for that user. The recovery-key lane (256-bit) is safe; the **password lane and the session-backup-key lane share this KDF and are the weak link.**
- **Severity rationale:** HIGH, not CRITICAL — it requires both a DB leak AND a weak password, and the ≥12-char/≥3-class policy plus the 256-bit recovery lane are real mitigations. But it is the codebase's own named #1 residual risk and the only realistic protocol-adjacent path to a full break.
- **Minimal fix:** Implement the documented L-3 migration: Argon2id (m≥64 MiB, t=3, p=1) behind a versioned `kdf_version` field with dual-read + lazy re-encrypt on next successful restore. Until then, keep `MIN_PASSWORD_LENGTH=12`+3-class as load-bearing and add the planned zxcvbn/HIBP breached-password gate.

### LOW

**L-1. `unsealDEK` trusts attacker-controlled `sealed.dek_version` when `opts.dekVersion` is omitted (binding-bypass footgun).**
- **File:** `money_tracker/shared/services/budgetCryptoService.js:438-439`.
- **Deviation:** The unseal context builder falls back to `sealed.dek_version` (a field in the server-controlled blob) when `opts.dekVersion` is absent, so the version is reconstructed FROM the same untrusted blob it is meant to authenticate. The other four ctx fields (ownerId, recipientId, shareId) have NO such fallback — an asymmetric, easy-to-miss gap.
- **Consequence:** A malicious server could present any `dek_version` label and it would still be accepted, defeating version/rollback pinning — **but only if a caller omits `opts.dekVersion`.** The sole in-repo caller always passes it, so this is **not currently exploitable**; it is a latent footgun for a future caller.
- **Minimal fix:** Make `opts.dekVersion` REQUIRED (throw if undefined/null) exactly like the other ctx fields, and delete the `: sealed.dek_version` fallback at line 439.

**L-2. Global skipped-key cap (`MAX_SKIPPED_TOTAL`) evicts oldest-by-insertion.**
- **File:** `doubleRatchetService.js:230-237, 349`.
- **Consequence:** Availability only, not confidentiality/integrity. Over a conversation accumulating >2000 outstanding skipped keys, the oldest can be evicted and a genuinely-delayed message become undecryptable. Mirrors Signal's own bounded-storage trade-off. Weak single-message DoS at most.
- **Minimal fix:** Acceptable as-is. Optionally raise the cap or evict by delivery-likelihood.

**L-3. Single long-lived AES-GCM wrap key with random 96-bit IVs + unbounded message-key archive approaches the NIST 2^32 bound.**
- **File:** `keyStorageService.js:257-268` (`_wrapSecret`); highest-volume caller `putDecryptedMessageKey` (~one wrap per decrypted message).
- **Consequence:** Defense-in-depth only — ~2^32 wraps under one per-device key are not reachable at realistic message volumes, and the local at-rest attacker who can read IndexedDB also has the non-extractable CryptoKey handle in-origin.
- **Minimal fix:** Document the bound + rely on archive eviction; or rotate the wrap key on a write-count threshold; or use an extended-nonce AEAD (XChaCha20-Poly1305 / AES-GCM-SIV) for the archive.

**L-4. Pairing `attempts` counter is client-incremented with a non-atomic read-modify-write.**
- **File:** `devicePairingService.js:119-136`.
- **Consequence:** A caller already authenticated AS the victim, racing parallel verify requests, could share a pre-increment `attempts` value and slightly inflate the 5-attempt budget. Bounded to irrelevance by the 80-bit entropy + 5-min TTL; an attacker with the victim's session already has greater powers. Not exploitable to recover the bundle.
- **Minimal fix:** Increment via an atomic server-side operation / RPC with row locking.

### INFO

**I-1. Seal KDF is SHA-512-truncated, not HKDF (doc/code mismatch).** `budgetCryptoService.js:255,267,475-491` — comments say "HKDF"; `_deriveSealKey` is `nacl.hash` (SHA-512) over `label‖DH_ss‖DH_es‖info` truncated to 32B. Cryptographically sound (high-entropy secret IKM, domain-separated, length-extension irrelevant for a fixed 32-byte prefix with a secret key), but inconsistent with the rest of the stack and misleading to a reader. Fix: correct the comments to "domain-separated SHA-512 KDF (not HKDF)", or switch to `_hkdf`.

**I-2. `dek_version` is never rotated/incremented.** `budgetKeyService.js:49,292` — `BUDGET_DEK_VERSION` is a hard-coded constant `1`; no rotation/re-key path exists. Binding a constant gives zero practical rollback protection (the "rollback fails closed" property is vacuously true). No regression by itself; flag so a pentester doesn't over-credit the binding or the absent DEK-rotation/FS control. Fix: implement rotation, or update docs to say rotation is not yet implemented.

**I-3. No X25519 low-order / all-zero-DH-output validation before `scalarMult`.** `cryptoPrimitivesService.js:178-181` (root); peer-supplied points in X3DH (`x3dhService.js:200-203,275-278`) and the seal (`budgetCryptoService.js:356-357,450-451`). TweetNaCl's `scalarMult` does not reject low-order points and returns an all-zero shared secret. **Not exploitable in the wired paths:** the high-value legs are protected by the verified SPK signature, the TOFU/pin of the X25519 IK, and (in the seal) the secret static-static DH_ss leg against the pinned owner key. RFC 7748 §6.1 contributory-behavior deviation / robustness gap. Fix (belt-and-suspenders): reject the all-zero output (and the known low-order set) before keying, ideally inside `dhRaw` itself.

**I-4. `parseRecoveryKey` accepts wrong-length / non-canonical input.** `passwordCryptoService.js:243-272` — decoder only rejects out-of-alphabet chars, not decoded length or residual-padding bits. No break: a wrong key yields wrong bytes and the AES-256-GCM auth tag fails. Fix: assert `bytes.length === RECOVERY_KEY_BYTES` for a cleaner failure.

---

## 5. Caveat — this is a same-model self-review

This report was produced by Opus 4.8 reviewing a stack that was, per the project memory, itself hardened across many Opus-only audit waves. A same-model reviewer shares the blind spots of the same-model author/auditor: it is structurally weak at catching the class of error that the model systematically does not "see" (e.g. subtle side-channel/timing issues in the underlying primitives, a flawed mental model of a spec corner shared by author and reviewer, or an implementation assumption that looks correct to this model family but is wrong). The confidence in §3's sound-properties is high *given the code as written*, but "high confidence from one model" is not the same as independent assurance.

**Recommendations before/around the pentest:**
1. Treat the H-1 PBKDF2→Argon2id migration as the top pre-pentest hardening item.
2. Commission an **independent human cryptographer** review of at least the X3DH AD/identity-binding wiring and the Double Ratchet header-binding-via-salt construction (the two places where the design departs most from a textbook implementation).
3. **Strongly consider migrating to libsignal** (the audited reference implementation) rather than maintaining a bespoke X3DH + Double Ratchet long-term. The bespoke stack is sound today, but every future change re-incurs the full review burden, and the header-binding-via-HKDF-salt and SHA-512-KDF-vs-HKDF idioms are the kind of non-standard choices that age into footguns. The bespoke seal/wrap/pairing layer can remain even if the messaging core moves to libsignal.

---

### Appendix — verification note
Each property and concern above was confirmed by reading the cited file at the cited line in this session. No claim was carried over unverified; the input analyses agreed with the code in every case I checked, and I added no concern that the code did not actually exhibit.
