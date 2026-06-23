# Forward Secrecy + Post-Compromise Security Design

**Status:** Design / implementable
**Date:** 2026-06-23
**Scope:** Replace the static-static ECDH session model in the E2E messenger with **X3DH (async handshake) + Double Ratchet**, giving real forward secrecy (FS) and post-compromise security (PCS).
**Hard constraints honored:** vanilla JS + `window.*` globals + `<script>` tags (no bundler dependency), GitHub Pages static hosting, **crypto cannot be runtime-tested** (so every claim is backed by a deterministic test gate), async/offline-recipient first message, out-of-order + skipped messages, `getMessages` re-decrypts full history on every open, device pairing, and **a clean break of existing encrypted data is acceptable**.

---

## 0. The problem we are replacing

Today (`lib/auth_db/encryption/services/keyManagementService.js`):

- `establishSession()` (~line 738) hardcodes `epoch = 0` and computes **one** static-static ECDH:
  `deriveSharedSecret(ourIdentitySecret, theirIdentityPublic)` = `nacl.box.before` → `deriveSessionKey(sharedSecret, 0)`.
- `encryptMessage()` (~line 816) derives `deriveMessageKey(sessionKey, 0, counter)` (HKDF info `…:MessageKey:0:{counter}`) and encrypts with `secretbox` (XSalsa20-Poly1305, random 24-byte nonce).
- `decryptMessage()` (~line 889) forces `epoch = 0`; when there's no cached session it calls `_deriveSessionFromHistory()` (~line 1354), which **re-runs the same static ECDH**.
- `checkAndRotateIfNeeded()` (~line 670) is a no-op; `regenerateKeys()` bumps epoch but breaks decryption. The whole epoch concept is vestigial.

**Consequence:** the per-conversation key is a deterministic function of two long-term identity secrets. Compromise of **either** identity secret retroactively decrypts **all** past and future messages. No FS, no PCS.

This is a **structural** change, not a config flip, for one reason: a ratchet's message keys are *deleted after use*, but `getMessages` re-decrypts the **entire** history newest-first in parallel (`Promise.all`, `messagingService.js:365`) on every open. Reconciling these is the load-bearing design decision (§5).

---

## 1. Chosen approach + WHY

**Decision: build a bespoke X3DH + Double Ratchet directly on the existing TweetNaCl primitives (X25519 via `nacl.box.before`, HKDF-SHA256 via WebCrypto, AEAD via `secretbox`, Ed25519 signatures via `nacl.sign` for signed prekeys), gated by deterministic test vectors.**

### Why bespoke over a library

The can't-runtime-test constraint is decisive and it **eliminates the WASM options**:

| Option | Verdict |
|---|---|
| `@signalapp/libsignal` (official) | Node native addon, **no browser/WASM target**. Cannot serve from GitHub Pages, no `<script>` path, won't reuse our `nacl.box` keys. |
| `libsignal-protocol-javascript` | **Archived since Aug 2021**, ~5 yrs unmaintained. Adopting dead crypto for the #1 roadmap feature is the worst long-term choice. |
| `@privacyresearch/...-typescript` | Community port, **stale (~3 yrs), unaudited**, 0.0.x. Own key format, can't consume our X25519 identity keys. |
| `@matrix-org/olm` (libolm WASM) | Browser-proven but **deprecated (Aug 2024)** with side-channel CVEs (CVE-2024-45191). **Opaque internal RNG → cannot be seeded → cannot author the FS-proving vector.** Own Ed25519/Curve25519 keys. olm.wasm MIME footgun on static hosts. |
| `matrix-sdk-crypto-wasm` (vodozemac) | Audited but **massively over-scoped** (full Matrix OlmMachine, device lists, to-device). Needs ESM bundling, opaque RNG, own key format, post-audit issues reported. Wrong altitude for 1:1. |

The deciding axis: **a deterministic test gate must PROVE forward secrecy without running the messenger.** A bespoke JS ratchet is fully deterministic when we inject the RNG (ephemeral keygen + the 24-byte `secretbox` nonce), so we can freeze seeds and assert byte-stable ciphertext, message-key deletion, and post-ratchet decrypt failure. The WASM ratchets have internal RNG we cannot pin and opaque state we cannot introspect — we literally cannot write the FS vector for them. This mirrors the project's existing **LAW-0 discipline**: prove the artifact with a deterministic gate before any claim; the gate, not a runtime click, is the arbiter.

Secondary reasons: (a) vanilla JS + GitHub Pages — loads via `<script>`/`window.*` exactly like today's services, no bundler, no WASM hosting, a few KB of our own code; (b) **reuses our existing X25519 identity keys verbatim** — every off-the-shelf option ships its own key format and would force a re-key beyond the clean break.

**The bespoke risk is implementation bugs** (nonce reuse, chain-key/skipped-key mismanagement, not deleting consumed keys, unauthenticated header). Mitigated, not eliminated, by: strict adherence to the Signal Double Ratchet + X3DH specs; deterministic immutable test vectors (§8); constant-time compares (`nacl.verify`); cross-impl interop vectors against `python-doubleratchet`/`ratchet-js`; authenticating the header as AEAD additional data.

**One cryptographic subtlety to get right:** `nacl.box.before(theirPub, ourSecret)` returns the **raw X25519 shared point** (well, NaCl applies HSalsa20 to it — see note). For the ratchet's `DH()` we must feed a raw scalar-mult result into HKDF as IKM. **Use `nacl.scalarMult(ourSecret, theirPub)` directly for all ratchet/X3DH DH operations** and treat its 32-byte output strictly as HKDF IKM. Do **not** rely on `box.before`'s internal HSalsa20 keying as the DH output, because that is a keyed PRF, not the bare DH the spec assumes. (We add a `CryptoPrimitivesService.dhRaw(ourSecret, theirPub)` wrapper = `nacl.scalarMult` to make this explicit and testable.)

---

## 2. X3DH handshake (async / offline recipient)

### 2.1 Keys per user

| Key | Type | Source |
|---|---|---|
| **IK** identity key | X25519 | existing `identity_keys.public_key` / local secret — **reused** |
| **IK_sig** identity signing key | Ed25519 | **NEW** — separate `nacl.sign` keypair (never reuse the X25519 box key for signing) |
| **SPK** signed prekey | X25519 | **NEW**, rotated periodically (e.g. weekly), signed by IK_sig |
| **SPK_sig** | Ed25519 signature over SPK pub | **NEW** |
| **OPK** one-time prekeys | X25519 pool | **NEW**, each used once then deleted |

We add an Ed25519 signing keypair because X25519 box keys cannot sign. The Ed25519 **public** key is published alongside IK and is itself pinned via TOFU (§2.4). Both the X25519 IK and Ed25519 IK_sig secrets travel together in the pairing bundle (§6).

### 2.2 New schema

**Server** (`messaging_app/lib/auth_db/backend/sql/complete-setup.sql`, identity-keys-style RLS):

```sql
-- one row per user (latest signed prekey)
CREATE TABLE IF NOT EXISTS prekeys (
  user_id            UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  identity_sign_pub  TEXT NOT NULL,            -- Ed25519 IK_sig public (base64)
  signed_prekey_pub  TEXT NOT NULL,            -- X25519 SPK public (base64)
  signed_prekey_sig  TEXT NOT NULL,            -- Ed25519 sig over SPK pub (base64)
  spk_id             INTEGER NOT NULL,         -- rotation id
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- pool of one-time prekeys
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  user_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  key_id      INTEGER NOT NULL,
  prekey_pub  TEXT NOT NULL,                   -- X25519 OPK public (base64)
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key_id)
);
```

RLS mirrors `identity_keys` (lines ~72-87): `SELECT TO authenticated` (anyone can fetch a peer's prekeys to start a session), `INSERT/UPDATE/DELETE` only `auth.uid() = user_id`. Add both table names to `encryptionConfigBase.js` + `moneyTrackerEncryptionConfig.js` `tables` maps.

**OPK consumption is client-side claim + delete:** the sender `SELECT … LIMIT 1` an OPK, then `DELETE` it (own-row DELETE is *not* allowed by the recipient-only RLS, so consumption must be a server RPC `claim_one_time_prekey(target_user)` that atomically pops one OPK and returns it — this is the one piece that needs a `SECURITY DEFINER` function). If the pool is exhausted, fall back to **SPK-only X3DH (drop DH4)** — standard and spec-permitted, with slightly weaker initial-message FS.

### 2.3 The four DHs and root-key derivation

Sender = Alice (initiator), Recipient = Bob (offline). Alice generates an ephemeral **EK_a** (X25519).

```
DH1 = DH(IK_a,  SPK_b)
DH2 = DH(EK_a,  IK_b)
DH3 = DH(EK_a,  SPK_b)
DH4 = DH(EK_a,  OPK_b)      // omitted if pool exhausted
SK  = HKDF-SHA256(
        ikm  = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4],
        salt = zero-filled / spec F-prefix,
        info = "MoneyTracker:X3DH:v1",
        len  = 32 )
```

(The `0xFF*32` prefix is the X3DH-spec domain separator; `DH()` = `dhRaw` = `nacl.scalarMult`.) `SK` is the **initial root key** handed to the Double Ratchet init (§3). The associated data `AD = IK_a_pub || IK_b_pub` is bound into the first message AEAD.

Bob, when he comes online, reads the X3DH preamble from the first message header (his IK/SPK/OPK secrets are local), recomputes the identical four DHs, derives the same `SK`, deletes the used OPK locally, and runs `ratchetInitBob`.

### 2.4 First-message bootstrap

The **first** ciphertext Alice sends carries an X3DH preamble in nullable message columns (§4): `x3dh_ik` (Alice's IK pub), `x3dh_ik_sign` (Alice's Ed25519 pub, for TOFU pin of her signing key), `x3dh_ek` (EK_a pub), `x3dh_spk_id`, `x3dh_opk_id` (which of Bob's prekeys were used). Bob verifies the SPK signature he previously published (he trusts his own), derives `SK`, and the conversation is bootstrapped with **no prior round-trip** — satisfying the offline-recipient constraint.

TOFU: extend `_getPinnedPeerKey` (`kMS:995`) to also pin the peer's **Ed25519 signing key** and to verify `signed_prekey_sig` against it before any X3DH. SPK signature failure ⇒ reject (fail closed).

---

## 3. Double Ratchet

New pure module `lib/auth_db/encryption/services/doubleRatchetService.js`, dual-exported (`window.*` + `module.exports`), all randomness routed through `CryptoPrimitivesService` so it's seedable.

### 3.1 State (per conversation)

```
RK            root key (32B)
CKs, CKr      sending / receiving chain keys (32B, nullable)
DHs           our current ratchet keypair (X25519)   // secret wrapped at rest
DHr           their current ratchet public key (nullable until first recv)
Ns, Nr        message number in sending / receiving chain
PN            number of messages in previous sending chain
MKSKIPPED     map {(DHr_pub, n) -> message key}, capped at MAX_SKIP
```

### 3.2 KDFs (HKDF-SHA256, salt = chain key — *pass explicit salt*; `_hkdf` derives a context salt when none given, which we must override)

```
KDF_RK(RK, dh_out):
  out = HKDF(ikm = dh_out, salt = RK, info = "MoneyTracker:RK:v1", len = 64)
  return RK' = out[0:32], CK = out[32:64]

KDF_CK(CK):
  MK  = HKDF(ikm = 0x01, salt = CK, info = "MoneyTracker:MK:v1", len = 32)
  CK' = HKDF(ikm = 0x02, salt = CK, info = "MoneyTracker:CK:v1", len = 32)
  return CK', MK
```

(Single-byte constants `0x01`/`0x02` give the message-key vs chain-key separation; using `salt = CK` keeps the chain irreversible — you cannot recover `CK` from `CK'` or `MK`. This is the FS property the gate proves.)

### 3.3 Init

```
ratchetInitAlice(SK, DHr_bob):          // Alice has Bob's ratchet pub (= Bob's SPK)
  DHs = generateKeyPair()
  RK, CKs = KDF_RK(SK, dhRaw(DHs.sec, DHr_bob))
  DHr = DHr_bob; CKr = null; Ns=Nr=PN=0; MKSKIPPED={}

ratchetInitBob(SK, DHs_bob):            // Bob's initial ratchet keypair = his SPK keypair
  DHs = DHs_bob; RK = SK; CKs = CKr = null; DHr = null; Ns=Nr=PN=0; MKSKIPPED={}
```

Bob's first ratchet keypair **is his signed prekey** keypair, so Alice's `DH(EK/DHs, SPK)` lines up with Bob's side without a second round-trip.

### 3.4 Encrypt

```
ratchetEncrypt(state, plaintext):
  CKs, MK = KDF_CK(CKs)
  header  = { dh: DHs.pub, pn: PN, n: Ns }
  Ns += 1
  nonce      = randomBytes(24)
  ciphertext = secretbox(plaintext, nonce, MK)      // AD = serialize(header) [|| AD_x3dh on msg 0]
  return { header, nonce, ciphertext, newState }
```

### 3.5 DH ratchet + decrypt

```
ratchetDecrypt(state, header, nonce, ciphertext):
  mk = trySkipped(state, header)                    // out-of-order / previously-skipped
  if mk: return decrypt(mk)

  if header.dh != DHr:                               // DIRECTION CHANGE → DH RATCHET STEP
     skipMessageKeys(state, header.pn)               // finish old recv chain up to PN
     PN = Ns; Ns = 0; Nr = 0
     DHr = header.dh
     RK, CKr = KDF_RK(RK, dhRaw(DHs.sec, DHr))       // step 1: advance recv chain
     DHs = generateKeyPair()                         // fresh ratchet key
     RK, CKs = KDF_RK(RK, dhRaw(DHs.sec, DHr))       // step 2: advance send chain  ← PCS heals here

  skipMessageKeys(state, header.n)                   // catch up within current recv chain
  CKr, MK = KDF_CK(CKr)
  Nr += 1
  return { plaintext: decrypt(MK, nonce, ciphertext), newState }
```

`skipMessageKeys(until)` advances `CKr`, storing each `(DHr_pub, n) -> MK` into `MKSKIPPED`, refusing to exceed **MAX_SKIP = 1000** (throw → fail closed; protects against a malicious huge `n`). `trySkipped` looks up `(header.dh, header.n)` and **deletes the entry on hit** (consume-once).

**PCS:** when the peer sends after a direction change, the two `KDF_RK` steps mix a *fresh* DH secret into the root key. An attacker who stole the old chain keys cannot derive the new ones without the new ratchet private key — the chain self-heals.

---

## 4. Exact code changes

### 4.1 New files

- `lib/auth_db/encryption/services/x3dhService.js` — `publishPrekeys()`, `claimPeerBundle(peerId)`, `deriveInitiatorRoot(bundle)→{SK, preamble}`, `deriveResponderRoot(preamble)→SK`. Uses `dhRaw` + `nacl.sign`.
- `lib/auth_db/encryption/services/doubleRatchetService.js` — pure `ratchetInitAlice/Bob/Encrypt/Decrypt` + test-only `_inspectState()` accessor (for the FS gate).
- `CryptoPrimitivesService.dhRaw(ourSec, theirPub)` = `nacl.scalarMult` (NEW), and `signDetached`/`verifyDetached`/`signKeyPair` wrappers over `nacl.sign` (NEW).

### 4.2 `keyManagementService.js` rewiring

- **`establishSession()` (738):** if a `ratchet_states` record exists for the conversation, return it. Else: if we are the **initiator** (we are sending first / no inbound X3DH yet) run `x3dhService.deriveInitiatorRoot` → `ratchetInitAlice` and stash the X3DH preamble to attach to the first outbound message; if we are the **responder** (first inbound message carried an X3DH preamble) run `deriveResponderRoot` → `ratchetInitBob`. Persist ratchet state. **Remove the `epoch = 0` hardcoding.**
- **`encryptMessage()` (816):** delegate to `ratchetEncrypt`, **persist the advanced state atomically**, return `{ ciphertext, nonce, header:{dh,pn,n}, x3dhPreamble? }`.
- **`decryptMessage()` (889):** delegate to `ratchetDecrypt`, persist advanced state, **and write the consumed per-message key to the `decrypted_message_keys` archive (§5)**. Replace the SM-10 advance-only high-water mark with the MKSKIPPED store.
- **DELETE `_deriveSessionFromHistory()` (1354)** — re-running it would reset the ratchet (the #1 footgun). History decrypts only via the archive (§5).
- Retire `checkAndRotateIfNeeded()` (670) and `regenerateKeys()` and all `epoch` plumbing.

### 4.3 Facade — unchanged signatures

`encryptionFacade.encryptMessage/decryptMessage` keep their signatures; they pass the new header/preamble through.

### 4.4 New message header + columns

`secure_db/sql/complete-setup.sql` `messages` table (line ~281), add:

```sql
ratchet_pub    TEXT,        -- header.dh  (sender ratchet pubkey, base64)
prev_chain_len INTEGER,     -- header.pn
msg_num        INTEGER,     -- header.n  (reuse for message number in chain)
x3dh_ik        TEXT,        -- X3DH preamble (nullable; first msg only)
x3dh_ik_sign   TEXT,
x3dh_ek        TEXT,
x3dh_spk_id    INTEGER,
x3dh_opk_id    INTEGER
-- key_epoch kept nullable, vestigial
```

**No grant/RLS change needed:** the existing `GRANT SELECT, INSERT ON messages` is whole-row (no column scoping) and `messages_insert_participant` WITH CHECK only constrains `sender_id` + membership. Header fields are non-secret. **Deploy the columns before the new client** or inserts fail.

`messagingService.sendMessage` (197) maps `encrypted.header.*` + preamble into the insert. `getMessages` (375) **and** the duplicate in `messengerController.js:773` must pass `msg.ratchet_pub/prev_chain_len/msg_num` + the x3dh_* fields into the `encryptedData` object. **Extract a shared `buildEncryptedData(msg)` mapper** to prevent drift between the two call sites.

### 4.5 Ratchet-state persistence (`keyStorageService.js`, bump DB `version` 1→2)

New IndexedDB stores in `onupgradeneeded`:

- `ratchet_states` — keyPath `conversationId`: `{RK, CKs, CKr, DHs(secret wrapped), DHr, Ns, Nr, PN}`.
- `skipped_message_keys` — keyPath `[conversationId, ratchet_pub, msg_num]` (the MKSKIPPED map, persisted).
- `decrypted_message_keys` — keyPath `messageId` (the history archive, §5).

All secret-bearing fields (ratchet secret, chain keys, archived MKs) wrapped with the existing **SM-02 AES-GCM `wrap_keys`** key. Extend `clearAll()` (801) to wipe all three (still preserving `wrap_keys`).

---

## 5. Full-history re-decryption (the load-bearing piece) — **per-message-key archive**

`getMessages` re-decrypts the **whole** conversation, newest-first, in parallel, every open. A ratchet deletes each message key after use and is strictly ordered, so you **cannot** replay it over history (and definitely not out-of-order/in-parallel). Resolution:

> **When a message is FIRST decrypted (the single-message realtime arrival path, in ratchet order), persist its individual message key to `decrypted_message_keys[messageId]` (wrapped). All subsequent `getMessages` calls decrypt each message by ARCHIVE LOOKUP, never by advancing the live ratchet.**

- `decryptMessage` first checks `decrypted_message_keys[msg.id]`; on hit it `secretbox.open(MK)` directly (no ratchet touch). On miss (a brand-new realtime message) it runs `ratchetDecrypt`, then **writes the consumed MK to the archive** keyed by message id.
- The batch `getMessages` path therefore only ever hits the archive — it is order-independent and parallel-safe, so the existing `Promise.all` newest-first code at `messagingService.js:365` and `messengerController.js:613/773` **keeps working unchanged**.
- The **skipped-key store and the archive are the same machinery**: a skipped key, once consumed, also lands in the archive keyed by message id.
- **Ordering rule:** the FIRST mint of an archive entry must run in ratchet order. Route realtime single-message arrivals through `ratchetDecrypt`; route the batch history render through archive-only lookup. The existing SM-10 comment already distinguishes realtime vs batch paths — we lean on that split.

**FS posture:** keys are deleted from the **live ratchet**; the archive is the user's own at-rest copy of keys for messages they can already read — same trust level as the plaintext already rendered on screen, and exactly what Signal-desktop does. An attacker who steals the device **and** the `wrap_keys` AES-GCM key can read local history (unavoidable for any client that re-renders history), but **wire/server compromise and identity-secret compromise no longer retroactively decrypt history** — which is the FS threat model that matters here.

We persist **per-message keys, not a plaintext memo** (a plaintext memo would also work for re-render but loses the ability to re-verify the AEAD tag and is a larger plaintext footprint; per-message keys keep authentication intact and double as the skipped-key store).

---

## 6. Device pairing / multi-device

The model has **one `identity_keys` row per user**, so a single shared ratchet across devices would double-ratchet (two devices advancing the same chain → permanent desync). Design:

- **Transfer across the pairing channel (unchanged shape):** identity secret (X25519 IK) **+ the new Ed25519 IK_sig secret** + the `sessionBackupKey`. Bump `exportPairingBundle` `v:1→2` to include `identitySignSecretB64`. **Do NOT transfer live ratchet state** (`RK/CKs/CKr/DHs/...`) — cloning it desyncs both devices.
- **New device starts FRESH ratchets.** On pairing it republishes its own SPK + OPK pool (it shares the identity, so peers still verify the same IK_sig). In-flight sessions get re-bootstrapped via X3DH on the next message — a clean break of in-flight ratchet state, which the prompt permits.
- **Old history on the new device** is read **only** from the transferred at-rest `decrypted_message_keys` archive. So: back up the archive (wrapped under `sessionBackupKey`) to the existing `conversation_session_keys`-style backup path so it travels with pairing; `importPairingBundle` restores it before first render.
- **Documented limitation:** **single active ratchet per device**; two simultaneously-active devices on the same identity will fight over the live chain. Full multi-device (per-device identities or sender-keys fan-out) is out of scope and noted as future work — it requires a schema rethink (multiple `identity_keys`/prekey rows per user). This is acceptable given the clean-break mandate and current single-active-device usage.

---

## 7. Clean-break migration

A clean break of existing encrypted data is explicitly acceptable, so there is **no decrypt-and-re-encrypt migration**:

1. Deploy schema first: `messages` new columns + `prekeys`/`one_time_prekeys` tables + `claim_one_time_prekey` RPC.
2. On first run of the new client, `clearAll()`-style wipe of `session_keys`/`historical_keys` ratchet-relevant stores; create the v2 IndexedDB stores; every user publishes IK_sig + SPK + OPK pool.
3. **Old messages become unreadable** (their static-ECDH keys are abandoned). Mark pre-cutover rows with a sentinel (`key_epoch` legacy / `ratchet_pub IS NULL AND x3dh_ik IS NULL`) and render `[Message from a previous encryption version — unavailable]` instead of erroring. Optionally hard-delete pre-cutover rows.
4. New conversations and all new messages use X3DH + ratchet from message zero.

---

## 8. TEST GATES (deterministic, node-runnable, no messenger runtime)

The services already dual-export via `module.exports`; gates run under `node` with a NaCl shim and a **seeded RNG hook** on `CryptoPrimitivesService.randomBytes`/`generateKeyPair`/nonce generation. Vectors are generated once with a frozen seed, committed, then **immutable (LAW-4: never softened)**. Required gates:

1. **HKDF KAT** — assert `_hkdf` matches RFC 5869 test vectors (anchors the KDF).
2. **X3DH KAT** — fixed IK/IK_sig/SPK/OPK/EK inputs → assert exact hex of `SK` (both initiator and responder paths derive identical `SK`).
3. **Ratchet transcript KAT** — Alice/Bob exchange a scripted transcript across ≥2 direction changes; assert each ciphertext **and** each derived message key matches a committed vector (catches any drift in DH order, HKDF info strings, or header parsing).
4. **(a) Round-trip incl. out-of-order** — deliver `[3,1,2]` and across a DH-ratchet boundary; assert all decrypt correctly and `|MKSKIPPED| ≤ MAX_SKIP`; assert a message arriving with `n` jump > MAX_SKIP throws (fail closed).
5. **(b) FORWARD SECRECY** — after decrypting message `N`: use `_inspectState()` to assert the message key for `N` and all chain keys for indices `< N` are **absent/zeroed** in live state; assert re-running `ratchetDecrypt` of message `N` from the post-state **FAILS** (key gone); assert the `decrypted_message_keys` archive still opens it. Additionally assert `KDF_CK` is one-way: given `CK'` and `MK`, you cannot reproduce `CK` (no inverse exists) — the literal FS proof.
6. **(c) POST-COMPROMISE SECURITY** — snapshot a "compromised" state (attacker holds `CKs/CKr/RK`), perform one full DH-ratchet step (direction change), then assert the attacker's stale keys **cannot** decrypt a post-ratchet message while the legitimate party can.
7. **Interop (hardening)** — generate cross-impl vectors from `python-doubleratchet` (Syndace) under identical seeds and assert our ciphertext/keys match, to validate the spec interpretation.

These gates are the substitute for runtime crypto testing and are the arbiter of correctness (LAW-0/LAW-4 discipline).

---

## 9. Staged build plan (small, reviewable, each independently testable)

Each stage lands behind the previous and ships its own green gate. No big-bang.

- **S0 — Primitives + RNG seam.** Add `CryptoPrimitivesService.dhRaw` (`nacl.scalarMult`), `signKeyPair`/`signDetached`/`verifyDetached` (`nacl.sign`), and a seedable RNG hook. Gate: HKDF RFC-5869 KAT (gate #1) + a dhRaw KAT. *No behavior change to messaging.*
- **S1 — `doubleRatchetService.js` (pure, offline).** Implement init/encrypt/decrypt/skip with `_inspectState`. Gate: transcript KAT (#3), round-trip + out-of-order (#4), FS (#5), PCS (#6). *Not wired into the app yet.*
- **S2 — `x3dhService.js` (pure, offline).** Four-DH derivation + SPK signing/verify. Gate: X3DH KAT (#2). *Not wired in.*
- **S3 — Schema.** `messages` columns + `prekeys`/`one_time_prekeys` + `claim_one_time_prekey` RPC + RLS; register tables in both config files. Deploy before any client change. Gate: schema apply + RLS smoke (SELECT peer prekeys works, cross-user INSERT denied).
- **S4 — Persistence.** Bump IndexedDB to v2; add `ratchet_states` / `skipped_message_keys` / `decrypted_message_keys`; wrap secrets with `wrap_keys`; extend `clearAll`. Gate: store round-trip (write→wrap→read→unwrap) unit test.
- **S5 — Wire encrypt path.** Rewire `establishSession` + `encryptMessage` to X3DH + `ratchetEncrypt`; add the shared `buildEncryptedData` mapper; map header/preamble in `sendMessage`. Gate: send produces spec-conformant header rows (assert columns) — still no decrypt change.
- **S6 — Wire decrypt + archive.** Rewire `decryptMessage` to `ratchetDecrypt` + archive mint; route realtime vs batch paths; delete `_deriveSessionFromHistory`; retire epoch/rotation. Gate: full send→archive→batch-re-decrypt round-trip incl. out-of-order, asserting batch path is archive-only (FS preserved). Update `messengerController.js:773` via the shared mapper.
- **S7 — Pairing/multi-device.** Bump pairing bundle to `v:2` (carry IK_sig); back up the archive under `sessionBackupKey`; new device starts fresh ratchets + republishes prekeys; render old history from the transferred archive. Gate: simulated pairing — new device reads archived history, in-flight session re-bootstraps via X3DH.
- **S8 — Clean-break + UX.** Sentinel + `[previous encryption version]` rendering for pre-cutover rows; OPK replenishment job; interop vectors (#7) wired into CI. Gate: pre-cutover rows render the sentinel without error; interop vectors green.

---

## Appendix — verified codebase anchors

- `keyManagementService.js`: `establishSession` ~738, `encryptMessage` ~816, `decryptMessage` ~889, `_deriveSessionFromHistory` ~1354, `checkAndRotateIfNeeded` ~670, `_getPinnedPeerKey` ~995, `exportPairingBundle`/`importPairingBundle` ~1205/1226.
- `cryptoPrimitivesService.js`: `generateKeyPair` 64, `randomBytes` 85, `deriveSharedSecret` 98 (= `nacl.box.before`), secretbox nonce 114/155. **No `nacl.sign` wrapper yet — added in S0.**
- `keyDerivationService.js`: `deriveMessageKey` ~62, `_hkdf` ~99 (derives a context salt when none passed — ratchet must pass explicit `salt = CK`).
- `keyStorageService.js`: `_openDatabase`/`onupgradeneeded` ~52-116 (stores: identity_keys, session_keys, historical_keys, wrap_keys, pinned_keys, recv_counters; DB version default 1), `clearAll` ~801.
- `messagingService.js`: `sendMessage` insert ~197, `getMessages` parallel re-decrypt ~365/375. Duplicate decrypt site `messengerController.js:773`, parallel fetch ~613/620.
- Schema: `messages` `secure_db/sql/complete-setup.sql` ~281 (message_counter BIGINT ~288), `GRANT SELECT,INSERT ON messages` ~378, `messages_insert_participant` RLS. Identity tables + RLS `messaging_app/lib/auth_db/backend/sql/complete-setup.sql` ~72-87.
