# PLATFORM — North Star

> The single source of truth for what this platform is, how it is composed, what it protects, how it must feel, and where it is going. Tied to the real repos, not marketing.

---

## 1. PURPOSE

**A privacy-first personal platform: end-to-end encrypted budgeting and messaging under one identity — the only place your spending and your conversations live behind the same zero-knowledge wall.**

Neither Signal (no money) nor Mint/YNAB/Copilot (no privacy — they aggregate and monetize your financial data) nor any messenger can offer this. The defensible asset is **one E2E identity** (`auth_db/encryption`) that spans both products, with the messenger embedded inside the budget app and shipped as an all-in-one installer. The mandate of this document: make that claim *literally true in the code* before it is ever marketed.

---

## 2. ARCHITECTURE

### 2.1 The five repos — layered responsibilities

| Layer | Repo | Owns (canonical) |
|---|---|---|
| **Foundation** | `auth_db` | DB client substrate + auth (user-lookup, delete-account edge fns) + the **E2E crypto/identity subsystem** (`encryption/`: key management, at-rest WebCrypto key wrap, TOFU pinning, device pairing, password/recovery backups) + canonical identity SQL. |
| **Messaging schema** | `secure_db` | Canonical messaging schema: `conversations` / `messages` / `message_attachments` / `session_keys` / `friends`, with hardened RLS (participant-bound inserts, column-scoped GRANTs, `is_blocked()` SECURITY DEFINER). |
| **Payments** | `payments_app` | Stripe: edge functions + **server-authoritative entitlement** (`start_trial` / `downgrade_to_free` SECURITY DEFINER RPCs — clients cannot self-grant tier). |
| **Messenger product** | `messaging_app` | Self-contained E2E messenger consuming `auth_db` + `payments_app`. |
| **Budget product + shell** | `money_tracker` | Budget app that **embeds** the messenger, consumes all submodules, and ships the all-in-one installer. |

**Layering principle:** the foundation knows nothing about the products; each schema/edge-fn artifact has exactly **one canonical home in its owning repo**, and everything else **references** it (submodule path, generated aggregate, deploy-from-source). No hand-merged supersets, no manual edge-fn copies.

### 2.2 Shared backend + submodule composition

- **One Supabase backend** (Postgres + Auth + Realtime + Storage + Edge Functions) serves both front-ends. RLS provides tenant isolation; Realtime drives live messaging; Storage holds (encrypted) attachments that auto-expire at 24h.
- **Two vanilla-JS / GitHub-Pages front-ends.** Views are thin `<script src>` wrappers over `lib/auth_db/...`, `lib/payments_app/...`, `lib/messaging/...` — JS reuse is real, not copy-paste. Per-app config is injected by file selection (`moneyTrackerDatabaseConfig.js` vs the messaging variant) over a shared `*ConfigBase.js` (strategy pattern).
- **Submodules:** `money_tracker` pulls `auth_db`, `payments_app`, and `messaging_app`; `messaging_app` in turn pulls `auth_db` + `payments_app`.

### 2.3 Known composition debt (must close — see Roadmap)

- **`secure_db` is an orphan.** It is *named* canonical but is a submodule of nothing (`.gitmodules` lists only `auth_db`, `payments_app`, `messaging`). The real schema lives as two diverging hand-merges: `messaging_app/.../complete-setup.sql` (~1306 lines) and `money_tracker/.../fresh-install-complete.sql` (~2097 lines), both already drifted from `secure_db/sql/complete-setup.sql` (~742 lines).
- **Edge functions copied 3–4×** (`payments_app/backend/edge-functions`, `payments_app/supabase/functions`, and each app's `database/supabaseEdgeFunctions`) and **actively drifting** — a fix in the canonical webhook does not reach the deployed copies; names diverged (`create-portal-session` vs `customer-portal`).
- **Nested double-vendoring:** `auth_db`/`payments_app` are checked out at two depths (`lib/auth_db` *and* `lib/messaging/lib/auth_db`). Two divergent copies of the **encryption subsystem** in one deployed page is a correctness *and* security hazard (mismatched TOFU pin store / key-wrap).
- **CI is gateless:** the two `deploy.yml` are byte-identical, run only `npm ci && build && deploy`, upload `path: '.'` (the whole repo incl. node_modules + server-side `.ts`/`.sql`) instead of `dist/`, and have no test/lint/drift/SHA-consistency check.

### 2.4 How a new product slots in (the target)

When the debt above is closed, a **third front-end** (e.g. a notes app) is *a day of wiring, not a re-merge*: add 3 submodules + thin wrapper views + one config file, assemble the DB from a **generated migration manifest** (`auth_db → secure_db → payments_app → app-local glue`, fixed dependency order, `git diff --exit-code` gated like a lockfile), deploy edge functions straight from the submodule path, and reuse a single `workflow_call` deploy workflow. It inherits auth, payments, and E2E messaging for free.

---

## 3. SECURITY MODEL

### 3.1 Threat model

Primary adversary: a **curious (or compromised, or subpoenaed) server operator** who can read the database, archive all ciphertext, and influence what keys/scripts the client receives. Secondary: **device theft / endpoint malware**, and **XSS / supply-chain swap** of the in-browser crypto. The whole model lives in the browser JS heap, so anything that can read that heap defeats everything.

### 3.2 What is covered (genuinely strong, post-remediation)

- **Primitives:** TweetNaCl X25519 + XSalsa20-Poly1305; HKDF-SHA256 key hierarchy (`SessionKey` from sharedSecret+epoch, `MessageKey` from sessionKey+epoch+counter); PBKDF2-SHA256 **600k** + AES-256-GCM password backups (random 32-byte salt + 12-byte IV per blob).
- **At-rest key wrap (SM-02):** identity secret is **never persisted in plaintext** — AES-GCM-wrapped under a **non-extractable** WebCrypto key in the `wrap_keys` IndexedDB store; legacy plaintext records detected and disposed; unwrap failures throw typed errors (`WRAP_KEY_UNAVAILABLE` / `IDENTITY_UNWRAP_FAILED`) rather than silently wiping.
- **TOFU (SM-01):** single chokepoint (`_getPinnedPeerKey`) both ECDH sites use; first contact pins the peer key.
- **Replay (SM-10):** per-`(conversation, epoch, sender)` high-water marks in `recv_counters`; Poly1305 per-message auth; non-masking auth failures (SM-24) — a single re-derive retry only if the freshly derived key actually differs, else a typed `DecryptionError`.
- **Device pairing:** 80-bit random code, PBKDF2-600k + AES-256-GCM wrapped **before** touching the server, single-use, 5-min expiry, fail-closed `MAX_ATTEMPTS`; raw identity secret only ever leaves as ciphertext.
- **RLS (`secure_db`):** `messages_insert_participant` binds `recipient_id` to the counterparty + calls SECURITY-DEFINER `is_blocked()`; column-scoped `GRANT UPDATE (read, read_at)` (can mark-read, cannot rewrite `encrypted_content`/`sender_id`); `session_keys_*_own` scopes rows to owner.
- **Entitlement:** server-authoritative SECURITY DEFINER RPCs — clients cannot self-grant tier.

### 3.3 The honest gaps (verified in code)

| # | Gap | Severity | Reality in the repo |
|---|---|---|---|
| 1 | **No forward secrecy / post-compromise security** | foundational | `establishSession()` and `_deriveSessionFromHistory()` both call `deriveSharedSecret(ourSecret, theirPublic)` — **static-static ECDH**; `epoch` hardcoded to `0` (`keyManagementService.js:744`), `checkAndRotateIfNeeded()` returns `{rotated:false, reason:'auto_rotation_disabled'}` (`:674`). The counter gives key *separation*, not a ratchet. One device compromise → **entire past and future** conversation history decryptable. Invisible to ERC/RLS/DRC-style gates. |
| 2 | **Recovery key shipped at testing-reduced 160-bit** | high | `passwordCryptoService.js:187` `RECOVERY_KEY_BYTES: 20` with an in-code `// TESTING ... For PRODUCTION set this back to 32`. It is one of only two secrets that unwrap the identity key. A documented downgrade in shipped code. |
| 3 | **Key-change is silent / auto-adopting** | high | On a peer fingerprint change `_getPinnedPeerKey` fires one `peerKeyChanged` event, then **re-pins and keeps encrypting to the new key**. Against a curious operator this is the exact MITM bypass: swap the published key, client warns once (non-blocking), then encrypts to the operator's key. |
| 4 | **Metadata fully exposed to the operator** | high | Bodies are E2E, but the **social graph + timing are plaintext**: `messages.sender_id/recipient_id/created_at/read/read_at/message_counter`, `conversations.user1_id/user2_id`, `message_attachments.file_name/file_size/mime_type`. The schema even comments "stored unencrypted for querying." |
| 5 | **CSP retains `'unsafe-inline'`** | high | `money_tracker/index.html` script-src AND style-src allow `'unsafe-inline'`. Since all keys/plaintext live in the JS heap, one inline-script XSS = total E2E compromise, not a contained bug. |
| 6 | **Budget data is NOT E2E encrypted** | foundational | `fresh-install-complete.sql` stores `estimated_amount`, `actual_amount NUMERIC(12,2)` and `category TEXT` in **plaintext**; budget/pots controllers contain zero encrypt/ciphertext calls. The headline "privacy-first budget" is aspirational on the server side today — a reviewer reading the schema sinks the positioning instantly. |
| 7 | **Supply-chain integrity unverified** | medium | No SRI/hash pinning found on the TweetNaCl/Stripe includes. A host/CDN/MITM swap silently backdoors the crypto with nothing on-page to notice. |
| 8 | **Transitive multi-device trust, no per-device identity** | medium | Pairing copies the **same** static identity secret to each device; no device list, no per-device key, no revocation; a peer's safety number does not change when a device is added, so a coerced pairing is invisible to counterparties. |

**One security principle:** *Encryption strength is capped by its weakest trust assumption, not its strongest algorithm.* A 600k-PBKDF2 / X25519 stack still grants total retroactive compromise because the session secret is static (no ratchet), the server is silently trusted on key changes (auto-adopting TOFU), and any inline-script XSS reads the keys straight out of the heap. **Close the static-key, silent-key-swap, and XSS paths before celebrating the primitives.**

---

## 4. UX PRINCIPLES

**North star:** *Security is felt as trust, never as homework.* Make the secure path the **invisible default** and the human-readable path the only one the user ever sees. Every screen that mentions keys, pairing, fingerprints — or silently signs the user out — is a place where security has leaked into the user's job.

1. **Onboarding is 2 real decisions.** Email + password and you're in. The recovery key is generated and auto-stowed inside the encrypted password backup with a single optional "save a backup" nudge — **not** a blocking copy-and-confirm wall (today `setupDeviceEncryption` disables "Continue to App" until "I have saved my recovery key" is ticked). Email verification is magic-link or deferred so the user lands in the app first.
2. **Adding a device feels like AirDrop.** Scan a QR / tap a code shown on the old device, trusted in seconds, on a dedicated **"Set up this device"** screen — *never* the current silent sign-out (today an unpaired device hits `PairingGuard.requirePairing()`, is signed out with only a `console.log`, and is dumped at a blank login — the single worst moment in the product).
3. **Messaging starts from a real contact list.** Search-as-you-type over the existing `friends` table + the user-lookup edge fn; pick a person, not retype an email into a modal. Recently-messaged + recipient validation before composing.
4. **Verification is one tap.** A per-conversation "Verify [name]" showing both safety numbers side-by-side (+QR), and an **automatic in-thread banner the instant a contact's key changes** — driven by the TOFU pin store that already exists but is surfaced nowhere in the thread today.
5. **Crypto is otherwise invisible.** No "Encrypting Your Data" theater on the happy path.
6. **One design language, sub-second loads.** Budget and messenger share one header and class system (migrate the messenger off its heavy inline styles); bundle per-route (`vite.config.js` already present) and lazy-load encryption/payments/messaging only after auth — the login page should not run `CryptoLibraryLoader.load()` + payments init + DB init before first paint.
7. **No jargon.** "this device" not "identity keys"; "link a device" not "pairing code"; "verify it's really them" not "encryption fingerprint / TOFU."
8. **Errors are inline toasts, not `alert()`.** Replace every native `alert()/confirm()` in the messenger (and any remaining in auth) with one shared toast/inline-validation component living in `auth_db/shared` so both apps reuse it.

---

## 5. COMPETITIVE POSITIONING

**The one thing no competitor can copy:** a **single zero-knowledge identity across money AND messaging.** Lead with it — and make it literally true first.

- **Defensible wedge:** E2E-encrypted **budget** data is the real differentiator vs the data-mining incumbents (Mint/YNAB/Copilot, who sell/aggregate). The pitch — *"the only place your spending and your chats live behind the same zero-knowledge wall"* — has **no direct competitor**. A privacy-preserving client-side CSV/OFX import (parse + categorize + encrypt in the browser, **no Plaid/server aggregation**) is itself a differentiator: "import your statements without anyone — including us — seeing them."
- **Table-stakes the messenger must reach** so privacy-conscious users don't have to *downgrade* their messaging to adopt ours: **forward secrecy** (Signal/WhatsApp/Matrix all ratchet; shipping weaker than the free incumbents is a credibility hole), **group chat** (schema is structurally 1:1 today — `(user1_id, user2_id)` with `user1_id < user2_id`, `conversation_participants` dropped — which caps adoption at niche secure-DM), **verified contacts in-thread**, **seamless multi-device with synced history**, and **disappearing messages** (today only attachments auto-expire at 24h).
- **Strategy:** competing as "another budget app" or "another secure messenger" is a losing two-front war. Once budget-E2E and the ratchet are real, reposition landing + pricing around *"one private identity for your money and your messages,"* and gate the **combined / cross-app / sharing** experience behind Premium while keeping single-app basics free — so the moat is also the monetization lever.

**One product principle:** Lead with the one thing no competitor can copy, and make it literally true before marketing it. Everything else is either table-stakes you must reach or a distraction.

---

## 6. ROADMAP — to truly secure, competitive, seamless

Ordered. Each tagged **[foundational] / [high] / [medium]** with a one-line why.

### THE #1 THING — do this first, above everything

**1. [foundational] Forward secrecy + post-compromise security (Double Ratchet).** *Why: the single largest gap to Signal/WhatsApp-class messengers and the one that turns "E2E" into total retroactive compromise on any one device theft.* Implement an X3DH-style handshake (signed prekeys + one-time prekeys added to `identity_keys` / a new `prekeys` table) feeding a Double Ratchet — a symmetric KDF chain advancing per message (forward secrecy) plus a DH ratchet injecting a fresh ephemeral X25519 on each direction change (post-compromise security). The existing `epoch`/`counter` fields and the HKDF chain are usable scaffolding; **replace the static `deriveSharedSecret` call site** with a ratchet state machine persisted alongside `session_keys`. Strongly prefer wrapping a vetted library (libsignal-protocol WASM) over a bespoke ratchet, keeping the X25519 identity keys as the X3DH identity input. **Gate:** a test proving an old message key cannot be re-derived after the chain advances.

### Foundational — the headline claims must become true

**2. [foundational] Encrypt budget data client-side.** *Why: the entire privacy wedge vs Mint/YNAB is currently unbacked — amounts and categories are plaintext on the server.* Encrypt `estimated_amount`/`actual_amount`/`category` with the `auth_db/encryption` facade (identity key is already provisioned), storing base64 ciphertext in the existing columns; design friend-sharing as a re-encrypt-to-recipient flow, not plaintext rows.

**3. [foundational] Wire `secure_db` as a submodule + delete the hand-merged schema.** *Why: the "canonical" schema is an orphan with two diverging masters — the biggest threat to the architecture claim.* Add `lib/secure_db` to both apps, reconcile the three versions into `secure_db` first, then generate the deployable DB from a fixed-order manifest gated by `git diff --exit-code`.

### High — close the silent-bypass and table-stakes gaps

**4. [high] Make key-change FAIL-CLOSED + surface verification in-thread.** *Why: auto-adopting TOFU is the exact curious-operator MITM bypass, and the safety number exists but is unusable.* Block new outbound encryption to a peer on fingerprint change until the user re-verifies (`generateSafetyNumber` already exists); keep decrypting received history; show an unverified-identity banner and a per-conversation "Verify [name]" view.

**5. [high] Remove `'unsafe-inline'` from CSP + add SRI/lockfile to the crypto bundle.** *Why: one inline-script XSS or a swapped dependency reads keys out of the heap and defeats all of the above.* Move inline handlers/styles to files, adopt nonces/hashes, self-host + pin TweetNaCl with SRI, and CI-check the served crypto hash.

**6. [high] Recovery key back to 256-bit + CI guard.** *Why: a documented testing downgrade is a latent at-rest weakness and an audit liability.* Set `RECOVERY_KEY_BYTES = 32`, regenerate any keys minted under the test value, and fail the build if it is ever `< 32`.

**7. [high] Fix the silent sign-out + recovery-key wall (activation killers).** *Why: the worst UX moment in the product (a "wrong password" dead end) and a security chore gating first feature.* Dedicated "Set up this device" screen (link-from-device → password restore → recovery key) *before* any sign-out; let users into the app immediately after key-gen with recovery surfaced as a dismissible banner.

**8. [high] Group chat.** *Why: a 1:1-only messenger can't be anyone's primary, capping adoption and the embed's stickiness.* Resurrect `conversation_participants` with membership-scoped RLS, then layer Sender Keys for group E2E — sequenced **after** the ratchet so groups aren't built on the static protocol.

**9. [high] Contact picker + privacy-preserving budget import.** *Why: messaging by retyped email and a manual-only budget both lose on day-to-day utility.* Search-as-you-type contact picker over `friends` + user-lookup; client-side CSV/OFX import that parses/categorizes/encrypts in the browser with no Plaid/server aggregation.

### Medium — harden, de-risk, polish

**10. [medium] Minimize server-visible metadata.** *Why: "E2E" today still leaks the full social graph + timing — the bulk of what surveillance wants.* Encrypt attachment `file_name` + bucket/pad `file_size`, explore sealed-sender (authenticate sender inside the ciphertext), coarsen `created_at`; document the honest residual.

**11. [medium] Per-device identity + revocation.** *Why: transitive trust makes a coerced pairing invisible to peers and revocation impossible without nuking the identity.* Per-device X25519 keypairs under a user identity, a device list, multi-device safety numbers — co-designed with X3DH-per-device.

**12. [medium] CI drift/parity/SHA gates + de-dupe edge functions + reusable deploy workflow.** *Why: every duplication above is silently mergeable today, and the nested double-vendor risks two crypto copies in one page.* One canonical edge-fn home, recursive SHA-consistency check, vite alias so the embedded messenger resolves a single `auth_db`, `path: 'dist'` deploy, and a `workflow_call` deploy reused by all apps.

**13. [medium] Disappearing messages + multi-device history sync, then reposition.** *Why: baseline expectations whose absence reads as "unfinished," and the moat only sells once it's real.* Per-conversation timer (client delete + server retention), tested history sync over the existing pairing/backup services, then reposition landing + pricing around the one-private-identity moat with combined/sharing gated behind Premium.

---

*This document is the platform's north star. When a change conflicts with it, change the code, not the document — unless reality has taught us the document is wrong, in which case update it here first.*
