# FINAL PRE-PENTEST SECURITY AUDIT — Privacy-First E2E Platform

**Date:** 2026-06-23
**Scope:** auth_db (identity + E2E crypto), secure_db (messaging schema/RLS), payments_app (Stripe edge functions), messaging_app (client), money_tracker (budget client + budget E2E). Shared Supabase (Postgres+RLS+Auth+Realtime+Storage+Edge Functions).
**Lens:** malicious authenticated user, malicious peer, MITM, AND a curious/compromised server (zero-knowledge must hold against the server itself). READ-ONLY review.
**Baseline reviewed:** the hardened, committed state after waves 1–3 (auth_db `ed51842`, secure_db `61c6b39`, payments_app `c2cbb34`, messaging_app `464e968`, money_tracker `0d75add`).

---

## 1. OVERALL VERDICT

**GO — the platform is ready for a serious external pentest, conditional on closing one HIGH and one LOW (neither is a remote/server/MITM exploit).**

The cryptographic core and the server-side authorization surface are in genuinely strong shape. All wave 1–3 fixes I re-verified are **confirmed closed** and several are notably robust (the H-1 atomic responder co-pin, the C-1 column-scoped GRANT + DEFINER RPC, the M-2 two-tier OPK token buckets, the M-3 completion-based webhook idempotency). I found **no new CRITICAL**, and **no new remotely-exploitable HIGH** reachable by the server, a MITM, a malicious peer, or a malicious authenticated user over the network.

The one carried HIGH (logout does not wipe the E2E key IndexedDB) is **real and confirmed** but requires **local/same-profile device access** — it is not in the network attacker model that an external red team primarily exercises. It should be fixed before launch but does not block the pentest.

**Residual-risk posture:** acceptable for an external test. Zero-knowledge against the server holds (message content is `encrypted_content`; attachment name/type/exact-size are client-encrypted with only a coarse size bucket in plaintext; sealed budget DEK is H-4 context-bound; private key secrets never leave the client). The remaining real risk is **at-rest device confidentiality after logout** (HIGH, local-access) plus inherent **metadata** exposure (conversation participants, coarse sizes, timing) that is architectural, not a defect.

---

## 2. FIX-VERIFICATION RESULTS (waves 1–3)

| ID | Fix | Status | Evidence |
|----|-----|--------|----------|
| **C-1** | data_shares UPDATE WITH CHECK + column-scoped GRANT + `update_share_grants` DEFINER RPC | **CLOSED** | `money_tracker/database/setup/apply-data-shares-with-check.sql:48-114` and `fresh-install-complete.sql:981-1130`. UPDATE policies carry WITH CHECK; table-wide UPDATE revoked, GRANT scoped to `status, wrapped_dek, wrap_nonce, wrap_eph_pub, wrap_owner_ik, dek_version, updated_at`; `can_edit/share_all_data/year/month/owner_user_id` only writable via the owner-asserting DEFINER RPC (`SET search_path`, re-asserts `auth.uid() = owner_user_id`). Recipient UPDATE pinned to own row, status→accepted/rejected only. |
| **H-1** | Responder X3DH X25519-IK pin (atomic co-pin) | **CLOSED (robust)** | `auth_db/encryption/services/keyManagementService.js:1303-1374` `_resolveResponderPeerIdentity`. Rejects a swapped wire `ikPub` even when the attacker supplies the genuine IK_sig (line 1332-1339); bound-pair check (1320-1327); cross-check vs published IK through TOFU chokepoint (1345-1354); IK_sig pinned FIRST so a sign-key change aborts before any X25519 pin is written; X25519 pin written LAST. |
| **H-2** | `enforcePasswordStrength` wired (min 12) | **CLOSED (note)** | `auth_db/shared/services/authService.js:557-563` (signup) and `1077-1083` (change). Calls `PasswordCrypto.enforcePasswordStrength`, with an inline `< 12` fallback. NOTE: the legacy `Validators.password` (`validators.js:45-46`) and `Constants.VALIDATION.MIN_PASSWORD_LENGTH = 6` (`constants.js:68`) still read 6 — these are NOT on the authoritative auth path but are stale and should be raised to 12 to avoid a future regression if any flow re-wires to the validator. (LOW/hygiene; see §3.) |
| **H-3** | Server `is_premium_active` + trial-expiry cron (messaging FREE, sharing Premium-gated) | **CLOSED** | `secure_db/sql/complete-setup.sql:418-423` (messaging INSERT has NO premium check by product decision); `money_tracker/.../fresh-install-complete.sql:957-962` (data_shares owner-INSERT gated on `is_premium_active`). DEFINER predicate, fail-closed, defined before use. |
| **H-4** | Authenticated context-bound DEK seal (v2) | **CLOSED** | `money_tracker/.../fresh-install-complete.sql:2162-2185`. Seal binds (owner_id, recipient_id, owner IK, recipient IK, dek_version, share_id); `wrap_owner_ik` verified against the TOFU-pinned sender key; static-static DH leg authenticates origin (no anonymous box). Recipient overwriting their own `wrapped_dek` is self-DoS only — they cannot forge a valid seal. |
| **H-5** | CSP unsafe-inline removed | **CLOSED (spot-checked)** | Messaging client renders all dynamic text via `_escapeHtml` / `textContent`, no inline `onclick`/`onmouseover` (delegated listeners, e.g. `messengerController.js:1168-1169`). Consistent with inline→external+addEventListener. |
| **H-6** | Attachment metadata encrypted (coarse size bucket) | **CLOSED** | `secure_db/sql/apply-attachment-metadata-encryption.sql:48-67`. name/type/exact-size in `encrypted_metadata` (XSalsa20-Poly1305 under conversation KEK); only `file_size_bucket` (rounded up) in plaintext. |
| **W2-1** | Attachment-id Number-coerced + data-attr/delegated listener | **CLOSED** | `messengerController.js:1148-1150` `Number(att.id)` + positive-integer guard; id only via `data-attachment-id`; delegated listener re-validates. |
| **W3-1** | Realtime never reads `.content` (requires ciphertext+ratchet) | **CLOSED** | Server stores `encrypted_content TEXT NOT NULL` (`secure_db/.../complete-setup.sql:348`); message SELECT scoped to conversation participants (405-412). Decryption is client-side via ratchet; server never sees plaintext. |
| **W3-2** | Ratchet-invariant attachment key AK0 + AAD | **CLOSED** | Consistent with H-6 (metadata sealed under the conversation's invariant attachment key); no per-message ratchet dependency for attachment metadata. |
| **W3-3** | `resolve_user_id_by_email` RPC + rate-limit + uniform response | **CLOSED** | `auth_db/backend/sql/apply-user-lookup-resolver.sql:47-91`. 30 lookups/caller/hour (`user_lookup_audit` ledger); DEFINER, `SET search_path`, granted to `service_role` only; edge fn `user-lookup.ts:61,104,157-158` binds `p_caller_id = authData.user.id` (verified JWT, not client-supplied). The ok/not_found distinction is inherent (you need the id to start a conversation) and is rate-limited. |
| **M-2** | `claim_one_time_prekey` token-buckets + own-only OPK SELECT | **CLOSED** | `apply-opk-claim-rate-limit.sql:36-39` (`select_own`), `44-58` (audit ledger + indexes), two-tier buckets per-(caller,target) ≤10/h and per-target ≤60/h. |
| **M-3** | Completion-based webhook idempotency | **CLOSED (robust)** | `stripe-webhook/index.ts:151-235,277-402`. Claim row `processed=false`; alreadyProcessed→short-circuit 200; inFlight→re-run idempotent handler; `processed=true` flipped only on success; failure returns 500 so Stripe retries. Handles the crash-after-claim case correctly. |
| **M-4** | Downgrade-plan validation | **CLOSED** | `update-subscription/index.ts:95-130,142-174` `validateDowngradeTarget` requires real, active, strictly-cheaper plan; caller bound to own `subscriptions` row via verified JWT (`63-72`). |
| **M-5** | `create_notification` relationship check | **CLOSED** | Notifications UPDATE is column-scoped to `read` (`fresh-install-complete.sql:1563`); relationship-gated creation per `apply-notification-relationship-check.sql`. |

**Cross-repo consistency:** the two webhook copies (`payments_app/backend/edge-functions/stripe-webhook.ts` and `payments_app/supabase/functions/stripe-webhook/index.ts`) are byte-identical (MD5 `310fd77c…`). All SECURITY DEFINER functions across all four SQL schemas pin `SET search_path` (verified programmatically — zero misses). No RLS `USING(true)` over-broad SELECT leaks private content (all are on legitimately-public tables: identity_keys, public_key_history, prekeys, subscription_plans, example_months — with one exception noted in §3).

---

## 3. NEW FINDINGS (CRITICAL → LOW)

### CRITICAL — none.

### HIGH

#### H-NEW-1 (carried, CONFIRMED REAL): Logout never wipes the E2E key IndexedDB or the at-rest wrap key
- **Attacker model:** local/same-profile device access — a second OS user on the same browser profile, a shared/kiosk/family computer, or device-theft/forensic access. NOT the server, MITM, or a remote peer.
- **File:line:** `auth_db/shared/services/authService.js:710-802` (`signOut` never calls `KeyStorageService.deleteDatabase()`/`clearAll()`); `auth_db/encryption/services/keyStorageService.js:1588-1629` (`clearAll` *intentionally preserves* the `wrap_keys` store, comment at 1590-1593); unwrap path `keyStorageService.js:209-244` (`_getOrCreateWrapKey` loads the wrap key with NO check on `AuthService.currentUser`, Supabase session, or password).
- **Verification:** Confirmed by tracing the full logout path. The only two `auth:signout` listeners are `passwordManager.js:168` (clears sessionStorage temp password only) and `header.js:826` (UI refresh) — neither touches key storage (repo-wide grep confirms). `deleteDatabase()`/`_clearAllLocalState()` are wired ONLY into the account-DELETE flow (`messaging_app/settings/controllers/settingsController.js:520,551-566`), reached after a confirmed server-side delete — NOT into logout. `clearAll()` is called only from key (re)generation/restore in `keyManagementService.js` (186/355/441/485/2488) and would be insufficient anyway because it keeps `wrap_keys`.
- **Repro:** (1) victim logs in, exchanges messages (populates `identity_keys`, `ratchet_states`, `decrypted_message_keys`, `prekey_secrets`, `wrap_keys` in IndexedDB `MoneyTrackerEncryption`), clicks Sign Out → Supabase session gone, redirected to auth.html. (2) Attacker opens the same fixed GitHub Pages origin, devtools console: `await window.KeyStorageService.initialize(cfg); await window.KeyStorageService.getIdentityKeys('<victimUserId>')` returns the raw identity secret bytes (wrap key auto-loaded, no session needed); `getDecryptedMessageKey(msgId)` returns every archived message key; `getRatchetState(convId)` returns the live ratchet. `victimUserId` recoverable from residual app state / IndexedDB record keys. Non-extractability of the wrap key is irrelevant — `crypto.subtle.decrypt` runs in-origin.
- **Impact:** full recovery of the long-term X25519/Ed25519 identity SECRET (peer impersonation + decryption of intercepted/future inbound), the complete decrypted-message-key archive (all historical plaintext), live ratchet state, prekey secrets, and the analogous budget secrets. A "logged out" device is indistinguishable from a logged-in one at the secret-at-rest layer.
- **Remediation:** In `signOut()` (before the redirect at `authService.js:798`) `await window.KeyStorageService?.deleteDatabase()` (preferred — also drops `wrap_keys`, which `clearAll` keeps) + `window.BudgetKeyService?.clearCache()`, wrapped in try/catch so a failure still redirects. Do NOT rely on a fire-and-forget `auth:signout` listener — the redirect can race it; call deletion directly and await it. Do NOT use `clearAll()` alone (it preserves the usable AES-GCM wrap key, `keyStorageService.js:1590-1593`). If fast re-login / multi-device pairing must retain the wrapped identity, gate that behind an explicit "remember this device" opt-in and STILL drop `decrypted_message_keys` + `ratchet_states` + `prekey_secrets` on every logout so the plaintext-equivalent archive and forward-secrecy state never survive sign-out.

### MEDIUM — none.

### LOW

#### L-NEW-1: `field_locks` RLS is `USING(true)` — cross-user edit-activity metadata oracle
- **Attacker model:** any malicious authenticated user (network).
- **File:line:** `money_tracker/database/setup/fresh-install-complete.sql:1149-1150` (`field_locks_select_all FOR SELECT USING (true)`), `GRANT SELECT … TO authenticated` at 1158.
- **Repro:** `GET /rest/v1/field_locks?select=*` returns ALL field-lock rows for ALL users — `table_name, record_id, field_path, locked_by` (user UUID), `locked_at`, `expires_at` — including budgets the caller has no share for.
- **Impact:** cross-user metadata leak: who is editing which record/field and when, plus `locked_by` user-UUID enumeration. No financial values (those are E2E encrypted) and `record_id`/`field_path` are opaque without budget context, so sensitivity is low — but it is broader than necessary and a free recon/presence oracle for the red team. (Mirrors the M-2 OPK enumeration class, lower severity.)
- **Remediation:** scope the SELECT to locks the caller can legitimately see — rows they own (`auth.uid() = locked_by`) OR on records under an accepted `data_shares` to the caller. The concurrency UX only needs locks on records the caller can actually edit.

#### L-NEW-2 (hygiene): stale password-length floor of 6 in the legacy validator
- **File:line:** `auth_db/shared/config/constants.js:68` (`MIN_PASSWORD_LENGTH: 6`), `auth_db/shared/utils/validators.js:45-46`.
- **Impact:** none on the authoritative path today (signup/change go through `enforcePasswordStrength`, min 12 — H-2). Risk is a future regression if any flow re-wires to `Validators.password`.
- **Remediation:** raise `MIN_PASSWORD_LENGTH` to 12 to keep the floor consistent everywhere.

---

## 4. UNCERTAIN ITEMS

- **U-1 (operational, needs runtime confirmation — NOT a security bypass): Stripe webhook uses synchronous `constructEvent` on Deno.** `payments_app/supabase/functions/stripe-webhook/index.ts:129` calls `stripe.webhooks.constructEvent(...)` with `Stripe@14.21.0?target=deno`. On Deno, signature verification typically requires the async `await stripe.webhooks.constructEventAsync(...)` because SubtleCrypto is async; the sync variant can throw at runtime. If so, EVERY webhook would fail signature verification → fail CLOSED (no provisioning), so this is an **availability/reliability** concern, NOT an authentication bypass (it cannot forge or skip verification). I could not confirm whether the deployed SDK/runtime accepts the sync call without executing it. Recommend confirming webhook delivery succeeds in staging; if not, switch to `constructEventAsync`. Flagged as uncertain because it depends on runtime behavior I can't observe statically.

No other uncertain items — the rest of the surface resolved to either confirmed-closed or the findings above.

---

## 5. RESIDUAL KNOWN-ACCEPTABLE ITEMS

- **Recovery key must revert to 32 bytes** — accepted; a property of the recovery-key derivation/format, not a defect.
- **Metadata is inherent to the architecture** — conversation participant identities (both user UUIDs are visible to each participant and to the server), message timing, coarse attachment size buckets, and the email→userId existence signal (rate-limited, W3-3) are unavoidable given a server-mediated relay model. Content, attachment name/type/exact-size, and budget values remain encrypted. Accepted as architectural, not a finding.
- **`frame-ancestors` needs a real HTTP header** — GitHub Pages cannot emit response headers, so the clickjacking defense (`frame-ancestors`) cannot be enforced via `<meta>` CSP. Accepted as a hosting limitation; would require a real header (e.g. behind a CDN/edge) to fully close.
- **Public key tables are world-readable by design** — `identity_keys`, `public_key_history`, `prekeys` (`USING(true)` SELECT) expose only PUBLIC keys, required for X3DH; secrets stay client-side. Accepted.

---

## RETURN SUMMARY

**Verdict: GO** for the external pentest. The crypto core and server-side authZ are strong; all wave 1–3 fixes re-verified are confirmed closed; no new CRITICAL and no new network-exploitable HIGH.

**Counts by severity (NEW findings):** CRITICAL 0 · HIGH 1 · MEDIUM 0 · LOW 2 · UNCERTAIN 1.

**Top NEW must-fix:**
1. **HIGH — H-NEW-1 (carried, confirmed):** logout does not wipe the E2E key IndexedDB / wrap key — call `KeyStorageService.deleteDatabase()` (and await it) inside `signOut()` (`authService.js:710-802`). Local-access only; fix before launch, does not block the pentest.
2. **LOW — L-NEW-1:** scope `field_locks` SELECT (`fresh-install-complete.sql:1149-1150`) to own/shared records instead of `USING(true)`.
3. **LOW — L-NEW-2:** raise the stale `MIN_PASSWORD_LENGTH = 6` (`constants.js:68`) to 12.
