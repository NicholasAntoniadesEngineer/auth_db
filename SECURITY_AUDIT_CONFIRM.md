# Convergence-Confirmation Security Audit

**Date:** 2026-06-23
**Scope:** auth_db (identity + E2E crypto + DB service + entitlement RPCs), secure_db (messaging schema/RLS),
payments_app (Stripe edge fns), messaging_app, money_tracker (budget + budget-E2E). Shared Supabase.
**Attacker model:** malicious authed user, malicious peer, MITM, AND a curious/compromised server (zero-knowledge must hold).
**Method:** READ-ONLY convergence pass over the committed state
(auth_db `70cea26`, secure_db `61c6b39`, payments_app `c2cbb34`, messaging_app `009968e`, money_tracker `df498e7`).

---

## 1. Is the loop QUIET?

**YES.** Zero new CRITICAL and zero new HIGH. Every prior CRITICAL/HIGH/MEDIUM/LOW finding is fixed,
committed, and — on re-examination against the live code — complete and not bypassable. No new
CRITICAL/HIGH surfaced by this lens. The remaining notes below are LOW / informational hardening only.

---

## 2. Fix-verification — all closed?

All verified against the actual committed source (file:line), not just the changelog.

| ID | Status | Evidence |
|----|--------|----------|
| **C-1** data_shares RLS (WITH CHECK + column GRANT + DEFINER RPC) | CLOSED | `money_tracker/database/setup/apply-data-shares-with-check.sql:48-114` — `REVOKE UPDATE ... ; GRANT UPDATE (status, wrap_*, dek_version, updated_at)` excludes `can_edit`/`share_all_data`/owner/recipient/scope, so a recipient PATCH of grant flags fails the column-privilege check (42501) BEFORE RLS. Recipient `WITH CHECK` pins `status IN ('accepted','rejected')`. Flag mutation only via owner-asserting `update_share_grants()` DEFINER RPC. |
| **H-1** responder X3DH IK pin | CLOSED | `auth_db/encryption/services/keyManagementService.js:1303-1374` (`_resolveResponderPeerIdentity`): pinned X25519 IK must byte-equal wire `ikPub` (line 1332); bound-pair + published cross-check; atomic co-pin; `_getPinnedPeerKey` throws on divergence. AD path mirrored at 1775-1808. |
| **H-2** enforcePasswordStrength(min12) | CLOSED | `shared/utils/validators.js:45` (MIN 12); `passwordCryptoService.js:364` enforce throws; `keyBackupService.js:85-86` calls it before backup. Backup KDF = PBKDF2-SHA256 600k + AES-256-GCM (`passwordCryptoService.js:10,35,71`). |
| **H-3** server is_premium_active + trial cron (messaging FREE, sharing Premium) | CLOSED | `money_tracker/database/setup/apply-premium-sharing-gate.sql:44-110` — DEFINER `is_premium_active()`; `data_shares_insert_as_owner` gated on it; `expire_overdue_trials()` + hourly pg_cron. `secure_db/.../complete-setup.sql:418-437` messages INSERT has NO premium check (free). |
| **H-4** authenticated context-bound DEK seal | CLOSED | `money_tracker/shared/services/budgetCryptoService.js:321-460` — static-static (owner auth) + ephemeral-static DH, context-bound HKDF (owner/recipient/dekVersion/shareId); unseal refuses legacy null `wrap_owner_ik` (411) and requires bound owner IK == pinned key (425). Wiring `databaseService.js:3007-3108` resolves recipient/owner keys through the TOFU chokepoint (`_getRecipientIdentityPublicKey:2966-2985` → `_getPinnedPeerKey`, fail-closed). |
| **H-5** CSP unsafe-inline removed | CLOSED | `messenger.html:13`, `money_tracker/index.html:8`, `monthlyBudget.html:11` — `script-src 'self' https://js.stripe.com` (no `unsafe-inline`); scoped `connect-src`; `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`. (`style-src 'unsafe-inline'` retained — documented, low impact w/o script exec.) |
| **H-6** attachment metadata encrypted | CLOSED | `secure_db/sql/apply-attachment-metadata-encryption.sql` (legacy cols nullable, `encrypted_metadata`/`metadata_nonce`/`file_size_bucket` added); `messaging_app/.../attachmentService.js:335-352` seals name/MIME/exact-size under the invariant KEK bound to storage_path; server sees only a coarse bucket. |
| **W2-1** att-id coerced at render | CLOSED | `attachmentService.js:808-814` coerces `Number(att.id)` and drops non-positive-int rows. |
| **W3-1** realtime requires ciphertext | CLOSED | `messages.encrypted_content TEXT NOT NULL` + column-scoped UPDATE grant. |
| **W3-2** ratchet-invariant attachment key | CLOSED | `doubleRatchetService.js:62-76,253,273` AK0 from invariant SK; `attachmentService.js:453-538` bound KEK + legacy fallback. |
| **W3-3** user-lookup resolver + rate-limit | CLOSED | `auth_db/backend/edge-functions/user-lookup.ts:101-209` — JWT-gated, RPC `resolve_user_id_by_email` per-caller rate-limit, uniform 200 `{userId|null}`. |
| **M-2** OPK token-buckets | CLOSED | `apply-opk-claim-rate-limit.sql:67-144` — per-pair ≤10/h, per-target ≤60/h; `select_own` closes the enumeration oracle. |
| **M-3** webhook completion-idempotency | CLOSED | `payments_app/.../stripe-webhook.ts:146-374` — claim-on-completion; inFlight reprocess; handler failure → 500 so Stripe retries. |
| **M-4** plan validation | CLOSED | `stripe-webhook.ts:690-798` positive-int + true-downgrade (strictly cheaper) check. |
| **M-5** notification relationship | CLOSED | `money_tracker/database/setup/apply-notification-relationship-check.sql`. |
| **F-1** logout wipes key IndexedDB | CLOSED | `authService.js:794-802` AWAITS `KeyStorageService.deleteDatabase()` (drops `wrap_keys`) before redirect; restorable from password backup. Header (`header.js:725`) lets `signOut()` own the redirect after the awaited wipe. |
| **LOW** password min 6→12 | CLOSED | `validators.js:45`. |
| Entitlement self-grant (PAY-3/RLS-03) | CLOSED | `payments_app/backend/sql/apply-entitlement-lockdown.sql` — DEFINER RPCs + staged REVOKE INSERT/UPDATE on `subscriptions`. |

**Incomplete / bypassable:** none found.

---

## 3. New findings

### CRITICAL: none
### HIGH: none

### LOW / informational (hardening, not exploitable against the stated model)

- **L-1 (LOW) — `getEmailById` retains a user-id existence oracle.**
  `user-lookup.ts:214-268` still returns 404-vs-200 keyed on user-id and is not rate-limited (unlike
  `findByEmail`). Impact is low: user-ids are random UUIDs (not enumerable) and the caller must already
  hold a valid id; it is a reverse-lookup convenience. Not new exploit surface, but for parity consider
  a uniform `{email|null}` 200 and the same per-caller throttle.

- **L-2 (LOW/INFO) — meta-tag `frame-ancestors` is inert.**
  CSP delivered via `<meta>` cannot enforce `frame-ancestors` (spec: ignored in meta). GitHub Pages
  cannot set an `X-Frame-Options` / CSP response header, so clickjacking framing is not hard-blocked.
  `object-src 'none'` + `base-uri 'self'` + `form-action 'self'` are in force. Pre-existing infra
  constraint, low impact for this app class; documented for the red team's awareness.

- **L-3 (INFO) — backup KDF migration TODO.**
  Identity backup uses PBKDF2-SHA256 @ 600k (current OWASP) + AES-256-GCM — acceptable. The in-code
  `TODO(H-2)` to move to Argon2id is a future hardening, not a present weakness.

- **L-4 (INFO) — `style-src 'unsafe-inline'` retained.**
  Deliberate (inline `style=` attributes). With `script-src` locked down there is no script-execution
  path; impact is cosmetic-only injection at most.

---

## 4. Final go / no-go

**GO.** The loop is QUIET. Against the full attacker model — including a curious/compromised server —
the zero-knowledge boundary holds: the server never sees budget DEKs, message plaintext, file bytes,
filenames/MIME/exact-size, or unwrapped identity secrets; all peer-key trust is anchored by a
fail-closed TOFU pin; all cross-user authorization is enforced server-side by RLS + column grants +
SECURITY DEFINER RPCs (not client checks). No new CRITICAL or HIGH. The 4 LOW/INFO items are optional
hardening and do not block the external red team.
