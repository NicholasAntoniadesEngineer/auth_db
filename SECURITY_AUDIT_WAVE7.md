# Security Audit — Wave 7

**Date:** 2026-06-24
**Auditor lens (NEW angle):** Cross-time / cross-repo **protocol state-machine & invariant** review —
TOCTOU, replay/reorder, consume-once, key-rotation grace windows, entitlement at-creation-vs-at-access,
webhook idempotency, and account-lifecycle cleanup. The deliberate goal was to find what a
*single-snapshot* lens misses: bugs that only appear when you trace a value across **time** (trial →
expiry, claim → reuse, bootstrap → reload, claim-row → redelivery) or across **repos** (auth_db crypto ↔
secure_db RLS ↔ money_tracker shares ↔ payments_app Stripe).

**State audited (committed HEADs):** auth_db `e115eac`, secure_db `35eae4b`, payments_app `8ba505d`,
messaging_app `882c1bc`, money_tracker `fddd476`. READ-ONLY.

---

## 1. VERDICT

**QUIET — zero new CRITICAL, zero new HIGH.**

The cross-time / cross-repo state machines are sound. Every invariant I traced across time held:
the Double-Ratchet skip/DH-ratchet ordering, X3DH OPK consume-once (DB-atomic `FOR UPDATE SKIP LOCKED`
+ local secret deletion), SPK rotation grace window, TOFU pin fail-closed on both initiator and
responder paths (including reload-safe AD reconstruction), Stripe webhook **completion-based**
idempotency, downgrade-target re-validation at both write and provision time, and server-authoritative
checkout pricing. Account deletion cascades all key/prekey/pairing material. No exploitable finding at
any severity that is both NEW and not already accepted-and-documented.

One **LOW/informational** doc-accuracy nit and several explicitly-accepted product/residual items are
listed below for completeness. None are must-fix.

---

## 2. NEW FINDINGS BY SEVERITY

### CRITICAL — none
### HIGH — none
### MEDIUM — none

### LOW

**L7-1 (LOW, informational / doc-accuracy):** `delete-account` deletion-contract comment is stale.
- **Attacker model:** none (documentation only — no exploit).
- **file:line:** `auth_db/backend/edge-functions/delete-account.ts:26-30`.
- **Detail:** The header comment enumerating the tables cleaned by `admin.deleteUser`'s FK cascade
  lists `identity_keys, public_key_history, paired_devices, … identity_key_backups` but **omits
  `prekeys`, `one_time_prekeys`, `opk_claim_audit`, `user_lookup_audit`, and `pairing_requests`.**
- **Verification that this is NOT a vuln:** I confirmed every one of those tables carries
  `user_id … REFERENCES auth.users(id) ON DELETE CASCADE` (auth_db/backend/sql/complete-setup.sql lines
  202, 313, 371, 434-435, 582). So the cascade *does* physically remove a deleted user's published SPK
  bundle and OPK pool — a peer cannot claim a ghost user's prekeys post-deletion, and the curious server
  retains no orphaned key material. The defect is purely that the comment under-states what is cleaned.
- **Impact:** none (cosmetic; could mislead a future maintainer into adding a redundant manual delete).
- **Remediation:** add the five tables to the comment's cascade list. No code change.

---

## 3. PRIOR FIXES RE-EXAMINED FOR INCOMPLETE / BYPASSABLE — all hold

I re-attacked the prior fixes most exposed to a cross-time bypass:

- **H-1 (responder X3DH IK pin) — HOLDS, incl. the reload path.** The responder authenticates the
  initiator's X25519 IK *before any DH* and atomically co-pins (IK, IK_sig)
  (`keyManagementService.js:1303-1374`). Critically, the **archive/history re-render** path reconstructs
  AD deterministically via `_reconstructAD` → `_resolveADInitiatorKey` (1723-1808), which re-asserts the
  pinned IK match read-only — so a reload between "responder ratchet persisted" and "msg0 archived" cannot
  be turned into an AD-forgery or a permanently-undecryptable msg0. No bypass.
- **H-3 (server entitlement: messaging FREE, sharing Premium) — HOLDS.** The Premium gate is the
  `is_premium_active()` SECURITY-DEFINER predicate on the **data_shares owner-INSERT**
  (money_tracker/database/setup/fresh-install-complete.sql:957-962), fail-closed if the subscriptions
  schema is absent, and expired trials evaluate to NOT-premium (line 841-860). A tampered client / direct
  PostgREST call cannot self-grant or create a share post-expiry. (See §5 for the *intentional* "old
  shares keep working after downgrade" decision — that is accepted, not a bypass.)
- **H-4 (authenticated context-bound DEK seal) / W3-2 (ratchet-invariant attachment key) — HOLD.** The
  attachment KEK is rooted in the **invariant** `AK0` (minted once from X3DH `SK`, never advances) with
  conversation+path bound into HKDF info (`keyManagementService.js:1996-2028`); the legacy RK-rooted path
  is read-only back-compat. A DH-ratchet step can no longer strand a previously-wrapped attachment.
- **M-3 (webhook completion-idempotency) — HOLDS.** Claim-on-INSERT, `processed` flips to true ONLY on
  handler success, failures return 500 to force Stripe retry, redelivery of an in-flight (claimed but
  unfinished) event **re-runs** the idempotent handler (stripe-webhook.ts:146-236, 301-375). The old
  "drop a failed cancellation → user keeps Premium forever" class is closed.
- **M-4 (downgrade plan validation) — HOLDS, both ends.** Validated on write
  (update-subscription.ts:104-109,157-189) *and* re-validated as a genuine strictly-cheaper active plan at
  provision time in the webhook (stripe-webhook.ts:686-798). A metadata-smuggled escalation falls through
  to plain cancellation.
- **OPK consume-once + rate-limit (M-2) — HOLDS.** `claim_one_time_prekey` pops with
  `FOR UPDATE SKIP LOCKED`, marks consumed, audit-rows the claim, and enforces per-pair (10/h) and
  per-target (60/h) buckets, counting only successful consumptions (complete-setup.sql:471-562). Responder
  deletes its OPK secret + published row after use (keyManagementService.js:1131-1139). No reuse, no
  drain, no SPK-fallback budget burn.
- **W3-3 + L-1 (lookup oracle + rate limit) — HOLDS.** Forward and reverse resolvers share one per-caller
  budget (counting hits AND misses), are service_role-only, and return generic errors
  (complete-setup.sql:604-714).

---

## 4. UNCERTAIN ITEMS

**None.** Every line of inquiry resolved decisively to either "safe" or "accepted product decision."
I specifically chased and *closed* (i.e., proved safe) the following candidates rather than leaving them
open:

- **Pairing brute-force `attempts` TOCTOU** (client read-modify-write of `attempts`,
  devicePairingService.js:134; GRANT UPDATE(attempts), complete-setup.sql:229). NOT exploitable: the
  pairing row is RLS-scoped to the owner and only the owner can redeem it, so the only party able to
  reset `attempts` is the account owner — who already holds both the session and the code. The limit is
  defense-in-depth against a session-but-not-code attacker, who in this system would already have full
  account access. Combined with an 80-bit code + 5-min expiry, no realistic brute force exists.
- **X3DH bootstrap-message replant to a different `conversationId`** (conversationId is server-controlled
  and is NOT bound into AD = IK_a‖IK_b). A curious server could replay a genuine Alice→Bob bootstrap under
  a fresh conversationId; Bob would derive a ratchet from the same preamble. Impact is nil: it is still the
  same two authentic identities (AD + TOFU pins bind them), no impersonation, no key disclosure, and the
  server can already drop/reorder. Not a confidentiality/integrity break.
- **friends UPDATE policy locking after accept** (secure_db/complete-setup.sql:128-131, USING status =
  'pending'): a functional limitation (no one can re-transition an accepted row via this policy), not a
  security gap — blocking is handled by the separate blocked_users table + is_blocked() server gate.

---

## 5. RESIDUAL / KNOWN-ACCEPTED (carried, NOT new)

- **Share persistence after Premium lapse (ACCEPTED PRODUCT DECISION).** Only the data_shares
  **owner-INSERT** is Premium-gated; **consumption** (recipient SELECT/UPDATE of the owner's `user_months`)
  is gated solely on `status='accepted'` (money_tracker/database/setup/fresh-install-complete.sql:953-1051).
  Consequence: a share created during a trial keeps working after the trial expires / the owner downgrades.
  This is explicitly documented as intentional at lines 953-956 ("only the OWNER INSERT is gated"). It is a
  business-logic choice, not a security-boundary violation — the malicious-authed-user cannot create NEW
  shares without Premium, and an existing share never crosses a confidentiality boundary the two parties
  did not already consent to. Recorded as residual-accepted; flag for product if the monetization model
  ever requires at-access re-checking.
- **L-3: backup KDF is PBKDF2 (not Argon2id).** Migration plan documented in
  PasswordCryptoService.enforcePasswordStrength + keyBackupService.js:81-87. Mitigated today by H-2
  (min-12 password) + 600k iterations. Accepted/known.
- **Simultaneous multi-device is OUT OF SCOPE** (sequential pairing only; two live devices on one identity
  desync the single ratchet). Documented at keyManagementService.js:2230-2237. Accepted/known.
- **pg_cron reapers are operator-gated.** If pg_cron is absent, RLS still HIDES expired
  pairing_requests/audit rows but at-rest ciphertext/metadata is not physically deleted until enabled
  (complete-setup.sql:729-766). Accepted/known; load-bearing only for at-rest hygiene, not access control.

---

## RETURN SUMMARY

- **QUIET:** yes
- **Counts by severity:** CRITICAL 0 · HIGH 0 · MEDIUM 0 · LOW 1 (L7-1, doc-accuracy only) · UNCERTAIN 0
- **Top NEW must-fix:** none
