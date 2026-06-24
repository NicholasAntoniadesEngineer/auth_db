# Security Audit — Wave 5 (final pre-pentest sweep)

Date: 2026-06-24
Scope: auth_db, secure_db, payments_app, messaging_app, money_tracker (all at latest committed HEAD)
Reviewer: offensive-security engineer (read-only)
Attacker model: malicious authed user, malicious peer, MITM, AND a curious/compromised server (zero-knowledge must hold vs. the server).

Latest commits reviewed:
- auth_db `5a9d3e0`, secure_db `35eae4b`/`61c6b39`, payments_app `b361221`, messaging_app `777e3ae`, money_tracker `4dc0c9f`.

---

## 1. Overall verdict

**The platform is READY for the external pentest.** The loop is still **QUIET — zero new CRITICAL and zero new HIGH.**

This wave deliberately went DEEPER than prior passes and concentrated on (a) the NEWEST committed code and (b) angles earlier passes may have under-weighted: the attachment metadata bound→legacy key fallback (oracle/confusion risk), the budget-share DEK seal KDF construction (DH-leg combination), the X3DH responder identity-pinning path (swapped-IK), server-authoritative entitlement lockdown (self-grant Premium), the Stripe webhook (signature + idempotency + metadata-driven re-provisioning), and every peer-controlled render sink (XSS on decrypted filename/message). All chains hold.

Every prior fix that was spot-checked (C-1, H-1, H-3, H-4, H-6, W3-1/2, M-3, M-4, SDB-01/04, SM-05/28/30, F-1) is intact and not bypassable.

---

## 2. NEW findings by severity

**None.**

No new CRITICAL, HIGH, MEDIUM, or LOW issues were identified in this wave.

---

## 3. Prior fixes — re-verification (all hold)

| Ref | Area | Verified at | Result |
|-----|------|-------------|--------|
| C-1 | `data_shares` write lockdown | money_tracker fresh-install-complete.sql:957-1134 | HOLDS. Owner-INSERT Premium-gated via `is_premium_active`; recipient UPDATE restricted to `status` via column GRANT (42501 before RLS); grant-flag mutation only via `update_share_grants` DEFINER RPC (re-asserts `owner_user_id = auth.uid()`). The new COALESCE on year/month (`4dc0c9f`) only prevents a NULL-clobber on the owner's own scope; it cannot widen scope to another user or change ownership — owner-gated and bounded. |
| H-1 | X3DH responder IK pin | keyManagementService.js `_resolveResponderPeerIdentity` 1303-1374 | HOLDS. Pinned X25519 IK must byte-match the wire `ikPub` before any DH; bound-pair check rejects a pinned IK_sig with no/mismatched X25519 pin; published-key cross-check via TOFU chokepoint; atomic co-pin. A swapped-IK-with-genuine-IK_sig bundle is rejected (no SK, no ratchet). |
| H-3 | server-authoritative Premium | payments complete-setup.sql:520-562; money_tracker:841-962 | HOLDS. `REVOKE INSERT,UPDATE ON subscriptions FROM authenticated` (line 520) routes all writes through DEFINER RPCs (`start_trial`/`downgrade_to_free`/`ensure_subscription`). `is_premium_active` computes entitlement from (status × plan) and denies an expired trial even before the cron sweep. Messaging is FREE (no gate on messages-INSERT); sharing is Premium (gate on `data_shares` owner-INSERT). No self-grant-Premium path. |
| H-4 | context-bound DEK seal | budgetCryptoService.js `sealDEKToRecipient`/`unsealDEK` 321-460; databaseService.js 3007-3108 | HOLDS. Authenticated 2-DH box (static-static owner auth + ephemeral-static freshness); `_deriveSealKey` concatenates both fixed-length DH legs + domain-separated, context-bound HKDF info (ownerIK, recipientIK, ownerId, recipientId, dekVersion, shareId). Unseal rebuilds context from independently-known values and requires `wrap_owner_ik == pinned owner key`; legacy/anonymous seals fail closed. A curious server cannot forge or transplant a seal. |
| H-6 | encrypted attachment metadata | attachmentService.js 335-442; secure_db:538-553 | HOLDS. name/MIME/exact-size sealed under the invariant context-bound attachment KEK; only a coarse `file_size_bucket` is plaintext. The new bound→legacy decrypt fallback (`777e3ae`) only tries a SECOND key the recipient derives from its OWN ratchet state on AEAD-auth failure — no plaintext, no key material, and no decision leaks to the server, so it is not an oracle. |
| W3-2 | ratchet-invariant attachment KEK (AK0) | keyManagementService.js `getSessionKey` 1996-2028; keyStorageService.js AK0 serialize 969-1007 | HOLDS. KEK derived from invariant AK0 + per-attachment path; survives DH-ratchet steps; legacy RK path retained read-only for pre-W3-2 rows. |
| M-3 | webhook completion-idempotency | stripe-webhook.ts 146-404 | HOLDS. Stripe signature verified (`constructEvent` on raw body) before any work; claim-on-insert with completion flag; handler failure returns 500 for retry instead of swallowing into 200. No unauthenticated write path. |
| M-4 | downgrade plan validation | update-subscription.ts 95-189; stripe-webhook.ts 686-798 | HOLDS. `validateDowngradeTarget` requires a positive-int, active, strictly-cheaper plan; re-validated again at provisioning time (defense in depth). |
| SDB-01/04 | messages recipient binding + read-receipt scope | secure_db:424-466 | HOLDS. INSERT binds `recipient_id` to the conversation counterparty + block check; UPDATE column-scoped to `read`/`read_at` and recipient-only; DELETE sender-only. |
| SM-05/30 | attachment + storage RLS | secure_db:565-672 | HOLDS. Rows immutable post-insert (no UPDATE policy/grant); download-count via DEFINER RPC scoped to participants; storage objects scoped by conversation-id path segment. |
| W2-1 / XSS | peer-controlled render sinks | messengerController.js 1078-1181, `_escapeHtml` 1260 | HOLDS. Decrypted (peer-controlled) message content, sender email, and attachment filename all pass through a genuine textContent→innerHTML escaper; ids Number-coerced; file icon from a fixed allowlist, never raw MIME. |
| F-1 | logout key wipe (multi-tab no-hang) | keyStorageService.js + authService.js (`5a9d3e0`) | HOLDS (functional fix; resolves-on-onblocked + Promise.race timeout). No security regression: the wipe still deletes the key DB; no-lockout restore preserved. |

---

## 4. UNCERTAIN items

**None.** Every chain examined this wave resolved to a definite "holds." No items require follow-up datasheet/API verification.

---

## 5. Residual / known-accepted (unchanged from prior waves)

- **Recovery-key length at 20 (testing).** Intentional; flip-to-32 is gated by `prod_readiness_check.js`. Accepted for the test phase, must be flipped for production. (Pre-existing, documented.)
- **Sequential (not simultaneous) multi-device pairing.** Documented limitation in keyStorageService.js §6: a single active ratchet per identity; true Sesame-style multi-device is out of scope. Not a vulnerability — a feature boundary.
- **`is_premium_active` correctness depends on the trial-expiry cron OR the predicate's inline `trial_end > NOW()` check.** The predicate already denies expired trials even without pg_cron, so revenue/entitlement is protected regardless; the cron is housekeeping. Accepted.
- **Edge-function source duplicated** under `backend/edge-functions/` and `supabase/functions/` — verified byte-identical for the three security-relevant functions. Cosmetic dual-source; not a security issue.

---

## Conclusion

Wave 5 is QUIET. The hardening from waves 1–4 + capstone + functional sweep is intact and not bypassable, and the newest committed changes introduce no regressions. The platform's zero-knowledge posture against a curious/compromised server holds across messaging, attachments, and budget sharing; the server-authoritative entitlement and RLS surfaces are locked down; the X3DH/Double-Ratchet identity-binding rejects key substitution. **Green-light for the external red team.**
