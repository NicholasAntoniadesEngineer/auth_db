# Pre-Pentest Security Audit — Privacy-First E2E Platform

**Scope:** `auth_db` (identity + E2E crypto: X3DH / Double Ratchet / wrap-at-rest / pairing / recovery + shared DB service + entitlement RPCs), `secure_db` (messaging schema/RLS), `payments_app` (Stripe edge functions + entitlement), `messaging_app` (messenger client), `money_tracker` (budget client + client-side budget E2E). Shared Supabase (Postgres + RLS + Auth + Realtime + Storage + Edge Functions). Vanilla JS + `window.*` globals + GitHub Pages; TweetNaCl vendored; client keys in IndexedDB wrapped under a non-extractable WebCrypto AES-GCM key.

**Assessment type:** Adversarial pre-pentest hardening review (READ-ONLY). Each finding below was independently traced to source and an exploit was attempted; refutation attempts are recorded.

**Attacker models exercised:** malicious authenticated user, malicious peer, network MITM, and — critically for the zero-knowledge claim — a curious/compromised server (DB operator / service role). The zero-knowledge guarantee is held to the standard that it must survive the server itself.

**Date:** 2026-06-23

---

## 1. Executive Summary

### Overall posture verdict: **NOT READY** for a serious external pentest. One CRITICAL blocker and a cluster of HIGH crypto/entitlement/XSS issues must be fixed first.

The platform's *foundations* are strong in places — the payments edge functions, the messaging/identity RLS, OPK-claim RPC gating, and at-rest key wrapping are mostly well-built, and several controls were positively re-verified as holding (forged-webhook rejection, IDOR closure on portal/list/update, server-authoritative entitlement writes via REVOKE + DEFINER RPCs). The crypto is real Signal-style X3DH + Double Ratchet, not theatre.

However, the design has **one structural authorization hole that is a true cross-user read+write break (CRITICAL)** and a set of **HIGH-severity issues that defeat the two headline promises of the product**: end-to-end peer authentication (the responder X3DH bootstrap trusts an unpinned identity key), zero-knowledge against the server (the budget-DEK seal and the password-encrypted identity backup), and revenue integrity (client-only Premium/trial entitlement). The CSP relaxation (`script-src 'unsafe-inline'`) means any future injection becomes full key theft, and metadata privacy (filenames, ciphertext length, social graph) leaks more than an "E2E" claim implies.

A serious red team will find the CRITICAL and the HIGH crypto/entitlement issues quickly. These are not style; they are exploitable against the platform's own stated threat model.

### Must-fix-first blockers (gate the pentest)

1. **`data_shares` UPDATE policies lack `WITH CHECK` (CRITICAL)** — a share recipient self-escalates a read-only single-month share into full read+write of the owner's entire E2E budget. Cross-user read AND write. *(Finding C-1.)*
2. **Responder X3DH bootstrap trusts an unpinned, unsigned initiator X25519 IK (HIGH)** — peer impersonation breaks E2E authentication on the receive side; silently defeats safety-number verification. *(Finding H-1.)*
3. **Password-encrypted identity backup is offline-brute-forceable; strong-password policy defined but never called (HIGH)** — zero-knowledge break for any weak password against an at-rest/leaked DB. *(Finding H-2.)*
4. **Premium/trial entitlement enforced only client-side; no server gate on `messages` insert and no trial-expiry job (HIGH)** — permanent free Premium / entitlement bypass. *(Finding H-3.)*
5. **S7 budget-DEK seal: recipient pubkey unpinned + anonymous box with no sender auth/context binding (HIGH)** — curious server redirects or forges shared-budget DEKs, breaking zero-knowledge for shared budgets. *(Finding H-4.)*

The `RECOVERY_KEY_BYTES = 20` testing value and the missing strong-password enforcement must be confirmed reverted/enforced for prod (Section 5).

### Severity counts

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 6 |
| MEDIUM | 7 |
| LOW | 14 |
| UNCERTAIN (human review) | 1 |

---

## 2. Findings by Severity

> Cross-surface deduplication note: two independent audit passes (crypto-protocol and crypto-impl) reported the responder-X3DH-bootstrap defect and the safety-number gap. They describe the **same root cause** and are merged into **H-1** (root) and **M-1** (amplifier). The OPK-exhaustion observation appears as both a client-side downgrade note and a server-RPC drain; merged into **M-2**. The `field_locks` SELECT-`USING(true)` issue appears under both authz and metadata-privacy lenses; merged into **L-9**.

---

### CRITICAL

#### C-1 — `data_shares` recipient/owner UPDATE policies have no `WITH CHECK`: share recipient escalates a read-only, single-month share to full read+write of the owner's entire budget

- **Attacker model:** malicious authenticated user who is the named `shared_with_user_id` of any `data_shares` row in `status='pending'` (e.g. the recipient of a legitimate read-only single-month share, before they accept it).
- **File:line:** `money_tracker/database/setup/fresh-install-complete.sql:847-851` (`data_shares_update_as_owner` / `data_shares_update_as_recipient`); read gate `:857-870`; write gate `:881-907`; table-wide UPDATE grant `:909`. Per-user DEK note `:281`. Confirmed un-patched by `apply-rls-hardening.sql` (which fixed friends/user_months/etc. but not these policies).
- **Exploit (repro):**
  1. Owner V shares ONE month read-only → row `{owner=V, shared_with=A, status='pending', share_all_data=false, can_edit=false, year=2026, month=1}` with `wrapped_dek` sealed to A (note: the DEK is a single **per-user** key that decrypts *every* budget blob).
  2. While the row is still `pending`, A escalates the columns WITHOUT touching status: `PATCH /rest/v1/data_shares?id=eq.<id>` body `{"can_edit":true,"share_all_data":true}`. The recipient policy's `USING` matches (old row is `pending`); PostgreSQL's implicit `WITH CHECK` (defaults to `USING` when omitted) still sees `status='pending'` and passes; the table-wide UPDATE grant permits writing those columns. Row becomes `{pending, can_edit=true, share_all_data=true}`.
  3. A accepts normally via the app's `update_share_status` RPC → `{accepted, can_edit=true, share_all_data=true}`.
  4. `user_months_select_shared` now returns ALL of V's months; A decrypts every one with the per-user DEK already unsealed from the legit share.
  5. `user_months_update_shared` now lets A `PATCH /rest/v1/user_months?user_id=eq.<V>` body `{"enc_payload":"...","enc_nonce":"..."}` to overwrite/destroy every month's encrypted blob.
- **Impact:** Cross-user **read** of the owner's entire budget history AND cross-user **write** (overwrite/corruption of every month's ciphertext; owner can no longer decrypt rows A rewrites). Defeats the least-privilege intent of the sharing model.
- **Exploitability:** High. Raw HTTP `PATCH` via the public PostgREST endpoint with the attacker's own JWT; no special privilege beyond being a pending recipient.
- **Correction to the originally-filed repro (important for the tester):** the single-PATCH form `{status:'accepted', can_edit:true, share_all_data:true}` does **NOT** work — Postgres uses the policy's `USING` as the implicit `WITH CHECK`, so flipping `status` to `accepted` in the same statement fails. The working path is the **two-step pending-window escalation then normal accept** shown above. The hole (missing `WITH CHECK` + table-wide grant) is real either way; only the ordering differs.
- **Residual dependency:** the legitimate accept goes through a SECURITY DEFINER `update_share_status(p_share_id,p_new_status,p_user_id)` RPC (`databaseService.js:4565-4577`) whose body is deployed out-of-repo. The attack assumes it sets only `status`. If that RPC also re-normalizes `can_edit`/`share_all_data` on accept, the **write**-escalation is blocked but the **read**-escalation (escalate-while-pending, then accept, then read all months) still stands. The finding holds at the RLS layer regardless — see UNCERTAIN note U-2 in Section 3 to confirm the RPC body.
- **Remediation:** Add `WITH CHECK` to both policies. Recipient policy: `USING (auth.uid()=shared_with_user_id AND status='pending')` with a `WITH CHECK` that pins `can_edit`, `share_all_data`, `owner_user_id`, `year`, `month` to their existing row values and only permits `status` to move to `accepted`/`rejected`. Simplest robust fix: **REVOKE table-wide UPDATE** and `GRANT UPDATE (status)` only to `authenticated` for the recipient path; route owner mutation of `can_edit`/`share_all_data` through a SECURITY DEFINER RPC (mirroring `start_trial`). Add `WITH CHECK (auth.uid()=owner_user_id)` to the owner policy to stop an owner reassigning `owner_user_id`. Add a regression test: a recipient PATCH that changes `can_edit`/`share_all_data` must be rejected.

---

### HIGH

#### H-1 — Responder X3DH bootstrap binds the session to an unsigned, unpinned initiator X25519 IK: peer impersonation breaks E2E authentication on the receive side

*(Merged: this is the same defect independently confirmed by the crypto-protocol and crypto-impl passes.)*

- **Attacker model:** compromised/curious server (it controls the plaintext message columns and can plant a bootstrap row); a malicious authenticated user who can insert a `messages` row with a chosen `sender_id` (RLS permitting); MITM on the bootstrap.
- **File:line:** responder branch of `establishSession` — `auth_db/encryption/services/keyManagementService.js:1078-1133` (only `_pinPeerSignKey(otherUserId, inboundPreamble.ikSignPub)` at `:1084-1086`; `inboundPreamble.ikPub` passed raw into `deriveResponderRoot` at `:1104-1113`). Consumed raw at `x3dhService.js:261`. AD reconstructed from the same attacker value at `keyManagementService.js:1600-1618`. Preamble origin (plaintext columns) `messaging_app/messaging/services/messagingService.js:83-91`; `senderId = msg.sender_id` at `:472`.
- **Exploit (repro):**
  1. Attacker generates an X25519 identity keypair and self-derives the matching Ed25519 IK_sig (IK_sig = `signKeyPairFromSeed(HKDF(X25519 secret, info='MoneyTracker:IK_sign:v1', salt=X25519 pub))` — `keyManagementService.js:784-816`; the attacker holds the X25519 secret so it can produce a self-consistent IK_sig).
  2. Attacker fetches Bob's published prekey bundle and runs a standard initiator X3DH to obtain `{ekPub, spkId, opkId}` and SK.
  3. Server/attacker plants a first inbound message to Bob: `sender_id = Alice`, `x3dh_ik = ATTACKER ikPub`, `x3dh_ik_sign = ATTACKER ikSignPub`, `x3dh_ek = ATTACKER ekPub`.
  4. Bob's `decryptMessage` finds no ratchet, sees the preamble, calls `establishSession` (responder). It TOFU-pins the **attacker's** Ed25519 as "Alice", and consumes the attacker's `ikPub` straight into `deriveResponderRoot` — **never** calling `_getPinnedPeerKey` for the X25519 IK. The AD = `preamble.ikPub || our_own_IK` is self-consistent with the forgery, so the AEAD check passes. Bob derives the same SK and renders the attacker's messages "from Alice".
- **Already-pinned variant (the serious one):** Even if Bob previously pinned Alice's real X25519 IK and Ed25519 IK_sig (pins are per-user, shared across conversations), the attacker crafts a NEW conversation bootstrap supplying Alice's **genuine** public Ed25519 IK_sig (passes `_pinPeerSignKey` unchanged) plus the **attacker's** X25519 `ikPub` (never checked). The pre-existing X25519 pin is silently bypassed because the responder branch never consults it.
- **Impact:** Full sender impersonation on the responder side, against a hostile server, even after the users verified safety numbers in a prior conversation. Breaks the E2E peer-authentication guarantee. `getSafetyNumber(Alice)` reads Alice's *real* published X25519 key (via `_getPinnedPeerKey`), which was never used to build the session — so out-of-band verification *matches* while the session is actually MITM'd, giving false assurance.
- **Exploitability:** High for the in-scope server/peer attacker. Not full account takeover (no key extraction from Bob) → HIGH, not CRITICAL.
- **Refutation attempts that failed:** (a) "an existing X25519 pin blocks it" — the responder path never reads the pin. (b) "the Ed25519 pin blocks it" — the attacker supplies Alice's genuine IK_sig and swaps only the unchecked X25519 IK. (c) "AD/AEAD catches the tamper" — AD is built from the same attacker `ikPub`. (d) "the SPK signature saves it" — that is the initiator's check; the responder trusts its own SPK and never ties the preamble identity to a pinned/published key.
- **Remediation:** In the responder branch, **before** `deriveResponderRoot`, resolve the peer's authentic X25519 IK via `_getPinnedPeerKey(otherUserId)` (which already fail-closes with `PeerIdentityChangedError`) and require `bytesEqual(deserialize(inboundPreamble.ikPub), pinned)`. On genuine first contact, pin `inboundPreamble.ikPub` as the X25519 IK (TOFU) so the safety number reflects what was bound. **Bind the X25519 IK and Ed25519 IK_sig pins atomically** (refuse if only one would be set) and verify `ikSignPub` is the deterministic IK_sig for the resolved X25519 IK (or have the initiator sign `ikPub` with IK_sig and verify responder-side), so a future bootstrap cannot carry a genuine IK_sig with a swapped IK. Apply the same resolve-and-compare in `_reconstructAD`'s responder path. Regression test: responder bootstrap with `ikPub` ≠ pinned/published X25519 IK must throw `PeerIdentityChangedError` and persist no ratchet state.

#### H-2 — Password-encrypted identity-key backup is offline-brute-forceable: strong-password policy defined but never enforced (zero-knowledge break for weak passwords)

- **Attacker model:** compromised/curious server / DB operator; any party with read access to `identity_key_backups` or a DB backup. (A fully active server already sees the plaintext password at login over TLS; the realistic path for this finding is the **passive/at-rest/leak** attacker who has stored bytes but not the live auth stream.)
- **File:line:** `passwordCryptoService.js:307` (`enforcePasswordStrength` defined) and `:273` (`validatePasswordStrength`) — **zero call sites** across all 5 repos. Sole gate is length≥8 at `authService.js:549`, `auth.html:792` (signup) and `:904` (reset). Backup encryption: `keyBackupService.js:80, 97-99`; KDF `passwordCryptoService.js:53-115` (PBKDF2-SHA256 600k + AES-256-GCM). Backup password = account password (`auth.html:805` → `signUp` → `createIdentityBackup`). Persisted as TEXT `complete-setup.sql:239-241`.
- **Exploit (repro):** Read a row's `password_encrypted_data`, `password_salt`, `password_iv`. For each candidate `w` in a wordlist: `key = PBKDF2-SHA256(w, salt, 600000, 256)`; attempt `AES-256-GCM.decrypt(ct, key, iv)`. The GCM tag validates only on the right key → unambiguous hit yields the 32-byte X25519 identity secret → derive X3DH/Double-Ratchet roots → decrypt all past/future messages and impersonate. PBKDF2-SHA256 is GPU-cheap; the accepted 8-char minimum and common passwords fall in hours-to-days, top-wordlist hits in seconds.
- **Impact:** Total E2E / zero-knowledge break for any user with a weak password against an at-rest DB read or leaked backup.
- **Exploitability:** High for weak passwords; not exploitable against a high-entropy password — which is precisely what the missing enforcement would have guaranteed. RLS does not protect this from the in-scope adversary (service role bypasses RLS; a cold backup ignores it).
- **Severity note:** Originally filed CRITICAL; adjusted to HIGH because it is gated on (a) a weak user password AND (b) the at-rest/leak attacker variant. Still a headline E2E break and a must-fix.
- **Remediation:** Call `PasswordCryptoService.enforcePasswordStrength(password)` in `AuthService.signUp` (before backup) and the reset handler; reject server-side too. Raise the bar (min length 12, integrate zxcvbn, block breached-password lists). Structurally: make the backup key derive from the high-entropy recovery key (treat password backup as convenience), add a server-unknown KDF pepper, and migrate the backup KDF from PBKDF2-SHA256 to memory-hard **Argon2id**. (The recovery-key path is the right primary escrow *iff* `RECOVERY_KEY_BYTES` is restored to 32 — see Section 5.)

#### H-3 — Premium messaging / trial entitlement is enforced only client-side: no server gate on `messages` insert and no trial-expiry job (entitlement bypass)

- **Attacker model:** any malicious authenticated user (any signed-up account).
- **File:line:** client auto-downgrade `payments_app/payments/services/subscriptionService.js:430-444`; signup trial trigger + missing server expiry `payments_app/backend/sql/complete-setup.sql:314-344, 368-407`; tier mapping treats `status==='trial'` as full Premium regardless of `trial_end` (`subscriptionService.js:82-85`); messaging insert RLS in `secure_db` has no subscription predicate.
- **Exploit (repro):** (1) Sign up — trigger writes `status='trial', plan=Premium, trial_end=NOW()+30d`. (2) The ONLY thing that flips an expired trial to Free is the *client* calling `downgrade_to_free()` when it locally observes `trial_end < now`. There is no server-side cron/trigger/RPC. (3) Never run that path — use a patched client, call APIs directly with the JWT, or block the `downgrade_to_free` network call. The row stays `status='trial'` with a long-past `trial_end` forever. (4) All consumers treat `status==='trial'` as Premium, and the `messages` INSERT policy gates only on conversation membership, not subscription. → Premium messaging for $0, permanently.
- **Impact:** Permanent free Premium for every account; the central revenue control is advisory only. Directly contradicts the stated server-authoritative-entitlement goal of the lockdown.
- **Exploitability:** High; trivial (just don't run the client downgrade path).
- **Remediation:** (a) Compute entitlement server-side as `(status='active' AND plan=Premium) OR (status='trial' AND trial_end > NOW())` — never trust `status` alone. (b) Add a pg_cron job downgrading rows where `status='trial' AND trial_end < NOW()`. (c) **Gate the protected resource**: add a SECURITY DEFINER entitlement check on `messages` INSERT (`secure_db`) requiring active Premium or an unexpired trial, so a tampered client cannot bypass the JS check.

#### H-4 — S7 budget-DEK seal: recipient pubkey unpinned (no TOFU) + anonymous box with no sender auth / context binding — curious server can redirect or forge shared budget DEKs

- **Attacker model:** compromised/curious server supplying/substituting the recipient public key (active key-substitution on the share path); a recipient who cannot cryptographically attribute the seal's origin.
- **File:line:** `createDataShare` `auth_db/database/services/databaseService.js:3954-3978` → `_sealShareDekForRecipient :2992` → `_getRecipientIdentityPublicKey :2954` (resolves via `HistoricalKeysService.getCurrentKey` / raw `identity_keys` read with RLS `USING(true)` at `:2969`, **not** through the `_getPinnedPeerKey` TOFU chokepoint at `keyManagementService.js:1640`). Seal/unseal: `money_tracker/shared/services/budgetCryptoService.js:262-282` (seal) / `:297-320` (unseal); fresh ephemeral sender key (anonymous box) `cryptoPrimitivesService.js:159`, `budgetCryptoService.js:272`. Unseal consumer `databaseService.js:3021`.
- **Exploit (repro) — curious-server, active:**
  1. Server generates X25519 keypair `S_pub/S_sec`.
  2. At share time, server sets recipient Bob's `identity_keys.public_key = S_pub` (it owns the table; service role bypasses RLS; Alice has no prior pin in this path).
  3. Alice's `createDataShare` → `_getRecipientIdentityPublicKey` returns `S_pub` → `sealDEKToRecipient` seals Alice's budget DEK under `DH(eph, S_pub)`, persisting `wrapped_dek`/`wrap_nonce`/`wrap_eph_pub` to `data_shares`.
  4. Server reads those columns, computes `unsealDEK` with `S_sec` → recovers Alice's per-user budget DEK → decrypts every shared `user_months`/`pots` row.
- **Forge-to-recipient variant:** because the box is anonymous (no sender auth) and binds nothing about `(owner_id, recipient_id, dek_version, share_id)`, the server or any user holding Bob's public key can fabricate a `data_shares` row sealing an attacker-known DEK to Bob plus matching attacker ciphertext; `_unsealOwnerDekFromShare` succeeds and Bob renders attacker-controlled data as a genuine peer's shared budget.
- **Impact:** Zero-knowledge break for shared budgets against the platform's committed adversary; no proof of origin on shares.
- **Exploitability:** HIGH (corrected up from MEDIUM): the path is **wired now** (`createDataShare`), not deferred. Requires an *active* key substitution on the share flow, scoped to shared-budget data (owner's own at-rest budget, wrapped under owner identity, is unaffected) — so narrower than a passive DM read, hence HIGH not CRITICAL.
- **Remediation:** Two independent fixes, both required. (1) Route `_getRecipientIdentityPublicKey` through `_getPinnedPeerKey` (fail-closed; do not seal to an unpinned/changed key). (2) Replace the anonymous box with an **authenticated** static+ephemeral construction (owner static identity secret in the DH) AND bind context — feed `(owner IK, recipient IK, owner_id, recipient_id, dek_version, share_id)` as HKDF info / AAD over the seal. `unsealDEK` must verify the bound context and the (pinned) sender static key before returning the DEK. Gate test: a seal whose bound IDs don't match the row, or whose sender key is unpinned/changed, must fail closed.

#### H-5 — CSP allows `script-src 'unsafe-inline'` with no nonce/hash: any HTML-injection becomes full key-stealing XSS / account takeover

*(Two passes reported this; merged.)*

- **Attacker model:** anyone who achieves script execution in the app origin — a malicious peer landing markup in any innerHTML sink, a future regression, a compromised vendored dependency, or a MITM-injected script. This is the last line of defense for an E2E app whose threat model assumes the page is attacked.
- **File:line:** identical CSP `script-src 'self' 'unsafe-inline' https://js.stripe.com` across `messaging_app/.../messenger.html:9`, `settings.html:9`, `auth/views/auth.html:7`, `payments_app/.../subscription.html:7`, and all `money_tracker` views + `lib/` mirrors. Because no nonce/hash is present, `'unsafe-inline'` is fully active. Reachable post-XSS targets: cleartext login password in `sessionStorage` (`passwordManager.js:38`, ≤10 min), unwrapped identity secret via `window.KeyStorageService.getIdentityKeys()` returning raw `secretKey` bytes (`keyStorageService.js:368-437`), and the Supabase JWT in localStorage. `connect-src https://*.supabase.co` makes exfil to an attacker Supabase project in-policy.
- **Exploit (chain):** (1) any injection sink that escaping misses (a regression like the historical `renderMessageThread`, a peer field, or a tainted dep); (2) with `'unsafe-inline'` active, the inline payload runs in the authenticated origin; (3) it reads the temp password / JWT and calls `getIdentityKeys()` to exfiltrate the identity secret + ratchet state; (4) permanent E2E compromise.
- **Impact:** Converts any single HTML-injection from "defense-in-depth saved us" to full account/key compromise.
- **Exploitability:** Not independently exploitable **today** — the live peer-controlled render paths I traced (`messengerController.js:1034-1035, 1108, 1119-1120, 461, 1487, 1852-1853`) all pass through a correct `_escapeHtml`. This is a HIGH defense-in-depth finding: it removes the only barrier behind every XSS sink. **One latent attribute-context risk:** `messengerController.js:1116` interpolates `att.id` **unescaped** into `data-attachment-id="${attId}"` and `onclick="...downloadAttachment(${attId})"` (escaped for fileName but not the id; the comment assumes a BIGSERIAL integer). If `att.id` can ever be non-integer, that becomes stored XSS — see UNCERTAIN U-1.
- **Remediation:** Remove `'unsafe-inline'` from `script-src`. Prerequisite refactor: convert inline event handlers to `addEventListener` wiring (`messenger.html:40,183,190` and the controller-generated `onclick`/`onmouseover` in `_renderAttachmentItem` ~`:1116` and `_renderDeleteControl` ~`:1145`); move the inline `<script>` block (`messenger.html:15`) to an external file. Then adopt `script-src 'self' https://js.stripe.com` (vendor everything) or a strict per-load nonce / `strict-dynamic`. Keep `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`; add `frame-ancestors 'none'` (see M-7) and consider narrowing `connect-src` to the single project host. Coerce `att.id` with `Number.isSafeInteger` (or escape it) at `:1116`.

#### H-6 — Attachment filename, MIME type, and exact byte-size stored in plaintext (E2E-encrypted bytes, cleartext metadata)

- **Attacker model:** curious/malicious server / DB operator (the zero-knowledge adversary); read-only Postgres access suffices.
- **File:line:** `secure_db/sql/complete-setup.sql:441-445` (`file_name TEXT`, `file_size BIGINT`, `mime_type TEXT`, comment "stored unencrypted for querying"); mirrored `money_tracker/database/setup/fresh-install-complete.sql:1652-1654`. Writer `messaging_app/messaging/services/attachmentService.js:469-471` (`file.name`, `file.size`, `file.type`). File bytes ARE E2E-encrypted (`_encryptFile :432`, per-file key wrapped under conversation key `:442`).
- **Exploit (repro):** `SELECT a.file_name, a.mime_type, a.file_size, c.user1_id, c.user2_id, a.created_at FROM message_attachments a JOIN conversations c ON c.id=a.conversation_id;` → original filenames (`divorce_settlement.pdf`, `passport_scan.jpg`), exact MIME, exact byte counts, both participant IDs, timestamps. No decryption, no key material, no client cooperation.
- **Impact:** Filenames routinely carry the most sensitive content; exact `file_size` enables known-file fingerprinting/confirmation against the encrypted blob. Materially undercuts the E2E posture; high PR/pentest damage.
- **Exploitability:** Trivial. The "for querying" justification is false — `file_name`/`file_size`/`mime_type` appear only in DDL/comments and the client reader (`attachmentService.js:612`), never in any RLS/trigger/function. RLS is irrelevant (adversary is the DB operator). The 24h expiry bounds only a passive live-snapshot window, not WAL/backups/continuous logging.
- **Remediation:** Move `file_name` and `mime_type` into the client-encrypted blob (e.g. an `encrypted_metadata` + nonce column sealed under the conversation session key); drop the plaintext columns. Store only a coarse `file_size` bucket (round up to fixed granularity) to blunt fingerprinting; encrypt exact size in the metadata blob if needed for integrity. Apply to both schemas and update writer (`:465-475`) and reader (`:610-614`). RLS already scopes rows to participants, so removing these columns costs no server functionality.

---

### MEDIUM

#### M-1 — Safety number covers X25519 IK only and is decoupled from the wire `ikPub`/`ikSignPub` the responder path actually trusts (amplifier of H-1)

- **Attacker model:** active MITM / hostile server, combined with H-1.
- **File:line:** `generateSafetyNumber` `cryptoPrimitivesService.js:364-398` (hashes only the two X25519 IKs); consumed `keyManagementService.js:1811-1827`; responder trusts wire `ikPub` at `:1078-1133` / `x3dhService.js:261,283`.
- **Exploit:** A hostile server leaves the victim's `identity_keys` row intact but substitutes the first inbound message's `ikPub`/`ikSignPub` with self-consistent MITM keys. Bob's responder session is keyed to the MITM, yet `getSafetyNumber` reads the untouched `identity_keys` row → the displayed number matches → the human verification ritual passes while the session is MITM'd.
- **Impact:** Defeats the one mitigation (compare safety numbers) for H-1's responder path.
- **Exploitability:** Requires H-1; not standalone. The safety number itself correctly covers the X25519 IK — the gap is that the responder trusts an unpinned wire key.
- **Remediation:** **The fix is H-1, not changing the hash.** Folding the (pinned) IK_sig into the hash does NOT close this gap because both `generateSafetyNumber` and the responder-trusted value diverge from the pinned material differently. Once the responder is forced to trust the same `identity_keys`-pinned X25519 IK that `getSafetyNumber` reflects (H-1 fix), the existing X25519-only number becomes a meaningful anchor for both roles. Optionally fold IK_sig in for defense-in-depth, but only after the wire/pinned divergence is removed.

#### M-2 — `claim_one_time_prekey()` lets any authenticated user drain a victim's entire OPK pool (forward-secrecy DoS / FS downgrade)

*(Merged: the server-RPC drain and the client-side silent-downgrade are the same issue from two angles. The pure client-side downgrade-without-signal piece is logged as L-1.)*

- **Attacker model:** malicious authenticated user targeting any other user by UUID.
- **File:line:** `auth_db/backend/sql/complete-setup.sql:427-485` (duplicate `apply-forward-secrecy-schema.sql:147-205`). SECURITY DEFINER, GRANT to `authenticated`, arbitrary target, no rate limit / per-caller cap; each call `FOR UPDATE SKIP LOCKED LIMIT 1` then `consumed=TRUE` (`:456-467`). Enumeration oracle `one_time_prekeys_select_all USING(true)` `:392-394`. Client-only replenish `keyManagementService.js:960-1002`.
- **Exploit (repro):** Authenticate; optionally `SELECT count(*) FROM one_time_prekeys WHERE user_id='<victim>' AND consumed=false`; then `rpc('claim_one_time_prekey', { target_user_id: '<victim>' })` in a loop until `opk_pub` returns NULL. Pool fully consumed. An offline victim never replenishes (replenish is client-side, fires only on the victim's own `publishPrekeys`).
- **Impact:** Every subsequent sender falls back to SPK-only X3DH (drops DH4), removing the one-time-prekey FS contribution for the first message of each new session; cheap, unlimited, targeted, repeatable DoS/downgrade.
- **Exploitability:** Trivial and unthrottled. MEDIUM not higher: SPK-only fallback is spec-permitted (`FORWARD_SECRECY_DESIGN.md §2.2`); the sender's ephemeral EK still yields a fresh SK, so this is a FS *downgrade*, not a confidentiality break — no plaintext is gained.
- **Remediation:** Add a per-`(caller,target)` and per-target token-bucket cap inside the DEFINER function (record claims in an `opk_claim_audit` table indexed on `(target, claimed_at)`); reject once exceeded. Tighten `one_time_prekeys_select_all` so callers can't enumerate arbitrary pools. Add server-side OPK replenishment + larger pool so transient drains self-heal. Keep both SQL copies in sync.

#### M-3 — Webhook idempotency keys on event RECEIPT not COMPLETION: a failed/crashed handler permanently drops the event (lost entitlement/cancellation)

- **Attacker model:** no active attacker required (integrity/availability bug); the security-relevant direction is a silently-dropped cancellation/payment-failure leaving a user on Premium.
- **File:line:** `payments_app/supabase/functions/stripe-webhook/index.ts:151-164` (`claimWebhookEvent` short-circuits on row existence, before the handler switch at `:168-201`); `claimWebhookEvent :257-297`. The `processed` column is write-only on the recovery path; nothing reads it to decide reprocessing.
- **Exploit / failure path:** `claimWebhookEvent` does `INSERT ... ON CONFLICT DO NOTHING` *before* dispatch. On any redelivery the row exists → returns 200 `{duplicate:true}` and the handler never runs. Two real triggers: (A) a handler-internal failure (PATCH 5xx, Stripe rate-limit) is swallowed into `{success:false}` and returned as HTTP **200**, so Stripe never retries and the write is lost on first delivery; (B) a timeout/OOM after the claim INSERT commits but before the response → Stripe retries → row exists → 200 duplicate → handler skipped forever.
- **Impact:** Permanent divergence between Stripe (source of truth) and the `subscriptions` table: `customer.subscription.deleted` (cancellation) or `invoice.payment_failed` (past_due) silently dropped → user keeps Premium / never flagged. Entitlement bypass + revenue loss.
- **Exploitability:** No deterministic attacker-controlled exploit; transient/operational. MEDIUM (downgraded from the originally-filed HIGH because the exact 500→retry path is largely unreachable — handlers return 200 even on failure — and an authenticated user has no reliable lever over timeouts; impact is the same lost-update either way).
- **Correction:** the originally-filed second file `backend/edge-functions/stripe-webhook/index.ts` does not exist; only the `supabase/functions` copy is present.
- **Remediation:** Make idempotency **completion-based**: on conflict, SELECT the existing `processed` and return tri-state `{firstDelivery | alreadyProcessed | inFlight}`; short-circuit with 200 only when `processed=true`; when `processed=false`, re-run the (idempotent, PATCH-by-user) handler. Make handlers re-throw / have the dispatcher return 500 on `result.success===false` so Stripe retries. Only set `processed=true` when `result.success===true`. Add a reconciliation cron against Stripe as a backstop.

#### M-4 — `update-subscription` accepts an unvalidated `newPlanId` as the pending downgrade plan (latent billing/tier escalation)

- **Attacker model:** malicious authenticated user acting on their own subscription.
- **File:line:** `payments_app/supabase/functions/update-subscription/index.ts:101-114` (`body.newPlanId` copied verbatim into Stripe `metadata.pendingPlanId` and `subscriptions.pending_plan_id`, no validation). Downstream provisioning `stripe-webhook` `handleSubscriptionDeleted :596-666` (looks up plan by that id and creates a Stripe subscription on its price, with no `is_active` / downgrade-legitimacy check).
- **Exploit:** `POST update-subscription` with `{changeType:'downgrade', newPlanId:<arbitrary int>}`. The id flows into Stripe metadata and (FK permitting) `pending_plan_id`; at period end the webhook re-provisions onto whatever plan that id names if it has a `stripe_price_id`.
- **Impact:** Latent privilege/billing escalation. Identity is correctly bound to the caller's own row (not cross-user).
- **Exploitability:** **Not exploitable today** — the live catalog is only Free (`stripe_price_id` NULL) and Premium; pointing at Free falls through to cancellation, at Premium is a no-op. Becomes a real escalation the moment a third/cheaper/mis-priced paid plan is added. MEDIUM-leaning-LOW; treated as MEDIUM because the unvalidated-client-id flows end-to-end into Stripe provisioning. *(Listed here for prioritization; effectively a latent LOW until a third plan exists.)*
- **Remediation:** Before writing `newPlanId`, fetch the target and current plan and assert `exists AND is_active AND price_cents <= current` (a true downgrade); reject otherwise. Re-validate in `handleSubscriptionDeleted` before `stripe.subscriptions.create`. Validate `newPlanId` is a positive integer.

#### M-5 — `create_notification` RPC has no caller↔target relationship check: arbitrary cross-user notification injection (spam/phishing)

- **Attacker model:** any authenticated user.
- **File:line:** `money_tracker/database/setup/fresh-install-complete.sql:1372-1450` (SECURITY DEFINER, GRANT EXECUTE to `authenticated`; forces `from_user_id=auth.uid()` `:1397`, blocks payment types `:1398-1400`, but no relationship check on `p_user_id`; inserts `p_user_id` and `COALESCE(p_message, v_title)` verbatim `:1426-1429`). `notifications` has no INSERT policy/grant — the RPC is the sole gate.
- **Exploit:** `POST /rest/v1/rpc/create_notification` `{"p_user_id":"<victim>","p_type":"share_request","p_message":"<attacker text>"}` → injected into any victim's feed with a legitimate-looking server-derived title.
- **Impact:** In-app spam / plaintext social-engineering to arbitrary known UUIDs.
- **Exploitability:** Trivial DB-side, but impact is **bounded to escaped plaintext spam** — the originally-claimed stored-XSS amplifier is **refuted**: the sole renderer (`notificationsController.js:686`) routes `message` through a correct `_escapeHtml`; the title is server-derived (CASE), not attacker-controlled; the badge uses `textContent`. No XSS, no cross-user read. Severity downgraded MEDIUM→**LOW** as an XSS, but the **authorization gap is real**; logged here as MEDIUM-priority authz hardening, LOW impact. *(See L-? — folded; treat as a LOW-impact authz fix.)*
- **Remediation:** Require a real relationship (`friends` / `data_shares` / shared conversation) between `auth.uid()` and `p_user_id` before inserting; else return forbidden. Add a per-caller rate limit and bound `p_message` length. Keep `_escapeHtml` and ensure any future notification renderer uses `_escapeHtml`/`textContent`.

> Note: M-5's true impact is LOW (escaped plaintext). It is listed adjacent to MEDIUM because the missing authorization control is worth scheduling promptly, but it does not gate the pentest.

#### M-6 — Unrestricted email↔UUID lookup oracle (`user-lookup` edge fn) + world-readable `identity_keys` = full-base de-anonymization

- **Attacker model:** any authenticated user.
- **File:line:** `auth_db/backend/edge-functions/user-lookup.ts:38-73` (authn only — verifies JWT, no authz), `:100-105` (routes to `findByEmail`/`getEmailById` with service-role client, no relationship param), `:132-178` (`findByEmail` membership oracle: 200+userId vs 404), `:183-237` (`getEmailById` arbitrary UUID→email). UUID harvest: `identity_keys_select_all USING(true)` `money_tracker/.../fresh-install-complete.sql:1076-1077`, GRANT `:1090`.
- **Exploit (repro):** (1) sign in. (2) `from('identity_keys').select('user_id')` → every UUID. (3) For each: `POST functions/v1/user-lookup {action:'getEmailById', userId:<uuid>}` → email. → complete UUID→email map for the whole base. Independently, `{action:'findByEmail', email:...}` → 200/404 membership oracle over any email list. No relationship, no rate limit.
- **Impact:** Full-base de-anonymization + membership directory dump on a privacy-first product.
- **Exploitability:** Trivial. MEDIUM — metadata/de-anonymization, not a content/crypto/auth break. Same function deployed across all clients.
- **Remediation:** Add authorization to `user-lookup`: resolve `getEmailById` only for UUIDs the caller shares a conversation/friend/data_share with; make `findByEmail` return a uniform response (or gate behind invite) to kill the membership oracle; add per-caller rate limiting. Replace `identity_keys_select_all USING(true)` with a relationship-scoped predicate, or move public-key distribution through the same authorized path. Audit `prekeys` / `public_key_history` for the same pattern.

#### M-7 — No clickjacking protection: CSP lacks `frame-ancestors`, no `X-Frame-Options`; GitHub Pages can't set headers and meta-CSP `frame-ancestors` is ignored

- **Attacker model:** web attacker hosting a page that frames the E2E app for UI-redress.
- **File:line:** CSP meta (no `frame-ancestors`) `messenger.html:9` and all views; no `X-Frame-Options`/`_headers`/frame-buster anywhere (grep clean). Deploy is GitHub Pages (`.github/workflows/deploy.yml`).
- **Exploit:** Attacker page embeds `messenger.html`/`settings.html` in a low-opacity iframe with bait UI over sensitive controls; an authenticated victim's clicks trigger device-pairing approval, share creation, recovery-key reveal, or delete-for-everyone.
- **Impact:** UI-redress against destructive and trust-establishing actions (pairing is an E2E-trust event).
- **Exploitability:** Realistic web-attacker; no MITM/auth needed. MEDIUM — needs victim interaction with bait UI, no direct key read, destructive flows often behind confirm dialogs.
- **Remediation:** Front the apps with a platform that can set real headers (Cloudflare/Netlify) and emit `X-Frame-Options: DENY` + `Content-Security-Policy: frame-ancestors 'none'` (+ Referrer-Policy, X-Content-Type-Options, HSTS). Interim on Pages: a head frame-buster (`if (self !== top){ top.location = self.location }`) that runs before paint with body hidden until the check passes. Do NOT just add `frame-ancestors` to the `<meta>` CSP — it is spec-ignored there.

> **Metadata-privacy MEDIUMs** (M-8, M-9, M-10) — three length/oracle side channels against the server. Grouped:

#### M-8 — Budget E2E ciphertext length leaks plaintext size (no padding): amount-magnitude / item-count side channel

- **Attacker model:** curious/malicious server reading `user_months.enc_payload` / `pots.enc_payload` lengths.
- **File:line:** `money_tracker/shared/services/budgetCryptoService.js:116-125` (`JSON.stringify` then secretbox, no padding) via `cryptoPrimitivesService.js:241-253` (XSalsa20-Poly1305 → `ct = pt + 16`).
- **Exploit:** `SELECT user_id, year, month, octet_length(decode(enc_payload,'base64')) plen, updated_at FROM user_months ORDER BY plen;` ranks rows by content size; diffing `plen` across `updated_at` detects item add/remove. A small `pots` blob vs a large verbose one distinguishes order-of-magnitude amounts.
- **Impact:** Order-of-magnitude amounts, per-month line-item count, and edit timeline inferable without the key.
- **Correction:** all fields share one blob, so only **total** plaintext length leaks (a long name masks a short amount) — per-field precision was overstated.
- **Exploitability:** Passive, zero crypto work. MEDIUM (metadata only).
- **Remediation:** Pad plaintext to fixed buckets (256/512B) before secretbox: prepend a 4-byte length header, zero-pad to the next bucket, encrypt raw bytes, strip on decrypt by the header. Gate behind `enc_version` bump for backward compat.

#### M-9 — Message ciphertext length leaks plaintext length (no padding before secretbox)

- **Attacker model:** curious/malicious server reading `messages.encrypted_content` lengths; passive Realtime/MITM observer.
- **File:line:** `cryptoPrimitivesService.js:241-247` (secretbox, no padding); send path `messagingService.js:236, 243`; schema `secure_db/sql/complete-setup.sql:286`.
- **Exploit:** `SELECT length(encrypted_content), sender_id, recipient_id, created_at, message_counter FROM messages` → per-conversation timeline of message sizes + exact timing + frequency, distinguishing short replies from long paragraphs.
- **Impact:** Classic E2E-messenger length+timing+graph metadata leak (the team's own `PLATFORM.md` item #10 already flags it).
- **Exploitability:** Trivial; MEDIUM — metadata, not content. (Content stays sealed.)
- **Remediation:** Pad to fixed buckets (e.g. 256B) inside the authenticated ciphertext (pad-then-encrypt), strip on decrypt. Document the honest residual: timing/frequency and plaintext sender/recipient/counter still leak the graph; those need sealed-sender work beyond padding.

#### M-10 — `field_locks` SELECT `USING(true)`: cross-tenant budget-structure + edit-activity metadata leak (+ lock-squatting advisory DoS)

*(Merged from the authz pass (L-rated) and the metadata pass (MEDIUM). Severity reconciled to MEDIUM for the cross-tenant structure leak once locks are populated; the squat-DoS leg is LOW and advisory-only.)*

- **Attacker model:** any authenticated user; also the server.
- **File:line:** `money_tracker/database/setup/fresh-install-complete.sql:929-930` (`field_locks_select_all FOR SELECT USING(true)`), GRANT `:938`; `field_path TEXT` `:917`, `locked_by` UUID `:918`; writer `fieldLockingService.js:55,97` (paths like `variable_costs[0].actualAmount`). Realtime channel `:482-491`.
- **Exploit:** `SELECT * FROM field_locks` (or open the Realtime `locks:*` channel) → every tenant's `locked_by`/record/`field_path`/timestamp — who is editing which record, which JSON path (revealing category presence / array indices / line-item counts), in real time, plus a victim UUID (de-anonymizable via M-6). Squat leg: INSERT a lock on a victim's `record_id` (`insert_own` checks only `locked_by=self`); UNIQUE + no UPDATE grant blocks the legit editor from acquiring it.
- **Impact:** Cross-user real-time presence/activity + partial budget structure (values stay encrypted); advisory edit DoS.
- **Exploitability:** Trivial RLS-wise. **Currently dormant:** `acquireFieldLock`/`subscribeToLocks` have no callers in the active app and the service's column names don't match the deployed table, so the table is effectively unpopulated today. Becomes a live leak the instant field locking is wired in (the clear intent). Squat-DoS is advisory only — no write path consults `field_locks`, so it blocks UI lock acquisition, not actual `user_months` writes.
- **Remediation:** Replace `USING(true)` with owner/share-scoped predicate (mirror `data_shares_select_involved :841-842`): `USING (auth.uid() = locked_by OR EXISTS (SELECT 1 FROM data_shares ds WHERE ds.owner_user_id = field_locks.owner_user_id AND ds.shared_with_user_id = auth.uid() AND ds.status='accepted'))`. Strengthen `insert_own` `WITH CHECK` to verify edit rights to the target record. Hash or coarsen `field_path` for shared resources. Reconcile the client schema with the deployed table (or drop the orphaned service). Harden before field locking ships.

---

### LOW

#### L-1 — OPK exhaustion silently downgrades new sessions to SPK-only with no downgrade signal
`keyManagementService.js:1028` (`hasOpk` optional), `x3dhService.js:199-205` (dh4 null), responder `:264-280`. No flag marks a session downgraded; no telemetry. *(Server-side drain is M-2; this is the silent-degradation half.)* **Fix:** record `hasOpk=false` on session state and log/telemetry it; surface abnormal drains.

#### L-2 — Pairing wraps the full identity bundle under an 80-bit code; server holds the offline-attackable ciphertext for the expiry window
`devicePairingService.js:29` (`PAIRING_CODE_BYTES=10`), `:57-78`; `exportPairingBundle` `keyManagementService.js:2035-2043` (identity secret + IK_sig secret + session backup key + ratchet snapshot); KDF `passwordCryptoService.js:34-35` (PBKDF2 600k). RLS only hides expired rows (`add-device-pairing.sql:30-31`); deletion is an operator-managed pg_cron. **Not exploitable** at 80 bits over PBKDF2-600k (>>10^15s); LOW footgun. **Fix:** keep ≥80 bits; enforce expired-row deletion in-schema rather than relying on external cron; shorten expiry to 60–120s; document the code guards the entire identity and must never be logged.

#### L-3 — Long-term identity secret transits the server as code-wrapped ciphertext in `pairing_requests` (defense-in-depth)
`keyManagementService.js:2037`; `devicePairingService.js:57-78`. **No working exploit:** a curious server can't open the 80-bit-protected blob, and a malicious-JS server already wins directly. Residual: the load-bearing pg_cron reaper is documented-but-not-deployed, leaving full-identity ciphertext at rest past TTL. **Fix:** ship the reaper in-schema; consider PAKE/SPAKE2 or server-blind QR pairing so the raw secret never parks server-side.

#### L-4 — Pairing attempt-limit is a non-atomic, client-driven read-modify-write (counter not server-enforced)
`devicePairingService.js:118-136` (read `attempts`, decrypt, then separate `queryUpdate`); GRANT UPDATE(attempts) `add-device-pairing.sql:50`. Race allows exceeding `MAX_ATTEMPTS=5`; the client can also never increment / reset to 0. **LOW** because the real floor is the 80-bit code + 5-min server-enforced TTL. **Fix:** atomic SECURITY DEFINER RPC `UPDATE ... SET attempts=attempts+1 WHERE id=$1 AND attempts<5 AND expires_at>now() RETURNING ...`; revoke client UPDATE(attempts).

#### L-5 — Safety-number digits use modulo-10 of raw hash bytes (modulo bias) and only 30 of 64 hash bytes
`cryptoPrimitivesService.js:386-389` (`b % 10`), default 6×5=30 digits. Sub-1-bit entropy loss on an already-~99-bit fingerprint; the 30-digit display is by design. **Not exploitable** (targeted second-preimage still ~2^99). **Fix:** rejection-sample or derive digits from big-endian chunks; ideally adopt Signal's reviewed construction.

#### L-6 — TweetNaCl adopted via mutable `window.nacl` with no SRI/self-test (supply-chain defense-in-depth)
`cryptoLibraryLoader.js:49-54` (adopts pre-existing `window.nacl` unverified), `:95-125` (script load with no `integrity`/`crossorigin`); consumed `cryptoPrimitivesService.js:50-51`; used for real unwrap `keyManagementService.js:1585`. KAT vectors are test-only. **Conditional** on a separate script foothold (the `'unsafe-inline'` CSP lowers the bar). **Fix:** add SRI (sha384) + `crossorigin`; don't blindly adopt `window.nacl`; run a startup KAT self-test before `initialized=true` (fail-closed); remove `'unsafe-inline'` (H-5).

#### L-7 — User email rendered unescaped into the header user-menu via `insertAdjacentHTML` (both apps)
`messaging_app/lib/auth_db/shared/header/header.js:145` (`<span>${userEmail}</span>`) injected `:982` (also initial render `:115`/`:228`); `money_tracker/shared/header/header.js:169` + duplicate block `:1041`/`:1084`. The client validator (`validators.js:15`) permits `< > " '`, so an HTML-bearing email *passes* — but GoTrue server-side email validation is the gate that currently blocks it. **Conditional** (admin-provisioned email / OAuth-SSO / future validation relaxation). Breaks the codebase's own escaping invariant. **Fix:** escape (or `textContent`) email + initials in all four sites; tighten `validators.js`; remove `'unsafe-inline'`.

#### L-8 — Raw server/Postgres error strings interpolated into innerHTML on settings status panels
`money_tracker/settings/controllers/settingsController.js:339,349,457,994,1512,1699,2474,2678` (raw `${error}`/`${error.message}` → innerHTML; the file's own `_escapeHtml` is used elsewhere). Sites `:2474`/`:2678` interpolate **server-controlled** error text (`databaseService.js:5115` surfaces raw PostgREST `error.message`). A compromised/curious server can return `<img src=x onerror=...>` in an error body → executes under `'unsafe-inline'`. **MEDIUM-leaning**, listed LOW because the six self-error sites are low-likelihood; the two server-fed sinks are the real (server-trust) risk. **Fix:** route all error text through `_escapeHtml` or set via `textContent`; treat server error strings as untrusted; remove `'unsafe-inline'`.

#### L-9 — Public-key tables world-readable to every authenticated user (enumeration surface)
`identity_keys`/`public_key_history`/`prekeys`/`one_time_prekeys` `SELECT USING(true)` — `complete-setup.sql:72-73, 106-107, 348-349, 392-394`. Membership/roster enumeration; **no write/drain** (INSERT/UPDATE owner-only, OPK consumption RPC-gated). Public material only; substitution risk is the server's (RLS can't fix authenticity). **Fix:** keep TOFU fail-closed; add out-of-band verification UX; route peer lookups through a rate-limited edge function instead of blanket `USING(true)`.

#### L-10 — `is_blocked(owner, blocked)` callable by anyone for arbitrary pairs (block-list privacy oracle)
`secure_db/sql/complete-setup.sql:174-188` (SECURITY DEFINER, GRANT to `authenticated`, no caller check; bypasses `blocked_users_select_own`). `POST /rpc/is_blocked {p_owner,p_blocked}` reveals whether A blocked B — defeats an explicit privacy control. **Fix:** add `AND p_blocked = auth.uid()` to the body (non-breaking: the sole legit caller `messages_insert_participant :368` always passes `auth.uid()`); mirror in `messaging_app/.../complete-setup.sql:176-190`.

#### L-11 — Entitlement/prekey DEFINER RPCs return raw `SQLERRM` to the client (schema/constraint disclosure)
`payments_app/.../complete-setup.sql:404-405,456-457,493-494`; `apply-entitlement-lockdown.sql:79-80,138-139,182-183`; `auth_db/.../complete-setup.sql:480-481`. `WHEN OTHERS THEN RETURN ... SQLERRM` leaks constraint/table names (no cross-user data — unique-violation echoes only the caller's own key). **Fix:** return a generic message, `RAISE LOG` the detail; catch `unique_violation` explicitly.

#### L-12 — `stripe-webhook` hardcodes `Access-Control-Allow-Origin: *` (drift from EB-10 allowlist) and echoes signature-stage `err.message`
`payments_app/supabase/functions/stripe-webhook/index.ts:92,106,160,214,231` (ACAO `*`), `:134` (echoes `err.message`). No credentials/cookies; signature gate blocks state change; only generic pre-auth diagnostics are readable. **Fix:** drop ACAO entirely (server-to-server) or route through the shared allowlist; return a static 400 body. (The originally-cited `backend/edge-functions` copy doesn't exist.)

#### L-13 — No codified `verify_jwt` config for `stripe-webhook` (no `supabase/config.toml`)
No `.toml` anywhere; deploy is copy-paste Dashboard. **Not a bypass** — `constructEvent` requires the server-only webhook secret regardless of gateway posture; worst case is silent breakage (availability). **Fix:** add `config.toml` with `[functions.stripe-webhook] verify_jwt=false` and `verify_jwt=true` for the four user-facing functions; prefer CLI deploy with `--no-verify-jwt`.

#### L-14 — Plaintext structural budget columns + inherent social-graph/timing metadata
(a) `month_name` redundant cleartext + `pots` row-count leak: `money_tracker/.../fresh-install-complete.sql:117-122` (year/month/month_name never nulled by `budgetMigrationService.js:70-73`), `pots` one row per pot. RLS blocks authenticated users; the adversary is the server. **Fix:** drop `month_name` (derive client-side); document year/month + pot-count as conscious residual; move pots into `enc_payload` if count must be hidden.
(b) Inherent graph/timing: `conversations`/`friends`/`blocked_users`/`messages` sender/recipient/counter/timestamps + `REPLICA IDENTITY FULL` (`secure_db/.../complete-setup.sql:647`) broadcast full metadata to a WAL/replication consumer. Largely architectural. **Fix:** document the "E2E hides content, not metadata" residual in the threat model; tightly restrict logical-replication/WAL access; sealed-sender/padding are roadmap items.

#### L-15 — Stale comment claims OPK own-row DELETE is not granted, but it IS (own-row scoped; no cross-user exploit)
`auth_db/.../complete-setup.sql:305-307` (comment) vs `:411-415` (policy + grant); same in `apply-forward-secrecy-schema.sql:127-133`. Property holds (own-row `USING`) but for the wrong stated reason. **No exploit**; maintenance hazard. **Fix:** correct the comment in both files.

---

## 3. UNCERTAIN — Items for Human Review

#### U-1 — `att.id` interpolated unescaped into an inline `onclick`/attribute (potential stored XSS under `'unsafe-inline'`)
`messengerController.js:1116` interpolates `att.id` without escaping into `data-attachment-id="${attId}"` and `onclick="...downloadAttachment(${attId})"` (fileName is escaped; the id is not, on the assumption it is a BIGSERIAL integer). **Needs verification:** confirm the provenance and type of `att.id` end-to-end — if it can ever be an attacker-influenced non-integer string (e.g. from a server-controlled or peer-influenced column), this is a live stored XSS that `'unsafe-inline'` (H-5) turns into key theft. If it is provably always an integer from `BIGSERIAL`, it is benign. **Recommended:** coerce with `Number.isSafeInteger`/`Number(attId)` regardless, and prefer `createElement` + `dataset` + `addEventListener`.

#### U-2 — `update_share_status` RPC body (deployed out-of-repo) — does it re-normalize `can_edit`/`share_all_data` on accept?
C-1's **write**-escalation assumes `update_share_status(p_share_id,p_new_status,p_user_id)` (`databaseService.js:4565-4577`) sets only `status`. Its name and the client (which passes only status) strongly imply this. **Needs verification** against the deployed function source. If it re-normalizes the flags on accept, write-escalation is blocked but the read-escalation (escalate-while-pending → accept → read all months) still holds. Either way C-1's `WITH CHECK` fix is required.

#### U-3 — Recovery-key entropy is a runtime constant set to a TESTING value (20 bytes / 160-bit)
`passwordCryptoService.js:187` ships `RECOVERY_KEY_BYTES: 20` with a comment inviting reduction "easier to type" and instructing 32 for prod. The 20-byte path is **live** (onboarding `keyManagementService.js:396` → `createIdentityBackup` → `recovery_encrypted_data`). **As shipped it is NOT exploitable** — a 160-bit *random* value behind PBKDF2-600k is infeasible to brute-force, and the server can't influence a client build-time constant. It is a **structural footgun** (security-critical entropy as a casually-editable convenience constant with no floor, comment actively inviting reduction; no CI/runtime guard). **Verdict:** LOW as an exploitable issue (the originally-filed MEDIUM overstates a non-existent present exploit), but it is a real prod-readiness liability — see Section 5. **Human decision:** confirm prod value is 32 and add a hard floor before assessment.

---

## 4. Prioritized Remediation Roadmap

### Phase 0 — Pentest blockers (do before any external assessment)
1. **C-1:** Add `WITH CHECK` to both `data_shares` UPDATE policies; REVOKE table-wide UPDATE, grant `UPDATE(status)` only; owner flag-mutation via DEFINER RPC. Add regression test. *(verify U-2 in passing.)*
2. **H-1:** Enforce X25519 IK pin in the responder X3DH branch (resolve via `_getPinnedPeerKey`, byte-equal, fail-closed; TOFU-pin on first contact; bind IK↔IK_sig). Regression test.
3. **H-2:** Wire `enforcePasswordStrength` into signup/reset (client + server); raise the bar (len≥12, zxcvbn, breached-list). Plan Argon2id migration + recovery-key-derived backup.
4. **H-3:** Server-authoritative entitlement: effective-entitlement formula, pg_cron trial-expiry, DEFINER entitlement gate on `messages` INSERT.
5. **H-4:** Pin recipient key via `_getPinnedPeerKey`; replace anonymous box with authenticated static+ephemeral + context binding (`owner_id`/`recipient_id`/`dek_version`/`share_id`). Gate test.

### Phase 1 — High-value hardening (fix before or immediately after Phase 0)
6. **H-5:** Remove `script-src 'unsafe-inline'` (refactor inline handlers/scripts → external + addEventListener; nonce/strict-dynamic). Fix U-1 `att.id` coercion.
7. **H-6:** Encrypt attachment `file_name`/`mime_type`; bucket `file_size`.
8. **M-3:** Completion-based webhook idempotency + handlers that fail loudly + reconciliation cron.
9. **M-6:** Authorize `user-lookup`; scope `identity_keys` SELECT.
10. **M-2:** Rate-limit `claim_one_time_prekey`; harden OPK enumeration; server-side replenish.

### Phase 2 — Medium privacy/authz
11. **M-7:** Real framing headers via header-capable host (+ interim frame-buster).
12. **M-8 / M-9:** Pad budget and message plaintext to fixed buckets (version-gated).
13. **M-10:** Scope `field_locks` SELECT; strengthen insert WITH CHECK; reconcile schema before field locking ships.
14. **M-4:** Validate `newPlanId` (latent until a third plan exists — fix before adding one).
15. **M-5:** Relationship check + rate limit on `create_notification`.

### Phase 3 — Low / defense-in-depth / hygiene
16. L-2/L-3/L-4 (pairing): ship pg_cron reaper in-schema, tighten TTL, atomic server-side attempt counter, consider PAKE pairing.
17. L-6 (SRI + KAT self-test), L-5 (safety-number bias), L-7/L-8 (escape email + error strings), L-10/L-11/L-12/L-13/L-15 (oracle/error/CORS/config/comment fixes), L-9 (enumeration), L-1 (downgrade telemetry), L-14 (document metadata residuals; restrict WAL access).

---

## 5. Testing-Only Weakenings That MUST Revert for Production

These are confirmed in-code testing/convenience values or unenforced policies that materially weaken security and must be corrected (and ideally guarded by a CI/startup assertion so they cannot silently regress) before the external assessment:

1. **`RECOVERY_KEY_BYTES = 20` (testing value).** `auth_db/encryption/services/passwordCryptoService.js:187`. The comment explicitly instructs **32 for production**. Set to 32 (256-bit), add a startup assertion (`throw if < 32`) and a unit test asserting the floor so a future "easier to type" reduction fails the build. Re-mint backups created under the test value. *(See U-3.)*

2. **Strong-password policy defined but NEVER enforced.** `enforcePasswordStrength`/`validatePasswordStrength` (`passwordCryptoService.js:307, 273`) have zero call sites; the only gate is length≥8. This is the load-bearing weakness behind H-2 (offline-brute-forceable identity backup). Must be wired into signup/reset (client + server) for prod. *(This is not merely a testing knob — it is a missing control, but it belongs on the must-revert-before-prod list.)*

3. **pg_cron reapers documented but not shipped in-schema.** Pairing-request expiry (`add-device-pairing.sql:28-31`) and trial-expiry downgrade (H-3) rely on operator-managed cron that the migrations only describe in comments. For prod, the deletion/downgrade jobs must actually exist; absence silently extends the at-rest pairing-ciphertext window (L-2/L-3) and leaves expired trials on Premium forever (H-3).

4. **(Confirm, not yet observed reduced in prod) `PAIRING_CODE_BYTES = 10` (80-bit).** Adequate today, but the same "convenience reduction" footgun as the recovery key (`devicePairingService.js:29`). Keep ≥80 bits; add a floor assertion.

5. **`script-src 'unsafe-inline'`** is a development convenience for inline handlers/scripts and must be removed for prod (H-5) so any injection cannot escalate to key theft.

---

## Appendix — Positively Verified Controls (do not re-chase)

Re-traced and confirmed **NOT exploitable**; recorded so the red team does not waste cycles:
- **Stripe webhook signature:** `constructEvent` on the raw body runs before any handler dispatch — forged events cannot grant Premium.
- **IDOR on `create-portal-session` / `list-invoices` / `update-subscription`:** identity from `auth.getUser(jwt)`; Stripe customer/subscription id always read from the caller's own row, never the body.
- **Checkout price/amount/plan:** set server-side from `subscription_plans`; client supplies only origin-validated URLs.
- **Server-authoritative entitlement writes:** `REVOKE INSERT, UPDATE ON subscriptions FROM authenticated` + SECURITY DEFINER RPCs (`start_trial`/`downgrade_to_free`/`ensure_subscription`) each re-asserting `auth.uid()`; `start_trial` blocks trial reuse; no RPC can reach paid Premium (only the service-role webhook can).
- **OPK consumption** is RPC-gated (own-row DELETE is scoped; cross-user drain is the rate-limit gap M-2, not a direct DELETE).
- **CORS** on the four user-facing functions uses a strict `Set`-based allowlist with `Vary: Origin`.
- **The two edge-function copies** (`backend/edge-functions` vs `supabase/functions`) are byte-identical (drift risk only — add a CI diff guard).

---

*End of report.*
