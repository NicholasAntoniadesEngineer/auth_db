# Security Audit — Wave 3 (Adversarial: asset-flow / infrastructure / creative-chain lens)

**Scope:** auth_db (identity + E2E crypto + shared DB service + entitlement RPCs), secure_db (messaging schema/RLS), payments_app (Stripe edge functions), messaging_app (messenger client), money_tracker (budget client + budget E2E). Shared Supabase (Postgres + RLS + Auth + Realtime + Storage + Edge Functions). Vanilla JS, `window.*` globals, GitHub Pages, vendored TweetNaCl, client keys in IndexedDB wrapped under a non-extractable WebCrypto AES-GCM key.

**Attacker models in scope:** malicious authenticated user, malicious peer, MITM, and a **curious/compromised server** (the zero-knowledge claim must hold against the server itself).

**Mandate:** report only NEW, adversarially-verified, exploitable findings beyond prior waves. Out of scope (already confirmed, NOT re-reported): C-1 `data_shares` UPDATE missing `WITH CHECK`; H-1 responder X3DH trusts unpinned X25519 IK; H-2 `enforcePasswordStrength` never called; H-3 entitlement client-only; H-4 budget-DEK seal unpinned/unauthenticated/unbound; H-5 CSP `unsafe-inline`; H-6 attachment metadata plaintext; M-2 `claim_one_time_prekey` OPK drain; M-3 webhook idempotency on receipt; M-4 `update-subscription` `newPlanId` unvalidated; M-5 `create_notification` no relationship check; the recovery-key 20-byte testing value; and Wave-2 NEW-H1 (server-controlled attachment `id` interpolated into an inline `onclick`). Anything materially equivalent to these is excluded.

**Constraint:** READ-ONLY audit. No files modified.

---

## 1. Summary

**NEW issues confirmed this wave: 3** (1 HIGH, 2 MEDIUM) + 1 LOW carried as borderline + 2 UNCERTAIN items for human review.

This wave focused on the asset-flow / data-movement boundaries that prior waves touched only at the crypto-primitive level: the **realtime delivery path** (where the server, not the peer, frames the payload the client renders), the **attachment key-distribution chain** (a second, non-ratchet key model that rides alongside the message ratchet), and the **identity/lookup infrastructure**.

The headline NEW finding (W3-1, HIGH) is a **content-forgery / E2E-bypass in the realtime message handler**: the client renders a `content` field taken verbatim from the server-controlled realtime payload whenever the same payload also claims `is_encrypted=false`. The `messages` table has **no `content` column**, so that field can only ever be fabricated by the server/MITM — yet the client trusts it and renders it attributed to the peer's `sender_id`. This lets a compromised server inject arbitrary chosen "messages" from any peer into a victim's thread with no peer-crypto compromise, directly violating the zero-knowledge / message-integrity guarantee the design promises to hold against the server itself. It is distinct from prior findings (H-6 = confidentiality of metadata; NEW-H1 = an *attachment-id* injection sink): this is a **message-body integrity/spoofing sink on the live message path**.

**Posture delta:** Net-negative until W3-1 is fixed. The platform's prior-wave CRITICAL/HIGH backlog (C-1, H-1..H-6) still dominates, but W3-1 raises the *integrity* risk against the in-scope compromised-server model independent of any peer-key compromise, so it should be triaged alongside the existing HIGHs. W3-2 and W3-3 are correctness/availability and discovery-oracle issues that a serious red team will probe. No regression was introduced by this read-only wave.

---

## 2. Findings by Severity

### HIGH

#### W3-1 — Realtime message handler renders a server-fabricated plaintext `content` field on the `is_encrypted=false` fallback → peer-attributed message forgery / E2E bypass

**Attacker model:** Curious/compromised server, a malicious DB function, or a MITM that can shape the body of a Supabase Realtime `postgres_changes` event (the realtime payload is authenticated transport but is NOT end-to-end-integrity-protected — its fields are whatever the server emits). No peer crypto compromise and no victim action beyond *having the conversation open* are required.

**File:line:** `messaging_app/messaging/controllers/messengerController.js:797-798` (and the surrounding INSERT handler `:771-840`), rendered via `_appendMessageToThread` → `_renderMessage` (`:855-863`, body at `:1033-1035`). The same defect is present in every deployed copy of this controller (e.g. the vendored `money_tracker/lib/messaging/.../messengerController.js`).

```js
// Decrypt the message
let content = newMessage.content;                       // <-- server-controlled payload field
if (newMessage.is_encrypted && newMessage.encrypted_content) {
    // ... ratchet decrypt path ...
}
// content is then rendered as the peer's message body
```

**The hole:** `newMessage` is `payload.new` — a JSON object the server controls. The decrypt branch is gated on `newMessage.is_encrypted && newMessage.encrypted_content`. If the server emits a realtime INSERT payload with `is_encrypted: false` (or simply omits `encrypted_content`) **and** an attacker-chosen `content` string, the branch is skipped and `content = newMessage.content` is taken verbatim and rendered in the victim's thread, labelled with `newMessage.sender_id` (also server-chosen) and the peer's resolved email. Crucially, the real `messages` table has **no `content` column at all** (`secure_db/sql/complete-setup.sql:344-369`); legitimate sends always set `is_encrypted: true` (`messagingService.js:259`). So a `content` field on the wire is *by construction* something only a malicious/compromised server or MITM could introduce — the client has no legitimate reason to trust it.

**Repro:**
1. Victim has conversation `N` open with peer `P` (so the conversation channel `conversation:N` is subscribed, `messengerController.js:745`).
2. The compromised server emits a realtime `postgres_changes` INSERT on `messages` for conversation `N` with a fabricated payload:
   ```json
   { "eventType": "INSERT",
     "new": { "id": 999999, "conversation_id": N, "sender_id": "<P's uuid>",
              "is_encrypted": false, "content": "Wire the deposit to IBAN GB00…",
              "created_at": "2026-06-23T12:00:00Z" } }
   ```
3. Handler passes the conversation/identity filters (`:777`, `:782`, `:792` — `sender_id` is P, not the viewer), takes the `is_encrypted=false` branch, sets `content` to the fabricated string, and appends it as a genuine bubble from P.

**Impact:** A compromised server (explicitly in scope) can **inject arbitrary chosen messages attributed to any peer** into a victim's live conversation, with correct sender name/email and no "cannot decrypt" indicator. This defeats the message-*integrity* half of the E2E guarantee (the design's promise that the server cannot read **or write** the conversation) without touching any key. It enables high-impact social-engineering (fraudulent payment instructions, fake "I approve" messages) and undermines the entire trust model of a privacy-first messenger. Content is HTML-escaped (`_escapeHtml`, `:1035`), so this is **not** XSS — it is message forgery/injection, a separate and serious integrity class.

**Exploitability:** High for the in-scope compromised-server / response-shaping-MITM attacker. Single crafted realtime frame; no peer key compromise; victim only needs the thread open. The batch-history path (`messagingService.getMessages`, `:461-481`) is NOT affected — it never reads a plaintext `content` field and shows `[Message corrupted]`/`[Cannot decrypt]` instead — which makes the realtime fallback an inconsistent, exploitable outlier.

**Remediation:**
- On the realtime path, **never** read `newMessage.content`. Treat a realtime message as encrypted-only: require `encrypted_content` + `encryption_nonce` and route exclusively through `encryptionFacade.decryptMessage(...)`; if they are absent, render a neutral `[Message unavailable]` placeholder. Delete the `let content = newMessage.content;` seed and the `is_encrypted` short-circuit.
- Mirror the batch path's contract so both decrypt sites share one rule (the codebase already centralises the column→field mapping in `MessagingService.buildEncryptedData`; centralise the "must be encrypted" decision the same way).
- Defense-in-depth: ignore any realtime field that has no backing table column (`content`, and any other non-schema key).

---

### MEDIUM

#### W3-2 — Attachment key is derived from the *current* ratchet root key `RK`, which advances on every DH ratchet step → shared attachments become permanently undecryptable; file-key wrap is also unbound (no AAD/context)

**Attacker model:** (a) Reliability/availability: any normal use — a single Double-Ratchet DH step between upload and download silently breaks attachment decryption (no attacker needed; a malicious peer can *force* it by sending one message). (b) Integrity hardening: a compromised server that can move/relabel rows (bounded today by SM-30 immutability, so this leg is hardening, not a live exploit).

**File:line:** `auth_db/encryption/services/keyManagementService.js:1976-1993` (`getSessionKey` derives the attachment key from `state.RK`); used by `messaging_app/messaging/services/attachmentService.js:322-355` (`_encryptFileKey`) and `:364-387` (`_decryptFileKey`).

```js
// getSessionKey(): attachment key = HKDF(ikm = RK, info="MoneyTracker:Attachment:v1", salt = RK)
return await KeyDerivationService._hkdf(state.RK, 'MoneyTracker:Attachment:v1', 32, state.RK);
```

**The hole:** The Double Ratchet's root key `RK` is **rotated on every DH-ratchet step** (each time the peer sends with a new `ratchet_pub`). The attachment file-key is wrapped under `HKDF(RK)` at upload time, but the recipient re-derives it under whatever `RK` is current at download time. As soon as one ratchet step occurs between upload and the recipient's download, `getSessionKey` returns a key derived from a *different* `RK`, `decryptBytes` hits a Poly1305 failure, and `downloadAttachment` fails closed with "Download failed" — the attachment is now **permanently undecryptable for both parties**, even though the ciphertext and metadata are intact. The in-code comment claims "Both parties share RK after X3DH bootstrap, so both derive the SAME attachment key" — that is only true at the instant of bootstrap; it is false for the lifetime of an advancing ratchet. Separately, the file-key wrap (`encryptBytes(fileKey, sessionKey)`) binds **no associated data** — not the attachment id, conversation id, uploader, or storage path — so the wrap is context-free.

**Repro:**
1. Alice uploads an attachment in conversation `N`; the file key is wrapped under `HKDF(RK_t0)`.
2. Either party sends one or more normal messages that trigger a DH-ratchet step; `RK` advances to `RK_t1`.
3. Bob (or Alice on another device) opens the attachment; `getSessionKey` returns `HKDF(RK_t1)`; `_decryptFileKey` → `decryptBytes` fails; download is refused. The attachment is lost despite being within its 24h TTL.

**Impact:** Data-loss / availability defect in the E2E attachment layer (a "Premium" feature). For a forward-secret messenger this is a near-certain failure in real conversations (ratchet steps are routine), so attachment sharing is effectively unreliable. The missing AAD on the file-key wrap is a latent integrity weakness that is currently contained only by the SM-30 row-immutability RLS — if any future change re-introduces an attachment UPDATE path, the unbound wrap becomes a row-substitution vector.

**Exploitability:** The availability break is trivially reachable (and a malicious peer can guarantee it by sending one message after the victim uploads). The integrity leg is latent under current RLS.

**Remediation:**
- Derive the attachment-wrapping key from a **stable** secret, not the live `RK`. Options: keep the per-attachment random file key (already done) but wrap it under a key derived from the X3DH/initial-root secret that does *not* advance (e.g. a dedicated, persisted per-conversation attachment KEK minted once at session bootstrap), or seal the file key the same way budget DEKs are sealed (authenticated box bound to the recipient identity). Whatever the choice, encrypt-time and decrypt-time derivation MUST be over an invariant input.
- Bind associated data into the file-key wrap (conversation id + attachment storage path/id) so a wrapped key cannot be lifted onto another row.

---

#### W3-3 — `user-lookup` `findByEmail` enumerates the full auth user list in-function and answers as an account-existence oracle (no pagination, no rate limit)

**Attacker model:** Any authenticated user (the function requires a valid Bearer JWT, SM-20). It is a discovery/enumeration oracle, not an auth bypass.

**File:line:** `auth_db/backend/edge-functions/user-lookup.ts` — `handleFindByEmail` (`listUsers()` call + 200/404 split).

**The hole (two parts):**
1. **Existence oracle:** `findByEmail` returns HTTP 200 + `{userId}` when an email maps to an account and 404 `{error:"User not found"}` otherwise, with no throttling. Any logged-in user can iterate an email list and reliably learn which addresses have accounts on the platform (and obtain their stable user ids), enabling targeted phishing / social-graph seeding. The platform is privacy-first, so confirmable membership is a meaningful leak.
2. **Unbounded list pull + correctness:** the lookup is implemented as `supabaseAdmin.auth.admin.listUsers()` then a client-side `.find()`. `listUsers()` is **paginated and returns only the first page by default** (≈50 users), so on any deployment past one page the lookup both (a) silently fails to find legitimate users beyond page 1 (a correctness/availability bug for "start conversation by email") and (b) pulls a page of *all* users' records into the edge function on every lookup (broad data handling for a single-email query).

**Repro:** Authenticated caller POSTs `{action:"findByEmail", email:"victim@example.com"}` repeatedly with different addresses; 200-vs-404 reveals membership. Separately, with >50 users, a valid existing email on page 2+ returns 404.

**Impact:** Account-existence enumeration + stable-id harvesting (privacy leak, phishing enablement); plus a real "cannot start conversation with valid users" defect at modest scale and an over-broad admin-list read per query.

**Exploitability:** The oracle is straightforward and unthrottled. The pagination defect is deterministic at scale.

**Remediation:**
- Resolve the email server-side with a targeted query (e.g. a `SECURITY DEFINER` SQL function over `auth.users` filtered by normalized email, or the Admin API's filtered lookup) instead of `listUsers()` + client `.find()`; never page the whole user table for a single lookup.
- Add per-caller rate limiting on `findByEmail`. Consider returning a uniform response shape (and requiring the target to be a confirmed contact, or requiring the caller to already know the exact address) to blunt mass enumeration; at minimum, throttle and log.

---

### LOW

#### W3-4 — Attachment storage object names use `Math.random()` for the unguessable path component

**Attacker model:** Defense-in-depth only; current confidentiality rests on the per-conversation Storage RLS (`secure_db/sql/complete-setup.sql:636-680`), not on path secrecy.

**File:line:** `messaging_app/messaging/services/attachmentService.js:446-447` — `const randomId = Math.random().toString(36).substring(2, 10); const storagePath = \`${conversationId}/${timestamp}-${randomId}\``.

**The hole:** The object key's only non-deterministic component is `Math.random()` (not CSPRNG). The Storage RLS already scopes reads/writes to conversation participants, so this is not a confidentiality break today; but the path component is security-adjacent (it is the per-object identifier inside a guessable `conversationId` folder), and using a non-cryptographic RNG for a security-adjacent identifier is a latent weakness should any path-based control ever be relied on.

**Remediation:** Use `window.CryptoPrimitivesService.randomBytes(...)` (already the project's CSPRNG seam, used for file keys at `:289`) to generate the random path component.

---

## 3. Uncertain Items (for human review)

- **U-W3-1 — `update_share_grants` resets `year`/`month` to NULL on every call (not COALESCE).** `money_tracker/database/setup/fresh-install-complete.sql:1115-1120` writes `year = p_year, month = p_month` unconditionally, while `can_edit`/`share_all_data` use `COALESCE`. A client that calls the RPC to toggle a flag but omits year/month will silently widen the share's month scope to "all months" (NULL year/month + `share_all_data` semantics in `user_months_select_shared`). The owner-only gate holds, so this is not cross-user escalation, but it can unintentionally over-share the owner's own data via a partial RPC call. **Needs confirmation of how `DatabaseService._applyShareGrants` populates `p_year`/`p_month` on a flag-only update** before rating; likely LOW–MEDIUM correctness/over-share.

- **U-W3-2 — `conversations_insert_participant` allows creating a conversation pairing yourself with any arbitrary user (no consent/friendship/block precondition).** `secure_db/sql/complete-setup.sql:322-325`. The first message INSERT is block-checked (`is_blocked`, `:437`), so a *blocked* sender is stopped, but any non-blocking user can force a conversation row + an initial message (subject to the X3DH/ratchet succeeding) with anyone. This is plausibly an intended "start by email" UX rather than a vuln, and message INSERT is the real gate — flagging for a product/security decision on whether unsolicited first-contact should require a friend/contact relationship. Out of scope if it duplicates the M-5 "no relationship check" theme; included here only because it concerns the *conversation* table, not `create_notification`.

---

## 4. Prioritized Remediation

1. **W3-1 (HIGH)** — Remove the realtime plaintext-`content` fallback; require ciphertext + ratchet decrypt on the live message path (mirror the batch path). Highest leverage: closes a server-side message-forgery / E2E-integrity bypass with a few-line change, independent of CSP.
2. **W3-2 (MEDIUM)** — Re-root the attachment key on an invariant secret (not the advancing ratchet `RK`) and bind AAD into the file-key wrap. Restores attachment reliability and removes a latent integrity weakness in the "Premium" attachment feature.
3. **W3-3 (MEDIUM)** — Replace `listUsers()`+`.find()` with a targeted, paginated-safe email resolution and add rate limiting to `findByEmail` to blunt account enumeration / id harvesting.
4. **W3-4 (LOW)** — Switch the attachment storage-path random component to the CSPRNG seam.
5. **U-W3-1 / U-W3-2** — Confirm and rate the two uncertain items; fix `update_share_grants` to `COALESCE` year/month if the client can issue flag-only updates.

*Wave 3 adds W3-1..W3-4 to the active backlog; the prior-wave CRITICAL/HIGH items (C-1, H-1..H-6) remain open and continue to govern overall priority.*
