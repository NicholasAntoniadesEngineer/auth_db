# Functional Regression Review — Post-Hardening Sweep

Scope: auth_db, secure_db, payments_app, messaging_app, money_tracker.
Lens: CORRECTNESS only (did the security-hardening pass break a normal user flow?), READ-ONLY.
Date: 2026-06-24.

---

## 1. Overall FUNCTIONAL verdict

**Core flows are largely intact. No confirmed BLOCKER (no core flow is dead for a single-tab user on a fresh install).** The CSP externalization (H-5) was done carefully — every page-init file is `defer`'d, every `getElementById(...).addEventListener` target exists, tab/help/send/attachment controls are wired via real listeners or delegated listeners on static containers, no inline `on*` handlers remain in source HTML, and all 11 new external init files pass `node --check`. Auth (signup/login/recovery/tabs), budget load + E2E DEK bootstrap + dual-read, messaging send/realtime-receive (W3-1), attachments send/receive (H-6/W3-2 with legacy fallbacks), sharing create (premium-gated + email resolver), notifications (M-5 relationship gate), and pairing all trace clean end-to-end.

**One real MAJOR regression exists in the logout path (F-1):** `KeyStorageService.deleteDatabase()` can hang forever on an `onblocked` event (a second open tab / connection), and it is `await`ed *before* the redirect with no timeout — so logout gets stuck on "Signing out..." and never redirects. Plus two MINOR/latent issues (a DB RPC that NULL-clobbers vestigial columns, and an attachment-metadata display degradation when ratchet `AK0` is asymmetric).

---

## 2. Confirmed regressions (BLOCKER → MINOR)

### MAJOR-1 — Logout can hang forever (no redirect) when a second connection holds the key DB (F-1)
- **Broken flow:** Logout / sign-out.
- **Repro:** User has the app open in two tabs (or any code path still holds an open connection to the `MoneyTrackerEncryption` IndexedDB) → clicks "Sign Out" in one tab → button shows "Signing out…" and the page never redirects to auth. The session is half-torn-down (localStorage/in-memory already cleared) but the user is stranded on the current page.
- **Cause / file:line:**
  - `auth_db/encryption/services/keyStorageService.js:1634-1660` — `deleteDatabase()` returns a Promise that resolves only on `onsuccess` and rejects only on `onerror`. The `onblocked` handler (line 1656-1658) **only logs a warning** — it neither resolves nor rejects. When another connection is open, IndexedDB fires `onblocked` (not `onsuccess`), so the Promise stays pending forever.
  - `auth_db/shared/services/authService.js:794-802` — `await window.KeyStorageService.deleteDatabase()` is awaited unconditionally before the redirect. The `try/catch` here does NOT catch a *pending* promise (only a thrown/rejected one), and unlike the server-side `signOut()` (which uses a 2 s `Promise.race` timeout at lines 757-761) there is no timeout on this await.
  - `auth_db/shared/services/authService.js:836` — the redirect (`window.location.href = authPath`) sits *after* the hung await, so it never runs. The header's `.catch()` fallback (`shared/header/header.js:726`) also never fires (a hang is not a rejection).
- **Severity:** MAJOR (core flow, but conditional on a second open connection; single-tab logout works).
- **Why it's a regression:** Pre-F-1, logout did not `await` an IndexedDB *deletion*. F-1 introduced the awaited `deleteDatabase()` and thus the hang path.
- **Fix:** Make the wipe non-hanging and non-blocking for the redirect. Either (a) in `deleteDatabase()`, have `onblocked` also `resolve()` (the delete is queued by the browser and completes once connections close — logout should proceed), or (b) wrap the await at authService.js:797 in a `Promise.race([..., timeout(~1500ms)])` exactly like the server sign-out, so a blocked delete can never strand the redirect. Option (a) is preferred (deletion still eventually happens); ideally do both.

### MINOR-1 (latent) — `update_share_grants` RPC NULL-clobbers `data_shares.year`/`month` on every share update (C-1)
- **Broken flow:** Updating an existing data share (owner edits months/access on a share that already exists).
- **Repro:** Owner re-shares / edits an existing share → client calls `update_share_grants(p_share_id, p_can_edit, p_share_all_data)` with only 3 args → RPC's UPDATE sets `year = p_year, month = p_month` with **no `COALESCE`** while both default to NULL.
- **Cause / file:line:** `money_tracker/database/setup/fresh-install-complete.sql:1115-1122` — `can_edit`/`share_all_data` use `COALESCE(...)` but `year`/`month` are written raw (`year = p_year, month = p_month`), and the client (`auth_db/database/services/databaseService.js:3124-3131`) never passes `p_year`/`p_month`, so they are always NULL.
- **Why it is only MINOR / latent (not MAJOR):** The actual share scoping is driven by the `shared_months` JSONB column (`money_tracker/database/services/dataSharingService.js:_isMonthInSharedList`); the read/permission path never reads `share.year`/`share.month` (verified: zero references). The client INSERT also never populates year/month, so they are NULL throughout and NULL→NULL is a no-op today. It is a footgun only if year/month scoping is ever revived.
- **Fix:** Add `COALESCE` to the RPC: `year = COALESCE(p_year, year), month = COALESCE(p_month, month)` — matching the can_edit/share_all_data pattern — so a 3-arg call cannot wipe scope columns.

### MINOR-2 — Attachment metadata (filename/type/exact size) shows a generic placeholder when ratchet `AK0` is asymmetric (H-6 + W3-2)
- **Broken flow:** Viewing a received attachment's filename / MIME / exact size (the file download itself still works).
- **Repro:** Sender's conversation ratchet state has an invariant attachment root `AK0`, recipient's does not (e.g. session established via a path that didn't seed AK0) → recipient's `getSessionKey(conversationId, {attachmentPath})` falls into the **legacy (no-AK0) branch** and derives a different key than the sender used → `_decryptMetadata` auth-fails → `_resolveMetadata` falls back to the now-NULL legacy plaintext columns → attachment renders as "Attachment" / `application/octet-stream` / coarse bucket size instead of the real metadata.
- **Cause / file:line:**
  - `messaging_app/messaging/services/attachmentService.js:389-412` (`_resolveMetadata` fallback) + `:335-352` (`_encryptMetadata` always uses the bound key).
  - `auth_db/encryption/services/keyManagementService.js:2013` — bound derivation is taken only when `state.AK0` is present; otherwise the legacy RK-rooted derivation is used. Metadata has no second (legacy) decrypt attempt — only the *file key* (`_decryptFileKey`, attachmentService.js:509-534) tries bound-then-legacy.
- **Severity:** MINOR (file content still downloads via the file-key bound→legacy fallback; only the display metadata degrades, and only when AK0 differs between peers). H-6 intentionally removed the plaintext columns, so there is nothing to fall back to.
- **Fix:** Mirror `_decryptFileKey`'s bound→legacy retry inside `_decryptMetadata`/`_resolveMetadata` (try the AK0-bound key, then the legacy session key) so metadata decrypts in the same cases the file key does. Confirm both peers seed `AK0` for all newly established sessions.

### MINOR-3 (deployment-dependent) — Share-grant flag may silently not persist if `update_share_grants` is not deployed
- **Broken flow:** "Share all data" toggle persistence on an updated share.
- **Repro:** `update_share_grants` RPC not deployed (or errors) → `_applyShareGrants` swallows the failure (best-effort, never throws), sets `share.share_all_data` only on the in-memory object → on next reload the recipient sees the un-updated grant.
- **Cause / file:line:** `auth_db/database/services/databaseService.js:3124-3143` (`_applyShareGrants` is best-effort) + `:3945`, `:4023` (UPDATE path relies entirely on the RPC for `share_all_data`, since C-1 withholds it from the direct UPDATE column-grant).
- **Severity:** MINOR and conditional on a missing migration (the function IS defined in `fresh-install-complete.sql:1085`); new-share INSERT still writes `share_all_data` directly so first-time shares are fine.
- **Fix:** None needed if the migration is applied; optionally surface a warning to the user when the RPC reports failure rather than only `console.warn`.

---

## 3. Flows confirmed SOUND end-to-end

- **Auth — signup / login / tabs / recovery / reset (H-2, H-5).** `authPageInit.js` is `defer`'d; `runInit()` runs after parse with a `DOMContentLoaded`-already-fired guard (money_tracker `auth/views/authPageInit.js:798-805`). All 9 top-level `getElementById(...).addEventListener` targets exist in `auth.html` (verified). Tab switching is wired (lines 75-93) and the programmatic `[data-tab="signin"].click()` (502/519) hits a real listener. **H-2 (min 12) is enforced on signup/reset only — sign-in checks only "non-empty" (`:412`), so existing short-password users are NOT locked out.**
- **Budget load + E2E (S2-S7, H-4).** Identity is provisioned at signup (`setupDeviceEncryption` → `generateAndStoreIdentityKeys`) and restored at login *before* redirect to landing/budget (`handlePostSignIn`), so `ensureBudgetDEK` → `getIdentityKeys` normally succeeds. `getAllMonths` wraps own-row `transformMonthFromDatabase` in per-row try/catch (`databaseService.js:1811-1817`), so one bad row never kills the page. The H-4 v2 seal fails closed on legacy seals, but unseal failure is caught per-share (`_unsealOwnerDekFromShare:3104`) and only skips the shared rows — the user's OWN budget is unaffected. `monthlyBudgetPageInit.js` uses `data-help-id` + `defer`; help modal binds correctly.
- **Messaging — send + realtime receive (W3-1).** Realtime no longer reads `newMessage.content`; it requires `encrypted_content` + `encryption_nonce` and routes through the ratchet, else shows a neutral placeholder (`messengerController.js` ~827). Column names match the write path (`messagingService.js:243-244`) and the batch read path (`:461`), and INSERT realtime payloads carry the full row, so genuine encrypted messages decrypt — no spurious "[Message unavailable]". messenger CSP includes `wss://*.supabase.co` for realtime.
- **Messaging — delegated message/attachment controls (W2-1, H-5).** Single delegated `click` listener on the static `#message-thread` (`messengerController.js` setupEventListeners), id-revalidated (`Number.isInteger && >0`), survives re-renders. No inline `onclick` remains; `#message-thread` exists in `messenger.html:54`.
- **Attachments — upload/download (H-6, W3-2).** `storage_path` is computed once and used for both the file-key wrap and metadata seal, then round-trips on download (consistent context binding). Schema makes `file_name/file_size/mime_type` NULLABLE and adds `encrypted_metadata/metadata_nonce/file_size_bucket` (`secure_db/sql/complete-setup.sql:538-542`), so the new metadata-free INSERT does not violate NOT NULL. File-key decrypt has a bound→legacy fallback. (Metadata-display caveat: MINOR-2.)
- **Sharing — create by email (C-1, premium gate, resolver RPC).** Client pre-checks `SubscriptionGuard.hasTier('premium')` and surfaces a clear "Premium subscription required" message (`databaseService.js:3804-3810`); not-found is handled (`:3816`). The new uniform resolver response (200 `{userId:null}` for not-found) is handled correctly by `findUserByEmail` (`:3649` null-check → `success:false`), and the old 404 path is still handled (`:3632`). New-share INSERT writes `share_all_data` directly (owner-owned row); UPDATE routes grant flags through the DEFINER RPC.
- **Payments — entitlement (H-3, is_premium_active).** Sharing is gated at the RLS layer via `is_premium_active(auth.uid())` which passes for active-Premium and live-trial users (`fresh-install-complete.sql:848-857`). **Messaging stays FREE** — the messages INSERT policy has no `is_premium_active` check (confirmed at `fresh-install-complete.sql:1795-1797`). (Sharing now requiring Premium is the *intended* entitlement change, not a regression.)
- **Notifications (M-5 relationship gate).** `create_notification` allows self + friends + data_share + conversation relationships in either direction, any status (`fresh-install-complete.sql:1640-1656`). Every genuine notify reason (friend_request/accepted, share_request/response, message_received) is preceded by the relationship row, and in `createDataShare` the conversation + share rows are created *before* the notification (`databaseService.js:3870/3967` then `:4174`), so the gate passes.
- **Pairing / multi-device + F-1 interaction.** F-1 wipes the key DB on logout, but `handlePostSignIn` restores the identity from the password backup *before* redirecting to landing, so `PairingGuard.requirePairing()` (landing) finds the restored keys and does not sign the user out. `PairingGuard`'s no-arg `KeyStorageService.initialize()` opens the same default DB name/version (`MoneyTrackerEncryption` v3) as the config-driven init (`keyStorageService.js:34,40` vs `moneyTrackerEncryptionConfig.js:38-39`) — no DB mismatch.
- **CSP fonts/icons.** Font Awesome and fonts are bundled locally (`lib/.../vendor/font-awesome`, `font-src 'self'`) — no CDN blocked by the tightened CSP. `connect-src` covers supabase (https+wss) and stripe; `frame-src`/`script-src` allow `js.stripe.com`.
- **Page-init syntax.** All 11 new `*PageInit.js`/init files pass `node --check`.

---

## RETURN SUMMARY

**Counts by severity:** BLOCKER 0 · MAJOR 1 · MINOR 3.

**Top regressions:**
1. **MAJOR — Logout hangs (no redirect) when a second connection holds the key IndexedDB.** `KeyStorageService.deleteDatabase()` `onblocked` neither resolves nor rejects (`auth_db/encryption/services/keyStorageService.js:1656`), and it is `await`ed before the redirect with no timeout (`auth_db/shared/services/authService.js:797` → redirect at `:836`). Fix: resolve on `onblocked` and/or `Promise.race` the await with a ~1.5s timeout (as the server sign-out already does). Conditional on multi-tab / lingering connection; single-tab logout works.
2. **MINOR — `update_share_grants` NULL-clobbers vestigial `year`/`month` on share update** (no `COALESCE`, `fresh-install-complete.sql:1118-1119`); harmless today (those columns are unused by the read path) but a latent footgun. Fix: COALESCE them.
3. **MINOR — Attachment metadata shows a generic placeholder when ratchet `AK0` differs between peers** (`_decryptMetadata` has no legacy fallback; H-6 removed the plaintext columns). File download still works. Fix: add the same bound→legacy retry the file key uses.

No core flow (auth, messaging, budget, sharing, payments, attachments, pairing, notifications) is dead end-to-end.
