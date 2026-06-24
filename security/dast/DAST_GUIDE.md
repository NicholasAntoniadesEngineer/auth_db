# DAST Guide — pointing live scanners at the platform

**Date:** 2026-06-24
**Scope:** the deployed GitHub Pages clients + the shared Supabase project
(PostgREST `/rest/v1`, Auth `/auth/v1`, Storage `/storage/v1`, Realtime, Edge
Functions `/functions/v1`).
**Companion:** `rls_abuse_probe.mjs` (the targeted RLS cross-user probe in this
directory). This guide covers the broader off-the-shelf DAST: OWASP ZAP at the
client + sqlmap / generic probing at PostgREST.

> **Architecture reality check.** This is a "thick client, thin trusted server"
> design: the browser holds all crypto keys and the anon Supabase key is **public
> by design**. The entire server-side authorization boundary is **Postgres RLS +
> column grants + SECURITY DEFINER RPCs**. So the single most important DAST
> target is **"can one authenticated user reach another user's rows / RPCs."**
> That is what `rls_abuse_probe.mjs` automates; ZAP/sqlmap cover the surrounding
> surface. Spend your scanner budget on the REST/RPC boundary, not on hunting
> classic server-rendered injection (there is almost no server-rendered HTML).

---

## 0. Prerequisites

- Two throwaway accounts (attacker + victim), each with a little seeded data.
- Their access-token JWTs and user-ids (see the header of `rls_abuse_probe.mjs`
  for the exact browser-console snippet).
- The project URL + anon/publishable key (already in the shipped client:
  `database/config/supabaseConfig.js` → `PROJECT_URL`, `PUBLISHABLE_API_KEY`).
- **Authorization to test the live project.** Coordinate timing — the trial-expiry
  cron and Realtime are live; do not flood production.

Run the targeted probe first — it is the highest-signal, lowest-noise check:

```bash
SUPABASE_URL="https://<ref>.supabase.co" \
SUPABASE_ANON_KEY="sb_publishable_..." \
ATTACKER_JWT="<attacker access_token>" \
VICTIM_USER_ID="<victim uuid>" \
VICTIM_MESSAGE_ID=... VICTIM_USER_MONTH_ID=... VICTIM_POT_ID=... \
VICTIM_SHARE_ID=... ATTACKER_USER_ID=... \
node auth_db/security/dast/rls_abuse_probe.mjs
```

---

## 1. OWASP ZAP against the deployed Pages site

### Setup
- Target: the GitHub Pages origin(s) (e.g. `https://<user>.github.io/<repo>/`).
  Each app (auth, messaging, payments, budget, pots, notifications, settings) is a
  separate set of static views — enumerate them all.
- **Authenticated scanning:** ZAP must carry a real session. The app uses Supabase
  Auth tokens in `localStorage` (key `sb-<ref>-auth-token`) and sends them as the
  `Authorization: Bearer` + `apikey` headers on every `fetch` to `/rest/v1`. Two
  options:
  1. **Replacer / header-injection:** add a ZAP *Replacer* rule injecting
     `Authorization: Bearer <jwt>` and `apikey: <anon>` on requests to the
     `*.supabase.co` host, so the active scan exercises authenticated REST.
  2. **Browser-recorded context:** drive the app with ZAP's HUD / a recorded
     Selenium/Playwright login, let ZAP capture the real XHRs, then spider/active
     scan from that authenticated context.

### What to scan
- **Passive scan** every page: missing security headers (expect the documented
  gaps — `frame-ancestors` inert via `<meta>` on Pages, `style-src 'unsafe-inline'`
  retained; confirm `script-src` is locked down — see `KNOWN_ACCEPTED_RISKS.md`),
  cookie flags (the app uses localStorage, not cookies), CSP correctness, mixed
  content, info leaks in responses.
- **Active scan** the client routes for **DOM XSS** specifically — this is the
  scenario that matters because an XSS can *use* the in-memory unwrapped identity
  key (it cannot export the non-extractable WebCrypto wrap key, but it can decrypt
  in place and exfil plaintext). Feed payloads through every place user-controlled
  text is rendered: message bodies (decrypted client-side), pot/budget names,
  display names, share messages, notification messages.
- **CSP validation:** confirm the live response CSP matches the repo
  (`script-src 'self' https://js.stripe.com` with NO `unsafe-inline`). Flag the
  stale `payments_app/payments/views/subscription.html` if that standalone app is
  deployed — its `script-src` still has `'unsafe-inline'`.
- **Spider** the `/functions/v1/<name>` edge endpoints (user-lookup,
  delete-account, checkout-session, customer-portal/create-portal-session,
  stripe-webhook, update-subscription, list-invoices) and fuzz their request
  bodies / auth handling.

### ZAP limits here
- ZAP's value is the **client + header/CSP/XSS** surface. It will NOT meaningfully
  test RLS row-ownership logic (that needs two identities and semantic assertions —
  use `rls_abuse_probe.mjs`). It cannot reason about the crypto protocol at all.
- ZAP active scan can be noisy against a live Supabase project (rate limits,
  Realtime). Throttle it.

---

## 2. sqlmap / generic probing at PostgREST

### Important: this is NOT a classic SQLi target
PostgREST builds parameterized queries; user input arrives as **PostgREST filter
operators** (`?col=eq.val`, `?col=ilike.*x*`) and JSON RPC args, not as raw SQL
string concatenation. Pointing sqlmap at `?id=eq.1` will almost certainly find
nothing via classic injection — and that is expected, not reassuring. Use sqlmap
mainly to **confirm the absence** of injection in the few places raw text reaches
SQL, and spend real effort on the PostgREST-specific abuse below.

### How to run sqlmap (confirmatory)
- Capture an authenticated REST request (e.g. a `GET /rest/v1/messages?...`) with
  its `apikey` + `Authorization` headers, save as a request file, and run:
  ```bash
  sqlmap -r req.txt --headers="apikey: <anon>\nAuthorization: Bearer <jwt>" \
         --batch --level=3 --risk=2 --dbms=postgresql
  ```
- Target the filter values and any RPC JSON arg that flows into a `LIKE`/`ilike`
  or a function body. The DEFINER functions use parameterized SQL and pinned
  `search_path`, so the realistic injection surface is tiny — but
  `resolve_user_id_by_email`'s `lower(trim(p_email))` path and any RPC that
  string-builds are worth a focused look.

### PostgREST-specific abuse to do BY HAND (sqlmap won't)
1. **Filter-bypass / over-broad selects:** try `select=*`, embedded resource
   expansion (`select=*,conversations(*)`), `or=(...)` filters, and large
   `limit`/`offset` to see if RLS still scopes every path. PostgREST resource
   embedding can traverse FKs — confirm RLS holds across an embedded join (e.g.
   `messages?select=*,conversations(*)`).
2. **Vertical access / RPC enumeration:** enumerate `/rest/v1/rpc/<fn>` for every
   function and call each cross-user (the probe covers the main ones; also try
   `downgrade_to_free`, `ensure_subscription`, `increment_attachment_download_count`,
   `is_premium_active`, `is_blocked`, `cleanup_expired_attachments`,
   `expire_overdue_trials` — the last two should be service-role-only).
3. **Mass-assignment on INSERT/UPDATE:** POST extra columns the policy/grant should
   ignore (e.g. set `user_id`, `owner_user_id`, `from_user_id`, `read`,
   `downloaded_count`, `enc_version`) and confirm the column GRANT / WITH CHECK
   rejects them.
4. **Storage:** hit `/storage/v1/object/list/message-attachments` and
   `/object/public/...` to confirm the bucket is private and object keys
   (`<conversationId>/...`) are not world-readable.
5. **Auth oracles:** probe `/auth/v1` (signup/login/reset) and the user-lookup
   edge function for email-existence oracles and the per-caller rate limit.

### sqlmap limits here
- Will not find RLS logic flaws (authorization, not injection).
- Will not exercise the crypto.
- Likely reports "not injectable" everywhere — interpret that as "PostgREST
  parameterizes," not "the API is safe."

---

## 3. What live DAST still does NOT cover (hand off elsewhere)

- **The bespoke crypto protocol** (X3DH / Double Ratchet / seals). No scanner
  reasons about FS/PCS, AD binding, nonce reuse, or domain separation. → human
  cryptographer, scoped in `CRYPTO_REVIEW_BRIEF.md`.
- **Concurrency / TOCTOU** (OPK claim races, share accept races, trial sweep) — DAST
  is single-threaded request/response; write a concurrent harness if you want this.
- **Realtime channel authorization** — confirm a subscriber on
  `conversation_id=eq.N` cannot subscribe to a conversation they are not in (the
  `REPLICA IDENTITY FULL` + RLS combination); this needs a Realtime client, not ZAP.
- **Edge-function secrets / Stripe webhook signature** verification under forged
  events — exercise `stripe-webhook` with an unsigned/replayed event and confirm
  the idempotency table (`stripe_webhook_events`) + signature check reject it.

---

## 4. Triage mapping

| DAST signal | Where it maps |
|---|---|
| Cross-user row read/write succeeds | RLS hole — CRITICAL; `rls_abuse_probe.mjs` FAIL |
| `subscriptions` client-writable | entitlement bypass — CRITICAL |
| DEFINER RPC acts cross-user / forges type | RPC authz hole — HIGH/CRITICAL |
| DOM XSS in decrypted content | key-use / plaintext exfil — HIGH |
| Public storage bucket / listable keys | attachment exposure — HIGH |
| Missing/weak headers on Pages | mostly the accepted L-2/L-4 infra items — LOW (confirm against `KNOWN_ACCEPTED_RISKS.md`) |
| sqlmap "not injectable" | expected (PostgREST parameterizes) — INFO |
