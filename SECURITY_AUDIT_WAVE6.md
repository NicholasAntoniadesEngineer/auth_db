# Security Audit — Wave 6

**Date:** 2026-06-24
**Auditor persona:** Senior offensive-security engineer (crypto-formal / config-as-code / supply-chain / privacy lens)
**Scope:** auth_db, secure_db, payments_app, messaging_app, money_tracker (shared Supabase, vanilla JS + window.* globals, GitHub Pages, vendored TweetNaCl, IndexedDB keys wrapped under non-extractable WebCrypto AES-GCM)
**Attacker model considered:** malicious authenticated user, malicious peer, MITM, and a curious/compromised server (zero-knowledge must hold against the server)
**Method:** READ-ONLY review of committed state + working trees. Re-verified prior fixes against datasheet/spec/code rather than trusting the fixed-list.

---

## 1. Verdict

**QUIET — zero new CRITICAL, zero new HIGH.**

The platform is genuinely well-hardened after 5 prior waves. I re-derived the core trust boundaries from scratch and could not find a new exploitable CRITICAL/HIGH:

- **X3DH** (`auth_db/encryption/services/x3dhService.js`): fail-closed SPK-signature verification before any DH, TOFU-pinned IK_sig binding, domain-separated KDF, correct four-DH order, OPK-optional. Sound.
- **Double Ratchet** (`auth_db/encryption/services/doubleRatchetService.js`): irreversible chain KDFs (salt=CK), header authenticated via HKDF-salt folding with an explicit guard against the empty-salt context fallback, MAX_SKIP + MAX_SKIPPED_TOTAL bounds, invariant attachment root AK0 from SK. Sound.
- **Cross-user DEK seal** (`money_tracker/shared/services/budgetCryptoService.js:321-492`): authenticated static+ephemeral box, context-bound HKDF info (owner/recipient IK + ids + dek_version + share_id), pinned-sender verification on unseal, legacy/anonymous seals rejected. Holds against a curious server (key substitution and forged/lifted seals all fail closed). Sound.
- **RLS** (auth_db / secure_db / money_tracker SQL): every mutating policy carries a WITH CHECK; column-scoped GRANTs on conversations/messages/data_shares/pairing_requests; OPK pool no longer enumerable (own-row SELECT); claim/email resolvers are rate-limited DEFINER RPCs with append-only audit ledgers and no `authenticated` grants. Sound.
- **Premium entitlement** is server-authoritative (`is_premium_active()` DEFINER, fail-closed when subscriptions schema absent) and gates `data_shares` owner-INSERT; messaging is intentionally FREE.
- **Stripe webhook** (`payments_app/.../stripe-webhook/index.ts`): signature-verified, completion-based idempotency (re-runs inFlight, 500s on handler failure for Stripe retry), downgrade plan re-validated as a true price decrease. `checkout-session` derives identity from the verified JWT and hard-codes the Premium plan server-side (no client plan injection).
- **CSP**: 17/17 *deployed source* pages use `script-src 'self' https://js.stripe.com` (no script `unsafe-inline`/`unsafe-eval`); `style-src 'unsafe-inline'` is the known-accepted residual.
- **Supply chain**: no production npm deps (build-only tailwind/vite, not shipped); vendored `nacl-fast.min.js`/`nacl-util.min.js` are byte-identical across apps; wrap-at-rest uses a non-extractable AES-256-GCM key with per-call random IV.
- **Duplicated payments edge functions** (`backend/edge-functions/*` vs `supabase/functions/*/index.ts`): byte-identical, no drift.

---

## 2. New findings by severity

### MEDIUM

**W6-M1 — H-5 (CSP script `unsafe-inline` removal) is UNCOMMITTED on the standalone payments_app; the committed HEAD + submodule mirrors still ship the weaker CSP.**

- **Attacker model:** any party able to inject markup/script into the payments subscription page (stored/reflected XSS, a compromised first-party asset, or a malicious dependency on that page). `script-src 'unsafe-inline'` removes the CSP layer that would otherwise block inline-script execution on a page that loads Stripe.js and runs the checkout flow.
- **file:line:**
  - `payments_app/payments/views/subscription.html` — **committed HEAD `b361221` still contains** `script-src 'self' 'unsafe-inline' https://js.stripe.com` and an inline `<script>` font-scale block. The H-5 fix (externalize the inline scripts + drop `unsafe-inline`) exists only in the **working tree** (`git status`: ` M payments/views/subscription.html`), and its two extracted files `payments/views/subscriptionFontScale.js` and `payments/views/subscriptionPageInit.js` are **untracked (`??`)** — i.e. never committed.
  - Submodule mirrors pinned to that committed HEAD therefore also carry the weak CSP:
    - `money_tracker/lib/payments_app/payments/views/subscription.html`
    - `messaging_app/lib/payments_app/payments/views/subscription.html`
    - `money_tracker/lib/messaging/lib/payments_app/payments/views/subscription.html`
- **Repro:**
  1. `cd payments_app && git show HEAD:payments/views/subscription.html | grep script-src` → shows `'unsafe-inline'`.
  2. `git status --short` → `M payments/views/subscription.html`, `?? subscriptionFontScale.js`, `?? subscriptionPageInit.js`.
  3. A clean checkout / GitHub-Pages deploy of payments_app at HEAD serves the `unsafe-inline` CSP **and** would 404 the un-committed external scripts (functional breakage of the font-scale + page init).
- **Impact:** Regression of a previously-claimed-fixed (H-5) hardening on one deployed surface. Defense-in-depth loss, not a directly-exploitable bug — there is no confirmed injection sink on this thin Stripe-redirect page, which is why this is MEDIUM and not HIGH. The money_tracker and messaging_app apps each serve their **own** committed subscription.html (both clean: `script-src 'self' https://js.stripe.com`) and route to their own tree, so the budget/messenger deployments are unaffected; only the **standalone payments_app deployment** is exposed.
- **Remediation:**
  1. Commit the working-tree change to `payments_app/payments/views/subscription.html` **and** `git add` + commit the two new files `subscriptionFontScale.js` / `subscriptionPageInit.js` (untracked files are the load-bearing half — without them the committed CSP-fixed page is functionally broken).
  2. Bump the `lib/payments_app` submodule pointer in money_tracker and messaging_app (and the nested `money_tracker/lib/messaging/lib/payments_app`) to the new payments_app commit so the mirrors stop shipping the stale CSP.
  3. Add a CI gate asserting no shipped HTML contains `unsafe-inline`/`unsafe-eval` in `script-src` (the existing live-config checks should grep the committed content, not the working tree).

---

### LOW

None new.

---

## 3. Prior fixes found incomplete / bypassable

- **H-5 (CSP — remove script `unsafe-inline`, "now incl payments subscription pages"):** INCOMPLETE for the standalone payments_app. The fix to its subscription page is present only as an uncommitted working-tree edit with two untracked support files; the committed HEAD (b361221) and all `lib/payments_app` submodule mirrors still ship `script-src 'self' 'unsafe-inline'`. See **W6-M1**. (The money_tracker and messaging_app first-party copies ARE committed-clean — so the headline "committed" claim holds for those two apps but not for payments_app.)

No other prior finding (C-1, H-1..H-4, H-6, W2-1, W3-1..3, L-1, M-2..M-5, F-1) was found incomplete or bypassable. Each was re-verified against the current code/spec and stands.

---

## 4. Uncertain items

- **`EXCEPTION WHEN OTHERS ... RETURN ... SQLERRM`** in `claim_one_time_prekey`, `resolve_user_id_by_email`, `resolve_email_by_user_id` (auth_db backend SQL) returns raw `SQLERRM` to the caller. The resolvers are service_role-only (edge function), so reachability by an end user is limited; `claim_one_time_prekey` is `authenticated`-callable and could surface internal SQL error text. Low-value info leak; flagged as uncertain (not confirmed exploitable, no secret content reachable through these paths). Worth tightening to a generic error string if a pentester probes it.
- **`pairing_requests` / `opk_claim_audit` / `user_lookup_audit` physical reaping** depends on an operator-set `pg_cron` job (RLS only hides expired rows). This is documented as load-bearing operator config; whether the cron is actually scheduled in the live project is outside a read-only source review.

---

## 5. Residual known-accepted

- `style-src 'unsafe-inline'` across all pages (inline `style=` attributes / `<style>` blocks). Style injection only; no script execution. Accepted.
- Recovery-key length pinned at 20 (testing) with a documented prod gate. Accepted per prior waves.
- TOFU (trust-on-first-use) for peer identity keys — no out-of-band verification UI. Accepted design choice for this threat model.
- CSP enforced via `<meta http-equiv>` only (no HTTP response header — GitHub Pages cannot set headers). `frame-ancestors` is meta-ignored; anti-framing is best-effort. Accepted constraint of the hosting platform.

---

## Summary for orchestrator

The platform is QUIET at the CRITICAL/HIGH bar. The single concrete deliverable is a hygiene/config-as-code regression: commit the already-written H-5 CSP fix (plus its two untracked support files) for the standalone payments_app and re-pin the submodule mirrors.
