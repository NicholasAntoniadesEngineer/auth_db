# Known / Accepted Risks — pre-pentest

**Date:** 2026-06-24
**Scope:** auth_db (+ the shared platform it underpins: secure_db, payments_app,
messaging_app, money_tracker).
**Purpose:** an honest, concise register of items the team has consciously
ACCEPTED for the external pentest (with the rationale each is accepted for) and
the prod-revert items still TRACKED. This is not a list of unknown bugs — every
item here was traced and is understood. See `SECURITY_AUDIT.md` (full findings),
`SECURITY_AUDIT_CONFIRM.md` (L-1..L-4 convergence), and `SECURITY_AUDIT.md §5`
(prod-revert list).

---

## A. Accepted for the pentest (infra-constrained / low impact)

### L-2 — meta-tag `frame-ancestors` is inert on GitHub Pages (no clickjacking header)
- **What:** CSP is delivered via an HTML `<meta>` tag. Per the CSP spec,
  `frame-ancestors` (and `X-Frame-Options`) are **ignored when set via `<meta>`** —
  they only take effect as a real HTTP **response header**. GitHub Pages (the
  current host) cannot set custom response headers, so framing is not hard-blocked.
- **Why accepted:** pre-existing infrastructure constraint, not a code defect.
  `object-src 'none'`, `base-uri 'self'`, and `form-action 'self'` are in force;
  destructive/trust-establishing flows (pairing, share creation, recovery-key
  reveal, delete-for-everyone) sit behind in-app confirmation. Impact is
  UI-redress requiring a victim to interact with bait UI; no direct key read.
- **Mitigation (future):** front the apps with a host/edge that can set real
  headers (Cloudflare/Netlify) emitting `X-Frame-Options: DENY` +
  `Content-Security-Policy: frame-ancestors 'none'` (and `Referrer-Policy`,
  `X-Content-Type-Options`, HSTS). Interim option on Pages: a pre-paint
  frame-buster (`if (self !== top) top.location = self.location`) with body
  hidden until the check passes. Do NOT just add `frame-ancestors` to the `<meta>`
  CSP — it is spec-ignored there.

### L-4 — `style-src 'unsafe-inline'` retained
- **What:** the CSP keeps `style-src 'unsafe-inline'` (while `script-src` is
  locked down to `'self' https://js.stripe.com`, no `unsafe-inline`).
- **Why accepted:** inline `style=` attributes are pervasive across the views;
  removing `unsafe-inline` for styles would be a large refactor for little gain.
  With `script-src` locked down there is **no script-execution path** from a
  style injection — the worst case is cosmetic style injection, not code
  execution or key theft. Low risk.
- **Mitigation (future):** migrate inline `style=` to classes / external CSS, then
  drop `'unsafe-inline'` from `style-src` for defense-in-depth.

---

## B. Tracked prod-revert items (must be done before the pentest build)

These are deliberate TESTING values / planned hardening, not accepted-forever.
The JS-checkable ones are enforced by the standalone release gate:

```bash
node encryption/tests/prod_readiness_check.js   # must exit 0 to ship; FAILS today by design
```

(It is intentionally SEPARATE from the dev S0-S13 crypto suite so it never breaks
the normal/dev test run. See `README.md` → "Before the pentest".)

### Recovery-key entropy must be restored to 32 bytes (256-bit)
- `PasswordCryptoService.RECOVERY_KEY_BYTES` ships at **20** (testing value, "8
  elements", easier to type for multi-device testing). It is **not exploitable as
  shipped** (160 random bits behind PBKDF2-600k is infeasible to brute-force, and
  the server cannot influence a client build-time constant), but it is a
  prod-readiness footgun. **Action gated by the guard:** flip 20 → 32 in
  `encryption/services/passwordCryptoService.js` and re-mint backups minted under
  the 20-byte value. (SECURITY_AUDIT.md §5 item 1 / U-3.)

### Argon2id backup-KDF migration (L-3) — planned, not yet implemented
- The password-encrypted identity/recovery/session backups use **PBKDF2-SHA256
  (600k) + AES-256-GCM** — acceptable today (OWASP-current), but the team intends
  to migrate to memory-hard **Argon2id + a server-unknown pepper**. A concrete,
  versioned migration plan (kdf_version field, Argon2id params, dual-read during
  rollout, lazy re-encrypt, server-unknown pepper) is documented in the
  `enforcePasswordStrength` doc block in
  `encryption/services/passwordCryptoService.js` (pointer from
  `keyBackupService.js`). This is a larger change deferred PAST the pentest;
  PBKDF2 + the enforced 12-char strong-password policy is the interim control.
  (SECURITY_AUDIT.md H-2 / L-3.)

### Other §5 items (checked outside this JS guard)
- **pg_cron reapers** (pairing-request expiry, trial-expiry downgrade) must be
  shipped in-schema, not just described in SQL comments. (§5 item 3 / H-3 / L-2/L-3.)
- **`script-src 'unsafe-inline'`** has already been removed from `script-src`
  (H-5 CLOSED) — listed here only so the §5 set is complete. The remaining
  `style-src 'unsafe-inline'` is item L-4 above.
- **`PAIRING_CODE_BYTES`** must keep its ≥80-bit floor (checked by the guard).

---

## C. Other LOW/INFO residuals (documented, not blocking)
- Metadata-privacy residuals (message/budget ciphertext length, social-graph and
  timing leakage to the server) are inherent to the current design and tracked in
  `SECURITY_AUDIT.md` (M-8/M-9/M-10/L-14). "E2E hides content, not metadata";
  padding / sealed-sender are roadmap items.
- L-1 (getEmailById existence oracle) is **CLOSED** in this pass — hardened to
  parity with W3-3 (per-caller rate limit via the shared `user_lookup_audit`
  ledger + uniform 200 `{email|null}`); see `backend/sql/apply-email-resolver.sql`
  and `backend/edge-functions/user-lookup.ts`.
