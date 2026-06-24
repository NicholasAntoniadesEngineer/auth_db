# Residual Risk Register — pre-pentest (honest)

**Date:** 2026-06-24
**Scope:** auth_db + the shared platform (secure_db, payments_app, messaging_app,
money_tracker) on one Supabase project (Postgres + RLS + Auth + Realtime +
Storage + Edge Functions), vanilla-JS clients on GitHub Pages, bespoke TweetNaCl
crypto, client keys in IndexedDB wrapped under a non-extractable WebCrypto
AES-GCM key.
**Purpose:** a candid register of what the internal audits did **not** cover and
where real residual risk remains. This complements `KNOWN_ACCEPTED_RISKS.md`
(consciously-accepted items) — this file is about **blind spots and uncertainty**,
not a clean bill of health.

> **Read this first.** Internal audit waves (1–5, ~215 finder-agents) "came back
> quiet" on new CRITICAL/HIGH against the hardened state. That means **those
> lenses found nothing new** — it does **not** mean the system is impenetrable.
> Every wave was the same kind of reviewer (static reading by the same model
> family) looking at the same code. The most valuable findings tend to come from
> a *different* lens: a live runtime, a fuzzer, a human cryptographer, an
> attacker with two real accounts. That is exactly what the external pentest adds.

---

## (a) What the internal audits did NOT cover

These are categorical gaps in method, not specific bugs:

1. **No live DAST / runtime testing.** Every wave read source. Nothing was
   executed against the running PostgREST, the deployed Pages site, the edge
   functions, or Realtime. RLS was reasoned about from the `*.sql` text, never
   *probed* with two real JWTs. → Artifact 3 (`security/dast/rls_abuse_probe.mjs`)
   is the first runtime check, and it only covers the attacks we thought to write.
2. **No fuzzing.** No malformed-input fuzzing of the crypto wire format (the
   Double Ratchet header / X3DH preamble parsing in `doubleRatchetService.js` /
   `x3dhService.js`), the edge-function request bodies, or the PostgREST filter
   surface. Parsing/`base64` decode edge cases are untested under hostile input.
3. **Cannot see live config.** Static review cannot confirm RLS is actually
   enabled on the live tables, that the `subscriptions` REVOKE actually ran, that
   the storage bucket is private, or that the service-role key never shipped to
   Pages. → Artifact 1 (`LIVE_CONFIG_CHECKS.sql`) addresses the assertable parts;
   the bucket/key/Auth items remain MANUAL.
4. **Same-model monoculture → shared blind spots.** The audit waves were run by
   the same model family. Any class of bug that this family systematically does
   not "see" is invisible across *all* waves no matter how many agents — adding
   more same-model agents does not reduce that correlated error. An independent
   human/tool team is the intended decorrelation.
5. **Verification can false-negative.** A reviewer can read a vulnerable line and
   judge it safe (we have already caught audit *fixes* that would have introduced
   bugs — see MEMORY: "Re-verify audit findings"). "No finding" from a reviewer is
   evidence, not proof.
6. **Concurrency / TOCTOU under real load untested.** Logic like the OPK claim
   (`FOR UPDATE SKIP LOCKED`), the trial-expiry sweep, and the share accept/grant
   races were reasoned about, not stress-tested with concurrent clients.
7. **Supabase platform internals are out of scope.** GoTrue (Auth), the Realtime
   server, Storage, and PostgREST themselves are trusted as-shipped; we audited
   our *use* of them, not their code.

---

## (b) The bespoke-crypto caveat — **single highest residual risk**

The messaging E2E and the budget-sharing seal are **hand-rolled** on TweetNaCl
primitives: a custom X3DH (`encryption/services/x3dhService.js`), a custom Double
Ratchet (`encryption/services/doubleRatchetService.js`), the v2 data-share DEK
seal, the budget-DEK wrap, pairing, and recovery. The primitives (X25519,
Ed25519, XSalsa20-Poly1305 secretbox, SHA-512) are from TweetNaCl and are sound;
**the protocol composition around them is ours and has never been reviewed by a
cryptographer or validated against a reference implementation.**

Why this is the top risk:

- Protocol-level crypto bugs (a missing domain separator, an unbound associated
  data field, a nonce reused across contexts, a signature not actually verified,
  a fallback that silently drops a DH) are **exactly the class internal reading
  and RLS probing are worst at catching** — they pass functional tests and ERC
  and look correct.
- The S0–S13 test suite proves the implementation is **self-consistent**
  (encrypt-then-decrypt round-trips, replay rejection, fail-closed) but a
  self-consistent protocol can still be cryptographically wrong (e.g. both sides
  agreeing on a key that an attacker can also derive).
- There is no formal model, no test vectors from an independent implementation,
  and no negative cross-tests against libsignal.

**Recommendation:** treat the bespoke crypto as the focus of an external
**human cryptographer review** (scoped in Artifact 4, `CRYPTO_REVIEW_BRIEF.md`),
and seriously consider migrating the messaging layer to **libsignal**
(`libsignal-client` WASM) so the protocol is a vetted library rather than our
composition. Until one of those happens, the FS/PCS and authenticity claims are
**asserted by us, not independently verified.**

---

## (c) Dependency / runtime risk (versions NOT audited for CVEs here)

The internal waves did not run a dependency CVE scan. Pinned/declared versions
found in the repos (verify against advisories at pentest time):

| Dependency | Version (where) | Notes |
|---|---|---|
| TweetNaCl | `1.0.3`, nacl-util `0.15.1` — vendored, self-hosted (`shared/vendor/crypto/nacl-fast.min.js`; pinned per `encryption/config/moneyTrackerEncryptionConfig.js:22`) | self-hosted (SM-11), no CDN. Vendored blobs have **no Subresource Integrity** check (local files, so SRI is N/A, but verify the bytes match upstream 1.0.3). |
| @supabase/supabase-js | `2.39.7` (vendored `shared/vendor/supabase/supabase.min.js`; edge functions import `@supabase/supabase-js@2.39.7` in payments_app, but `@2` floating in auth_db/messaging/money_tracker user-lookup) | the floating `@2` import resolves to "latest 2.x" at deploy — pin it. |
| Stripe SDK | `stripe@14.21.0?target=deno` (all edge functions) | server-side only (edge functions); not shipped to the browser except `https://js.stripe.com/v3` loaded in subscription views. |
| Deno std | `std@0.168.0/http/server.ts` (all edge functions) | **old.** Newer Deno runtimes prefer `std@0.2xx`; check for advisories and Deno-runtime compatibility. |
| Vite | `^6.0.0` (messaging_app/package.json:15, money_tracker/package.json:15) | build/dev tool; floating caret — a `package-lock`/CVE check is warranted. |

No `npm audit` / `deno` advisory scan has been run in this work. **Action:** run a
dependency advisory scan and pin the floating ranges (`@2`, `^6.0.0`) before the
pentest.

---

## (d) Deliberately deferred / known-accepted (cross-ref `KNOWN_ACCEPTED_RISKS.md`)

These are understood and consciously parked — listed here so the external team
does not "discover" them as surprises:

1. **Recovery-key entropy = 20 bytes (testing).**
   `PasswordCryptoService.RECOVERY_KEY_BYTES = 20`
   (`encryption/services/passwordCryptoService.js:194`, comment line 184: "MUST
   be 32 before production/pentest"). 160 bits behind PBKDF2-SHA256(600k) is not
   brute-forceable and the server cannot influence a build-time constant, but it
   **must be flipped to 32** before the pentest build. Gated by
   `encryption/tests/prod_readiness_check.js` (must exit 0). **This is the one
   prod-revert that is still outstanding as shipped.**
2. **Metadata leakage is inherent to the design.** E2E hides *content*, not
   *metadata*. The server still sees: the social graph (`friends`,
   `conversations`, `data_shares` rows), message timing and frequency, ciphertext
   *lengths* (only a coarse `file_size_bucket` for attachments — H-6 — but message
   bodies are unpadded), and who-talks-to-whom. No padding, no sealed-sender, no
   cover traffic. Tracked as M-8/M-9/M-10/L-14 in `SECURITY_AUDIT.md`.
3. **`frame-ancestors` is inert on GitHub Pages.** CSP is delivered via `<meta>`;
   per spec `frame-ancestors`/`X-Frame-Options` are ignored from `<meta>` and
   Pages cannot set response headers (L-2). Clickjacking is mitigated only by
   in-app confirmation on destructive flows + `object-src/base-uri/form-action`.
   A real fix needs a header-capable host (Cloudflare/Netlify) or a frame-buster.
4. **`style-src 'unsafe-inline'` retained** (L-4). `script-src` is locked down (no
   `unsafe-inline`, only `'self' https://js.stripe.com`), so worst case is
   cosmetic style injection, not code execution. **Inconsistency found:** the
   *standalone* `payments_app/payments/views/subscription.html:7` still has
   `script-src 'unsafe-inline'`, while every messaging_app/money_tracker view
   removed it (H-5). See "Issues found" below — this one is arguably not just
   accepted, it looks stale.
5. **Argon2id backup-KDF migration (L-3) — planned, not implemented.** Backups use
   PBKDF2-SHA256(600k)+AES-256-GCM (OWASP-current) with a documented migration
   plan to Argon2id + server-unknown pepper in the `enforcePasswordStrength` doc
   block. Deferred past the pentest.
6. **Sequential-only pairing / single-active assumptions.** Device pairing is a
   one-at-a-time code handoff (5-attempt limit, 5-minute expiry,
   `devicePairingService.js`); concurrent multi-device edge cases are not
   exhaustively modelled.
7. **pg_cron reapers are operator-set, not installer-created.** The trial-expiry
   sweep schedules itself *if* pg_cron is present; the **pairing_requests reaper
   is documented but never auto-created** — expired wrapped bundles linger at rest
   until a manually-scheduled `DELETE` runs (RLS only *hides* them). See
   `LIVE_CONFIG_CHECKS.sql` §e3.

---

## (e) What the external team is MOST likely to probe first (ranked)

Ranked by likely attacker ROI against *this* architecture:

1. **RLS cross-user access via direct PostgREST.** The anon key + REST endpoint
   are public by design; RLS is the *entire* server-side boundary. The first
   thing a competent tester does is grab two account JWTs and try to read/write
   the other user's `messages`, `user_months`, `pots`, `budget_dek`,
   `data_shares`, `subscriptions` directly — bypassing the client. (Artifact 3
   automates the obvious cases; a human will go further.) **Highest-value target.**
2. **Self-grant Premium / entitlement bypass.** Can a client write
   `subscriptions` directly (the REVOKE) or trick `is_premium_active()` / the
   trial logic / `start_trial` into granting Premium without paying? The
   data_shares Premium gate and the Stripe webhook idempotency are adjacent
   targets.
3. **The bespoke crypto.** A cryptographer probes FS/PCS, the responder-IK pin,
   AD/context binding, nonce management, domain separation (see Artifact 4). High
   *impact* if anything is wrong; needs the specialist lens, so it may come from a
   dedicated reviewer rather than the generalist pentester.
4. **SECURITY DEFINER RPC abuse.** `claim_one_time_prekey`, `create_notification`,
   `update_share_grants`, `start_trial`, `is_premium_active` all run elevated —
   probe for missing `auth.uid()` re-assertion, relationship-check bypass
   (cross-user notification injection), OPK-drain past the rate limit, and
   search_path tricks.
5. **Storage / attachments.** Private-bucket assumption, guessable object keys
   (`<conversationId>/...`), the download-count RPC, expiry bypass.
6. **Auth & account lifecycle.** Email-existence oracles (user-lookup edge fn
   rate limit), password reset / magic-link redirect handling, the
   delete-account edge function, session/JWT handling.
7. **Client-side XSS → key theft.** Since keys live in IndexedDB wrapped under a
   non-extractable WebCrypto key, an XSS cannot *export* the raw key — but it can
   *use* it (decrypt in place, exfil plaintext) and read the unwrapped secret in
   memory. `script-src` is locked down; the `style-src`/inline-style surface and
   the stale payments CSP are where they will poke.
8. **Metadata correlation.** A privacy-focused tester will demonstrate the
   social-graph / timing / size leakage (item d.2) even though it is "accepted" —
   expect it written up.

---

## Issues found while writing this register (worth a look)

- **Stale CSP in standalone payments_app.**
  `payments_app/payments/views/subscription.html:7` still ships
  `script-src 'self' 'unsafe-inline' https://js.stripe.com` **and omits
  `frame-ancestors 'none'`**, whereas the equivalent messaging_app/money_tracker
  views were hardened (H-5: `unsafe-inline` removed from `script-src`,
  `frame-ancestors 'none'` added). If the standalone payments app is deployed, it
  has a weaker script-src than the rest of the platform. Looks like a missed
  file in the H-5 sweep, not a deliberate acceptance.
- **Schema-coverage gap between deployment shapes.** The combined
  `money_tracker/database/setup/fresh-install-complete.sql` (28 tables) does
  **not** create `user_lookup_audit` or the `resolve_user_id_by_email` /
  `resolve_email_by_user_id` resolver functions — they exist only in
  `auth_db/backend/sql/complete-setup.sql`. If the live combined project ran
  *only* the money_tracker installer, the rate-limited email→userId resolver
  (W3-3 / L-1 oracle hardening) is **not present**, and user-lookup falls back to
  the older path. Confirm which installer(s) actually ran on the live project.
- **Floating dependency pins.** `@supabase/supabase-js@2` (auth_db / messaging /
  money_tracker user-lookup edge functions) and `vite ^6.0.0` resolve to "latest"
  at build/deploy — pin them before the pentest so the audited bytes are the
  shipped bytes.
