# LIVE_CONFIG_CHECKS — companion notes

**Date:** 2026-06-24
**File:** `auth_db/LIVE_CONFIG_CHECKS.sql`
**What it is:** a read-only, copy-paste self-audit for the **live** Supabase
project. The committed `*.sql` installers prove only the SQL we *wrote*; they
cannot prove the live project was migrated to that state. This script asserts the
live config matches intent and prints a `PASS` / `FAIL` / `WARN` / `REVIEW` /
`MANUAL` / `INFO` row per check.

## How to run

1. Supabase Dashboard → **SQL Editor** → New query.
2. Paste the whole of `LIVE_CONFIG_CHECKS.sql`, **Run**.
3. It is **read-only** (only `SELECT`s — no writes, no DDL). Safe on production.
4. Read each result block; chase **FAIL** first, then **WARN**/**REVIEW**, then
   complete the **MANUAL** rows.

## What each section asserts (and the source it is grounded in)

| § | Check | Grounded in |
|---|-------|-------------|
| 0 | Deployment-shape probe | which installers were run |
| a | RLS **enabled** on every expected table (`pg_class.relrowsecurity`) + positive control for any RLS-disabled public table | the 28 `CREATE TABLE` + `ENABLE ROW LEVEL SECURITY` in `money_tracker/database/setup/fresh-install-complete.sql`, plus `user_lookup_audit` from `auth_db/backend/sql/complete-setup.sql` |
| b | Every expected **policy** exists (`pg_policies`) + a **drift detector** for any live policy not in the repo | the `CREATE POLICY` names across all four installers |
| b2 | Storage `storage.objects` attachment policies present | secure_db / combined installers |
| c | **Entitlement lockdown**: `authenticated` has `SELECT` but NOT `INSERT/UPDATE/DELETE` on `subscriptions` | `REVOKE INSERT, UPDATE ON subscriptions FROM authenticated` (payments_app complete-setup.sql ~520; combined ~820) |
| c2–c4 | seq lockdown, service-only ledgers have no client grant, `data_shares` grant-flag columns are not client-writable | the `REVOKE`/`GRANT UPDATE(...)` column scoping (SEC-C1) |
| d | Every `SECURITY DEFINER` function pins `search_path` (`pg_proc.proconfig`) + a positive control listing the expected DEFINER functions | every DEFINER body in the installers carries `SET search_path = public` |
| e | `pg_cron` installed + `expire-overdue-trials` job scheduled; **recommended** `pairing_requests` reaper | `cron.schedule('expire-overdue-trials', '0 * * * *', ...)`; pairing reaper documented but **not auto-created** |
| f | **MANUAL** Dashboard items: private bucket, no service-role key in client, anon key only, Auth config, prod-revert gate | cannot be seen from SQL |

## Reading the status values

- **PASS** — live matches intent.
- **FAIL** — a real mismatch; the dangerous ones are RLS-off on an existing
  table, a missing policy on an RLS-on table, a client INSERT/UPDATE grant on
  `subscriptions`, a DEFINER function with no pinned `search_path`, or a
  client-writable `data_shares` grant flag.
- **WARN** — expected-absent on this deployment shape (e.g. `user_lookup_audit`
  is only created by the auth_db standalone file, not the combined installer), or
  `pg_cron` not installed. Read the `detail` column before dismissing.
- **REVIEW** (§b3) — a live policy that is **not** in the repo. Treat each as a
  potential hand-added permissive rule until you have explained it.
- **MANUAL** (§f) — verify by hand in the Dashboard / shipped bundle.

## Honest caveats (what this script does NOT prove)

- It checks **structure** (RLS on, policy exists, grant scope, search_path), not
  **policy semantics**. A policy named `messages_select_participant` that exists
  but whose `USING` was hand-edited to `true` would PASS §b. To catch that, also
  diff the live `pg_policies.qual` / `with_check` text against the installer, or
  re-run the installer onto a scratch project and `pg_dump --schema-only` both.
- It cannot see the **anon key vs service-role key** distinction in the shipped
  client, the **bucket privacy** flag, or **Auth** settings — those are the §f
  MANUAL rows.
- The **two deployment shapes** matter: the combined `money_tracker` installer
  does **not** create `user_lookup_audit` or the `resolve_*_by_*` resolver
  functions — those exist only in `auth_db/backend/sql/complete-setup.sql`. On the
  combined deploy these show as **WARN** by design. If your live project is meant
  to support email→userId discovery, confirm which file supplied that path (see
  the schema-coverage note in `RESIDUAL_RISKS.md`).

## Deployment-shape note (found while writing this)

`money_tracker/database/setup/fresh-install-complete.sql` creates **28** public
tables but does **not** include `user_lookup_audit` or the
`resolve_user_id_by_email` / `resolve_email_by_user_id` functions. Those live only
in `auth_db/backend/sql/complete-setup.sql`. So a combined deploy that ran *only*
the money_tracker installer either (a) also ran the auth_db file, or (b) is
running the older edge-function lookup path. The SQL flags this as WARN rather
than FAIL; confirm the intended discovery path during the pentest.
