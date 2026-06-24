-- ============================================================================
-- LIVE_CONFIG_CHECKS.sql — assert the LIVE Supabase project matches intent
-- ============================================================================
-- WHY THIS FILE EXISTS
--   The committed *.sql installers prove only the SQL we WROTE. They cannot prove
--   the LIVE project was actually migrated to that state (a hand-edit in the
--   Dashboard, a half-applied migration, a REVOKE that never ran, a SECURITY
--   DEFINER function created without `SET search_path`, RLS toggled off on one
--   table — none of those show up in the repo). This script is a read-only
--   self-audit you paste into the Supabase SQL editor; every check emits a
--   PASS / FAIL row so you can eyeball the whole config in one run.
--
-- HOW TO RUN
--   1. Supabase Dashboard -> SQL Editor -> New query.
--   2. Paste this whole file, Run. It is READ-ONLY (only SELECTs; no writes).
--   3. Scan the `status` column. Any `FAIL` (or `WARN`) is a finding to chase.
--
-- GROUNDING (every expected name below is taken from the real installers):
--   * Combined all-in-one DB (the money_tracker deploy):
--       money_tracker/database/setup/fresh-install-complete.sql   (28 tables)
--   * Standalone identity DB (the auth_db deploy):
--       auth_db/backend/sql/complete-setup.sql                    (+ user_lookup_audit)
--   * Messaging-only / payments-only deploys:
--       secure_db/sql/complete-setup.sql, payments_app/backend/sql/complete-setup.sql
--
-- IMPORTANT — TWO DEPLOYMENT SHAPES
--   This platform ships either as ONE combined database (money_tracker installer,
--   which folds identity + messaging + payments + budget into one project) or as
--   the per-app installers run in sequence (auth_db -> secure_db -> payments_app).
--   The combined installer does NOT create `user_lookup_audit` / the
--   `resolve_*_by_*` resolver functions — those live only in auth_db's standalone
--   complete-setup.sql. Section 0 detects which shape you are on, and the table /
--   policy checks below are written to PASS on the combined shape and FLAG (WARN)
--   the identity-resolver objects as "expected only if auth_db's file was run".
-- ============================================================================

-- ----------------------------------------------------------------------------
-- SECTION 0 — deployment-shape probe (informational; sets expectations below)
-- ----------------------------------------------------------------------------
SELECT
  '0. deployment shape' AS check_name,
  CASE
    WHEN to_regclass('public.user_months')        IS NOT NULL
     AND to_regclass('public.messages')           IS NOT NULL
     AND to_regclass('public.subscriptions')      IS NOT NULL
      THEN 'COMBINED all-in-one (money_tracker installer): budget+messaging+payments+identity'
    WHEN to_regclass('public.messages')           IS NOT NULL
     AND to_regclass('public.user_months')        IS NULL
      THEN 'MESSAGING/identity only (secure_db + auth_db)'
    WHEN to_regclass('public.user_lookup_audit')  IS NOT NULL
     AND to_regclass('public.messages')           IS NULL
      THEN 'IDENTITY only (auth_db complete-setup.sql)'
    ELSE 'UNRECOGNISED — review which installers were applied'
  END AS detail,
  'INFO' AS status;

-- ============================================================================
-- (a) RLS IS ENABLED ON EVERY TABLE THAT SHOULD HAVE IT
-- ============================================================================
-- pg_class.relrowsecurity is the live truth (does NOT depend on any policy
-- existing). We check, for each table we expect, that the table exists AND that
-- RLS is enabled. We ALSO surface any public table that has RLS *disabled* that
-- we did not anticipate (a positive-control catch for new/forgotten tables).
--
-- Expected table set = the 28 tables created by the combined installer, PLUS the
-- identity-resolver tables from auth_db's standalone file (flagged WARN-if-absent,
-- not FAIL, because the combined installer legitimately omits them).

WITH expected(tbl, origin) AS (
  VALUES
    -- budget / money_tracker
    ('user_months','combined'),
    ('example_months','combined'),
    ('pots','combined'),
    ('budget_dek','combined'),
    ('settings','combined'),
    -- payments
    ('subscription_plans','combined'),
    ('subscriptions','combined'),
    ('payments','combined'),
    ('payment_history','combined'),
    ('stripe_webhook_events','combined'),
    -- sharing
    ('data_shares','combined'),
    ('field_locks','combined'),
    -- social
    ('friends','combined'),
    ('blocked_users','combined'),
    -- identity / E2E keys
    ('identity_keys','combined'),
    ('public_key_history','combined'),
    ('paired_devices','combined'),
    ('key_rotation_locks','combined'),
    ('identity_key_backups','combined'),
    ('prekeys','combined'),
    ('one_time_prekeys','combined'),
    ('opk_claim_audit','combined'),
    ('pairing_requests','combined'),
    -- messaging
    ('conversations','combined'),
    ('messages','combined'),
    ('message_attachments','combined'),
    ('conversation_session_keys','combined'),
    -- notifications
    ('notifications','combined'),
    ('notification_preferences','combined'),
    -- identity-resolver rate-limit ledger (auth_db standalone ONLY)
    ('user_lookup_audit','auth_db-only')
)
SELECT
  'a. RLS enabled: ' || e.tbl AS check_name,
  e.origin                    AS expected_from,
  CASE
    WHEN c.relname IS NULL AND e.origin = 'auth_db-only'
      THEN 'WARN'   -- legitimately absent on the combined deploy
    WHEN c.relname IS NULL
      THEN 'FAIL'   -- table missing on a deploy that should have it
    WHEN c.relrowsecurity IS DISTINCT FROM TRUE
      THEN 'FAIL'   -- table exists but RLS is OFF  <-- the dangerous case
    ELSE 'PASS'
  END AS status,
  CASE
    WHEN c.relname IS NULL THEN 'table not present in this database'
    WHEN c.relrowsecurity IS DISTINCT FROM TRUE THEN 'RLS DISABLED on an existing table'
    ELSE 'RLS on'
  END AS detail
FROM expected e
LEFT JOIN pg_class c
  ON c.relname = e.tbl
 AND c.relnamespace = 'public'::regnamespace
 AND c.relkind = 'r'
ORDER BY status DESC, e.tbl;   -- FAIL/WARN float to the top

-- (a2) POSITIVE CONTROL — any public table with RLS DISABLED that is NOT one we
-- expect to be RLS-exempt. There are none we expect to be exempt, so every public
-- base table should be RLS-on. Anything listed here is a forgotten table.
SELECT
  'a2. unexpected RLS-disabled public table' AS check_name,
  c.relname AS detail,
  'FAIL'    AS status
FROM pg_class c
WHERE c.relnamespace = 'public'::regnamespace
  AND c.relkind = 'r'
  AND c.relrowsecurity = FALSE
ORDER BY c.relname;
-- (Zero rows = PASS for this control.)

-- ============================================================================
-- (b) EVERY EXPECTED RLS POLICY EXISTS
-- ============================================================================
-- Compare pg_policies (live) to the policy NAMES defined in the installers. A
-- missing policy on an RLS-enabled table can mean "all access denied" (locked
-- out) OR, worse, a table left with RLS on but the wrong/missing policy. We list
-- the exact (table, policy) pairs from the installers; FAIL = expected policy not
-- found live. (Storage-object policies are checked separately in (b2).)

WITH expected_policy(tbl, policy, origin) AS (
  VALUES
    -- identity_keys
    ('identity_keys','identity_keys_select_all','combined'),
    ('identity_keys','identity_keys_insert_own','combined'),
    ('identity_keys','identity_keys_update_own','combined'),
    ('identity_keys','identity_keys_delete_own','combined'),
    -- public_key_history
    ('public_key_history','public_key_history_select_all','combined'),
    ('public_key_history','public_key_history_insert_own','combined'),
    -- paired_devices
    ('paired_devices','paired_devices_select_own','combined'),
    ('paired_devices','paired_devices_insert_own','combined'),
    ('paired_devices','paired_devices_update_own','combined'),
    ('paired_devices','paired_devices_delete_own','combined'),
    -- key_rotation_locks
    ('key_rotation_locks','rotation_locks_select_own','combined'),
    ('key_rotation_locks','rotation_locks_insert_own','combined'),
    ('key_rotation_locks','rotation_locks_update_own','combined'),
    ('key_rotation_locks','rotation_locks_delete_own','combined'),
    -- pairing_requests
    ('pairing_requests','pairing_requests_select_own','combined'),
    ('pairing_requests','pairing_requests_insert_own','combined'),
    ('pairing_requests','pairing_requests_update_own','combined'),
    ('pairing_requests','pairing_requests_delete_own','combined'),
    -- identity_key_backups
    ('identity_key_backups','key_backups_select_own','combined'),
    ('identity_key_backups','key_backups_insert_own','combined'),
    ('identity_key_backups','key_backups_update_own','combined'),
    ('identity_key_backups','key_backups_delete_own','combined'),
    -- prekeys
    ('prekeys','prekeys_select_all','combined'),
    ('prekeys','prekeys_insert_own','combined'),
    ('prekeys','prekeys_update_own','combined'),
    ('prekeys','prekeys_delete_own','combined'),
    -- one_time_prekeys  (M-2: SELECT is own-row only, NOT select_all)
    ('one_time_prekeys','one_time_prekeys_select_own','combined'),
    ('one_time_prekeys','one_time_prekeys_insert_own','combined'),
    ('one_time_prekeys','one_time_prekeys_update_own','combined'),
    ('one_time_prekeys','one_time_prekeys_delete_own','combined'),
    -- budget
    ('user_months','user_months_select_own','combined'),
    ('user_months','user_months_insert_own','combined'),
    ('user_months','user_months_update_own','combined'),
    ('user_months','user_months_delete_own','combined'),
    ('user_months','user_months_select_shared','combined'),
    ('user_months','user_months_update_shared','combined'),
    ('pots','pots_select_own','combined'),
    ('pots','pots_insert_own','combined'),
    ('pots','pots_update_own','combined'),
    ('pots','pots_delete_own','combined'),
    ('budget_dek','budget_dek_select_own','combined'),
    ('budget_dek','budget_dek_insert_own','combined'),
    ('budget_dek','budget_dek_update_own','combined'),
    ('budget_dek','budget_dek_delete_own','combined'),
    ('example_months','example_months_select_all','combined'),
    ('settings','settings_select_own','combined'),
    ('settings','settings_insert_own','combined'),
    ('settings','settings_update_own','combined'),
    -- payments
    ('subscription_plans','subscription_plans_select_all','combined'),
    ('subscriptions','subscriptions_select_own','combined'),
    ('subscriptions','subscriptions_update_own','combined'),
    ('subscriptions','subscriptions_insert_own','combined'),
    ('payments','payments_select_own','combined'),
    ('payment_history','payment_history_select_own','combined'),
    -- sharing
    ('data_shares','data_shares_select_involved','combined'),
    ('data_shares','data_shares_insert_as_owner','combined'),
    ('data_shares','data_shares_update_as_owner','combined'),
    ('data_shares','data_shares_update_as_recipient','combined'),
    ('data_shares','data_shares_delete_as_owner','combined'),
    ('field_locks','field_locks_select_all','combined'),
    ('field_locks','field_locks_insert_own','combined'),
    ('field_locks','field_locks_delete_own','combined'),
    -- social
    ('friends','friends_select_involved','combined'),
    ('friends','friends_insert_own','combined'),
    ('friends','friends_update_as_friend','combined'),
    ('friends','friends_delete_involved','combined'),
    ('blocked_users','blocked_users_select_own','combined'),
    ('blocked_users','blocked_users_insert_own','combined'),
    ('blocked_users','blocked_users_delete_own','combined'),
    -- messaging
    ('conversations','conversations_select_participant','combined'),
    ('conversations','conversations_insert_participant','combined'),
    ('conversations','conversations_update_participant','combined'),
    ('messages','messages_select_participant','combined'),
    ('messages','messages_insert_participant','combined'),
    ('messages','messages_update_participant','combined'),
    ('messages','messages_delete_own','combined'),
    ('message_attachments','attachments_select_participant','combined'),
    ('message_attachments','attachments_insert_uploader','combined'),
    ('message_attachments','attachments_delete_uploader','combined'),
    ('conversation_session_keys','session_keys_select_own','combined'),
    ('conversation_session_keys','session_keys_insert_own','combined'),
    ('conversation_session_keys','session_keys_update_own','combined'),
    ('conversation_session_keys','session_keys_delete_own','combined'),
    -- notifications
    ('notifications','notifications_select_own','combined'),
    ('notifications','notifications_update_own','combined'),
    ('notifications','notifications_delete_own','combined'),
    ('notification_preferences','notification_prefs_select_own','combined'),
    ('notification_preferences','notification_prefs_insert_own','combined'),
    ('notification_preferences','notification_prefs_update_own','combined')
)
SELECT
  'b. policy: ' || ep.tbl || '.' || ep.policy AS check_name,
  CASE
    WHEN to_regclass('public.' || ep.tbl) IS NULL THEN 'WARN'   -- table absent on this deploy shape
    WHEN p.polname IS NULL                          THEN 'FAIL'   -- table present but policy missing
    ELSE 'PASS'
  END AS status,
  CASE
    WHEN to_regclass('public.' || ep.tbl) IS NULL THEN 'table not in this deployment'
    WHEN p.polname IS NULL THEN 'EXPECTED POLICY MISSING on existing table'
    ELSE 'present'
  END AS detail
FROM expected_policy ep
LEFT JOIN pg_policies p
  ON p.schemaname = 'public'
 AND p.tablename  = ep.tbl
 AND p.policyname = ep.policy
ORDER BY status DESC, ep.tbl, ep.policy;

-- (b2) STORAGE attachment policies (storage.objects) — these gate the private
-- message-attachments bucket by conversation participation. Quoted names from
-- the installer.
WITH expected_storage(policy) AS (
  VALUES ('Users can upload attachments'),
         ('Users can read attachments'),
         ('Users can delete attachments')
)
SELECT
  'b2. storage.objects policy: ' || es.policy AS check_name,
  CASE WHEN p.polname IS NULL THEN 'FAIL' ELSE 'PASS' END AS status
FROM expected_storage es
LEFT JOIN pg_policies p
  ON p.schemaname = 'storage'
 AND p.tablename  = 'objects'
 AND p.policyname = es.policy
ORDER BY status DESC, es.policy;

-- (b3) DRIFT DETECTOR — public policies that exist LIVE but are NOT in our
-- expected list above. A surprise policy (e.g. a permissive `USING (true)` added
-- by hand) is exactly the kind of thing that re-opens cross-user access. Review
-- every row this returns. (notification_preferences, settings etc. are expected;
-- anything unfamiliar is the signal.)
SELECT
  'b3. UNEXPECTED live policy' AS check_name,
  p.tablename || '.' || p.policyname AS detail,
  p.cmd AS command,
  'REVIEW' AS status
FROM pg_policies p
WHERE p.schemaname = 'public'
  AND (p.tablename, p.policyname) NOT IN (
    SELECT ep.tbl, ep.policy FROM (
      VALUES
        ('identity_keys','identity_keys_select_all'),('identity_keys','identity_keys_insert_own'),
        ('identity_keys','identity_keys_update_own'),('identity_keys','identity_keys_delete_own'),
        ('public_key_history','public_key_history_select_all'),('public_key_history','public_key_history_insert_own'),
        ('paired_devices','paired_devices_select_own'),('paired_devices','paired_devices_insert_own'),
        ('paired_devices','paired_devices_update_own'),('paired_devices','paired_devices_delete_own'),
        ('key_rotation_locks','rotation_locks_select_own'),('key_rotation_locks','rotation_locks_insert_own'),
        ('key_rotation_locks','rotation_locks_update_own'),('key_rotation_locks','rotation_locks_delete_own'),
        ('pairing_requests','pairing_requests_select_own'),('pairing_requests','pairing_requests_insert_own'),
        ('pairing_requests','pairing_requests_update_own'),('pairing_requests','pairing_requests_delete_own'),
        ('identity_key_backups','key_backups_select_own'),('identity_key_backups','key_backups_insert_own'),
        ('identity_key_backups','key_backups_update_own'),('identity_key_backups','key_backups_delete_own'),
        ('prekeys','prekeys_select_all'),('prekeys','prekeys_insert_own'),
        ('prekeys','prekeys_update_own'),('prekeys','prekeys_delete_own'),
        ('one_time_prekeys','one_time_prekeys_select_own'),('one_time_prekeys','one_time_prekeys_insert_own'),
        ('one_time_prekeys','one_time_prekeys_update_own'),('one_time_prekeys','one_time_prekeys_delete_own'),
        ('user_months','user_months_select_own'),('user_months','user_months_insert_own'),
        ('user_months','user_months_update_own'),('user_months','user_months_delete_own'),
        ('user_months','user_months_select_shared'),('user_months','user_months_update_shared'),
        ('pots','pots_select_own'),('pots','pots_insert_own'),('pots','pots_update_own'),('pots','pots_delete_own'),
        ('budget_dek','budget_dek_select_own'),('budget_dek','budget_dek_insert_own'),
        ('budget_dek','budget_dek_update_own'),('budget_dek','budget_dek_delete_own'),
        ('example_months','example_months_select_all'),
        ('settings','settings_select_own'),('settings','settings_insert_own'),('settings','settings_update_own'),
        ('subscription_plans','subscription_plans_select_all'),
        ('subscriptions','subscriptions_select_own'),('subscriptions','subscriptions_update_own'),
        ('subscriptions','subscriptions_insert_own'),
        ('payments','payments_select_own'),('payment_history','payment_history_select_own'),
        ('data_shares','data_shares_select_involved'),('data_shares','data_shares_insert_as_owner'),
        ('data_shares','data_shares_update_as_owner'),('data_shares','data_shares_update_as_recipient'),
        ('data_shares','data_shares_delete_as_owner'),
        ('field_locks','field_locks_select_all'),('field_locks','field_locks_insert_own'),('field_locks','field_locks_delete_own'),
        ('friends','friends_select_involved'),('friends','friends_insert_own'),
        ('friends','friends_update_as_friend'),('friends','friends_delete_involved'),
        ('blocked_users','blocked_users_select_own'),('blocked_users','blocked_users_insert_own'),
        ('blocked_users','blocked_users_delete_own'),
        ('conversations','conversations_select_participant'),('conversations','conversations_insert_participant'),
        ('conversations','conversations_update_participant'),
        ('messages','messages_select_participant'),('messages','messages_insert_participant'),
        ('messages','messages_update_participant'),('messages','messages_delete_own'),
        ('message_attachments','attachments_select_participant'),('message_attachments','attachments_insert_uploader'),
        ('message_attachments','attachments_delete_uploader'),
        ('conversation_session_keys','session_keys_select_own'),('conversation_session_keys','session_keys_insert_own'),
        ('conversation_session_keys','session_keys_update_own'),('conversation_session_keys','session_keys_delete_own'),
        ('notifications','notifications_select_own'),('notifications','notifications_update_own'),
        ('notifications','notifications_delete_own'),
        ('notification_preferences','notification_prefs_select_own'),
        ('notification_preferences','notification_prefs_insert_own'),
        ('notification_preferences','notification_prefs_update_own')
    ) AS known(tbl, policy)
  )
ORDER BY p.tablename, p.policyname;
-- (Zero rows = PASS. Any row = a live policy not in the repo; investigate.)

-- ============================================================================
-- (c) THE ENTITLEMENT LOCKDOWN: no INSERT/UPDATE on `subscriptions` for
--     `authenticated`  (premium must never be client-writable)
-- ============================================================================
-- The installer GRANTs SELECT then REVOKEs INSERT,UPDATE (payments_app/.../
-- complete-setup.sql lines ~134-135 + ~520; combined money_tracker ~466 + ~820).
-- All writes must go through the SECURITY DEFINER RPCs / Stripe service role.
-- We assert the `authenticated` role holds SELECT but NOT INSERT/UPDATE/DELETE.
SELECT
  'c. subscriptions client-write lockdown' AS check_name,
  string_agg(privilege_type, ',' ORDER BY privilege_type) AS granted_to_authenticated,
  CASE
    WHEN bool_or(privilege_type IN ('INSERT','UPDATE','DELETE')) THEN 'FAIL'  -- client can self-grant premium
    WHEN bool_or(privilege_type = 'SELECT') THEN 'PASS'                        -- read-only, as intended
    ELSE 'WARN'  -- no privileges at all: clients cannot even read their plan
  END AS status
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND table_name = 'subscriptions'
  AND grantee = 'authenticated';

-- (c2) the matching sequence lockdown: subscriptions_id_seq USAGE/SELECT is also
-- REVOKEd from authenticated (a client that cannot INSERT does not need the seq).
SELECT
  'c2. subscriptions_id_seq lockdown' AS check_name,
  CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.role_usage_grants
      WHERE object_schema = 'public'
        AND object_name = 'subscriptions_id_seq'
        AND grantee = 'authenticated'
    ) THEN 'WARN'   -- seq still granted; not exploitable alone but inconsistent with the lockdown
    ELSE 'PASS'
  END AS status;

-- (c3) Sanity: the service-role-only ledger tables grant NOTHING to authenticated
-- (opk_claim_audit, user_lookup_audit, stripe_webhook_events). A client must not
-- be able to read who-talks-to-whom or clear rate-limit rows.
WITH ledgers(tbl) AS (VALUES ('opk_claim_audit'),('user_lookup_audit'),('stripe_webhook_events'))
SELECT
  'c3. ledger has NO authenticated grant: ' || l.tbl AS check_name,
  CASE
    WHEN to_regclass('public.' || l.tbl) IS NULL THEN 'WARN'   -- table not on this deploy
    WHEN EXISTS (
      SELECT 1 FROM information_schema.role_table_grants g
      WHERE g.table_schema = 'public' AND g.table_name = l.tbl AND g.grantee = 'authenticated'
    ) THEN 'FAIL'   -- a client grant on a service-only ledger
    ELSE 'PASS'
  END AS status
FROM ledgers l
ORDER BY status DESC, l.tbl;

-- (c4) data_shares column-grant scope (SEC-C1): authenticated may UPDATE only the
-- allowed columns; can_edit / share_all_data / owner_user_id / shared_with_user_id
-- must NOT be in the client UPDATE privilege (owner flag-mutation goes through the
-- update_share_grants DEFINER RPC). FAIL = a grant flag column is client-writable.
SELECT
  'c4. data_shares forbidden UPDATE column: ' || column_name AS check_name,
  'FAIL' AS status
FROM information_schema.column_privileges
WHERE table_schema = 'public'
  AND table_name = 'data_shares'
  AND grantee = 'authenticated'
  AND privilege_type = 'UPDATE'
  AND column_name IN ('can_edit','share_all_data','owner_user_id','shared_with_user_id','year','month');
-- (Zero rows = PASS.)

-- ============================================================================
-- (d) EVERY SECURITY DEFINER FUNCTION PINS search_path
-- ============================================================================
-- A SECURITY DEFINER function without `SET search_path` is the classic search-path
-- hijack: an attacker plants a function/table in a schema earlier on the path and
-- the elevated function calls it. Every DEFINER function in the installers sets
-- `search_path = public`. We assert proconfig contains a search_path entry for
-- EVERY prosecdef function in `public`.  (This catches a hand-created DEFINER fn
-- and a function recreated without the SET clause.)
SELECT
  'd. DEFINER search_path: ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS check_name,
  CASE
    WHEN EXISTS (
      SELECT 1 FROM unnest(coalesce(p.proconfig, ARRAY[]::text[])) cfg
      WHERE cfg ILIKE 'search_path=%'
    ) THEN 'PASS'
    ELSE 'FAIL'   -- SECURITY DEFINER with NO pinned search_path
  END AS status,
  array_to_string(p.proconfig, ', ') AS proconfig
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.prosecdef = TRUE
ORDER BY status DESC, p.proname;

-- (d2) Positive control — the EXPECTED DEFINER functions are present. (Combined
-- deploy set; resolve_*_by_* are auth_db-standalone-only -> WARN if absent.)
WITH expected_def(fn, origin) AS (
  VALUES
    ('claim_one_time_prekey','combined'),
    ('create_notification','combined'),
    ('update_share_grants','combined'),
    ('update_share_status','combined'),
    ('start_trial','combined'),
    ('downgrade_to_free','combined'),
    ('ensure_subscription','combined'),
    ('is_premium_active','combined'),
    ('is_blocked','combined'),
    ('increment_attachment_download_count','combined'),
    ('expire_overdue_trials','combined'),
    ('cleanup_expired_attachments','combined'),
    ('create_trial_subscription','combined'),
    ('resolve_user_id_by_email','auth_db-only'),
    ('resolve_email_by_user_id','auth_db-only')
)
SELECT
  'd2. DEFINER fn present: ' || ed.fn AS check_name,
  ed.origin AS expected_from,
  CASE
    WHEN p.proname IS NOT NULL THEN 'PASS'
    WHEN ed.origin = 'auth_db-only' THEN 'WARN'   -- expected only if auth_db file was run
    ELSE 'FAIL'
  END AS status
FROM expected_def ed
LEFT JOIN pg_proc p
  ON p.proname = ed.fn
 AND p.pronamespace = 'public'::regnamespace
 AND p.prosecdef = TRUE
GROUP BY ed.fn, ed.origin, p.proname
ORDER BY status DESC, ed.fn;

-- ============================================================================
-- (e) pg_cron JOB for expire_overdue_trials EXISTS (revenue + entitlement hygiene)
-- ============================================================================
-- The installer schedules 'expire-overdue-trials' at '0 * * * *' IF pg_cron is
-- installed. is_premium_active() already denies expired trials even without the
-- cron, but the sweep keeps stored rows honest. We check: (1) pg_cron present,
-- (2) the named job exists. ALSO recommended (NOT auto-created by any installer):
-- a reaper for expired pairing_requests — flagged as a manual check.
SELECT
  'e. pg_cron extension installed' AS check_name,
  CASE WHEN EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron')
       THEN 'PASS' ELSE 'WARN' END AS status,
  'is_premium_active() still denies expired trials without it; sweep is hygiene' AS detail;

-- cron.job is only queryable if pg_cron is installed; guard with to_regclass.
SELECT
  'e2. cron job expire-overdue-trials scheduled' AS check_name,
  CASE
    WHEN to_regclass('cron.job') IS NULL THEN 'WARN'   -- pg_cron not installed
    WHEN EXISTS (
      SELECT 1 FROM cron.job
      WHERE jobname = 'expire-overdue-trials'
        AND active IS NOT FALSE
    ) THEN 'PASS'
    ELSE 'FAIL'   -- pg_cron present but the job is missing/inactive
  END AS status;

-- e3. MANUAL/RECOMMENDED — the pairing_requests reaper. The installer documents
-- (auth_db/backend/sql/complete-setup.sql ~212-215) that an operator-set cron must
-- run `DELETE FROM pairing_requests WHERE expires_at < now();` — RLS only HIDES
-- expired rows, it does not delete the at-rest wrapped bundle. No installer creates
-- this job. This check reports whether ANY cron job references pairing_requests.
SELECT
  'e3. pairing_requests reaper cron present (recommended)' AS check_name,
  CASE
    WHEN to_regclass('cron.job') IS NULL THEN 'WARN'
    WHEN EXISTS (SELECT 1 FROM cron.job WHERE command ILIKE '%pairing_requests%') THEN 'PASS'
    ELSE 'WARN'   -- not scheduled; expired wrapped bundles linger until manually reaped
  END AS status,
  'RLS hides expired rows; the at-rest ciphertext persists until a reaper deletes it' AS detail;

-- ============================================================================
-- (f) MANUAL DASHBOARD CHECKS (cannot be asserted from SQL — DO THESE BY HAND)
-- ============================================================================
-- The items below are NOT visible to a SQL query. Verify each in the Dashboard /
-- in the shipped client bundle and tick it off. They are emitted as MANUAL rows
-- so they appear in the same result set as a reminder.
SELECT * FROM (VALUES
  ('f1. storage bucket message-attachments is PRIVATE',
   'MANUAL',
   'Dashboard > Storage > message-attachments: "Public bucket" MUST be unchecked. A public bucket bypasses the storage.objects RLS policies entirely (object keys are guessable <conversationId>/...).'),
  ('f2. service-role key is NOT in any client/Pages bundle',
   'MANUAL',
   'grep the deployed GitHub Pages assets + every committed config for the service_role JWT / SUPABASE_SERVICE_ROLE_KEY. The client must ship ONLY the anon/publishable key (PROJECT_URL + PUBLISHABLE_API_KEY in database/config/supabaseConfig.js). The service-role key bypasses ALL RLS — it must live only in edge-function secrets.'),
  ('f3. only the anon/publishable key is shipped client-side',
   'MANUAL',
   'Confirm supabaseConfig.PUBLISHABLE_API_KEY is the anon/publishable key (prefix sb_publishable_ or a JWT with role:anon), never role:service_role. RLS is the boundary, so the anon key being public is by design.'),
  ('f4. Auth: leaked-password protection + email confirmation ON',
   'MANUAL',
   'Dashboard > Authentication > Providers/Policies: enable leaked-password (HaveIBeenPwned) protection and require email confirmation; set Site URL + Redirect URLs to the real Pages origins only.'),
  ('f5. pre-pentest prod-revert items applied',
   'MANUAL',
   'Run `node auth_db/encryption/tests/prod_readiness_check.js` — must exit 0. It gates RECOVERY_KEY_BYTES 20->32 and PAIRING_CODE_BYTES floor. See KNOWN_ACCEPTED_RISKS.md §B.')
) AS m(check_name, status, detail);

-- ============================================================================
-- END. Read the result tabs top-to-bottom; chase every FAIL, then every WARN,
-- then complete the MANUAL rows. PASS-only across (a)-(e) + all MANUAL ticked =
-- the live config matches the committed installers' intent.
-- ============================================================================
