-- ============================================================================
-- auth_db / backend / 00 — extensions + identity foundation
-- ============================================================================
-- FIRST script in the shared-database init runbook:
--     auth_db (this) -> secure_db -> payments -> budget
--
-- Identity model: there is NO `profiles` table. The identity store IS Supabase
-- `auth.users`. Email <-> user-id resolution is provided by the `user-lookup`
-- edge function (backend/edge-functions/user-lookup.ts), deployed separately.
--
-- Prerequisites handled here: the Postgres extensions every later script relies
-- on (gen_random_uuid / uuid generation). Safe to run on a fresh project and
-- idempotent on an existing one.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
