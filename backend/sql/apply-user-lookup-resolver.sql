-- ============================================================================
-- W3-3 — targeted, rate-limited email -> userId resolver for `user-lookup`
-- ============================================================================
-- Run this ONCE on a LIVE auth_db / identity database, THEN deploy the updated
-- user-lookup edge function (which calls resolve_user_id_by_email instead of
-- auth.admin.listUsers()).
--
-- WHAT IT FIXES (audit finding W3-3):
--   user-lookup.findByEmail used auth.admin.listUsers() (FIRST PAGE ONLY, ~50
--   users) + a JS .find(). That is:
--     * an unthrottled account-EXISTENCE ORACLE (200+userId vs 404 per email),
--     * a correctness bug — real users past page 1 were silently "not found",
--     * an over-broad read — a page of ALL users per single-email query.
--
-- WHAT IT ADDS:
--   * user_lookup_audit — per-caller rate-limit ledger (RLS on, NO authenticated
--     grants; service/DEFINER-written only).
--   * resolve_user_id_by_email(p_caller_id, p_email) SECURITY DEFINER — a single
--     INDEXED lookup against auth.users (paginated-safe at any scale) behind a
--     per-caller sliding-window cap (30/hour). Every attempt (hit OR miss) is
--     recorded so the oracle cannot be brute-forced cheaply. Granted ONLY to
--     service_role (the edge function), NEVER to authenticated.
--
-- ADDITIVE / NON-DESTRUCTIVE: CREATE TABLE IF NOT EXISTS + CREATE OR REPLACE
-- FUNCTION + DROP INDEX IF EXISTS before re-create. No DROP TABLE, no data
-- rewrite. Safe to re-run. search_path is pinned.
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS user_lookup_audit (
    id         BIGSERIAL PRIMARY KEY,
    caller_id  UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    looked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE user_lookup_audit IS 'W3-3: rate-limit ledger for resolve_user_id_by_email(). One row per lookup attempt (found or not) to throttle the account-existence oracle. Service/DEFINER-written only; no authenticated grants.';

DROP INDEX IF EXISTS idx_user_lookup_audit_caller;
CREATE INDEX idx_user_lookup_audit_caller
    ON user_lookup_audit(caller_id, looked_at);

ALTER TABLE user_lookup_audit ENABLE ROW LEVEL SECURITY;
-- No policies / no grants to `authenticated`: only the SECURITY DEFINER resolver
-- (called by the service-role edge function) reads/writes this table.

CREATE OR REPLACE FUNCTION resolve_user_id_by_email(p_caller_id UUID, p_email TEXT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    LOOKUP_WINDOW   CONSTANT INTERVAL := INTERVAL '1 hour';
    LOOKUP_MAX      CONSTANT INTEGER  := 30;   -- lookups per caller per window
    v_count   INTEGER;
    v_user_id UUID;
BEGIN
    IF p_caller_id IS NULL THEN
        RETURN jsonb_build_object('status', 'error', 'error', 'caller required');
    END IF;
    IF p_email IS NULL OR length(trim(p_email)) = 0 THEN
        RETURN jsonb_build_object('status', 'error', 'error', 'email required');
    END IF;

    SELECT count(*) INTO v_count
    FROM user_lookup_audit
    WHERE caller_id = p_caller_id
      AND looked_at > NOW() - LOOKUP_WINDOW;
    IF v_count >= LOOKUP_MAX THEN
        RETURN jsonb_build_object('status', 'rate_limited',
                                  'retry_after_seconds', EXTRACT(EPOCH FROM LOOKUP_WINDOW)::int);
    END IF;
    INSERT INTO user_lookup_audit (caller_id) VALUES (p_caller_id);

    SELECT id INTO v_user_id
    FROM auth.users
    WHERE lower(email) = lower(trim(p_email))
    LIMIT 1;

    IF v_user_id IS NULL THEN
        RETURN jsonb_build_object('status', 'not_found');
    END IF;
    RETURN jsonb_build_object('status', 'ok', 'user_id', v_user_id);
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('status', 'error', 'error', SQLERRM);
END;
$$;

REVOKE ALL ON FUNCTION resolve_user_id_by_email(UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_user_id_by_email(UUID, TEXT) TO service_role;

COMMIT;
