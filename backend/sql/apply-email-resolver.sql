-- ============================================================================
-- L-1 — targeted, rate-limited userId -> email resolver for `user-lookup`
-- ============================================================================
-- Run this ONCE on a LIVE auth_db / identity database, THEN deploy the updated
-- user-lookup edge function (which calls resolve_email_by_user_id instead of
-- a raw, unthrottled auth.admin.getUserById()).
--
-- Companion to apply-user-lookup-resolver.sql (W3-3, the email -> userId path).
-- Same pattern, opposite direction; reuses the SAME user_lookup_audit ledger so
-- a caller's lookups across BOTH directions share one per-caller budget.
--
-- WHAT IT FIXES (audit finding L-1):
--   user-lookup.getEmailById used auth.admin.getUserById() directly and returned
--   404-vs-200 keyed on the user id, with NO rate limit (unlike findByEmail after
--   W3-3). That is a user-id existence oracle + an unthrottled reverse-lookup.
--   Impact is LOW (user-ids are random UUIDs, not enumerable, and the caller must
--   already hold a valid id) but it is asymmetric with the W3-3 hardening; this
--   brings it to parity.
--
-- WHAT IT ADDS:
--   * resolve_email_by_user_id(p_caller_id, p_user_id) SECURITY DEFINER — a single
--     INDEXED lookup against auth.users behind the SAME per-caller sliding-window
--     cap (30/hour) recorded in user_lookup_audit. Every attempt (hit OR miss) is
--     recorded so neither direction can be brute-forced cheaply. Granted ONLY to
--     service_role (the edge function), NEVER to authenticated.
--
-- The edge function returns a UNIFORM 200 { email: <addr|null> } for both found
-- and not-found, so the response status no longer doubles as an existence oracle.
--
-- ADDITIVE / NON-DESTRUCTIVE: CREATE OR REPLACE FUNCTION only; relies on
-- user_lookup_audit already created by apply-user-lookup-resolver.sql (created
-- here too, IF NOT EXISTS, so this file is also safe to run standalone). No DROP
-- TABLE, no data rewrite. Safe to re-run. search_path is pinned.
-- ============================================================================

BEGIN;

-- Shared rate-limit ledger (also created by apply-user-lookup-resolver.sql).
CREATE TABLE IF NOT EXISTS user_lookup_audit (
    id         BIGSERIAL PRIMARY KEY,
    caller_id  UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    looked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP INDEX IF EXISTS idx_user_lookup_audit_caller;
CREATE INDEX idx_user_lookup_audit_caller
    ON user_lookup_audit(caller_id, looked_at);

ALTER TABLE user_lookup_audit ENABLE ROW LEVEL SECURITY;
-- No policies / no grants to `authenticated`: only the SECURITY DEFINER resolvers
-- (called by the service-role edge function) read/write this table.

CREATE OR REPLACE FUNCTION resolve_email_by_user_id(p_caller_id UUID, p_user_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    LOOKUP_WINDOW   CONSTANT INTERVAL := INTERVAL '1 hour';
    LOOKUP_MAX      CONSTANT INTEGER  := 30;   -- lookups per caller per window (shared w/ email->id)
    v_count INTEGER;
    v_email TEXT;
BEGIN
    IF p_caller_id IS NULL THEN
        RETURN jsonb_build_object('status', 'error', 'error', 'caller required');
    END IF;
    IF p_user_id IS NULL THEN
        RETURN jsonb_build_object('status', 'error', 'error', 'user id required');
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

    SELECT email INTO v_email
    FROM auth.users
    WHERE id = p_user_id
    LIMIT 1;

    IF v_email IS NULL THEN
        RETURN jsonb_build_object('status', 'not_found');
    END IF;
    RETURN jsonb_build_object('status', 'ok', 'email', v_email);
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('status', 'error', 'error', SQLERRM);
END;
$$;

REVOKE ALL ON FUNCTION resolve_email_by_user_id(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_email_by_user_id(UUID, UUID) TO service_role;

COMMIT;
