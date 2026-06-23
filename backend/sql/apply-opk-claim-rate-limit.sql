-- ============================================================================
-- M-2 — RATE-LIMIT claim_one_time_prekey() + close the OPK enumeration oracle
-- ============================================================================
-- Run this ONCE on a LIVE auth_db / identity database that already has the
-- forward-secrecy prekey schema (prekeys / one_time_prekeys / the claim RPC,
-- from apply-forward-secrecy-schema.sql or complete-setup.sql).
--
-- WHAT IT FIXES (audit finding M-2):
--   1) claim_one_time_prekey() let ANY authenticated user pop a victim's OPKs in
--      an unthrottled loop until the pool was empty, silently downgrading every
--      future first-message to SPK-only X3DH (forward-secrecy DoS/downgrade).
--   2) one_time_prekeys_select_all USING(true) let any user ENUMERATE an arbitrary
--      victim's pool (count unconsumed OPKs / watch a drain), a free recon oracle.
--
-- WHAT IT DOES:
--   * Adds opk_claim_audit (one row per SUCCESSFUL claim) — RLS on, NO grants to
--     `authenticated`; the SECURITY DEFINER RPC is the only reader/writer.
--   * Replaces claim_one_time_prekey() with a version that enforces two sliding-
--     window token buckets BEFORE consuming an OPK:
--        per-(caller,target) <= 10 / hour   (single-attacker drain)
--        per-target          <= 60 / hour   (Sybil/multi-account drain)
--   * Replaces one_time_prekeys_select_all (USING true) with select_own
--     (auth.uid() = user_id). Session bootstrap NEVER needs a peer's OPKs via
--     SELECT — the DEFINER RPC hands them out one-at-a-time — so this is free.
--
-- ADDITIVE / NON-DESTRUCTIVE: CREATE TABLE IF NOT EXISTS, CREATE OR REPLACE
-- FUNCTION, DROP POLICY/INDEX IF EXISTS before re-create. No DROP TABLE, no data
-- rewrite. Safe to re-run. search_path is pinned and auth.uid() is re-asserted.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1) Close the OPK enumeration oracle: own-rows-only SELECT.
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS one_time_prekeys_select_all ON one_time_prekeys;
DROP POLICY IF EXISTS one_time_prekeys_select_own ON one_time_prekeys;
CREATE POLICY one_time_prekeys_select_own ON one_time_prekeys
    FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- ----------------------------------------------------------------------------
-- 2) Rate-limit ledger (service/DEFINER-written only).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS opk_claim_audit (
    id         BIGSERIAL PRIMARY KEY,
    caller_id  UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    target_id  UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE opk_claim_audit IS 'M-2: rate-limit ledger for claim_one_time_prekey(). One row per successful OPK claim; indexed on (target, claimed_at) and (caller, target, claimed_at) to drive the per-target and per-(caller,target) token buckets. Service/DEFINER-written only; no authenticated grants.';

DROP INDEX IF EXISTS idx_opk_claim_audit_target;
CREATE INDEX idx_opk_claim_audit_target
    ON opk_claim_audit(target_id, claimed_at);
DROP INDEX IF EXISTS idx_opk_claim_audit_caller_target;
CREATE INDEX idx_opk_claim_audit_caller_target
    ON opk_claim_audit(caller_id, target_id, claimed_at);

ALTER TABLE opk_claim_audit ENABLE ROW LEVEL SECURITY;
-- No policies and no grants to `authenticated`: only the SECURITY DEFINER RPC
-- (running as the table owner, which bypasses RLS) reads/writes this table.

-- ----------------------------------------------------------------------------
-- 3) Rate-limited claim RPC.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION claim_one_time_prekey(target_user_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    OPK_WINDOW           CONSTANT INTERVAL := INTERVAL '1 hour';
    OPK_MAX_PER_PAIR     CONSTANT INTEGER  := 10;   -- one caller vs one target / window
    OPK_MAX_PER_TARGET   CONSTANT INTEGER  := 60;   -- all callers vs one target / window
    v_uid          UUID := auth.uid();
    v_prekey       prekeys%ROWTYPE;
    v_opk          one_time_prekeys%ROWTYPE;
    v_pair_count   INTEGER;
    v_target_count INTEGER;
BEGIN
    IF v_uid IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'not authenticated');
    END IF;

    IF target_user_id IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'target_user_id required');
    END IF;

    SELECT * INTO v_prekey FROM prekeys WHERE user_id = target_user_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'no prekey bundle for target');
    END IF;

    SELECT count(*) INTO v_pair_count
    FROM opk_claim_audit
    WHERE caller_id = v_uid
      AND target_id = target_user_id
      AND claimed_at > NOW() - OPK_WINDOW;
    IF v_pair_count >= OPK_MAX_PER_PAIR THEN
        RETURN jsonb_build_object('success', false, 'error', 'rate limited',
                                  'retry_after_seconds', EXTRACT(EPOCH FROM OPK_WINDOW)::int);
    END IF;

    SELECT count(*) INTO v_target_count
    FROM opk_claim_audit
    WHERE target_id = target_user_id
      AND claimed_at > NOW() - OPK_WINDOW;
    IF v_target_count >= OPK_MAX_PER_TARGET THEN
        RETURN jsonb_build_object('success', false, 'error', 'rate limited',
                                  'retry_after_seconds', EXTRACT(EPOCH FROM OPK_WINDOW)::int);
    END IF;

    SELECT * INTO v_opk
    FROM one_time_prekeys
    WHERE user_id = target_user_id AND consumed = FALSE
    ORDER BY id
    FOR UPDATE SKIP LOCKED
    LIMIT 1;

    IF FOUND THEN
        UPDATE one_time_prekeys
        SET consumed = TRUE, consumed_at = NOW()
        WHERE id = v_opk.id;
        INSERT INTO opk_claim_audit (caller_id, target_id) VALUES (v_uid, target_user_id);
    END IF;

    RETURN jsonb_build_object(
        'success', true,
        'target_user_id', target_user_id,
        'identity_sign_pub', v_prekey.identity_sign_pub,
        'signed_prekey_pub', v_prekey.signed_prekey_pub,
        'signed_prekey_sig', v_prekey.signed_prekey_sig,
        'spk_id', v_prekey.spk_id,
        'opk_id',  CASE WHEN v_opk.id IS NOT NULL THEN v_opk.key_id     ELSE NULL END,
        'opk_pub', CASE WHEN v_opk.id IS NOT NULL THEN v_opk.prekey_pub ELSE NULL END
    );
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;

GRANT EXECUTE ON FUNCTION claim_one_time_prekey(UUID) TO authenticated;

COMMIT;
