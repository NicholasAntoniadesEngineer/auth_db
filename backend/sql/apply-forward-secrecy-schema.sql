-- ============================================================================
-- FORWARD SECRECY — X3DH PREKEY SCHEMA (run ONCE in the Supabase SQL Editor)
-- ============================================================================
-- IDENTITY-SIDE migration for FORWARD_SECRECY_DESIGN.md (step S3). Adds the X3DH
-- prekey tables + the one-time-prekey claim RPC to an EXISTING auth_db / identity
-- database. ADDITIVE ONLY: it creates new objects and NEVER drops or rewrites any
-- existing table, column, policy, grant, or data. Safe to re-run (idempotent):
--   - CREATE TABLE IF NOT EXISTS
--   - CREATE OR REPLACE FUNCTION / TRIGGER guarded by DROP TRIGGER IF EXISTS
--   - DROP POLICY IF EXISTS before each CREATE POLICY
--   - DROP INDEX IF EXISTS before each CREATE INDEX
--
-- These tables hold ONLY PUBLIC key material (Ed25519 identity-signing public key,
-- X25519 signed-prekey public + its Ed25519 signature, and a pool of one-time prekey
-- publics). Secrets never leave the client.
--
-- Companion migration (run separately on the MESSAGING database):
--   secure_db/sql/apply-forward-secrecy-schema.sql  (adds the messages ratchet/X3DH columns)
--
-- DEPLOY ORDER: run BOTH migrations BEFORE shipping the forward-secrecy client (S4-S6).
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- prekeys: exactly one row per user (the latest signed prekey bundle).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS prekeys (
    user_id            UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    identity_sign_pub  TEXT NOT NULL,   -- Ed25519 IK_sig public key (base64)
    signed_prekey_pub  TEXT NOT NULL,   -- X25519 SPK public key (base64)
    signed_prekey_sig  TEXT NOT NULL,   -- Ed25519 signature over SPK pub (base64)
    spk_id             INTEGER NOT NULL,-- SPK rotation id (which signed prekey this is)
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE prekeys IS 'X3DH signed-prekey bundle, one row per user. Public material only; SELECT-able by any authenticated user for session bootstrap.';
COMMENT ON COLUMN prekeys.identity_sign_pub IS 'Ed25519 identity-signing public key (TOFU-pinned by peers). Separate from the X25519 identity_keys.public_key.';
COMMENT ON COLUMN prekeys.spk_id IS 'Signed-prekey rotation id; bumped each time the user rotates their SPK.';

CREATE OR REPLACE FUNCTION update_prekeys_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trigger_update_prekeys_updated_at ON prekeys;
CREATE TRIGGER trigger_update_prekeys_updated_at
    BEFORE UPDATE ON prekeys
    FOR EACH ROW
    EXECUTE FUNCTION update_prekeys_updated_at();

ALTER TABLE prekeys ENABLE ROW LEVEL SECURITY;

-- SELECT: any authenticated user may read any user's published prekey bundle, exactly
-- like identity_keys_select_all — a sender needs the peer's SPK + signature to run X3DH.
-- (Never anon: TO authenticated only.)
DROP POLICY IF EXISTS prekeys_select_all ON prekeys;
CREATE POLICY prekeys_select_all ON prekeys
    FOR SELECT TO authenticated USING (true);

-- INSERT/UPDATE/DELETE: owner only. WITH CHECK on INSERT and UPDATE stops a user from
-- writing or reassigning a bundle under another user_id (forging another user's prekeys).
DROP POLICY IF EXISTS prekeys_insert_own ON prekeys;
CREATE POLICY prekeys_insert_own ON prekeys
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS prekeys_update_own ON prekeys;
CREATE POLICY prekeys_update_own ON prekeys
    FOR UPDATE TO authenticated USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS prekeys_delete_own ON prekeys;
CREATE POLICY prekeys_delete_own ON prekeys
    FOR DELETE TO authenticated USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON prekeys TO authenticated;

-- ----------------------------------------------------------------------------
-- one_time_prekeys: a per-user pool of single-use X25519 prekeys (OPKs).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,  -- client-assigned OPK id (echoed in the X3DH preamble)
    prekey_pub  TEXT NOT NULL,     -- X25519 OPK public key (base64)
    consumed    BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, key_id)
);

COMMENT ON TABLE one_time_prekeys IS 'Pool of one-time X3DH prekeys (public only). Published by the owner; consumed ONE-at-a-time by a peer via claim_one_time_prekey(). Each OPK is used at most once.';
COMMENT ON COLUMN one_time_prekeys.consumed IS 'Marked TRUE atomically by claim_one_time_prekey() when a peer claims this OPK (consume-once).';

DROP INDEX IF EXISTS idx_one_time_prekeys_user_unconsumed;
-- Partial index drives the claim RPC: fetch one unconsumed OPK for a target fast.
CREATE INDEX idx_one_time_prekeys_user_unconsumed
    ON one_time_prekeys(user_id) WHERE consumed = FALSE;

ALTER TABLE one_time_prekeys ENABLE ROW LEVEL SECURITY;

-- SELECT (M-2 hardening): a caller may read ONLY their OWN OPK pool. The previous
-- USING(true) let any authenticated user enumerate an arbitrary victim's pool
-- (count unconsumed OPKs, watch a drain in progress) — a free recon oracle that
-- paired with the unthrottled claim RPC to make a targeted forward-secrecy drain
-- trivial to plan. Legitimate session bootstrap NEVER needs to SELECT a peer's
-- OPKs directly: the OPK is handed out one-at-a-time by claim_one_time_prekey()
-- (SECURITY DEFINER, which bypasses RLS), so closing client SELECT to own-rows
-- only costs nothing functionally. Public SPK/identity material still lives in
-- prekeys/identity_keys for X3DH; the OPK pool itself is no longer enumerable.
DROP POLICY IF EXISTS one_time_prekeys_select_all ON one_time_prekeys;
DROP POLICY IF EXISTS one_time_prekeys_select_own ON one_time_prekeys;
CREATE POLICY one_time_prekeys_select_own ON one_time_prekeys
    FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- INSERT: owner only — a user may only publish OPKs into their OWN pool.
DROP POLICY IF EXISTS one_time_prekeys_insert_own ON one_time_prekeys;
CREATE POLICY one_time_prekeys_insert_own ON one_time_prekeys
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

-- UPDATE: owner only (e.g. local bookkeeping). Consumption of ANOTHER user's OPK is
-- done by the SECURITY DEFINER RPC, which bypasses RLS; ordinary clients cannot mark a
-- peer's OPK consumed via this policy.
DROP POLICY IF EXISTS one_time_prekeys_update_own ON one_time_prekeys;
CREATE POLICY one_time_prekeys_update_own ON one_time_prekeys
    FOR UPDATE TO authenticated USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- DELETE: owner only — replenishment/cleanup of one's own pool. A SENDER cannot DELETE
-- a peer's OPK directly; that is the whole reason claim is an RPC.
DROP POLICY IF EXISTS one_time_prekeys_delete_own ON one_time_prekeys;
CREATE POLICY one_time_prekeys_delete_own ON one_time_prekeys
    FOR DELETE TO authenticated USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON one_time_prekeys TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE one_time_prekeys_id_seq TO authenticated;

-- ----------------------------------------------------------------------------
-- opk_claim_audit (M-2): one row per successful claim, the backing store for the
-- per-(caller,target) and per-target rate limits enforced inside the claim RPC.
-- SERVICE/DEFINER-written only — RLS is enabled and NO grants are issued to
-- `authenticated`, so an ordinary client can neither read it (it would leak who
-- is talking to whom) nor forge/clear entries to dodge the cap. The DEFINER
-- function writes it while running as the table owner, which bypasses RLS.
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
-- No policies, no grants to `authenticated`: the SECURITY DEFINER RPC is the sole
-- writer/reader. Ordinary clients cannot SELECT (privacy) or DELETE (cap-evasion).

-- ----------------------------------------------------------------------------
-- claim_one_time_prekey(target): atomically pop ONE unconsumed OPK for the target user
-- and return the full X3DH bundle the caller needs to bootstrap a session. SECURITY
-- DEFINER (mirrors start_trial/ensure_subscription) because consuming a PEER'S OPK
-- requires writing a row RLS would otherwise forbid; we re-assert auth.uid() inside and
-- reject NULL so the elevated function cannot be abused by an unauthenticated caller.
-- The OPK select-and-mark is done with FOR UPDATE SKIP LOCKED so two concurrent callers
-- never claim the same OPK (each skips a row another transaction has locked). If the
-- pool is empty, opk_id/opk_pub come back NULL and the caller falls back to SPK-only
-- X3DH (drop DH4) — spec-permitted (FORWARD_SECRECY_DESIGN.md §2.2).
--
-- M-2 RATE LIMIT: before consuming, the function counts recent SUCCESSFUL claims in
-- opk_claim_audit over a sliding window and rejects past two caps:
--   * per-(caller,target): a single user may claim at most OPK_MAX_PER_PAIR OPKs from
--     one victim per window — blocks a single attacker draining a victim's pool.
--   * per-target (all callers): at most OPK_MAX_PER_TARGET claims against one victim per
--     window — blocks a Sybil/multi-account drain of the same victim.
-- Both are token-bucket-style (count within NOW()-window). A legitimate sender opens
-- very few sessions per target per hour, so the caps sit far above honest traffic.
-- Caps/window are intentionally generous; tighten via this single definition if abused.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION claim_one_time_prekey(target_user_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    -- Token-bucket parameters (sliding window). Honest first-contact traffic is a
    -- handful of claims per target per hour; these caps sit well above that.
    OPK_WINDOW           CONSTANT INTERVAL := INTERVAL '1 hour';
    OPK_MAX_PER_PAIR     CONSTANT INTEGER  := 10;   -- one caller vs one target / window
    OPK_MAX_PER_TARGET   CONSTANT INTEGER  := 60;   -- all callers vs one target / window
    v_uid          UUID := auth.uid();
    v_prekey       prekeys%ROWTYPE;
    v_opk          one_time_prekeys%ROWTYPE;
    v_pair_count   INTEGER;
    v_target_count INTEGER;
BEGIN
    -- Re-assert the caller identity inside the SECURITY DEFINER body (defense in depth).
    IF v_uid IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'not authenticated');
    END IF;

    IF target_user_id IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'target_user_id required');
    END IF;

    -- The target must have a published signed-prekey bundle to be reachable.
    SELECT * INTO v_prekey FROM prekeys WHERE user_id = target_user_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'no prekey bundle for target');
    END IF;

    -- M-2: enforce the token buckets BEFORE consuming an OPK. Count only SUCCESSFUL
    -- claims (rows are written below only when an OPK was actually consumed), so a
    -- run of SPK-only fallbacks (empty pool) does not burn the caller's budget.
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

    -- Atomically grab ONE unconsumed OPK. FOR UPDATE SKIP LOCKED makes concurrent
    -- claims pick DIFFERENT rows (no double-claim, no blocking). May return zero rows
    -- (pool exhausted) — that is a valid SPK-only fallback, not an error.
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
        -- Record the SUCCESSFUL claim against both buckets. Only real consumptions
        -- count toward the cap (SPK-only fallback does not).
        INSERT INTO opk_claim_audit (caller_id, target_id) VALUES (v_uid, target_user_id);
    END IF;

    RETURN jsonb_build_object(
        'success', true,
        'target_user_id', target_user_id,
        'identity_sign_pub', v_prekey.identity_sign_pub,
        'signed_prekey_pub', v_prekey.signed_prekey_pub,
        'signed_prekey_sig', v_prekey.signed_prekey_sig,
        'spk_id', v_prekey.spk_id,
        -- opk_id/opk_pub are NULL when the pool is exhausted (SPK-only X3DH fallback).
        'opk_id',  CASE WHEN v_opk.id IS NOT NULL THEN v_opk.key_id     ELSE NULL END,
        'opk_pub', CASE WHEN v_opk.id IS NOT NULL THEN v_opk.prekey_pub ELSE NULL END
    );
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;

GRANT EXECUTE ON FUNCTION claim_one_time_prekey(UUID) TO authenticated;

COMMIT;
