-- ============================================================
-- auth_db — COMPLETE IDENTITY / E2E-CRYPTO SCHEMA (run ONCE on a fresh database)
-- Single self-contained file: extensions + all identity tables/policies/pairing.
-- DESTRUCTIVE (DROPs) — fresh install only. For an existing DB add pairing via
-- add-device-pairing.sql.
-- ============================================================
-- Extensions (required on a fresh project; idempotent)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- AUTH_DB — IDENTITY / E2E CRYPTO SCHEMA (canonical)
-- ============================================================================
-- Owns the identity & key-management tables that the encryption subsystem (now
-- hosted in auth_db/encryption) depends on. Messaging tables (conversations,
-- messages, attachments, conversation_session_keys, friends) live in
-- secure_db/sql/messaging-schema.sql. There are NO cross-FKs between the two, so
-- either order works; convention is identity first.
-- FRESH-INSTALL schema: the DROP statements below are DESTRUCTIVE. Do NOT run this
-- on a live DB (it would wipe identity keys + backups). To add device pairing to an
-- EXISTING DB, run add-device-pairing.sql instead. Requires 00_init_extensions.sql.
-- ============================================================================

-- Cleanup (identity tables only)
DROP TABLE IF EXISTS device_keys CASCADE;
DROP TABLE IF EXISTS paired_devices CASCADE;
DROP TABLE IF EXISTS key_rotation_locks CASCADE;
DROP TABLE IF EXISTS public_key_history CASCADE;
DROP TABLE IF EXISTS pairing_requests CASCADE;
DROP TABLE IF EXISTS identity_key_backups CASCADE;
DROP TABLE IF EXISTS identity_keys CASCADE;
DROP FUNCTION IF EXISTS update_identity_keys_updated_at() CASCADE;

-- ---- identity_keys, public_key_history, paired_devices, device_keys, key_rotation_locks ----
-- Identity keys (public keys for key exchange)
CREATE TABLE IF NOT EXISTS identity_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    current_epoch INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN identity_keys.current_epoch IS 'Current key epoch. Incremented on each key regeneration for key rotation support.';

CREATE OR REPLACE FUNCTION update_identity_keys_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_update_identity_keys_updated_at
    BEFORE UPDATE ON identity_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_identity_keys_updated_at();

DROP INDEX IF EXISTS idx_identity_keys_user_id;
CREATE INDEX idx_identity_keys_user_id ON identity_keys(user_id);

ALTER TABLE identity_keys ENABLE ROW LEVEL SECURITY;

-- SM-14: restrict SELECT to authenticated users only (no anon/world access).
-- Public keys must remain readable by every authenticated user for key exchange,
-- but never by the anon role. (Authenticity/TOFU pinning and routing discovery
-- through the rate-limited user-lookup edge function are tracked under SM-01/SM-20.)
CREATE POLICY identity_keys_select_all ON identity_keys
    FOR SELECT TO authenticated USING (true);

CREATE POLICY identity_keys_insert_own ON identity_keys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY identity_keys_update_own ON identity_keys
    FOR UPDATE USING (auth.uid() = user_id)
    -- HARDENING: WITH CHECK stops a user reassigning their key row to another user_id.
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY identity_keys_delete_own ON identity_keys
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_keys TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE identity_keys_id_seq TO authenticated;

-- Public key history (stores historical public keys for epoch-based decryption)
-- When a user regenerates keys, their old public key is archived here
CREATE TABLE IF NOT EXISTS public_key_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, epoch)
);

DROP INDEX IF EXISTS idx_public_key_history_user_epoch;
CREATE INDEX idx_public_key_history_user_epoch ON public_key_history(user_id, epoch);

ALTER TABLE public_key_history ENABLE ROW LEVEL SECURITY;

-- Public keys are readable by all authenticated users (needed for decryption)
CREATE POLICY public_key_history_select_all ON public_key_history
    FOR SELECT TO authenticated USING (true);

-- Users can only insert their own historical keys
CREATE POLICY public_key_history_insert_own ON public_key_history
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

GRANT SELECT, INSERT ON public_key_history TO authenticated;

COMMENT ON TABLE public_key_history IS 'Historical public keys for epoch-based decryption of old messages';
COMMENT ON COLUMN public_key_history.epoch IS 'Key epoch - increments each time user regenerates keys';

-- NOTE: user_key_backups table has been REMOVED and consolidated into identity_key_backups
-- The identity_key_backups table (defined later) stores:
-- - Password-encrypted identity secret key
-- - Recovery-key encrypted identity secret key
-- - Stable session backup key for multi-device support
-- Public keys are stored in the identity_keys table

-- Paired devices (for multi-device support)
CREATE TABLE IF NOT EXISTS paired_devices (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    device_fingerprint TEXT,
    is_primary BOOLEAN DEFAULT false,
    last_active TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN paired_devices.device_fingerprint IS 'Browser fingerprint for device identification';

DROP INDEX IF EXISTS idx_paired_devices_user_id;
CREATE INDEX idx_paired_devices_user_id ON paired_devices(user_id);

ALTER TABLE paired_devices ENABLE ROW LEVEL SECURITY;

CREATE POLICY paired_devices_select_own ON paired_devices
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY paired_devices_insert_own ON paired_devices
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY paired_devices_update_own ON paired_devices
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY paired_devices_delete_own ON paired_devices
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON paired_devices TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE paired_devices_id_seq TO authenticated;

-- ADB-05/CR-4: the deprecated `device_keys` table (CREATE/index/policy/grant) has
-- been removed — superseded by pairing_requests for the code-wrapped key handoff. It
-- is not referenced by the encryption config (only `paired_devices` is) and its
-- never-enforced 5-minute expiry left weakly-wrapped identity secrets able to linger.
-- The `DROP TABLE IF EXISTS device_keys CASCADE` in the cleanup section above stays so
-- re-running this script removes it from existing databases. (paired_devices is kept —
-- still referenced by the encryption config.)

-- Key rotation locks (prevents concurrent key rotations across devices/tabs)
CREATE TABLE IF NOT EXISTS key_rotation_locks (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    lock_token TEXT NOT NULL,
    locked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

COMMENT ON COLUMN key_rotation_locks.lock_token IS 'Unique token to identify lock owner';
COMMENT ON COLUMN key_rotation_locks.expires_at IS 'Lock auto-expires to prevent deadlocks (default 60 seconds)';

ALTER TABLE key_rotation_locks ENABLE ROW LEVEL SECURITY;

CREATE POLICY rotation_locks_select_own ON key_rotation_locks
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY rotation_locks_insert_own ON key_rotation_locks
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY rotation_locks_update_own ON key_rotation_locks
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY rotation_locks_delete_own ON key_rotation_locks
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON key_rotation_locks TO authenticated;


-- ---- pairing_requests (device pairing) ----
-- DEVICE PAIRING: pairing_requests (code-wrapped key handoff for multi-device)
-- The bundle (identity secret + session backup key) is PBKDF2+AES-GCM encrypted
-- under a one-time high-entropy code BEFORE storage; rows are RLS-owner-scoped,
-- single-use, and expiring. UPDATE is column-scoped to the attempt counter.
-- ============================================================
CREATE TABLE IF NOT EXISTS pairing_requests (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    encrypted_data TEXT NOT NULL,
    salt TEXT NOT NULL,
    iv TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pairing_requests_user_id ON pairing_requests(user_id);
ALTER TABLE pairing_requests ENABLE ROW LEVEL SECURITY;
-- ADB-03/RLS-09: defense-in-depth — an EXPIRED wrapped bundle must not be selectable
-- even before it is physically reaped. NOTE: the load-bearing half is an operator-set
-- pg_cron reaper: `DELETE FROM pairing_requests WHERE expires_at < now();` (RLS only
-- hides expired rows; it does not delete the at-rest ciphertext).
DROP POLICY IF EXISTS pairing_requests_select_own ON pairing_requests;
CREATE POLICY pairing_requests_select_own ON pairing_requests
    FOR SELECT USING (auth.uid() = user_id AND expires_at > now());
DROP POLICY IF EXISTS pairing_requests_insert_own ON pairing_requests;
CREATE POLICY pairing_requests_insert_own ON pairing_requests
    FOR INSERT WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS pairing_requests_update_own ON pairing_requests;
CREATE POLICY pairing_requests_update_own ON pairing_requests
    FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS pairing_requests_delete_own ON pairing_requests;
CREATE POLICY pairing_requests_delete_own ON pairing_requests
    FOR DELETE USING (auth.uid() = user_id);
GRANT SELECT, INSERT, DELETE ON pairing_requests TO authenticated;
GRANT UPDATE (attempts) ON pairing_requests TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE pairing_requests_id_seq TO authenticated;

-- ---- identity_key_backups (password/recovery backups + session backup key) ----
-- Password and recovery key encrypted identity key backups
-- Also stores the stable session backup key for multi-device support
CREATE TABLE IF NOT EXISTS identity_key_backups (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    -- Password-encrypted identity secret key
    password_encrypted_data TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_iv TEXT NOT NULL,
    -- Recovery-key encrypted identity secret key
    recovery_encrypted_data TEXT NOT NULL,
    recovery_salt TEXT NOT NULL,
    recovery_iv TEXT NOT NULL,
    -- Stable session backup key (encrypted with password)
    -- This key survives identity key rotation for reliable multi-device sync
    session_backup_key_encrypted TEXT,
    session_backup_key_salt TEXT,
    session_backup_key_iv TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id)
);

DROP INDEX IF EXISTS idx_key_backups_user_id;
CREATE INDEX idx_key_backups_user_id ON identity_key_backups(user_id);

ALTER TABLE identity_key_backups ENABLE ROW LEVEL SECURITY;

CREATE POLICY key_backups_select_own ON identity_key_backups
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY key_backups_insert_own ON identity_key_backups
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY key_backups_update_own ON identity_key_backups
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY key_backups_delete_own ON identity_key_backups
    FOR DELETE USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION update_key_backups_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_update_key_backups_updated_at
    BEFORE UPDATE ON identity_key_backups
    FOR EACH ROW
    EXECUTE FUNCTION update_key_backups_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_key_backups TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE identity_key_backups_id_seq TO authenticated;

-- identity performance indexes (moved from the messaging schema)
CREATE INDEX IF NOT EXISTS idx_identity_keys_updated ON identity_keys(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_public_key_history_user_epoch ON public_key_history(user_id, epoch);

-- ============================================================================
-- FORWARD SECRECY — X3DH PREKEYS (prekeys + one_time_prekeys + claim RPC)
-- ============================================================================
-- Supports the X3DH async handshake (FORWARD_SECRECY_DESIGN.md §2.2). These hold
-- ONLY PUBLIC key material — the Ed25519 identity-signing public key, the signed
-- prekey public key + its Ed25519 signature, and a pool of one-time prekey publics.
-- Secrets never leave the client. RLS mirrors identity_keys: every authenticated
-- user may SELECT any peer's published prekeys to start a session, but only the
-- owner may publish/replace/remove their own rows. One-time prekeys are consumed
-- atomically via the claim_one_time_prekey() SECURITY DEFINER RPC below (own-row
-- DELETE is intentionally NOT granted, so a sender cannot drain a peer's pool by
-- hand — they must go through the rate-limitable, one-at-a-time RPC).
-- ADDITIVE: CREATE TABLE IF NOT EXISTS only — no DROP, so this is safe to run on a
-- live DB. (The DROPs at the top of this file are identity-table-only.)

-- prekeys: exactly one row per user (the latest signed prekey bundle).
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

-- one_time_prekeys: a per-user pool of single-use X25519 prekeys (OPKs).
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

-- SELECT: any authenticated user may read OPK rows (the public pool); the actual
-- one-shot consumption is done by the RPC, not by client SELECT, so reading is benign.
DROP POLICY IF EXISTS one_time_prekeys_select_all ON one_time_prekeys;
CREATE POLICY one_time_prekeys_select_all ON one_time_prekeys
    FOR SELECT TO authenticated USING (true);

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

-- claim_one_time_prekey(target): atomically pop ONE unconsumed OPK for the target user
-- and return the full X3DH bundle the caller needs to bootstrap a session. SECURITY
-- DEFINER (mirrors start_trial/ensure_subscription) because consuming a PEER'S OPK
-- requires writing a row RLS would otherwise forbid; we re-assert auth.uid() inside and
-- reject NULL so the elevated function cannot be abused by an unauthenticated caller.
-- The OPK select-and-mark is done with FOR UPDATE SKIP LOCKED so two concurrent callers
-- never claim the same OPK (each skips a row another transaction has locked). If the
-- pool is empty, opk_id/opk_pub come back NULL and the caller falls back to SPK-only
-- X3DH (drop DH4) — spec-permitted (FORWARD_SECRECY_DESIGN.md §2.2).
CREATE OR REPLACE FUNCTION claim_one_time_prekey(target_user_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid     UUID := auth.uid();
    v_prekey  prekeys%ROWTYPE;
    v_opk     one_time_prekeys%ROWTYPE;
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
