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

-- Device keys (temporary storage for device pairing requests)
-- Pairing codes are short-lived (5 minutes) and contain encrypted identity keys
CREATE TABLE IF NOT EXISTS device_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_secret_key TEXT,
    encryption_nonce TEXT,
    pairing_code TEXT,
    expires_at TIMESTAMPTZ,
    is_primary BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON COLUMN device_keys.encrypted_secret_key IS 'Secret key encrypted with pairing-code-derived key (XSalsa20-Poly1305)';
COMMENT ON COLUMN device_keys.encryption_nonce IS 'Nonce used for secret key encryption';
COMMENT ON COLUMN device_keys.pairing_code IS '6-digit code for device pairing (expires after 5 minutes)';

DROP INDEX IF EXISTS idx_device_keys_user_id;
DROP INDEX IF EXISTS idx_device_keys_pairing_code;
CREATE INDEX idx_device_keys_user_id ON device_keys(user_id);
CREATE INDEX idx_device_keys_pairing_code ON device_keys(pairing_code) WHERE pairing_code IS NOT NULL;

ALTER TABLE device_keys ENABLE ROW LEVEL SECURITY;

-- SM-21: device_keys is correctly owner-scoped on every operation below
-- (auth.uid() = user_id), so no row is ever exposed beyond its owner.
-- NOTE: the 5-minute `expires_at` is NOT enforced here. The pairing flow that
-- writes these rows is being disabled separately; if it is ever re-enabled the
-- SELECT policy MUST also require `expires_at > now()` and a scheduled
-- `DELETE FROM device_keys WHERE expires_at < now()` must reap stale rows, so an
-- expired row holding the (weakly wrapped) identity secret cannot linger.
CREATE POLICY device_keys_select_own ON device_keys
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY device_keys_insert_own ON device_keys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY device_keys_update_own ON device_keys
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY device_keys_delete_own ON device_keys
    FOR DELETE USING (auth.uid() = user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON device_keys TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE device_keys_id_seq TO authenticated;

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
DROP POLICY IF EXISTS pairing_requests_select_own ON pairing_requests;
CREATE POLICY pairing_requests_select_own ON pairing_requests
    FOR SELECT USING (auth.uid() = user_id);
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
