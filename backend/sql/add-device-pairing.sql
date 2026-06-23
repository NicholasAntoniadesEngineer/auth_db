-- ============================================================================
-- DEVICE PAIRING — pairing_requests table (run in Supabase SQL Editor)
-- ============================================================================
-- Holds a SHORT-LIVED, code-wrapped bundle (identity secret + session backup key)
-- that device 1 creates so device 2 can read all existing data. The bundle is
-- already PBKDF2+AES-GCM encrypted under a high-entropy one-time code BEFORE it is
-- stored here, and the row is RLS-scoped to the owner, single-use, and expiring.
-- Idempotent: safe to re-run.
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS pairing_requests (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    encrypted_data TEXT NOT NULL,   -- AES-GCM ciphertext of the JSON key bundle
    salt TEXT NOT NULL,             -- PBKDF2 salt (base64)
    iv TEXT NOT NULL,               -- AES-GCM IV (base64)
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
-- Column-scoped UPDATE: clients may only bump the attempt counter, nothing else.
GRANT UPDATE (attempts) ON pairing_requests TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE pairing_requests_id_seq TO authenticated;

COMMIT;
