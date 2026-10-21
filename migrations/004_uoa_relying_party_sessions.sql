-- Stable users UUIDs remain product ownership and audit references.
-- Profile removal is owned by shipped 006_uoa_reference_only.sql.
-- Keep its original ordering valid for fresh and already-upgraded installs.
CREATE TABLE uoa_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject text NOT NULL,
    organization_id text,
    team_id text,
    sealed_refresh bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    closing boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX uoa_sessions_expiry ON uoa_sessions (expires_at);
ALTER TABLE mobile_handoff_codes ADD COLUMN session_id uuid REFERENCES uoa_sessions(id) ON DELETE CASCADE;
-- Old handoffs discarded their UOA capability and cannot become sessions.
DELETE FROM mobile_handoff_codes;
