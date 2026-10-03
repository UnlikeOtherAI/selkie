-- An unadmitted UOA family remains encrypted and unusable until cleanup succeeds.
ALTER TABLE uoa_sessions ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE uoa_sessions ADD CONSTRAINT uoa_sessions_unadmitted_closing
    CHECK (user_id IS NOT NULL OR closing);
CREATE INDEX uoa_sessions_pending_cleanup ON uoa_sessions(created_at) WHERE closing;
