ALTER TABLE uoa_sessions RENAME COLUMN sealed_refresh TO sealed_capability;
ALTER TABLE uoa_sessions ADD COLUMN capability_kind text NOT NULL DEFAULT 'refresh'
    CHECK (capability_kind IN ('refresh', 'broker', 'development'));
