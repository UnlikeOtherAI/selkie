-- A short admission window prevents maintenance racing an in-flight profile read.
ALTER TABLE uoa_sessions ADD COLUMN cleanup_after timestamptz NOT NULL DEFAULT now();
