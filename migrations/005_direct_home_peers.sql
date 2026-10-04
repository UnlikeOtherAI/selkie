ALTER TABLE devices DROP CONSTRAINT devices_os_platform_check;
ALTER TABLE devices ADD CONSTRAINT devices_os_platform_check
 CHECK (os_platform IN ('darwin','linux','windows','ios','android','tvos'));
-- Product-specific explicit service exposure, never a copied human identity.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS direct_scoped boolean NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS direct_home_port integer
    CHECK (direct_home_port BETWEEN 1 AND 65535);

CREATE OR REPLACE FUNCTION notify_direct_peers() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('selkie_direct_peers', 'changed');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER direct_device_updates AFTER INSERT OR UPDATE OR DELETE ON devices
FOR EACH STATEMENT EXECUTE FUNCTION notify_direct_peers();
CREATE TRIGGER direct_key_updates AFTER INSERT OR UPDATE OR DELETE ON device_keys
FOR EACH STATEMENT EXECUTE FUNCTION notify_direct_peers();

CREATE TABLE direct_home_grants (
 mobile_device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 home_device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY (mobile_device_id,home_device_id)
);
CREATE TRIGGER direct_grant_updates AFTER INSERT OR UPDATE OR DELETE ON direct_home_grants
FOR EACH STATEMENT EXECUTE FUNCTION notify_direct_peers();
