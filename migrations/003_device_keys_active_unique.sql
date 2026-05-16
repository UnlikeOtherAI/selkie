-- Scope the wg_public_key uniqueness constraint to active rows only.
--
-- The previous global UNIQUE index (uq_device_keys_public_key) allowed a
-- pre-registration hijack: an attacker could enroll with a victim's known
-- public key, permanently blocking the victim from enrolling their own device.
--
-- Replacing it with a partial index scoped to state='active' reduces the blast
-- radius: an attacker key can still cause a collision while their row is active,
-- but once that row is retired or revoked the victim can claim the key. Proof-
-- of-possession at enrollment time (a full mitigation) is deferred as a
-- separate larger change.
--
-- Down / revert: this migration is intentionally one-directional. Re-adding the
-- global unique index on an existing schema with retired/revoked duplicate keys
-- would fail. If a rollback is needed, restore from a pre-migration snapshot or
-- re-add the index manually after cleaning up any duplicate key rows.

-- Up
ALTER TABLE device_keys DROP CONSTRAINT IF EXISTS device_keys_wg_public_key_key;
DROP INDEX IF EXISTS uq_device_keys_public_key;

-- Pre-step: if any environment somehow contains multiple state='active' rows
-- sharing a wg_public_key (e.g. the race the partial index is designed to
-- close fired before this migration ran), retire all but the newest row per
-- key so CREATE UNIQUE INDEX below does not abort the migration tx and leave
-- a fleet of replicas unable to boot.
UPDATE device_keys
SET state = 'retired', retired_at = COALESCE(retired_at, now())
WHERE id IN (
    SELECT id FROM (
        SELECT id,
               row_number() OVER (PARTITION BY wg_public_key ORDER BY created_at DESC, id DESC) AS rn
        FROM device_keys
        WHERE state = 'active'
    ) ranked
    WHERE rn > 1
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_device_keys_active_public_key
    ON device_keys (wg_public_key)
    WHERE state = 'active';
