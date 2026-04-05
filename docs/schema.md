# Database Schema

Full PostgreSQL DDL for every persisted entity. Run via the migration tool on
server startup (`/migrations/` directory, applied in order).

---

## Extensions

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive text for email
```

---

## Tables

### `users`

```sql
CREATE TABLE users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sub           TEXT        NOT NULL UNIQUE,   -- UOA subject claim
    email         CITEXT      NOT NULL UNIQUE,
    display_name  TEXT        NOT NULL DEFAULT '',
    is_super      BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX users_sub_idx ON users (sub);
```

Notes:
- `sub` is the stable identifier from the UOA token (`sub` claim).
- `is_super` is set to `TRUE` for the first user to complete login when the
  `users` table is empty. Only one super user is set this way; subsequent
  super users require a direct DB update.

---

### `devices`

```sql
CREATE TABLE devices (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hostname            TEXT        NOT NULL,
    overlay_ip          INET        UNIQUE,          -- assigned from overlay CIDR pool
    status              TEXT        NOT NULL DEFAULT 'active'
                                    CHECK (status IN ('active','revoked','quarantined')),

    -- Hardware / OS fingerprint (reported at enrollment and refreshed on heartbeat)
    os_platform         TEXT,        -- darwin | linux | win32
    os_version          TEXT,
    os_arch             TEXT,
    kernel_version      TEXT,
    cpu_model           TEXT,
    cpu_cores           INTEGER,
    cpu_speed_mhz       INTEGER,
    total_memory_bytes  BIGINT,
    disk_total_bytes    BIGINT,
    disk_free_bytes     BIGINT,
    network_interfaces  JSONB,       -- [{name, mac, addresses:[]}]
    agent_version       TEXT,

    -- Metadata
    tags                TEXT[]      NOT NULL DEFAULT '{}',
    capabilities        TEXT[]      NOT NULL DEFAULT '{}',
    last_heartbeat_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Overlay IP reclaim: set when device is revoked; IP freed after 24h grace
    overlay_ip_released_at TIMESTAMPTZ
);

CREATE INDEX devices_owner_idx     ON devices (owner_id);
CREATE INDEX devices_status_idx    ON devices (status);
CREATE INDEX devices_overlay_ip_idx ON devices (overlay_ip);
```

---

### `device_keys`

Stores the current WireGuard public key for each device. Previous keys are
retained for audit and key rotation overlap.

```sql
CREATE TABLE device_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key  TEXT        NOT NULL,             -- base64 WireGuard pubkey
    is_current  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX device_keys_current_idx
    ON device_keys (device_id)
    WHERE is_current = TRUE;

CREATE INDEX device_keys_device_idx ON device_keys (device_id);
```

Notes:
- Only one key per device may have `is_current = TRUE` (enforced by partial unique index).
- On key rotation: set the old row `is_current = FALSE`, `retired_at = NOW()`,
  insert a new row with `is_current = TRUE`.

---

### `device_credentials`

Long-lived opaque device credentials (stored as bcrypt hash; plaintext never
persisted).

```sql
CREATE TABLE device_credentials (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id     UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    credential_hash TEXT      NOT NULL,   -- bcrypt of the 32-byte random token
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX device_credentials_device_idx ON device_credentials (device_id);
CREATE INDEX device_credentials_active_idx
    ON device_credentials (device_id)
    WHERE is_active = TRUE;
```

---

### `services`

Service catalog — one row per listening port/protocol reported by a device.

```sql
CREATE TABLE services (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id      UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name           TEXT        NOT NULL DEFAULT '',  -- user-annotated friendly name
    protocol       TEXT        NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp','udp')),
    port           INTEGER     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    description    TEXT        NOT NULL DEFAULT '',
    tags           TEXT[]      NOT NULL DEFAULT '{}',
    is_visible     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (device_id, protocol, port)
);

CREATE INDEX services_device_idx ON services (device_id);
```

---

### `connect_sessions`

ICE session broker records. One row per connection attempt.

```sql
CREATE TABLE connect_sessions (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_device_id   UUID        NOT NULL REFERENCES devices(id),
    target_device_id      UUID        NOT NULL REFERENCES devices(id),
    service_id            UUID        REFERENCES services(id),
    status                TEXT        NOT NULL DEFAULT 'pending'
                                      CHECK (status IN (
                                          'pending','exchanging','connected',
                                          'relay','closed','failed'
                                      )),

    -- ICE candidate sets (stored as JSON arrays of candidate strings)
    candidate_set_requester JSONB,
    candidate_set_target    JSONB,

    -- Path selected after ICE exchange
    selected_path         TEXT        CHECK (selected_path IN ('direct','relay')),

    -- Timing
    requested_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    connected_at          TIMESTAMPTZ,
    closed_at             TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
);

CREATE INDEX connect_sessions_requester_idx ON connect_sessions (requester_device_id);
CREATE INDEX connect_sessions_target_idx    ON connect_sessions (target_device_id);
CREATE INDEX connect_sessions_status_idx    ON connect_sessions (status);
CREATE INDEX connect_sessions_expires_idx   ON connect_sessions (expires_at)
    WHERE status NOT IN ('closed','failed');
```

Notes:
- `candidate_set_*` are written during the ICE exchange and retained for audit.
- `selected_path` is written once after path selection completes.

---

### `relay_credentials`

Short-lived TURN credentials minted per session.

```sql
CREATE TABLE relay_credentials (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID        NOT NULL REFERENCES connect_sessions(id) ON DELETE CASCADE,
    device_id       UUID        NOT NULL REFERENCES devices(id),
    username        TEXT        NOT NULL,   -- coturn TURN REST API username
    password        TEXT        NOT NULL,   -- HMAC-SHA1 credential
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX relay_credentials_session_idx ON relay_credentials (session_id);
CREATE INDEX relay_credentials_expires_idx ON relay_credentials (expires_at)
    WHERE revoked_at IS NULL;
```

---

### `relay_allocations`

Per-session relay usage records, written when a TURN allocation is observed.

```sql
CREATE TABLE relay_allocations (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id   UUID        NOT NULL REFERENCES relay_credentials(id),
    session_id      UUID        NOT NULL REFERENCES connect_sessions(id),
    relay_host      TEXT        NOT NULL,
    relay_port      INTEGER     NOT NULL,
    bytes_sent      BIGINT      NOT NULL DEFAULT 0,
    bytes_received  BIGINT      NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ
);

CREATE INDEX relay_allocations_session_idx    ON relay_allocations (session_id);
CREATE INDEX relay_allocations_credential_idx ON relay_allocations (credential_id);
```

---

### `audit_events`

Append-only audit log. Never updated; rows are only inserted.

```sql
CREATE TABLE audit_events (
    id            BIGSERIAL   PRIMARY KEY,   -- monotonic for tamper-evidence ordering
    event_type    TEXT        NOT NULL,      -- see event type registry below
    actor_user_id UUID        REFERENCES users(id),
    actor_device_id UUID      REFERENCES devices(id),
    target_user_id  UUID      REFERENCES users(id),
    target_device_id UUID     REFERENCES devices(id),
    target_service_id UUID    REFERENCES services(id),
    session_id    UUID,                      -- connect_sessions.id if applicable
    outcome       TEXT        NOT NULL DEFAULT 'success'
                              CHECK (outcome IN ('success','failure','denied')),
    detail        JSONB,                     -- event-specific structured fields
    trace_id      TEXT,                      -- OpenTelemetry trace ID
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_events_actor_user_idx    ON audit_events (actor_user_id);
CREATE INDEX audit_events_actor_device_idx  ON audit_events (actor_device_id);
CREATE INDEX audit_events_event_type_idx    ON audit_events (event_type);
CREATE INDEX audit_events_created_idx       ON audit_events (created_at DESC);
```

**Event type registry**

| `event_type` | When emitted |
|---|---|
| `user.login` | User completes SSO and session is minted |
| `user.login_failed` | Token validation fails |
| `user.logout` | User or server invalidates session |
| `device.enrolled` | Device credential and WG key registered |
| `device.heartbeat_failed` | Device misses 3 consecutive heartbeats |
| `device.key_rotated` | WireGuard key rotation completed |
| `device.revoked` | Device status set to `revoked` |
| `device.quarantined` | Device status set to `quarantined` |
| `service.manifest_updated` | Device reports updated port list |
| `session.requested` | `POST /v1/sessions` called |
| `session.policy_denied` | Policy evaluation returned deny |
| `session.exchange_completed` | ICE candidate exchange finished |
| `session.path_selected` | `direct` or `relay` path chosen |
| `session.closed` | Session closed by either party |
| `relay.credential_issued` | TURN credential minted |
| `relay.allocation_started` | TURN allocation observed |
| `relay.allocation_ended` | TURN allocation released |
| `pair_code.issued` | 6-char pairing code generated |
| `pair_code.claimed` | Pairing code consumed by admin UI |
| `pair_code.expired` | Code TTL expired unclaimed |
| `device_code.issued` | SSO device code generated |
| `device_code.authenticated` | SSO callback linked code to user |
| `device_code.expired` | Device code TTL expired |

---

### `pair_codes`

Ephemeral 6-character enrollment codes. Primary store is Redis (10-min TTL);
this table is the audit shadow — inserted on creation, updated on claim.

```sql
CREATE TABLE pair_codes (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    code        CHAR(6)     NOT NULL UNIQUE,
    device_id   UUID        REFERENCES devices(id),   -- set after claim
    wg_public_key TEXT      NOT NULL,                 -- submitted with pair/start
    status      TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','claimed','expired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes',
    claimed_at  TIMESTAMPTZ
);

CREATE INDEX pair_codes_status_idx   ON pair_codes (status);
CREATE INDEX pair_codes_expires_idx  ON pair_codes (expires_at) WHERE status = 'pending';
```

---

### `device_codes`

Ephemeral SSO device codes for browser-based enrollment. Primary store is
Redis; this table is the audit shadow.

```sql
CREATE TABLE device_codes (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    code          TEXT        NOT NULL UNIQUE,   -- 32 random bytes, base64url
    user_id       UUID        REFERENCES users(id),   -- set after SSO callback
    wg_public_key TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','authenticated','expired')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '15 minutes',
    authenticated_at TIMESTAMPTZ
);

CREATE INDEX device_codes_status_idx  ON device_codes (status);
CREATE INDEX device_codes_expires_idx ON device_codes (expires_at) WHERE status = 'pending';
```

---

## Overlay IP pool

The control server manages overlay IP allocation from `WG_OVERLAY_CIDR`.
IPs are tracked in the `devices` table (`overlay_ip` column). Revoked device
IPs are freed after a 24-hour grace period (when `overlay_ip_released_at` is
set, a background worker returns the IP to the available pool after 24h). IPs
are never immediately reused to avoid stale WireGuard peer table entries.

---

## Migration notes

- Migrations live in `/migrations/` and are applied on server startup.
- Use a tool such as `golang-migrate` or `goose`; the exact tool is not
  prescribed but must support transactional DDL and versioned files.
- Never drop columns in a migration — mark them deprecated and remove in a
  later migration after all server instances have been upgraded (see
  [deployment.md](deployment.md) for version skew policy).
