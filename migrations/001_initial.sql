CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id     text NOT NULL UNIQUE,
    email           citext NOT NULL UNIQUE,
    display_name    text NOT NULL,
    status          text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),
    is_super        boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    last_login_at   timestamptz
);

CREATE INDEX idx_users_status
    ON users (status);

CREATE INDEX idx_users_last_login_at
    ON users (last_login_at DESC NULLS LAST);

CREATE TABLE devices (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id            uuid NOT NULL
                             REFERENCES users(id) ON DELETE RESTRICT,
    hostname                 text NOT NULL,
    status                   text NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'active', 'revoked', 'quarantined')),
    overlay_ip               inet UNIQUE,
    overlay_ip_allocated_at  timestamptz,
    overlay_ip_reclaim_after timestamptz,
    credential_hash          text NOT NULL,
    credential_issued_at     timestamptz NOT NULL DEFAULT now(),
    credential_rotated_at    timestamptz NOT NULL DEFAULT now(),
    agent_version            text NOT NULL,
    os_platform              text NOT NULL
                             CHECK (os_platform IN ('darwin', 'linux', 'windows', 'ios', 'android')),
    os_version               text NOT NULL,
    os_arch                  text NOT NULL,
    kernel_version           text NOT NULL,
    cpu_model                text NOT NULL,
    cpu_cores                integer NOT NULL CHECK (cpu_cores > 0),
    cpu_speed_mhz            integer CHECK (cpu_speed_mhz >= 0),
    total_memory_bytes       bigint NOT NULL CHECK (total_memory_bytes >= 0),
    disk_total_bytes         bigint NOT NULL CHECK (disk_total_bytes >= 0),
    disk_free_bytes          bigint NOT NULL CHECK (disk_free_bytes >= 0),
    network_interfaces       jsonb NOT NULL DEFAULT '[]'::jsonb
                             CHECK (jsonb_typeof(network_interfaces) = 'array'),
    tags                     text[] NOT NULL DEFAULT '{}'::text[],
    capabilities             text[] NOT NULL DEFAULT '{}'::text[],
    external_endpoint_host   text,
    external_endpoint_port   integer
                             CHECK (
                                 external_endpoint_port IS NULL OR
                                 external_endpoint_port BETWEEN 1 AND 65535
                             ),
    last_seen_at             timestamptz,
    revoked_at               timestamptz,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT devices_owner_hostname_key UNIQUE (owner_user_id, hostname),
    CONSTRAINT devices_overlay_reclaim_check
        CHECK (
            overlay_ip_reclaim_after IS NULL OR
            revoked_at IS NOT NULL
        )
);

CREATE INDEX idx_devices_owner_status
    ON devices (owner_user_id, status);

CREATE INDEX idx_devices_last_seen_at
    ON devices (last_seen_at DESC NULLS LAST);

CREATE INDEX idx_devices_reclaim_after
    ON devices (overlay_ip_reclaim_after)
    WHERE overlay_ip_reclaim_after IS NOT NULL;

CREATE INDEX idx_devices_tags_gin
    ON devices USING gin (tags);

CREATE INDEX idx_devices_capabilities_gin
    ON devices USING gin (capabilities);

CREATE TABLE device_keys (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           uuid NOT NULL
                         REFERENCES devices(id) ON DELETE CASCADE,
    key_version         integer NOT NULL CHECK (key_version > 0),
    wg_public_key       text NOT NULL,
    state               text NOT NULL DEFAULT 'active'
                         CHECK (state IN ('active', 'retired', 'revoked')),
    rotated_from_key_id uuid
                         REFERENCES device_keys(id) ON DELETE SET NULL,
    activated_at        timestamptz NOT NULL DEFAULT now(),
    retired_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_keys_version_unique UNIQUE (device_id, key_version),
    CONSTRAINT device_keys_public_key_format
        CHECK (wg_public_key ~ '^[A-Za-z0-9+/]{43}=$')
);

CREATE UNIQUE INDEX uq_device_keys_public_key
    ON device_keys (wg_public_key);

CREATE UNIQUE INDEX uq_device_keys_active_per_device
    ON device_keys (device_id)
    WHERE state = 'active';

CREATE INDEX idx_device_keys_device_created_at
    ON device_keys (device_id, created_at DESC);

CREATE TABLE services (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id        uuid NOT NULL
                      REFERENCES devices(id) ON DELETE CASCADE,
    name             text NOT NULL,
    protocol         text NOT NULL
                      CHECK (protocol IN ('tcp', 'udp', 'http', 'https', 'ws', 'wss', 'browser-control')),
    local_bind       text NOT NULL,
    exposure_type    text NOT NULL
                      CHECK (exposure_type IN ('tcp', 'udp', 'http', 'ws', 'browser-control')),
    auth_mode        text NOT NULL DEFAULT 'inherit'
                      CHECK (auth_mode IN ('inherit', 'none', 'device', 'user')),
    health_status    text NOT NULL DEFAULT 'unknown'
                      CHECK (health_status IN ('healthy', 'degraded', 'unhealthy', 'unknown')),
    tags             text[] NOT NULL DEFAULT '{}'::text[],
    metadata         jsonb NOT NULL DEFAULT '{}'::jsonb
                      CHECK (jsonb_typeof(metadata) = 'object'),
    last_reported_at timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT services_device_name_bind_key UNIQUE (device_id, name, local_bind)
);

CREATE INDEX idx_services_device_health
    ON services (device_id, health_status);

CREATE INDEX idx_services_last_reported_at
    ON services (last_reported_at DESC);

CREATE INDEX idx_services_tags_gin
    ON services USING gin (tags);

CREATE INDEX idx_services_metadata_gin
    ON services USING gin (metadata);

CREATE TABLE connect_sessions (
    id                           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_user_id            uuid NOT NULL
                                  REFERENCES users(id) ON DELETE RESTRICT,
    requester_device_id          uuid
                                  REFERENCES devices(id) ON DELETE SET NULL,
    target_device_id             uuid NOT NULL
                                  REFERENCES devices(id) ON DELETE RESTRICT,
    target_service_id            uuid NOT NULL
                                  REFERENCES services(id) ON DELETE RESTRICT,
    requested_action             text NOT NULL,
    status                       text NOT NULL DEFAULT 'pending'
                                  CHECK (
                                      status IN (
                                          'pending',
                                          'authorizing',
                                          'candidate_exchange',
                                          'established',
                                          'closing',
                                          'closed',
                                          'denied',
                                          'expired',
                                          'failed'
                                      )
                                  ),
    requester_candidate_set      jsonb NOT NULL DEFAULT '[]'::jsonb
                                  CHECK (jsonb_typeof(requester_candidate_set) = 'array'),
    target_candidate_set         jsonb NOT NULL DEFAULT '[]'::jsonb
                                  CHECK (jsonb_typeof(target_candidate_set) = 'array'),
    selected_path                text
                                  CHECK (selected_path IN ('direct', 'relay')),
    selected_relay_allocation_id uuid,
    denial_reason                text,
    expires_at                   timestamptz NOT NULL,
    established_at               timestamptz,
    closed_at                    timestamptz,
    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_at                   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_connect_sessions_requester_status
    ON connect_sessions (requester_user_id, status, created_at DESC);

CREATE INDEX idx_connect_sessions_target_status
    ON connect_sessions (target_device_id, status, created_at DESC);

CREATE INDEX idx_connect_sessions_service_created_at
    ON connect_sessions (target_service_id, created_at DESC);

CREATE INDEX idx_connect_sessions_expires_at
    ON connect_sessions (expires_at);

CREATE INDEX idx_connect_sessions_requester_candidates_gin
    ON connect_sessions USING gin (requester_candidate_set);

CREATE INDEX idx_connect_sessions_target_candidates_gin
    ON connect_sessions USING gin (target_candidate_set);

CREATE TABLE relay_credentials (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connect_session_id uuid NOT NULL
                        REFERENCES connect_sessions(id) ON DELETE CASCADE,
    turn_username      text NOT NULL UNIQUE,
    password_hash      text NOT NULL,
    transport          text NOT NULL DEFAULT 'udp'
                        CHECK (transport IN ('udp', 'tcp', 'tls')),
    ttl_seconds        integer NOT NULL
                        CHECK (ttl_seconds > 0 AND ttl_seconds <= 3600),
    issued_at          timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    revoked_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT relay_credentials_expiry_check
        CHECK (expires_at > issued_at)
);

CREATE INDEX idx_relay_credentials_session
    ON relay_credentials (connect_session_id);

CREATE INDEX idx_relay_credentials_expires_at
    ON relay_credentials (expires_at);

CREATE TABLE relay_allocations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connect_session_id  uuid NOT NULL
                         REFERENCES connect_sessions(id) ON DELETE CASCADE,
    relay_credential_id uuid
                         REFERENCES relay_credentials(id) ON DELETE SET NULL,
    allocation_key      text NOT NULL UNIQUE,
    transport           text NOT NULL
                         CHECK (transport IN ('udp', 'tcp', 'tls')),
    state               text NOT NULL DEFAULT 'active'
                         CHECK (state IN ('active', 'closed', 'expired', 'failed')),
    client_addr         inet,
    client_port         integer
                         CHECK (client_port IS NULL OR client_port BETWEEN 1 AND 65535),
    relay_addr          inet,
    relay_port          integer
                         CHECK (relay_port IS NULL OR relay_port BETWEEN 1 AND 65535),
    peer_addr           inet,
    peer_port           integer
                         CHECK (peer_port IS NULL OR peer_port BETWEEN 1 AND 65535),
    bytes_up            bigint NOT NULL DEFAULT 0 CHECK (bytes_up >= 0),
    bytes_down          bigint NOT NULL DEFAULT 0 CHECK (bytes_down >= 0),
    started_at          timestamptz NOT NULL DEFAULT now(),
    ended_at            timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT relay_allocations_end_after_start
        CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX idx_relay_allocations_session_state
    ON relay_allocations (connect_session_id, state);

CREATE INDEX idx_relay_allocations_started_at
    ON relay_allocations (started_at DESC);

CREATE INDEX idx_relay_allocations_credential
    ON relay_allocations (relay_credential_id);

ALTER TABLE connect_sessions
    ADD CONSTRAINT connect_sessions_selected_relay_allocation_fkey
    FOREIGN KEY (selected_relay_allocation_id)
    REFERENCES relay_allocations(id)
    ON DELETE SET NULL;

CREATE TABLE audit_events (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_uuid      uuid NOT NULL DEFAULT gen_random_uuid(),
    actor_user_id   uuid
                     REFERENCES users(id) ON DELETE SET NULL,
    actor_device_id uuid
                     REFERENCES devices(id) ON DELETE SET NULL,
    action          text NOT NULL,
    outcome         text NOT NULL
                     CHECK (outcome IN ('success', 'failure', 'allow', 'deny', 'info')),
    target_table    text NOT NULL,
    target_id       uuid,
    remote_ip       inet,
    user_agent      text,
    trace_id        text,
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb
                     CHECK (jsonb_typeof(metadata) = 'object'),
    prev_hash       bytea,
    event_hash      bytea NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_events_event_uuid_key UNIQUE (event_uuid)
);

CREATE INDEX idx_audit_events_occurred_at
    ON audit_events (occurred_at DESC);

CREATE INDEX idx_audit_events_actor_user
    ON audit_events (actor_user_id, occurred_at DESC);

CREATE INDEX idx_audit_events_actor_device
    ON audit_events (actor_device_id, occurred_at DESC);

CREATE INDEX idx_audit_events_action
    ON audit_events (action, occurred_at DESC);

CREATE INDEX idx_audit_events_target
    ON audit_events (target_table, target_id, occurred_at DESC);

CREATE INDEX idx_audit_events_metadata_gin
    ON audit_events USING gin (metadata);

CREATE TABLE pair_codes (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash               bytea NOT NULL UNIQUE
                             CHECK (octet_length(code_hash) = 32),
    requested_hostname      text NOT NULL,
    requested_wg_public_key text NOT NULL
                             CHECK (requested_wg_public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    requested_agent_version text NOT NULL,
    requested_os_platform   text NOT NULL,
    requested_os_arch       text NOT NULL,
    status                  text NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'claimed', 'expired', 'locked')),
    fail_count              integer NOT NULL DEFAULT 0
                             CHECK (fail_count BETWEEN 0 AND 5),
    locked_until            timestamptz,
    claimant_user_id        uuid
                             REFERENCES users(id) ON DELETE SET NULL,
    claimed_device_id       uuid
                             REFERENCES devices(id) ON DELETE SET NULL,
    last_claim_attempt_at   timestamptz,
    expires_at              timestamptz NOT NULL,
    claimed_at              timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pair_codes_expiry_check
        CHECK (expires_at > created_at),
    CONSTRAINT pair_codes_lock_check
        CHECK (locked_until IS NULL OR locked_until >= created_at)
);

CREATE INDEX idx_pair_codes_expires_at
    ON pair_codes (expires_at);

CREATE INDEX idx_pair_codes_locked_until
    ON pair_codes (locked_until)
    WHERE locked_until IS NOT NULL;

CREATE INDEX idx_pair_codes_status_expires_at
    ON pair_codes (status, expires_at);

CREATE TABLE device_codes (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash        bytea NOT NULL UNIQUE
                             CHECK (octet_length(device_code_hash) = 32),
    requested_hostname      text NOT NULL,
    requested_wg_public_key text NOT NULL
                             CHECK (requested_wg_public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    requested_agent_version text NOT NULL,
    requested_os_platform   text NOT NULL,
    requested_os_arch       text NOT NULL,
    status                  text NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'authorized', 'consumed', 'expired')),
    poll_interval_seconds   integer NOT NULL DEFAULT 5
                             CHECK (poll_interval_seconds BETWEEN 1 AND 60),
    authorized_user_id      uuid
                             REFERENCES users(id) ON DELETE SET NULL,
    authorized_device_id    uuid
                             REFERENCES devices(id) ON DELETE SET NULL,
    last_poll_at            timestamptz,
    expires_at              timestamptz NOT NULL,
    authorized_at           timestamptz,
    consumed_at             timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_codes_expiry_check
        CHECK (expires_at > created_at)
);

CREATE INDEX idx_device_codes_expires_at
    ON device_codes (expires_at);

CREATE INDEX idx_device_codes_status_expires_at
    ON device_codes (status, expires_at);

CREATE INDEX idx_device_codes_authorized_user
    ON device_codes (authorized_user_id, created_at DESC);
