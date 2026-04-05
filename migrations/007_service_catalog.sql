CREATE TABLE device_services (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       uuid NOT NULL
                     REFERENCES devices(id) ON DELETE CASCADE,
    name            text NOT NULL,
    protocol        text NOT NULL
                     CHECK (protocol IN ('tcp', 'udp', 'http', 'https', 'ws', 'wss', 'browser-control')),
    local_bind      text NOT NULL,
    exposure_type   text NOT NULL
                     CHECK (exposure_type IN ('tcp', 'udp', 'http', 'ws', 'browser-control')),
    auth_mode       text NOT NULL DEFAULT 'inherit'
                     CHECK (auth_mode IN ('inherit', 'none', 'device', 'user')),
    health_status   text NOT NULL DEFAULT 'unknown'
                     CHECK (health_status IN ('healthy', 'degraded', 'unhealthy', 'unknown')),
    tags            text[] NOT NULL DEFAULT '{}'::text[],
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_services_device_name_bind_key UNIQUE (device_id, name, local_bind)
);

CREATE INDEX idx_device_services_device_health
    ON device_services (device_id, health_status);

CREATE INDEX idx_device_services_tags_gin
    ON device_services USING gin (tags);
