# Deployment

This document defines the production deployment model for the Silkie control
plane. The baseline runtime is Docker Compose with four core services:
PostgreSQL, Redis, coturn, and the Go server. Caddy sits in front as the TLS
terminator and reverse proxy.

## Topology

```text
Internet
  |
  v
Caddy :443/:80
  |
  +--> server :8080
  |
  +--> static admin UI (proxied from server)

server --> PostgreSQL :5432
server --> Redis :6379
server --> coturn TURN REST auth + health checks
clients --> coturn :3478/udp,tcp and :5349/tls (relay path)
```

## Docker Compose

The minimum local or single-node production layout is:

```yaml
services:
  postgres:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_DB: silkie
      POSTGRES_USER: silkie
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - redis_data:/data

  coturn:
    image: coturn/coturn:4.6
    restart: unless-stopped
    network_mode: host
    command:
      - -n
      - --use-auth-secret
      - --static-auth-secret=${COTURN_SECRET}
      - --realm=${UOA_DOMAIN}
      - --external-ip=${TURN_HOST}
      - --listening-port=${TURN_PORT}
      - --tls-listening-port=5349
    env_file:
      - .env

  server:
    image: ghcr.io/unlikeotherai/silkie-server:latest
    restart: unless-stopped
    depends_on:
      - postgres
      - redis
      - coturn
    env_file:
      - .env
    environment:
      DATABASE_URL: ${DATABASE_URL}
      REDIS_URL: ${REDIS_URL}
      SERVER_PORT: ${SERVER_PORT}
      LOG_LEVEL: ${LOG_LEVEL}
    command: ["/bin/sh", "-lc", "control-server migrate && exec control-server serve"]

  caddy:
    image: caddy:2
    restart: unless-stopped
    depends_on:
      - server
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./deploy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config

volumes:
  postgres_data:
  redis_data:
  caddy_data:
  caddy_config:
```

Notes:

- `coturn` needs host networking or equivalent direct UDP/TCP exposure.
- The server stays on a private container network; only Caddy and coturn are
  internet-facing.
- `control-server migrate && control-server serve` is required. If migration
  fails, the container must exit non-zero and never start the HTTP server.

## TLS termination with Caddy

Caddy is the only TLS endpoint. The Go server listens on plain HTTP on
`SERVER_PORT` behind it.

```caddyfile
silkie.example.com {
  encode zstd gzip

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
    Referrer-Policy "no-referrer"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
  }

  reverse_proxy server:${SERVER_PORT}
}
```

Operational rules:

- TLS certificates are managed by Caddy, not by the Go server.
- The server must trust `X-Forwarded-For` and `X-Forwarded-Proto` only from
  the Caddy container or private ingress network.
- SSE responses must disable proxy buffering and keep idle timeouts long
  enough for multi-hour event streams.

## Secret injection

Secrets are injected only through environment variables or container-runtime
secret mounts that are converted to env at process start. Nothing secret is
committed to the repo.

Required secrets:

| Variable | Purpose |
|---|---|
| `UOA_SHARED_SECRET` | UOA HS256 signing and verification secret |
| `INTERNAL_SESSION_SECRET` | HS256 key for Silkie-issued internal JWTs |
| `COTURN_SECRET` | TURN REST API HMAC secret shared with coturn |
| `POSTGRES_PASSWORD` | Postgres password when Compose provisions the DB |

Rules:

- `INTERNAL_SESSION_SECRET` must be distinct from `UOA_SHARED_SECRET`.
- `COTURN_SECRET` must be shared only between the server and coturn.
- Secrets must never be logged, echoed in health endpoints, or exposed through
  admin APIs.

## Migration on startup

Startup order is strict:

1. Wait for PostgreSQL readiness.
2. Run `control-server migrate`.
3. Acquire singleton worker locks.
4. Start HTTP listeners.
5. Begin background loops only after readiness probes succeed.

Constraints:

- Migrations are SQL-first and idempotent.
- Migration failure is fatal for that instance.
- Only one instance needs to apply a given migration, but every instance may
  attempt startup migration because PostgreSQL transaction locking serializes
  it safely.

## Graceful shutdown

On `SIGTERM` or container stop:

1. Mark the instance unready immediately so Caddy stops sending new requests.
2. Stop accepting new HTTP connections.
3. Keep existing SSE streams open for a short drain window so connected CLIs
   can reconnect cleanly.
4. Flush final audit events and trace exporters.
5. Release advisory locks and stop background workers.
6. Exit before the orchestrator hard-kills the process.

Recommended timings:

| Phase | Budget |
|---|---|
| Readiness off + stop new requests | immediate |
| SSE drain window | 15s |
| Worker shutdown + telemetry flush | 15s |
| Total termination grace period | 30s |

## Horizontal scaling

Silkie can run multiple stateless server instances, but only if all state that
matters outside one process is externalized.

Required shared components:

| Concern | Shared backend |
|---|---|
| durable state | PostgreSQL |
| rate limits, locks, live fan-out | Redis |
| TURN relay | coturn |
| TLS ingress | Caddy or external load balancer |

### SSE fan-out

The device event stream is `GET /v1/devices/{id}/events` and must work across
multiple server instances. That means in-memory broadcast is insufficient.

Required pattern:

- The instance that creates an event publishes it to Redis:
  `PUBLISH silkie:device:{id}:events <json-payload>`.
- Every server instance subscribes to the device channels for locally attached
  SSE clients.
- The SSE handler writes the Redis event payload directly to the open stream.

If this pub/sub layer is missing, only the instance that created the event can
reach its own SSE clients, which breaks scaled deployments.

## Leader election for singleton workers

Some loops must run exactly once cluster-wide:

- expired session reaper
- overlay IP reclaim worker
- audit hash chain maintenance
- version announcement / release sync

Use PostgreSQL advisory locks, not Redis locks, for these workers so lock
ownership follows the database transaction and survives Redis restarts cleanly.

Example:

```sql
SELECT pg_try_advisory_lock(8246351, 1);
```

Rules:

- Each singleton worker gets its own fixed lock tuple.
- If lock acquisition fails, the instance remains a normal API/SSE node and
  does not run that worker.
- Locks are released automatically on connection loss; workers must stop when
  their DB session drops.

## Blue/green deploy constraints

Blue/green is supported with constraints:

1. Database migrations must be backward-compatible first, destructive later.
   Add columns and tables before new code depends on them; drop old columns
   only after all old instances are gone.
2. Redis pub/sub payloads for SSE must remain compatible across the blue and
   green versions during overlap.
3. coturn credentials must validate against the same `COTURN_SECRET` on both
   stacks during cutover.
4. Advisory-lock worker IDs must not change between the blue and green
   versions, or both stacks may think they own the same singleton job.
5. Existing SSE clients will reconnect during cutover. The reconnect path must
   be safe and idempotent.

Do not run blue/green if the release contains a breaking schema migration that
the old binary cannot tolerate.

## CLI auto-update strategy

The CLI is installed from npm but updated under server policy control.

Policy:

- The server publishes the latest compatible CLI version and minimum required
  CLI version in its version metadata endpoint.
- The daemon checks on startup and once every 24 hours.
- Patch and minor updates are downloaded in the background, then applied by the
  platform service manager restart path.
- No forced hot-reload: the current daemon keeps running until the next
  restart or a user-triggered `silkie service restart`.

Operationally:

- macOS updater command: `npm install -g silkie@<version>`
- Linux updater command: `npm install -g silkie@<version>`
- Auto-update must be disabled if the package manager path is unknown or the
  install was not global.

## Version skew policy

Silkie is not wire-compatible across arbitrary versions. The server defines the
compatibility window.

| Component pair | Supported skew |
|---|---|
| server N ↔ CLI N | fully supported |
| server N ↔ CLI N-1 minor | supported |
| server N ↔ CLI older than N-1 minor | unsupported; CLI must upgrade |
| CLI newer than server by patch level | tolerated |
| CLI newer than server by minor level | rejected for enrollment; existing sessions may continue until restart |

Rules:

- Enroll and key rotation require an explicitly supported version pair.
- If the CLI is too old, the server returns a structured upgrade-required
  response instead of partially serving the request.
- If the server becomes unreachable during skew or upgrade mismatch, the CLI
  keeps its last-known WireGuard config and retries control-plane calls later.

## Health checks

Recommended probes:

| Path | Meaning |
|---|---|
| `GET /healthz` | process is alive |
| `GET /readyz` | database, Redis, and singleton worker prerequisites are ready |
| `GET /metrics` | Prometheus/OpenTelemetry scrape surface |

`/readyz` must fail if:

- PostgreSQL is unavailable
- Redis is unavailable
- startup migration has not finished
- the server has not yet subscribed to Redis pub/sub
