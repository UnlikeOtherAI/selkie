# Deployment

This document covers self-hosting the Silkie control server: Docker Compose
setup, TLS termination, secret injection, scaling, and operational procedures.

---

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A domain name pointing to your server's public IP
- Ports 80, 443, and 3478 (TURN UDP) open in your firewall

---

## Quickstart — single node

```sh
cp .env.example .env
# Edit .env with real secrets before proceeding

docker compose up -d
```

The Compose file starts four services: `postgres`, `redis`, `coturn`, and
`server`. A fifth service, `caddy`, handles TLS termination.

---

## Docker Compose

```yaml
# docker-compose.yml
version: "3.9"

services:
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: silkie
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: silkie
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U silkie"]
      interval: 5s
      timeout: 3s
      retries: 10

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10

  coturn:
    image: coturn/coturn:4.6-alpine
    restart: unless-stopped
    network_mode: host     # required for TURN; see note below
    environment:
      TURN_STATIC_AUTH_SECRET: ${COTURN_SECRET}
    command: >
      turnserver
        --use-auth-secret
        --static-auth-secret=${COTURN_SECRET}
        --realm=${UOA_DOMAIN}
        --listening-port=3478
        --tls-listening-port=5349
        --no-tcp-relay
        --log-file=stdout

  server:
    image: ghcr.io/unlikeotherai/silkie-server:latest
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://silkie:${POSTGRES_PASSWORD}@postgres:5432/silkie?sslmode=disable
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      UOA_BASE_URL: ${UOA_BASE_URL}
      UOA_DOMAIN: ${UOA_DOMAIN}
      UOA_SHARED_SECRET: ${UOA_SHARED_SECRET}
      UOA_AUDIENCE: ${UOA_AUDIENCE}
      UOA_CONFIG_URL: ${UOA_CONFIG_URL}
      UOA_REDIRECT_URL: ${UOA_REDIRECT_URL}
      INTERNAL_SESSION_SECRET: ${INTERNAL_SESSION_SECRET}
      COTURN_SECRET: ${COTURN_SECRET}
      TURN_HOST: ${TURN_HOST}
      TURN_PORT: ${TURN_PORT}
      WG_OVERLAY_CIDR: ${WG_OVERLAY_CIDR}
      WG_INTERFACE_NAME: ${WG_INTERFACE_NAME}
      SERVER_PORT: ${SERVER_PORT:-8080}
      LOG_LEVEL: ${LOG_LEVEL:-info}
    ports:
      - "127.0.0.1:8080:8080"   # exposed only to Caddy, not the internet
    volumes:
      - wg_keys:/var/lib/silkie/wg    # WireGuard server keys persist across restarts
    cap_add:
      - NET_ADMIN      # required for WireGuard interface management
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/healthz"]
      interval: 10s
      timeout: 3s
      retries: 5

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      server:
        condition: service_healthy

volumes:
  postgres_data:
  redis_data:
  wg_keys:
  caddy_data:
  caddy_config:
```

**coturn network_mode: host** — TURN requires the server to see the client's
real source IP for NAT traversal. Docker's network bridge rewrites source IPs,
breaking TURN. Running coturn in host network mode is the standard workaround
for single-node deployments.

---

## Caddyfile

```caddyfile
your.domain.com {
    reverse_proxy server:8080
}
```

Caddy obtains a Let's Encrypt TLS certificate automatically on first request.
For internal/private domains, replace with `tls internal` (requires a Caddy-
compatible local CA setup).

---

## Secret injection

All secrets come from environment variables, sourced from `.env`. Never
hard-code secrets in `docker-compose.yml` or commit `.env`.

Required secrets and recommended generation:

| Variable | Generate with |
|---|---|
| `POSTGRES_PASSWORD` | `openssl rand -base64 32` |
| `REDIS_PASSWORD` | `openssl rand -base64 32` |
| `INTERNAL_SESSION_SECRET` | `openssl rand -base64 64` |
| `COTURN_SECRET` | `openssl rand -base64 32` |
| `UOA_SHARED_SECRET` | From UOA dashboard |

---

## Database migrations

Migrations run automatically on server startup before the HTTP listener opens.
The server will refuse to start if migrations fail.

To run migrations manually (e.g. to inspect the SQL before applying):

```sh
docker compose run --rm server migrate up
docker compose run --rm server migrate status
docker compose run --rm server migrate down 1   # roll back one step
```

---

## Graceful shutdown

The server listens for `SIGTERM` (sent by Docker on `docker compose stop`).
On receipt:

1. HTTP listener stops accepting new connections.
2. In-flight requests are given 30 seconds to complete.
3. Background workers (heartbeat monitor, CIDR reclaim) are signalled to stop.
4. Database and Redis connections are closed.
5. WireGuard interface is brought down.
6. Process exits 0.

Set `SIGTERM_TIMEOUT=60` in the environment to extend the drain window for
long-lived SSE connections.

---

## Horizontal scaling

The control server is stateless for all HTTP request processing. To run
multiple instances behind a load balancer:

### What must be in Redis (not in-process)

| State | Redis key pattern |
|---|---|
| Pair code TTL and status | `silkie:pair:{code}` |
| Device code TTL and status | `silkie:device_code:{code}` |
| Rate limit counters | `silkie:ratelimit:{endpoint}:{key}` |
| SSE fan-out channel | `silkie:device:{id}:events` (pub/sub) |
| Distributed lock for singleton workers | Implemented via Postgres advisory locks |

### SSE fan-out

Each server instance holds SSE connections for the clients connected to it.
When a session event occurs on any instance, it publishes to the Redis channel
for that device:

```
PUBLISH silkie:device:{device_id}:events <json_event>
```

Every instance subscribed to that channel (because a client is connected to
it) forwards the event to its SSE stream. This allows any number of server
instances to serve SSE without coordinating directly.

### Load balancer requirements

- Use any HTTP load balancer (Caddy upstream, nginx, HAProxy, cloud LB).
- For SSE clients (admin UI polling): use sticky sessions OR configure the
  load balancer with long connection timeouts (≥ 5 minutes). Caddy handles
  this automatically with `reverse_proxy`.
- All instances must share the same `INTERNAL_SESSION_SECRET` and
  `UOA_SHARED_SECRET`.

---

## Leader election — singleton workers

Some workers must run on exactly one instance at a time:

- **Overlay IP reclaim** — returns revoked device IPs to the pool after 24h grace.
- **Pair code / device code expiry sweep** — marks expired codes in Postgres.
- **Heartbeat monitor** — marks devices offline after missed heartbeats.

These workers use **PostgreSQL advisory locks** for leader election:

```go
// Try to acquire advisory lock (non-blocking)
acquired, err := db.Exec("SELECT pg_try_advisory_lock($1)", workerID)
if !acquired {
    return  // another instance holds the lock
}
defer db.Exec("SELECT pg_advisory_unlock($1)", workerID)

// Run worker logic...
```

Worker IDs are stable integers defined as constants in the codebase. The lock
is held for the duration of the worker run and released at the end (or
implicitly when the DB connection closes on shutdown).

---

## Blue/green deployment

1. Bring up the new version (`green`) pointing at the same database.
2. Run migrations on `green` before switching traffic. Migrations must be
   backwards-compatible: only add columns (with defaults or nullable), never
   drop or rename. See version skew policy below.
3. Switch the load balancer to route new connections to `green`.
4. Allow `blue` to drain (existing SSE connections, in-flight requests).
5. Stop `blue` once connections have drained (check `server_connections`
   metric, or wait a fixed drain window of 60s).

---

## Version skew policy

The CLI daemon and control server must be compatible across one minor version.

| Server version | Compatible CLI versions |
|---|---|
| 1.2.x | 1.1.x, 1.2.x |
| 1.3.x | 1.2.x, 1.3.x |

- The server must never remove or rename a REST field while a previous CLI
  minor version is still in use.
- Deprecated fields are ignored by new CLI versions and remain present in
  responses for one minor version.
- The server returns `X-Silkie-Min-CLI-Version` in heartbeat responses; the
  CLI logs a warning if its version is below the minimum.

---

## CLI auto-update

The CLI does not auto-update itself. Updates are distributed via npm:

```sh
npm install -g silkie@latest
```

For managed deployments, wrap this in a cron job or use a configuration
management tool (Ansible, Puppet, Chef). The server's `X-Silkie-Min-CLI-Version`
header can be used to detect when an update is required.

---

## Health and readiness

| Endpoint | Returns |
|---|---|
| `GET /healthz` | `{"status":"ok"}` if the server is alive |
| `GET /readyz` | `{"status":"ok"}` if postgres and redis are reachable |
| `GET /version` | `{"version":"1.2.3","min_cli_version":"1.1.0"}` |

Use `/readyz` for load balancer health checks and Kubernetes readiness probes.
Use `/healthz` for liveness probes.
