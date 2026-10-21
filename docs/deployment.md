# Deployment

Selkie has two deployment shapes in this repository:

- local development: [docker-compose.yml](/System/Volumes/Data/.internal/projects/Projects/selkie/docker-compose.yml)
- **production: the shared Hetzner host** via
  [ops/docker-compose.prod.yml](/System/Volumes/Data/.internal/projects/Projects/selkie/ops/docker-compose.prod.yml)

> **History.** The earlier prototype targeted a dedicated Belgium GCP VM with a
> Cloud SQL Auth Proxy and Selkie's own Caddy
> ([ops/docker-compose.edge.yml](/System/Volumes/Data/.internal/projects/Projects/selkie/ops/docker-compose.edge.yml)).
> That topology is **superseded**. The edge compose file is kept for reference
> only; new work should target the production shape below.

## Production topology (current)

Production runs on a **shared Hetzner host** (`178.105.82.46`, Nuremberg) that
also hosts several other UnlikeOtherAI projects (voicepos, hugo, …). Selkie
**reuses** the shared edge proxy and database already on that box and brings
only what is specific to it (Redis, coturn, the WireGuard hub).

```text
Internet
  |
  +--> selkie.live ----------------------------> Cloud Run website (unchanged)
  |
  +--> admin.selkie.live --443--> shared Caddy --(edge net)--> selkie-server:8080
  +--> api.selkie.live   --443--> shared Caddy --(edge net)--> selkie-server:8080
  |
  +--> relay.selkie.live:51820/udp ------------> selkie-server wg0 (published)
  +--> relay.selkie.live:3478/udp,tcp ---------> selkie-coturn (host net)

Hetzner host /srv
  /srv/infra   shared Caddy (container `caddy`, net `edge`)
               shared Postgres 17 (container `postgres`, net `db`)
  /srv/selkie  ops/docker-compose.prod.yml ->
                 selkie-server  (bridge: edge + db + selkie-internal)
                 selkie-redis   (selkie-internal, 127.0.0.1:6379)
                 selkie-coturn  (host net)

selkie-server --(db net)----------> shared Postgres `postgres:5432` (db `selkie`)
selkie-server --(selkie-internal)-> selkie-redis:6379
selkie-server  owns wg0 inside its own netns (NET_ADMIN + /dev/net/tun)
```

### What is reused vs. owned

| Component  | Source                                            |
| ---------- | ------------------------------------------------- |
| TLS edge   | **reused** shared Caddy (`/srv/infra`, net `edge`)|
| PostgreSQL | **reused** shared Postgres 17 (`/srv/infra`, `db`)|
| Redis      | **owned** by Selkie (`selkie-redis`, private net) |
| coturn     | **owned** by Selkie (host net)                    |
| WireGuard  | **owned** by Selkie (server process, `wg0`)       |

Do **not** start a second Caddy or Postgres on the host, and do **not** edit
other projects' compose files or Caddy blocks.

## First-time provisioning

All commands run as `root` on the host.

1. **Source.** Sync the repo to `/srv/selkie` (rsync from a clean checkout, or
   `git clone`). The build context is `/srv/selkie` (Dockerfile at its root);
   the compose file lives at `ops/docker-compose.prod.yml`.

2. **Database.** Create a dedicated role + database on the shared instance
   (the shared superuser password is in `/srv/infra/.env`):

   ```sh
   docker exec -e PGPASSWORD="<super>" postgres \
     psql -U postgres -c "CREATE ROLE selkie LOGIN PASSWORD '<dbpw>'"
   docker exec -e PGPASSWORD="<super>" postgres \
     psql -U postgres -c "CREATE DATABASE selkie OWNER selkie"
   ```

   Migrations run automatically on server boot — there is no separate migrate
   step.

3. **Secrets / `.env`.** Write `/srv/selkie/.env` (mode 600, never committed).
   Generate fresh secrets on the host; the WireGuard keypair is generated with
   `wg genkey | tee >(wg pubkey)`. See [Runtime configuration](#runtime-configuration).

4. **Firewall (ufw).** The relay needs UDP/TCP beyond the shared 80/443:

   ```sh
   ufw allow 3478/tcp && ufw allow 3478/udp     # coturn STUN/TURN
   ufw allow 51820/udp                           # WireGuard
   ufw allow 49152:49200/udp                     # coturn relay range
   ```

5. **Caddy.** Append the Selkie site blocks
   ([ops/caddy/selkie.caddy](/System/Volumes/Data/.internal/projects/Projects/selkie/ops/caddy/selkie.caddy))
   to the shared `/srv/infra/caddy/Caddyfile`, then:

   ```sh
   docker exec caddy caddy validate --config /etc/caddy/Caddyfile
   docker exec caddy caddy reload   --config /etc/caddy/Caddyfile
   ```

6. **DNS.** Point `admin.`, `api.`, and `relay.selkie.live` (A records,
   DNS-only — not proxied) at `178.105.82.46`. `selkie.live` apex stays on
   Cloud Run. Caddy obtains Let's Encrypt certs for `admin.`/`api.` on the
   first request **after** DNS resolves to the host. If a cert attempt fired
   before propagation, `docker restart caddy` forces a fresh attempt.

7. **Bring up:**

   ```sh
   cd /srv/selkie
   ./ops/compose-prod.sh up -d --build
   ```

   The `--env-file .env` flag is **required**: compose otherwise interpolates
   top-level `${VARS}` from the compose file's directory (`ops/`) and silently
   blanks `REDIS_PASSWORD`, `COTURN_SECRET`, etc.

## Continuous deployment

Every push to `main` auto-deploys to the Hetzner host via
`.github/workflows/deploy.yml` (`deploy`), with its own non-cancelling
concurrency group so a rapid second push cannot abort an in-flight deploy. It
can also be run manually from the Actions tab (`workflow_dispatch`).

Deploy is **not** gated on the `ci` workflow: `ci` also covers the iOS app
(swiftlint) and other concerns orthogonal to the server, so gating would block
server deploys on unrelated failures. The safety net is the build itself —
`docker compose up -d --build` only swaps containers after a successful image
build, so a commit that fails to compile leaves the running server untouched.

The deploy job: rsyncs the repo to `/srv/selkie` (preserving `.env`), runs
`docker compose ... up -d --build`, then polls
`https://api.selkie.live/readyz` and fails the run if it never goes green.

Required GitHub repo secrets:

- `SELKIE_DEPLOY_SSH_KEY` — private key whose public half is in the host's
  `root` `authorized_keys` (comment `selkie-github-deploy`).
- `SELKIE_SSH_KNOWN_HOSTS` — `ssh-keyscan 178.105.82.46` output, for strict
  host-key checking.

Rotate the deploy key by regenerating the pair, replacing the `authorized_keys`
entry on the host, and updating `SELKIE_DEPLOY_SSH_KEY`.

The wrapper discovers the Compose project from the existing Selkie containers.
The current installation uses `ops`, including the persistent `ops_redis_data`
volume. Fresh installations use `selkie`. Conflicting ownership labels stop the
deploy before any containers are changed.

For the coordinated Coder broker contract and identity cutover, follow
[coordinated broker activation](coordinated-broker-activation.md), including the
verified recovery point and migration rollback limits, before merging the release.

## Day-2 operations

Canonical compose invocation (the wrapper supplies the existing project name and env-file):

```sh
cd /srv/selkie
./ops/compose-prod.sh <cmd>
```

- redeploy after a source change: `... up -d --build`
- logs: `docker logs selkie-server`
- health: `docker exec selkie-server wget -qO- http://127.0.0.1:8080/healthz`
- WireGuard state: `docker exec selkie-server wg show wg0`

## Runtime configuration

The server runs **as root in-container** with `cap_add: NET_ADMIN`. This is
required: `ip link add wg0 type wireguard` needs real `CAP_NET_ADMIN`, and the
image's uid-10001 + file-capabilities model is rejected with `EPERM` by the
host's 6.8 kernel for the WireGuard rtnetlink operation.

Key values that differ from the old prototype:

```dotenv
# Reach the shared Postgres over the `db` docker network by container name.
DATABASE_URL=postgres://selkie:<dbpw>@postgres:5432/selkie?sslmode=disable
# Selkie-owned Redis on the private network.
REDIS_URL=redis://:<redispw>@selkie-redis:6379/0
# coturn (host net) reaches Redis on loopback; server uses the service name.
COTURN_REDIS_STATSDB=redis://:<redispw>@127.0.0.1:6379/1
# coturn advertises the host's public IPv4 only (no docker bridge candidates).
TURN_EXTERNAL_IP=178.105.82.46
TURN_HOST=relay.selkie.live
WG_SERVER_ENDPOINT=relay.selkie.live
WG_SERVER_PORT=51820
WG_OVERLAY_CIDR=10.100.0.0/16
# The shared Caddy lives on the `edge` docker net (172.18/16); trust its XFF.
TRUSTED_PROXY_CIDRS=172.18.0.0/16,127.0.0.1/32
```

## SSO status

SSO is delegated to `authentication.unlikeotherai.com`. Production browser login
was verified on 2026-10-03: the UOA callback returned to
`https://admin.selkie.live/auth/callback`, the admin overview loaded, and the
server recorded successful login events. The earlier pending-integration note
is no longer current. The client secret and RSA config signing key are set.

For a new installation, approve its domain in UOA and configure the issued
client secret as described in [sso.md](sso.md). After changing `.env`, recreate
the server with `./ops/compose-prod.sh up -d server`; a plain container restart
does not reload environment variables.

See [first-use-readiness.md](first-use-readiness.md) for the remaining identity
and device acceptance requirements.

## DNS shape

Required public records:

- `selkie.live` -> Cloud Run website
- `admin.selkie.live` -> `178.105.82.46` (A, DNS-only)
- `api.selkie.live` -> `178.105.82.46` (A, DNS-only)
- `relay.selkie.live` -> `178.105.82.46` (A, DNS-only)

## Firewall policy

Internet-facing ports on the host:

- `80/tcp`, `443/tcp` (+ `443/udp` HTTP/3) — shared edge
- `3478/udp`, `3478/tcp` — coturn STUN/TURN
- `49152-49200/udp` — coturn relay range
- `51820/udp` — WireGuard

Internal-only:

- `127.0.0.1:5432` — shared Postgres (never public)
- `127.0.0.1:6379` — Selkie Redis (never public)
- `127.0.0.1:5766` — coturn CLI

## WireGuard hub rules

The server owns the WireGuard hub in the MVP.

- the server creates `wg0` on startup when `WG_PRIVATE_KEY` is present
- it assigns the first usable overlay address in `WG_OVERLAY_CIDR` to `wg0`
- every device gets `AllowedIPs = <server_overlay_ip>/32`; each server-side
  peer gets `AllowedIPs = <device_overlay_ip>/32`
- `PersistentKeepalive = 25` on both sides
- peer endpoint changes come from device heartbeats and are reconciled onto
  the host interface (this also covers the docker-NAT seen by `51820/udp`
  published from the bridge container)

## Cloud Run after cutover

- `selkie.live` (apex website) stays on Cloud Run
- the old prototype VM / Cloud Run `selkie-server` service, if any, is left out
  of DNS but not deleted, to keep rollback simple and avoid destructive GCP
  actions
