# Deployment

Selkie has two deployment shapes in this repository:

- local development: [docker-compose.yml](/System/Volumes/Data/.internal/projects/Projects/selkie/docker-compose.yml)
- prototype production edge VM: [ops/docker-compose.edge.yml](/System/Volumes/Data/.internal/projects/Projects/selkie/ops/docker-compose.edge.yml)

The approved prototype topology is intentionally cheap:

- `selkie.live` stays on Cloud Run
- `admin.selkie.live`, `api.selkie.live`, and `relay.selkie.live` terminate on one always-on Belgium VM
- PostgreSQL stays on the shared UnlikeOtherAI instance
- Redis, coturn, Caddy, and the Selkie server run on that VM

## Prototype topology

```text
Internet
  |
  +--> selkie.live ----------------------------> Cloud Run website
  |
  +--> admin.selkie.live ----------------------> Caddy :443 on Belgium VM
  |
  +--> api.selkie.live ------------------------> Caddy :443 on Belgium VM
  |
  +--> relay.selkie.live:51820/udp -----------> server-owned wg0 on Belgium VM
  |
  +--> relay.selkie.live:3478/udp,tcp --------> coturn on Belgium VM
  |
  +--> relay.selkie.live:5349/tcp ------------> coturn TLS on Belgium VM

Belgium VM
  |
  +--> Caddy
  +--> selkie-server
  +--> Redis
  +--> coturn
  +--> WireGuard wg0

selkie-server --> shared PostgreSQL
selkie-server --> local Redis
coturn --> local Redis statsdb
```

## Why the VM exists

The website can scale to zero. The VPN path cannot.

The VM is required because the Selkie server must:

- own `wg0`
- accept WireGuard on `51820/udp`
- route traffic between device `/32` peers
- rewrite peer endpoints from device heartbeats
- keep coturn reachable on its public UDP and TCP ports

Cloud Run is not a valid target for those responsibilities.

## Edge VM compose

Use [ops/docker-compose.edge.yml](/System/Volumes/Data/.internal/projects/Projects/selkie/ops/docker-compose.edge.yml) on the Belgium VM.

Runtime shape:

- `caddy` uses host networking and terminates TLS for `admin.` and `api.`
- `server` uses host networking and `CAP_NET_ADMIN` so it can create and manage `wg0`
- `coturn` uses host networking for direct UDP and TCP exposure
- `redis` listens on the VM and is intended to be reusable by other internal projects later

Important constraints:

- PostgreSQL is external in this prototype. Do not start a second local Postgres on the VM.
- Redis `6379` must never be exposed publicly. Limit it to internal VPC access only.
- IP forwarding must be enabled on the host.
- the VM is always on; this part cannot scale to zero.

## Required host configuration

The VM must be a Linux host in `europe-west1` with:

- machine type `e2-small`
- static public IP
- WireGuard kernel support
- Docker Engine and Compose plugin
- IPv4 forwarding enabled

Required host sysctls:

```sh
net.ipv4.ip_forward=1
net.ipv4.conf.all.src_valid_mark=1
```

## DNS shape

Required public records:

- `selkie.live` -> Cloud Run website
- `admin.selkie.live` -> Belgium VM static IP
- `api.selkie.live` -> Belgium VM static IP
- `relay.selkie.live` -> Belgium VM static IP

Recommended runtime values:

```dotenv
ADMIN_HOST=admin.selkie.live
API_HOST=api.selkie.live
RELAY_HOST=relay.selkie.live
TURN_HOST=relay.selkie.live
WG_SERVER_ENDPOINT=relay.selkie.live
WG_SERVER_PORT=51820
WG_INTERFACE_NAME=wg0
WG_OVERLAY_CIDR=10.100.0.0/16
```

The server overlay address is derived from `WG_OVERLAY_CIDR`. For `10.100.0.0/16`, the server owns `10.100.0.1/16` and each device gets its own `/32`.

## Firewall policy

Internet-facing ports on the VM:

- `80/tcp`
- `443/tcp`
- `3478/udp`
- `3478/tcp`
- `5349/tcp`
- `51820/udp`

Internal-only ports:

- `6379/tcp` for Redis
- `5766/tcp` for coturn CLI

## Secrets

Required secrets:

- `UOA_SHARED_SECRET`
- `INTERNAL_SESSION_SECRET`
- `COTURN_SECRET`
- `COTURN_CLI_PASSWORD`
- `WG_PRIVATE_KEY`
- `REDIS_PASSWORD`
- shared PostgreSQL credentials inside `DATABASE_URL`

Derived but non-secret runtime values:

- `WG_SERVER_PUBLIC_KEY`
- `WG_SERVER_ENDPOINT`
- `TURN_HOST`

Rules:

- `INTERNAL_SESSION_SECRET` must be distinct from `UOA_SHARED_SECRET`
- `WG_PRIVATE_KEY` never leaves the VM runtime secret store
- `WG_SERVER_PUBLIC_KEY` should be derived from `WG_PRIVATE_KEY`, not managed separately by hand
- secrets must never be committed or logged

## Caddy requirements

Caddy is the only TLS edge for `admin.` and `api.` on the VM.

Use [ops/Caddyfile](/System/Volumes/Data/.internal/projects/Projects/selkie/ops/Caddyfile). It must:

- reverse proxy to the local server HTTP port
- preserve long-lived SSE streams
- disable response buffering for `GET /api/v1/devices/{id}/events`

In this repo that is done with `flush_interval -1` on the SSE path.

## Runtime readiness

Readiness rules for the prototype VM:

1. PostgreSQL must be reachable.
2. Redis must be reachable when `REDIS_URL` is configured.
3. the server must initialize `wg0` successfully when `WG_PRIVATE_KEY` is configured.
4. Caddy should only start after the server health check passes.

## WireGuard hub rules

The server owns the WireGuard hub in the MVP.

Operational rules:

- the server creates `wg0` on startup when `WG_PRIVATE_KEY` is present
- the server assigns the first usable overlay address in `WG_OVERLAY_CIDR` to `wg0`
- every device gets `AllowedIPs = <server_overlay_ip>/32`
- every server-side peer gets `AllowedIPs = <device_overlay_ip>/32`
- `PersistentKeepalive = 25` is set on both sides
- peer endpoint changes come from device heartbeats and are reconciled onto the host interface

## Cloud Run after cutover

After `admin.` and `api.` are live on the VM:

- keep the existing Cloud Run `selkie-server` service out of DNS
- do not delete it during prototype rollout
- leave `selkie.live` on Cloud Run

This keeps rollback simple and avoids destructive GCP actions.
