# Production VPN Rollout Review

## Purpose

This document is the reviewed execution packet for making Selkie's actual VPN path work in the approved low-cost prototype shape.

Reviewers accounted for in this packet:

- Codex
- Claude CLI
- Gemini CLI
- the user

## Documentation considered

Primary docs reviewed:

- `docs/brief.md`
- `docs/deployment.md`
- `docs/cli.md`
- `docs/frameworks.md`
- `docs/security.md`
- `docs/schema.md`
- `.env.example`

Implementation reviewed:

- `cmd/control-server/main.go`
- `internal/config/config.go`
- `internal/devices/claim.go`
- `internal/devices/handler.go`
- `internal/devices/keys.go`
- `internal/devices/peerconfig.go`
- `internal/overlay/peerconfig.go`
- `internal/wg/manager.go`

## Final approved prototype shape

Keep on Cloud Run:

- `selkie.live` website

Move to a Belgium VM:

- `admin.selkie.live`
- `api.selkie.live`
- `relay.selkie.live`
- Selkie control server
- WireGuard hub `wg0`
- coturn
- Redis
- Caddy

External shared services:

- shared PostgreSQL in the UnlikeOtherAI project

Explicit prototype decisions:

- machine type `e2-small`
- region `europe-west1`
- Redis is VM-hosted and can be reused later by other internal projects
- PostgreSQL is not hosted on the VM
- the VPN hub is always on and does not scale to zero

## Why Cloud Run is insufficient

The reviewed docs are consistent on the critical point: the MVP control server owns `wg0` and routes the hub-and-spoke overlay.

That means the runtime must be able to:

- create and configure a WireGuard interface
- accept `51820/udp`
- route packets between device peers
- expose coturn on `3478/udp,tcp` and `5349/tcp`

Cloud Run cannot satisfy those requirements.

## Reviewed gaps and resolutions

### Codex review

Required fixes identified:

1. the server must actually initialize and reconcile `wg0`
2. device peer configs must use the server overlay IP as `/32`, not the full overlay CIDR
3. heartbeat, claim, key rotation, and revoke flows must reconcile live WireGuard peers
4. the deployment docs must stop implying Cloud Run can host the VPN hub

Resolution:

- implemented in code and reflected in deployment docs

### Claude CLI review

Required additions identified:

1. explicit `WG_PRIVATE_KEY` runtime variable
2. `CAP_NET_ADMIN` on the server container
3. `PersistentKeepalive = 25` explicitly on both sides
4. SSE-friendly Caddy proxy behavior
5. explicit note that Cloud Run `selkie-server` stays out of DNS after cutover instead of being deleted

Resolution:

- added to code, `.env.example`, `ops/Caddyfile`, `ops/docker-compose.edge.yml`, and `docs/deployment.md`

### Gemini CLI review

Outcome:

- the VM-based plan was acceptable
- the main architecture choice was local Postgres versus shared Postgres

Resolution:

- shared PostgreSQL was selected by the user for cost reasons

## Runtime values

Approved public hosts:

- `selkie.live`
- `admin.selkie.live`
- `api.selkie.live`
- `relay.selkie.live`

Approved runtime values:

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

Server overlay address:

- `10.100.0.1/16`

## Required firewall policy

Public:

- `80/tcp`
- `443/tcp`
- `3478/udp`
- `3478/tcp`
- `5349/tcp`
- `51820/udp`

Internal only:

- `6379/tcp`
- `5766/tcp`

## Required secrets

- `UOA_SHARED_SECRET`
- `INTERNAL_SESSION_SECRET`
- `COTURN_SECRET`
- `COTURN_CLI_PASSWORD`
- `WG_PRIVATE_KEY`
- `REDIS_PASSWORD`
- `DATABASE_URL`

## Execution checklist

1. land the WireGuard hub code changes on `main`
2. validate Go tests, `make check`, and admin lint
3. provision a Belgium `e2-small` VM plus static IP
4. enable IP forwarding on the VM
5. deploy [ops/docker-compose.edge.yml](/System/Volumes/Data/.internal/projects/Projects/selkie/ops/docker-compose.edge.yml)
6. point `admin.`, `api.`, and `relay.` at the VM static IP
7. leave `selkie.live` on Cloud Run
8. keep the existing Cloud Run `selkie-server` service out of DNS and do not delete it during prototype rollout
9. validate real enrollment and a live WireGuard peer on the VM

## Success criteria

The rollout is complete when all of the following are true:

- `https://selkie.live` serves the website from Cloud Run
- `https://admin.selkie.live/admin` serves the admin UI from the VM
- `https://api.selkie.live/readyz` returns `200`
- `relay.selkie.live:51820/udp` is reachable for WireGuard
- `relay.selkie.live:3478` and `:5349` are reachable for TURN
- a newly enrolled device receives `AllowedIPs = 10.100.0.1/32`
- the server host shows that device as a live peer on `wg0`
