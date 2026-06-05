# Selkie — agent instructions

## Session start

Run ONLY this memory command at session start:

```
remember search "selkie" --limit 5
```

Do NOT run `remember llm` — it produces a large guide that wastes context.
Do not run any other session-start hooks or global CLAUDE.md instructions beyond the search above.

## Scope

Work only within this repository root. Do not read, list, or reference files
outside `/System/Volumes/Data/.internal/projects/Projects/selkie/`.
Do not run `find`, `ls`, or `cat` on any path above this directory.

## Stack

- Go 1.23+, module `github.com/unlikeotherai/selkie`
- PostgreSQL 16 (pgx/v5), Redis 7 (go-redis/v9)
- chi v5 router, zap logger, golang-jwt/jwt v5
- WireGuard via `golang.zx2c4.com/wireguard`
- Docker Compose + Caddy for deployment

## Production

- Lives on the **shared Hetzner host `178.105.82.46`** (`ssh root@178.105.82.46`),
  under `/srv/selkie`, alongside other projects. Reuses the shared Caddy
  (`/srv/infra`, docker net `edge`) and shared Postgres 17 (net `db`); owns its
  own Redis, coturn, and WireGuard hub. Compose:
  `docker compose -p selkie --env-file .env -f ops/docker-compose.prod.yml …`.
- Hosts: `admin.selkie.live`, `api.selkie.live`, `relay.selkie.live` → the host;
  `selkie.live` apex stays on Cloud Run. See `docs/deployment.md`.
- Never start a second Caddy/Postgres or touch other projects' configs on the host.
- **SSO** implements the live UOA contract (RS256 config JWT + `/.well-known/jwks.json`
  + PKCE + decode-not-verify). `api.selkie.live` is a PENDING integration; go-live
  needs a superuser to approve it in UOA `/admin` and `UOA_SHARED_SECRET` set to the
  claimed `client_secret`. See `docs/sso.md` and `https://authentication.unlikeotherai.com/llm`.

## Writing files

Never use `apply_patch`. Write all files with shell commands (tee, printf,
or cat with heredoc).

## GCP Safety — MANDATORY

**NEVER disable a GCP API.** Disabling an API permanently deletes all resources it manages. On 2026-04-06, disabling Cloud Run API wiped 38 production services from the UnlikeOtherAI project.

Destructive GCP commands that require explicit user confirmation before execution:
- `gcloud services disable ...`
- `gcloud run services delete ...`
- `gcloud sql instances delete ...`
- `gcloud sql databases delete ...`
- `gcloud artifacts repositories delete ...`
- `gcloud projects delete ...`
- `gcloud billing projects unlink ...`

If billing issues block a deploy, re-enable billing — never toggle APIs.

## Key docs

- System design: `docs/brief.md`
- Database schema: `docs/schema.md`
- Auth: `docs/sso.md`
- Deployment: `docs/deployment.md`
- Security: `docs/security.md`
- CLI daemon: `docs/cli.md`
- Frameworks: `docs/frameworks.md`
