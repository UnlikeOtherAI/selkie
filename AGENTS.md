# Silkie — agent instructions

## Session start

Run ONLY this memory command at session start:

```
remember search "silkie" --limit 5
```

Do NOT run `remember llm` — it produces a large guide that wastes context.
Do not run any other session-start hooks or global CLAUDE.md instructions beyond the search above.

## Scope

Work only within this repository root. Do not read, list, or reference files
outside `/System/Volumes/Data/.internal/projects/Projects/silkie/`.
Do not run `find`, `ls`, or `cat` on any path above this directory.

## Stack

- Go 1.23+, module `github.com/unlikeotherai/silkie`
- PostgreSQL 16 (pgx/v5), Redis 7 (go-redis/v9)
- chi v5 router, zap logger, golang-jwt/jwt v5
- WireGuard via `golang.zx2c4.com/wireguard`
- Docker Compose + Caddy for deployment

## Writing files

Never use `apply_patch`. Write all files with shell commands (tee, printf,
or cat with heredoc).

## Key docs

- System design: `docs/brief.md`
- Database schema: `docs/schema.md`
- Auth: `docs/sso.md`
- Deployment: `docs/deployment.md`
- Security: `docs/security.md`
- CLI daemon: `docs/cli.md`
- Frameworks: `docs/frameworks.md`
