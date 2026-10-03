# First-use readiness

## Production inspection, 2026-10-03

- `admin.selkie.live`, `api.selkie.live`, and `relay.selkie.live` resolve to
  `178.105.82.46`, the shared host also serving `unlikeotherai.com`.
- Browser SSO completed and the admin overview and system pages loaded.
- `/healthz` returned `ok`; `/readyz` returned `ready`, checking PostgreSQL
  and Redis. Development login is disabled.
- PostgreSQL has migrations 001–003 applied, one user, zero devices, and zero
  connection sessions at the time of inspection.
- The WireGuard hub has `10.100.0.1/16`, listens on UDP 51820, and has forwarding
  enabled. No device peers are enrolled.
- The relay answered external STUN binding requests over UDP and TCP 3478.
  Authenticated TURN allocation and real device traffic have not been verified.
- The existing Compose project is `ops`, with Redis data in `ops_redis_data`.
  The previous deployment failed because it requested project `selkie` while
  fixed container names were already owned by `ops`. `ops/compose-prod.sh`
  selects the existing owner and refuses inconsistent ownership.

## Remaining acceptance

A working admin login does not establish that device connectivity works.
The desktop CLI remains a specification; its source is not in this repository.
Do not install the unrelated unscoped npm package `selkie`.
A supported native client must still be installed, enrolled, and used to prove
heartbeat, WireGuard handshake, an actual service connection, and TURN fallback.

## UOA identity migration

The implementation now keeps stable UOA subjects and existing product UUIDs,
reads profiles through the UOA API, seals independent refresh capabilities and
validates delegated broker authority centrally. Migrations 004–007 remove the
old email/name copies and preserve device ownership and audit references.
See [debug-login-sessions.md](debug-login-sessions.md) for the current contract.

The production observations above predate these migrations. Local database
and browser tests establish the implementation behavior; production migration,
real UOA login, mobile handoff and broker renewal still require deployment proof.
Real device traffic remains part of the native acceptance described above.
