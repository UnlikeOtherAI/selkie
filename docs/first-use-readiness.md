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

## Required UOA identity refactor

Inspection found durable copies of UOA-owned email and display name in
`users`, populated by `internal/auth/callback.go` and consumed by mobile handoff
and session issuance. The internal service broker also accepts profile fields
from its caller. This violates the repository's UOA authority rule. Changes
that extend that identity design are stopped pending this refactor.

1. Keep a stable UOA subject reference and product-specific device ownership
   and audit relationships. Resolve human profiles and current access through
   the UOA API using its documented authorization and capability contracts.
2. Introduce a bounded in-memory profile/access cache with explicit expiration
   and revocation handling. Fail closed when access cannot be established.
   Do not add a durable profile cache or local credential fallback.
3. Move browser, mobile, and internal broker consumers to that API-backed
   model. A broker must validate the UOA subject and authorization rather than
   trusting caller-supplied profile fields. Existing session imports only
   reuse valid Selkie sessions and do not create users.
4. Migrate foreign keys while preserving stable product references, then drop
   copied email/display-name data and related uniqueness constraints. Review
   any local status or role data against UOA-owned access before retaining it.
5. If organisation/team support is introduced, bind tenants to stable UOA
   organisation IDs and teams to UOA team IDs one-to-one. Do not duplicate the
   hierarchy or flatten multiple organisations into a shared container.
6. Verify login, revoked membership, profile changes, mobile handoff, service
   delegation, and existing device ownership against the live UOA API before
   declaring the identity migration complete.

No production identity data was changed during this inspection.
