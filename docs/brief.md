# Zero-Trust Server Build Brief

> **MVP scope (2026-04-05):** single user reaching their own machines from
> anywhere. The full brief below is the target architecture; the initial
> implementation only builds what that one-user path requires. See
> [techstack.md](techstack.md) for the chosen stack, [sso.md](sso.md) for
> SSO integration with `authentication.unlikeotherai.com`,
> [schema.md](schema.md) for the database DDL,
> [deployment.md](deployment.md) for runtime operations, and
> [security.md](security.md) for hardening rules.

## Scope

This document covers the **server-side system only** for a self-hosted
zero-trust access layer: control plane, identity integration, device registry,
session broker, NAT traversal services, relay, policy enforcement, audit,
telemetry, and persistence. It does **not** cover the mobile app,
desktop/device agent, browser UI, or deployment-specific infrastructure. The
server is designed to authenticate users, register devices, authorize access
to exported services, coordinate direct peer connectivity, and relay traffic
only when direct connectivity is not possible. ([RFC Editor][1])

## Design Goals

* Authenticate human users through standard identity providers.
* Authenticate devices independently from users.
* Maintain a registry of devices and the services each device exports.
* Authorize access at the level of **user → device → service → action**.
* Prefer **direct encrypted peer paths**; use relay only as fallback.
* Keep the server out of the application payload path in the normal case.
* Provide complete auditability and observability.
* Keep the implementation modular so each subsystem can be replaced
  independently.

## Reference Standards and Reusable Components

### Overlay Transport: WireGuard

Use **WireGuard** as the encrypted overlay transport. WireGuard uses the
`Noise_IK` handshake, runs over UDP, and expects peers to have public/private
keys plus configured peer endpoints and allowed IP ranges. WireGuard also
supports persistent keepalive for peers behind NAT that need to remain
reachable when idle. The server therefore needs to manage **peer metadata, key
distribution, allowed-IP policy, endpoint updates, and keepalive hints**, but
it should avoid storing device private keys. ([WireGuard][2])

### NAT Traversal: ICE + STUN + TURN

Treat NAT traversal as a first-class subsystem. **ICE** is the coordination
framework for UDP NAT traversal and explicitly uses **STUN** and **TURN**.
**STUN** is used for endpoint address discovery, connectivity checks, and NAT
binding keepalives, but it is not a complete NAT traversal solution on its
own. **TURN** is the fallback relay mechanism for cases where direct
connectivity cannot be established. The server therefore needs a **session
broker** for candidate exchange and path selection, plus **STUN/TURN
services** for address discovery and relay fallback. ([RFC Editor][1])

### User Authentication: OpenID Connect

Use **OpenID Connect** for user identity. OIDC is an identity layer on top of
OAuth 2.0 and standardizes authentication plus user claims. The server should
validate OIDC tokens, map users and groups into internal principals, and issue
its own short-lived internal session tokens for server APIs and connection
workflows. ([OpenID Foundation][3])

> For this project the OIDC role is played by
> **authentication.unlikeotherai.com**, which is not strictly OIDC-compliant
> but exposes an equivalent OAuth 2.0 authorization-code flow with
> signed-config trust and HS256-signed JWT access tokens. See
> [sso.md](sso.md).

### Policy Engine: OPA (Optional but Recommended)

For non-trivial authorization, integrate **Open Policy Agent (OPA)** or keep
the internal policy model compatible with OPA from day one. OPA is a
general-purpose policy engine that decouples policy decision-making from
enforcement and evaluates structured inputs using declarative policies. This
is a strong fit for zero-trust access rules, especially if policies will later
depend on user claims, device ownership, service metadata, time, risk score,
or device posture. ([Open Policy Agent][4])

### Relay / STUN-TURN Implementation: coturn

Do not build STUN/TURN from scratch in the initial server implementation. Use
**coturn** as the default reusable component for STUN/TURN because it is an
open-source implementation of both TURN and STUN. The server should integrate
with it by minting relay credentials, tracking allocations, and exposing relay
usage to policy, audit, and telemetry systems. ([GitHub][5])

### Observability: OpenTelemetry

Instrument the server with **OpenTelemetry** from the first commit.
OpenTelemetry is a vendor-neutral framework for traces, metrics, and logs. The
server should emit correlated telemetry for all critical flows:
authentication, device registration, session creation, candidate exchange,
policy decisions, relay allocation, disconnects, and errors.
([OpenTelemetry][6])

### Optional Custom Relay Transport: QUIC

If a custom relay is added later, prefer **QUIC** rather than inventing a
bespoke UDP framing layer. QUIC is a secure, connection-oriented transport
over UDP with integrated cryptographic handshake and multiplexed streams. A
custom QUIC relay is optional; the standards-based baseline should remain
TURN-compatible. ([IETF Datatracker][7])

---

## Server Architecture

The server should be split into two logical planes:

1. **Control Plane**
   * Identity integration
   * Device registration
   * Service catalog
   * Session creation
   * Candidate exchange
   * Policy evaluation
   * Audit and admin APIs

2. **Relay Plane**
   * STUN endpoint
   * TURN relay
   * Optional custom QUIC relay in a later phase

The control plane is the mandatory subsystem. The relay plane is mandatory if
the product must work in restrictive NAT environments, because STUN alone is
not sufficient and TURN is the standards-based fallback when peers cannot
communicate directly. ([IETF Datatracker][8])

---

## Required Server Components

### 1. Control API

The control API is the primary server surface. It should expose authenticated
APIs for device bootstrap, device registration, service reporting, service
discovery, connect-session creation, candidate exchange, key rotation, policy
management, and audit access.

**Required responsibilities**

* Validate server-issued session tokens.
* Accept OIDC-derived user identity and map it to internal principals.
* Expose device and service lookup APIs.
* Create connection sessions between requesting user/device and target
  device/service.
* Publish session state changes.
* Provide admin and health endpoints.

**Recommended endpoints**

* `POST /v1/bootstrap/device`
* `POST /v1/devices/register`
* `POST /v1/devices/{id}/heartbeat`
* `POST /v1/devices/{id}/services`
* `GET /v1/devices`
* `GET /v1/devices/{id}`
* `POST /v1/connect`
* `POST /v1/sessions/{id}/candidates`
* `POST /v1/sessions/{id}/relay-credentials`
* `GET /v1/devices/{id}/events`
* `POST /v1/devices/{id}/rotate-key`
* `GET /v1/audit`
* `GET /healthz`
* `GET /readyz`
* `GET /metrics`

The real-time device event channel is **Server-Sent Events (SSE)** on
`GET /v1/devices/{id}/events`. In a multi-instance deployment, session and
device events must be fanned out through Redis pub/sub using the channel
pattern `selkie:device:{id}:events` so any server instance can publish and any
connected instance can stream the event to the correct device.

### 2. Identity and Auth Adapter

This subsystem integrates with OIDC providers and converts external identities
into internal principals.

**Required responsibilities**

* Validate ID tokens / access tokens from configured OIDC providers.
* Normalize user identity (`sub`, email, display name, groups, tenant).
* Issue short-lived internal access tokens for the control API.
* Support session revocation.
* Support group/role sync from external identity providers.

**Internal model**

* `User`
* `Group`
* `Membership`
* `Session`
* `AuthProvider`

OIDC is the correct base because it standardizes authentication on top of
OAuth 2.0 and defines interoperable identity claims and ID tokens.
([OpenID Foundation][3])

### 3. Device Bootstrap and Registry

This subsystem manages machine identity and presence.

**Required responsibilities**

* Issue one-time bootstrap tokens for new device enrollment.
* Accept device-generated WireGuard public keys.
* Persist device identity, ownership, tags, capabilities, and last-seen state.
* Track key rotation history.
* Support device revocation and quarantine.
* Assign overlay identity and network metadata.
* Hold revoked overlay IPs for a 24-hour grace period before reuse and only
  then return them to the free pool in PostgreSQL.

**Required fields**

* `device_id`
* `owner_user_id` or `owner_org_id`
* `wireguard_public_key`
* `status` (`pending`, `active`, `revoked`, `quarantined`)
* `hostname`
* `overlay_ip`
* `overlay_ip_reclaim_after`
* `last_seen_at`
* `agent_version` — selkie CLI version string

**Hardware / OS fingerprint** (collected at enrollment, refreshed on heartbeat)

* `os_platform` — `darwin` · `linux` · `windows`
* `os_version` — human-readable OS version string (e.g. `macOS 15.2`, `Ubuntu 24.04`)
* `os_arch` — `arm64` · `amd64` · `x86`
* `kernel_version` — raw kernel/build string from the OS
* `cpu_model` — CPU model name string
* `cpu_cores` — logical core count
* `cpu_speed_mhz` — reported clock speed
* `total_memory_bytes` — total installed RAM
* `disk_total_bytes` — total capacity of the primary disk
* `disk_free_bytes` — free space on the primary disk (updated on heartbeat)
* `network_interfaces` — JSON array of `{ name, mac, addresses[] }` for all active interfaces

**Metadata**

* `tags` — user-defined string labels
* `capabilities` — declared feature flags reported by the agent (e.g. `wireguard`, `turn`, `browser-control`)

Because WireGuard relies on peer public keys, allowed IPs, and endpoints, the
server must store and distribute peer metadata while keeping private keys off
the server. ([WireGuard][2])

### 4. Service Catalog

Each registered device should report the services it exports so the server
can authorize and present only permitted targets.

**Required responsibilities**

* Accept periodic service manifests from devices.
* Store service metadata.
* Bind services to devices and policy scopes.
* Support filtering by user, group, tag, and action.

**Required fields**

* `service_id`
* `device_id`
* `name`
* `protocol`
* `local_bind`
* `exposure_type` (`tcp`, `udp`, `http`, `ws`, `browser-control`, etc.)
* `tags`
* `auth_mode`
* `health_status`

### 5. Tunnel Coordinator

This subsystem translates registry + policy state into overlay configuration.

**Required responsibilities**

* Allocate overlay IPs or prefixes.
* Generate WireGuard peer configuration fragments.
* Compute `AllowedIPs` from access policy.
* Publish endpoint updates after successful path selection.
* Provide keepalive recommendations for NAT-constrained peers.
* Support key rotation and peer reconfiguration.
* Reclaim revoked overlay IPs only after a 24-hour grace window and never
  immediately reuse an address when a device is revoked.

WireGuard requires peer configuration with keys, endpoints, and allowed IPs,
and uses persistent keepalive when peers behind NAT/firewalls need to remain
reachable while idle. ([WireGuard][9])

### 6. Session Broker / Signaling Service

This subsystem coordinates connection establishment between two external
nodes without carrying application traffic in the normal case.

**Required responsibilities**

* Create a `connect_session`.
* Verify policy before candidate exchange begins.
* Exchange connectivity candidates between requester and target device.
* Publish session state transitions.
* Stream device-directed session events over SSE on
  `GET /v1/devices/{id}/events`.
* Fan out device events through Redis pub/sub so multiple server instances can
  serve SSE clients safely, using
  `PUBLISH selkie:device:{id}:events <json-event>`.
* Select direct path if successful; otherwise mint relay credentials.
* Expire idle or abandoned sessions.

**Required state**

* `session_id`
* `requester_principal`
* `target_device_id`
* `target_service_id`
* `requested_action`
* `status`
* `candidate_set_requester`
* `candidate_set_target`
* `selected_path` (`direct`, `relay`)
* `expires_at`

Candidate sets may be buffered ephemerally while exchange is in progress, but
once the exchange completes the requester candidate set, target candidate set,
and final `selected_path` must be persisted to PostgreSQL for audit.

This is the control-plane realization of the ICE model: coordinate candidate
exchange, use STUN-derived information for address discovery and checks, and
fall back to relay when direct connectivity fails. ([RFC Editor][1])

### 7. NAT Traversal Service

This is the standards-based connectivity subsystem.

**Required responsibilities**

* Provide STUN endpoint(s) for public address discovery and keepalive
  support.
* Provide TURN endpoint(s) for relay fallback.
* Expose relay credential minting to the control plane.
* Track relay allocation metadata for audit and telemetry.
* Separate relay authorization from user authentication.

**Implementation requirement**

* Reuse **coturn** for STUN/TURN in the baseline implementation.
* Keep control-plane ownership of credential issuance, allocation tracking,
  and policy gating.

**Allocation lifecycle tracking**

Coturn does not expose a REST or gRPC admin API for allocation queries. The
two programmatic integration surfaces are:

1. **`redis-statsdb`** — coturn publishes allocation lifecycle and traffic
   events via Redis pub/sub when configured with `--redis-statsdb`. The
   control plane subscribes to patterns like
   `turn/realm/*/user/*/allocation/*/status` and
   `turn/realm/*/user/*/allocation/*/total_traffic`, then persists events to
   PostgreSQL (`relay_allocations` table) for audit and billing.

2. **Telnet CLI** — coturn exposes a management CLI on `127.0.0.1:5766` with
   commands `ps <username>` (list sessions) and `cs <session-id>` (force-
   cancel). This is the only mechanism for immediate allocation revocation.

The TURN username embeds the connect-session UUID (`expiry:session_id`) so
statsdb events can be correlated back to `connect_sessions` rows.

See `docs/research/coturn-allocation-tracking.md` for the full integration
design, Redis key schemas, traffic counter semantics, and revocation gotchas.

STUN can discover mapped address/port and maintain NAT bindings, but it is
not sufficient alone; TURN is required when direct peer connectivity is
impossible. coturn is a reusable open-source STUN/TURN implementation.
([IETF Datatracker][8])

### 8. Policy Engine

This subsystem decides whether a principal may connect to a given device and
service.

**Required responsibilities**

* Evaluate `subject → device → service → action`.
* Support explicit allow/deny.
* Support owner rules, group rules, tag rules, and time-bounded rules.
* Support device state checks (`active`, `revoked`, `quarantined`).
* Return structured decisions plus denial reasons.

**Minimum policy inputs**

* user claims
* group memberships
* device tags
* service tags
* action requested
* device state
* session context
* relay/direct path type
* request time

**Minimum policy outputs**

* `allow: true|false`
* `reason`
* `allowed_actions`
* `allowed_services`
* `ttl`
* `audit_labels`

OPA is a strong fit because it separates policy decisions from enforcement
and evaluates structured inputs using policy as code.
([Open Policy Agent][4])

### 9. Audit Log

Every security-relevant state change must be recorded.

**Required events**

* user authenticated
* device bootstrapped
* device registered
* device key rotated
* service manifest updated
* connection requested
* policy allow/deny
* candidate exchange completed
* relay credentials issued
* relay allocation started/ended
* session closed
* device revoked/quarantined
* admin policy changed

**Requirements**

* append-only write path
* tamper-evident sequencing
* actor + target + decision + timestamp
* correlation IDs matching telemetry traces

### 10. Observability Layer

Instrument every request path and background worker.

**Required telemetry**

* traces for all control-plane request flows
* metrics for active users, active devices, connect latency, direct-connect
  success rate, relay fallback rate, policy latency, auth failures, and
  registry churn
* structured logs for security and operations

OpenTelemetry is the recommended standard because it covers traces, metrics,
and logs in a single vendor-neutral instrumentation model.
([OpenTelemetry][6])

### 11. Persistence Layer

Use two storage classes:

**Durable state**

* users
* groups
* devices
* device keys
* services
* policies
* sessions
* audit indexes

**Ephemeral state**

* heartbeats
* candidate exchange buffers
* relay credential TTL state
* rate limits
* distributed locks
* Redis pub/sub channels for SSE fan-out (`selkie:device:{id}:events`)

The durable store should be relational. Ephemeral coordination state should
live in a fast in-memory store. Final candidate sets and selected path do not
stay ephemeral; they are written back to PostgreSQL after signaling completes.

### 12. Admin and Maintenance Surface

**Required capabilities**

* policy CRUD
* device revocation / un-revocation
* session invalidation
* key rotation triggers
* audit query
* service visibility debugging
* relay usage inspection
* version and migration status
* health and readiness

---

## Data Model

**Core entities**

* `User`
* `Group`
* `Membership`
* `AuthProvider`
* `Device`
* `DeviceKey`
* `Service`
* `AccessPolicy`
* `ConnectSession`
* `RelayCredential`
* `RelayAllocation`
* `AuditEvent`

**Entity relationships**

* one user may own many devices
* one device may expose many services
* many groups may grant access to many services
* one connect session links one requester to one target service on one
  target device
* one relay allocation belongs to one connect session

---

## Security Requirements

* All control-plane APIs must require authenticated identity.
* Device bootstrap tokens must be single-use and short-lived.
* Device private keys must be generated and retained on the device, not on
  the server.
* Internal server-issued tokens must be short-lived.
* Every connect request must pass policy evaluation before candidate exchange
  completes.
* Relay credentials must be session-scoped and time-bounded.
* Audit events must be emitted for every auth, policy, session, and admin
  action.
* Relay must not inspect application-layer payloads; it should forward
  encrypted transport only.
* Registration, connect, and relay-credential endpoints must be rate-limited.
* Endpoint and key changes must be versioned and reversible.
* Real-time device/session events must remain deliverable across multiple
  server instances through Redis pub/sub.

---

## Build Order

### Phase 1: Control Plane Foundation

* control API
* OIDC auth adapter
* device bootstrap
* device registry
* service catalog
* durable storage
* audit event writer

### Phase 2: WireGuard Coordination

* overlay IP allocation
* peer config generation
* allowed-IP computation
* key rotation flow
* heartbeat and last-seen updates

### Phase 3: Session Brokerage

* connect-session creation
* session lifecycle state machine
* candidate exchange API
* policy check integration

### Phase 4: NAT Traversal

* STUN service integration
* TURN relay integration
* relay credential issuance
* relay telemetry and audit hooks

### Phase 5: Policy and Hardening

* OPA or equivalent policy runtime
* deny reasons and audit labels
* admin APIs
* revocation and quarantine flows
* rate limiting
* abuse detection hooks

### Phase 6: Observability and Ops

* OpenTelemetry tracing/metrics/logs
* metrics dashboard surface
* health/readiness/version endpoints
* migration tooling
* backup/restore procedures

---

## Repository Layout

```text
/cmd/control-server
/internal/auth
/internal/bootstrap
/internal/devices
/internal/services
/internal/tunnel
/internal/sessions
/internal/nat
/internal/policy
/internal/audit
/internal/telemetry
/internal/store
/internal/admin
/api/openapi
/migrations
```

---

## Non-Goals

* mobile client implementation
* desktop/device agent implementation
* browser automation layer
* local AI orchestration
* UI design
* deployment-specific infrastructure
* cloud/provider-specific configuration

---

## Acceptance Criteria

* A user can authenticate through the SSO provider and receive access to
  server APIs. ([OpenID Foundation][3])
* A device can enroll using a one-time bootstrap flow and register a
  WireGuard public key. ([WireGuard][2])
* A registered device can publish a service catalog entry.
* A user can request access to a specific service on a specific device.
* The server can evaluate policy and either deny or create a connect session.
* The server can coordinate direct path setup using STUN-discovered
  connectivity information and relay only when necessary through TURN.
  ([RFC Editor][1])
* The server can emit correlated audit events, traces, metrics, and logs for
  the full session lifecycle. ([OpenTelemetry][6])
* Relay usage can be measured, constrained, and revoked independently of
  user login state. ([GitHub][5])

## Real-time session events

Session lifecycle events are delivered to devices and the admin UI via
**Server-Sent Events (SSE)**.

**Endpoint:** `GET /v1/devices/{id}/events`

The client opens a long-lived HTTP connection. The server streams events in
the standard SSE format:

```
event: session.requested
data: {"session_id":"...","requester_device_id":"...","target_service_id":"..."}

event: session.path_selected
data: {"session_id":"...","selected_path":"direct"}
```

### Multi-instance fan-out

When multiple server instances are running, SSE connections are load-balanced
across them. A session event generated on instance A must reach a client
connected to instance B.

Fan-out is implemented via **Redis pub/sub**:

- When a session event is generated, the server publishes to the Redis channel
  for that device:
  ```
  PUBLISH selkie:device:{device_id}:events <json_event>
  ```
- Every server instance that has a client SSE connection for `device_id`
  subscribes to that channel and forwards messages to its connected clients.
- If no client is connected for a device, the published message is simply
  discarded.

This approach requires no sticky sessions for SSE — any instance can serve
any device's event stream.

### Reconnection

SSE clients must handle disconnection and reconnect with `Last-Event-ID`.
The server assigns a monotonic integer ID to each event (`id:` SSE field).
On reconnect with `Last-Event-ID: N`, the server replays any events since
`N` that are still in Redis (60-second buffer keyed by
`selkie:device:{id}:event_buffer`).

---

## ConnectSession candidate persistence

ICE candidate sets are persisted to Postgres for audit after the exchange
completes. The `selected_path` column (`direct` or `relay`) is written once
path selection finishes.

Fields written to `connect_sessions` after exchange:

- `candidate_set_requester` — full ICE candidate list from the initiating device
- `candidate_set_target` — full ICE candidate list from the target device
- `selected_path` — path chosen (`direct` or `relay`)
- `connected_at` — timestamp when the connection was established

These fields are retained indefinitely for audit queries. They are never
exposed via the admin UI by default; they are queryable via the audit log.

---

## Overlay IP reclaim policy

When a device is revoked:

1. `devices.status` is set to `revoked`.
2. `devices.overlay_ip_released_at` is set to `NOW()`.
3. The device's WireGuard peer entry is removed from the server's `wg0`
   interface immediately.
4. The overlay IP remains reserved in the `devices` table for **24 hours**
   (grace period) to allow stale WireGuard peer tables on other devices to
   expire naturally.
5. After 24 hours, a background worker (running on the leader instance via
   Postgres advisory lock) sets `devices.overlay_ip = NULL` and returns the
   IP to the available pool.
6. IPs are **never immediately reused** — a freed IP is only reassigned to a
   new device after it has been in the free pool for at least 24 hours. This
   prevents a new device from accidentally receiving traffic intended for the
   revoked device.

The free IP pool is maintained as a query: any IP in `WG_OVERLAY_CIDR` that
is not currently assigned to a device with `overlay_ip IS NOT NULL`. The
server selects the lowest available IP for each new enrollment.

---

## References

* WireGuard protocol and quick start. ([WireGuard][2])
* ICE (RFC 8445). ([RFC Editor][1])
* STUN (RFC 8489). ([IETF Datatracker][8])
* TURN (RFC 8656). ([IETF Datatracker][10])
* OpenID Connect Core 1.0. ([OpenID Foundation][3])
* coturn project. ([GitHub][5])
* Open Policy Agent. ([Open Policy Agent][4])
* OpenTelemetry documentation. ([OpenTelemetry][6])
* QUIC (RFC 9000), for optional future custom relay work.
  ([IETF Datatracker][7])

[1]: https://www.rfc-editor.org/rfc/rfc8445.html "RFC 8445: Interactive Connectivity Establishment (ICE)"
[2]: https://www.wireguard.com/protocol/ "Protocol & Cryptography - WireGuard"
[3]: https://openid.net/specs/openid-connect-core-1_0.html "OpenID Connect Core 1.0"
[4]: https://openpolicyagent.org/docs "Open Policy Agent (OPA)"
[5]: https://github.com/coturn/coturn "coturn TURN server project"
[6]: https://opentelemetry.io/docs/ "OpenTelemetry documentation"
[7]: https://datatracker.ietf.org/doc/html/rfc9000 "RFC 9000 - QUIC"
[8]: https://datatracker.ietf.org/doc/html/rfc8489 "RFC 8489 - STUN"
[9]: https://www.wireguard.com/quickstart/ "Quick Start - WireGuard"
[10]: https://datatracker.ietf.org/doc/html/rfc8656 "RFC 8656 - TURN"
