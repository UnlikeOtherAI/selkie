# Frameworks & Platform Architecture

Silkie is a self-hosted zero-trust access layer composed of three runtime
components that communicate over authenticated APIs and an encrypted WireGuard
overlay.

## Components

```text
┌─────────────────────────────────────────────────────────────┐
│  Admin UI (browser)                                         │
│  Static HTML/JS served by the control server               │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS (internal session JWT)
┌──────────────────────────▼──────────────────────────────────┐
│  Control Server (Go, MVP owns wg0)                         │
│  Auth · Device registry · Session broker · Policy · Audit  │
│  Postgres (durable) · Redis (ephemeral)                    │
└──────────────────────────┬──────────────────────────────────┘
                           │ WireGuard overlay + STUN/TURN
┌──────────────────────────▼──────────────────────────────────┐
│  Silkie CLI (Node.js, runs as OS service on each device)   │
│  WireGuard peer · Heartbeat · Service manifest reporter    │
└─────────────────────────────────────────────────────────────┘
```

## Control Server

Language: **Go 1.23+** — see [techstack.md](techstack.md) for the full library
map.

The server is the single source of truth. It coordinates device identity,
policy, session establishment, and in the MVP it also owns the hub WireGuard
interface used to route traffic between device peers.

## Admin UI

Static HTML + Tailwind CSS + vanilla JS, served directly by the control
server. No build step. Templates live in `docs/template/` during design and
are moved to `internal/admin/static/` when wired to the server.

## CLI

Language: **Node.js** — see [cli.md](cli.md) for the full spec.

The CLI runs as a long-lived OS service on every enrolled device. Once
enrolled it:

1. Maintains a WireGuard peer connection to the overlay network.
2. Sends periodic heartbeats to the control server with current endpoint and
   service manifest.
3. Subscribes to SSE for session and config events.
4. Participates in ICE candidate exchange when a remote peer wants to connect.
5. Switches between direct path and TURN relay as network conditions change.

The CLI is the only component that ever holds the device's WireGuard private
key. The server receives and stores only public keys.

## Authentication flows

Two paths exist for enrolling a new device. Both terminate with the CLI
holding a device credential (long-lived opaque token stored locally) and the
server holding the device's WireGuard public key.

### Pairing code

Used when enrolling any machine regardless of whether a browser is available
on that machine.

```text
CLI                         Server                       Admin UI
 │                             │                             │
 │── POST /v1/auth/pair/start ─►│                             │
 │◄─ { code: "A3X9KF", ttl } ──│                             │
 │                             │                             │
 │  (display "A3X9KF" in terminal)                           │
 │                             │◄── POST /v1/auth/pair/claim ─│
 │                             │    { code, device_name }    │
 │◄── poll /v1/auth/pair/status ───────────────────────────► │
 │◄─ { status: "authenticated", credential, wg_config } ─────│
 │                             │                             │
 │  (write credential to disk, configure WireGuard)          │
```

- Code is 6 uppercase alphanumeric characters.
- Code state is stored server-side and is single-use.
- The CLI generates the WireGuard keypair locally before requesting the code;
  the public key is included in `pair/start` and bound to the eventual claim.

### SSO

Used when the user is sitting at the machine being enrolled and a browser is
available.

```text
CLI                         Server                       Browser
 │                             │                             │
 │── POST /v1/auth/device/start ►│                            │
 │◄─ { device_code, auth_url } ─│                            │
 │                             │                             │
 │  (open auth_url in default browser)                       │
 │──────────────────────────────────────────────────────────►│
 │                             │◄── SSO callback (UOA) ──────│
 │                             │    device_code validated    │
 │◄── poll /v1/auth/device/status ───────────────────────────│
 │◄─ { status: "authenticated", credential, wg_config } ─────│
 │                             │                             │
 │  (write credential to disk, configure WireGuard)          │
```

- `device_code` is a random 32-byte token stored only as a hash server-side.
- The browser SSO flow is the standard UOA OAuth 2.0 authorization-code flow
  described in [sso.md](sso.md), with the `device_code` carried as state.

## Client SDKs

Silkie exposes a connection API that lets any application initiate and manage
peer connections through the overlay. The SDK layer is designed around a
**C++ core library** that implements the connection logic once, with thin
language wrappers on top.

### C++ core (`libsilkie`)

The canonical implementation. Handles:

- WireGuard peer lifecycle
- ICE candidate exchange with the session broker
- TURN relay credential consumption and fallback path selection
- connection state machine: `connecting -> direct | relay -> closed`
- callback interface for connection events

All other SDKs wrap this library so behavior stays consistent across
platforms.

### Node.js SDK (`@silkie/sdk`)

Native addon wrapping `libsilkie`. Published on npm. Used by the CLI daemon
and available for Node.js applications that want to initiate or accept
connections programmatically.

### Swift SDK (`Silkie`)

Swift package wrapping `libsilkie` via a C bridge. Targets iOS and macOS.

### Kotlin SDK (`silkie-android`)

JNI wrapper around `libsilkie`. Targets Android and exposes a coroutines-based
API.

## Service manifest

After enrollment, the CLI scans for locally listening TCP/UDP ports and
reports a service manifest to the server on every heartbeat. The server stores
this as the device's service catalog.

## Overlay network

Silkie uses WireGuard as the encrypted overlay transport, but the MVP topology
is deliberately simple: **hub-and-spoke**.

### MVP topology

- The server owns a WireGuard interface, typically `wg0`.
- The server takes one stable overlay IP from `WG_OVERLAY_CIDR`, for example
  `10.100.0.1/16`.
- Every enrolled device gets its own `/32` overlay IP.
- Every device peers only with the server, not with every other device.
- The server routes packets between peer `/32` addresses once they arrive on
  `wg0`.

That means the data path for the MVP is:

```text
device A <-> server wg0 <-> device B
```

The server is on the WireGuard path in the MVP even when TURN is not used.
TURN remains a separate fallback for networks where the WireGuard UDP path
itself cannot be established directly.

### AllowedIPs computation

Silkie computes `AllowedIPs` differently on devices and on the server.

On enrolled devices:

- `AllowedIPs` is exactly the server overlay address as a `/32`.
- Example: if the server overlay IP is `10.100.0.1`, every device receives
  `AllowedIPs = 10.100.0.1/32`.
- Devices do not receive every other device's `/32` in the MVP.

On the server:

- Each peer entry gets `AllowedIPs = <device_overlay_ip>/32`.
- Example: device `10.100.0.7` becomes a server peer with
  `AllowedIPs = 10.100.0.7/32`.
- Future routed subnets can be added later, but the MVP allows only the
  device's single overlay address.

### Endpoint update flow

Endpoint changes are driven by device heartbeats and successful handshakes.

Flow:

1. The CLI includes its current public endpoint in heartbeat payloads.
2. The server stores that endpoint against the device record.
3. The tunnel coordinator rewrites the matching server-side WireGuard peer
   endpoint.
4. The next WireGuard handshake uses the updated endpoint automatically.

The server does not need to push a new peer list to every device just because
one device's external endpoint changes. Devices keep a single peer: the
server.

### Keepalive policy

`PersistentKeepalive = 25` is enabled for every peer on both sides:

- every device peer config includes `PersistentKeepalive = 25`
- every server-side peer entry also uses `PersistentKeepalive = 25`

This keeps NAT mappings warm and keeps endpoint discovery reasonably fresh.

### Routing responsibility

Because the topology is hub-and-spoke, the server must route between peers:

- IP forwarding must be enabled on the server host.
- The server WireGuard interface must own the full overlay CIDR locally.
- The control plane remains the allocator of `/32` device addresses.

See [brief.md](brief.md) for the full session-broker and relay design.
