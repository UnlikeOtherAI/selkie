# Frameworks & Platform Architecture

Silkie is a self-hosted zero-trust access layer composed of three runtime
components that communicate over authenticated APIs and an encrypted WireGuard
overlay.

## Components

```
┌─────────────────────────────────────────────────────────────┐
│  Admin UI (browser)                                         │
│  Static HTML/JS served by the control server               │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS (internal session JWT)
┌──────────────────────────▼──────────────────────────────────┐
│  Control Server  (Go)                                       │
│  Auth · Device registry · Session broker · Policy · Audit  │
│  Postgres (durable) · Redis (ephemeral)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │ WireGuard overlay + STUN/TURN
┌──────────────────────────▼──────────────────────────────────┐
│  Silkie CLI  (Node.js, runs as OS service on each device)   │
│  WireGuard peer · Heartbeat · Service manifest reporter    │
└─────────────────────────────────────────────────────────────┘
```

## Control Server

Language: **Go 1.23+** — see [techstack.md](techstack.md) for the full library
map.

The server is the single source of truth. It never carries application-layer
traffic in normal operation; it only coordinates device identity, policy, and
session establishment. The CLI talks to it over HTTPS using short-lived JWTs
minted after device enrollment.

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
3. Participates in ICE candidate exchange when a remote peer wants to connect.
4. Switches between direct path and TURN relay as network conditions change.

The CLI is the **only component that ever holds the device's WireGuard private
key.** The server receives and stores only the public key.

## Authentication flows

Two paths exist for enrolling a new device. Both terminate with the CLI
holding a device credential (long-lived opaque token stored locally) and the
server holding the device's WireGuard public key.

### Pairing code (primary)

Used when enrolling any machine regardless of whether a browser is available
on that machine.

```
CLI                         Server                       Admin UI
 │                             │                             │
 │── POST /v1/auth/pair/start ─►│                             │
 │◄─ { code: "A3X9KF", ttl } ──│                             │
 │                             │                             │
 │  (display "A3X9KF" in terminal)                           │
 │                             │◄── POST /v1/auth/pair/claim ─│
 │                             │    { code, device_name }    │
 │◄── poll /v1/auth/pair/status every 5s ──────────────────► │
 │◄─ { status: "authenticated", credential, wg_config } ─────│
 │                             │                             │
 │  (write credential to disk, configure WireGuard)          │
```

- Code is 6 alphanumeric characters (uppercase), stored in Redis with a 10-minute TTL.
- Single-use: claiming the code invalidates it immediately.
- The CLI generates the WireGuard keypair locally before requesting the code;
  the public key is included in `pair/start` and stored on claim.

### SSO (same-machine)

Used when the user is sitting at the machine being enrolled and a browser is
available.

```
CLI                         Server                       Browser
 │                             │                             │
 │── POST /v1/auth/device/start ►│                            │
 │◄─ { device_code, auth_url } ─│                            │
 │                             │                             │
 │  (open auth_url in default browser)                       │
 │──────────────────────────────────────────────────────────►│
 │                             │◄── SSO callback (UOA) ──────│
 │                             │    device_code validated    │
 │◄── poll /v1/auth/device/status every 5s ──────────────────│
 │◄─ { status: "authenticated", credential, wg_config } ─────│
 │                             │                             │
 │  (write credential to disk, configure WireGuard)          │
```

- `device_code` is a random 32-byte token stored in Redis with a 15-minute TTL.
- The browser SSO flow is the standard UOA OAuth 2.0 authorization-code flow
  described in [sso.md](sso.md), with the `device_code` carried as a state
  parameter so the server can mark it authenticated on callback.

## Client SDKs

Silkie exposes a connection API that lets any application initiate and manage
peer connections through the overlay. The SDK layer is designed around a
**C++ core library** that implements the connection logic once, with thin
language wrappers on top.

### C++ core (`libsilkie`)

The canonical implementation. Handles:

- WireGuard peer lifecycle (using the WireGuard userspace Go library via CGo
  or the native C++ binding).
- ICE candidate exchange with the session broker.
- TURN relay credential consumption and fallback path selection.
- Connection state machine: `connecting → direct | relay → closed`.
- Callback interface for connection events.

All other SDKs wrap this library. Keeping the logic in one place ensures
consistent behaviour across platforms.

### Node.js SDK (`@silkie/sdk`)

Native addon (`node-addon-api`) wrapping `libsilkie`. Published on npm.
Used by the CLI daemon and available for Node.js applications that want to
initiate or accept connections programmatically.

```js
import { SilkieClient } from '@silkie/sdk'

const client = new SilkieClient({ serverUrl, credential })
const conn = await client.connect({ deviceId, serviceId })
conn.on('data', chunk => { /* … */ })
```

### Swift SDK (`Silkie`)

Swift package wrapping `libsilkie` via a C bridging header. Targets iOS and
macOS. Used by the iOS/macOS app to connect to enrolled devices.

### Kotlin SDK (`silkie-android`)

JNI wrapper around `libsilkie`. Targets Android. Exposes a coroutines-based
API for connection management.

### Compatibility

Any platform that can link a C/C++ static or dynamic library can wrap
`libsilkie` directly. The C++ core exposes a flat C API header
(`silkie.h`) specifically to simplify FFI from languages with a C FFI
(Rust, Python, Go, etc.).

---

## Service manifest

After enrollment, the CLI scans for locally listening TCP/UDP ports and
reports a service manifest to the server on every heartbeat. The server stores
this as the device's service catalog (read-only from the admin UI). The user
can annotate services with friendly names via the admin.

## Overlay network

WireGuard is used as the encrypted peer-to-peer transport. The server manages
overlay IP allocation and peer config distribution. Direct paths are preferred;
TURN relay via coturn is the fallback when NAT prevents direct connectivity.
See [brief.md](brief.md) for the full NAT traversal design.

---

## WireGuard topology (MVP)

Silkie uses a **hub-and-spoke** topology for MVP. The control server runs a
WireGuard interface (`wg0`) and acts as the hub. Every enrolled device peers
directly to the server; devices do not peer with each other directly.

```
Device A ──── WireGuard ────► Server (hub, wg0)
Device B ──── WireGuard ────► Server (hub, wg0)
Device C ──── WireGuard ────► Server (hub, wg0)
```

Application traffic between Device A and Device B flows:

```
Device A → (WG encrypted) → Server → (WG encrypted) → Device B
```

This keeps the initial implementation simple: the server controls all peering,
there is no mesh configuration required, and NAT traversal between devices is
not needed for MVP.

### Server WireGuard interface

The server's `wg0` interface is configured once at startup:

```ini
[Interface]
PrivateKey = <server_private_key>
Address    = 10.100.0.1/16     # first IP in WG_OVERLAY_CIDR
ListenPort = 51820
```

The server's overlay IP is `10.100.0.1` (or the first host address in
`WG_OVERLAY_CIDR`). This is the IP that devices use as the WireGuard endpoint
when connecting.

### Device WireGuard configuration

Each device receives a `wg_config` block from the server after enrollment:

```ini
[Interface]
PrivateKey = <device_private_key>   # generated on-device, never transmitted
Address    = 10.100.x.y/32          # device's assigned overlay IP
DNS        = <optional>

[Peer]
PublicKey           = <server_public_key>
Endpoint            = <server_host>:51820
AllowedIPs          = 10.100.0.0/16   # entire overlay CIDR routed via server
PersistentKeepalive = 25
```

`AllowedIPs = 10.100.0.0/16` routes all overlay traffic through the server.
Devices do not need to know each other's endpoints; the server handles routing
between peers.

`PersistentKeepalive = 25` ensures the device's NAT mapping stays open so
the server can send packets to it. 25 seconds is the standard value below the
30-second NAT timeout of most residential routers.

### Server peer table (per enrolled device)

For each active device, the server maintains a WireGuard peer entry:

```ini
[Peer]
PublicKey           = <device_public_key>
AllowedIPs          = 10.100.x.y/32   # device's overlay IP only
```

The server does **not** set `Endpoint` for device peers — it learns the
device's current external endpoint dynamically from the WireGuard handshake.
The device's heartbeat updates the endpoint in the server's WireGuard peer
table via `wg set wg0 peer <pubkey> endpoint <ip>:<port>`.

### AllowedIPs computation

| Party | AllowedIPs |
|---|---|
| Device (for server peer) | `WG_OVERLAY_CIDR` (e.g. `10.100.0.0/16`) — routes all overlay traffic to server |
| Server (for device peer) | `<device_overlay_ip>/32` — only traffic destined for that device |

### Endpoint updates

When a device's external IP or port changes (roaming between networks):

1. The WireGuard handshake updates the server's peer table automatically
   (WireGuard learns the new endpoint from the incoming handshake).
2. On the next heartbeat, the daemon confirms the new endpoint by including
   it in the heartbeat payload. The server stores this in
   `devices.last_heartbeat_at` and updates the peer entry if needed.

### Key rotation

On server-initiated key rotation:

1. Server sends a key rotation request via SSE (`GET /v1/devices/{id}/events`).
2. Daemon generates a new keypair locally.
3. Daemon POSTs the new public key to `POST /v1/devices/{id}/rotate-key`.
4. Server updates `device_keys` (sets old key `is_current = FALSE`, inserts
   new key with `is_current = TRUE`) and updates `wg set wg0 peer` atomically.
5. Old WireGuard peer entry (by old pubkey) is removed; new peer entry is added.
6. Daemon applies the new private key to its local `wg0` interface.
