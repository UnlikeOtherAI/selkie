# Silkie CLI

The Silkie CLI is a Node.js daemon published on npm. It runs as a system
service on each enrolled device, maintains the WireGuard peer connection, and
reports the device's service manifest to the control server.

## Install

```sh
npm install -g silkie
```

Requires Node.js 20+. The package ships a native WireGuard binding and
pre-built coturn credentials helper for macOS (arm64/amd64) and Linux
(amd64/arm64).

## Run as a service

After enrollment, install the system service so the daemon starts on boot:

```sh
silkie service install   # launchd on macOS, systemd on Linux
silkie service start
silkie service status
silkie service stop
silkie service uninstall
```

The service runs as the current user. It does not require root except to
configure the WireGuard interface (handled once during install via a privileged
helper).

## Enrollment

Two authentication paths are available. Both result in the CLI holding a
device credential on disk (`~/.silkie/credential`) and the server registering
the device's WireGuard public key.

The CLI generates the WireGuard keypair locally on first run. The private key
never leaves the device.

### Option 1 — Pairing code (any machine)

Use this when enrolling a headless server or any machine where opening a
browser is inconvenient.

```sh
silkie enroll
```

The CLI:

1. Generates a local WireGuard keypair if one does not exist.
2. Requests a pairing code from the server (`POST /v1/auth/pair/start`).
3. Prints a **6-character code** (e.g. `A3X9KF`).
4. Polls `GET /v1/auth/pair/status` every 5 seconds.

While the CLI is waiting, open the Silkie admin UI, go to
**Devices → Enrol Device**, and enter the 6-character code. Once submitted,
the CLI receives its credential and WireGuard config automatically.

Codes expire after **10 minutes** and are single-use.

### Option 2 — SSO (machine with a browser)

Use this when you are sitting at the machine being enrolled.

```sh
silkie enroll --sso
```

The CLI:

1. Generates a local WireGuard keypair if one does not exist.
2. Requests a device authorization code from the server.
3. Opens the SSO login URL in the default browser.
4. Polls `GET /v1/auth/device/status` every 5 seconds.

Complete the login in the browser. The CLI will receive its credential
automatically once the SSO flow completes. No manual code entry required.

## Commands

| Command | Description |
|---|---|
| `silkie enroll` | Enrol this device using a pairing code |
| `silkie enroll --sso` | Enrol this device via SSO browser login |
| `silkie status` | Show device status, overlay IP, and active connections |
| `silkie service install` | Install the system service |
| `silkie service start` | Start the service |
| `silkie service stop` | Stop the service |
| `silkie service status` | Show service health |
| `silkie service uninstall` | Remove the system service |
| `silkie logout` | Revoke credential and remove device registration |
| `silkie logs` | Stream daemon logs |

## Configuration

Config lives at `~/.silkie/config.json`. Most values are written during
enrollment and should not be edited manually.

| Key | Description |
|---|---|
| `server_url` | Control server base URL |
| `device_id` | Assigned device ID |
| `credential` | Long-lived device credential token |
| `wg_public_key` | WireGuard public key (informational) |
| `overlay_ip` | Assigned overlay IP |

The WireGuard private key is stored separately at `~/.silkie/wg.key` with
mode `0600`.

## How it works

Once running, the daemon:

1. **Heartbeat** — POSTs to `/v1/devices/{id}/heartbeat` every 30 seconds,
   sending current external endpoint and service manifest.
2. **Service manifest** — Scans listening ports and reports them as the
   device's service catalog. The server exposes this in the admin UI.
3. **Session handling** — Subscribes to session events. When a remote peer
   requests a connection, the daemon participates in ICE candidate exchange
   via the session broker, preferring a direct WireGuard path and falling back
   to TURN relay.
4. **Key rotation** — Responds to server-initiated key rotation requests,
   generating a new keypair and uploading the new public key.

## Device fingerprint

At enrollment, and refreshed on every heartbeat, the CLI collects the
following information and sends it to the control server. All fields are
read from the OS — nothing is estimated or inferred.

| Field | Source |
|---|---|
| `hostname` | `os.hostname()` |
| `os_platform` | `os.platform()` — `darwin` / `linux` / `win32` |
| `os_version` | `os.version()` + `os.release()` combined into a readable string |
| `os_arch` | `os.arch()` |
| `kernel_version` | `os.version()` raw value |
| `cpu_model` | `os.cpus()[0].model` |
| `cpu_cores` | `os.cpus().length` |
| `cpu_speed_mhz` | `os.cpus()[0].speed` |
| `total_memory_bytes` | `os.totalmem()` |
| `disk_total_bytes` | `fs.statfs('/')` (or `C:\` on Windows) |
| `disk_free_bytes` | `fs.statfs('/')` — refreshed on every heartbeat |
| `network_interfaces` | `os.networkInterfaces()` — name, MAC, all assigned addresses |
| `agent_version` | package `version` field from `package.json` |

**What is and is not collected:**

- CPU and memory figures are point-in-time snapshots, not continuous monitoring.
- `disk_free_bytes` and `network_interfaces` are the only fields that change
  frequently; they are updated on every heartbeat so the server always has a
  current picture.
- No process list, no file system contents, no browser data, no user activity.
- The user can inspect exactly what will be sent before enrollment by running
  `silkie enroll --dry-run`.

## Privilege model

The daemon needs `CAP_NET_ADMIN` to create and configure the WireGuard
interface. This is handled differently per platform:

### macOS

The daemon runs as the current user. A **privileged helper tool** (a separate
setuid-root binary, installed to `/Library/PrivilegedHelperTools/` via SMJobBless)
performs the WireGuard interface operations on behalf of the daemon. The helper
is invoked once at service install time and again whenever the WireGuard
interface needs to be (re)created. `sudo` is not required after the initial
install.

The launchd plist (`~/Library/LaunchAgents/com.unlikeotherai.silkie.plist`) runs
the daemon as the current user. The helper communicates via a Mach port registered
in the bootstrap namespace.

### Linux

The systemd unit runs with elevated network capabilities:

```ini
[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
```

Alternatively, the daemon binary can be given `CAP_NET_ADMIN` directly via
`setcap cap_net_admin+eip /usr/local/bin/silkie-daemon`, in which case the
systemd unit can run as a non-root user.

---

## WireGuard interface lifecycle

| Event | Action |
|---|---|
| `service start` (first run) | Create `wg0` interface, apply full peer config from server |
| `service start` (subsequent) | Bring up existing `wg0`, sync peer config from server |
| Heartbeat response with updated peer config | Apply incremental peer config update via `wg set` |
| `service stop` | Bring `wg0` down (interface remains, peers removed) |
| `service uninstall` | Destroy `wg0` interface entirely |
| `silkie logout` | Stop tunnel, destroy interface, remove all local state |

The server's WireGuard interface address is the first IP in `WG_OVERLAY_CIDR`
(e.g. `10.100.0.1/16`). All devices peer to the server as hub.

---

## Backoff and resilience

### Heartbeat backoff

Heartbeats are sent every 30 seconds under normal conditions. On failure
(network error or server error response), the daemon backs off exponentially:

```
1s → 2s → 4s → 8s → 16s → 32s → 60s (cap)
```

Backoff resets to 30s on the next successful heartbeat.

### Server unreachable behaviour

When the server cannot be reached (DNS failure, TCP timeout, 5xx responses),
the daemon:

1. Keeps the WireGuard interface **up** with the last-known peer configuration.
2. Queues failed heartbeats in memory (up to 10 queued; older ones are
   discarded). On reconnect, sends the most recent heartbeat immediately.
3. Logs a warning per failure: `"server unreachable, retrying in Xs"`.
4. Does not tear down the overlay network — existing connections between devices
   remain functional as long as the WireGuard peers remain reachable directly.

### SSO polling backoff

During enrollment polling (`GET /v1/auth/pair/status` or
`GET /v1/auth/device/status`), the same exponential backoff applies if the
server is unreachable. The base interval is 5 seconds (as documented), and
backoff caps at 60 seconds.

---

## Logging

| Platform | Log file |
|---|---|
| macOS | `~/.silkie/silkie.log` |
| Linux | `~/.silkie/silkie.log` (also forwarded to journald if running under systemd) |

Log rotation: rotate at 10 MB, keep 3 files (`silkie.log`, `silkie.log.1`,
`silkie.log.2`). Implemented via the daemon's internal logger; no external
logrotate configuration required.

Log levels: `debug`, `info` (default), `warn`, `error`. Set `LOG_LEVEL` in the
environment or pass `--log-level` to the daemon.

### Service crash loop backoff

If the OS service crashes and is restarted by launchd or systemd, backoff is
handled by the service manager:

**macOS (launchd)** — set `ThrottleInterval` in the plist:
```xml
<key>ThrottleInterval</key>
<integer>10</integer>
```

**Linux (systemd)** — set restart limits in the unit:
```ini
[Service]
Restart=on-failure
RestartSec=10s
StartLimitIntervalSec=120s
StartLimitBurst=5
```

After 5 crashes in 120 seconds, systemd stops attempting to restart the
service. Run `systemctl reset-failed silkie` to clear the limit and retry.

---

## Security notes

- The WireGuard private key is generated locally and never transmitted.
- The device credential is an opaque token stored at rest in `~/.silkie/`.
  Treat it like a private key.
- Running `silkie logout` revokes the credential server-side and removes all
  local state.
- The daemon communicates with the server over HTTPS only. Self-signed certs
  are not accepted unless `--insecure` is passed explicitly (development only).
