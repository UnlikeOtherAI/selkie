# Silkie CLI

The Silkie CLI is a Node.js daemon published on npm. It runs as an OS service
on each enrolled device, maintains the local WireGuard interface, reports the
device's service manifest to the control server, and listens for real-time
session events over SSE.

## Install

```sh
npm install -g silkie
```

Requires Node.js 20+. The package ships native WireGuard support for macOS
and Linux.

## Run as a service

After enrollment, install the system service so the daemon starts on boot:

```sh
silkie service install
silkie service start
silkie service status
silkie service stop
silkie service uninstall
```

### Privilege model

WireGuard interface management is privileged. The daemon does not get broad
root access beyond that requirement.

- macOS: there is no Linux capability model, so Silkie uses a privileged
  root-owned helper. The preferred install is a launchd `LaunchDaemon`
  running as root; a tightly scoped setuid helper is the fallback. That
  helper may only create, configure, and destroy the Silkie WireGuard
  interface and associated routes.
- Linux: `silkie service install` writes a systemd unit that runs as root with
  an explicit capability boundary instead of unrestricted root behavior.

Reference Linux unit shape:

```ini
[Unit]
Description=Silkie daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/silkie daemon
Restart=always
RestartSec=1
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
```

### WireGuard interface lifecycle

The WireGuard interface lifecycle is owned by the daemon and helper:

1. On service start, create the interface if it does not already exist.
2. Apply the last-known Silkie config immediately so the overlay comes up
   before the first successful heartbeat.
3. Keep the interface up while the service is running, even if the server is
   temporarily unreachable.
4. On `silkie service stop`, remove the interface cleanly.
5. On `silkie service uninstall`, stop the service, destroy the interface,
   remove the helper or unit, and delete local state if the user also runs
   `silkie logout`.

The interface is not left behind on stop or uninstall.

### Service crash loop backoff

If the daemon exits unexpectedly, the installed service wrapper restarts it
with exponential backoff:

```text
1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, ...
```

The crash-loop counter resets after 10 minutes of stable runtime.

## Enrollment

Two authentication paths are available. Both result in the CLI holding a
device credential on disk (`~/.silkie/credential`) and the server registering
the device's WireGuard public key.

The CLI generates the WireGuard keypair locally on first run. The private key
never leaves the device.

### Option 1 — Pairing code

Use this when enrolling a headless server or any machine where opening a
browser is inconvenient.

```sh
silkie enroll
```

The CLI:

1. Generates a local WireGuard keypair if one does not exist.
2. Requests a pairing code from the server (`POST /v1/auth/pair/start`).
3. Prints a 6-character code such as `A3X9KF`.
4. Polls `GET /v1/auth/pair/status` until the code is claimed or expires.

Polling behavior:

- success resets the loop immediately
- transient network failures back off with `1s, 2s, 4s, 8s, 16s, 32s, 60s`
- the retry interval stays capped at 60 seconds until the server responds

Codes expire after 10 minutes and are single-use.

### Option 2 — SSO

Use this when you are sitting at the machine being enrolled.

```sh
silkie enroll --sso
```

The CLI:

1. Generates a local WireGuard keypair if one does not exist.
2. Requests a device authorization code from the server.
3. Opens the SSO login URL in the default browser.
4. Polls `GET /v1/auth/device/status` until the browser flow completes.

The same exponential retry schedule applies to this polling loop when the
server is unreachable: `1s, 2s, 4s, 8s, 16s, 32s, 60s`, capped at 60 seconds.

## Commands

| Command | Description |
|---|---|
| `silkie enroll` | Enroll this device using a pairing code |
| `silkie enroll --sso` | Enroll this device via SSO browser login |
| `silkie status` | Show device status, overlay IP, and active connections |
| `silkie service install` | Install the system service |
| `silkie service start` | Start the service |
| `silkie service stop` | Stop the service and destroy the WireGuard interface |
| `silkie service status` | Show service health |
| `silkie service uninstall` | Remove the system service and helper |
| `silkie logout` | Revoke the credential and remove device registration |
| `silkie logs` | Stream daemon logs |

## Configuration

Config lives at `~/.silkie/config.json`. Most values are written during
enrollment and should not be edited manually.

| Key | Description |
|---|---|
| `server_url` | Control server base URL |
| `device_id` | Assigned device ID |
| `credential` | Long-lived device credential token |
| `wg_public_key` | WireGuard public key |
| `overlay_ip` | Assigned overlay IP |

The WireGuard private key is stored separately at `~/.silkie/wg.key` with
mode `0600`.

## Runtime behavior

Once running, the daemon:

1. Brings up WireGuard from the last-known config on startup.
2. Heartbeats to `POST /v1/devices/{id}/heartbeat` every 30 seconds in steady
   state.
3. Reports services by scanning local listening ports and uploading the
   service manifest.
4. Subscribes to SSE on `GET /v1/devices/{id}/events` for session events, key
   rotation requests, and config refresh notifications.
5. Handles sessions by participating in ICE candidate exchange, preferring a
   direct path and falling back to TURN relay when necessary.
6. Rotates keys when instructed by the server.

### Heartbeat and poll backoff

Normal heartbeat cadence is 30 seconds. Only failed requests use backoff.

Retry sequence for failed heartbeats and other control-plane polling:

```text
1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, ...
```

Any successful response resets the retry delay back to the normal cadence.

### When the server is unreachable

The daemon does not tear down the overlay just because the control plane is
offline.

Behavior:

- keep the WireGuard interface up using the last-known config
- continue serving existing overlay traffic
- queue heartbeat intents locally and coalesce them to the latest state
- log warnings on every failed control-plane attempt
- resume normal heartbeats and config sync once the server becomes reachable

This avoids unnecessary tunnel churn during brief outages.

## Logging

On macOS and Linux, the daemon writes its log file to:

```text
~/.silkie/silkie.log
```

Rotation policy:

- rotate at 10 MB
- keep 3 archived files
- continue writing to the active file without truncating on restart

`silkie logs` tails this file and also surfaces recent service-manager status
when available.

## Device fingerprint

At enrollment, and refreshed on every heartbeat, the CLI collects the
following information and sends it to the control server. All fields are read
from the OS.

| Field | Source |
|---|---|
| `hostname` | `os.hostname()` |
| `os_platform` | `os.platform()` |
| `os_version` | `os.version()` + `os.release()` |
| `os_arch` | `os.arch()` |
| `kernel_version` | `os.version()` raw value |
| `cpu_model` | `os.cpus()[0].model` |
| `cpu_cores` | `os.cpus().length` |
| `cpu_speed_mhz` | `os.cpus()[0].speed` |
| `total_memory_bytes` | `os.totalmem()` |
| `disk_total_bytes` | `fs.statfs('/')` |
| `disk_free_bytes` | `fs.statfs('/')` |
| `network_interfaces` | `os.networkInterfaces()` |
| `agent_version` | package `version` from `package.json` |

What is and is not collected:

- CPU and memory figures are point-in-time snapshots.
- `disk_free_bytes` and `network_interfaces` are refreshed on every heartbeat.
- No process list, file contents, browser history, or user activity is sent.
- `silkie enroll --dry-run` prints the exact enrollment payload before any
  network call is made.

## Security notes

- The WireGuard private key is generated locally and never transmitted.
- The device credential is an opaque token stored at rest in `~/.silkie/`.
  Treat it like a private key.
- Running `silkie logout` revokes the credential server-side and removes all
  local state.
- The daemon communicates with the server over HTTPS only. Self-signed certs
  are not accepted unless `--insecure` is passed explicitly for development.
