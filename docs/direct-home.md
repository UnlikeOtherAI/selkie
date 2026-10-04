# Rafiki direct home connection

Rafiki embeds the `SelkieTunnelRuntime` Swift package in its iOS and tvOS app and
packet tunnel extension. There is no separate Apple TV Selkie app or second SSO
login. The app supplies a home-scoped grant from its existing UOA session. Apple
may request its one-time VPN permission.

The control API exchanges authenticated peer metadata over WebSockets. Media
bytes travel directly from the Apple device to the designated data machine via
WireGuard UDP; the public server never relays these bytes. The home peer exposes
one overlay TCP port, 8790, to the configured loopback service, 127.0.0.1:8790.
It has no LAN forwarding, default route, shell, file share, or internet gateway.
The Apple configuration contains only the exact home overlay /32. No other
machine or service port is available through this connection.

## Trusted Rafiki broker

On Selkie configure `SELKIE_RAFIKI_SERVICE_KEY` (a separate random service secret)
and `SELKIE_RAFIKI_HOME_DEVICE_ID` (the enrolled home UUID). Rafiki's server stores
the matching secret, HTTPS Selkie API base, and exact home UUID in its deployment
configuration. Never distribute the service secret to apps or the home daemon.

`POST /api/v1/internal/rafiki-session` uses `Authorization: Bearer <service-key>`
and JSON `{ "uoaSub": "<authenticated stable UOA subject>", "homeDeviceId":
"<configured UUID>", "authorizationExpiresAt": "<RFC3339 timestamp>" }`.
Selkie accepts only its configured active home and returns `{ "token": "...",
"expires_at": "..." }`. Rafiki must obtain the subject and current team admission
from its authenticated server session, never request-body identity. It bounds
expiry to the current UOA authorization window and five minutes. An admitted
team member can connect across home ownership; no Selkie invitation is needed.
Team removal denies renewal and installed leases expire on both endpoints.
UOA remains the identity and team authority; Selkie persists only its stable
subject reference and product-specific device/grant records.

A scoped mobile enrollment never creates a hub peer. Scoped tokens cannot list
or disconnect ordinary devices, replace an ordinary device's hostname/key, or
select another home. Both endpoints enforce installed authorization deadlines
locally even if the control WebSocket is blackholed. Control loss closes the
home service while the daemon reconnects with bounded backoff. Renewal of an
unchanged peer retains existing WireGuard handshakes and TCP streams.

## Apple integration

Pin the canonical Selkie repository to an exact reviewed commit in SwiftPM and
link `SelkieTunnelRuntime` to both app and extension. The extension subclasses
`SelkiePacketTunnelProvider`. Use the repository's
`App/ios/scripts/build-wireguard-go-bridge.sh` in the extension's build phase;
it resolves vendored sources relative to itself. The tested bridge toolchain is
Go 1.26.5. Enable the packet-tunnel-provider entitlement for both signed targets.
The key lives in the app's own Keychain; no shared identity/profile storage or
copied SSO cookie is necessary.

Create `SelkieVPNConnector` on the main actor. Call
`connect(token:apiBaseURL:hostname:platform:extensionBundleIdentifier:identityNamespace:)`
only when the authorized direct endpoint needs the home connection. Supply
`ios` or `tvos`, and the stable UOA subject as `identityNamespace`, so account
switches have separate device keys. `renewAuthorization(token:)` updates the
running extension without restarting playback. `isConnected` reads actual OS
connection state. After app restart,
`adoptExistingConnection(extensionBundleIdentifier:identityNamespace:)` adopts
only this account's active profile, enabling renewal without another start or
permission request. Renew while authorized and disconnect on logout.

The home media base is `http://<home overlay IPv4>:8790`; Rafiki advertises both
its LAN base and this configured overlay base with independently signed media
capabilities. Reachability must be proven by an actual capability request, not
by a VPN status flag. Browser HTTPS needs a trusted certificate and hostname
that resolves to the intended direct endpoint; never ignore TLS errors.

## One-time operator home enrollment

Build the Windows daemon from the reviewed revision:

```sh
GOOS=windows GOARCH=amd64 go build -o selkie-home-peer.exe ./cmd/home-peer
```

The deployed image includes an operator-only bootstrap helper. As a trusted
operator, select the existing owner's stable UOA reference and run it inside the
server container, where the deployed database and signing environment are
already present. The helper verifies an existing active reference, creates no
user/profile, and writes only a ten-minute token to a new file (no stdout):

```sh
docker exec selkie-server selkie-home-bootstrap \
  --uoa-reference '<existing stable UOA subject>' --output /tmp/home-enrollment.jwt
docker cp selkie-server:/tmp/home-enrollment.jwt /root/home-enrollment.jwt
chmod 600 /root/home-enrollment.jwt
docker exec selkie-server rm /tmp/home-enrollment.jwt
```

Transfer the token privately into the protected home directory, run first
enrollment within ten minutes, then remove both transfer copies. Never paste
credentials into logs, Git, chat, or command arguments. The UUID/overlay address
are nonsecret; the JSON state also contains private key/device credentials and
must not be printed wholesale.

On Windows, first create `C:\ProgramData\SelkieRafiki`, disable inherited ACLs,
and grant access only to SYSTEM and Administrators (plus a named operator only
while provisioning). Use elevated PowerShell:

```powershell
New-Item -ItemType Directory C:\ProgramData\SelkieRafiki -Force
icacls C:\ProgramData\SelkieRafiki /inheritance:r
icacls C:\ProgramData\SelkieRafiki /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
```

Place the daemon and transferred token there. Start it once with:

```powershell
C:\ProgramData\SelkieRafiki\selkie-home-peer.exe --state C:\ProgramData\SelkieRafiki\home.json --token-file C:\ProgramData\SelkieRafiki\home-enrollment.jwt --listen-port 51821 --service-port 8790 --target 127.0.0.1:8790
```

After enrollment stop it, remove the one-time token, and install the daemon as an
NSSM service running as SYSTEM with the same arguments **without `--token-file`**.
Configure restart on unexpected exit. Go file mode 0600 protects Unix files;
it does not replace Windows DACL protection. The protected state is the ongoing
device credential, not a human session. Revoke the device in Selkie to disable it.

The daemon discovers an IGD:2 router on its LAN and requests only its UDP51821
mapping, with a 1200-second lease refreshed every 600 seconds. It refuses to
replace another mapping and removes only its own matching mapping on shutdown.
Allow inbound UDP51821 for this executable in Windows Firewall; do not expose
media TCP8790 publicly. No router admin password or general network exposure is
needed. If the router cannot map UDP (or upstream CGNAT prevents reachability),
the daemon fails closed with a diagnostic. An operator can supply a verified
reachable literal IP/UDP endpoint with `--endpoint`; there is no relay fallback.

Read only `device_id` and `overlay_ip` from the protected state to configure the
broker's exact home UUID and Rafiki's overlay media base. Validate from outside
the home network with a real authorized media transfer before claiming remote
readiness. Local encrypted-UDP tests, signed builds, and a mapped port alone do
not establish remote playback.

## Validation

`go test -race ./...`, `go build ./...`, `go vet ./...`, and repository lint verify
source. `TestDirectEncryptedServiceAndRevocation` transfers bytes through real
WireGuard UDP, keeps the stream through renewal/another peer arrival, and proves
local expiry and revocation close it. Direct config tests reject default routes,
self/hub peers, duplicate allocations, and malformed endpoints. The home peer
rejects nonloopback targets and listens only on its designated overlay service.

Set `SELKIE_DIRECT_TEST_DATABASE_URL` to an isolated PostgreSQL database to run
`go test -race -run TestPostgresDirect -v ./internal/direct`. The test applies
migrations in a disposable schema and verifies persisted enrollment, scoped
API denials, grants, expiry, renewal and revocation. CI provides this database;
local runs without the variable explicitly skip this proof.
