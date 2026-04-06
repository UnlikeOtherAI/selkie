# Security

This document records the concrete security controls for the Selkie MVP. It
focuses on endpoint abuse resistance, bearer credential handling, admin UI
browser security, and audit coverage.

## Authentication surfaces

Selkie has three distinct credential types:

| Credential | Holder | Format | Storage |
|---|---|---|---|
| UOA access token | browser / mobile app | HS256 JWT from UOA | browser memory or mobile secure storage |
| internal session token | browser / mobile app | HS256 JWT from Selkie | `localStorage` in the SPA, Keychain/Keystore on mobile |
| device credential | CLI daemon | random 32 bytes, base64url-encoded | `~/.selkie/credential` on disk, bcrypt hash in Postgres |

The browser never gets raw device credentials. The CLI never gets a user
session token.

## Rate limits

All limits are enforced at the server, backed by Redis counters, and keyed by
the smallest identity that reduces collateral damage.

| Endpoint | Limit | Key |
|---|---|---|
| `POST /v1/auth/pair/start` | 10 per minute | source IP |
| `POST /v1/auth/pair/claim` | 5 failed attempts, then 1 hour lockout | source IP + normalized code |
| `POST /v1/devices/{id}/heartbeat` | 3 per minute | device ID |
| `POST /v1/connect` | 30 per minute | user ID |
| `POST /v1/sessions/{id}/relay-credentials` | 10 per minute | session ID |

Additional enrollment protection:

- Pair-code claim attempts are also counted per code.
- After 5 failed claims against the same code, that code is locked for
  15 minutes even if the attacking IP changes.

## Device credential format and verification

Device credentials are generated only by the server after successful
enrollment.

Format:

- 32 bytes from a cryptographically secure RNG
- base64url-encoded without padding before delivery to the CLI
- stored server-side only as a bcrypt hash

Server-side handling:

1. Generate 32 random bytes.
2. Base64url-encode the bytes for transport.
3. Hash with bcrypt before persistence.
4. Store the bcrypt hash in `devices.credential_hash`.
5. Never log or re-display the raw credential.

The bcrypt hash is used only for verification. The original credential is not
recoverable from the database.

## Device credential binding

A stolen bearer token must not be enough to impersonate a device. Every
device-authenticated API call binds the credential to the device's WireGuard
identity.

Required request headers:

| Header | Value |
|---|---|
| `Authorization` | `Bearer <device credential>` |
| `X-Selkie-Device-Key` | device WireGuard public key |
| `X-Selkie-Timestamp` | UNIX timestamp |
| `X-Selkie-Nonce` | single-use random nonce |
| `X-Selkie-Binding` | `base64url(HMAC-SHA256(credential, wg_public_key || method || path || timestamp || nonce || body_sha256))` |

Verification rules:

1. Look up the device by `X-Selkie-Device-Key`.
2. Verify the bearer credential against the stored bcrypt hash.
3. Recompute `X-Selkie-Binding` server-side and compare with
   `crypto/subtle.ConstantTimeCompare`.
4. Reject timestamps outside a 30-second skew window.
5. Reject nonce reuse using a short-lived Redis key.
6. For post-enrollment device endpoints, require the request to originate from
   the device's authenticated WireGuard overlay identity.

The HMAC binds the credential to the registered public key and to the concrete
HTTP request. The overlay-identity check means an attacker who steals only the
credential still cannot use it without the corresponding WireGuard private key.

## Pairing code hardening

Pairing codes are six uppercase alphanumeric characters.

- Search space: `36^6 = 2,176,782,336` combinations, about 2.2 billion.
- Codes expire after 10 minutes.
- Codes are deleted immediately on first successful claim.
- After 5 failed claim attempts for the same code, that code is locked for
  15 minutes.
- After 5 failed claim attempts from the same IP, the IP is locked out of
  `pair/claim` for 1 hour.

Storage and lookup:

- The server stores only an HMAC digest of the normalized code, not the
  plaintext code.
- Lookup compares digests and uses a timing-safe comparison before accepting a
  match.
- Claim and status polling always operate on the stored code record; there is
  no unaudited in-memory-only success path.

## Device code hardening

SSO device enrollment uses a random 32-byte `device_code`, not a short human
code.

Rules:

- `device_code` expires after 15 minutes.
- The browser callback consumes it exactly once.
- Polling the device-code status endpoint follows the CLI backoff policy and
  never reveals whether a code belongs to a valid user.

## CSRF and browser security

The admin UI is an SPA-style application:

- it sends Bearer tokens in the `Authorization` header
- tokens live in `localStorage`
- no session cookies are used

Because there are no ambient cookies, classical CSRF is not the primary
browser risk. The main browser risk is XSS.

Required XSS mitigations:

1. Use Subresource Integrity on any CDN-hosted JS or CSS assets.
2. Set a strict Content Security Policy from Caddy.
3. Avoid inline scripts in production builds; if a small inline bootstrap is
   unavoidable, pin it with a CSP hash.
4. Escape all server-rendered HTML and never trust service names, hostnames, or
   tags from devices.
5. Treat `localStorage` as sensitive because XSS can read it instantly.

Recommended CSP baseline:

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' https://fonts.googleapis.com;
  font-src 'self' https://fonts.gstatic.com;
  img-src 'self' data:;
  connect-src 'self';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none'
```

## Transport security

- All control-plane traffic is HTTPS only.
- Caddy terminates TLS; the Go server is private behind it.
- HSTS is enabled in production.
- Self-signed certificates are rejected by default. Development-only bypasses
  must be explicit and CLI-scoped.

## Relay credential security

TURN relay credentials are ephemeral HMAC-SHA1 tokens issued via coturn's
`use-auth-secret` mechanism. Security properties and limitations:

| Property | Status |
|---|---|
| Credential lifetime | 1 hour (configurable) |
| Credential scope | bound to one connect session |
| Revocation via credential deletion | blocks new connections only |
| Revocation of live allocation | requires coturn telnet CLI `cs` command |

**Critical gotcha:** credential TTL expiry does not terminate an established
TURN allocation. Coturn documents that in long-term credential mode, the
original password becomes a per-session parameter and persists until
disconnection. This means:

- Deleting a credential from Redis/PostgreSQL userdb prevents *new*
  authentication but does not affect a session that already authenticated.
- Revoking a user or session in the control plane must also call the coturn
  telnet CLI (`ps <username>` then `cs <session-id>`) to force-terminate the
  relay allocation.
- The control plane implements this via `internal/nat/cli.go`.

## Audit coverage

Every danger-zone operation must emit an audit event with actor, target,
decision, request IP, and correlation ID.

Danger-zone operations include:

- terminate all sessions
- revoke a device
- restore a revoked device
- rotate a device key
- issue relay credentials
- change policy
- change super-user state
- rotate secrets
- force disconnect a session
- force-terminate a relay allocation via coturn CLI

Audit events for these operations are written to `audit_events` even if the
operation fails or is denied.

## Logging rules

- Never log raw bearer credentials, pairing codes, device codes, refresh
  tokens, or HMAC inputs.
- Error logs may include credential IDs, session IDs, and truncated public keys.
- Security denials should log the rate-limit bucket key, not the secret input.

## Replay resistance

Replay protection applies to device-authenticated requests:

- timestamp window: 30 seconds
- nonce uniqueness: enforced in Redis for the full timestamp window
- body integrity: `body_sha256` is part of the binding MAC

If a request is replayed inside the timestamp window but with the same nonce,
it is rejected.
