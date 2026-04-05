# Security

This document covers rate limiting, authentication hardening, credential
design, and XSS/CSRF mitigations for the Silkie control server.

---

## Rate limits

Implemented with a sliding-window counter in Redis. Keys are prefixed
`silkie:ratelimit:` and expire automatically.

| Endpoint | Limit | Window | Lockout |
|---|---|---|---|
| `POST /v1/auth/pair/start` | 10 requests | 1 minute | per source IP |
| `POST /v1/auth/pair/claim` | 5 failed attempts | per code | 1-hour lockout on the code |
| `POST /v1/auth/device/start` | 10 requests | 1 minute | per source IP |
| `POST /v1/devices/{id}/heartbeat` | 3 requests | 1 minute | per device ID |
| `POST /v1/sessions` (connect) | 30 requests | 1 minute | per user ID |
| `POST /v1/sessions/{id}/relay-credentials` | 10 requests | 1 minute | per session ID |
| `POST /v1/auth/mobile/token` | 10 requests | 1 minute | per source IP |
| `POST /v1/auth/mobile/enroll` | 5 requests | 1 minute | per source IP |

On limit breach, return `429 Too Many Requests` with:
```json
{"error":"rate_limit_exceeded","retry_after":60}
```

Include `Retry-After: <seconds>` response header.

---

## Device credential design

### Format

A device credential is **32 random bytes encoded as base64url** (43 characters,
no padding). Generated server-side using a cryptographically secure RNG
(`crypto/rand` in Go).

```
silkie_<base64url(32 random bytes)>
```

The `silkie_` prefix allows credentials to be identified and revoked if leaked
(e.g. detected by secret scanning tools on GitHub).

### Storage

The credential is **never stored in plaintext** on the server. On issuance:

1. Generate 32 random bytes.
2. Produce the credential string: `silkie_<base64url(bytes)>`.
3. Return the credential to the device once (enrollment response only).
4. Store `bcrypt(credential, cost=12)` in `device_credentials.credential_hash`.

On every API call: extract the credential from the `Authorization: Bearer`
header, bcrypt-verify against the stored hash, reject if no match.

### Credential binding

To prevent a stolen credential from being used from a different device, every
authenticated API request must include a request-level HMAC:

```
X-Silkie-Request-Sig: HMAC-SHA256(credential || request_body_sha256 || unix_timestamp_minute)
```

The server recomputes the HMAC using the stored credential plaintext (held
only in the device's memory during the session) and rejects requests where the
signature does not match. This means a stolen credential token is useless
without the device's in-process credential value.

Implementation note: the `unix_timestamp_minute` component is the current Unix
timestamp truncated to the minute (`time.Now().Unix() / 60`). The server
accepts the current minute and the previous minute to tolerate clock skew.

---

## Pairing code anti-bruteforce

A 6-character alphanumeric (uppercase) code has `36^6 = 2,176,782,336`
combinations (~2.2 billion). This is sufficient to prevent online bruteforce
at realistic request rates, but rate limiting provides an additional layer.

Additional defenses:

- **5 failed claim attempts on a single code** → code is locked for 1 hour
  (Redis key: `silkie:pairlock:{code}`, TTL 3600s). The code is not deleted —
  it still expires naturally — but claim attempts return `423 Locked`.
- **Code deleted immediately on first successful claim.** The Redis key is
  deleted and `pair_codes.status` is set to `claimed` atomically.
- **Timing-safe comparison** for code lookup: use `hmac.Equal` or equivalent
  constant-time comparison when checking the code against stored values, to
  prevent timing oracle attacks.
- Codes are stored in Redis as uppercase; the server normalises input to
  uppercase before comparison to prevent case-sensitivity bypass.

---

## CSRF strategy

The admin UI is a single-page application that stores session tokens in
`localStorage` and sends them as `Authorization: Bearer <token>` headers.

**There is no cookie-based session on the admin UI.** This means the standard
CSRF attack vector (malicious site triggering a cross-origin request that
includes credentials automatically) does not apply: browsers do not
automatically attach `Authorization` headers to cross-origin requests.

No CSRF token is required. The security model relies on:

1. `Authorization` header (not a cookie) for all state-mutating requests.
2. CORS policy on the server (see below) to prevent unauthorized cross-origin
   reads.

### CORS policy

```
Access-Control-Allow-Origin: https://<UOA_DOMAIN>
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Max-Age: 600
```

The admin UI origin is the server's own domain. Do not allow `*` — wildcard
CORS defeats the authorization header isolation benefit.

---

## XSS mitigations

Because the admin UI uses no server-side rendering, XSS is the primary
injection risk. The following mitigations are required:

### Content Security Policy

Serve the following `Content-Security-Policy` header with every HTML response:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.tailwindcss.com https://fonts.googleapis.com;
  style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com https://fonts.gstatic.com;
  font-src https://fonts.gstatic.com;
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
```

Adjust `script-src` if CDN URLs change. `'unsafe-inline'` is limited to
`style-src` because Tailwind CDN injects inline styles; scripts must never be
inline.

### Subresource Integrity (SRI)

For any CDN asset referenced in HTML templates, include `integrity` and
`crossorigin` attributes:

```html
<script
  src="https://cdn.tailwindcss.com/3.4.1"
  integrity="sha384-<hash>"
  crossorigin="anonymous"
></script>
```

Compute the hash with:
```sh
curl -s https://cdn.tailwindcss.com/3.4.1 | openssl dgst -sha384 -binary | base64
```

Pin the hash in the template. Update when the CDN version changes.

### DOM construction

All JavaScript in the admin UI must construct DOM elements using
`document.createElement` and `element.textContent`. **Never use `innerHTML`
or `insertAdjacentHTML` with user-controlled strings.** This applies to all
row renderers, confirmation dialogs, and dynamic content.

This is enforced by a pre-commit hook that rejects any `.html` or `.js` file
containing `innerHTML` or `insertAdjacentHTML` where the argument is not a
static string literal.

---

## Audit events for danger-zone operations

The following operations must always emit an `audit_events` row, regardless of
outcome:

| Operation | `event_type` | Notes |
|---|---|---|
| Successful SSO login | `user.login` | Include session token ID |
| Failed token validation | `user.login_failed` | Include reason code |
| Device enrollment | `device.enrolled` | Include WG public key fingerprint |
| Device revocation | `device.revoked` | Include actor and reason |
| Device credential revocation | `device.credential_revoked` | |
| WG key rotation | `device.key_rotated` | Include old + new key fingerprints |
| Policy deny on connect | `session.policy_denied` | Include deny reason |
| Relay credential issued | `relay.credential_issued` | Include expiry |
| Pair code claimed | `pair_code.claimed` | Include admin user who claimed |
| Super user action (any) | (existing type + `is_super_action: true` in detail) | |

Audit events are written synchronously within the same database transaction as
the state change, so they cannot be lost if the server restarts mid-operation.

---

## Internal session tokens

Internal session tokens (issued to users after SSO login, distinct from device
credentials) are HS256-signed JWTs using `INTERNAL_SESSION_SECRET`.

Claims:

```json
{
  "sub": "<user.id (UUID)>",
  "iss": "silkie",
  "aud": "<UOA_DOMAIN>",
  "iat": 1700000000,
  "exp": 1700086400,   // 24 hours
  "jti": "<random UUID>",
  "is_super": true
}
```

- Tokens are not stored on the server — stateless validation via HMAC.
- `jti` is checked against a Redis blocklist to support explicit logout
  (`POST /v1/sessions/disconnect` adds `jti` to `silkie:revoked_jtis:{jti}`,
  TTL = token remaining lifetime).
- Token lifetime: 24 hours. No refresh token for the admin UI — users re-login
  via UOA SSO when the token expires.

---

## WireGuard key security

- The server's WireGuard private key is generated once and stored in the
  `wg_keys` Docker volume (outside the container image layer).
- Device WireGuard private keys are generated on-device and never transmitted.
  The server stores only the public key (`device_keys.public_key`).
- On key rotation: the old public key is retained in `device_keys` with
  `is_current = FALSE` for audit purposes. The WireGuard peer table is updated
  atomically: new key added, old key removed.

---

## Secrets checklist

Before going to production, verify:

- [ ] `INTERNAL_SESSION_SECRET` is at least 512 bits (64 random bytes, base64-encoded)
- [ ] `COTURN_SECRET` is at least 256 bits
- [ ] `UOA_SHARED_SECRET` matches the value in the UOA dashboard
- [ ] `POSTGRES_PASSWORD` and `REDIS_PASSWORD` are unique, not reused
- [ ] `.env` is in `.gitignore` and has never been committed
- [ ] Caddy TLS certificate is valid and auto-renewing
- [ ] `server` container is not exposed directly to the internet (only via Caddy)
- [ ] coturn is configured with `no-tcp-relay` and `realm` set to your domain
- [ ] CSP header is active on all HTML responses
- [ ] SRI hashes are pinned for all CDN assets
