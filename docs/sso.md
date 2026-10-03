# UOA sign-in

UnlikeOtherAI is Selkie's sole human identity authority. Selkie uses UOA's
custom authorization-code contract with a signed integration configuration.
The deployed SSO inspection on 2026-10-03 predates the new independent-session
migration; deployment verification must establish the new exact revision.

## Configuration and approval

`/auth/uoa-config` serves an RS256-signed JWT with `kid`. Its public key is
published at `/.well-known/jwks.json` on the configured domain. Configure
`UOA_CONFIG_SIGNING_KEY`, `UOA_CONFIG_SIGNING_KID`, `UOA_OWNER_SUB`,
`UOA_CONFIG_URL`, `UOA_SHARED_SECRET`, `UOA_BASE_URL`, `UOA_REDIRECT_URL` and
`UOA_MOBILE_REDIRECT_URL`. New integrations need approval in UOA admin.
The per-domain shared secret authenticates confidential API calls as
`sha256(domain + client_secret)`; it is not UOA's access-token signing secret.
The verified domain is the hostname of `UOA_CONFIG_URL`.

## Browser and mobile sign-in

`/auth/login` starts PKCE S256. The HttpOnly, SameSite=Lax verifier cookie binds
the callback to the initiating browser. A callback clears that cookie even if
the exchange fails. Confidential `/auth/token?config_url=...` receives
`{code,redirect_url,code_verifier}` and returns access/refresh tokens and their
lifetimes. The authenticated server channel establishes trust; Selkie decodes
the returned access token and checks its subject and expiry. It does not attempt
to verify UOA's private HS256 deployment key.

Selkie reads the exact subject through `/domain/users?domain=...&user_id=...`.
Email, name and avatar stay in memory. The stable subject maps to the existing
product UUID used by device ownership and audit foreign keys. Each sign-in
stores its own encrypted scoped refresh capability and issues a profile-free
local JWT containing a server-side session reference. Protected requests inspect
that session and current UOA authority; rotating refresh credentials are
serialized through database row locks and saved before profile lookups.

The browser callback returns its local handle in the URL fragment, which the
SPA removes immediately. The mobile callback instead returns a short-lived,
single-use handoff code. Its atomic exchange yields a mobile-audience handle
bound to the same server-side session. Expired or consumed handoffs fail closed.
Local handles without the new session reference require sign-in again.

## Debug logins, logout and the internal broker

See [debug-login-sessions.md](debug-login-sessions.md) for the bottom-right debug
button, 30-minute one-time codes, independent refresh families, confirmed family
logout, and bounded `session:broker` capability contract. The broker rejects
caller profile fields and validates live UOA authority before issuing a mobile
handle. Operator delegation must explicitly approve the exact Selkie API origin.

## Product authorization

The current MVP is a person reaching their own devices. Device routes retain
stable owner UUID filters. Selkie's `is_super` and operational `status` are
product administration extensions. Human membership and current organization/
team references come from UOA; Selkie stores no copied human directory or org
hierarchy. Historical personal devices receive no fabricated team assignment.

## Transport and outages

Confidential API calls have a ten-second timeout, reject redirects, and bound
responses to 64 KiB. Error messages never include upstream bodies or tokens.
Debug relays and broker calls use per-IP rate limits before expensive work.
A temporary authority/profile outage returns a retryable failure; it cannot
turn an unconfirmed logout into a cleared local session.

## Verification

`SELKIE_TEST_DATABASE_URL` enables the isolated PostgreSQL session tests in
`internal/auth/uoa_sessions_integration_test.go`. They verify independent
families, replay refusal, saved rotation before profile failures and retained
logout retry state. The headless `e2e` suite verifies actual local server login,
profile-free handles, device pages, and rendered debug controls using explicit
HTTP fixtures for the debug UI. Live provider and physical-device proof remain
separate deployment acceptance steps.
