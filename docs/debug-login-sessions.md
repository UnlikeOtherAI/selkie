# Independent debug logins

The bottom-right debug button on admin creates JSON with exactly `url` and
`token`. The token works once for 30 minutes. Renew replaces the previous code.
The login button accepts either JSON or the bare code and creates a separate
UOA refresh family. Normal logout revokes only that family and its unused codes.

## Identity and migration

UOA owns human profiles and authentication. Selkie keeps a stable UOA subject
and its existing product user UUID, device ownership, permissions, local
operational status and administrator extension. Migration 004 drops the former
email and display-name columns without changing device or audit references.
Devices in the current MVP belong to people; migration does not invent a team
assignment for historical personal devices. Current organization and team
references come from the authenticated UOA capability.

Each browser/mobile session has a separate sealed UOA refresh capability and
opaque session reference. Existing bearer transport remains available to the
mobile app. Old bearer tokens without a server-side session reference require
sign-in again. Mobile handoff codes remain single-use and carry the new session
reference rather than a copied profile. Confidential upstream requests reject
redirects, bound response sizes and never disclose upstream bodies in errors.

Session rotation is serialized through database locking and a bounded local
flight gate. Up to 1,024 memory-only authority/profile entries expire within two
minutes or the access-token expiry, whichever comes first. Every hit checks the
durable lifecycle, user status and sealed-capability fingerprint; another
instance rotating the capability invalidates the entry. Broker authority
validation remains uncached on every request. Rotated refresh tokens
are saved before profile reads, so a profile outage cannot discard a successor
capability. Logout retains a retryable session state until UOA confirms family
revocation. The internal broker accepts `{uoaSub, capability}` after its service-key check.
The capability is a UOA-issued `session:broker` delegation for the exact Selkie
API origin. Confidential `/auth/session-broker/validate` checks current epoch,
membership and delegation policy on every request. Selkie seals the capability,
fetches the profile separately and caps the mobile handle at its five-minute
expiry. Clients rebroker when it expires. The response stays `{token,expires_at}`.
Supplied email or name fields are rejected. Broker logout deletes its local
handle; these short-lived delegations have no refresh family. Source family
logout does not revoke an already issued broker capability; its expiry and
UOA epoch, membership and delegation policy still apply.

Explicit development login is available only on an unbound local install with
`DEV_MODE` and its confirmation flag. It uses a server-side development session,
never a UOA identity fallback. A configured UOA install disables that endpoint.
