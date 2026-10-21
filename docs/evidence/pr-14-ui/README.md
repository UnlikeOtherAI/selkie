# Legacy browser restoration

Both captures request `/admin/devices` with the same valid reference-bound
legacy JWT, copied profile claims, authority fixture and 1280 x 900 viewport.
The actual Vite sources are base `b2e79c3e43bb60141311d7b4f79c572425833fe1`
and repaired `fea78e5`. Headless Chrome ran on Maxis.

Before: the browser removes its stored token and subsequent requests return to
sign-in. After: it exchanges the validated token, preserves its session id and
expiry, saves no copied profile claims, and displays the current UOA profile.
The capture asserts no page errors and the exact cleaned persisted token.

The fixture responses isolate browser restoration. The Go/PostgreSQL checks and
CI browser suite separately exercise the running server and migrations.
