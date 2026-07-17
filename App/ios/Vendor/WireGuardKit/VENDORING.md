# Vendored WireGuardKit

This is a local, in-repo copy of the official WireGuard Apple package
(<https://github.com/WireGuard/wireguard-apple>), pinned to upstream commit
`ccc7472fd7d1c7c19584e6a30c45a56b8ba57790` (2023-02-14) — the last commit before
"App: bump minimum OS versions" (`901fe1c`).

## Why vendored instead of a remote SwiftPM dependency

Three independent incompatibilities make the upstream package unconsumable as a plain
remote SwiftPM dependency under the current toolchain (Xcode 26 / Go 1.26):

1. **Broken manifest on `master`.** Current `master` declares
   `// swift-tools-version:5.3` yet uses `.iOS(.v15)` / `.macOS(.v12)`, platform cases
   that require tools-version 5.5+. Strict SwiftPM (Xcode 16+/26) rejects this with
   `'v15' is unavailable`. This pinned revision predates that bump and uses
   `.iOS(.v12)` / `.macOS(.v10_14)`, which are valid — but see (3).
2. **Old tags don't build with Go 1.26.** The last valid-manifest release tag
   (`1.0.15-26`) carries 2021-era `golang.org/x/net`, which fails to link with modern
   Go (`invalid reference to syscall.recvmsg`). This revision carries the 2023
   wireguard-go sources, which build cleanly with Go 1.26.
3. **C header incompatible with Xcode 26 explicit modules.** `WireGuardKitC.h` uses
   `u_int32_t` / `u_char` / `u_int16_t` without including `<sys/types.h>`; strict Clang
   modules now require the direct include.

Vendoring lets us keep the official 2023 source verbatim while applying the two minimal
fixes needed to build today.

## Changes from upstream

- `Package.swift`: `swift-tools-version` raised to 5.9 and platforms set to
  `.iOS(.v15)` / `.macOS(.v11)` (a consistent, valid manifest). Target structure is
  otherwise identical to upstream.
- `Sources/WireGuardKitC/WireGuardKitC.h`: added `#include <sys/types.h>`.

Everything else (the Swift `WireGuardKit` sources, the C key/x25519 code, and the
`WireGuardKitGo` bridge incl. its Makefile) is unmodified upstream code.

## Go bridge

SwiftPM cannot compile the Go bridge. It is built by
`App/ios/scripts/build-wireguard-go-bridge.sh`, invoked as a pre-build phase on the
`SelkieTunnelExtension` target, which runs the upstream `Makefile` to produce
`libwg-go.a`. The script also maps `GOOS=ios` for the iOS Simulator (upstream maps only
device and macOS), so the extension compiles for the simulator too. A Go toolchain
(`brew install go`) is required to build.
