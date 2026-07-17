#!/bin/sh
# Builds the WireGuard Go bridge static library (libwg-go.a) for the current Xcode
# platform and installs it into CONFIGURATION_BUILD_DIR, where the linker resolves the
# `-lwg-go` reference declared by the WireGuardKitGo SwiftPM target.
#
# SwiftPM cannot compile the Go bridge on its own (see the wireguard-apple README), so
# we drive its upstream Makefile from this build phase. We additionally teach the
# Makefile to target the iOS Simulator (GOOS=ios), which upstream does not map by
# default — without this, simulator builds would link a macOS-tagged object and fail.
set -e

if [ "${SKIP_WIREGUARD_GO_BRIDGE:-0}" = "1" ]; then
    echo "warning: skipping WireGuard Go bridge build (SKIP_WIREGUARD_GO_BRIDGE=1)"
    exit 0
fi

export PATH="$PATH:/opt/homebrew/bin:/usr/local/bin"

if ! command -v go >/dev/null 2>&1; then
    echo "error: the Go toolchain is required to build the WireGuard packet tunnel (brew install go)"
    exit 1
fi

# The WireGuard Go bridge sources are vendored locally (see Vendor/WireGuardKit).
GO_SRC="$SRCROOT/Vendor/WireGuardKit/Sources/WireGuardKitGo"
if [ ! -d "$GO_SRC" ]; then
    echo "error: could not locate vendored WireGuardKitGo sources at $GO_SRC"
    exit 1
fi

echo "Building WireGuard Go bridge for ${PLATFORM_NAME:-unknown} (${ARCHS:-unknown}) from ${GO_SRC}"
make -C "$GO_SRC" GOOS_iphonesimulator=ios
