#!/bin/zsh
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v swiftlint >/dev/null 2>&1; then
  echo "error: swiftlint is required to build the iOS app" >&2
  exit 1
fi

swiftlint lint --strict --config .swiftlint.yml --force-exclude
