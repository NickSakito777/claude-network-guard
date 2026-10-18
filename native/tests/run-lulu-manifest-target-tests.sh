#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/lulu-manifest-target.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM

/usr/bin/xcrun swiftc -parse-as-library \
    native/macos/controller/GuardLuLuContracts.swift \
    native/macos/controller/ProtectedFiles.swift \
    native/macos/lulu/LuLuManifest.swift \
    native/tests/LuLuManifestTargetAvailabilityTests.swift \
    -framework Security -framework CryptoKit -o "$BUILD/lulu-manifest-target-tests"
"$BUILD/lulu-manifest-target-tests"
