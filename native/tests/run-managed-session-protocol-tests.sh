#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/managed-session-protocol.XXXXXX")
CACHE="$ROOT/.tools/target/swift-module-cache"
mkdir -p "$CACHE"
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM
python3 "$ROOT/native/tests/check-managed-session-source-snapshot.py"
/usr/bin/xcrun swiftc -module-cache-path "$CACHE" -D MANAGED_SESSION_FIXTURE_TESTS \
    -parse-as-library -framework Security \
    "$ROOT/native/macos/handover/ManagedSessionProtocol.swift" \
    "$ROOT/native/macos/handover/ManagedSessionSourceSnapshot.swift" \
    "$ROOT/native/tests/ManagedSessionProtocolTests.swift" \
    -o "$BUILD/managed-session-protocol-tests"
"$BUILD/managed-session-protocol-tests"
