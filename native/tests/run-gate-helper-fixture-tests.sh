#!/bin/sh
set -eu
GATE_HELPER_ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
GATE_HELPER_BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/guard-gate-helper-fixture.XXXXXX")
trap 'rm -rf "$GATE_HELPER_BUILD_DIR"' EXIT HUP INT TERM
mkdir -p "$GATE_HELPER_BUILD_DIR/production-modules" "$GATE_HELPER_BUILD_DIR/fixture-modules"

/usr/bin/xcrun clang -std=c11 -target arm64-apple-macosx13.0 \
    -mmacosx-version-min=13.0 -Wall -Wextra -Werror -pthread \
    -I "$GATE_HELPER_ROOT/native/macos/handover" \
    -c "$GATE_HELPER_ROOT/native/macos/handover/NativeGate.c" \
    -o "$GATE_HELPER_BUILD_DIR/NativeGate-production.o"
/usr/bin/xcrun swiftc -parse-as-library -emit-executable -target arm64-apple-macosx13.0 \
    -sdk /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
    -module-cache-path "$GATE_HELPER_BUILD_DIR/production-modules" \
    "$GATE_HELPER_ROOT/native/macos/handover/GateHelperIPC.swift" \
    "$GATE_HELPER_ROOT/native/macos/handover/GateHelperProduction.swift" \
    "$GATE_HELPER_ROOT/native/macos/handover/GateHelperMain.swift" \
    "$GATE_HELPER_BUILD_DIR/NativeGate-production.o" \
    -o "$GATE_HELPER_BUILD_DIR/guard-gate-helper-production"
if /usr/bin/nm -g "$GATE_HELPER_BUILD_DIR/guard-gate-helper-production" | rg -q 'ng_test_'; then
    echo "production helper unexpectedly contains NativeGate test symbols" >&2
    exit 1
fi

/usr/bin/xcrun clang -std=c11 -mmacosx-version-min=13.0 -DNG_OFFLINE_TEST \
    -Wall -Wextra -Werror -pthread -I "$GATE_HELPER_ROOT/native/macos/handover" \
    -c "$GATE_HELPER_ROOT/native/macos/handover/NativeGate.c" -o "$GATE_HELPER_BUILD_DIR/NativeGate.o"
/usr/bin/xcrun swiftc -parse-as-library -target arm64-apple-macosx13.0 \
    -sdk /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
    -module-cache-path "$GATE_HELPER_BUILD_DIR/fixture-modules" -D GUARD_GATE_FIXTURE_TESTS \
    "$GATE_HELPER_ROOT/native/macos/handover/GateHelperIPC.swift" \
    "$GATE_HELPER_ROOT/native/macos/handover/GateHelperProduction.swift" \
    "$GATE_HELPER_ROOT/native/macos/handover/GateHelperMain.swift" \
    "$GATE_HELPER_ROOT/native/tests/GateHelperLifecycleFixture.swift" \
    "$GATE_HELPER_ROOT/native/tests/GateHelperProductionFixture.swift" \
    "$GATE_HELPER_BUILD_DIR/NativeGate.o" -o "$GATE_HELPER_BUILD_DIR/gate-helper-fixture"
"$GATE_HELPER_BUILD_DIR/gate-helper-fixture" --fixture
