#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
OBSERVER_DIR=${PORT_OBSERVER_SOURCE_ROOT:-"$ROOT/native/macos/observer"}
SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/port-observer-runtime.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM
mkdir -p "$BUILD/swift-modules" "$BUILD/clang-modules"

/usr/bin/xcrun clang -target arm64-apple-macosx13.0 -isysroot "$SDK" \
    -c "$OBSERVER_DIR/ObserverIdentity.c" -o "$BUILD/ObserverIdentity.o"
/usr/bin/xcrun swiftc -parse-as-library -target arm64-apple-macosx13.0 -sdk "$SDK" \
    -module-cache-path "$BUILD/swift-modules" \
    -Xcc -fmodules-cache-path="$BUILD/clang-modules" \
    "$OBSERVER_DIR/PortObserverCandidate.swift" \
    "$OBSERVER_DIR/PortObserverRuntime.swift" \
    "$SCRIPT_DIR/PortObserverRuntimeTests.swift" \
    "$BUILD/ObserverIdentity.o" -lproc -o "$BUILD/port-observer-runtime-fixtures"
"$BUILD/port-observer-runtime-fixtures"
