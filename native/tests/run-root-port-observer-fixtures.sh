#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/root-port-observer.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM

/usr/bin/xcrun clang -fsyntax-only \
    -target arm64-apple-macosx13.0 \
    -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
    native/macos/observer/ObserverIdentity.c

/usr/bin/xcrun swiftc -parse-as-library \
    -module-cache-path "$BUILD/swift-modules" \
    -Xcc -fmodules-cache-path="$BUILD/clang-modules" \
    native/macos/checks/RootPortObserver.swift \
    native/macos/observer/PortObserverCandidate.swift \
    native/tests/RootPortObserverFixtureTests.swift \
    -o "$BUILD/root-port-observer-fixtures"
"$BUILD/root-port-observer-fixtures"

/usr/bin/xcrun swiftc -typecheck -parse-as-library \
    -target arm64-apple-macosx13.0 \
    -sdk /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
    -module-cache-path "$BUILD/swift-typecheck-modules" \
    -Xcc -fmodules-cache-path="$BUILD/clang-typecheck-modules" \
    native/macos/native/NativeClock.swift \
    native/macos/controller/GuardLuLuContracts.swift \
    native/macos/checks/NetworkEventPolicy.swift \
    native/macos/checks/WiFiAssociationEventMonitor.swift \
    native/macos/checks/EnvironmentChecker.swift \
    native/macos/checks/RootPortObserver.swift \
    native/macos/observer/PortObserverCandidate.swift
echo "Observer identity helper, EnvironmentChecker, RootPortObserver, and candidate producer typecheck passed."
