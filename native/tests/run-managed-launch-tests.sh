#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
ARTIFACTS="$ROOT/.guard-artifacts"
mkdir -p "$ARTIFACTS"
BUILD=$(mktemp -d "$ARTIFACTS/managed-launch-test.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM
export DEVELOPER_DIR=/Library/Developer/CommandLineTools

/usr/bin/xcrun --sdk macosx clang -mmacosx-version-min=13.0 \
    native/tests/ManagedLaunchFixture.c -o "$BUILD/managed-fixture"
/usr/bin/xcrun --sdk macosx clang -mmacosx-version-min=13.0 \
    -I native/macos/handover -c native/macos/handover/LegacyProcess.c \
    -o "$BUILD/LegacyProcess.o"
sh scripts/generate-cli-privacy-swift.sh "$BUILD/ManagedPrivacyDefaults.swift"
/usr/bin/xcrun swiftc -parse-as-library -D MANAGED_LAUNCH_FIXTURE_TESTS \
    -I native/macos/handover native/macos/handover/ManagedLaunchCandidate.swift \
    native/tests/ManagedLaunchCandidateTests.swift "$BUILD/ManagedPrivacyDefaults.swift" \
    "$BUILD/LegacyProcess.o" \
    -framework Security -framework CoreFoundation -o "$BUILD/managed-launch-tests"
ENABLE_BETA_TRACING_DETAILED=fixture-beta \
CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=fixture-beta \
ENABLE_ENHANCED_TELEMETRY_BETA=fixture-beta \
BETA_TRACING_ENDPOINT=fixture-only \
"$BUILD/managed-launch-tests" "$BUILD/managed-fixture"
