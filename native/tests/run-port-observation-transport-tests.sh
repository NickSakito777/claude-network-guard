#!/bin/sh
# Compile the production bridge/serializer, exercise only synthetic diagnostics,
# then decode its actual bytes through the production Rust DTO.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
# Respect the system-selected toolchain's license/availability before the
# existing project-only compiler selection. Never use that selection as a fallback.
/usr/bin/xcrun --find swiftc >/dev/null
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/guard-port-transport.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM
sh scripts/guard-tool.sh rustc --edition=2021 -Awarnings scripts/generate-cli-privacy-swift.rs -o "$BUILD/privacy-generator"
"$BUILD/privacy-generator" "$BUILD/ManagedPrivacyDefaults.swift"
for source in native/macos/handover/NativeGate.c native/macos/handover/LegacyProcess.c native/macos/checks/ObserverIdentity.c; do
    /usr/bin/xcrun clang -DNG_OFFLINE_TEST -mmacosx-version-min=13.0 -c "$source" -o "$BUILD/$(basename "$source" .c).o"
done
/usr/bin/xcrun swiftc -D GUARD_GATE_FIXTURE_TESTS -parse-as-library -target arm64-apple-macosx13.0 \
    -sdk /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
    -module-cache-path "$BUILD/swift-modules" -I native/macos/handover \
    native/macos/native/NativeClock.swift native/macos/controller/GuardLuLuContracts.swift \
    native/macos/controller/ProtectedFiles.swift native/macos/checks/NetworkEventPolicy.swift \
    native/macos/checks/WiFiAssociationEventMonitor.swift native/macos/checks/EnvironmentChecker.swift \
    native/macos/checks/RootPortObserver.swift native/macos/handover/SwiftNativeGate.swift \
    native/macos/handover/LegacyApplicationSupervisor.swift native/macos/handover/ManagedLaunchCandidate.swift \
    native/macos/lulu/LuLuManifest.swift native/macos/lulu/LuLuPolicy.swift \
    native/macos/lulu/LuLuServices.swift native/macos/GuardLuLuBridge.swift \
    "$BUILD/ManagedPrivacyDefaults.swift" native/tests/PortObservationTransportTests.swift \
    native/tests/GuardDiagnosticsTests.swift native/tests/LegacyLaunchCoordinationTests.swift \
    "$BUILD/NativeGate.o" "$BUILD/LegacyProcess.o" "$BUILD/ObserverIdentity.o" \
    -framework Security -framework CoreWLAN -o "$BUILD/native-transport-test"
"$BUILD/native-transport-test" "$BUILD/port-observation.json"
/usr/bin/xcrun swiftc -parse-as-library -module-cache-path "$BUILD/swift-modules" \
    native/macos/controller/GuardLuLuContracts.swift native/macos/GuardLuLuRenewalTests.swift \
    -o "$BUILD/renewal-fixtures"
"$BUILD/renewal-fixtures"
GUARD_PORT_OBSERVATION_FIXTURE="$BUILD/port-observation.json" \
TAURI_CONFIG='{"bundle":{"resources":[]}}' \
    sh scripts/guard-tool.sh cargo test --locked --offline --manifest-path src-tauri/Cargo.toml \
    guard::tests::native_port_observation_fixture_crosses_the_rust_wire_boundary -- --ignored
