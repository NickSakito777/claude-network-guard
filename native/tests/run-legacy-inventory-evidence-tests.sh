#!/bin/sh
# Standalone production Swift control-flow fixtures; C process adapters and ps
# are synthetic. Never query, launch or signal a real application/process.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
/usr/bin/xcrun --find swiftc >/dev/null
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/guard-inventory-evidence.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM
python3 - "$BUILD/LegacyInventoryIdentity.inc" <<'PY'
import sys
from pathlib import Path
s=Path('native/macos/handover/LegacyProcess.c').read_text()
start=s.index('int lg_process_status_identity(')
end=s.index('\nint lg_list_pids(',start)
Path(sys.argv[1]).write_text(s[start:end])
PY
/usr/bin/xcrun clang -mmacosx-version-min=13.0 -I native/macos/handover -I "$BUILD" \
    -c native/tests/LegacyInventoryFixture.c -o "$BUILD/Fixture.o"
/usr/bin/xcrun swiftc -parse-as-library -target arm64-apple-macosx13.0 \
    -sdk /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
    -module-cache-path "$BUILD/swift-modules" -I native/macos/handover \
    native/macos/controller/GuardLuLuContracts.swift \
    native/macos/handover/LegacyApplicationSupervisor.swift \
    native/tests/LegacyInventoryEvidenceTests.swift "$BUILD/Fixture.o" -o "$BUILD/inventory-test"
"$BUILD/inventory-test"
/usr/bin/xcrun clang -mmacosx-version-min=13.0 -I native/macos/handover \
    -Dsysctl=fixture_sysctl -Dproc_pidpath=fixture_proc_pidpath -Dproc_listpids=fixture_proc_listpids \
    -DSecRequirementCreateWithString=fixture_requirement -DSecCodeCopyGuestWithAttributes=fixture_guest \
    -DSecCodeCheckValidity=fixture_validity \
    -c native/macos/handover/LegacyProcess.c -o "$BUILD/Observed.o"
/usr/bin/xcrun clang -mmacosx-version-min=13.0 -I native/macos/handover \
    native/tests/LegacyProcessEvidenceTests.c "$BUILD/Observed.o" -framework Security -framework CoreFoundation \
    -o "$BUILD/process-evidence-test"
"$BUILD/process-evidence-test"
