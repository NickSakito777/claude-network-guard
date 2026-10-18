#!/bin/sh
# Offline gate tests use unnamed Unix socket pairs, never TCP listeners.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
SDK=$(/usr/bin/xcrun --show-sdk-path)
mkdir -p .guard-artifacts/gate-tests
for TEST in NativeGateTests NativeGateBackpressureTests; do
    /usr/bin/xcrun clang -isysroot "$SDK" -DNG_OFFLINE_TEST -Wall -Wextra -Werror -pthread \
        -I native/macos/handover native/macos/handover/NativeGate.c "native/tests/$TEST.c" \
        -o ".guard-artifacts/gate-tests/$TEST"
    ".guard-artifacts/gate-tests/$TEST"
done
