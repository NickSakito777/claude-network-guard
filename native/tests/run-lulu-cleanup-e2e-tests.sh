#!/bin/sh
# Explicit offline-only debug build: real Rust/Swift launch and finish ABI,
# injected process effects and Unix socket gates. Never install this test binary.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
/usr/bin/xcrun --find swiftc >/dev/null
GUARD_OFFLINE_E2E=1 TAURI_CONFIG='{"bundle":{"resources":[]}}' \
SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
CC=/Library/Developer/CommandLineTools/usr/bin/clang \
CXX=/Library/Developer/CommandLineTools/usr/bin/clang++ MACOSX_DEPLOYMENT_TARGET=13.0 \
sh scripts/guard-tool.sh cargo test --locked --offline --manifest-path src-tauri/Cargo.toml \
    offline_e2e_ -- --test-threads=1
