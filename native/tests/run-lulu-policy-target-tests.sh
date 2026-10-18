#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/lulu-policy-target.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM

/usr/bin/xcrun swiftc -parse-as-library \
    native/macos/lulu/LuLuPolicy.swift \
    native/tests/LuLuPolicyTargetBindingTests.swift \
    -framework CryptoKit -o "$BUILD/lulu-policy-target-tests"
"$BUILD/lulu-policy-target-tests" "$@"
