#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
test "$#" -eq 1
mkdir -p .guard-artifacts
BUILD=$(mktemp -d "$ROOT/.guard-artifacts/privacy-generator.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM
sh scripts/guard-tool.sh rustc --edition=2021 -Awarnings scripts/generate-cli-privacy-swift.rs -o "$BUILD/generate"
"$BUILD/generate" "$1"
