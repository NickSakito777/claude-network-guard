#!/bin/sh
# Project-only toolchain/cache locations; no persistent PATH or profile edits.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
export RUSTUP_HOME="$ROOT/.tools/rustup"
export CARGO_HOME="$ROOT/.tools/cargo"
export CARGO_TARGET_DIR="$ROOT/.tools/target"
export BUN_INSTALL_CACHE_DIR="$ROOT/.tools/bun-cache"
export NPM_CONFIG_CACHE="$ROOT/.tools/npm-cache"
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
export PATH="$ROOT/.tools/cargo/bin:$ROOT/.tools/bun/bin:$PATH"
unset GITHUB_ACTIONS
case "${1:-}" in
  bun|cargo|rustc|rustup) tool=$1; shift; exec "$tool" "$@" ;;
  *) echo 'usage: sh scripts/guard-tool.sh bun|cargo|rustc|rustup ...' >&2; exit 64 ;;
esac
