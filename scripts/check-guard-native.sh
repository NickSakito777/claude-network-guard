#!/bin/sh
# Compile the host without embedding the not-yet-integrated browser engine.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export TAURI_CONFIG='{"bundle":{"resources":[]}}'

# Under Actions, use the toolchain installed and cached by the workflow. The
# marker is captured before it is cleared so tests cannot enable privileged
# GITHUB_ACTIONS-only branches. Outside Actions, retain the repository-local
# toolchain and cache paths.
GUARD_USE_RUNNER_TOOLCHAIN=${GUARD_USE_RUNNER_TOOLCHAIN:-0}
if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  GUARD_USE_RUNNER_TOOLCHAIN=1
  unset GITHUB_ACTIONS
fi

run_cargo() {
  if [ "$GUARD_USE_RUNNER_TOOLCHAIN" = "1" ]; then
    cargo "$@"
  else
    sh scripts/guard-tool.sh cargo "$@"
  fi
}

run_cargo test --locked --offline --manifest-path src-tauri/Cargo.toml guard::tests
run_cargo test --locked --offline --manifest-path src-tauri/Cargo.toml operation_lease
run_cargo test --locked --offline --manifest-path src-tauri/Cargo.toml guard_macos::tests
run_cargo test --locked --offline --manifest-path src-tauri/Cargo.toml guard_windows::tests
run_cargo check --locked --offline --manifest-path src-tauri/Cargo.toml --features custom-protocol
