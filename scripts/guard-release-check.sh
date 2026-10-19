#!/bin/sh
# Local Guard pre-release checks only: no live network, install, launch, or enrollment.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

# GitHub Actions prepares Rust and Bun in the runner environment. Keep local
# checks isolated under .tools, but do not point a clean hosted runner at paths
# that only exist in this checkout. Clear the marker before tests so this
# offline check never opts into privileged CI-only test branches.
GUARD_USE_RUNNER_TOOLCHAIN=0
if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  GUARD_USE_RUNNER_TOOLCHAIN=1
  unset GITHUB_ACTIONS
fi
export GUARD_USE_RUNNER_TOOLCHAIN

run_bun() {
  if [ "$GUARD_USE_RUNNER_TOOLCHAIN" = "1" ]; then
    bun "$@"
  else
    sh scripts/guard-tool.sh bun "$@"
  fi
}

python3 - <<'PY'
import json
import re
from pathlib import Path

frontend = json.loads(Path("package.json").read_text())
tauri = json.loads(Path("src-tauri/tauri.conf.json").read_text())
cargo = Path("src-tauri/Cargo.toml").read_text()
match = re.search(r"(?ms)^\[package\]\s*\n(.*?)(?=^\[|\Z)", cargo)
version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', match.group(1)) if match else None
versions = {
    "package.json": frontend.get("version"),
    "tauri.conf.json": tauri.get("version"),
    "Cargo.toml": version.group(1) if version else None,
}
if len(set(versions.values())) != 1 or None in versions.values():
    raise SystemExit(f"Guard versions disagree: {versions}")
print(f"Guard version consistency: {next(iter(versions.values()))}")
PY

run_bun test src/guard-model.test.ts src/i18n.test.ts
run_bun run build
python3 scripts/test-guard-artifact-metadata.py
sh scripts/check-guard-native.sh
sh native/tests/run-managed-session-protocol-tests.sh
sh native/tests/run-lulu-manifest-target-tests.sh
sh native/tests/run-lulu-policy-target-tests.sh
