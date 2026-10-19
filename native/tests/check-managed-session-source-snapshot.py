#!/usr/bin/env python3
"""Check source snapshot freshness; this is not a Gate FD inheritance audit."""

from hashlib import sha256
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "native/macos/handover/ManagedSessionSourceSnapshot.swift"
CANONICAL_MARKER = b'static let sha256 = "<SOURCE-SNAPSHOT-SHA256>"'


def source_paths():
    roots = (
        ROOT / "native",
        ROOT / "src",
        ROOT / "src-tauri/src",
        ROOT / "src-tauri/native",
        ROOT / "scripts",
        ROOT / ".github/workflows",
    )
    suffixes = {
        ".c", ".h", ".m", ".mm", ".swift", ".rs", ".py", ".sh",
        ".ts", ".tsx", ".js", ".mjs", ".json", ".toml", ".yml", ".yaml",
    }
    paths = {path for root in roots for path in root.rglob("*")
             if path.is_file() and path.suffix in suffixes}
    paths.update(ROOT / relative for relative in (
        "native/macos/handover/ManagedSessionSourceSnapshot.swift",
        "native/tests/check-managed-session-source-snapshot.py",
        "native/tests/run-managed-session-protocol-tests.sh",
        "scripts/check-guard-gate.sh",
        "scripts/guard-release-check.sh",
        ".github/workflows/checks.yml",
        "src-tauri/Cargo.toml",
        "src-tauri/Cargo.lock",
        "src-tauri/build.rs",
        "src-tauri/tauri.conf.json",
        "package.json",
        "bun.lock",
    ))
    return sorted(paths)


def snapshot_digest():
    digest = sha256()
    for path in source_paths():
        if not path.is_file():
            raise SystemExit(f"source snapshot input is missing: {path.relative_to(ROOT)}")
        relative = path.relative_to(ROOT).as_posix().encode()
        content = path.read_bytes()
        if path == SNAPSHOT:
            content, replacements = re.subn(
                rb'static let sha256 = "[0-9a-f]{64}"', CANONICAL_MARKER, content
            )
            if replacements != 1:
                raise SystemExit("source snapshot must contain exactly one 64-digit SHA-256 marker")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def main():
    content = SNAPSHOT.read_bytes()
    match = re.search(rb'static let sha256 = "([0-9a-f]{64})"', content)
    if not match:
        raise SystemExit("source snapshot marker is not a lowercase SHA-256")
    expected = match.group(1).decode()
    actual = snapshot_digest()
    if actual != expected:
        print(f"stale managed-session source snapshot: expected {expected}, computed {actual}",
              file=sys.stderr)
        return 1
    print(f"source snapshot freshness marker verified (not an FD audit): {actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
