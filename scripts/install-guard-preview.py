#!/usr/bin/env python3
"""Install only the ad-hoc signed, non-enforcing review preview beside Guard.app."""
import ctypes
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / '.guard-artifacts/Guard-Preview.app'
NAME = 'Guard Preview.app'
BUNDLE_ID = 'local.fox.guard.preview'


def bundle_id(path):
    with (path / 'Contents/Info.plist').open('rb') as stream:
        return plistlib.load(stream).get('CFBundleIdentifier')


def main():
    applications = Path.home() / 'Applications'
    if applications.is_symlink() or not applications.is_dir():
        raise SystemExit('The current-user Applications folder is unavailable or linked.')
    if SOURCE.is_symlink():
        raise SystemExit('The staged preview path cannot be a symlink.')
    source = SOURCE.resolve(strict=True)
    if bundle_id(source) != BUNDLE_ID:
        raise SystemExit('The staged preview is missing or has an unexpected bundle identity.')
    destination = applications / NAME
    if destination.exists() or destination.is_symlink():
        raise SystemExit('Guard Preview.app already exists; nothing was replaced.')
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(source)], check=True)
    if any(source.rglob('lulu-manifest.json')):
        raise SystemExit('The preview unexpectedly contains a live LuLu deployment manifest.')

    stage = Path(tempfile.mkdtemp(prefix='.guard-preview-install-', dir=applications))
    staged_app = stage / NAME
    try:
        subprocess.run(['/usr/bin/ditto', '--rsrc', '--extattr', '--acl', str(source), str(staged_app)], check=True)
        if bundle_id(staged_app) != BUNDLE_ID:
            raise SystemExit('The staged copy has an unexpected bundle identity.')
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(staged_app)], check=True)
        renamex = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True).renamex_np
        renamex.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex.restype = ctypes.c_int
        # RENAME_EXCL makes the final same-volume move atomic and never replaces an app.
        if renamex(os.fsencode(staged_app), os.fsencode(destination), 0x00000004) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(destination))
    finally:
        if stage.exists():
            shutil.rmtree(stage)

    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(destination)], check=True)
    print(f'Installed {destination}; ID={BUNDLE_ID}; signed; not launched; no enrollment manifest.')


if __name__ == '__main__':
    main()
