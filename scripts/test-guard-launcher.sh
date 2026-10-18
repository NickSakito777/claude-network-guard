#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .guard-artifacts
/Library/Developer/CommandLineTools/usr/bin/clang -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk -Wall -Wextra -Werror browser-runtime/launcher/CCBrowser.c -o .guard-artifacts/guard-browser-entry-test
set +e
.guard-artifacts/guard-browser-entry-test --user-data-dir=/tmp/guard-untrusted-profile https://example.invalid/ > .guard-artifacts/launcher.out 2>&1
result=$?
set -e
test "$result" = 77
echo 'External browser launcher refused (77); no Chromium/host process launched.'
