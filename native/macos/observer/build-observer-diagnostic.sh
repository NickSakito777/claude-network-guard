#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf '%s\n' 'Usage: build-observer-diagnostic.sh NEW_OUTPUT_DIRECTORY' >&2
    exit 64
fi

OBSERVER_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
OUTPUT_DIR=$1
if [ -e "$OUTPUT_DIR" ]; then
    printf '%s\n' 'Refusing to overwrite an existing output directory' >&2
    exit 73
fi
mkdir -m 700 "$OUTPUT_DIR"
trap 'status=$?; if [ "$status" -ne 0 ]; then rm -rf "$OUTPUT_DIR"; fi' EXIT HUP INT TERM

SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
export DEVELOPER_DIR=/Library/Developer/CommandLineTools

/usr/bin/xcrun clang -target arm64-apple-macosx13.0 -isysroot "$SDK" \
    -c "$OBSERVER_DIR/ObserverStopSignal.c" -o "$OUTPUT_DIR/ObserverStopSignal.o"
/usr/bin/xcrun clang -target arm64-apple-macosx13.0 -isysroot "$SDK" \
    -c "$OBSERVER_DIR/ObserverIdentity.c" -o "$OUTPUT_DIR/ObserverIdentity.o"

/usr/bin/xcrun swiftc -parse-as-library -target arm64-apple-macosx13.0 -sdk "$SDK" \
    -module-cache-path "$OUTPUT_DIR/swift-modules" \
    -Xcc -fmodules-cache-path="$OUTPUT_DIR/clang-modules" \
    "$OBSERVER_DIR/PortObserverCandidate.swift" \
    "$OBSERVER_DIR/PortObserverRuntime.swift" \
    "$OBSERVER_DIR/PortObserverCandidateMain.swift" \
    "$OUTPUT_DIR/ObserverIdentity.o" "$OUTPUT_DIR/ObserverStopSignal.o" \
    -lproc -o "$OUTPUT_DIR/root-port-observer-diagnostic"

trap - EXIT HUP INT TERM
printf 'Built isolated stdout diagnostic binary: %s\n' "$OUTPUT_DIR/root-port-observer-diagnostic"
