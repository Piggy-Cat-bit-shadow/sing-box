#!/usr/bin/env bash
# Builds Libbox.xcframework from THIS repository and installs it into the pinned
# Apple client submodule.
#
# Usage: build-apple-libbox.sh [ios|macos|both]
#
# # Why this exists instead of `make lib_apple`
#
# `make lib_apple` runs `build_libbox -target apple` with no -platform, which expands
# to `ios,iossimulator,tvos,tvossimulator,macos`. That is upstream's full Apple
# matrix, and two parts of it are unusable here:
#
#   - iossimulator includes an amd64 slice, and the pinned cronet-go ships no
#     ios_amd64_simulator library, so the x86_64 simulator cannot link at all;
#   - tvOS is not a product this fork builds.
#
# This script therefore asks for exactly the slices the two shipped clients need.
# It also installs the result into clients/apple, which is where the submodule
# actually lives; build_libbox's own copy step targets a sibling ../sing-box-for-apple
# directory that only exists in a developer's upstream-style checkout.
#
# The framework is built from this working tree's experimental/libbox, so the apps
# link this fork at the current commit. Nothing is downloaded from an upstream
# release.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

which="${1:-both}"
case "$which" in
  ios)   targets="ios" ;;
  macos) targets="macos" ;;
  both)  targets="ios,macos" ;;
  *) echo "build-apple-libbox.sh: unknown target '$which' (ios|macos|both)" >&2; exit 2 ;;
esac

client="clients/apple"
if [ ! -d "$client" ]; then
  echo "FAIL: $client is missing; check out the submodule first." >&2
  exit 1
fi

echo "building Libbox.xcframework for: $targets"
echo "source commit: $(git rev-parse HEAD)"

rm -rf Libbox.xcframework
go run ./cmd/internal/build_libbox -target apple -platform "$targets"

if [ ! -d Libbox.xcframework ]; then
  echo "FAIL: Libbox.xcframework was not produced" >&2
  exit 1
fi

# The slices the clients require must be present. Checked rather than assumed,
# because a silently missing slice shows up much later as a confusing link error.
for required in ios-arm64; do
  if [ ! -d "Libbox.xcframework/$required" ]; then
    echo "FAIL: the xcframework has no $required slice" >&2
    ls Libbox.xcframework >&2
    exit 1
  fi
done

if [ "$which" != "ios" ] && [ ! -d "Libbox.xcframework/macos-arm64_x86_64" ] && [ ! -d "Libbox.xcframework/macos-arm64" ]; then
  echo "FAIL: the xcframework has no macOS slice" >&2
  ls Libbox.xcframework >&2
  exit 1
fi

# Install into the submodule, replacing whatever was there. This is the step that
# guarantees the app links OUR libbox rather than a stale or upstream one.
rm -rf "$client/Libbox.xcframework"
ditto Libbox.xcframework "$client/Libbox.xcframework"

echo "installed: $client/Libbox.xcframework"
python3 - "$client/Libbox.xcframework/Info.plist" <<'PY'
import plistlib, sys
with open(sys.argv[1], 'rb') as fh:
    plist = plistlib.load(fh)
for lib in sorted(plist['AvailableLibraries'], key=lambda x: x['LibraryIdentifier']):
    print(f"  {lib['LibraryIdentifier']:32} {lib['SupportedArchitectures']}")
PY
echo "build-apple-libbox: PASS"
