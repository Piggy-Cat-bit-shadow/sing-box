#!/usr/bin/env bash
# Builds Libbox.xcframework from THIS repository and installs it into an Apple client
# checkout.
#
# Usage:
#   build-apple-libbox.sh [ios|macos|both]   build, then install into APPLE_CLIENT_DIR
#   build-apple-libbox.sh install [dir]      install the already-built root framework
#
# APPLE_CLIENT_DIR selects the checkout to install into (default: clients/apple).
#
# # One framework, two clients
#
# iOS and macOS take their Swift source from two branches of the same Apple repository,
# but they link the SAME Libbox: it is compiled once from this repository's commit and
# the identical framework is installed into each checkout. `install` exists so the
# release pipeline can build once and place that one build in both places, rather than
# compiling a second copy that would differ by nothing except the compiler's mood.
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
client="${APPLE_CLIENT_DIR:-clients/apple}"

# install_into places the framework built at the repository root into a client checkout,
# replacing whatever was there. A stale slice left behind by an earlier build would make
# the two platforms link different frameworks while both believed they installed the same
# artifact, so the destination is removed rather than merged.
install_into() {
  local dest_client="$1"
  [ -d "$dest_client" ] || {
    echo "FAIL: $dest_client is missing; check the Apple client source out first." >&2
    exit 1
  }
  [ -d Libbox.xcframework ] || {
    echo "FAIL: Libbox.xcframework is not built at the repository root." >&2
    exit 1
  }
  rm -rf "$dest_client/Libbox.xcframework"
  ditto Libbox.xcframework "$dest_client/Libbox.xcframework"

  echo "installed: $dest_client/Libbox.xcframework"
  python3 - "$dest_client/Libbox.xcframework/Info.plist" <<'PY'
import plistlib, sys
with open(sys.argv[1], 'rb') as fh:
    plist = plistlib.load(fh)
for lib in sorted(plist['AvailableLibraries'], key=lambda x: x['LibraryIdentifier']):
    print(f"  {lib['LibraryIdentifier']:32} {lib['SupportedArchitectures']}")
PY
}

if [ "$which" = "install" ]; then
  install_into "${2:-$client}"
  echo "build-apple-libbox: PASS"
  exit 0
fi

case "$which" in
  ios)   targets="ios" ;;
  macos) targets="macos" ;;
  both)  targets="ios,macos" ;;
  *) echo "build-apple-libbox.sh: unknown target '$which' (ios|macos|both|install)" >&2; exit 2 ;;
esac

if [ ! -d "$client" ]; then
  echo "FAIL: $client is missing; check the Apple client source out first." >&2
  exit 1
fi

echo "building Libbox.xcframework for: $targets"
echo "source commit: $(git rev-parse HEAD)"

rm -rf Libbox.xcframework
# Prefer the local module cache when it already holds everything.
#
# gomobile resolves dependencies with GOPROXY=off internally, and the outer `go run`
# still reaches GitHub for anything missing. This machine's network to github.com
# fails intermittently (SSL_ERROR_SYSCALL), which turns a signing build into a
# network failure that looks like a toolchain problem. Every module this build needs
# is already in the local cache, so point the resolver at the cache first and fall
# back to the network only if a module really is missing.
cache_proxy="file://$(go env GOMODCACHE)/cache/download"
if [ -d "$(go env GOMODCACHE)/cache/download" ]; then
  echo "  module proxy: local cache first ($cache_proxy)"
  GOFLAGS="${GOFLAGS:-}" GOPROXY="$cache_proxy,https://proxy.golang.org,direct" \
    go run ./cmd/internal/build_libbox -target apple -platform "$targets"
else
  go run ./cmd/internal/build_libbox -target apple -platform "$targets"
fi

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

# Install into the client checkout, replacing whatever was there. This is the step that
# guarantees the app links OUR libbox rather than a stale or upstream one.
install_into "$client"
echo "build-apple-libbox: PASS"
