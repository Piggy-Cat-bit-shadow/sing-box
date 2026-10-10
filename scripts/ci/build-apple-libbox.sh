#!/usr/bin/env bash
# Builds Libbox.xcframework from THIS repository and installs it into an Apple client
# checkout.
#
# Usage:
#   build-apple-libbox.sh [ios|macos|both]      build, then install into APPLE_CLIENT_DIR
#   build-apple-libbox.sh install [dir] [src]   install an existing xcframework
#
# APPLE_CLIENT_DIR selects the checkout to install into (default: clients/apple).
# For `install`, `dir` defaults to APPLE_CLIENT_DIR and `src` to the repository root's
# Libbox.xcframework - pass a source when the framework came from an artifact install,
# which unpacks it into a client checkout rather than to the root.
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

# The gomobile work directory `build_libbox` isolates its output in. Named here because that
# is where a local build actually leaves the framework when there is no sibling client
# checkout; see the resolution below.
libbox_build_dir="$root/_libbox_build"

# install_into places an xcframework into a client checkout, replacing whatever was there. A
# stale slice left behind by an earlier build would make the two platforms link different
# frameworks while both believed they installed the same artifact, so the destination is
# removed rather than merged.
#
# The SOURCE is a parameter because there are two ways the framework reaches this point, and
# they do not leave it in the same place:
#
#   * a local build writes it to the repository root, and
#   * an artifact install (the publish path, APPLE_USE_PREBUILT_LIBBOX=1) unpacks it straight
#     into the iOS client checkout and never touches the root.
#
# Hardcoding the root made the second case fail with "not built at the repository root" while
# the framework was sitting in the iOS client, verified and ready to copy.
install_into() {
  local dest_client="$1" source="${2:-Libbox.xcframework}"
  [ -d "$dest_client" ] || {
    echo "FAIL: $dest_client is missing; check the Apple client source out first." >&2
    exit 1
  }
  [ -d "$source" ] || {
    echo "FAIL: no xcframework at $source." >&2
    echo "      Build one (build-apple-libbox.sh both) or install a verified artifact first." >&2
    exit 1
  }
  rm -rf "$dest_client/Libbox.xcframework"
  ditto "$source" "$dest_client/Libbox.xcframework"

  echo "installed: $dest_client/Libbox.xcframework  (from $source)"
  python3 - "$dest_client/Libbox.xcframework/Info.plist" <<'PY'
import plistlib, sys
with open(sys.argv[1], 'rb') as fh:
    plist = plistlib.load(fh)
for lib in sorted(plist['AvailableLibraries'], key=lambda x: x['LibraryIdentifier']):
    print(f"  {lib['LibraryIdentifier']:32} {lib['SupportedArchitectures']}")
PY
}

if [ "$which" = "install" ]; then
  install_into "${2:-$client}" "${3:-Libbox.xcframework}"
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
rm -rf "$libbox_build_dir/Libbox.xcframework"
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

# Where the framework lands depends on whether a sibling client checkout exists.
#
# `build_libbox` writes it to its isolated gomobile work directory and then RENAMES it into
# ../sing-box-for-apple if that directory is there - the developer layout, where the Apple
# client sits beside this repository. On CI there is no such sibling, so the framework stays
# in the work directory and this script's old check for ./Libbox.xcframework failed with
# "Libbox.xcframework was not produced" while gomobile printed
# "xcframework successfully written out to: .../_libbox_build/Libbox.xcframework" in the same
# log. The artifact existed; the check looked only where it is not.
#
# Both layouts are therefore accepted, and the local build is NORMALISED to the repository
# root so that everything downstream - install_into's default source, the checks below, and
# the packaging helper - keeps the single documented location it was written against.
if [ ! -d Libbox.xcframework ] && [ -d "$libbox_build_dir/Libbox.xcframework" ]; then
  echo "  framework is in the gomobile work directory; moving it to the repository root"
  mv "$libbox_build_dir/Libbox.xcframework" Libbox.xcframework
fi

if [ ! -d Libbox.xcframework ]; then
  echo "FAIL: Libbox.xcframework was not produced" >&2
  echo "      looked in . and $libbox_build_dir" >&2
  ls -d "$libbox_build_dir"/* 2>/dev/null >&2 || true
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
