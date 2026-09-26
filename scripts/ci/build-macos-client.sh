#!/usr/bin/env bash
# Builds a Jiejie Client Edition macOS core binary.
#
# Usage: build-macos-client.sh <goarch> <flavor> [output]
#        build-macos-client.sh arm64 lite   dist/sing-box-darwin-arm64
#        build-macos-client.sh arm64 naive  dist/sing-box-darwin-arm64-naive
#
# Flavors:
#
#   lite   the default macOS core. Tag set read from
#          release/BUILD_TAGS_JIEJIE_CLIENT_MACOS. No CGO.
#   naive  the same core plus the Naive (NaiveProxy) OUTBOUND, tag set read from
#          release/BUILD_TAGS_JIEJIE_CLIENT_MACOS_NAIVE. Requires CGO.
#
# Each tag set lives in exactly one file under release/, and both this script and
# the workflow read that file rather than repeating the list, so the two cannot
# drift.
#
# Both profiles are CLIENT profiles, unrelated to the Server Minimal profile the
# Linux VPS workflow ships. See docs/JIEJIE-MACOS-CLIENT.md.
#
# Why two profiles rather than one. The Naive outbound is gated on
# `with_naive_outbound`, which imports github.com/sagernet/cronet-go/all and links
# a prebuilt Chromium network stack through CGO. That works on darwin/arm64 and
# was verified, but it changes the artifact fundamentally: CGO on means a larger
# binary with native library dependencies, and off means a self-contained binary
# that runs anywhere. A GUI operator should choose that tradeoff rather than have
# it chosen for them, and a Cronet problem must never block the core itself.
#
# -trimpath and -buildvcs=false are used so the same commit produces an identical
# binary. A timestamp is deliberately NOT linked in: build time lives only in the
# BUILD-INFO sidecar, so the artifact hash is a function of the source alone.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

goarch="${1:-arm64}"
flavor="${2:-lite}"
output="${3:-}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

case "$flavor" in
  lite|client-macos)
    flavor="lite"
    tags_file="release/BUILD_TAGS_JIEJIE_CLIENT_MACOS"
    default_cgo=0
    suffix=""
    ;;
  naive|client-macos-naive)
    flavor="naive"
    tags_file="release/BUILD_TAGS_JIEJIE_CLIENT_MACOS_NAIVE"
    # Cronet is a CGO dependency: without it the build fails with "build
    # constraints exclude all Go files" in cronet-go/lib/darwin_arm64.
    default_cgo=1
    suffix="-naive"
    ;;
  *)
    echo "unknown flavor: $flavor (expected lite or naive)" >&2
    exit 2
    ;;
esac

if [ ! -f "$tags_file" ]; then
  echo "missing tag file: $tags_file" >&2
  exit 2
fi
tags="$(cat "$tags_file")"

if [ -n "$suffix" ] && ! grep -q "with_naive_outbound" <<<"$tags"; then
  echo "$tags_file does not enable with_naive_outbound; the naive flavor is misconfigured" >&2
  exit 2
fi
if [ -z "$suffix" ] && grep -q "with_naive_outbound" <<<"$tags"; then
  echo "$tags_file enables with_naive_outbound; the lite flavor must not" >&2
  exit 2
fi

if [ -z "$output" ]; then
  output="dist/sing-box-darwin-${goarch}${suffix}"
fi

# The version is read from release/JIEJIE_VERSION, the same file scripts/ci/version.sh
# uses, so `sing-box version` reports the product version instead of "unknown".
# It carries no timestamp and no commit, so the linked value is a function of the
# source alone and the artifact stays reproducible.
version="$(tr -d '[:space:]' < release/JIEJIE_VERSION)"
if [ -z "$version" ]; then
  echo "release/JIEJIE_VERSION is empty" >&2
  exit 2
fi

ldflags="-X github.com/sagernet/sing-box/constant.Version=${version} $(cat release/LDFLAGS)"

CGO_ENABLED="${CGO_ENABLED:-$default_cgo}"
export CGO_ENABLED

# cronet-go ships prebuilt static libraries only for the platforms it supports.
# Failing here with a clear message beats the linker's own "build constraints
# exclude all Go files", which does not say which flavor needs what.
if [ "$CGO_ENABLED" != "1" ] && [ "$flavor" = "naive" ]; then
  echo "the naive flavor requires CGO_ENABLED=1 (Cronet is a CGO dependency)" >&2
  exit 2
fi

echo "building jiejie-client-macos flavor=$flavor goos=darwin goarch=$goarch cgo=$CGO_ENABLED"
echo "tags:    $tags"
echo "ldflags: $ldflags"

mkdir -p "$(dirname "$output")"

GOOS=darwin GOARCH="$goarch" go build \
  -trimpath \
  -buildvcs=false \
  -tags "$tags" \
  -ldflags "$ldflags" \
  -o "$output" \
  ./cmd/sing-box

echo "built:  $output"
echo "bytes:  $(wc -c < "$output" | tr -d ' ')"
echo "sha256: $(sha256_of "$output")"
