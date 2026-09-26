#!/usr/bin/env bash
# Builds the Jiejie Client Edition macOS core binary.
#
# Usage: build-macos-client.sh <goarch> [output]
#        build-macos-client.sh arm64  dist/sing-box-darwin-arm64
#
# This script builds exactly one profile: the macOS client tag set read from
# release/BUILD_TAGS_JIEJIE_CLIENT_MACOS. That file is the single authoritative
# source for the tags; the workflow reads it too, so the two cannot drift.
#
# The profile is a CLIENT profile and is unrelated to the Server Minimal profile
# the Linux VPS workflow ships. See docs/JIEJIE-MACOS-CLIENT.md.
#
# Naive (Cronet) is OFF in this profile. The Naive OUTBOUND is gated on
# `with_naive_outbound`, which pulls github.com/sagernet/cronet-go/all — a CGO
# dependency that links a prebuilt Chromium network stack. Adding it is a
# separate profile (BUILD_TAGS_JIEJIE_CLIENT_MACOS_NAIVE) so that a Cronet
# problem can never block the macOS core itself.
#
# -trimpath and -buildvcs=false are used so the same commit produces an identical
# binary. A timestamp is deliberately NOT linked in: build time lives only in the
# BUILD-INFO sidecar, so the artifact hash is a function of the source alone.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

goarch="${1:-arm64}"
output="${2:-dist/sing-box-darwin-${goarch}}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tags_file="release/BUILD_TAGS_JIEJIE_CLIENT_MACOS"
tags="$(cat "$tags_file")"

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

# CGO is off for the base macOS profile on purpose: the standard client tag set
# has no CGO dependency, and a CGO_ENABLED=0 build produces a self-contained
# binary that runs on any macOS machine without a toolchain or dylib alongside
# it. The Naive profile is the one that flips this on.
CGO_ENABLED="${CGO_ENABLED:-0}"
export CGO_ENABLED

echo "building jiejie-client-macos goos=darwin goarch=$goarch"
echo "tags:   $tags"
echo "ldflags: $ldflags"

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
