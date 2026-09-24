#!/usr/bin/env bash
# Builds one Jiejie client binary.
#
# Usage: build-client.sh <goos> <goarch> <flavor> <output>
#
# -trimpath and -buildvcs=false are used so the same commit produces an
# identical binary (verified: two consecutive builds of the Windows target
# yielded the same SHA-256). Without them the embedded build path and VCS stamp
# would differ per machine.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

goos="$1"; goarch="$2"; flavor="$3"; output="$4"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

case "$flavor" in
  client-full)    tags_file="release/BUILD_TAGS_JIEJIE_CLIENT_FULL" ;;
  client-windows) tags_file="release/BUILD_TAGS_JIEJIE_CLIENT_WINDOWS" ;;
  server-minimal) tags_file="release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL" ;;
  *) echo "unknown flavor: $flavor" >&2; exit 2 ;;
esac
tags="$(cat "$tags_file")"

echo "building flavor=$flavor goos=$goos goarch=$goarch"
echo "tags: $tags"

CGO_ENABLED="${CGO_ENABLED:-0}"
export CGO_ENABLED

GOOS="$goos" GOARCH="$goarch" go build \
  -trimpath \
  -buildvcs=false \
  -tags "$tags" \
  -o "$output" \
  ./cmd/sing-box

echo "built: $output"
echo "bytes: $(wc -c < "$output" | tr -d ' ')"
echo "sha256: $(sha256_of "$output")"
