#!/usr/bin/env bash
# Builds the Jiejie VPS production server binary.
#
# Usage: build-server.sh <goos> <goarch> <output>
#
# This fork ships exactly one product, so this script builds exactly one
# profile: the Server Minimal tag set. The client flavours (client-full,
# client-windows) that this script used to accept were removed when the project
# was narrowed to VPS-only.
#
# -trimpath and -buildvcs=false are used so the same commit produces an
# identical binary. Without them the embedded build path and VCS stamp would
# differ per machine.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

goos="$1"; goarch="$2"; output="$3"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tags_file="release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL"
tags="$(cat "$tags_file")"

echo "building jiejie-server-minimal goos=$goos goarch=$goarch"
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
