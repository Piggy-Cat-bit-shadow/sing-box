#!/usr/bin/env bash
# Builds THE Jiejie VPS production server binary.
#
# Usage: build-server.sh <goos> <goarch> <output>
#        build-server.sh linux amd64 dist/sing-box-linux-amd64
#
# This fork ships exactly one server product, so this script builds exactly one
# profile: the Server Minimal tag set, read from
# release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL.
#
# # Why the version is injected here
#
# `constant.Version` defaults to "unknown" unless it is set at link time, so a
# build that skips -ldflags ships a binary whose `sing-box version` claims
# "unknown". That used to be handled by the workflow with its own `go build`
# invocation, which meant the release pipeline had TWO ways to build the server
# and only one of them set the version.
#
# The version now lives in this script, which is the single build entry point for
# this product, so every caller gets it - the workflow, the reproducibility check,
# and a developer running it by hand.
#
# release/JIEJIE_VERSION carries no timestamp and no commit, so the linked value is
# a function of the source alone and the artifact stays byte-reproducible.
#
# -trimpath and -buildvcs=false remove the checkout path and the VCS stamp; without
# them the same commit would produce a different binary on every machine.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

goos="$1"; goarch="$2"; output="$3"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tags_file="release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL"
if [ ! -f "$tags_file" ]; then
  echo "missing tag file: $tags_file" >&2
  exit 2
fi
tags="$(cat "$tags_file")"

version="$(tr -d '[:space:]' < release/JIEJIE_VERSION)"
if [ -z "$version" ]; then
  echo "release/JIEJIE_VERSION is empty" >&2
  exit 2
fi

# -s -w drops the symbol table and DWARF. The shipped artifact is therefore
# smaller, and the workflow keeps a separate unstripped link of the same program
# for the symbol audit rather than shipping symbols to users.
ldflags="-s -w -X github.com/sagernet/sing-box/constant.Version=${version} $(cat release/LDFLAGS)"

echo "building jiejie-server-minimal goos=$goos goarch=$goarch"
echo "tags:    $tags"
echo "ldflags: $ldflags"

CGO_ENABLED="${CGO_ENABLED:-0}"
export CGO_ENABLED

mkdir -p "$(dirname "$output")"

GOOS="$goos" GOARCH="$goarch" go build \
  -trimpath \
  -buildvcs=false \
  -tags "$tags" \
  -ldflags "$ldflags" \
  -o "$output" \
  ./cmd/sing-box

echo "built: $output"
echo "bytes: $(wc -c < "$output" | tr -d ' ')"
echo "sha256: $(sha256_of "$output")"
