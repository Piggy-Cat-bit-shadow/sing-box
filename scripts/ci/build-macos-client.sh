#!/usr/bin/env bash
# Builds THE Jiejie macOS arm64 production core.
#
# Usage: build-macos-client.sh <goarch> [output]
#        build-macos-client.sh arm64 dist/sing-box-darwin-arm64
#
# # One macOS product
#
# This fork ships exactly ONE macOS core. It contains the NaiveProxy outbound
# (Cronet) AND the MASQUE transport AND the full client protocol set, because
# those are the capabilities the product is for. There is no lite/naive split and
# no second user-visible core: a capability that is needed is in the product, and
# a capability that is not needed is not built at all.
#
# The tag set lives in release/BUILD_TAGS_JIEJIE_CLIENT_MACOS and nowhere else, so
# this script and the workflow cannot drift apart.
#
# # CGO
#
# `with_naive_outbound` links github.com/sagernet/cronet-go, a prebuilt Chromium
# network stack, so this profile is CGO=1 by definition. That is accepted rather
# than worked around: the alternative would be a second CGO-free core that cannot
# speak NaiveProxy, which is exactly the split this consolidation removes.
#
# # Reproducibility
#
# -trimpath and -buildvcs=false remove the checkout path and the VCS stamp, and no
# timestamp is linked into the binary: build time lives only in the BUILD-INFO
# sidecar. The same commit therefore produces a byte-identical binary. Verified by
# building twice and comparing SHA-256.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

goarch="${1:-arm64}"
output="${2:-}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tags_file="release/BUILD_TAGS_JIEJIE_CLIENT_MACOS"
if [ ! -f "$tags_file" ]; then
  echo "missing tag file: $tags_file" >&2
  exit 2
fi
tags="$(cat "$tags_file")"

# The product requirement, asserted rather than assumed. A tag-file edit that
# dropped the Naive outbound would still produce a working binary, so nothing else
# in the pipeline would notice that the shipped core lost a headline capability.
for required in with_gvisor with_quic with_utls with_clash_api with_naive_outbound jiejie_client_macos; do
  if ! grep -q "$required" <<<"$tags"; then
    echo "$tags_file is missing $required; the macOS core would lose a required capability" >&2
    exit 2
  fi
done

if [ -z "$output" ]; then
  output="dist/sing-box-darwin-${goarch}"
fi

# The version comes from release/JIEJIE_VERSION, the same file scripts/ci/version.sh
# reads, so `sing-box version` reports the product version instead of "unknown". It
# carries no timestamp and no commit, so the linked value depends only on source.
version="$(tr -d '[:space:]' < release/JIEJIE_VERSION)"
if [ -z "$version" ]; then
  echo "release/JIEJIE_VERSION is empty" >&2
  exit 2
fi

ldflags="-X github.com/sagernet/sing-box/constant.Version=${version} $(cat release/LDFLAGS)"

# Cronet ships prebuilt static libraries, so CGO is mandatory here. Defaulting it on
# means the workflow does not have to remember, and a caller that explicitly
# disables it gets a clear message rather than the linker's "build constraints
# exclude all Go files".
CGO_ENABLED="${CGO_ENABLED:-1}"
export CGO_ENABLED
if [ "$CGO_ENABLED" != "1" ]; then
  echo "the macOS core requires CGO_ENABLED=1: with_naive_outbound links Cronet" >&2
  exit 2
fi

echo "building jiejie-client-macos goos=darwin goarch=$goarch cgo=$CGO_ENABLED"
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
