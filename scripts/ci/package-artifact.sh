#!/usr/bin/env bash
# Packages one built artifact with its licence, metadata and hashes.
#
# Usage: package-artifact.sh <binary> <platform> <arch> <flavor> <outdir> [examples...]
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

binary="$1"; platform="$2"; arch="$3"; flavor="$4"; outdir="$5"; shift 5

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
eval "$(./scripts/ci/version.sh)"

name="jiejie-sing-box-${platform}-${arch}-${flavor}-${JJ_ARTIFACT_VERSION}"
stage="$(mktemp -d)"
mkdir -p "$outdir"

cp "$binary" "$stage/$(basename "$binary")"
cp LICENSE "$stage/LICENSE"
./scripts/ci/build-info.sh "$stage/BUILD-INFO.txt" "$platform" "$arch" "$flavor" "$binary"

# Example configs are shipped so an operator has a valid starting point, and
# they contain only placeholder credentials - never a real endpoint.
if [ "$#" -gt 0 ]; then
  mkdir -p "$stage/examples"
  for example in "$@"; do
    [ -f "$example" ] && cp "$example" "$stage/examples/"
  done
fi

# Hashes are computed over the STAGED files, so SHA256SUMS describes exactly
# what the archive contains.
( cd "$stage" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 -I{} sh -c 'printf "%s  %s\n" "$(sha256_of "{}")" "{}"' > SHA256SUMS )

rm -rf "$outdir/$name"
mv "$stage" "$outdir/$name"

echo "staged: $outdir/$name"
cat "$outdir/$name/SHA256SUMS"
