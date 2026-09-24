#!/usr/bin/env bash
# Writes BUILD-INFO.txt for one artifact.
#
# Deliberately records the TIMESTAMP only in this sidecar file, never in the
# binary. Embedding a timestamp in the binary would make the same commit produce
# a different hash on every build and destroy reproducibility; the sidecar gives
# operators the build date without that cost.
#
# Usage: build-info.sh <output-file> <platform> <arch> <flavor> [binary]
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

out="$1"; platform="$2"; arch="$3"; flavor="$4"; binary="${5:-}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

eval "$(./scripts/ci/version.sh)"

tags_file=""
case "$flavor" in
  server-minimal)      tags_file="release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL" ;;
  client-full)         tags_file="release/BUILD_TAGS_JIEJIE_CLIENT_FULL" ;;
  client-windows)      tags_file="release/BUILD_TAGS_JIEJIE_CLIENT_WINDOWS" ;;
esac
tags="$(cat "$tags_file" 2>/dev/null || echo unknown)"

# Dependency versions are read from the ACTUAL module graph, not hardcoded, so
# the file cannot claim a version the binary was not built against.
dep() { go list -m -f '{{.Version}}' "$1" 2>/dev/null || echo unknown; }

{
  echo "Jiejie sing-box build information"
  echo "================================="
  echo "flavor:                $flavor"
  echo "platform:              $platform"
  echo "arch:                  $arch"
  echo "version:               $JJ_VERSION"
  echo "artifact_version:      $JJ_ARTIFACT_VERSION"
  echo "git_commit:            $JJ_COMMIT"
  echo "git_short_sha:         $JJ_SHORT_SHA"
  echo "git_branch:            $JJ_BRANCH"
  echo "build_time_utc:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "go_version:            $JJ_GO_VERSION"
  echo "build_tags:            $tags"
  echo "quic_go:               $(dep github.com/sagernet/quic-go)"
  echo "sing_quic:             $(dep github.com/sagernet/sing-quic)"
  echo "sing:                  $(dep github.com/sagernet/sing)"
  echo ""
  echo "This build embeds NO timestamp: its hash is determined by the source"
  echo "commit and tags alone, so it is reproducible. The build_time_utc above is"
  echo "informational and lives only in this file."
} > "$out"

if [ -n "$binary" ] && [ -f "$binary" ]; then
  {
    echo ""
    echo "artifact:              $(basename "$binary")"
    echo "artifact_bytes:        $(wc -c < "$binary" | tr -d ' ')"
    echo "artifact_sha256:       $(sha256_of "$binary")"
  } >> "$out"
fi
