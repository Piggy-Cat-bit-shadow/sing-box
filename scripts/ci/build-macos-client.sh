#!/usr/bin/env bash
# Builds THE Jiejie macOS arm64 production core.
#
# Usage: build-macos-client.sh <goarch> [output]
#        build-macos-client.sh arm64 dist/sing-box-darwin-arm64
#
# # Full upstream feature profile
#
# This fork no longer maintains a product-specific protocol registry or an
# allowlist of permitted capabilities. The macOS core is built with upstream's
# own Darwin feature profile (release/DEFAULT_BUILD_TAGS): the complete protocol,
# endpoint, DNS-transport, service and certificate-provider registry that
# upstream ships.
#
# That means every capability upstream adds is inherited automatically. There is
# no fork-side list to update when upstream registers a new protocol, which was
# the whole point of retiring the product registry.
#
# The single deviation from upstream's tag file is the removal of
# `with_clash_api`, which no longer names any file: the Clash API was deleted
# from this fork as a control-plane decision (see docs/FORK-DIFF.md), not as a
# size cut. Keeping the tag would advertise a capability that does not exist.
#
# # CGO
#
# `with_naive_outbound` links github.com/sagernet/cronet-go, a prebuilt Chromium
# network stack, so this profile is CGO=1 by definition.
#
# # Reproducibility
#
# -trimpath and -buildvcs=false remove the checkout path and the VCS stamp, and no
# timestamp is linked into the binary: build time lives only in the BUILD-INFO
# sidecar. The same commit therefore produces a byte-identical binary.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

goarch="${1:-arm64}"
output="${2:-}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tags_file="release/DEFAULT_BUILD_TAGS"
if [ ! -f "$tags_file" ]; then
  echo "missing tag file: $tags_file" >&2
  exit 2
fi
tags="$(cat "$tags_file")"

# The profile must actually be the full upstream feature set. Asserted rather than
# assumed, because a silent revert to a narrower tag list would still produce a
# working binary and nothing downstream would notice that the core had lost
# capabilities. The list is upstream's own Darwin baseline; the point of the
# check is that the file still names all of it.
#
# with_gvisor is deliberately NOT in this list. Upstream removed the gVisor
# dependency (f857f0814, "Remove dependency on gVisor") and drives the TUN stack
# through the in-process Go stack instead, so the tag no longer exists in the
# upstream Darwin baseline this check mirrors.
for required in with_quic with_utls with_naive_outbound with_wireguard with_tailscale; do
  if ! grep -q "$required" <<<"$tags"; then
    echo "$tags_file is missing $required; the macOS core would lose part of the upstream feature profile" >&2
    exit 2
  fi
done

# And the converse: a tag whose feature has been removed must not come back.
#
# Narrowing the list above would otherwise be indistinguishable from simply
# deleting the requirement, which is what this check exists to prevent. If one of
# these reappears in the profile it means either a dependency was re-added without
# the architecture decision behind it, or the file was merged from a stale branch -
# both worth stopping for.
for retired in with_gvisor; do
  if grep -q "$retired" <<<"$tags"; then
    echo "$tags_file names $retired, which upstream retired (the gVisor dependency was" >&2
    echo "removed in favour of the Go TUN stack); the macOS core would link it back in" >&2
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

# The shipped macOS core is STRIPPED. -s drops the symbol table and -w drops the DWARF
# debug sections, which together are the single largest removable cost in this binary:
# measured at 12.38 MiB of __DWARF, and 24.37 MiB (34.8%) of the unstripped 70.03 MiB
# image once the symbol and string tables go too.
#
# The flags live in a macOS-profile-specific file rather than in release/LDFLAGS so that
# stripping is a property of THIS product. The Linux server, the deep audits and any
# local debug build keep their symbols, and nothing has to remember which product it is
# building.
#
# The cost is that `go tool nm` no longer works on the shipped artifact. That is
# deliberate: capability verification is done by building, running and checking the
# registry, not by inspecting stripped symbol tables.
strip_flags="-s -w"
ldflags="-X github.com/sagernet/sing-box/constant.Version=${version} $(cat release/LDFLAGS) ${strip_flags}"

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
