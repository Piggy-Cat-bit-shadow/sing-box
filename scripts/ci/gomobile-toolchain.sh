#!/usr/bin/env bash
# The single source of truth for which gomobile toolchain a build installs.
#
# Usage:
#   gomobile-toolchain.sh project              print the version root go.mod pins
#   gomobile-toolchain.sh apple                print the version the Apple build uses
#   gomobile-toolchain.sh install project      install gomobile+gobind at that version
#   gomobile-toolchain.sh install apple
#   gomobile-toolchain.sh diff                 show both, and whether they differ
#
# # Why this file exists
#
# `github.com/sagernet/gomobile/cmd/gomobile@v0.1.13` was written out three times:
# twice in .github/workflows/client-apple.yml and once in the Makefile's
# `lib_install` target. Three copies of one fact is three chances for a build to
# use a different generator than the one a reviewer read, and the Android workflow
# had already been moved to deriving its version from root go.mod for exactly that
# reason. The version now lives here, once, and the workflow and the Makefile both
# ask this script.
#
# # Two versions, each declared once, deliberately
#
# root go.mod requires github.com/sagernet/gomobile, and that pin is the project's
# toolchain: cmd/internal/build_libbox blank-imports it, the Android product is
# built from it, and the Android workflow derives its install version from go.mod
# rather than repeating a literal. The version is DERIVED here for the same reason
# a copy would be wrong: go.mod is where the dependency is actually resolved.
#
# The Apple build is one patch AHEAD of that pin and stays there. The difference is
# not cosmetic - v0.1.13 changes three files, and all three are in the Apple path:
#
#   bind/genobjc.go               emits `setter=set<Field>:` so that an ObjC
#                                 property whose Go field name starts with an
#                                 initialism (URL, ID) maps to the real generated
#                                 implementation instead of a clang-synthesised
#                                 dead ivar that silently never reaches Go.
#   cmd/gomobile/bind_iosapp.go   extracts external static libraries (cronet-go is
#                                 one) with `go list -deps` under GOPROXY=off, one
#                                 shared goCommandEnv() instead of a hand-rolled
#                                 GOMODCACHE prefix, and reports a `go list`
#                                 failure with its stderr instead of losing it.
#   cmd/gomobile/build.go         the same goCommandEnv() helper.
#
# Verified by diffing the two module versions in the module cache: exactly those
# three files differ.
#
# Apple was NOT moved down to the go.mod pin. That would trade a declared,
# documented one-patch gap for the loss of a binding fix, and no Apple build can be
# produced on this host to show the loss is harmless. `grep -rn 'gomobile/cmd' .`
# must find exactly one version literal in the tree: the line below.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------------------
# The one Apple declaration
# ---------------------------------------------------------------------------
#
# Read by `apple` and installed by `install apple`. Keep this line the ONLY place a
# gomobile version literal appears; scripts/ci/test-gomobile-toolchain.sh fails if
# another one appears in the workflows or the Makefile.
APPLE_GOMOBILE_VERSION="v0.1.13"

# A version literal that is not a version is worse than no pin: it would be
# installed as a branch or a revision and mean something different tomorrow.
check_version_shape() {
  local purpose="$1" version="$2"
  case "$version" in
    v[0-9]*) ;;
    *) die "the $purpose gomobile version '$version' is not a release version (it must start with 'v' and a digit)" ;;
  esac
  if [[ "$version" = *[!0-9A-Za-z._+-]* ]]; then
    die "the $purpose gomobile version '$version' contains characters outside [0-9A-Za-z._+-]"
  fi
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

project_version() {
  local version
  if ! version="$(cd "$repo_root" && go list -m -f '{{.Version}}' github.com/sagernet/gomobile 2>/dev/null)"; then
    die "cannot read the gomobile version from root go.mod. Run this from a checkout with the module graph available."
  fi
  [ -n "$version" ] && [ "$version" != "null" ] || die \
    "root go.mod does not require github.com/sagernet/gomobile, so there is no version to derive"
  check_version_shape "project" "$version"
  printf '%s\n' "$version"
}

apple_version() {
  check_version_shape "Apple" "$APPLE_GOMOBILE_VERSION"
  printf '%s\n' "$APPLE_GOMOBILE_VERSION"
}

version_for() {
  case "${1:-}" in
    project) project_version ;;
    apple) apple_version ;;
    *) die "unknown toolchain '${1:-<empty>}': expected 'project' (the root go.mod pin) or 'apple'" ;;
  esac
}

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
#
# Installs both binaries and proves WHICH MODULE they came from by reading their
# build info.
#
# `gomobile version` is NOT used: for a binary installed with `go install` from a
# module it prints "gomobile version unknown: binary is out of date, re-install
# it", because it looks for a version file that only exists in its own release
# layout. Treating that as a mismatch failed a step once while the install was
# perfectly fine. `go version -m` reads the stamped module path and version out of
# the binary itself, which is both reliable and a stronger statement.

cmd_install() {
  local purpose="${1:-}"
  [ -n "$purpose" ] || die "install: a toolchain is required ('project' or 'apple')"
  local version
  version="$(version_for "$purpose")"
  note "installing gomobile and gobind from github.com/sagernet/gomobile@$version ($purpose)"

  go install "github.com/sagernet/gomobile/cmd/gomobile@$version"
  go install "github.com/sagernet/gomobile/cmd/gobind@$version"

  local gobin
  gobin="$(go env GOPATH)/bin"
  # In a workflow this is how a later step sees the tools; outside one, GOPATH/bin
  # is already the operator's problem.
  if [ -n "${GITHUB_PATH:-}" ] && [ -f "${GITHUB_PATH}" ]; then
    echo "$gobin" >> "$GITHUB_PATH"
  fi

  local tool
  for tool in gomobile gobind; do
    [ -x "$gobin/$tool" ] || die "$tool was not installed to $gobin"
    note "--- $tool build info"
    go version -m "$gobin/$tool" | sed -n '1,6p'
    if ! go version -m "$gobin/$tool" | grep -q "github.com/sagernet/gomobile[[:space:]]*$version"; then
      die "$gobin/$tool was not built from github.com/sagernet/gomobile@$version"
    fi
  done
  note "PASS: gomobile and gobind are built from github.com/sagernet/gomobile@$version"
}

# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
#
# Informational, and deliberately not a failure: an independent Apple pin is a
# decision, not drift. What must not happen is the difference becoming invisible,
# which is what three literals in three files allowed.

cmd_diff() {
  local project apple
  project="$(project_version)"
  apple="$(apple_version)"
  note "project (root go.mod): $project"
  note "apple (this file):     $apple"
  if [ "$project" = "$apple" ]; then
    note "the two are identical; the Apple pin can be dropped from this file"
  else
    note "the Apple build is pinned independently; see the header for why"
  fi
}

main() {
  [ "$#" -gt 0 ] || die "usage: gomobile-toolchain.sh <project|apple|install|diff> [toolchain]"
  local sub="$1"
  shift
  case "$sub" in
    project | apple) version_for "$sub" ;;
    install) cmd_install "$@" ;;
    diff) cmd_diff ;;
    *) die "unknown subcommand '$sub'" ;;
  esac
}

main "$@"
