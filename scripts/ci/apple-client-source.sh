#!/usr/bin/env bash
# Resolves, checks out and verifies the Apple client source for each of the two Apple
# products this fork ships.
#
# Usage:
#   apple-client-source.sh resolve                 print the resolved selection as shell assignments
#   apple-client-source.sh sha          <ios|macos>
#   apple-client-source.sh branch       <ios|macos>
#   apple-client-source.sh dir          <ios|macos>
#   apple-client-source.sh checkout     <ios|macos> [dir]
#   apple-client-source.sh verify       <ios|macos> [dir]
#   apple-client-source.sh assert-distinct
#
# # The topology this encodes
#
# The two Apple products take their Swift source from two branches of ONE Apple client
# repository, and link ONE Libbox framework built once from this repository:
#
#     parent HEAD  ->  one Libbox.xcframework
#                          |
#            +-------------+-------------+
#            v                           v
#     Repo B @ IOS_APPLE_SHA      Repo B @ MACOS_APPLE_SHA
#     branch hako-ui              branch dev
#     SFI - custom Hako UI        SFM - original sing-box UI
#
# The branches are NOT merged. There is no Apple commit that carries both UIs.
#
# # Where each SHA comes from
#
# ios    This repository's `clients/apple` gitlink. The gitlink is the single authority:
#        it is what the release commit records, and duplicating it into a file would
#        create a second value that can disagree with it.
#
# macos  release/apple-client-refs.env, as an exact commit. The branch is recorded
#        alongside it and every checkout asserts the commit is an ancestor of that
#        branch, so the pin cannot silently point somewhere the branch never had.
#
# # Fail closed
#
# A missing pin, an unreadable repository, an unreachable commit, a commit that is not
# on the declared branch, or a checkout whose HEAD is not the expected commit are all
# hard failures. Nothing here falls back to a branch tip: publishing a client built from
# whatever `dev` happened to be is the failure this script exists to prevent.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

refs_file="release/apple-client-refs.env"

# The iOS source is the submodule this repository pins. macOS gets an ephemeral checkout
# under build/, so the parent still records exactly ONE Apple gitlink.
ios_dir_default="clients/apple"
macos_dir_default="build/apple-client-macos"

fail() { echo "apple-client-source: $*" >&2; exit 1; }

# --- configuration -----------------------------------------------------------

load_refs() {
  [ -f "$refs_file" ] || fail "no $refs_file; the macOS Apple source is unpinned."
  # shellcheck disable=SC1090
  . "$refs_file"
  [ -n "${APPLE_CLIENT_REPOSITORY:-}" ] || fail "$refs_file sets no APPLE_CLIENT_REPOSITORY"
  [ -n "${MACOS_APPLE_BRANCH:-}" ] || fail "$refs_file sets no MACOS_APPLE_BRANCH"
  [ -n "${MACOS_APPLE_SHA:-}" ] || fail \
    "$refs_file sets no MACOS_APPLE_SHA. A macOS build must name an exact commit;
  following the branch tip would make the release unreproducible."
  case "$MACOS_APPLE_SHA" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) fail "MACOS_APPLE_SHA '$MACOS_APPLE_SHA' is not a commit SHA" ;;
  esac
}

# ios_sha reads the parent gitlink. `git ls-tree HEAD` rather than a working-tree read:
# the value that will be published is the one the commit records.
ios_sha() {
  local sha
  sha="$(git ls-tree HEAD "$ios_dir_default" | awk '{print $3}')"
  [ -n "$sha" ] || fail "this commit records no gitlink at $ios_dir_default"
  printf '%s\n' "$sha"
}

platform_dir() {
  case "$1" in
    ios)   printf '%s\n' "${2:-$ios_dir_default}" ;;
    macos) printf '%s\n' "${2:-$macos_dir_default}" ;;
    *) fail "unknown platform '$1' (expected ios or macos)" ;;
  esac
}

platform_sha() {
  case "$1" in
    ios)   ios_sha ;;
    macos) load_refs; printf '%s\n' "$MACOS_APPLE_SHA" ;;
    *) fail "unknown platform '$1' (expected ios or macos)" ;;
  esac
}

platform_branch() {
  case "$1" in
    ios)   printf '%s\n' "${IOS_APPLE_BRANCH:-hako-ui}" ;;
    macos) load_refs; printf '%s\n' "$MACOS_APPLE_BRANCH" ;;
    *) fail "unknown platform '$1' (expected ios or macos)" ;;
  esac
}

# --- checkout ----------------------------------------------------------------

# fetch_ref ensures the client repository knows the declared branch. Fetching the
# branch (not the SHA) is deliberate: fetching an arbitrary commit by SHA depends on a
# server-side setting, and the ancestor assertion below needs the branch ref anyway.
fetch_branch() {
  local dir="$1" branch="$2"
  git -C "$dir" fetch --prune origin \
    "+refs/heads/$branch:refs/remotes/origin/$branch" >/dev/null 2>&1 \
    || fail "could not fetch branch '$branch' into $dir"
}

require_commit() {
  local dir="$1" sha="$2"
  git -C "$dir" cat-file -e "$sha^{commit}" 2>/dev/null || fail \
    "$dir does not contain commit $sha.
  The pin names a commit this repository cannot reach."
}

# require_on_branch asserts the pinned commit is an ancestor of the declared branch.
# Without it a pin could be edited to any commit in the repository while still claiming
# to be "dev", and the release would carry a source that branch never had.
require_on_branch() {
  local dir="$1" sha="$2" branch="$3"
  git -C "$dir" merge-base --is-ancestor "$sha" "refs/remotes/origin/$branch" 2>/dev/null || fail \
    "commit $sha is not an ancestor of origin/$branch.
  The macOS pin must be a commit of the branch it names; refusing to build a source
  that the declared branch never contained."
}

checkout_ios() {
  local dir; dir="$(platform_dir ios "$1")"
  local want; want="$(ios_sha)"

  if [ ! -d "$dir" ]; then
    fail "$dir is missing. The iOS source is this repository's Apple submodule; check it out with:
    git submodule update --init --recursive $ios_dir_default"
  fi
  [ -e "$dir/.git" ] || fail "$dir is not a git checkout."

  # The nested submodule (Frameworks/Runestone) is what the Xcode project resolves
  # packages from, so it is part of "the iOS source", not an optional extra.
  git -C "$dir" submodule update --init --recursive >/dev/null 2>&1 || fail \
    "could not initialise the nested submodules of $dir"

  local actual; actual="$(git -C "$dir" rev-parse HEAD)"
  [ "$actual" = "$want" ] || fail \
    "$dir is at $actual but this commit pins it at $want.
  A build here would not be the iOS source this commit records."
  printf '%s\n' "$actual"
}

checkout_macos() {
  local dir; dir="$(platform_dir macos "$1")"
  load_refs
  local want="$MACOS_APPLE_SHA" branch="$MACOS_APPLE_BRANCH" repo="$APPLE_CLIENT_REPOSITORY"

  # An ephemeral checkout, never a second submodule: the parent must keep recording
  # exactly one Apple gitlink, and that one is the iOS source.
  if [ ! -d "$dir/.git" ]; then
    rm -rf "$dir"
    mkdir -p "$(dirname "$dir")"
    git clone --no-checkout "$repo" "$dir" >/dev/null 2>&1 || fail \
      "could not clone $repo into $dir"
  fi

  # A stale origin URL would silently build a different repository than the pin names.
  local origin_url
  origin_url="$(git -C "$dir" remote get-url origin 2>/dev/null || true)"
  [ "$origin_url" = "$repo" ] || fail \
    "$dir has origin '$origin_url' but the pin names '$repo'.
  Remove $dir and re-run so the checkout matches the pin."

  fetch_branch "$dir" "$branch"
  require_commit "$dir" "$want"
  require_on_branch "$dir" "$want" "$branch"

  git -C "$dir" checkout --detach "$want" >/dev/null 2>&1 || fail \
    "could not check out $want in $dir"
  git -C "$dir" submodule update --init --recursive >/dev/null 2>&1 || fail \
    "could not initialise the nested submodules of $dir"

  local actual; actual="$(git -C "$dir" rev-parse HEAD)"
  [ "$actual" = "$want" ] || fail "$dir is at $actual after checkout, expected $want"
  printf '%s\n' "$actual"
}

verify() {
  local platform="$1" dir; dir="$(platform_dir "$1" "$2")"
  local want; want="$(platform_sha "$platform")" || exit 1
  [ -e "$dir/.git" ] || fail "$dir is not a git checkout."
  local actual; actual="$(git -C "$dir" rev-parse HEAD)"
  [ "$actual" = "$want" ] || fail \
    "$dir is at $actual but the $platform Apple source must be $want."
  echo "PASS: $platform Apple source $dir @ $actual"
}

# assert-distinct is the topology invariant stated as a check: the two products must be
# built from different UI sources. If the two SHAs ever coincided, one platform would be
# silently shipping the other's UI, which is the exact confusion this selection removes.
assert_distinct() {
  load_refs
  local ios macos
  ios="$(ios_sha)"
  macos="$MACOS_APPLE_SHA"
  [ "$ios" != "$macos" ] || fail \
    "the iOS and macOS Apple sources are both $ios.
  iOS must be the custom Hako UI and macOS the original sing-box UI; one SHA cannot be both."
  echo "PASS: iOS ($ios) and macOS ($macos) are distinct Apple sources"
}

show() {
  local dir="${1:-}"
  echo "APPLE_CLIENT_REPOSITORY=$APPLE_CLIENT_REPOSITORY"
  echo "IOS_APPLE_BRANCH=${IOS_APPLE_BRANCH:-hako-ui}"
  echo "IOS_APPLE_SHA=$(ios_sha)"
  echo "IOS_APPLE_DIR=$ios_dir_default"
  echo "MACOS_APPLE_BRANCH=$MACOS_APPLE_BRANCH"
  echo "MACOS_APPLE_SHA=$MACOS_APPLE_SHA"
  echo "MACOS_APPLE_DIR=${dir:-$macos_dir_default}"
}

# --- dispatch ----------------------------------------------------------------

action="${1:-}"
case "$action" in
  resolve)
    load_refs
    show
    ;;
  sha)     shift; platform_sha "${1:?usage: sha <ios|macos>}" ;;
  branch)  shift; platform_branch "${1:?usage: branch <ios|macos>}" ;;
  dir)     shift; platform_dir "${1:?usage: dir <ios|macos>}" "${2:-}" ;;
  checkout)
    shift
    case "${1:?usage: checkout <ios|macos> [dir]}" in
      ios)   checkout_ios "${2:-}" ;;
      macos) checkout_macos "${2:-}" ;;
      *) fail "unknown platform '$1' (expected ios or macos)" ;;
    esac
    ;;
  verify)
    shift
    verify "${1:?usage: verify <ios|macos> [dir]}" "${2:-}"
    ;;
  assert-distinct)
    assert_distinct
    ;;
  ""|-h|--help)
    sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    fail "unknown action '$action'"
    ;;
esac
