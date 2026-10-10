#!/usr/bin/env bash
# Resolves, checks out and verifies the Apple client source for the two Apple products
# this fork ships.
#
# Usage:
#   apple-client-source.sh resolve                 print the resolved selection as shell assignments
#   apple-client-source.sh sha          <ios|macos>
#   apple-client-source.sh branch       <ios|macos>
#   apple-client-source.sh dir          <ios|macos>
#   apple-client-source.sh checkout     <ios|macos> [dir]
#   apple-client-source.sh verify       <ios|macos> [dir]
#   apple-client-source.sh assert-shared-source
#   apple-client-source.sh assert-on-branch [dir]
#
# # The topology this encodes
#
# Both Apple products take their Swift source from ONE commit of ONE Apple client
# repository, and link ONE Libbox framework built once from this repository:
#
#     parent HEAD  ->  one Libbox.xcframework
#                          |
#            +-------------+-------------+
#            v                           v
#     Apple source @ APPLE_SHA    Apple source @ APPLE_SHA
#     scheme SFI - iOS            scheme SFM - macOS
#
# There is no per-platform source selection. Which UI a device shows is decided by the
# Apple source at runtime, from the device idiom; the parent only decides which commit is
# built. An earlier revision of this script did the opposite - it resolved macOS to an
# independent `dev` pin and asserted the two sources were DISTINCT - which made the parent
# repository, not the Apple source, the thing that decided UI ownership. That is why the
# invariant here is `assert-shared-source`, and why no subcommand reads a macOS commit out
# of a file.
#
# # Where the SHA comes from
#
# `clients/apple` is this repository's Apple submodule, and its gitlink is the single
# authority: it is what the release commit records. Both platforms resolve to it, and
# duplicating it into a file would create a second value that could disagree with it.
#
# # Why two directories exist even though the SHA is one
#
# Each platform applies its own overlays (compatibility, branding, entitlements) to its
# working tree, so they must not share one. They share the SHA and nothing else:
#
#     clients/apple                the authoritative checkout (used by iOS by default)
#     build/apple-client-macos     an ephemeral checkout of the SAME commit
#
# Overlays may leave either tree dirty; HEAD never moves. That is checked, not assumed:
# `verify` requires `git rev-parse HEAD` to equal the gitlink in whichever tree it is
# pointed at.
#
# # Fail closed
#
# A missing gitlink, an unreachable commit, an ephemeral tree whose origin is not the
# declared repository, or a checkout whose HEAD is not the gitlink are all hard failures.
# Nothing here falls back to a branch tip: publishing a client built from whatever a branch
# happened to be is the failure this script exists to prevent.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

refs_file="release/apple-client-refs.env"

# The two working trees. iOS uses the submodule directly; macOS gets an ephemeral copy of
# the same commit so the two overlays cannot contaminate each other.
ios_dir_default="clients/apple"
macos_dir_default="build/apple-client-macos"

fail() { echo "apple-client-source: $*" >&2; exit 1; }

# --- configuration -----------------------------------------------------------

load_refs() {
  [ -f "$refs_file" ] || fail "no $refs_file; the Apple client repository is undeclared."
  # shellcheck disable=SC1090
  . "$refs_file"
  [ -n "${APPLE_CLIENT_REPOSITORY:-}" ] || fail "$refs_file sets no APPLE_CLIENT_REPOSITORY"
  if [ -n "${MACOS_APPLE_SHA:-}${MACOS_APPLE_BRANCH:-}" ]; then
    fail "$refs_file still declares a macOS-specific Apple source.
  Both platforms build the clients/apple gitlink now; a per-platform source pin is the
  two-source model this topology removed. Delete MACOS_APPLE_SHA and MACOS_APPLE_BRANCH."
  fi
}

# apple_sha reads the parent gitlink. `git ls-tree HEAD` rather than a working-tree read:
# the value that will be published is the one the commit records.
apple_sha() {
  local sha
  sha="$(git ls-tree HEAD "$ios_dir_default" | awk '{print $3}')"
  [ -n "$sha" ] || fail "this commit records no gitlink at $ios_dir_default"
  case "$sha" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) fail "the gitlink at $ios_dir_default ('$sha') is not a commit SHA" ;;
  esac
  printf '%s\n' "$sha"
}

platform_dir() {
  case "$1" in
    ios)   printf '%s\n' "${2:-$ios_dir_default}" ;;
    macos) printf '%s\n' "${2:-$macos_dir_default}" ;;
    *) fail "unknown platform '$1' (expected ios or macos)" ;;
  esac
}

# platform_sha answers "which Apple commit does this product build?" - and for both
# products the answer is the same gitlink. This is the single most important line in the
# file: if either arm ever reads a different source, the two products stop being one.
platform_sha() {
  case "$1" in
    ios|macos) apple_sha ;;
    *) fail "unknown platform '$1' (expected ios or macos)" ;;
  esac
}

# platform_branch names the branch the pinned commit is reviewed on. It is informational: it
# feeds the ancestry check and the diagnostics, and it never selects a commit.
#
# Both arms load the refs file and answer with the SAME branch, because there is only one
# source now. They do not fall back to `IOS_APPLE_BRANCH`: that name records the branch the
# iOS product tracked before the two UI families were merged into one tree, so returning it
# would answer "which branch does the pinned commit live on?" with a stale historical value -
# and, worse, the answer would depend on whether some earlier call had already sourced the
# file. Loading the file here makes the answer a property of the file, not of the caller's
# environment.
platform_branch() {
  case "$1" in
    ios|macos) ;;
    *) fail "unknown platform '$1' (expected ios or macos)" ;;
  esac
  load_refs
  [ -n "${APPLE_CLIENT_BRANCH:-}" ] || fail "$refs_file sets no APPLE_CLIENT_BRANCH"
  printf '%s\n' "$APPLE_CLIENT_BRANCH"
}

# --- checkout ----------------------------------------------------------------

# fetch_branch ensures a checkout knows the declared branch. Fetching the branch rather than
# the SHA is deliberate: fetching an arbitrary commit by SHA depends on a server-side
# setting, and the ancestor assertion below needs the branch ref anyway.
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
  The gitlink names a commit this repository cannot reach."
}

# require_on_branch asserts the pinned commit is an ancestor of the declared branch, so a
# gitlink cannot be edited to a commit that the reviewed branch never contained.
require_on_branch() {
  local dir="$1" sha="$2" branch="$3"
  git -C "$dir" merge-base --is-ancestor "$sha" "refs/remotes/origin/$branch" 2>/dev/null || fail \
    "commit $sha is not an ancestor of origin/$branch.
  The pinned Apple source must be a commit of the branch this fork reviews; refusing to
  build a source that the declared branch never contained."
}

checkout_ios() {
  local dir; dir="$(platform_dir ios "$1")"
  local want; want="$(apple_sha)"

  if [ ! -d "$dir" ]; then
    fail "$dir is missing. The Apple source is this repository's submodule; check it out with:
    git submodule update --init --recursive $ios_dir_default"
  fi
  [ -e "$dir/.git" ] || fail "$dir is not a git checkout."

  # The nested submodule (Frameworks/Runestone) is what the Xcode project resolves
  # packages from, so it is part of "the Apple source", not an optional extra.
  git -C "$dir" submodule update --init --recursive >/dev/null 2>&1 || fail \
    "could not initialise the nested submodules of $dir"

  local actual; actual="$(git -C "$dir" rev-parse HEAD)"
  [ "$actual" = "$want" ] || fail \
    "$dir is at $actual but this commit pins it at $want.
  A build here would not be the Apple source this commit records."
  printf '%s\n' "$actual"
}

# checkout_macos produces a SECOND working tree of the SAME commit. It is a copy rather than
# a second submodule so that the parent keeps recording exactly one Apple gitlink, and it is
# a copy rather than the submodule itself so the macOS overlays cannot touch the iOS tree.
checkout_macos() {
  local dir; dir="$(platform_dir macos "$1")"
  local want; want="$(apple_sha)"
  local repo; load_refs; repo="$APPLE_CLIENT_REPOSITORY"
  local branch; branch="$(platform_branch macos)"

  # The submodule has to exist first: it is the local source the copy is taken from, so
  # this command never needs the network for the commit itself.
  local submodule="$ios_dir_default"
  [ -d "$submodule/.git" ] || fail \
    "$submodule is not checked out, so there is no Apple source to copy.
  Run 'git submodule update --init --recursive $submodule' first."

  fetch_branch "$submodule" "$branch"
  require_commit "$submodule" "$want"
  require_on_branch "$submodule" "$want" "$branch"

  # Re-clone when the tree is missing or its origin is not the declared repository: a stale
  # origin would silently build a different repository than the refs file names.
  local origin_url=""
  if [ -d "$dir/.git" ]; then
    origin_url="$(git -C "$dir" remote get-url origin 2>/dev/null || true)"
  fi
  if [ "$origin_url" != "$repo" ]; then
    if [ -n "$origin_url" ]; then
      fail "$dir has origin '$origin_url' but $refs_file names '$repo'.
  Remove $dir and re-run so the checkout matches the declared repository."
    fi
    rm -rf "$dir"
    mkdir -p "$(dirname "$dir")"
    # A local, shared-object clone: cheap, offline, and it carries every commit the
    # submodule has - which is the commit we are about to check out.
    git clone --shared --no-checkout "$submodule" "$dir" >/dev/null 2>&1 || fail \
      "could not copy $submodule into $dir"
    git -C "$dir" remote set-url origin "$repo" >/dev/null 2>&1 || fail \
      "could not point $dir at $repo"
  fi

  git -C "$dir" fetch --prune origin \
    "+refs/heads/$branch:refs/remotes/origin/$branch" >/dev/null 2>&1 || true
  require_commit "$dir" "$want"

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

# assert-shared-source is the topology invariant stated as a check: both products must be
# built from the SAME Apple commit, and that commit must be the parent's gitlink. This
# replaces the older `assert-distinct`, which asserted the opposite and would now fail every
# correct build. If the two ever differ, one platform is silently shipping the other's UI
# ownership - the exact confusion the single-source topology removes.
assert_shared_source() {
  load_refs
  local ios macos gitlink
  ios="$(platform_sha ios)"
  macos="$(platform_sha macos)"
  gitlink="$(apple_sha)"
  [ "$ios" = "$macos" ] || fail \
    "the iOS and macOS Apple sources differ ($ios vs $macos).
  Both products must build the clients/apple gitlink; a per-platform source is the
  two-source model this topology removed."
  [ "$ios" = "$gitlink" ] || fail \
    "the resolved Apple source $ios is not the gitlink $gitlink.
  The gitlink is the only authority for which Apple commit a release builds."
  echo "PASS: iOS and macOS share Apple source $ios"
}

# assert-on-branch proves the pinned commit is on the reviewed branch, which `resolve` cannot
# show on its own because the gitlink carries no branch name. It is a diagnostic, not a
# source selector: it never changes which commit is built.
assert_on_branch() {
  local dir; dir="$(platform_dir ios "${1:-}")"
  local sha; sha="$(apple_sha)"
  local branch; branch="$(platform_branch ios)"
  [ -d "$dir/.git" ] || fail "$dir is not a git checkout."
  fetch_branch "$dir" "$branch"
  require_commit "$dir" "$sha"
  require_on_branch "$dir" "$sha" "$branch"
  echo "PASS: pinned Apple source $sha is on origin/$branch"
}

# show emits the resolved selection as shell assignments. Every name below keeps its
# historical spelling because callers `eval` this output and then read those names: the
# migration changed what the macOS names RESOLVE TO, not what they are called. Dropping
# `MACOS_APPLE_SHA` here would have made every consumer fail on an unbound variable under
# `set -u`, which is a silent interface break dressed up as a rename.
#
# The macOS names therefore answer "which Apple commit does the macOS product build?" - and
# the answer is the same gitlink. `MACOS_APPLE_DIR` stays distinct because the two platforms
# still need separate working trees for their overlays.
show() {
  local dir="${1:-}"
  local sha; sha="$(apple_sha)"
  local branch; branch="$(platform_branch ios)"
  echo "APPLE_CLIENT_REPOSITORY=$APPLE_CLIENT_REPOSITORY"
  echo "APPLE_CLIENT_BRANCH=$branch"
  echo "APPLE_CLIENT_SHA=$sha"
  echo "IOS_APPLE_BRANCH=$branch"
  echo "IOS_APPLE_SHA=$sha"
  echo "IOS_APPLE_DIR=$ios_dir_default"
  echo "MACOS_APPLE_BRANCH=$branch"
  echo "MACOS_APPLE_SHA=$sha"
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
  assert-shared-source)
    assert_shared_source
    ;;
  assert-on-branch)
    shift
    assert_on_branch "${1:-}"
    ;;
  ""|-h|--help)
    sed -n '2,54p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    fail "unknown action '$action'"
    ;;
esac
