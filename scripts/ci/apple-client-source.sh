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
#
# The refs file is loaded even though the SHA no longer comes from it, so that the same
# misconfiguration fails here as everywhere else: a refs file that has been edited back to
# the two-source model must be refused by every subcommand, not only by the ones that
# happen to read the file.
platform_sha() {
  case "$1" in
    ios|macos) ;;
    *) fail "unknown platform '$1' (expected ios or macos)" ;;
  esac
  load_refs
  apple_sha
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
  load_refs
  local branch; branch="$(platform_branch macos)"
  local repo="$APPLE_CLIENT_REPOSITORY"

  # The macOS tree is a second working copy of the SAME commit, and it is produced from the
  # submodule when that exists because a local copy is cheap and needs no network.
  #
  # It is NOT required to exist. The macOS job deliberately checks the parent out with
  # `submodules: false` - it has no use for the iOS tree, and the Libbox it links arrives as
  # a downloaded artifact - so this function has to work with only the gitlink to go on.
  # Requiring the submodule made that job fail with
  # "clients/apple is not checked out, so there is no Apple source to copy" while the source
  # it needed was one fetch away.
  local submodule="$ios_dir_default"
  local have_submodule=0
  [ -d "$submodule/.git" ] && have_submodule=1

  if [ "$have_submodule" = "1" ]; then
    fetch_branch "$submodule" "$branch"
    require_commit "$submodule" "$want"
    require_on_branch "$submodule" "$want" "$branch"
  fi

  # Where the copy draws its objects from. With a submodule that is the submodule's own store,
  # refreshed on every call; without one the clone's own store is used and the commit is
  # fetched into it below.
  local objects_source=""
  if [ "$have_submodule" = "1" ]; then
    objects_source="$(git -C "$submodule" rev-parse --absolute-git-dir)/objects"
    [ -d "$objects_source" ] || fail \
      "cannot locate the object store of $submodule; the macOS copy cannot be refreshed from it."
  fi

  # Which source tree the copy came from is answered by its object-store wiring, not by
  # `origin`: a `--shared` clone points `origin` at the source PATH rather than at the Apple
  # repository URL, and the URL can be re-pointed between runs, so comparing origin would be
  # both wrong on a healthy tree and unstable across runs.
  if [ -d "$dir/.git" ] && [ -n "$objects_source" ]; then
    local copy_git_dir; copy_git_dir="$(git -C "$dir" rev-parse --absolute-git-dir)"
    local alternate=""
    [ -f "$copy_git_dir/objects/info/alternates" ] && \
      alternate="$(head -n 1 "$copy_git_dir/objects/info/alternates")"
    if [ -n "$alternate" ] && [ "$alternate" != "$objects_source" ]; then
      fail "$dir draws its objects from '$alternate' instead of $submodule.
  Remove $dir and re-run so the copy is taken from the source this commit pins."
    fi
  fi

  if [ ! -d "$dir/.git" ]; then
    rm -rf "$dir"
    mkdir -p "$(dirname "$dir")"
    if [ "$have_submodule" = "1" ]; then
      # A local, shared-object clone: cheap, offline, and it carries every commit the
      # submodule has - which is the commit we are about to check out.
      git clone --shared --no-checkout "$submodule" "$dir" >/dev/null 2>&1 || fail \
        "could not copy $submodule into $dir"
    else
      # No submodule to copy: clone the declared repository instead. Blobless and
      # single-branch, because only one commit is ever needed here.
      git clone --filter=blob:none --no-checkout "$repo" "$dir" >/dev/null 2>&1 || fail \
        "could not clone $repo into $dir"
    fi
  fi

  if [ "$have_submodule" = "1" ]; then
    # Refresh the alias rather than fetch: a `--shared` clone aliases the source's object
    # database at clone time, and the submodule gains objects afterwards - every time the
    # gitlink moves - so the alias has to be re-pointed before the wanted commit resolves.
    #
    # Fetching a commit that exists only locally is awkward by design (a bare fetch of an
    # arbitrary SHA is not guaranteed, and a refspec for a commit that is on no branch cannot
    # be written), while an alternate is exactly the mechanism for "this object store is also
    # mine".
    local copy_git_dir; copy_git_dir="$(git -C "$dir" rev-parse --absolute-git-dir)"
    mkdir -p "$copy_git_dir/objects/info"
    printf '%s\n' "$objects_source" > "$copy_git_dir/objects/info/alternates"
  elif ! git -C "$dir" cat-file -e "$want^{commit}" 2>/dev/null; then
    # The clone does not have the commit yet. Fetch the reviewed branch and try again: the
    # pinned commit is an ancestor of it by construction, so this resolves it in one fetch
    # without depending on the server allowing a fetch by raw SHA.
    git -C "$dir" fetch --no-tags --filter=blob:none origin \
      "+refs/heads/$branch:refs/remotes/origin/$branch" >/dev/null 2>&1 || true
    git -C "$dir" cat-file -e "$want^{commit}" 2>/dev/null || fail \
      "$want is not reachable from origin/$branch of $repo.
  The pinned Apple source must be a commit of the branch this fork reviews.
  If the gitlink was just moved, push $branch first: the commit has to be on the branch a
  fresh checkout can fetch."
  fi

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
