#!/usr/bin/env bash
# One command to produce a signed Apple artifact.
#
# Usage:
#   ./scripts/release-apple.sh development        signed iOS IPA and macOS DMG
#   ./scripts/release-apple.sh development-ios    signed iOS IPA
#   ./scripts/release-apple.sh development-macos  signed macOS DMG
#   ./scripts/release-apple.sh testflight         iOS and macOS, one App Record
#   ./scripts/release-apple.sh testflight-ios     iOS only
#   ./scripts/release-apple.sh testflight-macos   macOS only
#   ./scripts/release-apple.sh unsigned           unsigned IPA and DMG (CI parity)
#
# # Why this exists
#
# Producing a runnable client takes six steps in a specific order, and getting the
# order wrong produces something that builds and does not run. Rather than expect
# anyone to remember them, each target runs the whole sequence and stops at the
# first real problem.
#
# It is a thin wrapper: every step is an existing script, and the signing values
# come from scripts/ci/apple-signing-config.sh exactly as they do when those scripts
# are run individually. Nothing about the build is reimplemented here.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

target="${1:-development}"
case "$target" in
  development|development-ios|development-macos) ;;
  testflight|testflight-ios|testflight-macos) ;;
  unsigned) ;;
  ""|-h|--help)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "release-apple.sh: unknown target '$target'" >&2
    echo "  expected one of: development, development-ios, development-macos," >&2
    echo "                   testflight, testflight-ios, testflight-macos, unsigned" >&2
    exit 2
    ;;
esac

case "$target" in
  unsigned)                             _default_mode=unsigned ;;
  testflight|testflight-ios|testflight-macos) _default_mode=testflight ;;
  *)                                    _default_mode=development ;;
esac
export APPLE_SIGNING_MODE="${APPLE_SIGNING_MODE:-$_default_mode}"
export APPLE_SIGNING_STYLE="${APPLE_SIGNING_STYLE:-automatic}"

# --- local publishing configuration -------------------------------------------
#
# A function, not a top-level block: it uses `local` so that the variables it derives cannot leak
# into the rest of the script, which is what the signing regression test asserts. It ran as a
# top-level block for a while, which is a syntax-level error - `local` outside a function - that
# only fired when the file it guards existed, so a machine without .env.apple.local never saw it.
load_local_publishing_config() {
  # Order of precedence:
  #   1. variables already exported in this shell
  #   2. .env.apple.local in the repository root, if present
  #   3. otherwise the configuration layer reports exactly what is missing
  #
  # The file is sourced, which assigns unconditionally, so every variable it names would
  # otherwise OVERWRITE a value the caller exported. The set of variables is therefore
  # captured before sourcing and restored afterwards.
  #
  # The set is derived from the file rather than listed here. An earlier version restored two
  # variables by hand, so a caller who exported APPLE_TEAM_ID or APPLE_SIGNING_STYLE was
  # silently overridden by the file - a documented precedence that did not hold.
  local_env="$root/.env.apple.local"
  if [ -f "$local_env" ]; then
    # Refuse a file that is not ignored: if someone force-added it, sourcing it would
    # quietly publish their bundle IDs on the next commit.
    if git check-ignore -q "$local_env" 2>/dev/null; then
      # Every variable the file assigns, with its caller-exported value (empty when unset).
      # `set -u` is active, so the "-" expansion is what keeps an unset name from aborting.
      local -a _env_names=()
      while IFS= read -r _name; do
        [ -n "$_name" ] && _env_names+=("$_name")
      done < <(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p' "$local_env" | sort -u)

      local -a _env_saved=()
      local _name
      for _name in "${_env_names[@]}"; do
        _env_saved+=("${!_name-}")
      done

      # shellcheck disable=SC1090
      source "$local_env"

      # Restore only names the caller had actually set. A name the caller left unset keeps the
      # file's value, which is what "the file fills gaps" means; a name that was set is put
      # back even when the file assigned it to empty, so the restore is faithful.
      local _i
      for _i in "${!_env_names[@]}"; do
        if [ -n "${_env_saved[$_i]}" ]; then
          export "${_env_names[$_i]}=${_env_saved[$_i]}"
        fi
      done
      unset _name _i _env_names _env_saved
      echo "configuration: loaded $local_env"
    else
      echo "release-apple: refusing to read $local_env" >&2
      echo "  That file is NOT git-ignored, so it could be committed and publish your" >&2
      echo "  bundle identifiers. Restore the .gitignore rule for .env.apple.local," >&2
      echo "  or export the values in your shell instead." >&2
      exit 2
    fi
  fi
}

load_local_publishing_config

eval "$(./scripts/ci/apple-signing-config.sh)"


# One build number for the whole run.
#
# Both TestFlight scripts default APPLE_BUILD_NUMBER to their own `date -u +%Y%m%d%H%M`. Run
# separately that is harmless, but `testflight` uploads iOS and macOS into ONE App Store Connect
# record, and letting each derive its own value means a run spanning a minute boundary publishes two
# build numbers for a single release. Deriving it once here and exporting it keeps the pair together;
# an explicit APPLE_BUILD_NUMBER from the caller still wins.
case "$target" in
  testflight|testflight-ios|testflight-macos)
    if [ -z "${APPLE_BUILD_NUMBER:-}" ]; then
      export APPLE_BUILD_NUMBER="$(date -u +%Y%m%d%H%M)"
    fi
    ;;
esac
mkdir -p dist/apple

step() {
  echo
  echo "== $* =="
}

# Which cronet archive this build will link, before anything is built.
#
# It runs for every target and before the first build, because the question it answers - does the
# resolved fork pin actually reach the native archive - is a property of the checkout, not of a
# platform, and a release that discovers it late has already built an artifact that must be thrown
# away.
step "cronet provenance"; ./scripts/ci/verify-cronet-provenance.sh --require-archives apple

# ---------------------------------------------------------------------------
# Shared preflight
# ---------------------------------------------------------------------------
step "repository state"
if [ -n "$(git status --porcelain)" ]; then
  echo "  note: the working tree has uncommitted changes; they will be built as-is"
  git status --short | sed 's/^/    /'
fi
echo "  commit:   $(git rev-parse HEAD)"
echo "  mode:     $APPLE_SIGNING_MODE"
echo "  style:    $APPLE_SIGNING_STYLE"
[ -n "${APPLE_BUILD_NUMBER:-}" ] && echo "  build:    $APPLE_BUILD_NUMBER"

# ---------------------------------------------------------------------------
# The two Apple UI sources
# ---------------------------------------------------------------------------
#
# One Apple repository, two branches: iOS carries the custom Hako UI, macOS the original
# sing-box UI. They are separate sources and are never merged. Each is materialised at the
# exact revision the release selects - the iOS one is the parent's gitlink, the macOS one
# the commit pinned in release/apple-client-refs.env - and the SAME Libbox build is
# installed into both.
step "select the Apple sources"
eval "$(./scripts/ci/apple-client-source.sh resolve)"
./scripts/ci/apple-client-source.sh assert-distinct

ios_client_dir="$IOS_APPLE_DIR"
macos_client_dir="$MACOS_APPLE_DIR"
export APPLE_CLIENT_REPOSITORY IOS_APPLE_SHA IOS_APPLE_BRANCH MACOS_APPLE_SHA MACOS_APPLE_BRANCH

echo "  iOS:   $IOS_APPLE_BRANCH @ $IOS_APPLE_SHA  (custom Hako UI)   -> $ios_client_dir"
echo "  macOS: $MACOS_APPLE_BRANCH @ $MACOS_APPLE_SHA (original sing-box UI) -> $macos_client_dir"

# The iOS source is the submodule the parent records; this asserts the checkout matches.
./scripts/ci/apple-client-source.sh checkout ios >/dev/null
# The macOS source is an ephemeral checkout of the pinned commit, created on demand.
./scripts/ci/apple-client-source.sh checkout macos >/dev/null

step "signing environment"
# In unsigned mode this prints SKIP; otherwise it fails with an actionable message
# rather than letting xcodebuild produce something unusable.
./scripts/ci/check-apple-signing-environment.sh

if [ "$APPLE_SIGNING_MODE" = "unsigned" ]; then
  step "signing regression tests"
  # Run in a clean environment.
  #
  # The suite asserts that an unconfigured development/testflight build is REJECTED, and its checks
  # read the ambient environment. This script has already sourced .env.apple.local and exported the
  # resolved signing values, so running the suite as an ordinary child made those checks observe a
  # configured environment and fail. Passing the values in explicitly is what the suite's own `env`
  # invocations already do for the cases they care about.
  env -u APPLE_TEAM_ID -u APPLE_BASE_BUNDLE_ID -u APPLE_APP_GROUP_ID \
      -u APPLE_SIGNING_MODE -u APPLE_SIGNING_STYLE \
      ./scripts/ci/test-apple-signing.sh >/dev/null
  echo "  signing regression suite passed"
fi

  # Libbox is either built here or installed from a CI-verified artifact.
  #
  # The prebuilt path exists so the one-command publish can reuse the framework CI already compiled
  # and validated for this commit, rather than compiling it a third time on the publishing Mac.
  #
  # The mode fails closed rather than falling back: if a caller asked for a prebuilt Libbox and none
  # is installed, building one silently would make the published binary differ from the artifact the
  # caller believed it was shipping.
  #
  # Either way the SAME framework ends up in both checkouts. It is built once, or unpacked once from
  # one verified artifact - never compiled per platform, which is what would let the two clients link
  # cores that differ.
  if [ "${APPLE_USE_PREBUILT_LIBBOX:-0}" = "1" ]; then
    step "use the prebuilt Libbox"
    libbox="$ios_client_dir/Libbox.xcframework"
    if [ ! -d "$libbox" ]; then
      echo "FAIL: APPLE_USE_PREBUILT_LIBBOX=1 but $libbox is not installed." >&2
      echo "  Install a verified artifact first, then re-run with this variable set." >&2
      echo "  Refusing to build one instead: that would publish a binary that does not match" >&2
      echo "  the artifact you verified." >&2
      exit 2
    fi
    echo "  using: $libbox"
    echo "  slices: $(ls "$libbox" | grep -v Info.plist | tr '\n' ' ')"
    # The macOS checkout is a different source tree, so the framework is placed there
    # explicitly rather than assumed to be present - and the SOURCE is named, because an
    # artifact install unpacks into the iOS client and never writes the repository root.
    ./scripts/ci/build-apple-libbox.sh install "$macos_client_dir" "$libbox"
  else
    step "build Libbox once from this fork"
    APPLE_CLIENT_DIR="$ios_client_dir" ./scripts/ci/build-apple-libbox.sh both
    # The build above left the framework at the repository root, which is this call's default
    # source.
    ./scripts/ci/build-apple-libbox.sh install "$macos_client_dir"
  fi

# The two checkouts must link the identical framework. Checked rather than assumed: the
# whole point of building once is that iOS and macOS ship one core, and installing is
# where that could quietly stop being true.
step "verify both clients link the same Libbox"
./scripts/ci/check-apple-shared-libbox.sh "$ios_client_dir" "$macos_client_dir"

step "prepare the iOS Apple client"
APPLE_CLIENT_DIR="$ios_client_dir" APPLE_CLIENT_PLATFORM=ios ./scripts/ci/prepare-apple-client.sh

step "prepare the macOS Apple client"
APPLE_CLIENT_DIR="$macos_client_dir" APPLE_CLIENT_PLATFORM=macos ./scripts/ci/prepare-apple-client.sh

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
do_ios() {
  step "build signed iOS IPA"
  APPLE_CLIENT_DIR="$ios_client_dir" \
    ./scripts/ci/build-ios-ipa.sh dist/apple/JiejieBox-${APPLE_SIGNING_MODE}.ipa
  step "verify the signed IPA"
  ./scripts/ci/verify-apple-signed-artifact.sh ios-ipa dist/apple/JiejieBox-${APPLE_SIGNING_MODE}.ipa
}

do_macos() {
  step "build signed macOS DMG"
  APPLE_CLIENT_DIR="$macos_client_dir" \
    ./scripts/ci/build-macos-dmg.sh dist/apple/SFM-${APPLE_SIGNING_MODE}.dmg
  step "verify the signed DMG"
  ./scripts/ci/verify-apple-signed-artifact.sh macos-dmg dist/apple/SFM-${APPLE_SIGNING_MODE}.dmg
}

# The single-record product model. Both platforms ship as one App Store Connect
# record, which is only possible because the two main apps share a bundle id.
print_topology() {
  cat <<EOF
  App:        JiejieBox
  Bundle ID:  $APPLE_IOS_APP_BUNDLE_ID
  Platforms:  iOS, macOS
  Record:     one App Store Connect record (universal purchase)

  The macOS App Store app is the SFM target. SFM.System ($APPLE_MACOS_STANDALONE_BUNDLE_ID)
  is a separate Developer ID product - it is unsandboxed and installs a privileged
  helper and a System Extension - and is deliberately NOT part of this record.
EOF
}

case "$target" in
  development)       do_ios; do_macos ;;
  development-ios)   do_ios ;;
  development-macos) do_macos ;;
  unsigned)          do_ios; do_macos ;;

  testflight-ios)
    step "App Store Connect topology"; print_topology
    step "build and upload iOS TestFlight"
    APPLE_CLIENT_DIR="$ios_client_dir" ./scripts/ci/build-ios-testflight.sh
    ;;

  testflight-macos)
    step "App Store Connect topology"; print_topology
    step "build and upload macOS TestFlight"
    APPLE_CLIENT_DIR="$macos_client_dir" ./scripts/ci/build-macos-testflight.sh
    ;;

  testflight)
    # One shared configuration, one Libbox build, both Apple sources prepared above, then
    # both platforms. Each TestFlight builder is pointed at its own Apple checkout: iOS at
    # the custom-UI source, macOS at the original-UI one. Both read the same Libbox and the
    # same APPLE_BUILD_NUMBER, which is what keeps them in one App Store Connect record.
    step "App Store Connect topology"; print_topology
    step "build and upload iOS TestFlight"
    APPLE_CLIENT_DIR="$ios_client_dir" ./scripts/ci/build-ios-testflight.sh
    step "build and upload macOS TestFlight"
    APPLE_CLIENT_DIR="$macos_client_dir" ./scripts/ci/build-macos-testflight.sh
    ;;
esac

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
step "result"
ls -la dist/apple/*.ipa dist/apple/*.dmg 2>/dev/null | sed 's/^/  /' || true

if [ "$APPLE_SIGNING_MODE" = "unsigned" ]; then
  cat <<'EOF'

  These are UNSIGNED artifacts: they validate that the client builds and packages
  correctly, and they have the right structure. Their App Group, Network Extension
  and System Extension do not work at runtime.

  For something you can actually run, set real Apple values and use:
      APPLE_TEAM_ID=... APPLE_BASE_BUNDLE_ID=... APPLE_APP_GROUP_ID=... \
        ./scripts/release-apple.sh development
EOF
elif [ "$APPLE_SIGNING_MODE" = "development" ]; then
  cat <<'EOF'

  Signed for development. To check it on this Mac:
      ./scripts/ci/verify-macos-runtime.sh /Applications/SFM.app

  To install the iOS build, the device must be registered and connected; see
  docs/APPLE-DEVELOPMENT-SIGNING.md.
EOF
fi
