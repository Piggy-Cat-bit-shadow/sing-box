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
# Order of precedence:
#   1. variables already exported in this shell
#   2. .env.apple.local in the repository root, if present
#   3. otherwise the configuration layer reports exactly what is missing
#
# The file is read with `source` and only fills gaps, so an explicit export always
# wins and the file can never silently override a value chosen for one run. It is
# git-ignored, and .env.apple.local.example documents the shape.
local_env="$root/.env.apple.local"
if [ -f "$local_env" ]; then
  # Refuse a file that is not ignored: if someone force-added it, sourcing it would
  # quietly publish their bundle IDs on the next commit.
  if git check-ignore -q "$local_env" 2>/dev/null; then
    local_base_before="${APPLE_BASE_BUNDLE_ID:-}"
    local_group_before="${APPLE_APP_GROUP_ID:-}"
    # shellcheck disable=SC1090
    source "$local_env"
    # An exported value takes precedence: restore anything that was already set.
    [ -n "$local_base_before" ] && export APPLE_BASE_BUNDLE_ID="$local_base_before"
    [ -n "$local_group_before" ] && export APPLE_APP_GROUP_ID="$local_group_before"
    echo "configuration: loaded $local_env"
  else
    echo "release-apple: refusing to read $local_env" >&2
    echo "  That file is NOT git-ignored, so it could be committed and publish your" >&2
    echo "  bundle identifiers. Restore the .gitignore rule for .env.apple.local," >&2
    echo "  or export the values in your shell instead." >&2
    exit 2
  fi
fi

eval "$(./scripts/ci/apple-signing-config.sh)"

mkdir -p dist/apple

step() {
  echo
  echo "== $* =="
}

# ---------------------------------------------------------------------------
# Shared preflight
# ---------------------------------------------------------------------------
step "repository state"
if [ -n "$(git status --porcelain)" ]; then
  echo "  note: the working tree has uncommitted changes; they will be built as-is"
  git status --short | sed 's/^/    /'
fi
echo "  commit:   $(git rev-parse HEAD)"
echo "  submodule: clients/apple @ $(git -C clients/apple rev-parse HEAD)"
echo "  mode:     $APPLE_SIGNING_MODE"
echo "  style:    $APPLE_SIGNING_STYLE"

step "signing environment"
# In unsigned mode this prints SKIP; otherwise it fails with an actionable message
# rather than letting xcodebuild produce something unusable.
./scripts/ci/check-apple-signing-environment.sh

if [ "$APPLE_SIGNING_MODE" = "unsigned" ]; then
  step "signing regression tests"
  ./scripts/ci/test-apple-signing.sh >/dev/null
  echo "  14 checks passed"
fi

step "build Libbox from this fork"
./scripts/ci/build-apple-libbox.sh both

step "prepare the Apple client"
./scripts/ci/prepare-apple-client.sh

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
do_ios() {
  step "build signed iOS IPA"
  ./scripts/ci/build-ios-ipa.sh dist/apple/JiejieBox-${APPLE_SIGNING_MODE}.ipa
  step "verify the signed IPA"
  ./scripts/ci/verify-apple-signed-artifact.sh ios-ipa dist/apple/JiejieBox-${APPLE_SIGNING_MODE}.ipa
}

do_macos() {
  step "build signed macOS DMG"
  ./scripts/ci/build-macos-dmg.sh dist/apple/JiejieBox-macOS-${APPLE_SIGNING_MODE}.dmg
  step "verify the signed DMG"
  ./scripts/ci/verify-apple-signed-artifact.sh macos-dmg dist/apple/JiejieBox-macOS-${APPLE_SIGNING_MODE}.dmg
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
    step "build and upload iOS TestFlight"; ./scripts/ci/build-ios-testflight.sh
    ;;

  testflight-macos)
    step "App Store Connect topology"; print_topology
    step "build and upload macOS TestFlight"; ./scripts/ci/build-macos-testflight.sh
    ;;

  testflight)
    # One shared configuration, one Libbox build, one overlay, then both platforms.
    # Building Libbox and applying the overlay once matters: they are the slow steps
    # and applying the overlay twice is refused by design (it fails closed), so the
    # combined target cannot simply call the two individual ones.
    step "App Store Connect topology"; print_topology
    step "build and upload iOS TestFlight"; ./scripts/ci/build-ios-testflight.sh
    step "build and upload macOS TestFlight"; ./scripts/ci/build-macos-testflight.sh
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
