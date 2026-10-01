#!/usr/bin/env bash
# One command to produce a signed Apple artifact.
#
# Usage:
#   ./scripts/release-apple.sh development        signed iOS IPA and macOS DMG
#   ./scripts/release-apple.sh development-ios    signed iOS IPA
#   ./scripts/release-apple.sh development-macos  signed macOS DMG
#   ./scripts/release-apple.sh testflight         TestFlight archive and upload
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
  development|development-ios|development-macos|testflight) ;;
  unsigned) ;;
  ""|-h|--help)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "release-apple.sh: unknown target '$target'" >&2
    echo "  expected one of: development, development-ios, development-macos, testflight, unsigned" >&2
    exit 2
    ;;
esac

export APPLE_SIGNING_MODE="${APPLE_SIGNING_MODE:-$([ "$target" = "unsigned" ] && echo unsigned || ([ "$target" = "testflight" ] && echo testflight || echo development))}"
export APPLE_SIGNING_STYLE="${APPLE_SIGNING_STYLE:-automatic}"

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
  ./scripts/ci/build-ios-ipa.sh dist/apple/SFI-${APPLE_SIGNING_MODE}.ipa
  step "verify the signed IPA"
  ./scripts/ci/verify-apple-signed-artifact.sh ios-ipa dist/apple/SFI-${APPLE_SIGNING_MODE}.ipa
}

do_macos() {
  step "build signed macOS DMG"
  ./scripts/ci/build-macos-dmg.sh dist/apple/SFM-${APPLE_SIGNING_MODE}.dmg
  step "verify the signed DMG"
  ./scripts/ci/verify-apple-signed-artifact.sh macos-dmg dist/apple/SFM-${APPLE_SIGNING_MODE}.dmg
}

case "$target" in
  development)       do_ios; do_macos ;;
  development-ios)   do_ios ;;
  development-macos) do_macos ;;
  unsigned)          do_ios; do_macos ;;
  testflight)        step "build and upload TestFlight"; ./scripts/ci/build-ios-testflight.sh ;;
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
