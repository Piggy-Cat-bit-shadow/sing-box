#!/usr/bin/env bash
# Preflight for an Apple development-signed build.
#
# Usage: check-apple-signing-environment.sh
#
# # Behaviour
#
#   unsigned mode     SKIP. Nothing to check; exits 0 with an explanation.
#   development mode  Verifies everything that can be verified BEFORE xcodebuild
#                     runs, and fails with an actionable message otherwise.
#
# Checking up front matters because the failures it catches are otherwise
# expensive and confusing: a missing certificate surfaces as an opaque
# "No signing certificate found" many minutes into a build, and a mismatched App
# Group does not surface at all until the app is installed and cannot open its
# database.
#
# See docs/APPLE-DEVELOPMENT-SIGNING.md for how to obtain each value.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

eval "$(./scripts/ci/apple-signing-config.sh)"

if [ "$APPLE_SIGNING_MODE" = "unsigned" ]; then
  echo "check-apple-signing-environment: SKIP (APPLE_SIGNING_MODE=unsigned)"
  echo "  An unsigned build applies no entitlements, so there is no identity,"
  echo "  profile or App Group to validate. The artifact is a compile and packaging"
  echo "  check only; its App Group and Network Extension do not work at runtime."
  exit 0
fi

echo "check-apple-signing-environment: development mode"
fail=0

# ---------------------------------------------------------------------------
# 1. A code-signing identity for the configured team must exist.
# ---------------------------------------------------------------------------
echo "  code signing identities:"
identities="$(security find-identity -v -p codesigning 2>/dev/null || true)"
# `security` exits 0 and prints this when the keychain has no usable identity.
case "$identities" in
  *"0 valid identities found"*) identities="" ;;
esac
if [ -z "$identities" ]; then
  echo "    FAIL: no valid code signing identity is available." >&2
  echo "          Open Xcode > Settings > Accounts, sign in, and create a" >&2
  echo "          development certificate, or import your .p12 into the login" >&2
  echo "          keychain. Note that an Apple Development certificate also needs" >&2
  echo "          its intermediate; see docs/APPLE-DEVELOPMENT-SIGNING.md." >&2
  fail=1
else
  printf '%s\n' "$identities" | sed 's/^/    /'
  # The identity's team must match the configured one, or the build will pick a
  # certificate that cannot sign these bundle IDs.
  if ! printf '%s\n' "$identities" | grep -q "($APPLE_TEAM_ID)"; then
    echo "    FAIL: no signing identity found for team $APPLE_TEAM_ID." >&2
    echo "          The identities listed above belong to other teams. Either set" >&2
    echo "          APPLE_TEAM_ID to one of those teams, or create/import a" >&2
    echo "          certificate for $APPLE_TEAM_ID." >&2
    fail=1
  else
    echo "    ok: an identity for team $APPLE_TEAM_ID is present"
  fi
fi

# ---------------------------------------------------------------------------
# 2. The resolved configuration must be self-consistent.
# ---------------------------------------------------------------------------
echo "  resolved signing configuration:"
echo "    mode:       $APPLE_SIGNING_MODE"
echo "    style:      $APPLE_SIGNING_STYLE"
echo "    team:       $APPLE_TEAM_ID"
echo "    base id:    $APPLE_BASE_BUNDLE_ID"
echo "    app group:  $APPLE_APP_GROUP_ID"

# An App Group that is not prefixed with "group." is a common mistake and iOS
# rejects it at runtime rather than at build time.
case "$APPLE_APP_GROUP_ID" in
  group.*) ;;
  *)
    echo "    FAIL: APPLE_APP_GROUP_ID must start with 'group.', got '$APPLE_APP_GROUP_ID'." >&2
    fail=1
    ;;
esac

# The App Group must be distinct from the bundle ID namespace check: an app group
# shared with the tunnel must not accidentally be the app's own identifier.
if [ "$APPLE_APP_GROUP_ID" = "$APPLE_BASE_BUNDLE_ID" ]; then
  echo "    FAIL: the App Group equals the bundle ID; they are different namespaces." >&2
  fail=1
fi

if [ "$APPLE_SIGNING_STYLE" = "manual" ]; then
  echo "  manual signing profiles:"
  for pair in \
    "IOS_APP_PROFILE:${IOS_APP_PROFILE:-}" \
    "IOS_EXTENSION_PROFILE:${IOS_EXTENSION_PROFILE:-}" \
    "IOS_UI_EXTENSION_PROFILE:${IOS_UI_EXTENSION_PROFILE:-}" \
    "MACOS_APP_PROFILE:${MACOS_APP_PROFILE:-}" \
    "MACOS_SYSTEM_EXTENSION_PROFILE:${MACOS_SYSTEM_EXTENSION_PROFILE:-}" \
    "MACOS_HELPER_PROFILE:${MACOS_HELPER_PROFILE:-}"
  do
    name="${pair%%:*}"; value="${pair#*:}"
    echo "    $name = $value"
  done
  echo "    note: profile existence is verified by xcodebuild; a profile that does"
  echo "          not match its bundle ID or team fails there with a clear message."
else
  echo "  signing style: automatic (Xcode creates and manages the profiles)"
  echo "    note: this requires the Apple ID to be signed in under Xcode >"
  echo "          Settings > Accounts, with this team available."
fi

# ---------------------------------------------------------------------------
# 3. Multicast must be consistent with what the account actually has.
# ---------------------------------------------------------------------------
echo "  multicast:"
if [ "$APPLE_ENABLE_MULTICAST" = "true" ]; then
  echo "    enabled: the build will request com.apple.developer.networking.multicast."
  echo "    This REQUIRES the Multicast Networking entitlement to have been granted"
  echo "    for your account. If it has not, signing fails."
else
  echo "    disabled (default): multicast is stripped from the tunnel and system"
  echo "    extension entitlements. Set APPLE_ENABLE_MULTICAST=true once Apple"
  echo "    grants it."
fi

[ "$fail" -eq 0 ] || {
  echo "check-apple-signing-environment: FAIL" >&2
  exit 1
}
echo "check-apple-signing-environment: PASS"
