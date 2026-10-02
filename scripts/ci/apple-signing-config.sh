#!/usr/bin/env bash
# Central Apple signing configuration for the Jiejie fork.
#
# Sourced by the Apple build scripts and the preflight check. Every signing value
# lives here or in the environment, so no Team ID, bundle ID, App Group or profile
# name is scattered through the build commands, and none of it is committed.
#
# Usage:
#   eval "$(./scripts/ci/apple-signing-config.sh)"
#
# or, to inspect what a mode would resolve to:
#   ./scripts/ci/apple-signing-config.sh --print
#
# # Why this exists
#
# The Apple scripts must work in two very different situations:
#
#   unsigned     no Apple account. Produces structurally correct artifacts for CI
#                and for packaging checks. Entitlements are NOT applied and the
#                App Group and System Extension do NOT work at runtime.
#
#   development  the developer's own Apple Developer Program account, own Mac and
#                own device. Produces runnable, correctly entitled artifacts.
#
# The transition between them must be configuration only. This file is the whole
# of that configuration surface.
#
# # Fail closed
#
# In development mode a missing value is an ERROR, never a silent downgrade to
# unsigned. A build that quietly falls back would produce an artifact that looks
# fine and cannot connect, which is exactly the failure this work exists to
# prevent.
set -euo pipefail

# ---------------------------------------------------------------------------
# Mode
# ---------------------------------------------------------------------------
APPLE_SIGNING_MODE="${APPLE_SIGNING_MODE:-unsigned}"
case "$APPLE_SIGNING_MODE" in
  unsigned|development|testflight) ;;
  *)
    echo "apple-signing-config: APPLE_SIGNING_MODE must be 'unsigned', 'development' or 'testflight', got '$APPLE_SIGNING_MODE'" >&2
    exit 2
    ;;
esac

# Automatic lets Xcode manage provisioning, which is what a local development
# build on one's own machine wants. Manual takes explicit profiles, which is what
# CI would use once it has the secrets. Both are supported; the default suits the
# local case because that is the first target.
APPLE_SIGNING_STYLE="${APPLE_SIGNING_STYLE:-automatic}"
case "$APPLE_SIGNING_STYLE" in
  automatic|manual) ;;
  *)
    echo "apple-signing-config: APPLE_SIGNING_STYLE must be 'automatic' or 'manual', got '$APPLE_SIGNING_STYLE'" >&2
    exit 2
    ;;
esac

# iCloud drive is a real profile-storage backend in this client (see
# ApplicationLibrary/Views/Profile/EditProfileView.swift, where iCloud is one of
# Local / iCloud / Remote). It is nevertheless switched, because enabling it means
# creating an iCloud container and assigning it to two more App IDs, and the client
# degrades cleanly without it: FilePath.iCloudDirectory falls back to a stub URL
# when the ubiquity container is unavailable, and the Local backend is unaffected.
APPLE_ENABLE_ICLOUD="${APPLE_ENABLE_ICLOUD:-false}"
case "$APPLE_ENABLE_ICLOUD" in
  true|false) ;;
  *)
    echo "apple-signing-config: APPLE_ENABLE_ICLOUD must be 'true' or 'false', got '$APPLE_ENABLE_ICLOUD'" >&2
    exit 2
    ;;
esac

# Multicast Networking must be requested from Apple separately, so it is off by
# default. Turning it on is the only change needed once it is granted.
APPLE_ENABLE_MULTICAST="${APPLE_ENABLE_MULTICAST:-false}"
case "$APPLE_ENABLE_MULTICAST" in
  true|false) ;;
  *)
    echo "apple-signing-config: APPLE_ENABLE_MULTICAST must be 'true' or 'false', got '$APPLE_ENABLE_MULTICAST'" >&2
    exit 2
    ;;
esac

# ---------------------------------------------------------------------------
# Values required only in development mode.
# ---------------------------------------------------------------------------
missing=()

require() {
  local name="$1"
  local value="$2"
  if [ -z "$value" ]; then
    missing+=("$name")
  fi
}

# development and testflight both sign with a real identity; only the export
# destination differs (a local IPA versus App Store Connect).
if [ "$APPLE_SIGNING_MODE" != "unsigned" ]; then
  # --- identity ---------------------------------------------------------
  # If APPLE_TEAM_ID was not supplied, derive it from the signing certificate
  # rather than making the user look it up. The team is the certificate's OU field,
  # NOT the value in its name: for
  #   "Apple Development: <name> (ABCDE12345)"  ->  CN identifier is ABCDE12345
  # while the team is the OU, and the two are frequently different. Using the name
  # value fails with `No Account for Team "<wrong>"`, which reads as a missing
  # account even though the account is present and signed in.
  if [ -z "${APPLE_TEAM_ID:-}" ]; then
    # `|| true` matters: on a machine with no Apple Development certificate (CI,
    # or a fresh checkout) `security` exits non-zero, and under `set -o pipefail`
    # that aborts the whole assignment - turning "no certificate to detect a team
    # from" into a hard failure of a script that only needed a fallback value.
    detected_team="$(security find-certificate -a -c "Apple Development" -p 2>/dev/null \
      | openssl x509 -noout -subject 2>/dev/null \
      | tr ',' '\n' | grep -oE 'OU=[A-Z0-9]+' | cut -d= -f2 | sort -u | head -1 || true)"
    if [ -n "$detected_team" ]; then
      APPLE_TEAM_ID="$detected_team"
      APPLE_TEAM_ID_DETECTED=1
    fi
  fi
  require APPLE_TEAM_ID "${APPLE_TEAM_ID:-}"

  # The bundle identifier base every target derives from. The project already
  # builds its identifiers as $(BASE_PACKAGE_IDENTIFIER) plus a suffix, so
  # setting this one value produces the whole consistent set.
  require APPLE_BASE_BUNDLE_ID "${APPLE_BASE_BUNDLE_ID:-}"

  # The App Group shared by the host app and its tunnel/network extension. The
  # first fatal runtime error observed was the client being unable to write its
  # App Group database, so this is required rather than derived: a wrong or
  # mismatched value fails silently at runtime rather than at build time.
  require APPLE_APP_GROUP_ID "${APPLE_APP_GROUP_ID:-}"

  # Manual signing needs explicit profiles. Automatic signing has Xcode create
  # and manage them, so they are deliberately not required there.
  if [ "$APPLE_SIGNING_STYLE" = "manual" ]; then
    require IOS_APP_PROFILE "${IOS_APP_PROFILE:-}"
    require IOS_EXTENSION_PROFILE "${IOS_EXTENSION_PROFILE:-}"
    require IOS_UI_EXTENSION_PROFILE "${IOS_UI_EXTENSION_PROFILE:-}"
    require MACOS_APP_PROFILE "${MACOS_APP_PROFILE:-}"
    require MACOS_SYSTEM_EXTENSION_PROFILE "${MACOS_SYSTEM_EXTENSION_PROFILE:-}"
    require MACOS_HELPER_PROFILE "${MACOS_HELPER_PROFILE:-}"
  fi
fi

if [ "${#missing[@]}" -gt 0 ]; then
  {
    echo "apple-signing-config: APPLE_SIGNING_MODE=$APPLE_SIGNING_MODE is missing required configuration:"
    for name in "${missing[@]}"; do
      echo "  - $name"
    done
    echo
    echo "These are intentionally NOT stored in the repository. Export them in your"
    echo "shell (or a local, git-ignored file you source) and re-run. See"
    echo "docs/APPLE-DEVELOPMENT-SIGNING.md."
    echo
    echo "Refusing to continue: falling back to an unsigned build here would produce"
    echo "an artifact that builds and installs but cannot reach its App Group or"
    echo "start its tunnel."
  } >&2
  exit 3
fi

# A signed build that still carries upstream's identity means the override did not
# take effect. This check exists because that failure is otherwise invisible: the
# build succeeds and the artifact is simply unusable on the developer's account.
UPSTREAM_TEAM_ID="P8XK3KHB48"
UPSTREAM_BUNDLE_PREFIX="io.nekohasekai"

if [ "$APPLE_SIGNING_MODE" != "unsigned" ]; then
  if [ "${APPLE_TEAM_ID:-}" = "$UPSTREAM_TEAM_ID" ]; then
    echo "apple-signing-config: APPLE_TEAM_ID is upstream's team ($UPSTREAM_TEAM_ID)." >&2
    echo "  A development build must use your own team, or signing will fail with a" >&2
    echo "  profile that does not match this project." >&2
    exit 3
  fi
  case "${APPLE_BASE_BUNDLE_ID:-}" in
    "$UPSTREAM_BUNDLE_PREFIX".*|"$UPSTREAM_BUNDLE_PREFIX")
      echo "apple-signing-config: APPLE_BASE_BUNDLE_ID is still upstream's ($APPLE_BASE_BUNDLE_ID)." >&2
      echo "  Set it to an identifier your team owns." >&2
      exit 3
      ;;
  esac
fi

# ---------------------------------------------------------------------------
# Derived values
# ---------------------------------------------------------------------------
# Every target's identifier is the base plus the suffix the project already uses,
# so one value keeps the whole set consistent.
base="${APPLE_BASE_BUNDLE_ID:-$UPSTREAM_BUNDLE_PREFIX.sfamt}"
APPLE_IOS_APP_BUNDLE_ID="$base"
# The macOS App Store app is the SFM target, and it already uses the SAME bundle
# identifier as iOS. That is what makes one App Store Connect record possible:
#
#   SFI        <base>             sandboxed, packet-tunnel-provider   (iOS)
#   SFM        <base>             sandboxed, packet-tunnel-provider   (macOS)
#   SFM.System <base>.standalone  no sandbox, System Extension        (Developer ID)
#
# SFM.System is upstream's stand-alone distribution: it installs a System Extension
# and a privileged helper, so it cannot be sandboxed and is not an App Store product.
# It keeps the .standalone suffix and is NOT part of the single-record model. The
# suffix is load-bearing rather than cosmetic - it appears in code-signing
# requirement strings (CommandXPC, RootHelperService, the helper's launchd plist),
# so those must keep matching whatever that target is actually called.
APPLE_IOS_EXTENSION_BUNDLE_ID="$base.extension"
APPLE_MACOS_APP_BUNDLE_ID="$base"
APPLE_MACOS_SYSTEM_EXTENSION_BUNDLE_ID="$base.system"
# The Developer ID stand-alone product, which is not an App Store record.
APPLE_MACOS_STANDALONE_BUNDLE_ID="$base.standalone"

group="${APPLE_APP_GROUP_ID:-group.$UPSTREAM_BUNDLE_PREFIX.sfamt}"

if [ "${1:-}" = "--print" ]; then
  cat <<EOF
APPLE_SIGNING_MODE=$APPLE_SIGNING_MODE
APPLE_SIGNING_STYLE=$APPLE_SIGNING_STYLE
APPLE_ENABLE_MULTICAST=$APPLE_ENABLE_MULTICAST
APPLE_ENABLE_ICLOUD=$APPLE_ENABLE_ICLOUD
APPLE_TEAM_ID=${APPLE_TEAM_ID:-}
APPLE_TEAM_ID_DETECTED=${APPLE_TEAM_ID_DETECTED:-0}
APPLE_BASE_BUNDLE_ID=$base
APPLE_APP_GROUP_ID=$group
APPLE_IOS_APP_BUNDLE_ID=$APPLE_IOS_APP_BUNDLE_ID
APPLE_IOS_EXTENSION_BUNDLE_ID=$APPLE_IOS_EXTENSION_BUNDLE_ID
APPLE_MACOS_APP_BUNDLE_ID=$APPLE_MACOS_APP_BUNDLE_ID
APPLE_MACOS_STANDALONE_BUNDLE_ID=$APPLE_MACOS_STANDALONE_BUNDLE_ID
APPLE_MACOS_SYSTEM_EXTENSION_BUNDLE_ID=$APPLE_MACOS_SYSTEM_EXTENSION_BUNDLE_ID
EOF
  exit 0
fi

# Emit as shell assignments for callers that eval this.
cat <<EOF
APPLE_SIGNING_MODE=$APPLE_SIGNING_MODE
APPLE_SIGNING_STYLE=$APPLE_SIGNING_STYLE
APPLE_ENABLE_MULTICAST=$APPLE_ENABLE_MULTICAST
APPLE_ENABLE_ICLOUD=$APPLE_ENABLE_ICLOUD
APPLE_TEAM_ID=${APPLE_TEAM_ID:-}
APPLE_TEAM_ID_DETECTED=${APPLE_TEAM_ID_DETECTED:-0}
APPLE_BASE_BUNDLE_ID=$base
APPLE_APP_GROUP_ID=$group
APPLE_IOS_APP_BUNDLE_ID=$APPLE_IOS_APP_BUNDLE_ID
APPLE_IOS_EXTENSION_BUNDLE_ID=$APPLE_IOS_EXTENSION_BUNDLE_ID
APPLE_MACOS_APP_BUNDLE_ID=$APPLE_MACOS_APP_BUNDLE_ID
APPLE_MACOS_STANDALONE_BUNDLE_ID=$APPLE_MACOS_STANDALONE_BUNDLE_ID
APPLE_MACOS_SYSTEM_EXTENSION_BUNDLE_ID=$APPLE_MACOS_SYSTEM_EXTENSION_BUNDLE_ID
EOF
