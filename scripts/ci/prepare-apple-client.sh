#!/usr/bin/env bash
# Prepares the pinned Apple client submodule for an UNSIGNED personal-test build.
#
# Usage: prepare-apple-client.sh [--submodule-sha <sha>]
#
# # Two independent overlays
#
# This script applies exactly two overlays, kept separate on purpose so one can be
# retired without disturbing the other:
#
#   [compatibility]    Adapts the pinned Apple client to this fork's libbox API.
#                      Needed because the client is pinned and its generated
#                      bindings drifted. This is a build-time source adaptation.
#
#   [personal-signing] Removes the multicast entitlement, which has to be requested
#                      from Apple separately. Once that is granted, this overlay is
#                      simply dropped and the compatibility overlay is untouched.
#
# # Why an overlay rather than editing the submodule
#
# clients/apple is a pinned upstream checkout. Committing changes inside it would
# either be lost on the next submodule checkout or turn into an unmaintainable
# private fork. The adaptation is applied to the WORKING TREE at build time, and the
# parent repository never records a modified gitlink: the submodule HEAD is asserted
# to equal the parent's gitlink before AND after.
#
# # Fail-closed
#
# Every edit is anchored on text that must exist and is verified afterwards. If the
# pinned client is ever repinned and an anchor disappears, this exits non-zero rather
# than producing a subtly wrong app. Nothing is applied with fuzzy matching.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# Signing configuration drives the entitlement overlay (multicast). Sourced here
# rather than passed in so the overlay always sees the same resolved values the
# build will use.
eval "$("$root/scripts/ci/apple-signing-config.sh")"

expected_sha=""
while [ $# -gt 0 ]; do
  case "$1" in
    --submodule-sha) expected_sha="$2"; shift 2 ;;
    *) echo "prepare-apple-client.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

submodule_path="clients/apple"
platform_swift="$submodule_path/Library/Network/ExtensionPlatformInterface.swift"
provider_swift="$submodule_path/Library/Network/ExtensionProvider.swift"
extension_entitlements="$submodule_path/Extension/Extension.entitlements"

if [ ! -e "$submodule_path/.git" ] && [ ! -d "$submodule_path/.git" ]; then
  echo "FAIL: $submodule_path is not a checked-out submodule." >&2
  echo "      Run: git submodule update --init --recursive" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 0. The submodule must be exactly the commit the parent records.
# ---------------------------------------------------------------------------
recorded_sha="$(git ls-tree HEAD "$submodule_path" | awk '{print $3}')"
actual_sha="$(git -C "$submodule_path" rev-parse HEAD)"

if [ -z "$recorded_sha" ]; then
  echo "FAIL: the parent repository records no gitlink for $submodule_path." >&2
  exit 1
fi
if [ "$actual_sha" != "$recorded_sha" ]; then
  echo "FAIL: submodule is not at the commit the parent repository records." >&2
  echo "  parent records: $recorded_sha" >&2
  echo "  checked out:    $actual_sha" >&2
  exit 1
fi
if [ -n "$expected_sha" ] && [ "$actual_sha" != "$expected_sha" ]; then
  echo "FAIL: submodule SHA $actual_sha does not match the requested $expected_sha." >&2
  exit 1
fi
echo "submodule: $submodule_path @ $actual_sha (matches the parent gitlink)"

# ---------------------------------------------------------------------------
# 1. [compatibility] Adapt the pinned client to this fork's libbox API.
# ---------------------------------------------------------------------------
echo "overlay [compatibility]: libbox API"

for f in "$platform_swift" "$provider_swift"; do
  if [ ! -f "$f" ]; then
    echo "FAIL: $f does not exist; the pinned client was restructured." >&2
    exit 1
  fi
done

# Anchors: existing code this overlay attaches to. Their presence proves we are
# patching the revision it was written for.
if ! grep -qF "public func usePlatformAutoDetectControl() -> Bool {" "$platform_swift"; then
  echo "FAIL: anchor 'usePlatformAutoDetectControl' not found in $platform_swift." >&2
  echo "      The pinned client changed; this overlay must be reviewed." >&2
  exit 1
fi
if ! grep -qF "LibboxPromotePowerReportDraft()" "$provider_swift"; then
  echo "FAIL: $provider_swift no longer calls LibboxPromotePowerReportDraft();" >&2
  echo "      its compatibility shim is no longer needed or no longer correct." >&2
  exit 1
fi

# Refuse to apply twice rather than appending a second copy.
if grep -qF "func usePlatformAutoRedirect() -> Bool" "$platform_swift"; then
  echo "FAIL: the compatibility overlay appears to be already applied." >&2
  exit 1
fi

python3 "$root/scripts/ci/apply-apple-compat-overlay.py" "$platform_swift"

# --- verify what was written actually says what we intend -------------------
checks_failed=0
for required in \
  "func usePlatformAutoRedirect() -> Bool {" \
  "func createAutoRedirect(_ options: Data?, handler: LibboxAutoRedirectHandlerProtocol?) throws -> LibboxAutoRedirectSessionProtocol {" \
  "auto redirect is not supported on Apple platforms" \
  "func LibboxPromotePowerReportDraft()"
do
  if ! grep -qF "$required" "$platform_swift"; then
    echo "FAIL: expected '$required' after applying the compatibility overlay" >&2
    checks_failed=1
  fi
done

# Behaviour-critical: redirect stays OFF, creation stays UNSUPPORTED. A future
# "fix" that turns these into stub successes is caught here.
if ! python3 "$root/scripts/ci/check-apple-compat-overlay.py" "$platform_swift"; then
  checks_failed=1
fi

# Notification must NOT have been shimmed: exactly one implementation of send(_:).
send_count="$(grep -cE "func send\(_ notification: LibboxNotification\?\) throws" "$platform_swift" || true)"
if [ "$send_count" != "1" ]; then
  echo "FAIL: expected exactly one send(_:) implementation, found $send_count." >&2
  echo "      Notification delivery must keep a single implementation." >&2
  checks_failed=1
fi

[ "$checks_failed" -eq 0 ] || exit 1
echo "  [compatibility] usePlatformAutoRedirect -> false"
echo "  [compatibility] createAutoRedirect      -> explicit unsupported error"
echo "  [compatibility] PromotePowerReportDraft -> no-op (no draft entry point in this libbox)"
echo "  [compatibility] notification send(_:)   -> untouched, single implementation"

# ---------------------------------------------------------------------------
# 1b. [compatibility] Fix AppConfiguration.teamID.
# ---------------------------------------------------------------------------
# teamID is interpolated into XPC and System Extension code-signing requirements
# of the form `certificate leaf[subject.OU] = "<teamID>"`. It was derived by
# splitting the App Group name on the first dot, which cannot produce a team id
# under any App Group convention this project uses ("group" or "TEAMIDio"), so
# those requirements could never be satisfied and every XPC connection would be
# rejected at runtime. The build's real team is carried in the bundle instead.
python3 "$root/scripts/ci/fix-apple-team-id.py" "$submodule_path"

# ---------------------------------------------------------------------------
# 2. [entitlements] Multicast switch and App Group consistency.
# ---------------------------------------------------------------------------
# Multicast Networking must be requested from Apple separately, so it is off by
# default and stripped from every target that would declare it. Once granted,
# APPLE_ENABLE_MULTICAST=true keeps it and no further edit is needed.
#
# Both products are handled, not just iOS: the macOS System Extension declares the
# same capability and would fail to sign for the same reason.
echo "overlay [entitlements]: multicast=$APPLE_ENABLE_MULTICAST"

# The targets that actually participate in the two shipped products. Enumerated
# from the verified builds rather than from the project's full target list, which
# also contains tvOS and UI-test targets this fork does not ship.
ios_app_entitlements="$submodule_path/SFI/SFI.entitlements"
ios_tunnel_entitlements="$submodule_path/Extension/Extension.entitlements"
ios_intents_entitlements="$submodule_path/IntentsExtension/IntentsExtension.entitlements"
macos_app_entitlements="$submodule_path/SFM.System/SFM.entitlements"
macos_sysext_entitlements="$submodule_path/SystemExtension/SystemExtension.entitlements"
macos_share_entitlements="$submodule_path/ShareExtension.System/ShareExtension.entitlements"
macos_helper_entitlements="$submodule_path/HelperService/RootHelper.entitlements"

for f in "$ios_app_entitlements" "$ios_tunnel_entitlements" \
         "$macos_app_entitlements" "$macos_sysext_entitlements" \
         "$macos_share_entitlements" "$macos_helper_entitlements"; do
  if [ ! -f "$f" ]; then
    echo "FAIL: $f does not exist; the pinned client was restructured." >&2
    exit 1
  fi
done

read_plist() { plutil -convert xml1 -o - "$1" 2>/dev/null || cat "$1"; }
has_key() {
  if read_plist "$1" | grep -q "<key>$2</key>"; then echo 1; else echo 0; fi
}

fail=0

# --- multicast ---------------------------------------------------------------
if [ "$APPLE_ENABLE_MULTICAST" = "true" ]; then
  for f in "$ios_tunnel_entitlements" "$macos_sysext_entitlements"; do
    if [ "$(has_key "$f" com.apple.developer.networking.multicast)" != "1" ]; then
      echo "FAIL: $APPLE_ENABLE_MULTICAST=true but $(basename "$f") declares no multicast" >&2
      fail=1
    fi
  done
  echo "  [entitlements] multicast kept (APPLE_ENABLE_MULTICAST=true)"
else
  for f in "$ios_tunnel_entitlements" "$macos_sysext_entitlements"; do
    if [ "$(has_key "$f" com.apple.developer.networking.multicast)" = "1" ]; then
      /usr/libexec/PlistBuddy -c "Delete :com.apple.developer.networking.multicast" "$f" >/dev/null 2>&1 || true
      if [ "$(has_key "$f" com.apple.developer.networking.multicast)" != "0" ]; then
        echo "FAIL: could not remove multicast from $f" >&2; fail=1
      else
        echo "  [entitlements] removed multicast from $(basename "$(dirname "$f")")"
      fi
    fi
  done
fi

# --- the tunnel capabilities must survive whatever we did above --------------
# iOS: losing packet-tunnel-provider would install but never connect.
if [ "$(has_key "$ios_tunnel_entitlements" com.apple.developer.networking.networkextension)" != "1" ]; then
  echo "FAIL: iOS extension lost com.apple.developer.networking.networkextension" >&2; fail=1
elif ! read_plist "$ios_tunnel_entitlements" | grep -q "packet-tunnel-provider"; then
  echo "FAIL: iOS extension no longer lists packet-tunnel-provider" >&2; fail=1
else
  echo "  [entitlements] iOS extension keeps packet-tunnel-provider"
fi

# macOS uses the System Extension variant of the same capability.
if [ "$(has_key "$macos_sysext_entitlements" com.apple.developer.networking.networkextension)" != "1" ]; then
  echo "FAIL: macOS system extension lost the networkextension entitlement" >&2; fail=1
elif ! read_plist "$macos_sysext_entitlements" | grep -q "packet-tunnel-provider-systemextension"; then
  echo "FAIL: macOS system extension no longer lists packet-tunnel-provider-systemextension" >&2; fail=1
else
  echo "  [entitlements] macOS system extension keeps packet-tunnel-provider-systemextension"
fi

# The host app must be allowed to install the system extension.
if [ "$(has_key "$macos_app_entitlements" com.apple.developer.system-extension.install)" != "1" ]; then
  echo "FAIL: macOS app lost com.apple.developer.system-extension.install" >&2; fail=1
else
  echo "  [entitlements] macOS app keeps system-extension.install"
fi

# --- App Group consistency ---------------------------------------------------
# This is the failure that was actually observed at runtime: the client could not
# write its App Group database. The cause is a host app and extension resolving to
# DIFFERENT groups, which no build-time signature check would catch, because each
# signature is individually valid.
#
# Every participating target must resolve to the same group. The value is compared
# after substitution so that a target using $(TeamIdentifierPrefix) is checked in
# its expanded form rather than assumed to be right.
app_group_for() {
  read_plist "$1" | python3 -c '
import plistlib, sys
data = sys.stdin.buffer.read()
try:
    plist = plistlib.loads(data)
except Exception:
    print(""); raise SystemExit
groups = plist.get("com.apple.security.application-groups") or []
print(groups[0] if groups else "")
'
}

# --- iCloud switch -----------------------------------------------------------
# iCloud drive is a real profile backend here, not dead weight: the client offers
# Local / iCloud / Remote storage. It is off by default because enabling it means
# creating an iCloud container and assigning it to two more App IDs, which is pure
# setup cost for personal testing, and the client copes without it -
# FilePath.iCloudDirectory falls back to a stub URL when the ubiquity container is
# unavailable, and the Local backend is unaffected.
echo "overlay [entitlements]: icloud=$APPLE_ENABLE_ICLOUD"
for f in "$ios_app_entitlements" "$ios_intents_entitlements" "$macos_app_entitlements"; do
  [ -f "$f" ] || continue
  if [ "$APPLE_ENABLE_ICLOUD" = "true" ]; then
    continue
  fi
  removed_any=0
  for key in \
    com.apple.developer.icloud-container-identifiers \
    com.apple.developer.icloud-services \
    com.apple.developer.ubiquity-container-identifiers
  do
    if [ "$(has_key "$f" "$key")" = "1" ]; then
      /usr/libexec/PlistBuddy -c "Delete :$key" "$f" >/dev/null 2>&1 || true
      if [ "$(has_key "$f" "$key")" != "0" ]; then
        echo "FAIL: could not remove $key from $f" >&2; fail=1
      else
        removed_any=1
      fi
    fi
  done
  if [ "$removed_any" = "1" ]; then
    echo "  [entitlements] removed iCloud entitlements from $(basename "$(dirname "$f")")"
  else
    echo "  [entitlements] $(basename "$(dirname "$f")"): no iCloud entitlements to remove"
  fi
done

# --- the macOS targets must use the SAME group form as iOS -------------------
#
# Upstream's project is inconsistent here, and the macOS side is wrong:
#
#   iOS   SFI.entitlements and Extension.entitlements use $(APP_GROUP_IDENTIFIER),
#         which the project defines as "group.$(BASE_PACKAGE_IDENTIFIER)".
#   macOS SFM.System and SystemExtension use
#         "$(TeamIdentifierPrefix)$(BASE_PACKAGE_IDENTIFIER)".
#
# TeamIdentifierPrefix is supplied by provisioning and is EMPTY outside a signed
# build, so the macOS value collapses to a bare bundle identifier. An App Group
# without the "group." prefix is not a valid group at all, which is exactly the
# "client cannot write App Group database" failure observed at runtime: the xpc
# service and the app resolve to different, unusable containers.
#
# Rewriting the macOS entitlements to the same $(APP_GROUP_IDENTIFIER) the iOS side
# already uses makes every target agree by construction, rather than by hoping two
# different expressions happen to coincide. It also removes the empty-prefix
# collapse, since APP_GROUP_IDENTIFIER has no provisioning dependency.
macos_group_files="$macos_app_entitlements $macos_sysext_entitlements $macos_share_entitlements $macos_helper_entitlements"
for f in $macos_group_files; do
  current="$(app_group_for "$f")"
  case "$current" in
    *'$(TeamIdentifierPrefix)'*)
      /usr/libexec/PlistBuddy -c "Set :com.apple.security.application-groups:0 \$(APP_GROUP_IDENTIFIER)" "$f" >/dev/null 2>&1 || true
      updated="$(app_group_for "$f")"
      if [ "$updated" != '$(APP_GROUP_IDENTIFIER)' ]; then
        echo "FAIL: could not normalise the App Group in $f (still '$updated')" >&2; fail=1
      else
        echo "  [app-group] normalised $(basename "$(dirname "$f")") to \$(APP_GROUP_IDENTIFIER)"
      fi
      ;;
  esac
done

app_group_for() {
  read_plist "$1" | python3 -c '
import plistlib, sys
data = sys.stdin.buffer.read()
try:
    plist = plistlib.loads(data)
except Exception:
    print(""); raise SystemExit
groups = plist.get("com.apple.security.application-groups") or []
print(groups[0] if groups else "")
'
}

groups_seen=""
for f in "$ios_app_entitlements" "$ios_tunnel_entitlements" \
         "$macos_app_entitlements" "$macos_sysext_entitlements" \
         "$macos_share_entitlements" "$macos_helper_entitlements"; do
  raw="$(app_group_for "$f")"
  if [ -z "$raw" ]; then
    echo "FAIL: $(basename "$(dirname "$f")") declares no App Group" >&2; fail=1
    continue
  fi
  # Expand the build settings the project uses, so the comparison is on the value
  # that will actually be signed. TeamIdentifierPrefix is expanded to the
  # configured team, which is what provisioning supplies at build time.
  expanded="$(printf '%s' "$raw" | sed "s/\$(TeamIdentifierPrefix)/${APPLE_TEAM_ID:-}/g; s/\$(BASE_PACKAGE_IDENTIFIER)/${APPLE_BASE_BUNDLE_ID}/g; s/\$(APP_GROUP_IDENTIFIER)/${APPLE_APP_GROUP_ID}/g")"
  echo "  [app-group] $(basename "$(dirname "$f")"): $expanded"
  case "$expanded" in
    *'$('*)
      echo "FAIL: $(basename "$f") uses an unexpanded build setting: $expanded" >&2; fail=1 ;;
  esac
  case " $groups_seen " in
    *" $expanded "*) ;;
    *) groups_seen="$groups_seen $expanded" ;;
  esac
done

group_count="$(printf '%s' "$groups_seen" | wc -w | tr -d ' ')"
if [ "$group_count" != "1" ]; then
  echo "FAIL: the targets resolve to $group_count different App Groups:$groups_seen" >&2
  echo "      The host app and its extensions MUST share one group, or the client" >&2
  echo "      cannot open its database at runtime." >&2
  fail=1
else
  echo "  [app-group] all targets agree on:$groups_seen"
fi

# Every entitlements file must still be a valid plist.
for f in "$ios_app_entitlements" "$ios_tunnel_entitlements" \
         "$macos_app_entitlements" "$macos_sysext_entitlements" \
         "$macos_share_entitlements" "$macos_helper_entitlements"; do
  if ! plutil -lint "$f" >/dev/null 2>&1; then
    echo "FAIL: $f is no longer a valid plist" >&2; fail=1
  fi
done

[ "$fail" -eq 0 ] || exit 1

# ---------------------------------------------------------------------------
# 3. The submodule HEAD must be untouched by all of the above.
# ---------------------------------------------------------------------------
final_sha="$(git -C "$submodule_path" rev-parse HEAD)"
if [ "$final_sha" != "$recorded_sha" ]; then
  echo "FAIL: the submodule HEAD moved during preparation." >&2
  exit 1
fi
echo "submodule HEAD unchanged: $final_sha"
echo "prepare-apple-client: PASS"
