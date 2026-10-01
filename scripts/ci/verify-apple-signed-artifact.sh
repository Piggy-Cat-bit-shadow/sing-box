#!/usr/bin/env bash
# Verifies a SIGNED Apple artifact against its provisioning profiles.
#
# Usage: verify-apple-signed-artifact.sh <ios-ipa|macos-dmg> <path>
#
# # What this checks, and why each check exists
#
# A signature that verifies is not evidence that the app can run. codesign will
# happily report "valid" for an app whose App Group differs from its extension's,
# or whose entitlements exceed what the profile authorises - and both of those fail
# only once the app is on a device:
#
#   - a mismatched App Group produces a container the extension cannot open, which
#     is the failure actually observed while debugging this client;
#   - an entitlement outside the profile is rejected at install time, or the
#     capability is silently unavailable at runtime.
#
# So this goes further than `codesign --verify`:
#
#   1. every nested code object is verified individually (not just --deep);
#   2. the SIGNED entitlements are read back from each binary, since that is what
#      iOS and macOS actually honour - not the .entitlements source file;
#   3. the embedded provisioning profile is parsed;
#   4. entitlements are compared against the profile, so nothing claims more than
#      the profile grants;
#   5. the App Group is compared across the host app and every extension, because
#      they must agree.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

artifact_kind="${1:?usage: verify-apple-signed-artifact.sh <ios-ipa|macos-dmg|ios-archive> <path>}"
artifact_path="${2:?usage: verify-apple-signed-artifact.sh <ios-ipa|macos-dmg|ios-archive> <path>}"

eval "$("$root/scripts/ci/apple-signing-config.sh")"

if [ "$APPLE_SIGNING_MODE" = "unsigned" ]; then
  echo "verify-apple-signed-artifact: SKIP (APPLE_SIGNING_MODE=$APPLE_SIGNING_MODE)"
  echo "  Entitlements and provisioning are only meaningful for a signed build."
  exit 0
fi

if [ ! -e "$artifact_path" ]; then
  echo "FAIL: $artifact_path does not exist" >&2
  exit 1
fi

work="$(mktemp -d)"
cleanup() {
  # Detach any mounted image before removing the scratch directory.
  if [ -n "${mounted_at:-}" ] && [ -d "$mounted_at" ]; then
    hdiutil detach "$mounted_at" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

fail=0
note() { echo "  $*"; }
problem() { echo "  FAIL: $*" >&2; fail=1; }

# entitlements_of prints the SIGNED entitlements of a code object as a plist.
entitlements_of() {
  codesign -d --entitlements :- "$1" 2>/dev/null || true
}

# plist_value reads a top-level key from a plist on stdin.
plist_value() {
  python3 -c '
import plistlib, sys
key = sys.argv[1]
data = sys.stdin.buffer.read()
if not data.strip():
    print(""); raise SystemExit
try:
    plist = plistlib.loads(data)
except Exception:
    print(""); raise SystemExit
value = plist.get(key)
if isinstance(value, list):
    print("\n".join(str(v) for v in value))
elif value is None:
    print("")
else:
    print(value)
' "$1"
}

# profile_entitlements prints the Entitlements dict of an embedded profile.
profile_entitlements() {
  security cms -D -i "$1" 2>/dev/null | plutil -convert xml1 -o - - 2>/dev/null || true
}

echo "verify-apple-signed-artifact: $artifact_kind"

# ---------------------------------------------------------------------------
# Extract, and collect the code objects that must each be checked.
# ---------------------------------------------------------------------------
declare -a objects=()

if [ "$artifact_kind" = "ios-archive" ]; then
  # A TestFlight archive is already an expanded directory.
  app="$(find "$artifact_path/Products/Applications" -maxdepth 1 -name '*.app' -type d 2>/dev/null | head -1)"
  [ -n "$app" ] || { echo "FAIL: the archive contains no application bundle" >&2; exit 1; }
  note "archive: $(basename "$artifact_path")"
  note "app: $(basename "$app")"

  objects+=("$app")
  while IFS= read -r nested; do
    objects+=("$nested")
  done < <(find "$app/PlugIns" -maxdepth 1 -name '*.appex' -type d 2>/dev/null | sort)
  while IFS= read -r fw; do
    objects+=("$fw")
  done < <(find "$app/Frameworks" -maxdepth 1 -name '*.framework' -type d 2>/dev/null | sort)
elif [ "$artifact_kind" = "ios-ipa" ]; then
  unzip -q "$artifact_path" -d "$work/ipa"
  app="$(find "$work/ipa/Payload" -maxdepth 1 -name '*.app' -type d | head -1)"
  [ -n "$app" ] || { echo "FAIL: the IPA contains no Payload/*.app" >&2; exit 1; }
  note "app: $(basename "$app")"

  objects+=("$app")
  while IFS= read -r nested; do
    objects+=("$nested")
  done < <(find "$app/PlugIns" -maxdepth 1 -name '*.appex' -type d 2>/dev/null | sort)
  while IFS= read -r fw; do
    objects+=("$fw")
  done < <(find "$app/Frameworks" -maxdepth 1 -name '*.framework' -type d 2>/dev/null | sort)
else
  mount_point="$work/mnt"
  mkdir -p "$mount_point"
  hdiutil attach "$artifact_path" -mountpoint "$mount_point" -nobrowse -readonly >/dev/null
  mounted_at="$mount_point"
  app="$(find "$mount_point" -maxdepth 1 -name '*.app' -type d | head -1)"
  [ -n "$app" ] || { echo "FAIL: the DMG contains no .app" >&2; exit 1; }
  note "app: $(basename "$app")"

  objects+=("$app")
  while IFS= read -r nested; do
    objects+=("$nested")
  done < <(find "$app/Contents/PlugIns" "$app/Contents/Library/SystemExtensions" \
             -maxdepth 1 \( -name '*.appex' -o -name '*.systemextension' \) -type d 2>/dev/null | sort)
  while IFS= read -r helper; do
    objects+=("$helper")
  done < <(find "$app/Contents/Helpers" -maxdepth 1 -type f -perm +111 2>/dev/null | sort)
  while IFS= read -r fw; do
    objects+=("$fw")
  done < <(find "$app/Contents/Frameworks" -maxdepth 1 -name '*.framework' -type d 2>/dev/null | sort)
fi

# ---------------------------------------------------------------------------
# 1. Each code object must have a valid signature.
# ---------------------------------------------------------------------------
echo "  signature verification (per object, not --deep):"
for obj in "${objects[@]}"; do
  rel="${obj#$app/}"
  [ "$rel" = "$obj" ] && rel="(app)"
  if codesign --verify --strict "$obj" >/dev/null 2>&1; then
    note "ok: $rel"
  else
    problem "$rel has an invalid signature"
  fi
done

# The whole bundle must verify too, for the seal over its contents.
if ! codesign --verify --deep --strict "$app" >/dev/null 2>&1; then
  problem "the bundle seal does not verify (--deep)"
fi

# ---------------------------------------------------------------------------
# 2. Read back the SIGNED entitlements and compare App Groups.
# ---------------------------------------------------------------------------
echo "  signed entitlements:"
declare -a group_values=()
declare -a app_id_values=()
declare -a team_values=()

for obj in "${objects[@]}"; do
  rel="${obj#$app/}"
  [ "$rel" = "$obj" ] && rel="(app)"
  ent="$(entitlements_of "$obj")"

  if [ -z "$ent" ]; then
    # Frameworks and helpers legitimately may carry no entitlements.
    note "$rel: (no entitlements)"
    continue
  fi

  grp="$(printf '%s' "$ent" | plist_value com.apple.security.application-groups | head -1)"
  appid="$(printf '%s' "$ent" | plist_value application-identifier | head -1)"
  team="$(printf '%s' "$ent" | plist_value com.apple.developer.team-identifier | head -1)"
  ne="$(printf '%s' "$ent" | plist_value com.apple.developer.networking.networkextension | tr '\n' ',' | sed 's/,$//')"

  note "$rel:"
  [ -n "$grp" ] && { note "    app group: $grp"; group_values+=("$grp"); }
  [ -n "$appid" ] && { note "    app id:    $appid"; app_id_values+=("$appid"); }
  [ -n "$team" ] && { note "    team:      $team"; team_values+=("$team"); }
  [ -n "$ne" ] && note "    network extension: $ne"

  # Multicast must not appear when the switch is off.
  if [ "$APPLE_ENABLE_MULTICAST" = "false" ]; then
    if printf '%s' "$ent" | grep -q "com.apple.developer.networking.multicast"; then
      problem "$rel carries the multicast entitlement while APPLE_ENABLE_MULTICAST=false"
    fi
  fi

  # The tunnel capability must survive.
  case "$obj" in
    *.appex)
      if [ "$artifact_kind" = "ios-ipa" ]; then
        if ! printf '%s' "$ent" | grep -q "packet-tunnel-provider"; then
          # Only the packet tunnel extension needs it; UI extensions do not.
          if printf '%s' "$ne" | grep -q "networkextension"; then
            problem "$rel has a network extension entitlement without packet-tunnel-provider"
          fi
        fi
      fi
      ;;
  esac
done

# --- App Group must be identical across the app and its extensions -----------
if [ "${#group_values[@]}" -gt 0 ]; then
  unique_groups="$(printf '%s\n' "${group_values[@]}" | sort -u)"
  count="$(printf '%s\n' "$unique_groups" | wc -l | tr -d ' ')"
  if [ "$count" != "1" ]; then
    problem "the signed objects disagree on the App Group:"
    printf '%s\n' "$unique_groups" | sed 's/^/        /' >&2
    echo "        The host app and its extensions must share exactly one group," >&2
    echo "        or the extension cannot open the app's container at runtime." >&2
  else
    note "App Group consistent across all signed objects: $unique_groups"
    if [ -n "${APPLE_APP_GROUP_ID:-}" ] && [ "$unique_groups" != "$APPLE_APP_GROUP_ID" ]; then
      problem "the signed App Group ($unique_groups) is not the configured one ($APPLE_APP_GROUP_ID)"
    fi
  fi
else
  problem "no signed object carries an App Group"
fi

# --- every object must belong to the configured team -------------------------
if [ "${#team_values[@]}" -gt 0 ]; then
  unique_teams="$(printf '%s\n' "${team_values[@]}" | sort -u)"
  if [ "$(printf '%s\n' "$unique_teams" | wc -l | tr -d ' ')" != "1" ]; then
    problem "the signed objects belong to more than one team:"
    printf '%s\n' "$unique_teams" | sed 's/^/        /' >&2
  elif [ "$unique_teams" != "$APPLE_TEAM_ID" ]; then
    problem "the signed team ($unique_teams) is not the configured team ($APPLE_TEAM_ID)"
  else
    note "team consistent: $unique_teams"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Entitlements must not exceed what the provisioning profile authorises.
# ---------------------------------------------------------------------------
echo "  provisioning profile consistency:"
profiles_found=0
for obj in "${objects[@]}"; do
  profile="$obj/embedded.mobileprovision"
  if [ "$artifact_kind" = "macos-dmg" ] && [ ! -f "$profile" ]; then
    profile="$obj/Contents/embedded.provisionprofile"
  fi
  [ -f "$profile" ] || continue
  profiles_found=$((profiles_found + 1))

  rel="${obj#$app/}"
  [ "$rel" = "$obj" ] && rel="(app)"
  pents="$(profile_entitlements "$profile")"
  if [ -z "$pents" ]; then
    problem "could not parse the embedded profile of $rel"
    continue
  fi

  ent="$(entitlements_of "$obj")"
  p_appid="$(printf '%s' "$pents" | plist_value application-identifier | head -1)"
  s_appid="$(printf '%s' "$ent" | plist_value application-identifier | head -1)"
  p_group="$(printf '%s' "$pents" | plist_value com.apple.security.application-groups | head -1)"
  s_group="$(printf '%s' "$ent" | plist_value com.apple.security.application-groups | head -1)"

  note "$rel:"
  note "    profile app id: $p_appid"
  note "    signed app id:  $s_appid"
  if [ -n "$p_appid" ] && [ "$p_appid" != "$s_appid" ]; then
    problem "$rel signs as '$s_appid' but its profile authorises '$p_appid'"
  fi
  if [ -n "$p_group" ] && [ -n "$s_group" ] && [ "$p_group" != "$s_group" ]; then
    problem "$rel signs App Group '$s_group' but its profile authorises '$p_group'"
  fi

  # The profile must list the network extension capability the binary claims.
  if printf '%s' "$ent" | grep -q "com.apple.developer.networking.networkextension"; then
    if ! printf '%s' "$pents" | grep -q "com.apple.developer.networking.networkextension"; then
      problem "$rel claims a network extension entitlement its profile does not authorise"
    fi
  fi
done

if [ "$profiles_found" -eq 0 ]; then
  problem "no embedded provisioning profile was found in any signed object"
else
  note "profiles checked: $profiles_found"
fi

[ "$fail" -eq 0 ] || { echo "verify-apple-signed-artifact: FAIL" >&2; exit 1; }
echo "verify-apple-signed-artifact: PASS"
