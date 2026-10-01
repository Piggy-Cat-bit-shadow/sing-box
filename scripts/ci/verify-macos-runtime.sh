#!/usr/bin/env bash
# Runtime smoke test for a development-signed macOS client.
#
# Usage: verify-macos-runtime.sh [path-to-SFM.app]
#
# Run this on YOUR Mac, not in CI. It checks the things a build cannot: that the
# app actually launches and that its App Group container is usable.
#
# # Why this is separate from the build
#
# The build proves the app is signed with the right entitlements. It cannot prove
# the entitlements WORK, and the difference matters here because the first fatal
# error observed while debugging this client was exactly that:
#
#   the client could not write its App Group database.
#
# A signed entitlement that names a group the App IDs are not assigned to is
# individually valid and completely broken. Only running the app reveals it, so
# this script deliberately does not reach for `codesign --verify` and call it a
# day - it exercises the container.
#
# # What it does not claim
#
# System Extension activation needs an interactive approval in System Settings. It
# is reported as NOT TESTED unless it is already active, rather than being faked.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

eval "$("$root/scripts/ci/apple-signing-config.sh")"

app="${1:-/Applications/SFM.app}"

if [ "$APPLE_SIGNING_MODE" != "development" ]; then
  echo "verify-macos-runtime: refusing to run in APPLE_SIGNING_MODE=$APPLE_SIGNING_MODE"
  echo "  Runtime checks are only meaningful for a signed, entitled build."
  exit 2
fi

if [ ! -d "$app" ]; then
  echo "verify-macos-runtime: $app not found." >&2
  echo "  Build and install first, or pass the path to the built SFM.app." >&2
  exit 1
fi

fail=0
note() { echo "  $*"; }
problem() { echo "  FAIL: $*" >&2; fail=1; }

echo "verify-macos-runtime: $app"
echo "  signing mode: $APPLE_SIGNING_MODE"
echo "  team:         $APPLE_TEAM_ID"
echo "  app group:    $APPLE_APP_GROUP_ID"

# ---------------------------------------------------------------------------
# 1. The signed entitlements must name the configured group (not just any group).
# ---------------------------------------------------------------------------
echo "== signed entitlements =="
signed_group="$(codesign -d --entitlements :- "$app" 2>/dev/null \
  | python3 -c '
import plistlib, sys
data = sys.stdin.buffer.read()
try:
    plist = plistlib.loads(data)
except Exception:
    print(""); raise SystemExit
groups = plist.get("com.apple.security.application-groups") or []
print(groups[0] if groups else "")
')"
if [ -z "$signed_group" ]; then
  problem "the app's signed entitlements declare no App Group"
elif [ "$signed_group" != "$APPLE_APP_GROUP_ID" ]; then
  problem "the app signs App Group '$signed_group' but '$APPLE_APP_GROUP_ID' was configured"
else
  note "app group in signature: $signed_group"
fi

# Every nested extension must agree, or the tunnel writes to a different container.
while IFS= read -r nested; do
  n_group="$(codesign -d --entitlements :- "$nested" 2>/dev/null \
    | python3 -c '
import plistlib, sys
data = sys.stdin.buffer.read()
try:
    plist = plistlib.loads(data)
except Exception:
    print(""); raise SystemExit
groups = plist.get("com.apple.security.application-groups") or []
print(groups[0] if groups else "")
')"
  rel="${nested#$app/Contents/}"
  if [ -z "$n_group" ]; then
    # A helper or framework without entitlements is fine.
    continue
  fi
  if [ "$n_group" != "$signed_group" ]; then
    problem "$rel uses App Group '$n_group', the app uses '$signed_group'"
  else
    note "$rel agrees: $n_group"
  fi
done < <(find "$app/Contents/PlugIns" "$app/Contents/Library/SystemExtensions" \
           -maxdepth 1 \( -name '*.appex' -o -name '*.systemextension' \) -type d 2>/dev/null | sort)

# ---------------------------------------------------------------------------
# 2. The app must launch and stay up.
# ---------------------------------------------------------------------------
echo "== launch =="
# Capture output so an immediate crash is visible rather than silent.
launch_log="$(mktemp)"
"$app/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null)" \
  >"$launch_log" 2>&1 &
launch_pid=$!

sleep 6
if ! kill -0 "$launch_pid" 2>/dev/null; then
  problem "the app exited within 6 seconds of launching"
  echo "  --- output ---" >&2
  sed 's/^/    /' "$launch_log" >&2 | head -30
  # A GUI app launched from a terminal may legitimately exit; report the reason.
else
  note "the app is still running after 6s (pid $launch_pid)"
  kill "$launch_pid" 2>/dev/null || true
  wait "$launch_pid" 2>/dev/null || true
fi

if grep -qiE "permission denied|not permitted|Operation not permitted" "$launch_log"; then
  problem "the app logged a permission error, which usually means the App Group is not assigned to its App ID:"
  grep -iE "permission denied|not permitted" "$launch_log" | head -5 | sed 's/^/    /' >&2
fi
rm -f "$launch_log"

# ---------------------------------------------------------------------------
# 3. The App Group container must exist and be writable.
# ---------------------------------------------------------------------------
# This is the check that would have caught the failure this work started from.
echo "== App Group container =="
# The app must have run once for macOS to create the container.
container="$HOME/Library/Group Containers/$APPLE_APP_GROUP_ID"
if [ ! -d "$container" ]; then
  problem "no App Group container at $container"
  echo "        The container is created on first use. If the app ran and this is" >&2
  echo "        still missing, the App Group in the signed entitlements is not" >&2
  echo "        assigned to the App IDs - see docs/APPLE-DEVELOPMENT-SIGNING.md." >&2
else
  note "container: $container"
  probe="$container/.jiejie-write-probe"
  if printf 'probe' > "$probe" 2>/dev/null; then
    if [ "$(cat "$probe")" = "probe" ]; then
      note "write/read OK"
    else
      problem "wrote the probe file but read back different content"
    fi
    rm -f "$probe"
  else
    problem "cannot write to the container; the app will fail to store its database"
  fi
fi

# ---------------------------------------------------------------------------
# 4. System Extension — reported, never faked.
# ---------------------------------------------------------------------------
echo "== System Extension =="
if command -v systemextensionsctl >/dev/null 2>&1; then
  if systemextensionsctl list 2>/dev/null | grep -q "$APPLE_MACOS_SYSTEM_EXTENSION_BUNDLE_ID"; then
    note "active: $APPLE_MACOS_SYSTEM_EXTENSION_BUNDLE_ID"
  else
    echo "  NOT TESTED: the System Extension is not active."
    echo "              Activate it in System Settings > General > Login Items &"
    echo "              Extensions > System Extensions, then re-run."
    echo "              For a development build you may also need:"
    echo "                systemextensionsctl developer on"
  fi
else
  echo "  NOT TESTED: systemextensionsctl is unavailable on this host."
fi

[ "$fail" -eq 0 ] || { echo "verify-macos-runtime: FAIL" >&2; exit 1; }
echo "verify-macos-runtime: PASS"
echo "  Note: App Group and launch verified. System Extension activation is only"
echo "  reported, because it requires an interactive approval this script cannot give."
