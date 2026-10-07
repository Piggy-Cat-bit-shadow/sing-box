#!/usr/bin/env bash
# Fails unless an archived macOS app is branded under the expected product name.
#
# Usage: check-macos-app-name.sh <app-bundle> [expected-name]
#
# # Why this is its own script
#
# The macOS product reached TestFlight still called sing-box because nothing checked
# the NAME - every gate that existed looked at identifiers, entitlements and signing.
# The branding overlay rewrites the pinned project's source, so the archive is the
# first place the result becomes visible, and an app uploaded under the wrong name
# cannot be corrected without another build. This is the gate that exists for it.
#
# It is separate from build-macos-testflight.sh so that the check can be exercised
# against a fixture bundle without archiving anything: a gate that has never been run
# against a bundle named sing-box is not known to catch one.
#
# # What "the name" means
#
# Two things, because different macOS surfaces read different ones and a partial
# rename would leave them disagreeing:
#
#   the .app bundle's directory name    what Finder, the Dock and Launchpad show
#   CFBundleDisplayName                 the name in the menu bar and About
#   CFBundleName                        used as a fallback when no display name exists
#
# CFBundleName is only asserted when it is present: the project generates its Info.plist
# and a missing key is legitimate, so requiring it would fail on a correct build. A key
# that is present and wrong is a real disagreement and is treated as one.
#
# # Expected name
#
# Read from the branding overlay rather than passed in by every caller, so the name the
# overlay writes and the name this gate requires cannot drift apart. A caller may still
# pass one explicitly.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: check-macos-app-name.sh <app-bundle> [expected-name]" >&2
  exit 2
fi

app="$1"
overlay="$root/scripts/ci/apply-apple-macos-branding-overlay.py"
expected="${2:-}"

if [ -z "$expected" ]; then
  # Anchored on the assignment, not a bare search for the string: the same name also
  # appears in the "not Jijiebox / JiejieBox" comments, and matching one of those would
  # make this gate require the wrong spelling.
  expected="$(
    python3 - "$overlay" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'^\s*NEW_NAME = "([^"]+)"', src, re.M)
if not m:
    sys.exit("the macOS branding overlay declares no NEW_NAME")
print(m.group(1))
PY
  )"
  if [ -z "$expected" ]; then
    echo "check-macos-app-name: cannot resolve the expected product name from $overlay" >&2
    exit 2
  fi
fi

fail() {
  echo "check-macos-app-name: $*" >&2
  exit 1
}

[ -d "$app" ] || fail "$app is not an application bundle"
plist="$app/Contents/Info.plist"
[ -f "$plist" ] || fail "$app has no Contents/Info.plist"

read_key() {
  /usr/libexec/PlistBuddy -c "Print :$1" "$plist" 2>/dev/null || true
}

display="$(read_key CFBundleDisplayName)"
name="$(read_key CFBundleName)"
bundle_name="$(basename "$app")"

# The bundle name is where the rename is visible in Finder and the Dock, and it is what
# the previous failure looked like: sing-box.app installed from TestFlight.
if [ "$bundle_name" != "$expected.app" ]; then
  fail "the app bundle is named '$bundle_name', expected '$expected.app'"
fi

if [ "$display" != "$expected" ]; then
  fail "CFBundleDisplayName is '${display:-<missing>}', expected '$expected'"
fi

if [ -n "$name" ] && [ "$name" != "$expected" ]; then
  fail "CFBundleName is '$name' but CFBundleDisplayName is '$expected'; the bundle disagrees with itself"
fi

echo "check-macos-app-name: PASS ($bundle_name, CFBundleDisplayName=$display)"
