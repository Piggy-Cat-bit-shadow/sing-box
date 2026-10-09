#!/usr/bin/env bash
# The Apple libbox ABI probe: the migrated call sites, the interface implementer, the
# screen-state observer and the pre-migration shapes, compiled against a Libbox
# xcframework that was actually built - not against a reading of the core's source.
#
# Usage:
#   apple-abi-probe.sh <path-to-Libbox.xcframework>
#
# # Why a compiler and not a grep
#
# The StringBox migration moved the RESULT of a bound Go method from a bare string to a
# boxed object, and a call site that still reads the old shape is a compile error, not a
# runtime surprise. A source sweep can only report what it recognises as a call site -
# it missed the implementation side entirely on both clients, because a type that
# CONFORMS to a bound Go interface also has to move and looks like neither a call nor a
# declaration of the migrated method. `redcheck.swift` exists so that the green run
# cannot be vacuous: if the old shapes ever compile again, the migration has been
# reverted in the artifact and this script fails.
#
# # What each file is
#
#   callsites.swift    the right-hand sides of docs/fork/apple-stringbox-callsites.patch
#   implementer.swift  docs/fork/apple-bridge-session-implementer.patch's witness
#   observer.swift     Library/Network/ScreenStateObserver.swift, verbatim from
#                      docs/fork/apple-screen-state-observer.patch
#   redcheck.swift     the PRE-migration shapes; must NOT compile
#   runtime.swift      links and runs against the macOS slice, proving the box round-trips
#   notify-initial-state-probe.c
#                      the Darwin notify semantics §12 of the brief depends on: does a
#                      dispatch registration deliver a state that already exists?
#
# The macOS system-framework list in link_macos() is not decoration: the static framework
# needs libbsm for _audit_token_to_pid and IOUSBHost for the USB/IP symbols, and the link
# fails without them.
set -euo pipefail

fw="${1:?usage: apple-abi-probe.sh <path-to-Libbox.xcframework>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/apple-abi-probe"

ios_slice="$fw/ios-arm64"
macos_slice="$(ls -d "$fw"/macos-* 2>/dev/null | head -1 || true)"

[ -d "$ios_slice" ] || { echo "FAIL: no ios-arm64 slice in $fw" >&2; exit 1; }
[ -n "$macos_slice" ] || { echo "FAIL: no macOS slice in $fw" >&2; exit 1; }

ios_sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
macos_sdk="$(xcrun --sdk macosx --show-sdk-path)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "framework: $fw"
echo "  ios slice:   $ios_slice"
echo "  macos slice: $macos_slice"

# --- 1. GREEN: the migrated shapes and the observer, iOS device ---------------
#
# observer.swift is the whole point of compiling this for iOS: `import notify` and
# recordScreenState/recordLockState only exist in that configuration.
echo
echo "-- green: migrated call sites + implementer + observer, arm64-apple-ios15.0"
if swiftc -typecheck -target arm64-apple-ios15.0 -sdk "$ios_sdk" -F "$ios_slice" \
    "$here/callsites.swift" "$here/implementer.swift" "$here/observer.swift" 2>"$tmp/green.log"; then
  echo "   GREEN OK (0 errors)"
else
  echo "   FAIL: the migrated shapes do not compile against this framework:"
  grep "error:" "$tmp/green.log" | head -20 >&2
  exit 1
fi

# --- 2. GREEN: the same shapes for macOS -------------------------------------
echo
echo "-- green: the same three files, arm64-apple-macos13.0 (the observer compiles away)"
if swiftc -typecheck -target arm64-apple-macos13.0 -sdk "$macos_sdk" -F "$macos_slice" \
    "$here/callsites.swift" "$here/implementer.swift" "$here/observer.swift" 2>"$tmp/macos.log"; then
  echo "   GREEN OK (0 errors)"
else
  echo "   FAIL: the migrated shapes do not compile for macOS:"
  grep "error:" "$tmp/macos.log" | head -20 >&2
  exit 1
fi

# --- 3. RED: the pre-migration shapes must be rejected ------------------------
echo
echo "-- red: the pre-migration shapes must NOT compile"
if swiftc -typecheck -target arm64-apple-ios15.0 -sdk "$ios_sdk" -F "$ios_slice" \
    "$here/redcheck.swift" 2>"$tmp/red.log"; then
  echo "   FAIL: the old ABI shapes compiled - the migration is not in this artifact" >&2
  exit 1
fi
if ! grep -q "LibboxStringBox" "$tmp/red.log"; then
  echo "   FAIL: redcheck failed for a reason other than the boxed return type:" >&2
  head -20 "$tmp/red.log" >&2
  exit 1
fi
echo "   RED OK ($(grep -c 'error:' "$tmp/red.log") errors, all naming LibboxStringBox)"

# --- 4. Link and RUN against the macOS slice ---------------------------------
echo
echo "-- runtime: link and run against the macOS slice"
# shellcheck disable=SC2086
if swiftc -target arm64-apple-macos13.0 -sdk "$macos_sdk" -F "$macos_slice" "$here/runtime.swift" \
    -framework Foundation -framework AppKit -framework CoreFoundation -framework CoreText \
    -framework CoreServices -framework CFNetwork -framework Network -framework SystemConfiguration \
    -framework Security -framework IOKit -framework IOUSBHost -framework UniformTypeIdentifiers \
    -framework DiskArbitration -lresolv -lbsm -o "$tmp/runtime_probe" 2>"$tmp/link.log"; then
  "$tmp/runtime_probe"
else
  echo "   FAIL: the macOS slice did not link:" >&2
  tail -20 "$tmp/link.log" >&2
  exit 1
fi

echo
echo "apple-abi-probe: PASS"
