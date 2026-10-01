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
# 2. [personal-signing] Retire the multicast entitlement from the iOS extension.
# ---------------------------------------------------------------------------
echo "overlay [personal-signing]: multicast entitlement"

if [ ! -f "$extension_entitlements" ]; then
  echo "FAIL: $extension_entitlements does not exist; upstream restructured it." >&2
  exit 1
fi

read_plist() { plutil -convert xml1 -o - "$1" 2>/dev/null || cat "$1"; }
has_key() {
  if read_plist "$1" | grep -q "<key>$2</key>"; then echo 1; else echo 0; fi
}

if [ "$(has_key "$extension_entitlements" com.apple.developer.networking.multicast)" != "1" ]; then
  echo "FAIL: $extension_entitlements has no multicast entitlement, so this overlay" >&2
  echo "      no longer describes the tree." >&2
  exit 1
fi

/usr/libexec/PlistBuddy -c "Delete :com.apple.developer.networking.multicast" "$extension_entitlements" >/dev/null 2>&1 || true

fail=0
if [ "$(has_key "$extension_entitlements" com.apple.developer.networking.multicast)" != "0" ]; then
  echo "FAIL: multicast entitlement still present" >&2; fail=1
else
  echo "  [personal-signing] removed: com.apple.developer.networking.multicast"
fi

# The tunnel is the product; losing this would install but never connect.
if [ "$(has_key "$extension_entitlements" com.apple.developer.networking.networkextension)" != "1" ]; then
  echo "FAIL: com.apple.developer.networking.networkextension was lost" >&2; fail=1
elif ! read_plist "$extension_entitlements" | grep -q "packet-tunnel-provider"; then
  echo "FAIL: packet-tunnel-provider is no longer listed" >&2; fail=1
else
  echo "  [personal-signing] kept: networkextension (packet-tunnel-provider)"
fi

if [ "$(has_key "$extension_entitlements" com.apple.security.application-groups)" != "1" ]; then
  echo "FAIL: com.apple.security.application-groups was lost" >&2; fail=1
else
  echo "  [personal-signing] kept: application-groups"
fi

if ! plutil -lint "$extension_entitlements" >/dev/null 2>&1; then
  echo "FAIL: $extension_entitlements is no longer a valid plist" >&2; fail=1
fi
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
