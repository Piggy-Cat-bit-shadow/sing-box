#!/usr/bin/env bash
# Builds, verifies and uploads a macOS TestFlight build.
#
# Usage: build-macos-testflight.sh [--archive-only]
#
# # Which macOS app this builds, and why it is not SFM.System
#
# The project has two macOS apps, and only one of them is an App Store product:
#
#   SFM         bundle id <base>             sandboxed, packet-tunnel-provider
#   SFM.System  bundle id <base>.standalone  no sandbox, System Extension + helper
#
# SFM.System exists so the client can run outside the sandbox as a stand-alone
# install: it ships a privileged helper (RootHelper) and a System Extension, and it
# declares com.apple.developer.system-extension.install. Sandboxing is not optional
# for Mac App Store distribution, and installing a privileged helper is not
# something a sandboxed App Store app may do, so that product is distributed outside
# the store (Developer ID) and is not part of a TestFlight build.
#
# SFM is the sandboxed app whose bundle identifier is the SAME as the iOS app's,
# which is what allows both platforms to live in one App Store Connect record.
#
# So this is not a stripped-down build of SFM.System: it is a different target that
# was already designed for the App Store, and the DMG flow in build-macos-dmg.sh
# continues to cover SFM.System for local use.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

archive_only=false
while [ $# -gt 0 ]; do
  case "$1" in
    --archive-only) archive_only=true; shift ;;
    *) echo "build-macos-testflight.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

eval "$("$root/scripts/ci/apple-signing-config.sh")"

if [ "$APPLE_SIGNING_MODE" != "testflight" ]; then
  echo "build-macos-testflight.sh: APPLE_SIGNING_MODE must be 'testflight', got '$APPLE_SIGNING_MODE'" >&2
  exit 2
fi

client="clients/apple"
scheme="SFM"
work="build/apple-testflight-macos"
archive_path="$work/SFM.xcarchive"
mkdir -p "$work"

marketing_version="$(tr -d '[:space:]' < release/JIEJIE_VERSION)"
build_number="${APPLE_BUILD_NUMBER:-$(date -u +%Y%m%d%H%M)}"
git_sha="$(git rev-parse HEAD)"

echo "macOS TestFlight build"
echo "  marketing version: $marketing_version"
echo "  build number:      $build_number"
echo "  git sha:           $git_sha"
echo "  team:              $APPLE_TEAM_ID"
echo "  bundle id:         $APPLE_MACOS_APP_BUNDLE_ID (the App Store app, SFM)"

# The single-record model depends on this being true, so check it rather than
# assume it: the export step would otherwise create a second App Store record that
# cannot be undone after the first upload.
if [ "$APPLE_MACOS_APP_BUNDLE_ID" != "$APPLE_IOS_APP_BUNDLE_ID" ]; then
  echo "FAIL: the macOS App Store bundle id ($APPLE_MACOS_APP_BUNDLE_ID) differs from" >&2
  echo "      the iOS one ($APPLE_IOS_APP_BUNDLE_ID). They must match for a single" >&2
  echo "      App Store Connect record, and this cannot be changed after the first" >&2
  echo "      upload." >&2
  exit 1
fi

if [ ! -d "$client/Libbox.xcframework" ]; then
  echo "FAIL: $client/Libbox.xcframework is missing; build it first with" >&2
  echo "      ./scripts/ci/build-apple-libbox.sh both" >&2
  exit 1
fi

# The SFM target links a SwiftUI editor stack whose dependencies attach the
# SwiftLint build-tool plug-in; it cannot load sourcekitdInProc inside Xcode's
# plug-in sandbox and aborts the build. See build-macos-dmg.sh for the full
# explanation - the same removal applies here, and to the resolved checkouts in
# DerivedData only, never to the pinned submodule.
echo "resolving packages"
xcodebuild -resolvePackageDependencies \
  -project "$client/sing-box.xcodeproj" \
  -scheme "$scheme" \
  -derivedDataPath "$work/dd" >/dev/null 2>&1 || true

removed_plugins=0
while IFS= read -r pkg; do
  case "$(basename "$(dirname "$pkg")")" in
    SwiftLintPlugin) continue ;;
  esac
  if grep -q "SwiftLintPlugin" "$pkg"; then
    python3 "$root/scripts/ci/strip-swiftlint-plugin.py" "$pkg"
    removed_plugins=$((removed_plugins + 1))
    echo "  dropped SwiftLint plug-in from $(basename "$(dirname "$pkg")")"
  fi
done < <(find "$work/dd/SourcePackages/checkouts" -maxdepth 2 -name Package.swift 2>/dev/null | sort)
[ "$removed_plugins" -eq 0 ] && echo "  note: no SwiftLint plug-in attachment found"

echo "archiving (Release, macOS, arm64)"
rm -rf "$archive_path"
xcodebuild archive \
  -project "$client/sing-box.xcodeproj" \
  -scheme "$scheme" \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -archivePath "$archive_path" \
  -derivedDataPath "$work/dd" \
  ARCHS=arm64 \
  ONLY_ACTIVE_ARCH=NO \
  BASE_PACKAGE_IDENTIFIER="$APPLE_BASE_BUNDLE_ID" \
  APP_GROUP_IDENTIFIER="$APPLE_APP_GROUP_ID" \
  DEVELOPMENT_TEAM="$APPLE_TEAM_ID" \
  # Distribution signing, for the same reason as the iOS archive: the project pins
  # CODE_SIGN_IDENTITY = "Apple Development" in Release, so an archive that
  # overrides nothing asks Apple for a *Mac App Development* profile, which is
  # device-scoped. Manual style must accompany the distribution identity, because
  # Automatic derives the profile type from the identity and the two then
  # contradict each other on every target.
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="Apple Distribution" \
  MARKETING_VERSION="$marketing_version" \
  CURRENT_PROJECT_VERSION="$build_number" \
  -allowProvisioningUpdates \
  -skipPackagePluginValidation \
  2>&1 | tail -30

if [ ! -d "$archive_path" ]; then
  echo "FAIL: no archive was produced at $archive_path" >&2
  exit 1
fi

app="$(find "$archive_path/Products/Applications" -maxdepth 1 -name '*.app' -type d | head -1)"
if [ -z "$app" ] || [ ! -d "$app" ]; then
  echo "FAIL: the archive contains no application bundle" >&2
  find "$archive_path/Products" -maxdepth 3 -type d 2>/dev/null | head -10 >&2
  exit 1
fi
echo "archived app: $app"

built_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist" 2>/dev/null || echo '?')"
built_build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist" 2>/dev/null || echo '?')"
built_bundle="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist" 2>/dev/null || echo '?')"
echo "  CFBundleShortVersionString: $built_version"
echo "  CFBundleVersion:           $built_build"
echo "  CFBundleIdentifier:        $built_bundle"

# --- pre-upload gate ----------------------------------------------------------
# The same standard as iOS: nothing reaches Apple unless it is provably ours and
# structurally what an App Store build must be.
echo "pre-upload gate"
gate_failed=0
gate() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  PASS: $name"; else echo "  FAIL: $name" >&2; gate_failed=1; fi
}

gate "bundle id is ours (not upstream)" bash -c "case '$built_bundle' in io.nekohasekai.*) exit 1;; *) exit 0;; esac"
gate "bundle id matches the iOS app id" test "$built_bundle" = "$APPLE_IOS_APP_BUNDLE_ID"
gate "team id is not upstream" test "$APPLE_TEAM_ID" != "P8XK3KHB48"
gate "main app is signed" codesign --verify --strict "$app"
# Guard against an empty identity, which makes the build succeed while producing a
# product that is not signed at all - a passing build with nothing uploadable.
gate "main app is signed for distribution" \
  bash -c "codesign -dv '$app' 2>&1 | grep -q 'Apple Distribution'"
gate "build number is set" test "$built_build" != "?" -a -n "$built_build"

# Mac App Store distribution requires the sandbox. Without it the app cannot be
# submitted at all, and a build that gets this far would fail later at Apple.
main_ent="$(codesign -d --entitlements :- "$app" 2>/dev/null || true)"
gate "app is sandboxed" bash -c "printf '%s' '$main_ent' | grep -q com.apple.security.app-sandbox"
gate "no System Extension install entitlement (not an App Store capability)" \
  bash -c "! printf '%s' '$main_ent' | grep -q com.apple.developer.system-extension.install"
gate "Packet Tunnel entitlement present" \
  bash -c "printf '%s' '$main_ent' | grep -q packet-tunnel-provider"
gate "App Group present" bash -c "printf '%s' '$main_ent' | grep -q application-groups"
gate "no multicast entitlement" \
  bash -c "! printf '%s' '$main_ent' | grep -q com.apple.developer.networking.multicast"

# A privileged helper cannot be installed by a sandboxed App Store app, so its
# presence would mean the wrong target was archived.
gate "no privileged helper embedded" bash -c "! test -d '$app/Contents/Library/LaunchDaemons'"
gate "no System Extension embedded" bash -c "! test -d '$app/Contents/Library/SystemExtensions'"

gate "no upstream team in the signature" \
  bash -c "! codesign -d --verbose=4 '$app' 2>&1 | grep -q 'P8XK3KHB48'"

[ "$gate_failed" -eq 0 ] || {
  echo "FAIL: the pre-upload gate did not pass; refusing to upload." >&2
  exit 1
}

echo "archive: $archive_path"

if [ "$archive_only" = "true" ]; then
  echo "build-macos-testflight: ARCHIVE ONLY (not uploaded)"
  exit 0
fi

# --- export options -----------------------------------------------------------
export_dir="$work/export"
export_plist="$work/ExportOptions.plist"
mkdir -p "$export_dir"

method="app-store-connect"
if ! xcodebuild -help 2>/dev/null | grep -q "$method"; then
  method="app-store"
fi
echo "export method: $method"

cat > "$export_plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>$method</string>
	<key>destination</key>
	<string>upload</string>
	<key>teamID</key>
	<string>$APPLE_TEAM_ID</string>
	<key>signingStyle</key>
	<string>automatic</string>
	<key>uploadSymbols</key>
	<true/>
	<key>manageAppVersionAndBuildNumber</key>
	<false/>
</dict>
</plist>
PLIST

echo "exporting and uploading to App Store Connect"
set +e
xcodebuild -exportArchive \
  -archivePath "$archive_path" \
  -exportPath "$export_dir" \
  -exportOptionsPlist "$export_plist" \
  -allowProvisioningUpdates \
  2>&1 | tail -40
export_status=${PIPESTATUS[0]}
set -e

echo
if [ "$export_status" -eq 0 ]; then
  echo "TESTFLIGHT UPLOAD: PASS (macOS)"
  echo "  bundle id:     $built_bundle"
  echo "  version:       $built_version"
  echo "  build number:  $built_build"
  echo "  archive:       $archive_path"
  echo "  git sha:       $git_sha"
  echo "  uploaded at:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
else
  echo "TESTFLIGHT UPLOAD: FAIL (macOS, export/upload exited $export_status)" >&2
  echo "  The archive is valid and verified; only the upload failed." >&2
  exit 1
fi
