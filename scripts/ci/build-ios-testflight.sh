#!/usr/bin/env bash
# Builds, verifies and uploads an iOS TestFlight build.
#
# Usage: build-ios-testflight.sh [--archive-only]
#
# # Why this is not the development flow with a different export step
#
# A TestFlight build must be a Release ARCHIVE produced by `xcodebuild archive`,
# because that is what reconstructs the bundle the way App Store Connect expects:
# symbol collection, bitcode-era layout, and every nested target signed in the
# dependency order Xcode decides. Re-signing the development IPA would produce
# something that looks equivalent and is not.
#
# So the pipeline is archive -> verify the archive -> export with an upload
# destination, and each stage is checked before the next runs. Nothing is uploaded
# unless the pre-upload gate in Section 34 passes.
#
# # What it will not do
#
# It will not invent a certificate, a team or an App Store Connect record, and it
# will not silently fall back to an unsigned build. If Apple requires an
# interactive step - a licence agreement, or the first App Record - it stops and
# says so.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

archive_only=false
while [ $# -gt 0 ]; do
  case "$1" in
    --archive-only) archive_only=true; shift ;;
    *) echo "build-ios-testflight.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

eval "$("$root/scripts/ci/apple-signing-config.sh")"

if [ "$APPLE_SIGNING_MODE" != "testflight" ]; then
  echo "build-ios-testflight.sh: APPLE_SIGNING_MODE must be 'testflight', got '$APPLE_SIGNING_MODE'" >&2
  echo "  TestFlight is a separate mode: it archives and exports to App Store" >&2
  echo "  Connect, which is a different signing path from a local development IPA." >&2
  exit 2
fi

client="clients/apple"
work="build/apple-testflight"
archive_path="$work/SFI.xcarchive"
mkdir -p "$work"

# --- version and build number -------------------------------------------------
# App Store Connect rejects a build whose CFBundleVersion is not greater than the
# last accepted one for the same marketing version, so the build number is derived
# from the clock rather than being a constant. YYYYMMDDHHMM is monotonic, is within
# Apple's allowed character set, and fits the numeric comparison.
marketing_version="$(tr -d '[:space:]' < release/JIEJIE_VERSION)"
build_number="${APPLE_BUILD_NUMBER:-$(date -u +%Y%m%d%H%M)}"
git_sha="$(git rev-parse HEAD)"

echo "TestFlight build"
echo "  marketing version: $marketing_version"
echo "  build number:      $build_number"
echo "  git sha:           $git_sha"
echo "  team:              $APPLE_TEAM_ID"
echo "  bundle id:         $APPLE_IOS_APP_BUNDLE_ID"

# --- archive ------------------------------------------------------------------
if [ ! -d "$client/Libbox.xcframework" ]; then
  echo "FAIL: $client/Libbox.xcframework is missing; build it first with" >&2
  echo "      ./scripts/ci/build-apple-libbox.sh both" >&2
  exit 1
fi

echo "archiving (Release, iphoneos, arm64)"
rm -rf "$archive_path"
xcodebuild archive \
  -project "$client/sing-box.xcodeproj" \
  -scheme SFI \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath "$archive_path" \
  -derivedDataPath "$work/dd" \
  ARCHS=arm64 \
  ONLY_ACTIVE_ARCH=NO \
  BASE_PACKAGE_IDENTIFIER="$APPLE_BASE_BUNDLE_ID" \
  APP_GROUP_IDENTIFIER="$APPLE_APP_GROUP_ID" \
  DEVELOPMENT_TEAM="$APPLE_TEAM_ID" \
  CODE_SIGN_STYLE=Automatic \
  MARKETING_VERSION="$marketing_version" \
  CURRENT_PROJECT_VERSION="$build_number" \
  -allowProvisioningUpdates \
  -skipPackagePluginValidation \
  2>&1 | tail -30

if [ ! -d "$archive_path" ]; then
  echo "FAIL: no archive was produced at $archive_path" >&2
  exit 1
fi

app="$archive_path/Products/Applications/sing-box.app"
if [ ! -d "$app" ]; then
  # The product name is not the scheme name; find whatever was produced.
  app="$(find "$archive_path/Products/Applications" -maxdepth 1 -name '*.app' -type d | head -1)"
fi
if [ -z "$app" ] || [ ! -d "$app" ]; then
  echo "FAIL: the archive contains no application bundle" >&2
  find "$archive_path/Products" -maxdepth 3 -type d 2>/dev/null | head -10 >&2
  exit 1
fi
echo "archived app: $app"

# Record what was actually built, for the report and BUILD-INFO.
built_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Info.plist" 2>/dev/null || echo '?')"
built_build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Info.plist" 2>/dev/null || echo '?')"
built_bundle="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Info.plist" 2>/dev/null || echo '?')"
echo "  CFBundleShortVersionString: $built_version"
echo "  CFBundleVersion:           $built_bundle"
echo "  CFBundleIdentifier:        $built_bundle"

# --- pre-upload gate ----------------------------------------------------------
# Every one of these must hold before anything is sent to Apple. They are the
# difference between an archive that merely built and one that is provably ours.
echo "pre-upload gate"
gate_failed=0
gate() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS: $name"
  else
    echo "  FAIL: $name" >&2
    gate_failed=1
  fi
}

gate "bundle id is ours (not upstream)" bash -c "case '$built_bundle' in io.nekohasekai.*) exit 1;; *) exit 0;; esac"
gate "bundle id matches the configured base" test "$built_bundle" = "$APPLE_IOS_APP_BUNDLE_ID"
gate "team id is not upstream" test "$APPLE_TEAM_ID" != "P8XK3KHB48"
gate "main app is signed" codesign --verify --strict "$app"
gate "build number is set" test "$built_build" != "?" -a -n "$built_build"

# The Packet Tunnel extension is the product; a TestFlight build without it is
# useless even though it would upload fine.
appex="$app/PlugIns/Extension.appex"
gate "Packet Tunnel extension is present" test -d "$appex"
gate "Packet Tunnel is signed" codesign --verify --strict "$appex"

if [ -d "$appex" ]; then
  ent="$(codesign -d --entitlements :- "$appex" 2>/dev/null || true)"
  gate "Packet Tunnel has packet-tunnel-provider" bash -c "printf '%s' '$ent' | grep -q packet-tunnel-provider"
  gate "no multicast entitlement" bash -c "! printf '%s' '$ent' | grep -q com.apple.developer.networking.multicast"
  gate "Packet Tunnel has an App Group" bash -c "printf '%s' '$ent' | grep -q application-groups"
fi

# The upstream identity must not appear anywhere in the signed result.
gate "no upstream team in the signature" bash -c "! codesign -d --verbose=4 '$app' 2>&1 | grep -q 'P8XK3KHB48'"

[ "$gate_failed" -eq 0 ] || {
  echo "FAIL: the pre-upload gate did not pass; refusing to upload." >&2
  echo "      An archive that cannot be shown to be ours must not reach App Store" >&2
  echo "      Connect." >&2
  exit 1
}

echo "archive: $archive_path"
echo "archive-sha256: $(shasum -a 256 "$archive_path/Products/Applications/$(basename "$app")"/* 2>/dev/null | head -1 | awk '{print $1}')"

if [ "$archive_only" = "true" ]; then
  echo "build-ios-testflight: ARCHIVE ONLY (not uploaded)"
  exit 0
fi

# --- export options -----------------------------------------------------------
# Generated rather than committed: it names the team, and Apple has changed the
# accepted export method over time, so it is derived from what this Xcode supports.
export_dir="$work/export"
export_plist="$work/ExportOptions.plist"
mkdir -p "$export_dir"

method="app-store-connect"
if ! xcodebuild -help 2>/dev/null | grep -q "$method"; then
  # Older Xcode calls the same destination "app-store".
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
echo "  (this may take several minutes; Apple's transport is slow)"

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
  echo "TESTFLIGHT UPLOAD: PASS"
  echo "  bundle id:     $built_bundle"
  echo "  version:       $built_version"
  echo "  build number:  $built_build"
  echo "  archive:       $archive_path"
  echo "  git sha:       $git_sha"
  echo "  uploaded at:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "Apple now processes the build server-side. That is not part of this"
  echo "command's success: check TestFlight in App Store Connect for the result."
else
  echo "TESTFLIGHT UPLOAD: FAIL (export/upload exited $export_status)" >&2
  echo "  The archive itself is valid and was verified; only the upload failed." >&2
  echo "  Common causes, in order of likelihood:" >&2
  echo "    - Xcode is not signed in: Xcode > Settings > Accounts" >&2
  echo "    - the app record does not exist yet in App Store Connect" >&2
  echo "    - an agreement or tax form needs accepting by the Account Holder" >&2
  exit 1
fi
