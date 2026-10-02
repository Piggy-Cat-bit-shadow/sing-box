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

# THE ARCHIVE MUST BE SIGNED
#
# An earlier version of this script produced an unsigned archive and relied on
# -exportArchive to sign it. That does not work, and Apple's validator says so:
#
#   Missing Entitlement. The bundle 'sing-box.app' is missing entitlement
#   'com.apple.developer.networking.networkextension'.
#   Invalid Info.plist value. NSExtensionFileProviderDocumentGroup ... must match
#   values contained in the com.apple.security.application-groups entitlement.
#   The given value ... was not found because this entitlement was not present.
#
# -exportArchive validates the archive's entitlements and only re-signs what
# validates; it cannot supply entitlements that were never applied. An unsigned
# archive carries none, so every capability reads as missing. The entitlements
# files themselves are correct.
#
# The archive is therefore signed with automatic signing. That needs a provisioning
# profile to exist, and with the project's Apple Development identity it is a
# development profile, which requires at least one registered device. Development
# profiles are sufficient here: the export re-signs for distribution, which is where
# the App Store profile is created.
# Resolve packages as a separate step.
#
# The archive otherwise resolves the package graph inline, and a transient network
# failure there aborts the whole build with exit 74 ("Could not resolve package
# dependencies: RPC failed"), which reads like a project problem and is not. Doing
# it first also means the resolve can be retried without rebuilding anything.
echo "resolving packages"
for attempt in 1 2 3; do
  if xcodebuild -resolvePackageDependencies \
      -project "$client/sing-box.xcodeproj" \
      -scheme SFI \
      -derivedDataPath "$work/dd" >/dev/null 2>&1; then
    break
  fi
  echo "  resolve attempt $attempt failed (network); retrying"
  sleep 5
done

echo "archiving (Release, iphoneos, arm64; automatic signing, re-signed at export)"
rm -rf "$archive_path"
# Clear the derived data too. Xcode caches the resolved package graph and the
# build settings derived from it, and a cache written while the archive still used
# the project's development identity keeps that identity in play: the build then
# asks Apple for an iOS *App Development* profile even though the command line says
# Apple Distribution, which makes a signing-mode problem look like a device problem.
# Reproduced by running the identical command line against a fresh directory, where
# it correctly requests distribution.
rm -rf "$work/dd"
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
  MARKETING_VERSION="$marketing_version" \
  CURRENT_PROJECT_VERSION="$build_number" \
  DEVELOPMENT_TEAM="$APPLE_TEAM_ID" \
  CODE_SIGN_STYLE=Automatic \
  -allowProvisioningUpdates \
  -skipPackagePluginValidation \
  2>&1 | tail -120
# `tail -60` keeps the report readable while still showing the resolved signing
# settings and the profile types Xcode asked for. Truncating harder than this hid
# the very lines that distinguish a development profile request from a distribution
# one, which is the difference between a signing-mode bug and a device problem.

if [ ! -d "$archive_path" ]; then
  echo "FAIL: no archive was produced at $archive_path" >&2
  exit 1
fi

# Discover the application bundle rather than assuming its name.
#
# The product name is deliberately not the scheme name, and the branding overlay
# changes it (the SFI scheme produces JiejieBox.app). Hardcoding either value would
# make this script wrong the moment branding changes, so it reads the archive.
# Fail closed on anything other than exactly one application: picking one of several
# would silently archive the wrong product.
app_dir="$archive_path/Products/Applications"
app_count="$(find "$app_dir" -maxdepth 1 -name '*.app' -type d 2>/dev/null | wc -l | tr -d ' ')"
if [ "$app_count" != "1" ]; then
  echo "FAIL: expected exactly one application in the archive, found $app_count" >&2
  find "$app_dir" -maxdepth 1 -name '*.app' -type d 2>/dev/null | sed 's/^/      /' >&2
  echo "      Archiving an ambiguous archive could ship the wrong product." >&2
  exit 1
fi
app="$(find "$app_dir" -maxdepth 1 -name '*.app' -type d | head -1)"
echo "archived app: $(basename "$app")"
echo "archived app: $app"

# Record what was actually built, for the report and BUILD-INFO.
built_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Info.plist" 2>/dev/null || echo '?')"
built_build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Info.plist" 2>/dev/null || echo '?')"
built_bundle="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Info.plist" 2>/dev/null || echo '?')"
echo "  CFBundleShortVersionString: $built_version"
echo "  CFBundleVersion:           $built_build"
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
gate "build number is set" test "$built_build" != "?" -a -n "$built_build"
# The archive must be signed: entitlements only exist on a signed bundle, and Apple
# validates them from the archive rather than from the export.
gate "the archive is signed" codesign --verify --strict "$app"
gate "the archive carries the network extension entitlement" \
  bash -c "codesign -d --entitlements :- '$app' 2>/dev/null | grep -q com.apple.developer.networking.networkextension"

# Entitlements come from the built extension, which exists regardless of signing.
# They are read here rather than after export because a capability that is wrong in
# the project is worth catching before the upload attempt.
appex="$app/PlugIns/Extension.appex"
gate "Packet Tunnel extension is present" test -d "$appex"
if [ -d "$appex" ]; then
  ent="$(codesign -d --entitlements :- "$appex" 2>/dev/null || true)"
  # The archive is unsigned, so entitlements may not be readable from the signature.
  # Fall back to the entitlements file the build actually used.
  if [ -z "$ent" ] && [ -f "$client/Extension/Extension.entitlements" ]; then
    ent="$(cat "$client/Extension/Extension.entitlements")"
  fi
  gate "Packet Tunnel has packet-tunnel-provider" bash -c "printf '%s' '$ent' | grep -q packet-tunnel-provider"
  gate "no multicast entitlement" bash -c "! printf '%s' '$ent' | grep -q com.apple.developer.networking.multicast"
  gate "Packet Tunnel has an App Group" bash -c "printf '%s' '$ent' | grep -q application-groups"
fi

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

# "app-store-connect" is the current name; "app-store" is deprecated and warns.
# Detecting support by grepping `xcodebuild -help` does NOT work - that text does not
# list method names - which is how the deprecated value kept being selected. This
# Xcode accepts app-store-connect, so use it directly.
method="app-store-connect"
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

# --- verify what was uploaded ------------------------------------------------
#
# destination=upload sends the build to App Store Connect and writes NO local
# artifact: the export directory is empty afterwards, for iOS exactly as for macOS.
# An earlier version of this check expected an IPA there and reported
# "the export reported success but produced no IPA" on uploads that had in fact
# succeeded - a false negative in the check, not a failed build.
#
# So verify the thing that is both checkable and meaningful: the archive the upload
# was built from. It is DEVELOPMENT-signed by design - that is what carries the
# entitlements Apple validates, and the distribution re-signing happens inside the
# export - so asserting a distribution authority here would fail on a good build.
if [ "$export_status" -eq 0 ]; then
  vfail=0
  vgate() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then echo "  PASS: $name"; else echo "  FAIL: $name" >&2; vfail=1; fi
  }
  profile="$app/embedded.mobileprovision"
  vgate "the uploaded archive is signed" codesign --verify --strict "$app"
  vgate "the signature belongs to our team" \
    bash -c "codesign -dvvv '$app' 2>&1 | grep -q 'TeamIdentifier=$APPLE_TEAM_ID'"
  vgate "it embeds a provisioning profile" test -f "$profile"
  vgate "the profile authorises this app id" \
    bash -c "security cms -D -i '$profile' 2>/dev/null | grep -q '$APPLE_IOS_APP_BUNDLE_ID'"
  vgate "no upstream team anywhere in the signature" \
    bash -c "! codesign -dvvv '$app' 2>&1 | grep -q P8XK3KHB48"
  # The entitlements Apple validated: a missing-entitlement rejection is about these.
  vgate "carries the network extension entitlement" \
    bash -c "codesign -d --entitlements :- '$app' 2>/dev/null | grep -q com.apple.developer.networking.networkextension"
  vgate "carries the App Group" \
    bash -c "codesign -d --entitlements :- '$app' 2>/dev/null | grep -q com.apple.security.application-groups"
  vgate "has no multicast entitlement" \
    bash -c "! codesign -d --entitlements :- '$app' 2>/dev/null | grep -q com.apple.developer.networking.multicast"
  [ "$vfail" -eq 0 ] || { echo "FAIL: the uploaded build is not what it should be" >&2; exit 1; }
fi

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
  # "App record ... not found" is the expected first-run state and is a one-off
  # manual step, not a build defect. Lead with it rather than making the reader
  # work through a list of unrelated possibilities.
  echo "  If the error was 'App record ... not found on App Store Connect', the app" >&2
  echo "  does not exist there yet. Create it once, then re-run:" >&2
  echo "    App Store Connect > My Apps > + > New App > iOS" >&2
  echo "    Bundle ID: $APPLE_IOS_APP_BUNDLE_ID (must match exactly)" >&2
  echo "  This is required once per app, not per build, and it is the only step in" >&2
  echo "  the TestFlight flow that cannot be done from the command line." >&2
  echo "  Otherwise check, in order: Xcode is signed in (Settings > Accounts); an" >&2
  echo "  agreement or tax form needs the Account Holder to accept it." >&2
  exit 1
fi
