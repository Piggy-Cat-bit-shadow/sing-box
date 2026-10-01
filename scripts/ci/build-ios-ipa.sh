#!/usr/bin/env bash
# Builds an UNSIGNED iOS arm64 IPA from the pinned Apple client submodule.
#
# Usage: build-ios-ipa.sh <output-ipa> [--app-name SFI]
#
# # What this produces
#
# A structurally complete, unsigned iPhoneOS arm64 app packaged as an IPA:
#
#   Payload/SFI.app/
#   Payload/SFI.app/PlugIns/Extension.appex      <- the Packet Tunnel provider
#
# "Unsigned" means no Apple signing identity was applied. That is deliberate: this
# artifact exists to be RE-SIGNED later with a real certificate and provisioning
# profile. Nothing here contacts Apple, uses a certificate, a provisioning profile,
# a Team ID or App Store Connect.
#
# # Why `build` and not `archive`
#
# `xcodebuild archive` with Export.plist performs an export step that expects a real
# provisioning profile. For an unsigned artifact that step cannot succeed, so this
# builds the app directly (Release, iphoneos, arm64) and packages the resulting
# bundle. The output is the same app bundle an archive would contain.
#
# # The Packet Tunnel extension is not optional
#
# sing-box on iOS is a Network Extension: the app is a shell and the tunnel lives in
# the .appex. An IPA without PlugIns/ is a broken product, so its presence and
# architecture are asserted at the end rather than assumed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

out="${1:?usage: build-ios-ipa.sh <output-ipa>}"
shift || true
scheme="SFI"

# Signing configuration: mode, team, identifiers and the multicast switch.
eval "$("$root/scripts/ci/apple-signing-config.sh")"

work="build/apple-ios"
mkdir -p "$(dirname "$out")"

client="clients/apple"
if [ ! -d "$client" ]; then
  echo "FAIL: $client is missing; run the submodule checkout first." >&2
  exit 1
fi

# --- 1. The libbox the app links must come from THIS repository. ----------------
if [ ! -d "$client/Libbox.xcframework" ]; then
  echo "FAIL: $client/Libbox.xcframework is missing." >&2
  echo "      The Apple app would link no libbox, or an upstream one." >&2
  echo "      Build it from this repository first: make lib_apple" >&2
  exit 1
fi

echo "libbox: built from this repository (clients/apple/Libbox.xcframework)"
echo "        $(find "$client/Libbox.xcframework/ios-arm64" -name Libbox -type f | head -1)"

# --- 2. Build unsigned. ---------------------------------------------------------
rm -rf "$work"
mkdir -p "$work"

echo "building $scheme (Release, iphoneos, arm64, unsigned)"

# These settings are what make the build unsigned. CODE_SIGNING_ALLOWED=NO stops
# Xcode from requiring an identity; the empty identity and the "do not embed
# profiles" flags keep it from reaching for a provisioning profile. ENTITLEMENTS
# are still processed, because the app must declare what it will be signed FOR -
# only the signature itself is absent.
# Resolve packages as a separate step before building.
#
# Without this, xcodebuild resolves the package graph inline during the build, and
# Xcode's SwiftPM integration has been observed to abort there:
#
#   ** INTERNAL ERROR: Uncaught exception **
#   -[NSMutableArray insertObjects:atIndexes:]: count of array (26) differs from
#   count of index set (25)   (IDESwiftPackageCore.registerDependencyFileReferences)
#
# That is an Xcode crash rather than a fault in this project, and it is not
# deterministic - the same commit built fine locally afterwards, and the macOS job,
# which already resolved packages up front, passed on the very same CI run.
# Resolving first keeps the two phases separate and gives the graph a chance to be
# complete before the build reads it.
echo "resolving packages"
xcodebuild -resolvePackageDependencies \
  -project "$client/sing-box.xcodeproj" \
  -scheme "$scheme" \
  -derivedDataPath "$work/dd" >/dev/null 2>&1 || true

build_settings=(
  -project "$client/sing-box.xcodeproj"
  -scheme "$scheme"
  -configuration Release
  -destination 'generic/platform=iOS'
  -derivedDataPath "$work/dd"
  ARCHS=arm64
  ONLY_ACTIVE_ARCH=NO
  -skipPackagePluginValidation
  # APP_GROUP_IDENTIFIER is passed for BOTH modes, because the project defines it
  # inconsistently: the iOS targets use "group.$(BASE_PACKAGE_IDENTIFIER)" while
  # ten macOS configuration blocks use
  # "$(TeamIdentifierPrefix)$(BASE_PACKAGE_IDENTIFIER)". TeamIdentifierPrefix comes
  # from provisioning and is empty outside a signed build, so the macOS value
  # collapses to a bare bundle identifier. That is not a valid App Group at all,
  # and it is why the app could not open its shared container: the host app and the
  # extension resolved to different, unusable paths.
  #
  # Passing it here overrides every one of those blocks at once, so all targets
  # agree by construction rather than by two expressions coinciding.
  APP_GROUP_IDENTIFIER="$APPLE_APP_GROUP_ID"
)

if [ "$APPLE_SIGNING_MODE" = "unsigned" ]; then
  echo "building $scheme (Release, iphoneos, arm64, UNSIGNED)"
  build_settings+=(
    CODE_SIGNING_ALLOWED=NO
    CODE_SIGNING_REQUIRED=NO
    CODE_SIGN_IDENTITY=""
    CODE_SIGN_ENTITLEMENTS=""
    EXPANDED_CODE_SIGN_IDENTITY=""
    PROVISIONING_PROFILE_SPECIFIER=""
    DEVELOPMENT_TEAM=""
  )
else
  echo "building $scheme (Release, iphoneos, arm64, DEVELOPMENT-SIGNED)"
  echo "  team:      $APPLE_TEAM_ID"
  echo "  base id:   $APPLE_BASE_BUNDLE_ID"
  echo "  app group: $APPLE_APP_GROUP_ID"
  echo "  style:     $APPLE_SIGNING_STYLE"
  # Signing is left ENABLED so Xcode signs each target itself, including the
  # Packet Tunnel extension. Clearing CODE_SIGN_ENTITLEMENTS here would strip the
  # App Group and networkextension capabilities, which is precisely the failure
  # this mode exists to avoid.
  build_settings+=(
    BASE_PACKAGE_IDENTIFIER="$APPLE_BASE_BUNDLE_ID"
    DEVELOPMENT_TEAM="$APPLE_TEAM_ID"
  )
  if [ "$APPLE_SIGNING_STYLE" = "automatic" ]; then
    build_settings+=(CODE_SIGN_STYLE=Automatic -allowProvisioningUpdates)
  else
    build_settings+=(
      CODE_SIGN_STYLE=Manual
      PROVISIONING_PROFILE_SPECIFIER="$IOS_APP_PROFILE"
    )
  fi
fi

xcodebuild build "${build_settings[@]}" 2>&1 | tail -40

# --- 3. Locate the built app. ---------------------------------------------------
# The bundle name is NOT the scheme name: the SFI scheme produces `sing-box.app`.
# Read it from the scheme so a rename upstream cannot silently break this.
product_name="$(grep -oE 'BuildableName = "[^"]*\.app"' "$client/sing-box.xcodeproj/xcshareddata/xcschemes/$scheme.xcscheme" | head -1 | sed -E 's/.*"([^"]*)".*/\1/')"
if [ -z "$product_name" ]; then
  echo "FAIL: could not determine the product name for scheme $scheme" >&2
  exit 1
fi
echo "product: $product_name"

app="$(find "$work/dd/Build/Products" -maxdepth 2 -name "$product_name" -type d | head -1)"
if [ -z "$app" ]; then
  echo "FAIL: $product_name was not produced under $work/dd/Build/Products" >&2
  find "$work/dd/Build/Products" -maxdepth 2 -type d | head -20 >&2
  exit 1
fi
echo "built app: $app"

# --- 4. Package as an IPA. ------------------------------------------------------
stage="$work/ipa"
rm -rf "$stage"
mkdir -p "$stage/Payload"
# ditto preserves symlinks, resource forks and the framework bundle layout, which a
# plain cp -R can flatten inside .framework directories.
ditto "$app" "$stage/Payload/$product_name"

# --- 5. Strip the misleading residue of any previous signature. -----------------
# The build is unsigned, but Xcode may still leave a _CodeSignature directory or an
# embedded provisioning profile behind. Their presence would suggest the app carries
# a signature it does not have, which is exactly the confusion this artifact must
# avoid. Only these are removed - never binaries, Info.plist, PlugIns or resources.
if [ "$APPLE_SIGNING_MODE" = "unsigned" ]; then
  while IFS= read -r residue; do
    echo "  removing $residue"
    rm -rf "$residue"
  done < <(find "$stage/Payload" \( -name "_CodeSignature" -o -name "embedded.mobileprovision" \) -print)
else
  # The signature and its embedded profile are the deliverable in this mode.
  echo "  keeping signature and embedded provisioning profiles"
fi

# --- 6. Assert the bundle is complete and iPhoneOS/arm64. ----------------------
fail=0

main_bin="$stage/Payload/$product_name/${product_name%.app}"
if [ ! -f "$main_bin" ]; then
  # The executable name is recorded in Info.plist, not assumed to equal the bundle.
  exec_name="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$stage/Payload/$product_name/Info.plist" 2>/dev/null || true)"
  main_bin="$stage/Payload/$product_name/$exec_name"
fi
if [ ! -f "$main_bin" ]; then
  echo "FAIL: the main executable was not found" >&2
  fail=1
else
  echo "main executable: $(basename "$main_bin")"
  archs="$(lipo -archs "$main_bin" 2>/dev/null || true)"
  echo "  archs: $archs"
  case "$archs" in
    *arm64*) ;;
    *) echo "FAIL: the main executable is not arm64" >&2; fail=1 ;;
  esac
  # A simulator build must never ship.
  if otool -l "$main_bin" 2>/dev/null | grep -A 4 LC_BUILD_VERSION | grep -qiE "platform +[37]\b"; then
    echo "FAIL: the main executable targets the simulator, not iPhoneOS" >&2
    fail=1
  fi
  platform="$(otool -l "$main_bin" 2>/dev/null | grep -A 4 LC_BUILD_VERSION | awk '/platform/{print $2; exit}')"
  echo "  platform: ${platform:-unknown} (2 = iPhoneOS)"
  [ "${platform:-}" = "2" ] || { echo "FAIL: main executable is not an iPhoneOS build" >&2; fail=1; }
fi

# The Packet Tunnel extension is the product. Its absence is always a failure.
appex_dir="$stage/Payload/$product_name/PlugIns"
if [ ! -d "$appex_dir" ]; then
  echo "FAIL: PlugIns/ is missing; the app has no extensions" >&2
  fail=1
else
  appex_count="$(find "$appex_dir" -maxdepth 1 -name '*.appex' | wc -l | tr -d ' ')"
  echo "extensions: $appex_count"
  [ "$appex_count" -gt 0 ] || { echo "FAIL: no .appex was packaged" >&2; fail=1; }

  # At least one extension must be the packet tunnel provider.
  tunnel_found=0
  while IFS= read -r appex; do
    point="$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionPointIdentifier' "$appex/Info.plist" 2>/dev/null || true)"
    name="$(basename "$appex")"
    echo "  $name -> ${point:-<no extension point>}"
    if [ "$point" = "com.apple.networkextension.packet-tunnel" ]; then
      tunnel_found=1
      exe="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$appex/Info.plist" 2>/dev/null || true)"
      if [ -z "$exe" ] || [ ! -f "$appex/$exe" ]; then
        echo "FAIL: $name has no executable" >&2; fail=1
      else
        earchs="$(lipo -archs "$appex/$exe" 2>/dev/null || true)"
        echo "    archs: $earchs"
        case "$earchs" in
          *arm64*) ;;
          *) echo "FAIL: the packet tunnel executable is not arm64" >&2; fail=1 ;;
        esac
        eplatform="$(otool -l "$appex/$exe" 2>/dev/null | grep -A 4 LC_BUILD_VERSION | awk '/platform/{print $2; exit}')"
        echo "    platform: ${eplatform:-unknown} (2 = iPhoneOS)"
        [ "${eplatform:-}" = "2" ] || { echo "FAIL: the packet tunnel is not an iPhoneOS build" >&2; fail=1; }
      fi
    fi
  done < <(find "$appex_dir" -maxdepth 1 -name '*.appex' | sort)

  [ "$tunnel_found" -eq 1 ] || {
    echo "FAIL: no extension declares com.apple.networkextension.packet-tunnel" >&2; fail=1; }
fi

# Info.plist essentials.
info="$stage/Payload/$product_name/Info.plist"
for key in CFBundleIdentifier CFBundleExecutable CFBundlePackageType CFBundleVersion CFBundleShortVersionString MinimumOSVersion; do
  val="$(/usr/libexec/PlistBuddy -c "Print :$key" "$info" 2>/dev/null || true)"
  printf '  %-26s %s\n' "$key" "${val:-<MISSING>}"
  [ -n "$val" ] || { echo "FAIL: $key is missing from the app Info.plist" >&2; fail=1; }
done

# No Apple signature may be present: this artifact is unsigned by design.
# "not signed at all" is the EXPECTED state, not a failure.
if codesign -dv "$stage/Payload/$product_name" >/dev/null 2>&1; then
  echo "  note: the bundle carries a signature (Xcode ad-hoc or otherwise)"
  codesign -dv "$stage/Payload/$product_name" 2>&1 | grep -E "Authority|Signature|Identifier" | head -3 || true
else
  echo "  signature: not signed at all (expected for an unsigned artifact)"
fi

[ "$fail" -eq 0 ] || { echo "FAIL: iOS bundle verification failed" >&2; exit 1; }

# --- 7. Zip it. -----------------------------------------------------------------
# Resolve the output to an absolute path BEFORE changing directory. Evaluating
# `dirname "$out"` inside the subshell would resolve a relative output against the
# staging directory instead of the caller's working directory.
mkdir -p "$(dirname "$out")"
out_abs="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
# zip from inside the staging directory so the archive root is exactly Payload/.
( cd "$stage" && zip -qry "$out_abs" Payload )

echo "built: $out"
echo "bytes: $(wc -c < "$out" | tr -d ' ')"
echo "sha256: $(shasum -a 256 "$out" | awk '{print $1}')"
