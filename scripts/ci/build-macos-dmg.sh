#!/usr/bin/env bash
# Builds an UNSIGNED macOS arm64 DMG from the pinned Apple client submodule.
#
# Usage: build-macos-dmg.sh <output-dmg>
#
# # What this produces
#
#   SFM.app (arm64, unsigned) inside a compressed DMG.
#
# # Why not `make build_macos_dmg_apple`
#
# That target chains archive -> exportArchive -> create-dmg, and the export step
# reads SFM.System/Export.plist, which requests method=developer-id with two named
# provisioning profiles. Without a Developer ID certificate that export cannot
# succeed, so the upstream chain is unusable for an unsigned artifact. This script
# keeps the parts that work (build the app, verify it, wrap it in a DMG) and drops
# only the export step that requires Apple signing assets.
#
# # arm64 only
#
# The user's machine is Apple Silicon and this stage is personal testing, so no
# Intel or universal slice is built. The architecture is verified rather than
# assumed, so a stray x86_64 slice fails the build instead of shipping.
#
# # Not notarized
#
# No notarytool, no stapler, no Developer ID. Gatekeeper will warn on first launch,
# which is expected and is re-signed later.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

out="${1:?usage: build-macos-dmg.sh <output-dmg>}"
scheme="SFM.System"

# Signing configuration: mode, team, identifiers and the multicast switch all come
# from here, so nothing is hardcoded and nothing is silently defaulted in a signed
# build. See scripts/ci/apple-signing-config.sh.
eval "$("$root/scripts/ci/apple-signing-config.sh")"

work="build/apple-macos"
mkdir -p "$(dirname "$out")"

client="clients/apple"
if [ ! -d "$client" ]; then
  echo "FAIL: $client is missing; run the submodule checkout first." >&2
  exit 1
fi

if [ ! -d "$client/Libbox.xcframework" ]; then
  echo "FAIL: $client/Libbox.xcframework is missing; build it with make lib_apple first." >&2
  exit 1
fi
echo "libbox: built from this repository (clients/apple/Libbox.xcframework)"

# --- 1. Build unsigned, arm64. --------------------------------------------------
rm -rf "$work"
mkdir -p "$work"

# SwiftLint runs as a build-tool plug-in attached by one of the SFM dependencies'
# own Package.swift (nekohasekai/CodeEditSourceEditor). Its plug-in sandbox cannot
# load sourcekitdInProc, so it aborts the build with
#   SourceKittenFramework/library_wrapper.swift: Fatal error:
#   Loading sourcekitdInProc.framework/Versions/A/sourcekitdInProc failed
# Xcode offers no flag to skip EXECUTING a dependency's build-tool plug-in (only
# -skipPackagePluginValidation, which suppresses the trust prompt rather than the
# run), and this was verified to fail identically with a PRISTINE Apple client, so
# it is an environment incompatibility rather than anything this repository does.
#
# The plug-in is a lint step, so it is removed from the RESOLVED DEPENDENCY
# CHECKOUTS. Those live in DerivedData and are not part of the pinned submodule,
# so the Apple client source is untouched; resolving first makes them exist, and
# the edit then applies to whichever file actually attaches it.
echo "resolving packages"
xcodebuild -resolvePackageDependencies \
  -project "$client/sing-box.xcodeproj" \
  -scheme "$scheme" \
  -derivedDataPath "$work/dd" >/dev/null 2>&1 || true

removed_plugins=0
while IFS= read -r pkg; do
  # Skip the plug-in package's own manifest: it declares itself, which is not an
  # attachment and must be left alone. The script enforces this too; checking here
  # as well keeps the log honest about what was actually changed.
  case "$(basename "$(dirname "$pkg")")" in
    SwiftLintPlugin) continue ;;
  esac
  if grep -q "SwiftLintPlugin" "$pkg"; then
    python3 "$root/scripts/ci/strip-swiftlint-plugin.py" "$pkg"
    removed_plugins=$((removed_plugins + 1))
    echo "  dropped SwiftLint plug-in from $(basename "$(dirname "$pkg")")"
  fi
done < <(find "$work/dd/SourcePackages/checkouts" -maxdepth 2 -name Package.swift 2>/dev/null | sort)

if [ "$removed_plugins" -eq 0 ]; then
  echo "  note: no SwiftLint plug-in attachment found in the resolved packages"
fi

# --- signing mode ------------------------------------------------------------
#
# The two modes differ in exactly one way: whether Xcode is allowed to sign.
#
#   unsigned     No identity, no entitlements, no provisioning. Produces a
#                structurally valid app for CI and packaging checks. Its App Group
#                and System Extension do NOT work at runtime, and the summary says
#                so rather than implying otherwise.
#
#   development  Xcode signs every target with the configured team, so the nested
#                System Extension, share extension and helper each get their own
#                correct signature, entitlements and profile. This is the mode that
#                produces something runnable.
#
# Entitlements are deliberately NOT cleared in development mode. Doing so is what
# silently removes the App Group and Network Extension capabilities, producing an
# app that installs and then cannot connect - the exact failure this mode exists to
# prevent.
build_settings=(
  -project "$client/sing-box.xcodeproj"
  -scheme "$scheme"
  -configuration Release
  -destination 'generic/platform=macOS'
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
  echo "building $scheme (Release, macOS, arm64, UNSIGNED)"
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
  echo "building $scheme (Release, macOS, arm64, DEVELOPMENT-SIGNED)"
  echo "  team:      $APPLE_TEAM_ID"
  echo "  base id:   $APPLE_BASE_BUNDLE_ID"
  echo "  app group: $APPLE_APP_GROUP_ID"
  echo "  style:     $APPLE_SIGNING_STYLE"
  # The identifiers are overridden from one base so the whole target set stays
  # consistent, and the project's own upstream values are replaced rather than
  # edited in place.
  build_settings+=(
    BASE_PACKAGE_IDENTIFIER="$APPLE_BASE_BUNDLE_ID"
    DEVELOPMENT_TEAM="$APPLE_TEAM_ID"
  )
  if [ "$APPLE_SIGNING_STYLE" = "automatic" ]; then
    build_settings+=(CODE_SIGN_STYLE=Automatic -allowProvisioningUpdates)
  else
    build_settings+=(
      CODE_SIGN_STYLE=Manual
      PROVISIONING_PROFILE_SPECIFIER="$MACOS_APP_PROFILE"
    )
  fi
fi

xcodebuild build "${build_settings[@]}" 2>&1 | tail -40

# A signed build that did not actually sign is a failure, not a warning. Xcode can
# succeed while skipping signing if a setting is wrong, and the resulting app looks
# built but cannot install.
if [ "$APPLE_SIGNING_MODE" = "development" ]; then
  built_app="$(find "$work/dd/Build/Products/Release" -maxdepth 1 -name '*.app' -type d | head -1)"
  if [ -z "$built_app" ]; then
    echo "FAIL: no .app was produced; cannot verify the development signature" >&2
    exit 1
  fi
  if ! codesign -dv "$built_app" >/dev/null 2>&1; then
    echo "FAIL: APPLE_SIGNING_MODE=development but the app is not signed." >&2
    echo "      The build succeeded without applying a signature, which means it" >&2
    echo "      would install but could not reach its App Group or start its tunnel." >&2
    exit 1
  fi
  echo "  signature applied: $(codesign -dv "$built_app" 2>&1 | grep -E '^Authority=' | head -1)"
fi

# --- 2. Locate the app. ---------------------------------------------------------
# The bundle name is NOT the scheme name: the SFM.System scheme produces SFM.app.
# Read it from the scheme rather than hardcoding either.
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

# --- 3. Verify structure and architecture before packaging. --------------------
fail=0
app_name="$(basename "$app")"

exe="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null || true)"
main_bin="$app/Contents/MacOS/$exe"
if [ ! -f "$main_bin" ]; then
  echo "FAIL: no main executable at Contents/MacOS/$exe" >&2
  fail=1
else
  archs="$(lipo -archs "$main_bin" 2>/dev/null || true)"
  echo "main executable: $exe"
  echo "  archs: $archs"
  shasum -a 256 "$main_bin" | awk '{print "  sha256: "$1}'
  case "$archs" in
    *x86_64*) echo "FAIL: an x86_64 slice is present; this stage is arm64 only" >&2; fail=1 ;;
  esac
  case "$archs" in
    *arm64*) ;;
    *) echo "FAIL: the main executable is not arm64" >&2; fail=1 ;;
  esac
  file "$main_bin"
fi

for key in CFBundleIdentifier CFBundleVersion CFBundleShortVersionString; do
  val="$(/usr/libexec/PlistBuddy -c "Print :$key" "$app/Contents/Info.plist" 2>/dev/null || true)"
  printf '  %-26s %s\n' "$key" "${val:-<MISSING>}"
  [ -n "$val" ] || { echo "FAIL: $key is missing" >&2; fail=1; }
done

# Embedded content: extensions and frameworks must not smuggle in an Intel slice.
echo "embedded content:"
while IFS= read -r nested; do
  rel="${nested#$app/Contents/}"
  narchs="$(lipo -archs "$nested" 2>/dev/null || true)"
  [ -n "$narchs" ] || continue
  echo "  $rel -> $narchs"
  case "$narchs" in
    *x86_64*) echo "FAIL: $rel contains an x86_64 slice" >&2; fail=1 ;;
  esac
done < <(find "$app/Contents" \( -path "*/MacOS/*" -o -path "*frameworks/*" -o -name "*.appex" \) -type f -perm +111 2>/dev/null | sort -u | head -40)

[ "$fail" -eq 0 ] || { echo "FAIL: macOS app verification failed" >&2; exit 1; }

# --- 4. Build the DMG. ----------------------------------------------------------
# create-dmg makes a Finder-friendly disk image. If it is unavailable, hdiutil
# produces an equivalent (if plainer) image, so the build does not depend on a
# Homebrew formula being installed.
dmg_stage="$work/dmg"
rm -rf "$dmg_stage"
mkdir -p "$dmg_stage"
ditto "$app" "$dmg_stage/$app_name"
ln -s /Applications "$dmg_stage/Applications"

rm -f "$out"
if command -v create-dmg >/dev/null 2>&1; then
  echo "packaging with create-dmg"
  icon="$app/Contents/Resources/AppIcon.icns"
  icon_args=()
  [ -f "$icon" ] && icon_args=(--volicon "$icon")
  create-dmg \
    --volname "sing-box" \
    "${icon_args[@]}" \
    --icon "$app_name" 0 0 \
    --hide-extension "$app_name" \
    --app-drop-link 0 0 \
    --skip-jenkins \
    "$out" "$dmg_stage" >/dev/null 2>&1 || {
      echo "create-dmg failed; falling back to hdiutil" >&2
      rm -f "$out"
      hdiutil create -volname "sing-box" -srcfolder "$dmg_stage" -ov -format UDZO "$out" >/dev/null
    }
else
  echo "create-dmg not installed; packaging with hdiutil"
  hdiutil create -volname "sing-box" -srcfolder "$dmg_stage" -ov -format UDZO "$out" >/dev/null
fi

if [ ! -f "$out" ]; then
  echo "FAIL: no DMG was produced at $out" >&2
  exit 1
fi

# --- 5. Verify the DMG actually contains the app. ------------------------------
# A DMG that mounts but lacks the app is the failure mode worth catching here.
mount_point="$work/mnt"
mkdir -p "$mount_point"
if hdiutil attach "$out" -mountpoint "$mount_point" -nobrowse -readonly >/dev/null 2>&1; then
  if [ ! -d "$mount_point/$app_name" ]; then
    echo "FAIL: $app_name is not present inside the mounted DMG" >&2
    ls -la "$mount_point" >&2
    hdiutil detach "$mount_point" >/dev/null 2>&1 || true
    exit 1
  fi
  mounted_exe="$mount_point/$app_name/Contents/MacOS/$exe"
  mounted_archs="$(lipo -archs "$mounted_exe" 2>/dev/null || true)"
  echo "mounted DMG: $app_name present, executable archs: $mounted_archs"
  case "$mounted_archs" in
    *arm64*) ;;
    *) echo "FAIL: the app inside the DMG is not arm64" >&2; hdiutil detach "$mount_point" >/dev/null 2>&1 || true; exit 1 ;;
  esac
  hdiutil detach "$mount_point" >/dev/null 2>&1 || true
else
  echo "FAIL: the DMG could not be mounted for verification" >&2
  exit 1
fi

echo "built: $out"
echo "bytes: $(wc -c < "$out" | tr -d ' ')"
echo "sha256: $(shasum -a 256 "$out" | awk '{print $1}')"
