#!/usr/bin/env bash
# Regression tests for the macOS TestFlight app name.
#
# Usage: test-apple-macos-name.sh [--source-dir <dir>]
#
# # The failure this exists for
#
# The macOS TestFlight app installed as `sing-box`. The iOS branding overlay brands the
# SFI target only, and the macOS App Store product is a different target (SFM), so
# nothing renamed it. Every pre-upload gate looked at identifiers, entitlements and
# signing, so the wrong name reached Apple unchallenged.
#
# # What is asserted
#
#   1. the macOS overlay brands SFM Debug and Release, and the SFM scheme's application
#      buildable, and nothing else
#   2. running it twice changes nothing (idempotent)
#   3. it FAILS CLOSED: a partially branded project, a configuration set it does not
#      recognise, a scheme in an ambiguous or unknown state, a missing project
#   4. the iOS overlay is unaffected: it still brands SFI and still leaves SFM alone,
#      and the macOS overlay does not touch SFI
#   5. prepare-apple-client.sh routes each platform to its own overlay
#   6. the pre-upload name gate passes a Jiejiebox bundle and FAILS a sing-box one
#   7. the pinned macOS source really is the structure the overlay was written for, and
#      the overlay really does apply to it
#
# # Fixtures
#
# Checks 1-4 run against a small synthetic Xcode project written by this script: three
# targets share PRODUCT_NAME = "sing-box" and near-identical configuration bodies, which
# is exactly the shape an implementation that located configurations by body text rather
# than by id would get wrong. Synthetic means no network and no Apple checkout, and makes
# the fail-closed cases expressible at all - they are corruptions of a known-good fixture.
#
# Check 7 then reads the REAL pinned project, because a fixture can only prove the overlay
# is self-consistent; it cannot prove it matches the source it will be applied to. That is
# the failure this task exists for - an overlay that was right about a target nobody built.
# Where no macOS checkout is present, check 7 is reported as SKIPPED, never as a pass.
#
# # When it must run
#
# Check 7 asserts the PINNED state - the sing-box anchors are present and the checkout is
# unmodified - and applies the overlay to a COPY rather than in place. It therefore has to
# run BEFORE prepare-apple-client.sh brands the real checkout: a run afterwards would be
# asking the suite to observe a pristine source that the build overlays had already
# rewritten, and it would fail on a perfectly correct build. The workflow runs it at that
# point. --source-dir overrides which checkout is read, so the ordering can be demonstrated
# locally against a checkout whose phase this script does not otherwise know.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

source_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --source-dir) source_dir="${2:?--source-dir needs a directory}"; shift 2 ;;
    *) echo "test-apple-macos-name: unknown argument: $1" >&2; exit 2 ;;
  esac
done

overlay="$root/scripts/ci/apply-apple-macos-branding-overlay.py"
ios_overlay="$root/scripts/ci/apply-apple-branding-overlay.py"
name_gate="$root/scripts/ci/check-macos-app-name.sh"

pass=0
fail=0
skip=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS: $name"
    pass=$((pass + 1))
  else
    echo "  FAIL: $name" >&2
    fail=$((fail + 1))
  fi
}

expects_fail() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  FAIL: $name (expected failure, but it succeeded)" >&2
    fail=$((fail + 1))
  else
    echo "  PASS: $name"
    pass=$((pass + 1))
  fi
}

skipped() {
  echo "  SKIP: $1"
  skip=$((skip + 1))
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

brand="$(sed -nE 's/^NEW_NAME = "([^"]+)".*/\1/p' "$overlay" | head -1)"
if [ -z "$brand" ]; then
  echo "FAIL: the macOS overlay declares no NEW_NAME" >&2
  exit 1
fi
echo "macOS product brand under test: $brand"

if [ ! -f "$overlay" ] || [ ! -f "$name_gate" ]; then
  echo "FAIL: the macOS branding overlay or the name gate is missing" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# The fixture
# ---------------------------------------------------------------------------
write_fixture() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir/sing-box.xcodeproj/xcshareddata/xcschemes"

  cat > "$dir/sing-box.xcodeproj/project.pbxproj" <<'PBX'
// !$*UTF8*$!
{
	archiveVersion = 1;
	objects = {

/* Begin PBXNativeTarget section */
		AAAAAAAAAAAAAAAAAAAAAAAA /* SFM */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = AAAAAAAAAAAAAAAA000001 /* Build configuration list for PBXNativeTarget "SFM" */;
			name = SFM;
		};
		BBBBBBBBBBBBBBBBBBBBBBBB /* SFM.System */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = BBBBBBBBBBBBBBBB000001 /* Build configuration list for PBXNativeTarget "SFM.System" */;
			name = "SFM.System";
		};
		CCCCCCCCCCCCCCCCCCCCCCCC /* SFI */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = CCCCCCCCCCCCCCCC000001 /* Build configuration list for PBXNativeTarget "SFI" */;
			name = SFI;
		};
		DDDDDDDDDDDDDDDDDDDDDDDD /* SFT */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = DDDDDDDDDDDDDDDD000001 /* Build configuration list for PBXNativeTarget "SFT" */;
			name = SFT;
		};
/* End PBXNativeTarget section */

/* Begin XCConfigurationList section */
		AAAAAAAAAAAAAAAA000001 /* Build configuration list for PBXNativeTarget "SFM" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				3AEC21162A459B1A00A63465 /* Debug */,
				3AEC21172A459B1A00A63465 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		BBBBBBBBBBBBBBBB000001 /* Build configuration list for PBXNativeTarget "SFM.System" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				3AEECC112A6DF9CA006A0E0C /* Debug */,
				3AEECC122A6DF9CA006A0E0C /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		CCCCCCCCCCCCCCCC000001 /* Build configuration list for PBXNativeTarget "SFI" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				3AEC20FF2A459AB500A63465 /* Debug */,
				3AEC21002A459AB500A63465 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		DDDDDDDDDDDDDDDD000001 /* Build configuration list for PBXNativeTarget "SFT" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				3AC03BA12A72BF3500B7946F /* Debug */,
				3AC03BA22A72BF3500B7946F /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
/* End XCConfigurationList section */

/* Begin XCBuildConfiguration section */
		3AEC21162A459B1A00A63465 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				CODE_SIGN_ENTITLEMENTS = SFM/SFM.entitlements;
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER)";
				PRODUCT_NAME = "sing-box";
			};
			name = Debug;
		};
		3AEC21172A459B1A00A63465 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				CODE_SIGN_ENTITLEMENTS = SFM/SFM.entitlements;
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER)";
				PRODUCT_NAME = "sing-box";
			};
			name = Release;
		};
		3AEECC112A6DF9CA006A0E0C /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER).standalone";
				PRODUCT_NAME = SFM;
			};
			name = Debug;
		};
		3AEECC122A6DF9CA006A0E0C /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER).standalone";
				PRODUCT_NAME = SFM;
			};
			name = Release;
		};
		3AEC20FF2A459AB500A63465 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER)";
				PRODUCT_NAME = "sing-box";
			};
			name = Debug;
		};
		3AEC21002A459AB500A63465 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER)";
				PRODUCT_NAME = "sing-box";
			};
			name = Release;
		};
		3AC03BA12A72BF3500B7946F /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER)";
				PRODUCT_NAME = "sing-box";
			};
			name = Debug;
		};
		3AC03BA22A72BF3500B7946F /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER)";
				PRODUCT_NAME = "sing-box";
			};
			name = Release;
		};
/* End XCBuildConfiguration section */
	};
	rootObject = FFFFFFFFFFFFFFFFFFFFFFFF /* Project object */;
}
PBX

  cat > "$dir/sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme" <<'SCHEME'
<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion = "2620" version = "1.7">
   <BuildAction parallelizeBuildables = "YES">
      <BuildActionEntries>
         <BuildActionEntry buildForTesting = "YES" buildForRunning = "YES">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "3AEC21082A459B1900A63465"
               BuildableName = "sing-box.app"
               BlueprintName = "SFM"
               ReferencedContainer = "container:sing-box.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <TestAction buildConfiguration = "Debug">
      <Testables>
         <TestableReference skipped = "NO">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "3A6313A62F0CEFDD0060A550"
               BuildableName = "SFMUITests.xctest"
               BlueprintName = "SFMUITests"
               ReferencedContainer = "container:sing-box.xcodeproj">
            </BuildableReference>
         </TestableReference>
      </Testables>
   </TestAction>
   <LaunchAction buildConfiguration = "Debug">
      <BuildableProductRunnable runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "3AEC21082A459B1900A63465"
            BuildableName = "sing-box.app"
            BlueprintName = "SFM"
            ReferencedContainer = "container:sing-box.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </LaunchAction>
   <ProfileAction buildConfiguration = "Release">
      <BuildableProductRunnable runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "3AEC21082A459B1900A63465"
            BuildableName = "sing-box.app"
            BlueprintName = "SFM"
            ReferencedContainer = "container:sing-box.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </ProfileAction>
</Scheme>
SCHEME
}

# Reads one setting out of one target configuration by id, so an assertion is about the
# configuration the overlay was told to edit rather than whichever similar line appears
# first in the file.
setting() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import re, sys
path, target, config, key = sys.argv[1:5]
src = open(path, encoding="utf-8").read()
m = re.search(r'Build configuration list for PBXNativeTarget "' + re.escape(target) +
              r'" \*/ = \{(.*?)\n\t\t\};', src, re.S)
if not m:
    sys.exit(1)
arr = re.search(r'buildConfigurations = \((.*?)\);', m.group(1), re.S)
for cid, name in re.findall(r'([0-9A-Fa-f]{24}) /\* (\w+) \*/', arr.group(1)):
    if name != config:
        continue
    b = re.search(rf'{cid} /\* {name} \*/ = \{{\s*isa = XCBuildConfiguration;(.*?)\n\t\t\}};',
                  src, re.S)
    if not b:
        sys.exit(1)
    v = re.search(rf'^\s*{re.escape(key)} = "?([^";]*)"?;', b.group(1), re.M)
    print(v.group(1) if v else "")
    sys.exit(0)
sys.exit(1)
PY
}

echo "== the macOS overlay brands SFM Debug and Release =="
fixture="$work/apply"
write_fixture "$fixture"

check "the overlay applies cleanly to the upstream fixture" python3 "$overlay" "$fixture"

for config in Debug Release; do
  check "SFM $config PRODUCT_NAME is $brand" \
    test "$(setting "$fixture/sing-box.xcodeproj/project.pbxproj" SFM "$config" PRODUCT_NAME)" = "$brand"
  check "SFM $config CFBundleDisplayName is $brand" \
    test "$(setting "$fixture/sing-box.xcodeproj/project.pbxproj" SFM "$config" INFOPLIST_KEY_CFBundleDisplayName)" = "$brand"
done

check "all three SFM scheme application buildables are $brand.app" \
  bash -c "test \"\$(grep -c 'BuildableName = \"$brand.app\"' '$fixture/sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme')\" = 3"

echo "== nothing else moved =="
# The fault lines: three targets share the product name and two share the display name,
# so a replacement not addressed by configuration id shows up here.
for target in SFI SFT; do
  for config in Debug Release; do
    check "$target $config PRODUCT_NAME is still sing-box" \
      test "$(setting "$fixture/sing-box.xcodeproj/project.pbxproj" "$target" "$config" PRODUCT_NAME)" = "sing-box"
    check "$target $config CFBundleDisplayName is still sing-box" \
      test "$(setting "$fixture/sing-box.xcodeproj/project.pbxproj" "$target" "$config" INFOPLIST_KEY_CFBundleDisplayName)" = "sing-box"
  done
done
for config in Debug Release; do
  check "SFM.System $config keeps PRODUCT_NAME = SFM" \
    test "$(setting "$fixture/sing-box.xcodeproj/project.pbxproj" SFM.System "$config" PRODUCT_NAME)" = "SFM"
  check "SFM.System $config keeps CFBundleDisplayName = sing-box" \
    test "$(setting "$fixture/sing-box.xcodeproj/project.pbxproj" SFM.System "$config" INFOPLIST_KEY_CFBundleDisplayName)" = "sing-box"
done
check "the SFM.System bundle id is unchanged" \
  grep -q 'PRODUCT_BUNDLE_IDENTIFIER = "\$(BASE_PACKAGE_IDENTIFIER).standalone";' \
    "$fixture/sing-box.xcodeproj/project.pbxproj"
check "the app bundle id is unchanged" \
  grep -q 'PRODUCT_BUNDLE_IDENTIFIER = "\$(BASE_PACKAGE_IDENTIFIER)";' \
    "$fixture/sing-box.xcodeproj/project.pbxproj"
check "the extension buildable is untouched" \
  grep -q 'BuildableName = "SFMUITests.xctest"' \
    "$fixture/sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme"
check "the SFM target is still called SFM" \
  grep -q 'Build configuration list for PBXNativeTarget "SFM"' \
    "$fixture/sing-box.xcodeproj/project.pbxproj"

echo "== a second apply changes nothing =="
before="$(cat "$fixture/sing-box.xcodeproj/project.pbxproj" "$fixture/sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme" | shasum | awk '{print $1}')"
check "the overlay is idempotent" python3 "$overlay" "$fixture"
after="$(cat "$fixture/sing-box.xcodeproj/project.pbxproj" "$fixture/sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme" | shasum | awk '{print $1}')"
check "re-applying produced byte-identical files" test "$before" = "$after"

echo "== the macOS overlay's field-wise state machine =="
# The overlay decides each FIELD on its own, by exact equality:
#
#     value == old  ->  rewrite to new
#     value == new  ->  already satisfied, leave it
#     anything else ->  hard fail
#
# Per-field rather than per-configuration, because the pinned Apple source really ships a mixed
# configuration: SFM Debug and Release carry PRODUCT_NAME = "sing-box" with
# INFOPLIST_KEY_CFBundleDisplayName = "Jiejiebox" - the display name a user reads is branded and
# the upstream product identifier is not. Treating that as partial corruption refused to build a
# valid source; every case below is asserted so the state machine cannot silently lose a
# transition.
#
# `set_field` writes one field of one SFM configuration to an exact value, which is how each
# starting state is constructed.
set_field() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import re, sys
path, cid, key, value = sys.argv[1:5]
src = open(path, encoding="utf-8").read()
# The id appears FIRST in the configuration LIST, as a bare reference, and only later as the
# definition. Anchoring on `cid /* Name */ = {` selects the definition; a plain str.index(cid)
# lands on the reference and silently finds no fields.
m = re.search(rf'{re.escape(cid)} /\* \w+ \*/ = \{{', src)
if not m:
    sys.exit(f"set_field: no block definition for {cid}")
i = m.start()
j = src.index("\n\t\t};", i)
block = src[i:j]
new_block, n = re.subn(rf'^(\s*{re.escape(key)} = )"[^"]*";', rf'\g<1>"{value}";', block, flags=re.M)
if n != 1:
    sys.exit(f"set_field: {key} matched {n} times in {cid}")
open(path, "w", encoding="utf-8").write(src[:i] + new_block + src[j:])
PY
}
sfm_debug=3AEC21162A459B1A00A63465
sfm_release=3AEC21172A459B1A00A63465

# --- old/old: the plain upstream project, fully overlaid --------------------
both_upstream="$work/matrix-old-old"
write_fixture "$both_upstream"
check "old/old: the overlay applies" python3 "$overlay" "$both_upstream"
for config in Debug Release; do
  check "old/old: SFM $config PRODUCT_NAME is now $brand" \
    test "$(setting "$both_upstream/sing-box.xcodeproj/project.pbxproj" SFM "$config" PRODUCT_NAME)" = "$brand"
  check "old/old: SFM $config display name is now $brand" \
    test "$(setting "$both_upstream/sing-box.xcodeproj/project.pbxproj" SFM "$config" INFOPLIST_KEY_CFBundleDisplayName)" = "$brand"
done

# --- old/new: the SOURCE-OWNED mixed state; only the rest is overlaid -------
# This is the shape the pinned Apple source actually ships, so it is the case that matters.
source_mixed="$work/matrix-old-new"
write_fixture "$source_mixed"
for cid in $sfm_debug $sfm_release; do
  set_field "$source_mixed/sing-box.xcodeproj/project.pbxproj" "$cid" INFOPLIST_KEY_CFBundleDisplayName "$brand"
done
check "old/new: the fixture really carries the source-owned display name" \
  test "$(setting "$source_mixed/sing-box.xcodeproj/project.pbxproj" SFM Debug INFOPLIST_KEY_CFBundleDisplayName)" = "$brand"
check "old/new: and still the upstream product name" \
  test "$(setting "$source_mixed/sing-box.xcodeproj/project.pbxproj" SFM Debug PRODUCT_NAME)" = "sing-box"
check "old/new: the overlay completes the remaining field" python3 "$overlay" "$source_mixed"
for config in Debug Release; do
  check "old/new: SFM $config PRODUCT_NAME is now $brand" \
    test "$(setting "$source_mixed/sing-box.xcodeproj/project.pbxproj" SFM "$config" PRODUCT_NAME)" = "$brand"
  check "old/new: SFM $config display name is still $brand" \
    test "$(setting "$source_mixed/sing-box.xcodeproj/project.pbxproj" SFM "$config" INFOPLIST_KEY_CFBundleDisplayName)" = "$brand"
done

# --- new/new: already fully branded, so a second apply is a no-op -----------
check "new/new: a fully branded project is accepted, not refused" python3 "$overlay" "$both_upstream"

# --- unknown/new: fail closed on a value this overlay does not recognise ----
# The discriminating case: one field holds a third value. The overlay must refuse rather than
# guess, which is what keeps "exact" meaningful.
unknown_value="$work/matrix-unknown"
write_fixture "$unknown_value"
set_field "$unknown_value/sing-box.xcodeproj/project.pbxproj" "$sfm_debug" PRODUCT_NAME "SomethingElse"
expects_fail "unknown/new: an unrecognised PRODUCT_NAME is refused" python3 "$overlay" "$unknown_value"
check "unknown/new: the fixture was not modified by the refused run" \
  test "$(setting "$unknown_value/sing-box.xcodeproj/project.pbxproj" SFM Release PRODUCT_NAME)" = "sing-box"

# The states the overlay must still refuse, unchanged by the refactor.
both_branded_one_upstream="$work/partial"
write_fixture "$both_branded_one_upstream"
python3 - "$both_branded_one_upstream/sing-box.xcodeproj/project.pbxproj" "$brand" <<'PY'
import sys
p, brand = sys.argv[1], sys.argv[2]
src = open(p, encoding="utf-8").read()
old = '3AEC21162A459B1A00A63465 /* Debug */ = {'
i = src.index(old)
j = src.index('name = Debug;', i)
src = src[:i] + src[i:j].replace('"sing-box"', f'"{brand}"') + src[j:]
open(p, "w", encoding="utf-8").write(src)
PY
check "a Debug configuration branded while Release is upstream is completed, not refused" \
  python3 "$overlay" "$both_branded_one_upstream"
check "and the completed Debug keeps the brand" \
  test "$(setting "$both_branded_one_upstream/sing-box.xcodeproj/project.pbxproj" SFM Debug PRODUCT_NAME)" = "$brand"
check "and Release was brought up to the brand too" \
  test "$(setting "$both_branded_one_upstream/sing-box.xcodeproj/project.pbxproj" SFM Release PRODUCT_NAME)" = "$brand"

unexpected="$work/unexpected"
write_fixture "$unexpected"
python3 - "$unexpected/sing-box.xcodeproj/project.pbxproj" <<'PY'
import sys
p = sys.argv[1]
src = open(p, encoding="utf-8").read()
# A third configuration on SFM: new scope the overlay was never reviewed for.
src = src.replace("""				3AEC21172A459B1A00A63465 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		BBBBBBBBBBBBBBBB000001""", """				3AEC21172A459B1A00A63465 /* Release */,
				3AEC21182A459B1A00A63465 /* Profile */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		BBBBBBBBBBBBBBBB000001""", 1)
src = src.replace("""		3AEECC112A6DF9CA006A0E0C /* Debug */ = {""", """		3AEC21182A459B1A00A63465 /* Profile */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				INFOPLIST_KEY_CFBundleDisplayName = "sing-box";
				PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER)";
				PRODUCT_NAME = "sing-box";
			};
			name = Profile;
		};
		3AEECC112A6DF9CA006A0E0C /* Debug */ = {""", 1)
open(p, "w", encoding="utf-8").write(src)
PY
check "the fixture really has an unexpected configuration" \
  grep -q '3AEC21182A459B1A00A63465 /\* Profile \*/' "$unexpected/sing-box.xcodeproj/project.pbxproj"
expects_fail "an unrecognised configuration set is refused" python3 "$overlay" "$unexpected"

ambiguous="$work/ambiguous"
write_fixture "$ambiguous"
python3 - "$ambiguous/sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme" "$brand" <<'PY'
import sys
p, brand = sys.argv[1], sys.argv[2]
src = open(p, encoding="utf-8").read()
src = src.replace('''               BlueprintIdentifier = "3AEC21082A459B1900A63465"
               BuildableName = "sing-box.app"''',
'''               BlueprintIdentifier = "3AEC21082A459B1900A63465"
               BuildableName = "''' + brand + '''.app"''', 1)
open(p, "w", encoding="utf-8").write(src)
PY
expects_fail "a scheme referencing both the old and new name is refused" python3 "$overlay" "$ambiguous"

unknown="$work/unknown"
write_fixture "$unknown"
python3 - "$unknown/sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme" <<'PY'
import sys
p = sys.argv[1]
src = open(p, encoding="utf-8").read()
src = src.replace('''               BlueprintIdentifier = "3AEC21082A459B1900A63465"
               BuildableName = "sing-box.app"''',
'''               BlueprintIdentifier = "3AEC21082A459B1900A63465"
               BuildableName = "SomeOtherName.app"''', 1)
open(p, "w", encoding="utf-8").write(src)
PY
expects_fail "an unknown application buildable is refused" python3 "$overlay" "$unknown"

missing="$work/missing"
mkdir -p "$missing"
expects_fail "a project directory with no pbxproj is refused" python3 "$overlay" "$missing"
expects_fail "no client directory at all is refused" python3 "$overlay" "$work/does-not-exist"

echo "== the two overlays keep their own scopes =="
# iOS brands SFI from its own overlay and macOS brands SFM from this one. The scopes are
# kept apart structurally rather than by running both against one fixture: each overlay
# addresses a different target and a different scheme FILE, which is what makes it
# possible to change one platform's branding without touching the other platform's build.
#
# The iOS overlay's own end-to-end behaviour is covered where it can be covered for real,
# in test-apple-signing.sh against the pinned iOS client. Duplicating a stand-in iOS
# project here would assert a fixture rather than the client.
check "the iOS overlay still targets the SFI target" \
  grep -q '^TARGET = "SFI"$' "$ios_overlay"
check "the macOS overlay targets the SFM target" \
  grep -q '^TARGET = "SFM"$' "$overlay"
check "the two overlays address different schemes" \
  bash -c "! diff <(grep '^SCHEME = ' '$ios_overlay') <(grep '^SCHEME = ' '$overlay') >/dev/null"
check "the macOS overlay left SFI untouched" \
  test "$(setting "$fixture/sing-box.xcodeproj/project.pbxproj" SFI Debug PRODUCT_NAME)" = "sing-box"
check "the macOS overlay left SFM.System's product name untouched" \
  test "$(grep -c 'PRODUCT_NAME = SFM;' "$fixture/sing-box.xcodeproj/project.pbxproj")" = "2"
# The macOS product is published as Jiejiebox; the iOS one has always been JiejieBox. The
# difference is deliberate and this fix must not quietly align them.
check "the macOS overlay brands exactly Jiejiebox" \
  test "$(sed -nE 's/^NEW_NAME = "(.*)"$/\1/p' "$overlay")" = "Jiejiebox"
check "the iOS overlay does not brand Jijiebox" \
  bash -c "! grep -q '\"Jijiebox\"' '$ios_overlay'"

echo "== prepare routes each platform to its own branding =="
prepare="$root/scripts/ci/prepare-apple-client.sh"
check "prepare selects the macOS overlay for APPLE_CLIENT_PLATFORM=macos" \
  grep -q 'apply-apple-macos-branding-overlay.py' "$prepare"
check "prepare still selects the iOS overlay otherwise" \
  grep -q 'apply-apple-branding-overlay.py' "$prepare"
check "prepare guards the macOS overlay on the platform" \
  grep -q 'if \[ "\$APPLE_CLIENT_PLATFORM" = "macos" \]; then' "$prepare"

echo "== the pre-upload name gate =="
# A gate that has never rejected a sing-box bundle is not known to catch one, so it is
# exercised in both directions against real bundle layouts.
make_bundle() {
  local path="$1" display="$2" cfbundlename="${3:-}"
  rm -rf "$path"
  mkdir -p "$path/Contents"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict>'
    echo '  <key>CFBundleIdentifier</key><string>com.example.jiejiebox</string>'
    echo "  <key>CFBundleDisplayName</key><string>$display</string>"
    if [ -n "$cfbundlename" ]; then
      echo "  <key>CFBundleName</key><string>$cfbundlename</string>"
    fi
    echo '</dict></plist>'
  } > "$path/Contents/Info.plist"
}

bundles="$work/bundles"
good="$bundles/$brand.app"
make_bundle "$good" "$brand"
check "the gate accepts $brand.app with CFBundleDisplayName=$brand" "$name_gate" "$good" "$brand"
check "the gate resolves the expected name from the overlay when not told" "$name_gate" "$good"

# The exact regression this fix exists to remove.
bad="$bundles/sing-box.app"
make_bundle "$bad" "sing-box"
expects_fail "the gate rejects sing-box.app, the bug this fix is for" "$name_gate" "$bad"

# Misspellings the task explicitly forbids. A close-but-wrong name installs under a name
# nobody asked for, so each is asserted to fail rather than trusted to be unlikely.
for wrong in Jijiebox JiejieBox Jiejiebox2 jiejiebox; do
  make_bundle "$bundles/$wrong.app" "$wrong"
  expects_fail "the gate rejects '$wrong' as the app name" "$name_gate" "$bundles/$wrong.app"
done

# A partial rename leaves the bundle directory and the plist disagreeing, in either order.
make_bundle "$bundles/disagree.app" "$brand" "sing-box"
expects_fail "the gate rejects a bundle whose CFBundleName disagrees" "$name_gate" "$bundles/disagree.app"
make_bundle "$bundles/renamed/$brand.app" "sing-box"
expects_fail "the gate rejects a $brand.app whose display name is sing-box" \
  "$name_gate" "$bundles/renamed/$brand.app"
make_bundle "$bundles/other/sing-box.app" "$brand"
expects_fail "the gate rejects sing-box.app even when its display name is $brand" \
  "$name_gate" "$bundles/other/sing-box.app"

# A bundle with no display name at all is not a branded bundle.
make_bundle "$bundles/nodisplay/$brand.app" "$brand"
python3 - "$bundles/nodisplay/$brand.app/Contents/Info.plist" <<'PY'
import re, sys
p = sys.argv[1]
src = open(p, encoding="utf-8").read()
src = re.sub(r"\s*<key>CFBundleDisplayName</key><string>[^<]*</string>", "", src)
open(p, "w", encoding="utf-8").write(src)
PY
expects_fail "the gate rejects a bundle with no CFBundleDisplayName" \
  "$name_gate" "$bundles/nodisplay/$brand.app"

expects_fail "the gate refuses a path that is not a bundle" "$name_gate" "$bundles"
check "the TestFlight builder runs the gate before uploading" \
  grep -q 'check-macos-app-name.sh' "$root/scripts/ci/build-macos-testflight.sh"
check "the TestFlight builder no longer repeats the name itself" \
  bash -c "! grep -qE '^built_name=' '$root/scripts/ci/build-macos-testflight.sh'"

echo "== the pinned macOS source matches what the overlay expects =="
# The fixture proves the overlay is self-consistent. This proves it matches the source it
# is applied to, and that applying it there produces the branded name rather than failing
# on a structure it no longer recognises.
if [ -n "$source_dir" ]; then
  # An explicit checkout overrides the resolver, so the phase-dependent half can be run
  # against a specific tree - a pristine one, or a deliberately branded one to show that
  # this half is not phase-agnostic. The expected revision still comes from the PARENT
  # repository rather than from the checkout under test, so a checkout cannot nominate
  # itself as its own authority.
  #
  # The revision is read from the resolver, not from the refs file: both platforms build the
  # clients/apple gitlink now, and the resolver is the one place that says so. Reading a
  # per-platform variable here would abort under `set -u` and, worse, would reassert the
  # two-source model this repository removed.
  macos_dir="$source_dir"
  macos_sha="$(cd "$root" && ./scripts/ci/apple-client-source.sh sha macos)"
else
  macos_dir="$(./scripts/ci/apple-client-source.sh dir macos 2>/dev/null || true)"
  macos_sha="$(./scripts/ci/apple-client-source.sh sha macos 2>/dev/null || true)"
fi
pinned_pbx="$macos_dir/sing-box.xcodeproj/project.pbxproj"
pinned_scheme="$macos_dir/sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme"

if [ -f "$pinned_pbx" ] && [ -f "$pinned_scheme" ]; then
  check "the macOS checkout is at the pinned revision" \
    test "$(git -C "$macos_dir" rev-parse HEAD)" = "$macos_sha"

  check "the pinned SFM target has exactly the Debug and Release configurations" python3 - "$pinned_pbx" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
problems = []
for target in ("SFM", "SFM.System"):
    m = re.search(r'Build configuration list for PBXNativeTarget "' + re.escape(target) +
                  r'" \*/ = \{(.*?)\n\t\t\};', src, re.S)
    if not m:
        problems.append(f"no configuration list for {target}")
        continue
    arr = re.search(r"buildConfigurations = \((.*?)\);", m.group(1), re.S)
    names = [n for _, n in re.findall(r"([0-9A-Fa-f]{24}) /\* (\w+) \*/", arr.group(1))]
    if sorted(names) != ["Debug", "Release"]:
        problems.append(f"{target} configurations are {names}, expected Debug and Release")
if problems:
    print("\n".join("    - " + p for p in problems), file=sys.stderr)
    sys.exit(1)
PY

  check "the pinned SFM configurations still declare the anchors the overlay rewrites" python3 - "$pinned_pbx" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'Build configuration list for PBXNativeTarget "SFM" \*/ = \{(.*?)\n\t\t\};', src, re.S)
ids = re.findall(r"([0-9A-Fa-f]{24}) /\*", 
                 re.search(r"buildConfigurations = \((.*?)\);", m.group(1), re.S).group(1))
problems = []
for cid in ids:
    b = re.search(rf'{cid} /\* (\w+) \*/ = \{{\s*isa = XCBuildConfiguration;(.*?)\n\t\t\}};',
                  src, re.S)
    if not b:
        problems.append(f"{cid} has no XCBuildConfiguration block")
        continue
    name, body = b.group(1), b.group(2)
    for key in ("PRODUCT_NAME", "INFOPLIST_KEY_CFBundleDisplayName"):
        v = re.search(rf'^\s*{key} = "([^"]*)";', body, re.M)
        if not v:
            problems.append(f"SFM {name} declares no {key}")
        elif v.group(1) != "sing-box":
            problems.append(f"SFM {name} {key} is {v.group(1)!r}, expected 'sing-box'")
if problems:
    print("\n".join("    - " + p for p in problems), file=sys.stderr)
    sys.exit(1)
PY

  check "the pinned SFM scheme has exactly three SFM application buildables" \
    test "$(grep -c 'BlueprintIdentifier = "3AEC21082A459B1900A63465"' "$pinned_scheme")" = "3"
  check "the pinned SFM scheme names all of them sing-box.app" \
    test "$(grep -c 'BuildableName = "sing-box.app"' "$pinned_scheme")" = "3"
  check "the pinned scheme keeps the UI test buildable" \
    grep -q 'BuildableName = "SFMUITests.xctest"' "$pinned_scheme"

  # And the overlay really applies to that source, on a copy - the pinned checkout stays
  # exactly as it was, which is asserted again afterwards.
  real_copy="$work/real-copy"
  cp -R "$macos_dir" "$real_copy"
  check "the overlay applies to a copy of the pinned macOS source" python3 "$overlay" "$real_copy"
  check "the pinned SFM target is branded by the overlay" \
    test "$(setting "$real_copy/sing-box.xcodeproj/project.pbxproj" SFM Release PRODUCT_NAME)" = "$brand"
  check "the pinned SFM Release display name is branded too" \
    test "$(setting "$real_copy/sing-box.xcodeproj/project.pbxproj" SFM Release INFOPLIST_KEY_CFBundleDisplayName)" = "$brand"
  check "the pinned SFM.System target is not branded" \
    test "$(setting "$real_copy/sing-box.xcodeproj/project.pbxproj" SFM.System Release PRODUCT_NAME)" = "SFM"
  check "the pinned SFI target is not branded by the macOS overlay" \
    test "$(setting "$real_copy/sing-box.xcodeproj/project.pbxproj" SFI Release PRODUCT_NAME)" = "sing-box"
  check "the overlay is idempotent on the pinned source" python3 "$overlay" "$real_copy"
  check "the pinned checkout itself was not modified" \
    test -z "$(git -C "$macos_dir" status --porcelain)"
  check "applying the overlay moved no repository revision" \
    test "$(git -C "$macos_dir" rev-parse HEAD)" = "$macos_sha"
else
  skipped "no macOS Apple checkout at $macos_dir; run ./scripts/ci/apple-client-source.sh checkout macos"
fi

echo
echo "test-apple-macos-name: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ] || exit 1
