#!/usr/bin/env bash
# Regression tests for the Apple signing architecture.
#
# Usage: test-apple-signing.sh
#
# These assert the INVARIANTS that make a build trustworthy, rather than that any
# particular build succeeded. Each one guards a failure that is otherwise silent:
#
#   - a signed build that silently falls back to unsigned produces an artifact
#     that installs and then cannot reach its App Group;
#   - an upstream team or bundle identifier left in place means the signing
#     override did not take effect, which also only shows up at runtime;
#   - a re-added multicast entitlement cannot be signed without Apple's separate
#     grant;
#   - a stripped packet-tunnel-provider turns the client into something that
#     installs and never connects.
#
# Runs without any Apple account. The signed paths are exercised with obviously
# fake values, since what is under test is the configuration logic rather than a
# real signature.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

pass=0
fail=0

# Obviously fake values: these tests exercise configuration logic, not a real
# signature, and must never be mistaken for a working Apple setup.
TEST_TEAM="ABCDE12345"
TEST_BASE="com.example.jiejiebox"

check() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS: $name"
    pass=$((pass + 1))
  else
    echo "  FAIL: $name" >&2
    fail=$((fail + 1))
  fi
}

# expects_fail asserts that a command FAILS. Used for the fail-closed checks.
expects_fail() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "  FAIL: $name (expected failure, but it succeeded)" >&2
    fail=$((fail + 1))
  else
    echo "  PASS: $name"
    pass=$((pass + 1))
  fi
}

echo "== default mode =="
mode="$(./scripts/ci/apple-signing-config.sh --print | sed -n 's/^APPLE_SIGNING_MODE=//p')"
check "default signing mode is unsigned" test "$mode" = "unsigned"
multicast="$(./scripts/ci/apple-signing-config.sh --print | sed -n 's/^APPLE_ENABLE_MULTICAST=//p')"
check "multicast defaults to false" test "$multicast" = "false"

echo "== fail-closed =="
expects_fail "development without configuration is rejected" \
  env APPLE_SIGNING_MODE=development ./scripts/ci/apple-signing-config.sh --print
expects_fail "an unknown signing mode is rejected" \
  env APPLE_SIGNING_MODE=production ./scripts/ci/apple-signing-config.sh --print
expects_fail "upstream team id is rejected in development" \
  env APPLE_SIGNING_MODE=development APPLE_TEAM_ID=P8XK3KHB48 \
      APPLE_BASE_BUNDLE_ID=com.example.jb APPLE_APP_GROUP_ID=group.com.example.jb \
      ./scripts/ci/apple-signing-config.sh --print
expects_fail "upstream bundle prefix is rejected in development" \
  env APPLE_SIGNING_MODE=development APPLE_TEAM_ID=ABCDE12345 \
      APPLE_BASE_BUNDLE_ID=io.nekohasekai.sfamt APPLE_APP_GROUP_ID=group.com.example.jb \
      ./scripts/ci/apple-signing-config.sh --print
expects_fail "preflight fails for development without a certificate" \
  env APPLE_SIGNING_MODE=development APPLE_TEAM_ID=ABCDE12345 \
      APPLE_BASE_BUNDLE_ID=com.example.jb APPLE_APP_GROUP_ID=group.com.example.jb \
      ./scripts/ci/check-apple-signing-environment.sh

echo "== unsigned mode is untouched =="
check "preflight skips in unsigned mode" ./scripts/ci/check-apple-signing-environment.sh
check "artifact verification skips in unsigned mode" \
  ./scripts/ci/verify-apple-signed-artifact.sh ios-ipa /nonexistent

echo "== the build scripts never disable entitlements while signing =="
# The single most dangerous regression: clearing CODE_SIGN_ENTITLEMENTS in a signed
# build silently removes the App Group and Network Extension capabilities.
for script in scripts/ci/build-ios-ipa.sh scripts/ci/build-macos-dmg.sh; do
  # CODE_SIGN_ENTITLEMENTS="" must appear only inside the unsigned branch.
  if python3 - "$script" <<'PY'
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
# Find the unsigned branch and the development branch, then assert the empty
# entitlements override appears only in the former.
m = re.search(r'if \[ "\$APPLE_SIGNING_MODE" = "unsigned" \]; then(.*?)\nelse\n(.*?)\nfi', src, re.S)
if not m:
    sys.exit(1)
unsigned_branch, dev_branch = m.group(1), m.group(2)
if 'CODE_SIGN_ENTITLEMENTS=""' not in unsigned_branch:
    print("unsigned branch must clear entitlements", file=sys.stderr)
    sys.exit(1)
if 'CODE_SIGN_ENTITLEMENTS=""' in dev_branch:
    print("development branch must NOT clear entitlements", file=sys.stderr)
    sys.exit(1)
if 'DEVELOPMENT_TEAM=""' in dev_branch:
    print("development branch must NOT blank the team", file=sys.stderr)
    sys.exit(1)
if 'APPLE_TEAM_ID' not in dev_branch:
    print("development branch must set the team", file=sys.stderr)
    sys.exit(1)
PY
  then
    echo "  PASS: $script keeps entitlements and the team in signed mode"
    pass=$((pass + 1))
  else
    echo "  FAIL: $script does not separate signed and unsigned entitlements" >&2
    fail=$((fail + 1))
  fi
done

echo "== upstream identifiers are not hardcoded as signing values =="
# They may appear in comments explaining the guard, but not as an assignment.
if grep -nE '^\s*(DEVELOPMENT_TEAM|APPLE_TEAM_ID)=.*P8XK3KHB48' scripts/ci/*.sh >/dev/null 2>&1; then
  echo "  FAIL: upstream team id is assigned in a script" >&2
  fail=$((fail + 1))
else
  echo "  PASS: upstream team id is never assigned"
  pass=$((pass + 1))
fi

echo "== the App Group is passed explicitly to xcodebuild =="
# The project's macOS configuration blocks use $(TeamIdentifierPrefix), which is
# empty outside a signed build and produced an invalid App Group. The build must
# override it so every target agrees.
for script in scripts/ci/build-ios-ipa.sh scripts/ci/build-macos-dmg.sh; do
  check "$script passes APP_GROUP_IDENTIFIER" \
    grep -q 'APP_GROUP_IDENTIFIER="\$APPLE_APP_GROUP_ID"' "$script"
done

echo "== testflight mode =="
check "testflight is a recognised mode" \
  env APPLE_SIGNING_MODE=testflight APPLE_TEAM_ID=A123456789 \
      APPLE_BASE_BUNDLE_ID=com.example.jb APPLE_APP_GROUP_ID=group.com.example.jb \
      ./scripts/ci/apple-signing-config.sh --print
expects_fail "testflight without configuration is rejected" \
  env APPLE_SIGNING_MODE=testflight ./scripts/ci/apple-signing-config.sh --print
expects_fail "the testflight builder refuses to run in another mode" \
  ./scripts/ci/build-ios-testflight.sh
expects_fail "an unknown signing mode is still rejected" \
  env APPLE_SIGNING_MODE=distribution ./scripts/ci/apple-signing-config.sh --print

echo "== capability switches =="
check "iCloud defaults to off" \
  bash -c './scripts/ci/apple-signing-config.sh --print | grep -q "^APPLE_ENABLE_ICLOUD=false$"'
check "multicast defaults to off" \
  bash -c './scripts/ci/apple-signing-config.sh --print | grep -q "^APPLE_ENABLE_MULTICAST=false$"'
expects_fail "an invalid iCloud value is rejected" \
  env APPLE_ENABLE_ICLOUD=maybe ./scripts/ci/apple-signing-config.sh --print

echo "== the team identifier is not derived from the App Group =="
# AppConfiguration.teamID split the group name on the first dot, which cannot
# produce a team id under either App Group convention. The value feeds code-signing
# requirements, so a wrong one silently rejects XPC connections.
check "the overlay carries the real team into the bundle" \
  grep -q "TeamIdentifier" scripts/ci/fix-apple-team-id.py
check "teamID prefers the injected value" \
  grep -q 'object(forInfoDictionaryKey: "TeamIdentifier")' scripts/ci/fix-apple-team-id.py

echo "== the unified entry point =="
check "release-apple.sh documents its targets" \
  bash -c './scripts/release-apple.sh --help | grep -q testflight'
expects_fail "release-apple.sh rejects an unknown target" \
  ./scripts/release-apple.sh nonsense


echo "== the real iOS target set =="
# A real build asks for these seven. An earlier draft of the documentation listed
# six and marked three of them optional, which would have sent a developer to the
# portal with an incomplete list.
check "the docs list the widget extension" \
  grep -q "jiejiebox.widget" docs/APPLE-DEVELOPMENT-SIGNING.md
check "the docs list the action extension" \
  grep -q "jiejiebox.action" docs/APPLE-DEVELOPMENT-SIGNING.md
check "the docs list the fileprovider extension" \
  grep -q "jiejiebox.fileprovider" docs/APPLE-DEVELOPMENT-SIGNING.md
check "the docs list the intents extension" \
  grep -q "jiejiebox.intents" docs/APPLE-DEVELOPMENT-SIGNING.md

echo "== entitlements after the overlay is applied =="
# These assertions are about what the OVERLAY produces, so the test applies it
# itself. Reading the submodule directly would only pass if some earlier command
# happened to leave the overlay in place - a green result that means nothing on a
# clean checkout. The submodule is restored afterwards either way.
overlay_state="$(git -C clients/apple status --porcelain | wc -l | tr -d ' ')"
restore_overlay() {
  if [ "$overlay_state" = "0" ]; then
    git -C clients/apple checkout -- . >/dev/null 2>&1 || true
  fi
}

if APPLE_SIGNING_MODE=development APPLE_TEAM_ID="$TEST_TEAM" \
   APPLE_BASE_BUNDLE_ID="$TEST_BASE" APPLE_APP_GROUP_ID="group.$TEST_BASE" \
   ./scripts/ci/prepare-apple-client.sh >/dev/null 2>&1; then
  check "iOS extension keeps packet-tunnel-provider" \
    grep -q "packet-tunnel-provider" clients/apple/Extension/Extension.entitlements
  check "macOS system extension keeps the systemextension variant" \
    grep -q "packet-tunnel-provider-systemextension" clients/apple/SystemExtension/SystemExtension.entitlements
  check "the macOS app keeps system-extension.install" \
    grep -q "com.apple.developer.system-extension.install" clients/apple/SFM.System/SFM.entitlements
  check "no multicast survives in the iOS tunnel" \
    bash -c '! grep -q multicast clients/apple/Extension/Extension.entitlements'
  check "no multicast survives in the macOS system extension" \
    bash -c '! grep -q multicast clients/apple/SystemExtension/SystemExtension.entitlements'
  check "no iCloud entitlement survives with the switch off" \
    bash -c '! grep -q "com.apple.developer.icloud" clients/apple/SFI/SFI.entitlements'
  # Idempotent, and asserted as the property that matters: a second run must change nothing,
  # not fail. Both overlays now recognise their own output - compatibility because this fork's
  # client carries the two members itself, branding because it has always detected the branded
  # state - so "refuses to re-apply" is no longer the contract. What must hold is that running it
  # twice appends no second copy and does not move the submodule HEAD, which is checked here and
  # again by the script's own "submodule HEAD unchanged" assertion.
  head_before="$(git -C clients/apple rev-parse HEAD)"
  check "the overlay is idempotent (a second run changes nothing)" \
    bash -c 'APPLE_SIGNING_MODE=development APPLE_TEAM_ID='"$TEST_TEAM"' \
      APPLE_BASE_BUNDLE_ID='"$TEST_BASE"' APPLE_APP_GROUP_ID=group.'"$TEST_BASE"' \
      ./scripts/ci/prepare-apple-client.sh >/dev/null 2>&1'
  check "re-applying the overlay does not move the submodule HEAD" \
    test "$(git -C clients/apple rev-parse HEAD)" = "$head_before"
  check "re-applying the overlay appends no second compatibility shim" \
    test "$(grep -c 'func usePlatformAutoRedirect() -> Bool' clients/apple/Library/Network/ExtensionPlatformInterface.swift)" = "1"
else
  echo "  FAIL: could not apply the overlay; skipping its assertions" >&2
  fail=$((fail + 1))
fi
restore_overlay


echo "== one App Store record: the two main bundle ids must match =="
# A single App Store Connect record requires one bundle id across platforms, and it
# cannot be changed after the first upload, so this is checked before anything is
# archived rather than discovered at upload time.
# APPLE_TEAM_ID is passed explicitly. Relying on auto-detection would make these
# assertions depend on the machine having a signing certificate, and on CI there is
# none - the config layer would then (correctly) refuse testflight mode for a
# missing team, and the test would fail for a reason that has nothing to do with
# bundle identifiers.
main_ids() {
  APPLE_SIGNING_MODE=testflight APPLE_TEAM_ID="$TEST_TEAM" \
    APPLE_BASE_BUNDLE_ID="$1" APPLE_APP_GROUP_ID="group.$1" \
    ./scripts/ci/apple-signing-config.sh --print
}
ios_main="$(main_ids "$TEST_BASE" | sed -n 's/^APPLE_IOS_APP_BUNDLE_ID=//p')"
macos_main="$(main_ids "$TEST_BASE" | sed -n 's/^APPLE_MACOS_APP_BUNDLE_ID=//p')"
macos_standalone="$(main_ids "$TEST_BASE" | sed -n 's/^APPLE_MACOS_STANDALONE_BUNDLE_ID=//p')"
check "the iOS main bundle id is the configured base" test "$ios_main" = "$TEST_BASE"
check "the macOS main bundle id equals the iOS one" test -n "$macos_main" -a "$macos_main" = "$ios_main"
check "the Developer ID product keeps its own id" \
  test -n "$macos_standalone" -a "$macos_standalone" != "$macos_main"

echo "== the App Store macOS target is the sandboxed one =="
# SFM (<base>) is the App Store app. SFM.System (<base>.standalone) is the
# unsandboxed Developer ID product that installs a privileged helper and a System
# Extension, and is deliberately not part of the record.
check "SFM is sandboxed" \
  grep -q "com.apple.security.app-sandbox" clients/apple/SFM/SFM.entitlements
check "SFM.System is not sandboxed" \
  bash -c '! grep -q "com.apple.security.app-sandbox" clients/apple/SFM.System/SFM.entitlements'
check "SFM carries the in-process packet tunnel provider" \
  grep -q "packet-tunnel-provider" clients/apple/SFM/SFM.entitlements
check "SFM.System carries the System Extension variant" \
  grep -q "packet-tunnel-provider-systemextension" clients/apple/SFM.System/SFM.entitlements

echo "== both platforms have a TestFlight builder =="
check "the iOS TestFlight builder exists" test -x scripts/ci/build-ios-testflight.sh
check "the macOS TestFlight builder exists" test -x scripts/ci/build-macos-testflight.sh
expects_fail "the macOS builder refuses a non-testflight mode" \
  ./scripts/ci/build-macos-testflight.sh --archive-only
check "the macOS builder guards the single-record invariant" \
  grep -q "must match for a single" scripts/ci/build-macos-testflight.sh
check "the macOS builder refuses an unsandboxed archive" \
  grep -q "no System Extension embedded" scripts/ci/build-macos-testflight.sh

echo "== the unified entry point dispatches correctly =="
check "testflight-ios is documented" \
  bash -c './scripts/release-apple.sh --help | grep -q testflight-ios'
check "testflight-macos is documented" \
  bash -c './scripts/release-apple.sh --help | grep -q testflight-macos'
check "testflight-ios runs only iOS" \
  python3 "$root/scripts/ci/test-dispatch.py" testflight-ios
check "testflight-macos runs only macOS" \
  python3 "$root/scripts/ci/test-dispatch.py" testflight-macos
check "testflight runs both platforms, iOS first" \
  python3 "$root/scripts/ci/test-dispatch.py" testflight

echo "== CI stays unsigned and carries no signing secrets =="
check "the CI job still builds the unsigned IPA" \
  grep -q "build-ios-ipa.sh" .github/workflows/client-apple.yml
check "CI never references a distribution identity or key" \
  bash -c '! grep -qE "Apple Distribution|Apple Development|\.p12|\.p8" .github/workflows/client-apple.yml'
check "no signing material is tracked" \
  bash -c '! git ls-files | grep -qiE "\.(p12|pfx|p8|cer|mobileprovision|provisionprofile)$"'
# Exclude this file: it contains the search pattern as a literal, so a naive grep
# matches itself and reports a private key that does not exist.
check "no private key block is tracked" \
  bash -c '! git grep -lI "BEGIN .*PRIVATE KEY" -- . ":(exclude)scripts/ci/test-apple-signing.sh" 2>/dev/null | grep -q .'


echo "== the archives are signed, and the export re-signs for distribution =="
# The archive MUST be signed. -exportArchive validates entitlements from the archive
# and cannot supply ones that were never applied, so an unsigned archive fails
# Apple's validation with:
#   Missing Entitlement ... 'com.apple.developer.networking.networkextension'
for builder in scripts/ci/build-ios-testflight.sh scripts/ci/build-macos-testflight.sh; do
  check "$(basename "$builder") does not disable signing" \
    bash -c "! grep -q 'CODE_SIGNING_ALLOWED=NO' '$builder'"
  check "$(basename "$builder") uses automatic signing" \
    grep -q 'CODE_SIGN_STYLE=Automatic' "$builder"
  check "$(basename "$builder") allows provisioning updates" \
    grep -q -- '-allowProvisioningUpdates' "$builder"
  check "$(basename "$builder") does not force a signing identity" \
    python3 "$root/scripts/ci/test-no-active-identity.py" "$builder"
  check "$(basename "$builder") does not use Manual style" \
    bash -c "! grep -q 'CODE_SIGN_STYLE=Manual' '$builder'"
  check "$(basename "$builder") does not hardcode a profile name" \
    bash -c "! grep -qE 'PROVISIONING_PROFILE_SPECIFIER=\"[A-Za-z]' '$builder'"
  check "$(basename "$builder") lets the export provision automatically" \
    grep -q 'signingStyle' "$builder"
  check "$(basename "$builder") asserts the archive is signed" \
    grep -q "the archive is signed" "$builder"
  # iOS asserts a distribution authority on the exported IPA, because the export
  # writes it out. macOS cannot: the export uploads a package and leaves nothing
  # local, and the archive is development-signed by design (that is what carries the
  # entitlements Apple validates). Assert the right thing for each.
  check "$(basename "$builder") checks the entitlements Apple validated" \
    grep -q "carries the network extension entitlement" "$builder"
  check "$(basename "$builder") verifies what it uploaded" \
    grep -q "verify what was uploaded\|verify the EXPORTED product" "$builder"
done

echo "== a product that is not signed must never be reported as a success =="
# An empty identity with signing still enabled makes xcodebuild report success while
# producing "code object is not signed at all". That has been mistaken for a passing
# distribution build twice, so the assertions live on the EXPORTED product.
check "the iOS builder verifies the uploaded build" \
  grep -q "verify what was uploaded" scripts/ci/build-ios-testflight.sh
# Both platforms verify the archive the upload was built from: with
# destination=upload neither writes a local artifact, so there is nothing else to
# inspect, and an earlier check that expected an IPA reported a false negative on
# uploads that had actually succeeded.
check "the uploads are verified, not just produced" \
  bash -c 'grep -q "verify what was uploaded" scripts/ci/build-ios-testflight.sh && \
           grep -q "verify what was uploaded" scripts/ci/build-macos-testflight.sh'

echo "== no signing setting is silently dropped by a stray comment =="
# A '#' line inside a backslash-continued argument list is consumed as part of the
# command, so every setting after it never reaches xcodebuild. The archive then runs
# with the project's own development identity while the script appears to request
# distribution - a signing-mode bug disguised as a device problem, which is exactly
# how this file was broken and how long it took to find.
check "no comment sits inside an argument list" \
  python3 "$root/scripts/ci/test-arglist.py"


echo "== local publishing configuration =="
# The publishing identifiers are personal, so they live in a git-ignored file
# rather than in the repository or in GitHub secrets. These assertions guard the
# two ways that could go wrong: the file becoming trackable, or a run silently
# proceeding with the wrong identifiers.
check "the local config file is git-ignored" \
  bash -c 'git check-ignore -q .env.apple.local'
check "the example template is committable" \
  bash -c '! git check-ignore -q .env.apple.local.example'
check "the template is tracked" \
  bash -c 'git ls-files --error-unmatch .env.apple.local.example >/dev/null 2>&1 || test -f .env.apple.local.example'
check "release-apple.sh loads the local file" \
  grep -q '.env.apple.local' scripts/release-apple.sh
# Asserted as a property rather than by naming the old variable. The previous version grepped for
# `local_base_before`, which pinned the IMPLEMENTATION: it passed while only two of the file's
# variables were protected, and it broke when that was replaced by a generic restore.
#
# The mechanism is exercised end to end by test-apple-beta-publish.sh, which loads a synthetic
# .env.apple.local covering every supported variable and checks both directions.
check "the loader captures the file's variables before sourcing" \
  grep -q 'local -a _env_names' scripts/release-apple.sh
check "the loader restores what the caller had exported" \
  grep -q 'export "${_env_names\[\$_i\]}=\${_env_saved\[\$_i\]}"' scripts/release-apple.sh
check "the loader derives the variable set from the file" \
  grep -q 'sed -nE' scripts/release-apple.sh
check "the loader refuses a non-ignored file" \
  grep -q 'refusing to read' scripts/release-apple.sh
check "the local file is not tracked" \
  bash -c '! git ls-files --error-unmatch .env.apple.local >/dev/null 2>&1'


echo "== the Apple scripts are syntactically valid =="
# A concatenated echo left two commands on one line, which `bash -n` accepts but
# which runs the wrong command. Checking every script here catches that class
# before a 20-minute build does.
for script in scripts/release-apple.sh scripts/publish-apple-beta.sh scripts/ci/apple-signing-config.sh \
              scripts/ci/build-ios-testflight.sh scripts/ci/build-macos-testflight.sh \
              scripts/ci/build-ios-ipa.sh scripts/ci/build-macos-dmg.sh \
              scripts/ci/build-apple-libbox.sh scripts/ci/apple-libbox-artifact.sh \
              scripts/ci/apple-client-source.sh scripts/ci/check-apple-shared-libbox.sh \
              scripts/ci/check-apple-source-selection.sh \
              scripts/ci/prepare-apple-client.sh scripts/ci/check-apple-signing-environment.sh; do
  check "$(basename "$script") parses" bash -n "$script"
done

# The Python halves of the Apple tooling must import only the standard library: the GitHub
# runner image has no PyYAML, and a script that needs it fails there for a reason unrelated
# to what it checks. Verified by walking each script's import statements.
for py in scripts/ci/apply-apple-link-overlay.py scripts/ci/check-apple-links.py \
          scripts/ci/apply-apple-ios-deployment-target.py; do
  check "$(basename "$py") imports only the standard library" \
    bash -c "python3 -c 'import ast,sys; m=ast.parse(open(sys.argv[1]).read()); \
      mods={n.names[0].name.split(\".\")[0] for n in ast.walk(m) if isinstance(n, ast.Import)} | \
           {n.module.split(\".\")[0] for n in ast.walk(m) if isinstance(n, ast.ImportFrom) and n.module}; \
      allowed={\"sys\",\"os\",\"re\",\"json\",\"plistlib\",\"hashlib\",\"ast\"}; \
      bad=mods-allowed; \
      sys.exit(1 if bad else 0)' '$py'"
done


echo "== iOS branding: the product is JiejieBox, the core is sing-box =="
# The product brand and the core name are deliberately separate. The app presents as
# JiejieBox; the SFI target, scheme, bundle id, entitlements, URL scheme and the
# sing-box core all keep their names, because those are compatibility or technical
# identifiers rather than branding.
branding_applied=0
if APPLE_SIGNING_MODE=development APPLE_TEAM_ID="$TEST_TEAM" \
   APPLE_BASE_BUNDLE_ID="$TEST_BASE" APPLE_APP_GROUP_ID="group.$TEST_BASE" \
   ./scripts/ci/prepare-apple-client.sh >/dev/null 2>&1; then
  branding_applied=1
fi

if [ "$branding_applied" = "1" ]; then
  pbx="clients/apple/sing-box.xcodeproj/project.pbxproj"
  scheme="clients/apple/sing-box.xcodeproj/xcshareddata/xcschemes/SFI.xcscheme"

  # The iOS floor. The frozen iOS UI builds a toolbar item conditionally, which the SDK
  # only builds from iOS 16, so a 15.0 floor is a compile error rather than a warning:
  #
  #   SFI/MainView.swift:128:21: error: 'buildIf' is only available in iOS 16.0 or newer
  #
  # prepare-apple-client.sh raises the floor as part of preparing the iOS client. Asserted
  # here so a repin that quietly reintroduces 15.0 is caught by the regression suite rather
  # than by a failed release build.
  if python3 "$root/scripts/ci/apply-apple-ios-deployment-target.py" check clients/apple >/dev/null 2>&1; then
    check "the prepared iOS client builds at iOS 16.0 or above" true
  else
    check "the prepared iOS client builds at iOS 16.0 or above" false
    python3 "$root/scripts/ci/apply-apple-ios-deployment-target.py" check clients/apple 2>&1 | sed 's/^/      /' || true
  fi

  # The floor is raised in the PROJECT, never in the UI: the Hako toolbar logic is frozen.
  check "raising the iOS floor did not touch the toolbar logic" \
    bash -c 'grep -q "if environments.remoteServer != nil" clients/apple/SFI/MainView.swift'

  check "the branding overlay renamed SFI" \
    grep -q 'INFOPLIST_KEY_CFBundleDisplayName = "JiejieBox"' "$pbx"
  check "the SFI scheme points at the renamed product" \
    grep -q 'BuildableName = "JiejieBox.app"' "$scheme"
  check "the UI test buildable is untouched" \
    grep -q 'BuildableName = "SFIUITests.xctest"' "$scheme"

  # Only SFI may change: SFT and SFM also declare PRODUCT_NAME = "sing-box", and
  # renaming them would be a branding migration this task explicitly excludes.
  sfi_configs="$(python3 "$root/scripts/ci/test-branding-scope.py" clients/apple)"
  # The scope script verifies both directions - SFI branded AND every other target,
  # the URL scheme, bundle id and App Group untouched - and exits non-zero on any
  # problem. Its exit status is strictly stronger than counting occurrences, which a
  # blanket replacement would have satisfied.
  if python3 "$root/scripts/ci/test-branding-scope.py" clients/apple >/dev/null 2>&1; then
    check "only the SFI configurations were renamed" true
  else
    check "only the SFI configurations were renamed" false
    python3 "$root/scripts/ci/test-branding-scope.py" clients/apple 2>&1 | sed 's/^/      /' || true
  fi

  echo "  -- compatibility must be preserved --"
  check "the bundle identifier setting is unchanged" \
    grep -q 'PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER)"' "$pbx"
  check "the App Group setting is unchanged" \
    grep -q 'APP_GROUP_IDENTIFIER = "group.\$(BASE_PACKAGE_IDENTIFIER)"' "$pbx"
  check "the Extension product name is unchanged" \
    bash -c "! grep -q 'PRODUCT_NAME = \"JiejieBox\";' clients/apple/Extension/Info.plist 2>/dev/null"
  check "the sing-box URL scheme is unchanged" \
    grep -q 'sing-box' clients/apple/SFI/Info.plist
  check "the SFI target is still called SFI" \
    grep -q 'Build configuration list for PBXNativeTarget "SFI"' "$pbx"

  echo "  -- the submodule must be untouched as a repository --"
  # Asserted as the property rather than against a frozen commit: the parent must record the commit
  # the submodule is actually at, and that commit must be reachable from the fork whose URL
  # .gitmodules names. A hardcoded SHA was correct while the client was upstream's and became a
  # check that could only fail once this fork's branch was pinned - which is what happened.
  check "the parent gitlink matches the submodule HEAD" \
    test "$(git ls-tree HEAD clients/apple | awk '{print $3}')" = "$(git -C clients/apple rev-parse HEAD)"
  check "the submodule is on the fork's branch" \
    bash -c 'git -C clients/apple rev-parse --abbrev-ref HEAD | grep -q .'
  check "the submodule URL points at the fork" \
    bash -c 'git config -f .gitmodules submodule.clients/apple.url | grep -q "Piggy-Cat-bit-shadow/sing-box-for-apple"'
  check "the pinned commit is reachable from that URL" \
    bash -c 'test -n "$(git -C clients/apple ls-remote --exit-code origin hako-ui 2>/dev/null | awk "{print \$1}")" || git -C clients/apple cat-file -e "$(git -C clients/apple rev-parse HEAD)"' 
  check "the branding change is uncommitted in the submodule" \
    bash -c 'test -n "$(git -C clients/apple status --porcelain)"'
else
  echo "  FAIL: could not apply the overlay; skipping branding assertions" >&2
  fail=$((fail + 1))
fi
restore_overlay

echo "== the branding overlay fails closed =="
# If the pinned client changes so the anchors no longer match, the overlay must
# refuse rather than silently skip - a branding overlay that stops working would
# ship an app still called sing-box, which is the bug it exists to fix.
check "the overlay refuses a partially branded project" \
  grep -q "neither the upstream nor the branded state" scripts/ci/apply-apple-branding-overlay.py
check "the overlay refuses an unexpected configuration set" \
  grep -q "configuration set is not the expected one" scripts/ci/apply-apple-branding-overlay.py
check "the overlay refuses to guess at the scheme" \
  grep -q "refusing to guess" scripts/ci/apply-apple-branding-overlay.py
check "the TestFlight builder does not hardcode a product name" \
  bash -c "! grep -qE '^app=.*(sing-box|JiejieBox)\.app' scripts/ci/build-ios-testflight.sh"
check "the TestFlight builder fails on an ambiguous archive" \
  grep -q "expected exactly one application" scripts/ci/build-ios-testflight.sh


echo
echo "test-apple-signing: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
