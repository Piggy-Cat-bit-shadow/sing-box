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

echo "== entitlements that must survive every overlay =="
check "iOS extension keeps packet-tunnel-provider" \
  grep -q "packet-tunnel-provider" clients/apple/Extension/Extension.entitlements
check "macOS system extension keeps the systemextension variant" \
  grep -q "packet-tunnel-provider-systemextension" clients/apple/SystemExtension/SystemExtension.entitlements
check "the macOS app keeps system-extension.install" \
  grep -q "com.apple.developer.system-extension.install" clients/apple/SFM.System/SFM.entitlements

echo "== no capability is added that the account may not have =="
check "no multicast survives in the iOS tunnel" \
  bash -c '! grep -q multicast clients/apple/Extension/Extension.entitlements'
check "no multicast survives in the macOS system extension" \
  bash -c '! grep -q multicast clients/apple/SystemExtension/SystemExtension.entitlements'
check "no iCloud entitlement survives with the switch off" \
  bash -c '! grep -q "com.apple.developer.icloud" clients/apple/SFI/SFI.entitlements'


echo
echo "test-apple-signing: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
