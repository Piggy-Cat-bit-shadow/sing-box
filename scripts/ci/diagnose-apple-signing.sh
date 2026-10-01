#!/usr/bin/env bash
# Reports whether this Mac can actually produce a signed Apple build.
#
# Usage: diagnose-apple-signing.sh
#
# # Why this is separate from the preflight
#
# check-apple-signing-environment.sh answers "is the configuration complete and is
# there a usable identity". This answers a different and more specific question that
# costs a lot of time to discover otherwise: Xcode can hold an Apple ID in its
# account list that has NO authenticated session, in which case the certificate is
# present and valid, `security find-identity` reports it, and provisioning still
# fails with:
#
#   No Account for Team "<team>". Add a new account in Accounts settings or verify
#   that your accounts have valid credentials.
#
# That wording points at the account list, which already contains the account, so
# it reads as a contradiction. The real cause is an expired or never-completed
# sign-in, and the only fix is an interactive one.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

echo "Apple signing diagnosis"
echo

# --- toolchain ---------------------------------------------------------------
echo "toolchain"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
if xcodebuild -version >/dev/null 2>&1; then
  echo "  xcode:      $(xcodebuild -version | head -1)"
  echo "  DEVELOPER_DIR: $DEVELOPER_DIR"
else
  echo "  FAIL: xcodebuild is not usable (tried DEVELOPER_DIR=$DEVELOPER_DIR)"
  echo "        A first launch of Xcode is also required to accept its licence."
fi

# --- identities --------------------------------------------------------------
echo
echo "code signing identities"
if identities="$(security find-identity -v -p codesigning 2>/dev/null)" &&
   [ -n "$identities" ] &&
   ! printf '%s' "$identities" | grep -q "0 valid identities found"; then
  printf '%s\n' "$identities" | sed 's/^/  /'
  # The team in parentheses is the one provisioning must be asked for.
  # The parenthesised value in the name is the certificate's individual
  # identifier; the TEAM is the OU field. They are often different, and using the
  # wrong one produces "No Account for Team \"...\"" even when the account is
  # present and signed in.
  echo "  team IDs (from the certificate OU field, which is the real one):"
  security find-certificate -a -c "Apple Development" -p 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null \
    | tr ',' '\n' | grep -oE 'OU=[A-Z0-9]+' | sed 's/OU=/    /' | sort -u
  names="$(printf '%s' "$identities" | grep -oE '\(([A-Z0-9]{10})\)' | tr -d '()' | sort -u | tr '\n' ' ')"
  echo "  identifiers in the certificate NAME (NOT the team): ${names:-none}"
else
  echo "  none"
  echo "  Without a valid identity nothing can be signed. Note that importing a"
  echo "  certificate is not sufficient on its own: its Apple WWDR intermediate must"
  echo "  also be installed, or the identity is reported as invalid."
fi

# --- Xcode account -----------------------------------------------------------
echo
echo "Xcode account"
account_plist=""
while IFS= read -r candidate; do
  account_plist="$candidate"
done < <(find "$HOME/Library/Developer/Xcode/UserData" -name "AppleAccounts.plist" 2>/dev/null | head -1)

if [ -n "$account_plist" ] && [ -f "$account_plist" ]; then
  username="$(plutil -extract 0.username raw -o - "$account_plist" 2>/dev/null || true)"
  if [ -n "$username" ]; then
    echo "  registered: $username"
    # An account entry is not a session. This is the distinction that matters.
    if security find-generic-password -s "Xcode-AppleID" -a "$username" >/dev/null 2>&1; then
      echo "  session:    present (authenticated)"
    else
      echo "  session:    ABSENT - the account is listed but not authenticated"
      echo
      echo "  This is why provisioning fails with:"
      echo "    No Account for Team \"<team>\". Add a new account in Accounts settings"
      echo "    or verify that your accounts have valid credentials."
      echo
      echo "  The account IS in the list; what is missing is a completed sign-in."
      echo "  Fix, interactively (Xcode will ask for the password and a 2FA code):"
      echo "    Xcode > Settings > Accounts > select the account > Sign In again"
      echo "  Then re-run this script and confirm 'session: present'."
    fi
  else
    echo "  no account is registered with Xcode"
    echo "  Add one: Xcode > Settings > Accounts > +"
  fi
else
  echo "  no account is registered with Xcode"
  echo "  Add one: Xcode > Settings > Accounts > +"
fi

# --- provisioning reachability -----------------------------------------------
echo
echo "provisioning reachability"
# The only reliable test is to ask Xcode to provision something.
if [ "${APPLE_DIAGNOSE_SKIP_BUILD:-}" = "1" ]; then
  echo "  skipped (APPLE_DIAGNOSE_SKIP_BUILD=1)"
else
  probe_log="$(mktemp)"
  rm -rf /tmp/dsh-apple-diag-dd
  set +e
  perl -e 'alarm 240; exec @ARGV' xcodebuild \
    -project clients/apple/sing-box.xcodeproj \
    -scheme SFI \
    -configuration Debug \
    -destination 'generic/platform=iOS' \
    -derivedDataPath /tmp/dsh-apple-diag-dd \
    -allowProvisioningUpdates \
    -skipPackagePluginValidation \
    DEVELOPMENT_TEAM="${APPLE_TEAM_ID:-}" \
    BASE_PACKAGE_IDENTIFIER="${APPLE_BASE_BUNDLE_ID:-io.nekohasekai.sfamt}" \
    build >"$probe_log" 2>&1
  probe_status=$?
  set -e

  if grep -q 'No Account for Team' "$probe_log"; then
    echo "  FAIL: Xcode cannot provision - no authenticated account for the team."
    echo "        See 'Xcode account' above."
  elif grep -q "No profiles for" "$probe_log"; then
    echo "  provisioning reached Apple, but these identifiers are not registered yet:"
    grep -oE "No profiles for '[^']+'" "$probe_log" | sort -u | sed 's/^/    /'
    echo "  With a working account, -allowProvisioningUpdates creates them itself."
  elif [ "$probe_status" -eq 0 ]; then
    echo "  PASS: Xcode provisioned and built successfully."
  else
    echo "  inconclusive (exit $probe_status); the first errors were:"
    grep -E "error:" "$probe_log" | head -5 | sed 's/^/    /'
  fi
  rm -f "$probe_log"
fi
