#!/usr/bin/env bash
# Tests for gomobile-toolchain.sh, and for the single-source rule it exists to keep.
#
# Usage: test-gomobile-toolchain.sh
# Exit: 0 = every case behaved as required, 1 = a case did not.
#
# # Why this file exists
#
# `github.com/sagernet/gomobile/cmd/gomobile@v0.1.13` had been written out three
# times - twice in .github/workflows/client-apple.yml and once in the Makefile - so
# the version a build actually used was a property of three files agreeing. The
# failure mode is silent: nothing breaks when a literal in one place stops matching
# the others, the build simply uses a different generator than the reviewer read,
# and the resulting xcframework differs.
#
# A green run of the script would not catch that reintroduction. What catches it is
# asserting on the TREE: no gomobile version literal may exist outside the one
# declaration, and every install site must go through the script.
#
# The offline cases run everywhere. The install cases are skipped unless
# GOMOBILE_TOOLCHAIN_TEST_INSTALL=1, because they hit the module proxy and take
# about a minute; they are run by hand and in the report, not on every push.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
tool="$script_dir/gomobile-toolchain.sh"

[ -f "$tool" ] || { echo "FAIL: gomobile-toolchain.sh not found at $tool" >&2; exit 1; }

failures=0
cases=0

report() { # <name> <expected 0|nonzero> <actual> [detail]
  local name="$1" expected="$2" actual="$3" detail="${4:-}"
  cases=$((cases + 1))
  local ok=0
  if [ "$expected" = "0" ]; then
    [ "$actual" -eq 0 ] && ok=1
  else
    [ "$actual" -ne 0 ] && ok=1
  fi
  if [ "$ok" = "1" ]; then
    printf 'PASS  %-58s %s\n' "$name" "$detail"
  else
    printf 'FAIL  %-58s expected exit %s, got %s %s\n' "$name" "$expected" "$actual" "$detail"
    failures=$((failures + 1))
  fi
}

fail_case() {
  cases=$((cases + 1))
  failures=$((failures + 1))
  printf 'FAIL  %-58s %s\n' "$1" "$2"
}

# ---------------------------------------------------------------------------
# The single-source rule
# ---------------------------------------------------------------------------
#
# A version literal is `gomobile` or `gobind` followed by `@v<something>`. The one
# allowed site is the declaration inside gomobile-toolchain.sh.

allowed="$script_dir/gomobile-toolchain.sh"

# grep -rn over the files that can install a toolchain. `--include` keeps the scan
# to files that could carry a command; docs are excluded because they quote the
# command in prose and are not executed. This test file is excluded for the same
# reason: its header quotes the old form to explain what went wrong.
# Comment lines are dropped first: a `#` line cannot install anything, and several
# files explain the removed literal in prose. A trailing comment on a real command
# line is NOT dropped, because that line still runs.
literals="$(cd "$repo_root" && grep -rnE 'gomobile/(cmd/)?(gomobile|gobind)@v' \
  --include='*.yml' --include='Makefile' --include='*.mk' --include='*.sh' . 2>/dev/null \
  | grep -v '^\./clients/' \
  | grep -vE ':[0-9]+:[[:space:]]*#' || true)"

offenders="$(printf '%s\n' "$literals" \
  | grep -v '^\./scripts/ci/gomobile-toolchain.sh:' \
  | grep -v '^\./scripts/ci/test-gomobile-toolchain.sh:' \
  | grep -v '^$' || true)"
if [ -z "$offenders" ]; then
  report "no gomobile version literal outside the one declaration" 0 0
else
  fail_case "no gomobile version literal outside the one declaration" \
    "found a hardcoded version; ask scripts/ci/gomobile-toolchain.sh instead:
$(printf '%s\n' "$offenders" | sed 's/^/      /')"
fi

# The declaration itself must exist exactly once, or the "single" source is two.
declarations="$(grep -cE '^APPLE_GOMOBILE_VERSION="v' "$allowed" || true)"
if [ "$declarations" -eq 1 ]; then
  report "the Apple version is declared exactly once" 0 0
else
  fail_case "the Apple version is declared exactly once" "found $declarations declaration(s) in $allowed"
fi

# ---------------------------------------------------------------------------
# The install sites use it
# ---------------------------------------------------------------------------

for site in ".github/workflows/client-apple.yml" "Makefile"; do
  if grep -q 'gomobile-toolchain.sh' "$repo_root/$site"; then
    report "$site installs through gomobile-toolchain.sh" 0 0
  else
    fail_case "$site installs through gomobile-toolchain.sh" "no call found"
  fi
done

# The Apple workflow must name the Apple toolchain explicitly at every install
# site: a bare `install` would be ambiguous, and defaulting to one of them is how
# the drift started.
sites="$(grep -c 'gomobile-toolchain.sh install apple' "$repo_root/.github/workflows/client-apple.yml" || true)"
if [ "$sites" -eq 2 ]; then
  report "both Apple install sites name the apple toolchain" 0 0 "count=$sites"
else
  fail_case "both Apple install sites name the apple toolchain" "count=$sites, expected 2"
fi

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

apple="$(bash "$tool" apple)"
case "$apple" in
  v[0-9]*) report "apple prints a release version" 0 0 "$apple" ;;
  *) fail_case "apple prints a release version" "got '$apple'" ;;
esac

if command -v go >/dev/null 2>&1; then
  project="$(cd "$repo_root" && bash "$tool" project)"
  case "$project" in
    v[0-9]*) report "project derives a release version from go.mod" 0 0 "$project" ;;
    *) fail_case "project derives a release version from go.mod" "got '$project'" ;;
  esac

  # The derived version must be the one go.mod actually requires, not something the
  # script invented. Read the require line directly and compare.
  #
  # awk rather than sed: the `\+` quantifier is a GNU extension that BSD sed on the
  # macOS runners treats as a literal, which silently produced an empty comparison
  # value here.
  from_gomod="$(cd "$repo_root" && awk '$1 == "github.com/sagernet/gomobile" { print $2; exit }' go.mod)"
  if [ -n "$from_gomod" ] && [ "$project" = "$from_gomod" ]; then
    report "the derived version matches root go.mod" 0 0 "$project = $from_gomod"
  else
    fail_case "the derived version matches root go.mod" "derived '$project', go.mod says '$from_gomod'"
  fi
else
  fail_case "go is available to derive the project version" "go not found on PATH"
fi

# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

# A bad argument must fail rather than silently installing something.
rc=0; bash "$tool" install >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then report "install without a toolchain is refused" nonzero "$rc"
else fail_case "install without a toolchain is refused" "it succeeded"; fi

rc=0; bash "$tool" install golang.org/x/mobile >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then report "an unknown toolchain is refused" nonzero "$rc"
else fail_case "an unknown toolchain is refused" "it succeeded"; fi

rc=0; bash "$tool" bogus >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then report "an unknown subcommand is refused" nonzero "$rc"
else fail_case "an unknown subcommand is refused" "it succeeded"; fi

# The Apple declaration must be a version, so a branch name cannot be pinned by
# accident - and neither can an empty value.
if grep -qE '^APPLE_GOMOBILE_VERSION="v[0-9]' "$allowed" \
   && ! grep -qE '^APPLE_GOMOBILE_VERSION="(main|master|HEAD|latest)' "$allowed"; then
  report "the Apple declaration is a version, not a branch" 0 0
else
  fail_case "the Apple declaration is a version, not a branch" "inspect $allowed"
fi

# The justification must survive. If someone drops the reason, the pin becomes
# unexplained drift, which is the state this file exists to prevent.
if grep -q 'genobjc' "$allowed" && grep -q 'bind_iosapp' "$allowed"; then
  report "the Apple pin's reason is recorded next to it" 0 0
else
  fail_case "the Apple pin's reason is recorded next to it" "the header no longer names what v0.1.13 fixes"
fi

# ---------------------------------------------------------------------------
# Optional: really install and read the binaries' build info
# ---------------------------------------------------------------------------
#
# Off by default: it reaches the module proxy and takes about a minute. It is the
# only case that proves the installed BINARIES are the declared ones rather than
# the declared strings being right, so it is worth running by hand after any change
# to the declaration.

if [ "${GOMOBILE_TOOLCHAIN_TEST_INSTALL:-0}" = "1" ]; then
  echo
  echo "--- installing the apple toolchain and reading go version -m"
  rc=0
  out="$(bash "$tool" install apple 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "are built from github.com/sagernet/gomobile@$apple"; then
    report "install apple proves the binaries from their build info" 0 0 "$apple"
    printf '%s\n' "$out" | grep -E '^(---|PASS|installing)' | sed 's/^/      /'
  else
    fail_case "install apple proves the binaries from their build info" \
      "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-200)"
  fi
else
  printf 'SKIP  %-58s set GOMOBILE_TOOLCHAIN_TEST_INSTALL=1 to run\n' \
    "install apple proves the binaries (network)"
fi

# ---------------------------------------------------------------------------

echo
if [ "$failures" -eq 0 ]; then
  echo "PASS: all $cases cases behaved as required"
  exit 0
fi
echo "FAIL: $failures of $cases cases did not behave as required" >&2
exit 1
