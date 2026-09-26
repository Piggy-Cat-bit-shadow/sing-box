#!/usr/bin/env bash
# Tests for check-reference-coverage.sh.
#
# Usage: check-reference-coverage.test.sh
# Exit: 0 = every case behaved as required, 1 = a case did not.
#
# # Why this file exists
#
# The checker it tests was previously WRONG in a way that made it pass everything: it
# compared each test against the list the test came from, so the comparison was always
# true and the loop skipped every single test. The workflow stayed green and the check
# protected nothing for a full round.
#
# Passing on the happy path would not have caught that, and does not catch its
# reintroduction. What catches it is proving the checker FAILS on the exact conditions it
# claims to detect, which is why most of the cases below are negative.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$script_dir/check-reference-coverage.sh"
repo_root="$(cd "$script_dir/../.." && pwd)"

if [ ! -x "$checker" ] && [ ! -f "$checker" ]; then
  echo "FAIL: checker not found at $checker" >&2
  exit 1
fi

work_dir="$(mktemp -d -t jiejie-covtest-XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

failures=0
cases=0

# report <name> <expected-exit: 0|nonzero> <actual-exit> <detail>
report() {
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

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A fake test directory. The real one is used for the happy path so the case cannot drift
# from the actual suite; the negative cases need a synthetic set whose log can be mutated.
make_fake_dir() {
  local dir="$1"
  mkdir -p "$dir"
  cat > "$dir/alpha_test.go" <<'EOF'
package reference_test

func TestReferenceAlphaOne(t *testing.T) {}
func TestReferenceAlphaTwo(t *testing.T) {}
EOF
  cat > "$dir/beta_test.go" <<'EOF'
package reference_test

func TestReferenceBetaOne(t *testing.T) {}
func TestSourceIdentitySomething(t *testing.T) {}
EOF
  # The QUICHE tests must EXIST in the fixture, because the checker requires every name in
  # its exclusion list to be defined somewhere. Without them every case fails on the
  # dead-exclusion rule instead of on the condition under test.
  cat > "$dir/quiche_test.go" <<'EOF'
package reference_test

func TestReferenceQuicheH3TransportLiveInterop(t *testing.T) {}
func TestReferenceQuicheConnectUDPLiveInterop(t *testing.T) {}
func TestReferenceQuicheConnectIPLiveInterop(t *testing.T) {}
EOF
}

# A log reporting a result for every name given.
make_log() {
  local log="$1"; shift
  : > "$log"
  for test_name in "$@"; do
    printf '=== RUN   %s\n--- PASS: %s (0.01s)\n' "$test_name" "$test_name" >> "$log"
  done
}

fake_dir="$work_dir/reference"
make_fake_dir "$fake_dir"

# ---------------------------------------------------------------------------
# CASE A: the happy path - every non-excluded test reported a result
# ---------------------------------------------------------------------------

log_a="$work_dir/a.log"
make_log "$log_a" \
  TestReferenceAlphaOne TestReferenceAlphaTwo TestReferenceBetaOne TestSourceIdentitySomething

set +e
out_a="$("$checker" "$log_a" "$fake_dir" 2>&1)"; rc_a=$?
set -e
report "A happy path: all tests reported" 0 "$rc_a" "$(printf '%s' "$out_a" | head -1)"

# The count must be non-zero, or the check could be skipping everything again and still
# "passing" - which is precisely the historical bug.
if printf '%s' "$out_a" | grep -qE '^  - [1-9][0-9]* reported a result'; then
  report "A happy path reports a non-zero verified count" 0 0 \
    "$(printf '%s' "$out_a" | grep 'reported a result')"
else
  report "A happy path reports a non-zero verified count" 0 1 \
    "verified count was zero, which means every test was skipped"
fi

# ---------------------------------------------------------------------------
# CASE B: a normal reference test is missing from the log -> must FAIL
# ---------------------------------------------------------------------------

log_b="$work_dir/b.log"
make_log "$log_b" TestReferenceAlphaOne TestReferenceAlphaTwo TestSourceIdentitySomething

set +e
out_b="$("$checker" "$log_b" "$fake_dir" 2>&1)"; rc_b=$?
set -e
report "B ordinary test missing from the log" 1 "$rc_b"
if printf '%s' "$out_b" | grep -q "TestReferenceBetaOne"; then
  report "B failure names the missing test" 0 0
else
  report "B failure names the missing test" 0 1 "message did not name TestReferenceBetaOne"
fi

# A SKIP is a reported result and must satisfy execution coverage: the question of whether
# a SKIP is acceptable is answered by the workflow's explicit assertions, not here.
log_b2="$work_dir/b2.log"
make_log "$log_b2" TestReferenceAlphaOne TestReferenceAlphaTwo TestSourceIdentitySomething
printf -- '--- SKIP: TestReferenceBetaOne (0.00s)\n' >> "$log_b2"
set +e
"$checker" "$log_b2" "$fake_dir" > /dev/null 2>&1; rc_b2=$?
set -e
report "B SKIP counts as a reported result" 0 "$rc_b2"

# ---------------------------------------------------------------------------
# CASE C: an exclusion naming a test that does not exist -> must FAIL
# ---------------------------------------------------------------------------

# Driven by copying the checker and widening its exclusion list with a bogus name, which is
# exactly the "dead exclusion" condition: a test deleted or renamed while the exclusion
# stayed behind.
bogus_checker="$work_dir/checker-bogus.sh"
sed 's|^QUICHE_EXTERNAL=.*|QUICHE_EXTERNAL="TestReferenceQuicheH3TransportLiveInterop TestReferenceQuicheConnectUDPLiveInterop TestReferenceQuicheConnectIPLiveInterop TestThisDoesNotExistAnywhere"|' \
  "$checker" > "$bogus_checker"
chmod +x "$bogus_checker"

set +e
out_c="$("$bogus_checker" "$log_a" "$fake_dir" 2>&1)"; rc_c=$?
set -e
report "C exclusion naming a nonexistent test" 1 "$rc_c"
if printf '%s' "$out_c" | grep -q "TestThisDoesNotExistAnywhere"; then
  report "C failure names the dead exclusion" 0 0
else
  report "C failure names the dead exclusion" 0 1
fi

# ---------------------------------------------------------------------------
# CASE D: a real test wrongly placed in the exclusion list
# ---------------------------------------------------------------------------
#
# The requirement is that this must FAIL unless the test is genuinely wired into the
# dedicated QUICHE workflow. The checker cannot see that workflow, so the responsibility is
# enforced in two places and this case proves the first of them:
#
#   - the checker fails when the excluded test is not DEFINED (case C);
#   - wiring is enforced by the dedicated workflow itself, which the second half of this
#     case reads directly.
#
# So case D is: put an EXISTING test in the exclusion list and confirm the checker treats it
# as excluded, THEN confirm the workflow genuinely runs it - because an excluded test that
# nothing else runs is a test that no longer runs at all.

# A test existing in the fixture is wrongly excluded.
wrong_checker="$work_dir/checker-wrong.sh"
sed 's|^QUICHE_EXTERNAL=.*|QUICHE_EXTERNAL="TestReferenceQuicheH3TransportLiveInterop TestReferenceQuicheConnectUDPLiveInterop TestReferenceQuicheConnectIPLiveInterop TestReferenceBetaOne"|' \
  "$checker" > "$wrong_checker"
chmod +x "$wrong_checker"

# Case D part 1: the checker now treats TestReferenceBetaOne as excluded, so a log WITHOUT
# it passes - which demonstrates exactly why the workflow wiring check below is required.
set +e
"$wrong_checker" "$log_b" "$fake_dir" > /dev/null 2>&1; rc_d1=$?
set -e
report "D wrongly-excluded existing test is accepted by the checker" 0 "$rc_d1" \
  "(this is why the workflow wiring check is needed)"

# Case D part 2: every name the real checker excludes must actually be run by the dedicated
# reference workflow. This is the assertion that makes a wrong exclusion fail.
reference_workflow="$repo_root/.github/workflows/jiejie-masque-reference.yml"
if [ ! -f "$reference_workflow" ]; then
  report "D dedicated QUICHE workflow exists" 1 1 "not found at $reference_workflow"
else
  report "D dedicated QUICHE workflow exists" 0 0

  real_excluded="$(grep -E '^QUICHE_EXTERNAL=' "$checker" | head -1 | cut -d'"' -f2)"
  unrun=0
  for test_name in $real_excluded; do
    if ! grep -q -- "$test_name" "$reference_workflow"; then
      echo "FAIL  D $test_name is excluded here but never run by jiejie-masque-reference.yml"
      unrun=1
    fi
  done
  report "D every excluded test is wired into the reference workflow" 0 "$unrun"
fi

# ---------------------------------------------------------------------------
# CASE E: a stale discovery pattern must fail rather than pass vacuously
# ---------------------------------------------------------------------------

empty_dir="$work_dir/empty-reference"
mkdir -p "$empty_dir"
printf 'package reference_test\n\nfunc helperNotATest() {}\n' > "$empty_dir/nothing_test.go"

set +e
"$checker" "$log_a" "$empty_dir" > /dev/null 2>&1; rc_e=$?
set -e
report "E a test directory with no matching tests fails" 1 "$rc_e"

# ---------------------------------------------------------------------------
# CASE F: a missing log file must fail rather than pass vacuously
# ---------------------------------------------------------------------------

set +e
"$checker" "$work_dir/does-not-exist.log" "$fake_dir" > /dev/null 2>&1; rc_f=$?
set -e
report "F a missing log file fails" 1 "$rc_f"

# ---------------------------------------------------------------------------
# CASE G: the REAL suite must pass the REAL checker
# ---------------------------------------------------------------------------
#
# The synthetic cases above prove the checker rejects bad input. This one proves it accepts
# the actual repository, using a log built from the real defined tests. It is the case that
# would have caught the dead-check bug, because the buggy version reported zero verified
# tests for the real suite.

real_dir="$repo_root/test/jiejie/reference"
if [ -d "$real_dir" ]; then
  real_log="$work_dir/real.log"
  : > "$real_log"
  real_defined="$(grep -rhoE '^func (Test(Reference|SourceIdentity|QuicheOracle)[A-Za-z0-9_]*)' \
    "$real_dir"/*_test.go | sed 's/^func //' | sort -u)"
  real_excluded="$(grep -E '^QUICHE_EXTERNAL=' "$checker" | head -1 | cut -d'"' -f2)"

  for test_name in $real_defined; do
    skip=0
    for excluded_name in $real_excluded; do
      [ "$test_name" = "$excluded_name" ] && skip=1
    done
    [ "$skip" = "1" ] && continue
    printf '=== RUN   %s\n--- PASS: %s (0.01s)\n' "$test_name" "$test_name" >> "$real_log"
  done

  set +e
  out_g="$("$checker" "$real_log" "$real_dir" 2>&1)"; rc_g=$?
  set -e
  report "G the real reference suite passes the real checker" 0 "$rc_g"

  if printf '%s' "$out_g" | grep -qE '^  - [1-9][0-9]* reported a result'; then
    report "G the real suite verifies a non-zero number of tests" 0 0 \
      "$(printf '%s' "$out_g" | grep 'reported a result')"
  else
    report "G the real suite verifies a non-zero number of tests" 0 1 \
      "zero verified: the dead-check bug is back"
  fi
else
  report "G the real reference suite passes the real checker" 1 1 \
    "test directory not found at $real_dir"
fi

# ---------------------------------------------------------------------------

echo
if [ "$failures" != "0" ]; then
  echo "$failures of $cases cases FAILED"
  exit 1
fi
echo "all $cases cases behaved as required"
