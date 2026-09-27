#!/usr/bin/env bash
# Verifies that every reference test DEFINED in test/jiejie/reference actually reported a
# result in the run that was just executed.
#
# Usage: check-reference-coverage.sh <log-file> [test-dir]
#
#   <log-file>  the `go test -v` output of the reference run
#   [test-dir]  where the tests live (default: test/jiejie/reference)
#
# Exit: 0 = every test accounted for, 1 = a test is unaccounted for.
#
# # Why this exists as a script rather than inline YAML
#
# The check was inline, and its exclusion logic was wrong in a way that made it skip EVERY
# test while still reporting success - so the check protected nothing and the workflow
# stayed green. Logic that silent needs to be executable on its own, with fixtures that
# prove it fails when it should. See check-reference-coverage.test.sh.
#
# # What it does and does not prove
#
# It proves EXECUTION: every defined test appears in the log with a result, so a test that
# fell out of the -run filter cannot pass unnoticed. There are no exclusions: a reference
# test either ran here or the check fails. (An exclusion list used to exist for the Google
# QUICHE live interop tests, which were driven by an out-of-tree Bazel-built `masque_client`
# rather than by `go test`. That harness has been removed, and with it the exclusions.)
#
# It does NOT interpret SKIP as PASS. A SKIP is a reported result and satisfies this check,
# which is correct here because some reference tests are expected to skip against a binary
# that cannot serve them. Whether a SKIP is ACCEPTABLE is a separate question answered by
# the explicit per-test assertions in the workflow, not by this script. Deleting those
# assertions would remove the positive evidence this check cannot provide.
set -euo pipefail

log_file="${1:-}"
test_dir="${2:-test/jiejie/reference}"

if [ -z "$log_file" ]; then
  echo "usage: $0 <log-file> [test-dir]" >&2
  exit 2
fi
if [ ! -f "$log_file" ]; then
  echo "::error::coverage check: log file '$log_file' does not exist" >&2
  exit 2
fi
if [ ! -d "$test_dir" ]; then
  echo "::error::coverage check: test directory '$test_dir' does not exist" >&2
  exit 2
fi

defined="$(grep -rhoE '^func (Test(Reference|SourceIdentity|QuicheOracle)[A-Za-z0-9_]*)' \
  "$test_dir"/*_test.go | sed 's/^func //' | sort -u)"

if [ -z "$defined" ]; then
  echo "::error::coverage check: no reference tests found in $test_dir, so this check is" >&2
  echo "::error::verifying nothing. The discovery pattern may have gone stale." >&2
  exit 1
fi

missing=0
checked=0

for test_name in $defined; do
  checked=$((checked + 1))

  if ! grep -qE -- "--- (PASS|FAIL|SKIP): ${test_name}( |$)" "$log_file"; then
    echo "::error::$test_name is defined in $test_dir but the run never reported it."
    echo "::error::It is not matched by the -run filter, so it never executed."
    echo "::error::A test that does not run is NOT a pass."
    missing=1
  fi
done

if [ "$missing" != "0" ]; then
  echo "::error::the reference suite has tests outside the CI filter." >&2
  exit 1
fi

total="$(printf '%s\n' "$defined" | wc -l | tr -d ' ')"

echo "reference coverage OK: $total defined tests accounted for"
echo "  - $checked reported a result in this run"
echo "  - 0 excluded: every reference test must run here"
