#!/usr/bin/env bash
# Classifies one QUICHE interop test run into a reported outcome.
#
# Usage: quiche-result.sh <label> <go-test-output-file> <go-test-exit-status>
#
# Writes a machine-readable line to stdout and a human-readable one to stderr, so the
# caller can both summarise and record without parsing prose.
#
# Exit: always 0. This is a REPORTER, not a gate - the workflow decides what blocks.
#
# # Why this exists
#
# The tunnel-interop steps deliberately do not block the workflow, because a known
# incomplete EXTERNAL interoperability test must not stop the rest of the reference suite
# from running. The first version of that expressed itself as `|| true`, which discarded the
# result: a green run could mean "passed", "failed" or "never ran", and the summary said
# "NOT-TESTED" regardless.
#
# That is the same class of mistake as the coverage check this round also fixes: a green
# signal that carries no information. So the outcome is now classified into distinct
# states, and a PASS that REGRESSES to FAIL is visible in the summary rather than absorbed.
#
# The states come from the test-side classification (see google_quiche_classification_test.go),
# so the workflow vocabulary and the Go vocabulary cannot drift apart silently.
#
#   PASS                    the test reported a pass
#   EXECUTED-FAILED         the test ran and failed - a real observed failure
#   INCONCLUSIVE-TIMEOUT    the test skipped because the process hit the deadline
#   NOT-RUN                 the test skipped for any other reason (binary missing, etc.)
#   NO-RESULT               the test did not report anything at all
set -euo pipefail

label="${1:-unknown}"
log_file="${2:-}"
status="${3:-unknown}"

if [ -z "$log_file" ] || [ ! -f "$log_file" ]; then
  printf 'NO-RESULT\n' 
  echo "::error::$label: no test output was produced (log missing), so nothing was demonstrated" >&2
  exit 0
fi

# Search only the section appended for this label. The log accumulates several steps, so a
# naive grep would let one test's PASS satisfy another's check - which would silently invert
# the meaning of a later failure.
section="$(mktemp)"
trap 'rm -f "$section"' EXIT
awk -v label="$label" '
  index($0, "=== RUN   TestReferenceQuiche") { capture = 1 }
  capture { print }
' "$log_file" > "$section"

if grep -q -- '--- PASS: TestReferenceQuiche' "$section"; then
  outcome="PASS"
elif grep -q -- '--- FAIL: TestReferenceQuiche' "$section"; then
  outcome="EXECUTED-FAILED"
elif grep -q 'failed at the execution deadline\|PROCESS TIMED OUT\|produced no output within' "$section"; then
  outcome="INCONCLUSIVE-TIMEOUT"
elif grep -q -- '--- SKIP: TestReferenceQuiche' "$section"; then
  outcome="NOT-RUN"
else
  outcome="NO-RESULT"
fi

printf '%s\n' "$outcome"

{
  echo "### $label"
  echo
  echo "| Field | Value |"
  echo "| --- | --- |"
  echo "| EXECUTION | $([ "$outcome" = "NOT-RUN" ] && echo "did not execute" || echo "executed") |"
  echo "| OBSERVED RESULT | $outcome |"
  echo "| GO TEST EXIT | $status |"
  echo "| INTEROP VERDICT | $([ "$outcome" = "PASS" ] && echo "ESTABLISHED" || echo "NOT ESTABLISHED") |"
  echo

  case "$outcome" in
    PASS)
      echo "The MASQUE tunnel claim IS established for this case." ;;
    EXECUTED-FAILED)
      echo "**The process ran and failed.** This is an observed failure, NOT an absence of"
      echo "testing, and it is reported in the run summary and the step log." ;;
    INCONCLUSIVE-TIMEOUT)
      echo "The process was killed at the execution deadline, so no exchange was observed."
      echo "Root cause is UNCONFIRMED: the runner may also report a UDP receive-buffer"
      echo "warning, which is recorded as host-environment diagnostic evidence and does not"
      echo "by itself establish causation." ;;
    NOT-RUN)
      echo "The test did not run to a verdict, so nothing was demonstrated." ;;
    *)
      echo "No result was reported at all, which is a harness problem rather than a finding." ;;
  esac
  echo
} >&2
