#!/usr/bin/env bash
# Run the full test/jiejie integration suite.
#
# CI deliberately does NOT run this package (see the rationale in
# .github/workflows/server-linux-amd64.yml): it takes ~12 minutes and four Naive UoT
# audits fail by design. It still runs locally, and this wrapper exists because the
# package has TWO characteristics that make a bare `go test ./jiejie/` misleading:
#
#   1. It exceeds the default 600s timeout. Measured on Apple M1: 699s with 200
#      passing and 4 pre-existing failures, and 86s for the target-ACL subset alone.
#      A bare run therefore ends in "panic: test timed out", which reads like a hang
#      rather than a slow suite.
#
#   2. Four tests fail at baseline. They are NOT caused by anything recent; they fail
#      identically on the pinned baseline revision. They are classified below so a
#      real regression is not lost among them.
#
# Usage: scripts/ci/run-jiejie-suite.sh [extra go test args...]
set -euo pipefail

cd "$(dirname "$0")/../.."

# Keep in step with release/BUILD_TAGS_JIEJIE_CLIENT_MACOS: the suite exercises the
# Naive outbound, so it needs the client profile's tags.
TAGS="with_quic,with_naive_outbound,badlinkname,tfogo_checklinkname0"

# Comfortably above the measured 699s, so exceeding it means something really is stuck.
TIMEOUT="${JIEJIE_TIMEOUT:-1200s}"

# Failures that reproduce on the pinned baseline and are not caused by current work.
# Kept as a list rather than a skip so they still RUN and their output is visible:
# silently skipping known failures is how a real one hides.
# TestAuditUoTV2NonConnectMode and TestAuditUoTV2NonConnectMultipleTargets were
# listed here as "UoT read request: unknown address family: 8". That was a FALSE
# PRODUCT DIAGNOSIS and they have been REMOVED from this list because they now
# PASS: the harness was framing an HTTP/1 CONNECT payload as Naive padded data,
# so the server read the frame's length byte (0x08) as a SOCKS address family.
# HTTP/1 is a RAW tunnel; the product was correct all along. See
# TestAuditUoTPaddingContractIsTransportDependent for the contract, and
# docs/JIEJIE-NAIVE-UOT-FALSE-P0.md for the retraction.
#
# They are deleted rather than kept as "expected failures" on purpose: leaving a
# fixed test on a known-failure list is how a real regression later hides behind
# the label.
KNOWN_FAILURES=(
  "TestAuditLoopbackIsReachableByDefault"         # loopback reachability audit
  "TestAuditRouteRuleBlocksLoopback"              # loopback routing audit
)

echo "==> test/jiejie with tags: $TAGS (timeout $TIMEOUT)"
set +e
(cd test && go test -tags "$TAGS" -count=1 -timeout "$TIMEOUT" -v ./jiejie/) \
  > /tmp/jiejie-suite.log 2>&1
status=$?
set -e

passed=$(grep -c '^--- PASS' /tmp/jiejie-suite.log || true)
skipped=$(grep -c '^--- SKIP' /tmp/jiejie-suite.log || true)
failed=$(grep -c '^--- FAIL' /tmp/jiejie-suite.log || true)
echo "==> passed=$passed skipped=$skipped failed=$failed (go test exit $status)"

if [ "$failed" -eq 0 ]; then
  echo "==> OK"
  exit 0
fi

# Separate the known-baseline failures from anything new.
unexpected=0
while IFS= read -r name; do
  [ -z "$name" ] && continue
  known=0
  for candidate in "${KNOWN_FAILURES[@]}"; do
    if [ "$name" = "$candidate" ]; then known=1; break; fi
  done
  if [ "$known" -eq 1 ]; then
    echo "    known-baseline failure: $name"
  else
    echo "    UNEXPECTED FAILURE:     $name"
    unexpected=$((unexpected + 1))
  fi
done < <(grep '^--- FAIL' /tmp/jiejie-suite.log | sed 's/^--- FAIL: \([^ ]*\).*/\1/')

echo
echo "Full output: /tmp/jiejie-suite.log"

if [ "$unexpected" -gt 0 ]; then
  echo "==> FAIL: $unexpected unexpected failure(s)"
  exit 1
fi

# A timeout is never a known-baseline outcome.
if [ "$status" -ne 0 ] && ! grep -q '^--- FAIL' /tmp/jiejie-suite.log; then
  echo "==> FAIL: the suite did not complete (timed out or crashed)"
  exit 1
fi

echo "==> OK apart from the $failed known-baseline failure(s)"
