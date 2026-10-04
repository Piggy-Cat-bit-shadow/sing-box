#!/usr/bin/env bash
# Verifies the assumptions this fork makes about the code it pins.
#
# Usage: verify-upstream-assumptions.sh
#
# # Why this exists, and why it is separate from the unit suite
#
# The fork's riskiest dependency is not a bug. It is that upstream changes underneath a local
# assumption: a field appears in DialerOptions, a verdict changes meaning in sing-tun, a helper starts
# walking a writer chain it used to ignore. None of those break the build. They change behaviour
# silently, which is the one failure mode a fork with this much local semantics cannot absorb.
#
# Every assumption below is enforced somewhere - by a tripwire test, by a behavioural comparison, or
# by the compiler. This script runs the ones that a test can express, quickly enough to gate a push,
# and prints where each assumption lives so an audit has a starting point.
#
# The list is deliberately short. A gate that runs everything is a gate nobody waits for, and an
# assumption list that covers every line is a list nobody reads.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=lib.sh
source ./scripts/ci/lib.sh

tags="$(cat release/DEFAULT_BUILD_TAGS)"

# The tripwires, grouped by the assumption they defend. Each entry is a package and a -run pattern,
# so a failure names the assumption rather than "the suite".
run_tripwire() {
  local assumption="$1"
  local packages="$2"
  local pattern="$3"
  echo "--- ${assumption}"
  # shellcheck disable=SC2086
  go test -count=1 -timeout 15m -tags "$tags" -run "$pattern" $packages
}

echo "== pinned revisions =="
go list -m github.com/sagernet/sing github.com/sagernet/sing-tun github.com/sagernet/cronet-go >/dev/null 2>&1 || true
go list -m github.com/sagernet/sing github.com/sagernet/sing-tun github.com/sagernet/cronet-go

echo
echo "== tripwires =="

# sing-tun's FlowVerdict handling: the Direct Fast Path decides with a verdict, and every claim it
# makes about the data path depends on what the pinned stacks do with that verdict.
run_tripwire \
  "ActionBypass is not honoured by a TUN stack (if this fails, the Direct Offload scope must be re-derived)" \
  "./protocol/tun/" \
  'TestDispatcherConsumesOnlyAFlow|TestDispatcherTreatsBypassAndAcceptIdentically|TestBypassReachesTheSameDataPathAsAccept|TestANewTrackerOnABypassIsNeverCreated|TestABypassFlowIsNeverCounted|TestABypassedUDPDatagramTakesTheUserspacePath|TestBypassWithAPortBecomesAFlow'

# The route options the fast path reads. An upstream field the fork does not apply is a field the
# decision cannot see.
run_tripwire \
  "every route option reaches the metadata the fast path inspects" \
  "./route/" \
  'TestEveryRouteOptionReachesTheMetadata|TestTheCompletenessCheckDetectsAnUncoveredField|TestRouteOptionApplicationIsIdempotent'

# DialerOptions classification: same failure mode one layer down.
run_tripwire \
  "every DialerOptions field is classified for native bypass" \
  "./common/dialer/" \
  'TestEveryDialerOptionIsClassified|TestUnclassifiedOptionBlocksEverything|TestZeroProfileRefuses|TestBlockersNameEveryBit'

# The direct outbound's answer for TCP and UDP, which is what makes the bypass verdict inert and what
# the cost comparison rests on.
run_tripwire \
  "the direct outbound answers PreMatchContinue for TCP and UDP, and neither verdict carries a tracker" \
  "./route/" \
  'TestBothConfigurationsReachTheSameVerdictAndTheSameWork|TestDirectOffloadHitReport|TestDirectOffloadRefusalIsAttributed'

# The upload gate's contract with the copy engine: capability truthfulness, headroom, MTU, ownership.
run_tripwire \
  "the upload gate preserves the copy engine's capabilities (batch writers, MTU, headroom, ownership)" \
  "./common/trafficsched/" \
  'TestGate|TestUpload|TestPacketBatch|TestOwnership|TestOversizedWriteCannotEscapeShaping|TestAggregateShapingCoversTheHighPriorityLane'

# The scheduler's rate seam and its accounting, which the production rate source is installed through.
run_tripwire \
  "the scheduler admits no more than the configured rate and covers the high-priority lane" \
  "./common/trafficsched/" \
  'TestAdmittedRateMatchesTheConfiguredRate|TestRateSourceObservationSeam|TestPacedSchedulerLeavesNoGoroutineBehind|TestReleaseAllDoesNotShutTheSchedulerDown'

# The FakeIP and DNS ordering in JudgeFlow, which is a policy boundary rather than an optimisation.
run_tripwire \
  "DNS handling precedes every bypass, and a FakeIP placeholder never reaches the route sets" \
  "./protocol/tun/" \
  'TestDNSHijack|TestFakeIPIsNot|TestNoFakeIPTransport|TestNonDNS|TestL0'

echo
echo "== the compile-time half =="
# Assumptions the compiler already enforces, listed so an audit knows they are covered: if upstream
# changes any signature below, the fork stops building rather than changing behaviour.
cat <<'EOF'
  tun.FlowTracker / tun.FlowHandle / tun.FlowVerdict        protocol/tun, route
  tun.ForwardDispatcher / ForwardStage / ForwardWriteback   protocol/tun tests
  tun.GoConn.Splice + tun.SpliceOptions counters            route/splice.go
  tun.Handler                                               protocol/tun
  adapter.BypassableOutbound / ConnectionTracker / FlowOutbound
  adapter.FakeIPStore.Contains, adapter.FakeIPTransport
  option.DialerOptions, option.AbstractDialerOptions
EOF

echo
echo "PASS: every pinned-upstream assumption above still holds"
