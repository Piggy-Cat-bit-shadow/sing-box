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

# The retired gVisor build tag must not come back into any profile.
#
# The pinned sagernet/gvisor still has the LX 048 window: performHandshake nils ep.h and releases
# its mutex before Close(), while handleConnecting gates only on the endpoint state, so an
# unestablished TCP endpoint can dereference a nil handshake from an internal goroutine - a panic
# no recover() in our goroutine can catch (Leadaxe's fix needs a third module fork, which this
# fork's architecture deliberately does not carry). The protection is that the tag is not in any
# profile: without it sing-tun returns ErrGVisorNotIncluded for stack gvisor/mixed, which is a
# clean configuration error. If a profile ever names it again, this fails here instead of shipping
# an unrecoverable panic.
echo
echo "--- no build profile carries with_gvisor"
for tags_file in release/DEFAULT_BUILD_TAGS release/DEFAULT_BUILD_TAGS_OTHERS release/DEFAULT_BUILD_TAGS_WINDOWS; do
  if [ ! -f "$tags_file" ]; then
    continue
  fi
  if grep -q 'with_gvisor' "$tags_file"; then
    echo "FAIL: $tags_file names with_gvisor. The pinned gvisor still has the handshake nil-deref" >&2
    echo "      window (LX 048); enabling it needs the fork documented in the phase-1 audit." >&2
    exit 1
  fi
done
echo "PASS: no profile names with_gvisor"

# The sing-tun acceptLoop deferred (LX 040).
#
# The pinned sing-tun still ends the system stack's TCP accept loop on ANY listener error:
#
#     conn, err := listener.Accept()
#     if err != nil {
#         return
#     }
#
# with no log and no re-listen, while s.tcpPort stays the port every new SYN is NAT-rewritten onto.
# One foreign close of that listener fd (the observed trigger is a fast restart sharing the process
# fd space) therefore turns into permanent failure for all new TCP until the tunnel is rebuilt,
# with QUIC/UDP unaffected - which is what makes it look like "the browser is dead but Telegram
# works". It cannot be fixed from this repository: acceptLoop and tcpPort are unexported and
# ResetNetwork does not re-listen, so a wrapper or a retry goroutine would be a fake fix. The
# phase-1 decision is to hold it as a dependency-owned deferral.
#
# This tripwire is that decision's expiry condition: if a future pin changes the shape, the check
# fails and the deferral must be re-audited (upstream may have fixed it, in which case the deferral
# is simply deleted) instead of being carried forward unexamined. See
# docs/fork/lx-stability-audit-phase1.md section 2.3.
echo
echo "--- sing-tun acceptLoop is still the pinned, vulnerable shape (LX 040 deferral)"
sing_tun_dir="$(go list -m -f '{{.Dir}}' github.com/sagernet/sing-tun 2>/dev/null || true)"
if [ -z "$sing_tun_dir" ] || [ ! -f "$sing_tun_dir/stack_system.go" ]; then
  echo "FAIL: cannot locate the pinned sing-tun source to check its acceptLoop." >&2
  echo "      Install the module (go mod download) or update this check; do not skip it silently." >&2
  exit 1
fi
if ! grep -q 'func (s \*System) acceptLoop' "$sing_tun_dir/stack_system.go"; then
  echo "FAIL: the pinned sing-tun no longer defines System.acceptLoop in stack_system.go." >&2
  echo "      The LX 040 deferral was recorded against that function; re-audit it, then either" >&2
  echo "      delete the deferral (upstream fixed it) or update this tripwire with the new shape." >&2
  exit 1
fi
# The predicate is "the statement right after `if err != nil {` inside acceptLoop is a bare
# return". Checking for the `if` line alone would pass for a fixed version too, because that line
# survives any fix; the body is what says whether the loop gives up or recovers.
sing_tun_accept_loop_returns_bare() {
  awk '/func \(s \*System\) acceptLoop/ { inLoop = 1 } inLoop { print } inLoop && /^}/ { exit }' "$1" \
    | awk '/if err != nil \{/ { getline nextLine; gsub(/^[ \t]+|[ \t]+$/, "", nextLine); if (nextLine == "return") { vulnerable = 1 } } END { exit (vulnerable ? 0 : 1) }'
}
if ! sing_tun_accept_loop_returns_bare "$sing_tun_dir/stack_system.go"; then
  echo "FAIL: the pinned sing-tun acceptLoop no longer returns bare on an Accept error." >&2
  echo "      Upstream may have made it self-healing: re-audit the LX 040 deferral and remove it" >&2
  echo "      if so. Do not carry the deferral forward without re-reading it." >&2
  exit 1
fi
echo "PASS: acceptLoop still returns on any Accept error; LX 040 deferral stands"

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
