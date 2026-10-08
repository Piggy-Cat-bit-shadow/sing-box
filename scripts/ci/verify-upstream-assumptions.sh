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

# The sing-tun acceptLoop self-heal (LX 040).
#
# This fork now PINS ITS OWN sing-tun (see docs/fork/lx-stability-audit-phase1.md section 2.3) to
# carry the accept-loop fix. The check therefore serves two purposes:
#
#   1. it verifies that the pin really carries the fix. If the go.mod replace is dropped, or points
#      at unpatched upstream, this fails - alarmingly, because the permanent-TCP-failure bug would
#      be back and nothing else in CI would notice;
#   2. it tells us whether upstream has caught up, because that is this fork's removal condition.
#      That half is advisory (it needs an authenticated gh and network) and never fails the build.
#
# The fixed shape accepts on a listener that is re-created after an unexpected error, so the loop
# calls recoverListener. The vulnerable shape returns bare on any accept error, which is what this
# checks for.
echo
echo "--- sing-tun acceptLoop carries the LX 040 self-heal"
sing_tun_dir="$(go list -m -f '{{.Dir}}' github.com/sagernet/sing-tun 2>/dev/null || true)"
sing_tun_replace="$(go list -m -f '{{if .Replace}}{{.Replace.Path}}@{{.Replace.Version}}{{end}}' github.com/sagernet/sing-tun 2>/dev/null || true)"
if [ -z "$sing_tun_dir" ] || [ ! -f "$sing_tun_dir/stack_system.go" ]; then
  echo "FAIL: cannot locate the pinned sing-tun source to check its acceptLoop." >&2
  echo "      Install the module (go mod download) or update this check; do not skip it silently." >&2
  exit 1
fi

# The pin must BE our fork. If the replace is dropped or reverted, the permanent-TCP-failure bug is
# back and nothing else in CI would notice.
case "$sing_tun_replace" in
  github.com/Piggy-Cat-bit-shadow/sing-tun@*)
    echo "      replace: $sing_tun_replace" ;;
  "")
    echo "FAIL: github.com/sagernet/sing-tun is not replaced; the LX 040 fix is not linked." >&2
    echo "      Expected: replace github.com/sagernet/sing-tun => github.com/Piggy-Cat-bit-shadow/sing-tun <version>" >&2
    exit 1 ;;
  *)
    echo "FAIL: sing-tun is replaced by '$sing_tun_replace', which is not this fork." >&2
    echo "      Re-audit the LX 040 pin before accepting a different replacement." >&2
    exit 1 ;;
esac

# The pinned source must contain the fix, and the fix must be the one this repo audited.
if grep -q 'func (s \*System) acceptLoop' "$sing_tun_dir/stack_system.go" 2>/dev/null; then
  : # expected
else
  echo "FAIL: the pinned sing-tun no longer defines System.acceptLoop in stack_system.go." >&2
  echo "      The LX 040 self-heal was written against that function; re-audit it and update this" >&2
  echo "      check and docs/fork/lx-stability-audit-phase1.md together." >&2
  exit 1
fi
if ! grep -q 's.recoverListener(' "$sing_tun_dir/stack_system.go"; then
  echo "FAIL: the pinned sing-tun acceptLoop does not call recoverListener." >&2
  echo "      It must carry the LX 040 fix: classify the accept error, re-bind on an unexpected" >&2
  echo "      failure, bounded backoff, and never resurrect the listener after Close." >&2
  exit 1
fi
sing_tun_accept_loop_returns_bare() {
  awk '/func \(s \*System\) acceptLoop/ { inLoop = 1 } inLoop { print } inLoop && /^}/ { exit }' "$1" \
    | awk '/if err != nil \{/ { getline nextLine; gsub(/^[ \t]+|[ \t]+$/, "", nextLine); if (nextLine == "return") { vulnerable = 1 } } END { exit (vulnerable ? 0 : 1) }'
}
if sing_tun_accept_loop_returns_bare "$sing_tun_dir/stack_system.go"; then
  echo "FAIL: the pinned sing-tun acceptLoop returns bare on an Accept error." >&2
  echo "      Every new TCP flow dies permanently after one unexpected accept error." >&2
  exit 1
fi
if grep -q 'recoveredListeners' "$sing_tun_dir/stack_system.go"; then
  echo "PASS: the pinned fork carries the LX 040 accept-loop self-heal"
else
  echo "PASS: the pinned sing-tun no longer returns bare on an Accept error"
  echo "      BUT it is not this fork's patch (no recovery counter). Probe whether upstream fixed it"
  echo "      independently and, if so, prefer upstream and retire the fork."
fi

# Advisory only: has upstream caught up? That is the fork's removal condition.
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  upstream_head="$(gh api repos/SagerNet/sing-tun/commits/dev --jq '.sha' 2>/dev/null || true)"
  if [ -n "$upstream_head" ]; then
    upstream_file="$(gh api "repos/SagerNet/sing-tun/contents/stack_system.go?ref=$upstream_head" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)"
    if [ -n "$upstream_file" ]; then
      printf '%s' "$upstream_file" > /tmp/sing-tun-upstream-stack-system.go
      if sing_tun_accept_loop_returns_bare /tmp/sing-tun-upstream-stack-system.go; then
        echo "      upstream/dev ($upstream_head) still returns bare; fork still required"
      else
        echo "      NOTE: upstream/dev ($upstream_head) no longer returns bare. It may have fixed"
        echo "      LX 040 independently - re-audit and retire this fork if so."
      fi
      rm -f /tmp/sing-tun-upstream-stack-system.go
    fi
  fi
else
  echo "      (upstream probe skipped: gh unavailable or not authenticated)"
fi

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
