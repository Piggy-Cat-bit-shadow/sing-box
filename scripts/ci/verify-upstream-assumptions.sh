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

# GVISOR MUST NOT BE SHIPPED.
#
# This block used to assert the OPPOSITE: that with_gvisor was compiled into Android and that the
# linked gVisor was therefore our patched fork carrying the 048 nil-handshake guard. That was
# correct at the time - 048 was a real crash surface on a shipped stack.
#
# The product condition has changed. The Android UI no longer depends on "stack": "mixed"/"gvisor",
# so gVisor is retired from shipped artifacts. The risk is gone because the EXPOSURE is gone, not
# because 048 was never real, and the check is INVERTED rather than deleted: deleting it would
# delete the only thing that notices the exposure coming back.
#
# Three parts, unchanged in shape:
#   1. the libbox builder's own tag-policy test, which asks the same function the builders use
#      (cmd/internal/build_libbox) - the property that made it catch the real thing;
#   2. the profile files, still scanned, so the two tag sources cannot drift apart;
#   3. the dependency invariant, inverted: no shipped variant names with_gvisor, so the retired
#      fork must not still be wired into go.mod.
echo
echo "--- gVisor: retired from shipped artifacts (inverted invariant)"
if ! go test -count=1 ./cmd/internal/build_libbox/ >/dev/null 2>&1; then
  echo "FAIL: the libbox tag-policy test failed. It asserts that NO shipped variant compiles" >&2
  echo "      with_gvisor, and that the retired fork is not still wired into go.mod." >&2
  echo "      Run it directly for the detail:" >&2
  echo "          go test -v ./cmd/internal/build_libbox/" >&2
  exit 1
fi
echo "PASS: no shipped variant (android-main, android-legacy, apple) compiles with_gvisor"

for tags_file in release/DEFAULT_BUILD_TAGS release/DEFAULT_BUILD_TAGS_OTHERS release/DEFAULT_BUILD_TAGS_WINDOWS; do
  if [ ! -f "$tags_file" ]; then
    continue
  fi
  if grep -q 'with_gvisor' "$tags_file"; then
    echo "FAIL: $tags_file names with_gvisor. gVisor was intentionally retired after the Android UI" >&2
    echo "      stopped depending on mixed/gvisor. Re-enabling it requires a new product review and" >&2
    echo "      restoring and re-auditing LX 048. See docs/fork/upstream-sync-2026-10.md." >&2
    exit 1
  fi
done
echo "PASS: no profile tag file carries with_gvisor"

# The inverted dependency half. This is the tripwire against a silent re-enable: while no shipped
# variant compiles the tag, the retired fork must not still be the replacement for gVisor.
gvisor_replace="$(go list -m -f '{{if .Replace}}{{.Replace.Path}}@{{.Replace.Version}}{{end}}' github.com/sagernet/gvisor 2>/dev/null || true)"
case "$gvisor_replace" in
  "")
    echo "PASS: gVisor carries no replacement; the retired fork is no longer wired in" ;;
  github.com/Piggy-Cat-bit-shadow/gvisor@*)
    # PENDING, not FAIL, and the distinction is the whole point.
    #
    # The SHIPPED exposure is already zero: the builder test above asserts that no variant compiles
    # with_gvisor, which is the thing that made 048 a crash surface. What remains is the dependency
    # edge, and it cannot be removed yet for a concrete reason: protocol/tun still imports gVisor
    # behind the with_gvisor build tag, so the module graph keeps requiring it until the upstream Go
    # TUN stack (a1b01b4) replaces that code path. That is upstream's own ordering - ede8d9a
    # "Remove dependency on gVisor" follows the Go stack rather than preceding it.
    #
    # Failing here would make CI red for a state that is correct and mid-migration, which trains
    # people to ignore the check. Passing silently would lose the fact. So it reports, and it is
    # tied to a named migration rather than to a date.
    echo "PENDING: gVisor is still replaced by the retired fork: $gvisor_replace"
    echo "         The shipped exposure is already zero (no variant compiles with_gvisor, asserted)."
    echo "         The dependency edge is removed by the Go TUN stack migration (upstream a1b01b4,"
    echo "         then ede8d9a), because protocol/tun still imports gVisor behind the build tag."
    echo "         When that lands, this branch must become a FAIL if the replace survives."
    echo "         See docs/fork/upstream-sync-2026-10.md." ;;
  *)
    echo "FAIL: gvisor is replaced by '$gvisor_replace', which is neither the retired fork nor absent." >&2
    echo "      Re-audit this before accepting a different replacement." >&2
    exit 1 ;;
esac

# Whatever gVisor remains (upstream still supports the tag until the Go TUN stack lands), it must
# not be reachable from a shipped artifact. The builder-level assertion above is what guarantees
# that; this records the intent so a reader knows the guard is deliberate.

# Artifact-level proof, not a module-graph claim: link the probe with the Android tag composition
# and read the dependency out of the built binary. This is the check that would have caught the
# original gap, where the profile files said one thing and the shipped build did another.
probe_tags="$(cat release/DEFAULT_BUILD_TAGS),with_gvisor"
probe_bin="$(mktemp -t sing-box-artifact-probe.XXXXXX)"
if go build -tags "$probe_tags" -o "$probe_bin" ./cmd/ci-artifact-probe >/dev/null 2>&1; then
  if go version -m "$probe_bin" 2>/dev/null | grep -q '=>[[:space:]]*github.com/Piggy-Cat-bit-shadow/gvisor'; then
    echo "PASS: an artifact built with with_gvisor links the patched gVisor fork"
  else
    echo "FAIL: an artifact built with with_gvisor does not link the patched gVisor fork." >&2
    echo "      The dependency provenance in the built binary is the release fact; fix the pin" >&2
    echo "      before shipping, because Android compiles this tag." >&2
    rm -f "$probe_bin"
    exit 1
  fi
  if go version -m "$probe_bin" 2>/dev/null | grep -q 'with_gvisor'; then
    echo "      probe build tags include with_gvisor"
  fi
else
  echo "FAIL: could not build the artifact probe with with_gvisor." >&2
  echo "      ./cmd/ci-artifact-probe is the release check's view of a linked artifact; if it does" >&2
  echo "      not build, the provenance cannot be verified." >&2
  rm -f "$probe_bin"
  exit 1
fi
rm -f "$probe_bin"

# Advisory only: has upstream caught up? That is the fork's removal condition.
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  upstream_head="$(gh api repos/SagerNet/gvisor/commits/go --jq '.sha' 2>/dev/null || true)"
  if [ -n "$upstream_head" ]; then
    upstream_dispatcher="$(gh api "repos/SagerNet/gvisor/contents/pkg/tcpip/transport/tcp/dispatcher.go?ref=$upstream_head" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)"
    if [ -n "$upstream_dispatcher" ]; then
      printf '%s' "$upstream_dispatcher" > /tmp/gvisor-upstream-dispatcher.go
      if awk '/^func handleConnecting\(/ { inFunc = 1 } inFunc { print } inFunc && /^}/ { exit }' /tmp/gvisor-upstream-dispatcher.go | grep -q 'ep\.h == nil'; then
        echo "      NOTE: upstream go ($upstream_head) now guards the nil handshake. It may have fixed"
        echo "      LX 048 independently - re-audit and retire this fork if so."
      else
        echo "      upstream go ($upstream_head) still dereferences nil; fork still required"
      fi
      rm -f /tmp/gvisor-upstream-dispatcher.go
    fi
  fi
else
  echo "      (upstream probe skipped: gh unavailable or not authenticated)"
fi

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
