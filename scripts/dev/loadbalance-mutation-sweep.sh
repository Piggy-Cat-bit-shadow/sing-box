#!/usr/bin/env bash
# Mutation sweep for the loadbalance feature.
#
# One mutation at a time: break a load-bearing line, run the test that is supposed to notice,
# require it to fail, restore the file, and require the suite to be green again. A mutation
# that leaves the test green means the test does not pin the behaviour it names.
#
# Usage: scripts/dev/loadbalance-mutation-sweep.sh   (from the repository root)
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
TAGS="$(cat release/DEFAULT_BUILD_TAGS)"

GROUP=protocol/group/loadbalance.go
STRATEGY=protocol/group/loadbalance_strategy.go
ROUTE=route/route.go
TRAFFIC=route/traffic_class.go

failures=0
run_case() {
    local name="$1" file="$2" from="$3" to="$4" pkg="$5" pattern="$6"
    cp "$file" "/tmp/mutation-backup-$(basename "$file")"

    python3 - "$file" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if old not in text:
    print("ANCHOR-MISSING", file=sys.stderr)
    sys.exit(3)
open(path, "w").write(text.replace(old, new, 1))
PY
    if [ $? -ne 0 ]; then
        echo "SKIP  $name (anchor not found)"
        cp "/tmp/mutation-backup-$(basename "$file")" "$file"
        failures=$((failures + 1))
        return
    fi

    if go test -tags "$TAGS" -count=1 -timeout 300s -run "$pattern" "./$pkg/" >/tmp/mutation-run.log 2>&1; then
        echo "BAD   $name — the test named for this behaviour stayed GREEN"
        failures=$((failures + 1))
    else
        echo "ok    $name — red as expected"
    fi

    cp "/tmp/mutation-backup-$(basename "$file")" "$file"
    if ! go test -tags "$TAGS" -count=1 -timeout 300s -run "$pattern" "./$pkg/" >/tmp/mutation-restore.log 2>&1; then
        echo "BAD   $name — the test did not go green again after restore"
        failures=$((failures + 1))
    fi
}

# A. round robin always answers with the first member
run_case "A round-robin pinned to member 0" "$GROUP" \
    "	target := slot % uint64(candidates)" \
    "	target := uint64(0) // MUTATION" \
    protocol/group 'TestLoadBalanceRoundRobinRotatesOverMembers|TestLoadBalanceRouteRotatesTheDialedMember'

# B. the speculative preview consumes a decision
run_case "B preview advances the rotation" "$ROUTE" \
    "	if flowAware, isFlowAware := group.(adapter.FlowAwareOutboundGroup); isFlowAware {
			outbound = flowAware.SelectForFlow(metadata, network, commit)" \
    "	if flowAware, isFlowAware := group.(adapter.FlowAwareOutboundGroup); isFlowAware {
			outbound = flowAware.SelectForFlow(metadata, network, true) // MUTATION" \
    route 'TestLoadBalanceRoutePreMatchDoesNotConsumeASelection'

# C. one UDP session resolves twice, so it consumes two members
#
# Per-datagram selection would have to be introduced in the router's copy loop, which this
# feature does not touch: after one resolution the group hands back the member's own packet
# connection and is never consulted again. What a mutation can express is the equivalent
# defect one level up - a second resolution for the same session - which spends a second
# decision and can leave the chain describing a member the session is not using.
run_case "C the session resolves twice" "$ROUTE" \
    "	if !common.Contains(outbound.Network(), network) {
		return nil, E.New(strings.ToUpper(network), \" is not supported by outbound: \", outbound.Tag())
	}
	return chain, nil" \
    "	if network == N.NetworkUDP { // MUTATION
		if second, secondErr := resolveOutbound(chain[0], metadata, network, commit); secondErr == nil {
			chain = second
		}
	}
	if !common.Contains(outbound.Network(), network) {
		return nil, E.New(strings.ToUpper(network), \" is not supported by outbound: \", outbound.Tag())
	}
	return chain, nil" \
    route 'TestLoadBalanceRouteUdpSessionStaysOnOneMember'

# D. health filtering removed
run_case "D health filter removed" "$GROUP" \
    "	return g.healthy(member, network)" \
    "	return true // MUTATION" \
    protocol/group 'TestLoadBalanceHealthFiltersCandidates'

# E. the sticky cache is never read
run_case "E affinity read removed" "$GROUP" \
    "	if tag, pinned := g.affinity.member(key); pinned {" \
    "	if tag, pinned := g.affinity.member(key); false && pinned { // MUTATION" \
    protocol/group 'TestLoadBalanceStickyPinsSourceAndDestination'

# F. the hash key is always empty
run_case "F hash key emptied" "$STRATEGY" \
    "	for i := 0; i < len(key); i++ {
		hash ^= uint64(key[i])" \
    "	for i := 0; i < 0*len(key); i++ {
		hash ^= uint64(key[i])" \
    protocol/group 'TestLoadBalanceConsistentHashingIsStableForOneDestination'

# G. the chain stops at the group, so the leaf it publishes is not the member that is dialed
run_case "G chain leaf is the group" "$ROUTE" \
    "		chain = append(chain, outbound)
	}
	if !common.Contains(outbound.Network(), network) {" \
    "		break // MUTATION
	}
	if !common.Contains(outbound.Network(), network) {" \
    route 'TestLoadBalanceRouteChainLeafMatchesTheDialedMember'

# H. the class is read from the group rather than from the chain the flow took
run_case "H class read from the group only" "$TRAFFIC" \
    "	for _, outbound := range chain {
		if policy, loaded := policies[outbound.Tag()]; loaded {
			return policy.Class
		}
	}
	for _, outbound := range chain {
		if trafficclass.MatchTag(outbound.Tag()) {
			return trafficclass.AutoTagClass
		}
	}" \
    "	// MUTATION: only the outermost element, as if the chain were the group alone
	if policy, loaded := policies[chain[0].Tag()]; loaded {
		return policy.Class
	}
	if trafficclass.MatchTag(chain[0].Tag()) {
		return trafficclass.AutoTagClass
	}" \
    route 'TestLoadBalanceRouteTrafficClassFollowsTheResolvedChain'

# I. the group drops the health checker instead of closing it
#
# The group owns exactly one background resource - the measurement engine it composes - so a
# close that forgets it leaves a ticker, a context and a goroutine behind for every reload.
run_case "I close drops the checker" "$GROUP" \
    "	if health != nil {
		return health.Close()
	}
	return nil
}" \
    "	if health != nil {
		return nil // MUTATION: the engine is dropped, never stopped
	}
	return nil
}" \
    protocol/group 'TestLoadBalanceRepeatedLifecycleDoesNotLeakGoroutines'

echo
if [ "$failures" -eq 0 ]; then
    echo "mutation sweep: PASS — every named test noticed its mutation"
else
    echo "mutation sweep: $failures problem(s)"
fi
exit "$failures"
