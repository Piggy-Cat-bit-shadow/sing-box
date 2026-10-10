package physicalpath

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ADVERSARIAL: the user-visible consequence of Hops() not numbering packet order
// ---------------------------------------------------------------------------
//
// The mechanism is pinned in hops_packet_order_attack_test.go. This file establishes what a user
// actually sees, through the production entry point (`ValidateRoots`, which
// adapter/outbound/manager.go:278 calls once per root with the networks the ROUTING RULES proved).
//
// Two consequences, in opposite directions:
//
//	FALSE PASS  a route with no business entry has no network requirement, so a routing rule that
//	            delivers a network the routing-selected hop cannot carry is ACCEPTED.
//	FALSE MISS  a single-hop route has no exit flag, so Leaves()/Report.Leaves() omit it.

// TestADeliveredNetworkTheChainCannotCarryIsAccepted is the false PASS, and it is the exact class of
// defect START-01 exists to remove - reached from the other side.
//
// Configuration:
//
//	route rule: {network: udp, outbound: c}      <- UDP is PROVEN to reach c
//	c.detour = b                                 <- c is the routing-selected hop, carries TCP only
//	b.detour = a                                 <- the underlays
//
// The business UDP flow arrives at `c`. `c` cannot carry UDP, so this configuration is unusable and
// the start must refuse it. `advertisedNetworks` is not consulted here - the requirement is the
// DELIVERED set, `[udp]` - so the only thing that can refuse it is `businessEntry` answering true for
// `c` and `validateNode`'s network step running on it.
func TestADeliveredNetworkTheChainCannotCarryIsAccepted(t *testing.T) {
	a := dualLeaf("a")
	b := dualLeaf("b", "a")
	c := tcpLeaf("c", "b")
	registry := newRegistry(a, b, c)

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{c}, nil,
		[]string{N.NetworkUDP}, Declarations{})
	require.NoError(t, err)

	// What the report claims about each hop, so a failure names the requirement that was applied.
	for _, check := range report.Nodes {
		t.Logf("hop=%s path=%q position=%d exit=%v requirement=%v",
			check.Hop, check.Path, check.Position, check.Exit, check.Requirement)
	}

	require.False(t, report.Reachable(),
		"a routing rule delivers UDP to outbound/c, and outbound/c is the hop the flow arrives at "+
			"because it is the routing-selected hop. It carries TCP only, so the configuration cannot "+
			"work and Start must refuse it. The report accepted it: nodes=%v failures=%v",
		describeChecks(report.Nodes), report.Failures)
}

// TestASingleHopRootIsNotAReportedLeaf is the false MISS: `Leaves()` and `Report.Leaves()` filter on
// `Exit`, and a single-hop route never has that flag set.
//
// The root is validated DIRECTLY rather than through a group, because a root the manager already
// described through a group is skipped as an optional root (adapter/outbound/manager.go:274) - and
// production validates EVERY endpoint as its own root, which is the ordinary single-hop shape.
func TestASingleHopRootIsNotAReportedLeaf(t *testing.T) {
	direct := dualLeaf("direct")
	registry := newRegistry(direct)

	leaves, err := registry.resolver().Leaves(direct)
	require.NoError(t, err)
	require.Len(t, leaves, 1,
		"a dependency-free outbound is a complete route: it is the hop the routing selected AND the "+
			"hop the flow leaves from, so it is a leaf in every sense the model documents. Leaves() "+
			"returned %d entries", len(leaves))
	require.Equal(t, "direct", leaves[0].Tag)
	require.True(t, leaves[0].Exit)
}

// TestTheReportLeavesAOneHopRootOutOfItsOwnLeafList is the same defect at the report layer.
func TestTheReportLeavesAOneHopRootOutOfItsOwnLeafList(t *testing.T) {
	direct := dualLeaf("direct")
	registry := newRegistry(direct)

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{direct}, nil,
		[]string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)
	require.True(t, report.Reachable())

	require.Len(t, report.Nodes, 1, "the root itself is the one node examined")
	require.True(t, report.Nodes[0].Exit,
		"a dependency-free root is the hop the flow leaves from, so HopCheck.Exit must be true; the "+
			"report says %v", report.Nodes[0].Exit)
	require.Len(t, report.Leaves(), 1,
		"Report.Leaves() is documented as 'the checks for the nodes where each route ends', and this "+
			"route ends at its only hop. It returned %d entries", len(report.Leaves()))
}

// TestADeliveredNetworkIsEnforcedOnATwoHopChain is the false PASS with the SIMPLEST fixture, so the
// defect cannot be attributed to the three-hop shape.
//
// `exit.detour = entry`, exit carries TCP only, and a routing rule proves UDP is delivered to exit.
// Under packet order the routing-selected hop is `exit` - the last hop - so the UDP flow arrives
// there and cannot be carried. Two hops is the ordinary detour shape.
func TestADeliveredNetworkIsEnforcedOnATwoHopChain(t *testing.T) {
	entry := dualLeaf("entry")
	exit := tcpLeaf("exit", "entry")
	registry := newRegistry(entry, exit)

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{exit}, nil,
		[]string{N.NetworkUDP}, Declarations{})
	require.NoError(t, err)
	for _, check := range report.Nodes {
		t.Logf("hop=%s path=%q position=%d exit=%v requirement=%v",
			check.Hop, check.Path, check.Position, check.Exit, check.Requirement)
	}
	require.False(t, report.Reachable(),
		"outbound/exit is the routing-selected hop and a rule delivers UDP to it; it carries TCP "+
			"only, so Start must refuse the configuration. Report: nodes=%v failures=%v",
		describeChecks(report.Nodes), report.Failures)
}

// TestADeliveredNetworkIsEnforcedOnASingleHopRoot is the same requirement on the shape the defect
// does NOT reach, kept as the discriminating control: it shows that this file's fixtures DO produce
// a refusal when a business entry exists at all.
func TestADeliveredNetworkIsEnforcedOnASingleHopRoot(t *testing.T) {
	only := tcpLeaf("only")
	registry := newRegistry(only)

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{only}, nil,
		[]string{N.NetworkUDP}, Declarations{})
	require.NoError(t, err)
	require.False(t, report.Reachable(),
		"a tcp-only hop that a rule delivers udp to must be refused; this is the control that proves "+
			"the fixtures above are capable of producing a failure")
}
