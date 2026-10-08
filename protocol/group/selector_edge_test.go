package group

import (
	"testing"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the relationship between a selector's selectable set and the edges the startup cycle
// check can see.
//
// # Why a selector cannot be the place a routing loop appears (LX 024)
//
// The dial path has no hop limit: a cycle in the outbound graph is unbounded mutual recursion
// (Selector.DialContext -> member.DialContext -> ...) that ends in `fatal error: stack overflow`,
// which no recover() can contain. The startup topological sort in adapter/outbound/manager.go is
// what makes that impossible, and it discovers edges through Dependencies().
//
// A selector is only safe because of one identity: the set of tags it can ever hand a connection to
// is exactly the list it reports as Dependencies(). Every runtime selection - SelectOutbound from the
// Clash API, from the daemon's SelectOutbound RPC, from the cached selection restored at Start -
// resolves through the same `outbounds` map that Start filled from that list, so no mutation can
// create an edge the sort did not already see. A cycle that the sort accepted cannot be closed later,
// and a cycle it would have rejected cannot be created later either.
//
// These tests pin that identity and the two behaviours it implies. If SelectOutbound could ever
// accept a tag outside All(), the startup check would stop being sufficient and the dial path would
// need a per-dial guard.

// TestSelectorSelectableSetIsExactlyItsDependencySet is the identity itself.
func TestSelectorSelectableSetIsExactlyItsDependencySet(t *testing.T) {
	t.Parallel()

	selector, _ := newSelectorFixture(t, false)

	require.Equal(t, []string{"node-a", "node-b"}, selector.All())
	require.Equal(t, selector.All(), selector.Dependencies(),
		"every member is a static edge, so the graph the startup sort validates is a superset of the "+
			"graph a dial can walk; if the two ever diverge, an accepted configuration can still loop")
}

// TestSelectorRefusesToSelectAnUndeclaredTag is the mutation boundary.
//
// The tag that would close a cycle is only ever reachable if it is a declared member, and a declared
// member is an edge the sort already saw. An undeclared tag must be refused AND leave the selection
// untouched: a rejected mutation that still moved the selection would be the same defect in a
// different place.
func TestSelectorRefusesToSelectAnUndeclaredTag(t *testing.T) {
	t.Parallel()

	selector, _ := newSelectorFixture(t, false)
	require.Same(t, selector.Selected(N.NetworkTCP), selector.Selected(N.NetworkUDP),
		"the fixture starts with one selection for both networks")

	for _, tag := range []string{"node-c", "", "group", "node-a "} {
		require.False(t, selector.SelectOutbound(tag),
			"a tag the selector never declared cannot be selected, so it cannot add an edge")
		require.Equal(t, "node-a", selector.Selected(N.NetworkTCP).Tag(),
			"a refused selection must leave the former, valid selection in place")
	}
}

// TestSelectorStillAcceptsALegitimateSelection is the compatibility half: refusing what cannot be
// selected must not refuse what can.
func TestSelectorStillAcceptsALegitimateSelection(t *testing.T) {
	t.Parallel()

	selector, _ := newSelectorFixture(t, false)

	require.True(t, selector.SelectOutbound("node-b"))
	require.Equal(t, "node-b", selector.Selected(N.NetworkTCP).Tag())
	require.Equal(t, []string{"node-b"}, selector.References(),
		"the active edge is reported by identity, which is what the idle-resource walk follows")

	require.True(t, selector.SelectOutbound("node-a"))
	require.Equal(t, "node-a", selector.Selected(N.NetworkTCP).Tag())

	// Re-selecting the current member is a no-op that still reports success.
	require.True(t, selector.SelectOutbound("node-a"))
	require.Equal(t, "node-a", selector.Selected(N.NetworkTCP).Tag())
}
