package physicalpath

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// TestValidateRootsRefusesARouteWhoseDeclaredDetourDoesNotExist is the standalone-API half of the
// "missing detour" question, and it is deliberately NOT about the manager.
//
// # What the two callers do differently, and why the difference is a defect
//
// `adapter/outbound`'s start-order lint rejects `dependency[tag] not found for outbound[tag]` from
// the DECLARED dependency edge set BEFORE it runs this dry run, so the product path never reaches
// the case below. That is what leaves.go:462-468 means when it says the missing tag "is reported by
// the caller's own existence check".
//
// `ValidateRoots` is exported, and `Report.Reachable` is documented as the stronger question:
//
//	A node the dry run could not determine - an unknown hop - does NOT count as reachable: the
//	question this answers is "was every leaf PROVEN usable", and an unproven leaf is not.
//
// A route truncated by a missing dependency has NO exit at all - numberRoute is called with
// `complete=false`, so not one node of it claims to be the far end. Every hop that IS known can be
// perfectly usable. So a caller that gates on `ValidateRoots(...).Err()`, or on
// `report.Reachable()`, is told that a route which provably never reaches a far end was proven
// usable. That is a false READY, and it is a fact about THIS function rather than about the lint
// that happens to run before it in the one caller this repository ships.
//
// The assertion is the inverse of that: a truncated route must not be reported as reachable, and
// the report must say which route was truncated and why.
func TestValidateRootsRefusesARouteWhoseDeclaredDetourDoesNotExist(t *testing.T) {
	// `ghost` is declared as the hop this one dials through and exists nowhere in the registry, so
	// the enumeration returns routeTruncated: the route never reaches its far end.
	exit := dualLeaf("exit", "ghost")
	registry := newRegistry(exit)

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{exit}, nil,
		[]string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)

	t.Logf("roots=%v", report.Roots)
	for _, check := range report.Nodes {
		t.Logf("hop=%s path=%q position=%d exit=%v requirement=%v unknowns=%v",
			check.Hop, check.Path, check.Position, check.Exit, check.Requirement, check.Unknowns)
	}
	t.Logf("failures=%v reachable=%v err=%v", report.Failures, report.Reachable(), report.Err())

	// Preconditions that make the failure meaningful rather than accidental: the walk has to have
	// produced a node at all, and that node must NOT claim to be the exit. If either is false the
	// fixture is not reaching the truncated branch and the assertion below would be vacuous.
	require.Len(t, report.Nodes, 1, "the walk must record the hop that declares the missing detour")
	require.False(t, report.Nodes[0].Exit,
		"a route that never reached its far end must not claim an exit; if this is true the fixture "+
			"is not on the truncated branch and the assertion below proves nothing")

	require.False(t, report.Reachable(),
		"outbound/exit declares `detour: ghost` and no such outbound exists, so the route is "+
			"truncated and no leaf of it was ever proven usable. Reporting it as reachable is a "+
			"false READY for every caller of this exported API. nodes=%v failures=%v",
		describeChecks(report.Nodes), report.Failures)

	require.Error(t, report.Err(),
		"the report must refuse the configuration: a caller that starts a box on Err()==nil would "+
			"start a route whose detour cannot be dialled")
}

// TestValidateRootsStillAcceptsACompleteRoute is the discriminating control.
//
// Without it, a change that made Reachable() false for everything would satisfy the test above.
// The same fixture shape with the detour RESOLVING must stay reachable when nothing else is wrong.
func TestValidateRootsStillAcceptsACompleteRoute(t *testing.T) {
	entry := dualLeaf("entry")
	exit := dualLeaf("exit", "entry")
	registry := newRegistry(entry, exit)

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{exit}, nil,
		[]string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)
	require.True(t, report.Reachable(),
		"a two-hop route whose detour resolves carries TCP and a rule delivers TCP, so it must stay "+
			"reachable; nodes=%v failures=%v", describeChecks(report.Nodes), report.Failures)
	require.NoError(t, report.Err())
}
