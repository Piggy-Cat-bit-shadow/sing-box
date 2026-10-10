package physicalpath

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// P1: one topology, every API, one contract
// ---------------------------------------------------------------------------
//
// Every previous round asserted one API at a time, which is how `Build` came to report packet order
// while `Hops` reported descent order for the same graph without anyone noticing. This file asks all
// the APIs the SAME question about the SAME fixture and fails on any disagreement.
//
// # The three semantic axes, kept apart
//
//	DECLARATION  selected exit -> dependency underlay -> deeper dependency
//	PHYSICAL     device -> deepest underlay -> middle -> selected exit -> target
//	CONTROL      route/root -> outer group -> inner group -> selected member
//
// `Build.Hops`, `Hops()` and `Leaves()` must agree on PHYSICAL. Control never participates in
// physical order. `Exit` is true only for the routing-selected hop of a COMPLETE route, so a route
// truncated by a missing dependency must not promote its truncation point to an exit.
//
// These are DIAGNOSTIC tests: they print the disagreement rather than asserting a fix into place,
// because the fix has to be designed against measured behaviour, not against a guess.

func reportPath(t *testing.T, label string, path Path) {
	t.Helper()
	for _, hop := range path.Hops {
		t.Logf("%s BUILD hop %-10q pos=%d entry=%v exit=%v chain=%v owner=%q",
			label, hop.DeclaredTag, hop.Position, hop.Position == 0,
			hop.Position == len(path.Hops)-1, hop.DeclaredTag, hop.ControlOwner)
	}
	for _, unknown := range path.Unknowns {
		t.Logf("%s BUILD unknown %-10q pos=%d reason=%q", label, unknown.Node, unknown.Position, unknown.Reason)
	}
	entry, hasEntry := path.Entry()
	exit, hasExit := path.Exit()
	t.Logf("%s BUILD entry=(%q,%v) exit=(%q,%v) controlPath=%v hops=%d unknowns=%d",
		label, entry.DeclaredTag, hasEntry, exit.DeclaredTag, hasExit, path.ControlPath,
		len(path.Hops), len(path.Unknowns))
}

func reportNodes(t *testing.T, label string, nodes []PathNode) {
	t.Helper()
	for _, node := range nodes {
		t.Logf("%s HOPS node %-10q route=%-24q pos=%d exit=%v current=%v resolved=%v required=%v",
			label, node.Tag, node.Route(), node.Position, node.Exit, node.IsCurrent, node.Resolved,
			node.RequiredNetworks)
	}
}

// TestDiagnosticPathContractAcrossAPIs is the diagnostic. It does not assert a fix: it records what
// each API says so the disagreement can be measured rather than argued about.
func TestDiagnosticPathContractAcrossAPIs(t *testing.T) {
	cases := []struct {
		name  string
		build func() *Resolver
		root  string
	}{
		{
			name: "two hop: exit.detour = entry",
			build: func() *Resolver {
				return newRegistry(tcpLeaf("entry"), tcpLeaf("exit", "entry")).resolver()
			},
			root: "exit",
		},
		{
			name: "three hop: c -> b -> a",
			build: func() *Resolver {
				return newRegistry(tcpLeaf("a"), tcpLeaf("b", "a"), tcpLeaf("c", "b")).resolver()
			},
			root: "c",
		},
		{
			name: "missing deepest underlay",
			build: func() *Resolver {
				// `exit.detour = missing-entry` and nothing else, so exactly one hop is known.
				return newRegistry(tcpLeaf("exit", "missing-entry")).resolver()
			},
			root: "exit",
		},
		{
			name: "three hop with the entry missing",
			build: func() *Resolver {
				return newRegistry(tcpLeaf("b", "missing-a"), tcpLeaf("c", "b")).resolver()
			},
			root: "c",
		},
		{
			name: "single hop, no dependency",
			build: func() *Resolver {
				return newRegistry(tcpLeaf("direct")).resolver()
			},
			root: "direct",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			resolver := testCase.build()

			built, buildErr := Build(resolver, TagOrOutbound{Tag: testCase.root}, Options{Network: N.NetworkTCP})
			if buildErr != nil {
				t.Logf("Build error: %v", buildErr)
			}
			reportPath(t, testCase.name, built)

			nodes, hopsErr := resolver.Hops(mustLookup(t, resolver, testCase.root))
			if hopsErr != nil {
				t.Logf("Hops error: %v", hopsErr)
			}
			reportNodes(t, testCase.name, nodes)

			leaves, leavesErr := resolver.Leaves(mustLookup(t, resolver, testCase.root))
			if leavesErr != nil {
				t.Logf("Leaves error: %v", leavesErr)
			}
			t.Logf("%s LEAVES count=%d", testCase.name, len(leaves))
			for _, leaf := range leaves {
				t.Logf("%s   leaf %-10q route=%q pos=%d", testCase.name, leaf.Tag, leaf.Route(), leaf.Position)
			}
		})
	}
}

// mustLookup resolves a tag in a fixture registry.
func mustLookup(t *testing.T, resolver *Resolver, tag string) adapter.Outbound {
	t.Helper()
	outbound, loaded := resolver.Lookup(tag)
	if !loaded {
		t.Fatalf("fixture tag %q is not in the registry", tag)
	}
	return outbound
}
