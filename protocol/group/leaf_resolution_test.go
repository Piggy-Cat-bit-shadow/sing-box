package group

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for leaf resolution.
//
// # Why the leaf matters
//
// A measurement's result is attributed to a node. If a group's selection moves while the
// measurement is in flight, resolving the leaf afterwards attributes the delay to whatever the
// group moved TO - a node that may never have been measured. Resolving once, up front, makes the
// attribution a fact about the connection that was actually tested.

// switchingGroup is a group whose selection can be changed at will.
type switchingGroup struct {
	adapter.Outbound
	tag      string
	selected atomic.Pointer[adapter.Outbound]
}

func (g *switchingGroup) Type() string      { return "switching" }
func (g *switchingGroup) Tag() string       { return g.tag }
func (g *switchingGroup) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (g *switchingGroup) Selected(network string) adapter.Outbound {
	selected := g.selected.Load()
	if selected == nil {
		return nil
	}
	return *selected
}

func (g *switchingGroup) All() []string {
	selected := g.Selected(N.NetworkTCP)
	if selected == nil {
		return nil
	}
	return []string{selected.Tag()}
}

func (g *switchingGroup) AttachConnection(closer io.Closer) func() { return func() {} }

func (g *switchingGroup) selectOutbound(outbound adapter.Outbound) {
	g.selected.Store(&outbound)
}

// TestResolveURLTestLeafFixesAttributionBeforeMeasurement is §64(M).
//
// The leaf is resolved while the group selects A. The group then moves to B. The resolved leaf must
// still be A: it is the node the measurement is about to test.
func TestResolveURLTestLeafFixesAttributionBeforeMeasurement(t *testing.T) {
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}

	group := &switchingGroup{tag: "group"}
	group.selectOutbound(nodeA)

	leaf, err := ResolveURLTestLeaf(group, N.NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, "node-a", leaf.Tag())

	// The group moves while a measurement would be in flight.
	group.selectOutbound(nodeB)

	require.Equal(t, "node-a", leaf.Tag(),
		"the resolved leaf is fixed: the result belongs to the node that was measured, not to "+
			"whatever the group moved to afterwards")
	require.Equal(t, "node-b", RealTag(group, N.NetworkTCP),
		"while a fresh resolution correctly reports the new selection")
}

// TestResolveURLTestLeafFollowsNestedGroups covers the ordinary nesting case.
func TestResolveURLTestLeafFollowsNestedGroups(t *testing.T) {
	leaf := &stubOutbound{tag: "leaf"}

	inner := &switchingGroup{tag: "inner"}
	inner.selectOutbound(leaf)

	outer := &switchingGroup{tag: "outer"}
	outer.selectOutbound(inner)

	resolved, err := ResolveURLTestLeaf(outer, N.NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, "leaf", resolved.Tag())

	// A plain outbound resolves to itself.
	self, err := ResolveURLTestLeaf(leaf, N.NetworkTCP)
	require.NoError(t, err)
	require.Same(t, leaf, self)
}

// TestResolveURLTestLeafDetectsCycles is §37, §64(N).
//
// A configuration can describe a cycle. The traversal must detect it rather than follow it forever;
// the previous implementation was a bare loop with no record, so RealTag on a cycle never returned.
func TestResolveURLTestLeafDetectsCycles(t *testing.T) {
	groupA := &switchingGroup{tag: "group-a"}
	groupB := &switchingGroup{tag: "group-b"}

	// A -> B -> A
	groupA.selectOutbound(groupB)
	groupB.selectOutbound(groupA)

	done := make(chan error, 1)
	go func() {
		_, err := ResolveURLTestLeaf(groupA, N.NetworkTCP)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err, "a cycle must be reported, not followed")
	case <-time.After(3 * time.Second):
		t.Fatal("leaf resolution did not return for a cycle; the traversal must detect one " +
			"rather than loop forever")
	}

	// RealTag must be equally safe: it is the path every display and attribution caller uses.
	tagDone := make(chan string, 1)
	go func() { tagDone <- RealTag(groupA, N.NetworkTCP) }()

	select {
	case tag := <-tagDone:
		require.Empty(t, tag, "an unresolvable outbound reports an empty tag rather than hanging")
	case <-time.After(3 * time.Second):
		t.Fatal("RealTag did not return for a cycle")
	}
}

// TestResolveURLTestLeafHandlesSelfReference is the smallest cycle.
func TestResolveURLTestLeafHandlesSelfReference(t *testing.T) {
	group := &switchingGroup{tag: "self"}
	group.selected.Store(new(adapter.Outbound))
	*group.selected.Load() = group

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := ResolveURLTestLeaf(group, N.NetworkTCP)
		require.Error(t, err, "a self-referential group is a cycle")
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("self-referential group did not terminate")
	}
}

// TestResolveURLTestLeafReportsMissingSelection covers the other unresolvable case.
func TestResolveURLTestLeafReportsMissingSelection(t *testing.T) {
	group := &switchingGroup{tag: "empty"}
	var none adapter.Outbound
	group.selected.Store(&none)

	_, err := ResolveURLTestLeaf(group, N.NetworkTCP)
	require.Error(t, err, "a group with no selection cannot resolve to a leaf")

	require.Empty(t, RealTag(group, N.NetworkTCP))
}

var _ = context.Background
