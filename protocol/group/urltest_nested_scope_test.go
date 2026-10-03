package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/batch"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for a nested URLTest group's measurement scope.
//
// # The defect these pin
//
// A URLTest member that is itself a URLTest group was handled by calling nested.group.urlTest(),
// which runs the CHILD's health check against the CHILD's configured URL and then rewrites the
// child's own selection. The parent then folded those results into its own ranking.
//
// Two things are wrong with that. The parent ranks a member by a delay measured against a target
// the PARENT never chose, so a member can win or lose on an unrelated measurement. And a parent
// health check silently mutates the child's selection - the child's policy is supposed to be the
// child's own business.
//
// The correct contract: the parent measures the child's CURRENT leaf against the PARENT's target,
// and the child's own selection is left untouched.

// TestNestedGroupIsMeasuredAgainstTheParentTarget is §63, §64.
//
// The parent must evaluate a nested group by measuring that group's CURRENT LEAF against the
// PARENT's target. The observable proof available without a live probe target is which leaves the
// batch decides to test: with the old behaviour the parent never queued the child's leaves at all
// - it delegated to the child's own health check against the child's URL - so the parent's
// freshness table stayed empty for them.
//
// A live measurement is not needed to show that. What is needed is the set of leaves the batch
// considered, which is recorded in b.checked.
func TestNestedGroupIsMeasuredAgainstTheParentTarget(t *testing.T) {
	parentTarget := "https://parent.example/probe"
	childTarget := "https://child.example/probe"

	leafA := &stubOutbound{tag: "leaf-a"}
	leafB := &stubOutbound{tag: "leaf-b"}

	childGroup, _ := newGroupFixture(t, childTarget, leafA, leafB)
	child := &URLTest{
		Adapter: outbound.NewAdapter(C.TypeURLTest, "child", []string{N.NetworkTCP}, []string{"leaf-a", "leaf-b"}),
		group:   childGroup,
		link:    childTarget,
		tags:    []string{"leaf-a", "leaf-b"},
	}

	parent, _ := newGroupFixture(t, parentTarget, child)

	// The batch resolves a group's members by tag, so the manager must know the leaves.
	manager := &taggedOutboundManager{byTag: map[string]adapter.Outbound{
		"leaf-a": leafA,
		"leaf-b": leafB,
	}}

	require.NotEqual(t, parent.scope, childGroup.scope,
		"the test is only meaningful while the parent and child targets differ")

	// Run one batch directly so the set of leaves it considered can be inspected.
	runner, _ := batch.New(context.Background(), batch.WithConcurrencyNum[any](10))

	testBatch := &urlTestBatch{
		batch:    runner,
		ctx:      context.Background(),
		outbound: manager,
		history:  parent.history,
		logger:   parent.logger,
		scope:    parent.scope,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
	}
	testBatch.test([]adapter.Outbound{child}, parent.link, 0, true)
	runner.Wait()

	// The parent's batch must have descended to the child's leaves.
	require.True(t, testBatch.checked["leaf-a"],
		"the parent must measure the child's current leaf against its OWN target; the nested "+
			"group used to be handed to the child's own health check instead, so the parent never "+
			"queued the child's leaves at all")
	require.True(t, testBatch.checked["leaf-b"])
}

// TestNestedGroupSelectionIsNotMutatedByParentCheck is §63's other half.
//
// The child's selection is the child's own policy. A parent health check must not change it.
func TestNestedGroupSelectionIsNotMutatedByParentCheck(t *testing.T) {
	leafA := &stubOutbound{tag: "leaf-a"}
	leafB := &stubOutbound{tag: "leaf-b"}

	childGroup, childStorage := newGroupFixture(t, "https://child.example/probe", leafA, leafB)
	child := &URLTest{
		Adapter: outbound.NewAdapter(C.TypeURLTest, "child", []string{N.NetworkTCP}, []string{"leaf-a", "leaf-b"}),
		group:   childGroup,
		link:    "https://child.example/probe",
		tags:    []string{"leaf-a", "leaf-b"},
	}

	// Give the child a definite selection of its own.
	childStorage.StoreURLTestHistoryFor("leaf-b", childGroup.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 5})
	childStorage.StoreURLTestHistoryFor("leaf-a", childGroup.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 900})

	before, _ := childGroup.Select(N.NetworkTCP)
	require.NotNil(t, before)
	require.Equal(t, "leaf-b", before.Tag(), "the child's own selection is leaf-b")

	// A parent whose member is the child.
	parent, _ := newGroupFixture(t, "https://parent.example/probe", child)
	parent.CheckOutbounds(context.Background(), true)

	after, _ := childGroup.Select(N.NetworkTCP)
	require.NotNil(t, after)
	require.Equal(t, before.Tag(), after.Tag(),
		"the parent's health check must not change the child's selection; the child chooses its "+
			"own member from its own measurements")
}

// taggedOutboundManager resolves members by tag, which is how a batch expands a group.
type taggedOutboundManager struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
}

func (m *taggedOutboundManager) Outbounds() []adapter.Outbound { return nil }
func (m *taggedOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.byTag[tag]
	return outbound, loaded
}
