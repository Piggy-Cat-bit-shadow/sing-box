package physicalpath

// PATH-03, the combinatorial guard: once the enumeration keeps one entry per (node, route) pair
// instead of one per node, a graph built out of layers of parallel groups can have exponentially
// many such pairs.
//
// The guard answers that with a REFUSAL rather than with a prefix. A truncated enumeration cannot
// support the claim the enumeration exists to support - "every route under this root was validated"
// - so it is not a report at all.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTheNodeBudgetRefusesRatherThanTruncatingSilently is the guard's contract.
func TestTheNodeBudgetRefusesRatherThanTruncatingSilently(t *testing.T) {
	fixture := newDiamondFixture()

	// The default budget is far above any real object graph: this diamond is three (node, route)
	// pairs and nothing is refused.
	nodes, err := fixture.registry.resolver().Hops(fixture.outer)
	require.NoError(t, err)
	require.Len(t, nodes, 3, "middle, shared via A, shared via B")
	require.Positive(t, DefaultNodeBudget)

	// A budget below the number of pairs must refuse rather than answer with a prefix of the truth.
	resolver := fixture.registry.resolver().WithNodeBudget(2)
	nodes, err = resolver.Hops(fixture.outer)
	require.Error(t, err, "a truncated enumeration must never be reported as a complete one")
	require.Nil(t, nodes, "a partial list is not a report")
	require.Contains(t, err.Error(), "budget")
	require.Contains(t, err.Error(), "NOT validated")

	leaves, err := resolver.Leaves(fixture.outer)
	require.Error(t, err, "Leaves inherits the refusal instead of returning what it did enumerate")
	require.Nil(t, leaves)

	// The budget belongs to the resolver it was asked of, and raising it is a property of that
	// resolver rather than a process-wide switch.
	_, err = resolver.WithNodeBudget(DefaultNodeBudget).Hops(fixture.outer)
	require.NoError(t, err, "a raised budget enumerates the same legal graph without refusing")

	// And the resolver the low budget was asked of is unchanged: the builder pins a copy.
	_, err = resolver.Hops(fixture.outer)
	require.Error(t, err, "the low-budget resolver still refuses: WithNodeBudget must not mutate it")
}
