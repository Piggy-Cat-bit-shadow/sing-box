package bridge

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for the SCOPE ownership of a bridge instance index.
//
// # Why this file exists next to index_leak_test.go
//
// index_leak_test.go proves that the constructor claims nothing and that acquireIndex/releaseIndex
// are balanced and idempotent. Those are the helpers, and they were already right. What nothing
// pinned is the WIRING: that allocateIndex actually hands the release to the Scope.
//
// The product closes a Box by closing its Scope, and Scope.Close() runs the entries handed to it
// through scope.Add - it never calls a component's Close() method. Deleting the scope.Add inside
// allocateIndex would leak one process-global slot per Box close, and every existing test in this
// package would still pass, because every one of them drives the helpers directly.
//
// These tests drive the real adapter.Scope instead. The full network start needs a real TUN device a
// unit test cannot create, so the scope is driven the way Start drives it: allocateIndex is the
// function Start calls, and it is where the ownership is transferred.

func newTestScope() *adapter.Scope {
	return adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
}

// TestScopeCloseReleasesBridgeIndex is invariant #1 for the bridge slot.
//
// A slot claimed while the Scope is open must be back in the pool once the Scope closes, because
// Box.Close() is the only release the product performs.
func TestScopeCloseReleasesBridgeIndex(t *testing.T) {
	before := usedIndexCount()

	base := &backendBase{}
	scope := newTestScope()
	require.NoError(t, base.allocateIndex(scope))
	require.Equal(t, before+1, usedIndexCount(), "the slot must be held while the Scope is open")

	require.NoError(t, scope.Close())
	require.Equal(t, before, usedIndexCount(),
		"closing the Scope must return the slot: Box.Close() closes the Scope and never calls the "+
			"backend's Close(), so a release that is not handed to the Scope never runs")
}

// TestRepeatedStartThroughScopeHoldsOneSlot guards the scope-owned path against a repeated Start
// consuming a second slot.
func TestRepeatedStartThroughScopeHoldsOneSlot(t *testing.T) {
	before := usedIndexCount()

	base := &backendBase{}
	scope := newTestScope()
	require.NoError(t, base.allocateIndex(scope))
	require.NoError(t, base.allocateIndex(scope))
	require.NoError(t, base.allocateIndex(scope))
	require.Equal(t, before+1, usedIndexCount(),
		"a repeated Start must register the same slot, not claim one per call")

	require.NoError(t, scope.Close())
	require.Equal(t, before, usedIndexCount())
}

// TestScopeCloseCannotDoubleRelease covers the ordering the pool actually depends on.
//
// Close runs the registered release once. If a second release followed it, the slot would be handed
// to another bridge while this one still believed it owned it, which corrupts the pool rather than
// merely leaking from it. The test takes a slot AFTER the close to prove the pool is consistent, not
// just that the counter moved.
func TestScopeCloseCannotDoubleRelease(t *testing.T) {
	before := usedIndexCount()

	base := &backendBase{}
	scope := newTestScope()
	require.NoError(t, base.allocateIndex(scope))
	require.NoError(t, scope.Close())
	require.NoError(t, scope.Close())
	base.releaseIndex()

	require.Equal(t, before, usedIndexCount())

	// The pool must still hand out a consistent slot.
	other := &backendBase{}
	otherScope := newTestScope()
	require.NoError(t, other.allocateIndex(otherScope))
	require.Equal(t, before+1, usedIndexCount(),
		"a slot must still be available after a double close")
	require.NoError(t, otherScope.Close())
	require.Equal(t, before, usedIndexCount())
}

// TestOneScopeCloseDoesNotReleaseAnothersSlot is §4's "two Boxes / mixed create and close"
// requirement at the level the ownership lives: closing one owner must not free a slot a different
// owner is still using.
func TestOneScopeCloseDoesNotReleaseAnothersSlot(t *testing.T) {
	before := usedIndexCount()

	first := &backendBase{}
	second := &backendBase{}
	firstScope := newTestScope()
	secondScope := newTestScope()

	require.NoError(t, first.allocateIndex(firstScope))
	require.NoError(t, second.allocateIndex(secondScope))
	require.Equal(t, before+2, usedIndexCount(), "two owners hold two distinct slots")

	require.NoError(t, firstScope.Close())
	require.Equal(t, before+1, usedIndexCount(),
		"closing one owner must release exactly its own slot")
	require.NotEqual(t, first.index, second.index,
		"two live bridges must not share an index")

	require.NoError(t, secondScope.Close())
	require.Equal(t, before, usedIndexCount())
}
