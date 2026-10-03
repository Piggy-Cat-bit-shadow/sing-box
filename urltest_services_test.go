package box

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Tests for the Box's URL-test service injection.
//
// # The defect these pin
//
// The coordinator was created only inside the branch that created a missing HistoryStorage, so the
// two decisions were coupled. A caller that supplied its own HistoryStorage - a normal thing to do
// when building a Box context - got no coordinator at all, and every measurement in that Box ran
// unbounded. The reverse combination silently replaced a caller's chosen limit with the default.
//
// The four combinations are therefore each asserted explicitly, and identity is checked rather than
// merely presence: "already provided" must mean "left alone".

// TestURLTestServicesBothAbsent is §23.
func TestURLTestServicesBothAbsent(t *testing.T) {
	ctx, _ := ensureURLTestServices(context.Background())

	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	require.NotNil(t, history, "a Box must supply a history storage when the caller has none")

	coordinator := urltest.CoordinatorFromContext(ctx)
	require.NotNil(t, coordinator, "and a coordinator, or measurements run unbounded")
	require.Equal(t, C.URLTestConcurrencyLimit, coordinator.Limit())
}

// TestURLTestServicesHistoryOnly is §22.
//
// This is the combination the old coupling broke: a caller with its own history storage got no
// coordinator at all.
func TestURLTestServicesHistoryOnly(t *testing.T) {
	provided := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), provided)

	ctx, _ = ensureURLTestServices(ctx)

	require.Same(t, provided, service.PtrFromContext[urltest.HistoryStorage](ctx),
		"a caller's history storage must be kept, not replaced")

	coordinator := urltest.CoordinatorFromContext(ctx)
	require.NotNil(t, coordinator,
		"a coordinator must still be supplied. Previously it was created only alongside a missing "+
			"history storage, so this common case left every measurement in the Box unbounded")
	require.Equal(t, C.URLTestConcurrencyLimit, coordinator.Limit())
}

// TestURLTestServicesCoordinatorOnly is §21.
//
// A caller's chosen limit must survive.
func TestURLTestServicesCoordinatorOnly(t *testing.T) {
	const customLimit = 3
	provided := urltest.NewCoordinator(customLimit)
	ctx := urltest.ContextWithCoordinator(context.Background(), provided)

	ctx, _ = ensureURLTestServices(ctx)

	require.Same(t, provided, urltest.CoordinatorFromContext(ctx),
		"a caller's coordinator must be kept, not replaced by the default")
	require.Equal(t, customLimit, urltest.CoordinatorFromContext(ctx).Limit(),
		"and its limit must be the one the caller chose, not the Box default")

	require.NotNil(t, service.PtrFromContext[urltest.HistoryStorage](ctx),
		"the missing history storage is supplied")
}

// TestURLTestServicesBothPresent is §24.
func TestURLTestServicesBothPresent(t *testing.T) {
	providedHistory := urltest.NewHistoryStorage()
	providedCoordinator := urltest.NewCoordinator(7)

	ctx := service.ContextWithPtr(context.Background(), providedHistory)
	ctx = urltest.ContextWithCoordinator(ctx, providedCoordinator)

	ctx, _ = ensureURLTestServices(ctx)

	require.Same(t, providedHistory, service.PtrFromContext[urltest.HistoryStorage](ctx))
	require.Same(t, providedCoordinator, urltest.CoordinatorFromContext(ctx))
	require.Equal(t, 7, urltest.CoordinatorFromContext(ctx).Limit())
}

// TestURLTestServicesAreIndependentAcrossBoxes is §20.
//
// Two Box contexts must not share a limiter, which is what makes a configuration-check Box unable
// to starve the running one.
func TestURLTestServicesAreIndependentAcrossBoxes(t *testing.T) {
	ctxA, _ := ensureURLTestServices(context.Background())
	ctxB, _ := ensureURLTestServices(context.Background())

	coordinatorA := urltest.CoordinatorFromContext(ctxA)
	coordinatorB := urltest.CoordinatorFromContext(ctxB)

	require.NotSame(t, coordinatorA, coordinatorB,
		"each Box must get its own coordinator")
	require.NotSame(t,
		service.PtrFromContext[urltest.HistoryStorage](ctxA),
		service.PtrFromContext[urltest.HistoryStorage](ctxB),
		"and its own history storage")

	// Exhausting one must not block the other.
	releaseA, err := coordinatorA.Acquire(ctxA)
	require.NoError(t, err)
	defer releaseA()
	for index := 1; index < coordinatorA.Limit(); index++ {
		_, err = coordinatorA.Acquire(ctxA)
		require.NoError(t, err)
	}
	require.Equal(t, coordinatorA.Limit(), coordinatorA.InFlight())

	releaseB, err := coordinatorB.Acquire(ctxB)
	require.NoError(t, err,
		"Box B must not be blocked by Box A exhausting its budget; a shared limiter would let a "+
			"temporary configuration-check Box stall the running one")
	releaseB()
}

// Tests for the ownership of the URL-test history storage.
//
// # Why ownership has to be explicit
//
// Putting a storage on the context does not make it part of the Box lifecycle. When the Box creates
// one, only the Box knows and only the Box can close it; the daemon closes the instance it creates.
// A standalone Box that created one and never closed it left the storage live after Close - closed
// flag unset, maps retained, late writers still accepted - so a measurement finishing after
// teardown could write into a Box that no longer existed.
//
// The rule is one-directional and easy to get wrong in the other direction too: closing a storage
// the caller owns would break the daemon, which closes its own after the Box is gone.

// TestBoxOwnedHistoryStorageIsReported tests the creation half.
func TestBoxOwnedHistoryStorageIsReported(t *testing.T) {
	ctx, owned := ensureURLTestServices(context.Background())

	require.NotNil(t, owned,
		"a storage the helper creates must be reported, or nothing can ever close it")
	require.Same(t, owned, service.PtrFromContext[urltest.HistoryStorage](ctx),
		"and it is the one installed on the context")

	// A second call must not create a second storage, and must not claim ownership of the existing
	// one.
	secondCtx, secondOwned := ensureURLTestServices(ctx)
	require.Nil(t, secondOwned,
		"the storage already exists, so this call created nothing and owns nothing")
	require.Same(t, owned, service.PtrFromContext[urltest.HistoryStorage](secondCtx))
}

// TestCallerHistoryStorageIsNotOwned tests the other half.
func TestCallerHistoryStorageIsNotOwned(t *testing.T) {
	provided := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), provided)

	_, owned := ensureURLTestServices(ctx)

	require.Nil(t, owned,
		"a caller-supplied storage must not be reported as owned. Closing it would break a caller "+
			"that keeps using it - the daemon closes its own instance after the Box is gone")
}

// TestOwnedHistoryStorageCloseIsTerminal states the contract the Box relies on.
func TestOwnedHistoryStorageCloseIsTerminal(t *testing.T) {
	_, owned := ensureURLTestServices(context.Background())
	require.NotNil(t, owned)

	scope, err := urltest.NewMeasurementScope("https://example.com/probe", nil)
	require.NoError(t, err)

	owned.StoreDisplayHistory("node-a", scope, &adapter.URLTestHistory{Delay: 10})
	require.NoError(t, owned.Close())

	require.Nil(t, owned.LoadURLTestHistory("node-a"),
		"a closed storage holds nothing")

	// A late writer must be refused, which is the property the Box depends on: a measurement that
	// finishes after teardown must not repopulate a storage for a Box that no longer exists.
	owned.StoreDisplayHistory("node-a", scope, &adapter.URLTestHistory{Delay: 99})
	require.Nil(t, owned.LoadURLTestHistory("node-a"),
		"a late write after Close must be discarded")
}
