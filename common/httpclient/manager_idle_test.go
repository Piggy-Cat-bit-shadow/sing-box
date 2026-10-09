package httpclient

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCloseIdleConnectionsRetiresEveryManagedTransportWithoutReplacingIt is the pool half of the
// reuse boundary.
//
// This manager owns the connections behind provider refresh, remote rule sets, the dashboard and the
// API. Until this method existed the reference manager's walk could not reach them, so a resume
// boundary retired every pool except these four consumers' - the gap was latency rather than
// correctness, because those fetches are staggered after a wake anyway, but it was real: a rule-set
// refresh after a long sleep could be handed a connection the sleep had killed.
//
// The assertions are the two halves that must both hold, and the second is the one an over-eager
// implementation gets wrong:
//
//  1. every managed transport's idle connections are released, and
//  2. the inner transport is NOT swapped, so nothing about this can make the next request dial a
//     different path. That is the difference from ResetNetwork, which replaces the epoch; a resume is
//     not a network change, and a "retire" that replaced the transport would be a reconnect trigger
//     wearing a lifecycle name.
func TestCloseIdleConnectionsRetiresEveryManagedTransportWithoutReplacingIt(t *testing.T) {
	t.Parallel()
	var builtFirst, builtSecond atomic.Int64
	var idleClosedFirst, idleClosedSecond atomic.Int64
	var closedFirst, closedSecond atomic.Int64
	first := &ManagedTransport{
		cheapRebuild: true,
		factory: func() (innerTransport, error) {
			builtFirst.Add(1)
			return &fakeInnerTransport{closed: &closedFirst, idleClosed: &idleClosedFirst}, nil
		},
	}
	second := &ManagedTransport{
		cheapRebuild: true,
		factory: func() (innerTransport, error) {
			builtSecond.Add(1)
			return &fakeInnerTransport{closed: &closedSecond, idleClosed: &idleClosedSecond}, nil
		},
	}
	// The epochs are built by real use, which is also what puts an idle pooled connection there to
	// release: a transport that was never used has nothing to retire.
	for _, transport := range []*ManagedTransport{first, second} {
		response, err := transport.RoundTrip(newTestRequest())
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
	}
	require.EqualValues(t, 1, builtFirst.Load())
	require.EqualValues(t, 1, builtSecond.Load())

	manager := &Manager{managedTransports: []*ManagedTransport{first, second}}
	manager.CloseIdleConnections()

	require.EqualValues(t, 1, idleClosedFirst.Load(),
		"the boundary did not reach the first managed transport's idle pool")
	require.EqualValues(t, 1, idleClosedSecond.Load(),
		"the boundary did not reach the second managed transport's idle pool")
	require.Zero(t, closedFirst.Load(), "the boundary closed the inner transport instead of its idle connections")
	require.Zero(t, closedSecond.Load())

	// And the transport survives: the next request uses the SAME inner transport, so a boundary cannot
	// have made it dial. This is the assertion that separates this method from ResetNetwork.
	response, err := first.RoundTrip(newTestRequest())
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.EqualValues(t, 1, builtFirst.Load(),
		"the boundary replaced the inner transport: the next request pays a dial it should not")

	// The contrast, on the same object: the reset-shaped pass DOES replace it, because a real network
	// transition must not carry a verdict about the network being left.
	manager.ResetNetwork()
	response, err = second.RoundTrip(newTestRequest())
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.EqualValues(t, 2, builtSecond.Load(),
		"ResetNetwork no longer replaces the inner transport: the two passes are no longer distinguishable")
}

// TestCloseIdleConnectionsIsSafeOnAnEmptyAndAClosedManager keeps the two lifecycle edges honest.
//
// A boundary can arrive while the manager is being torn down - the governor is closed before the
// scope that owns this object, and the walk snapshots the transport list before calling anything - so
// an empty list and a list whose transports have already been closed must both be no-ops rather than
// panics or resurrected connections.
func TestCloseIdleConnectionsIsSafeOnAnEmptyAndAClosedManager(t *testing.T) {
	t.Parallel()
	var idleClosed atomic.Int64
	manager := &Manager{}
	require.NotPanics(t, manager.CloseIdleConnections)

	transport := &ManagedTransport{
		cheapRebuild: true,
		factory: func() (innerTransport, error) {
			return &fakeInnerTransport{idleClosed: &idleClosed}, nil
		},
	}
	response, err := transport.RoundTrip(newTestRequest())
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	manager.managedTransports = []*ManagedTransport{transport}

	require.NoError(t, manager.close())
	require.NotPanics(t, manager.CloseIdleConnections,
		"a boundary that arrives after teardown must be a no-op")
	require.EqualValues(t, 0, idleClosed.Load(),
		"the boundary reached a transport that had already been closed")
}
