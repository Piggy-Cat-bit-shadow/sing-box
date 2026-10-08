package runtimecoord

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// P1-2: recovery ownership must be generation-safe.
//
// # The defect a bare `pending bool` had
//
//	grant for generation N              pending = true
//	publish N+1                         pending = false   (bookkeeping reset)
//	grant for N+1                       pending = true
//	the N rebind finishes               pending = false   <- clears what N+1 owns
//
// A third trigger would then be granted while the N+1 rebind was still running, so "one logical
// recovery at a time" was not actually guaranteed across a generation change - which is precisely
// when several triggers arrive together.
//
// The second half of the defect was that the generation change only reset bookkeeping. Clearing a
// flag is not cancellation: a rebind blocked in a dial learns about a superseded generation through
// its context or not at all.

// The interleaving from the brief, step by step.
func TestLeaseSupersededCompletionCannotReleaseTheNewGeneration(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	// 1. an old rebind is granted
	oldLease, granted := registration.BeginRebind(adapter.RebindHandshakeGiveUp)
	require.True(t, granted)
	require.EqualValues(t, 0, oldLease.Generation())

	// 2. the network changes
	coordinator.Advance(1)

	// 3. a new rebind is granted for the new generation
	newLease, granted := registration.BeginRebind(adapter.RebindNetworkChanged)
	require.True(t, granted, "a new generation must be able to recover immediately")
	require.EqualValues(t, 1, newLease.Generation())
	require.NotEqual(t, oldLease.ID(), newLease.ID(), "the two recoveries must be distinguishable")

	// 4. the old rebind finishes late
	oldLease.Complete()

	// 5. the new recovery must still be owned
	require.Same(t, newLease, registration.InflightLease(),
		"a superseded completion must not release the recovery the new generation owns")
	require.False(t, newLease.Expired())

	// 6. and while it is owned, no third recovery can be granted
	_, granted = registration.BeginRebind(adapter.RebindHandshakeGiveUp)
	require.False(t, granted, "one logical recovery at a time, across generations")

	// 7. the owner completes, and the state is clean
	newLease.Complete()
	require.Nil(t, registration.InflightLease())
}

// A generation change must actually CANCEL the recovery that belonged to the old network, not merely
// forget it.
func TestLeaseIsCancelledByAGenerationChange(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	lease, granted := registration.BeginRebind(adapter.RebindHandshakeGiveUp)
	require.True(t, granted)

	select {
	case <-lease.Context().Done():
		t.Fatal("the lease must be live before the generation changes")
	default:
	}

	coordinator.Advance(1)

	select {
	case <-lease.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("a generation change must cancel the superseded recovery's context; a rebind blocked in a dial observes nothing else")
	}
	require.True(t, lease.Expired())
	require.ErrorIs(t, lease.Context().Err(), context.Canceled)
}

// Close must reach a blocked recovery too, and nothing may act on the resource afterwards.
func TestLeaseIsCancelledByClose(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	lease, granted := registration.BeginRebind(adapter.RebindHandshakeGiveUp)
	require.True(t, granted)
	require.NoError(t, coordinator.Close())

	select {
	case <-lease.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("Close must cancel an in-flight recovery")
	}
	require.True(t, lease.Expired())
	_, granted = registration.BeginRebind(adapter.RebindManual)
	require.False(t, granted, "a closed registration grants nothing")
}

// Removal (the scope cleanup) must cancel as well, so a torn-down resource is never acted on.
func TestLeaseIsCancelledByRemoval(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	registration.SetRecoveryWindow(time.Hour)

	lease, granted := registration.BeginRebind(adapter.RebindManual)
	require.True(t, granted)
	remove()

	select {
	case <-lease.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("removal must cancel an in-flight recovery")
	}
}

// Double completion is harmless, and completion after invalidation is a no-op.
func TestLeaseDoubleAndPostInvalidationCompletion(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	lease, granted := registration.BeginRebind(adapter.RebindManual)
	require.True(t, granted)
	lease.Complete()
	lease.Complete() // idempotent, must not panic or corrupt state
	require.Nil(t, registration.InflightLease())

	_, granted = registration.BeginRebind(adapter.RebindManual)
	require.False(t, granted, "the window is still consumed by the first recovery")

	// Completing the superseded lease again, after the registration has moved on, is still a no-op.
	registration.CompleteRebind()
	require.Nil(t, registration.InflightLease())
}

// Repeated generation advances must each leave the registration able to recover exactly once, and
// must never leave a stale lease owning it.
func TestLeaseRepeatedAdvancesNeverStrandTheRegistration(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()

	for generation := uint64(1); generation <= 20; generation++ {
		coordinator.Advance(generation)
		lease, granted := registration.BeginRebind(adapter.RebindHandshakeGiveUp)
		require.Truef(t, granted, "generation %d must be able to recover", generation)
		require.Equal(t, generation, lease.Generation())
		lease.Complete()
		require.Nil(t, registration.InflightLease())
	}
}

// Concurrent Schedule / Advance / Complete under the race detector.
func TestLeaseConcurrentScheduleAdvanceComplete(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Millisecond)

	var waitGroup sync.WaitGroup
	waitGroup.Add(4)
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 300; index++ {
			coordinator.Advance(uint64(index + 1))
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 300; index++ {
			if lease, granted := registration.BeginRebind(adapter.RebindHandshakeGiveUp); granted {
				lease.Complete()
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 300; index++ {
			registration.CompleteRebind()
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 300; index++ {
			_ = registration.Stale()
			_ = registration.InflightLease()
		}
	}()
	waitGroup.Wait()
	// Whatever the interleaving, the registration must not be left owning a recovery nobody can
	// complete: a stranded lease would disable recovery for the life of the resource.
	if lease := registration.InflightLease(); lease != nil {
		lease.Complete()
	}
	require.Nil(t, registration.InflightLease())
}

// The lease must not add a resident goroutine or timer.
func TestLeaseAddsNoGoroutine(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	baseline := runtimeNumGoroutine()
	for index := 0; index < 200; index++ {
		lease, granted := registration.BeginRebind(adapter.RebindManual)
		if granted {
			lease.Complete()
		}
	}
	settleGoroutines(t, baseline+4)
}

func runtimeNumGoroutine() int { return runtime.NumGoroutine() }

func settleGoroutines(t *testing.T, bound int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= bound {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine count %d did not settle to %d", runtime.NumGoroutine(), bound)
}
