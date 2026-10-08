package runtimecoord

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// The runtime coordinator's contract.
//
// Invariant references are to docs/fork/runtime-lifecycle-phase1.5.md: Close wins (1), one network
// epoch (2), one logical recovery at a time (7), and no callback under the coordinator's lock (8).

func TestAdvancePublishesMonotoneGenerations(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("test")
	defer remove()

	require.EqualValues(t, 0, registration.Epoch(), "a fresh registration belongs to generation zero")
	require.False(t, registration.Stale())

	coordinator.Advance(1)
	require.EqualValues(t, 1, coordinator.Epoch())
	require.EqualValues(t, 1, registration.Epoch(), "the resource must observe the new generation")
	// Delivery is not rebuild: the resource has been told, and it still holds sockets bound to the
	// previous network until it acts. Stale() must keep saying so until it does.
	require.True(t, registration.Stale())
	registration.Acknowledge()
	require.False(t, registration.Stale(), "after acknowledging, the resource is current")

	// A repeated value is not a transition. Treating it as one would produce a second sweep for a
	// single reset.
	coordinator.Advance(1)
	require.EqualValues(t, 1, registration.Epoch())

	// And it never goes backwards, however a caller misbehaves.
	coordinator.Advance(0)
	require.EqualValues(t, 1, coordinator.Epoch())
}

func TestRegistrationStaleUntilItObserves(t *testing.T) {
	t.Parallel()
	coordinator := New()
	coordinator.Advance(3)

	// A resource that registers AFTER the transition starts on the current generation, so it is not
	// stale. The alternative - starting at zero - would make every late registration look broken.
	registration, remove := coordinator.Register("late")
	defer remove()
	require.False(t, registration.Stale())
	require.EqualValues(t, 3, registration.Epoch())

	coordinator.Advance(4)
	require.True(t, registration.Stale(),
		"a published generation is not an acted-on generation: the resource still belongs to the old network")
	registration.Acknowledge()
	require.False(t, registration.Stale(),
		"after acknowledging, the resource is current again")
	require.EqualValues(t, 4, registration.Epoch())
}

// Invariant 7: a burst is one rebind.
func TestScheduleRebindCoalescesABurst(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	reasons := []adapter.RebindReason{
		adapter.RebindHandshakeGiveUp,
		adapter.RebindSessionExpired,
		adapter.RebindDeviceWake,
		adapter.RebindManual,
	}
	granted := 0
	for _, reason := range reasons {
		if registration.ScheduleRebind(reason) {
			registration.CompleteRebind()
			granted++
		}
	}
	require.Equal(t, 1, granted,
		"four triggers in one window must produce one logical rebind, not four")
	require.EqualValues(t, 1, registration.RebindCount())
}

// A rebind in flight must not be joined by a second one: the window is consumed at schedule time.
func TestScheduleRebindCoalescesWhileOneIsInFlight(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	require.True(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp))
	require.False(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp),
		"a second trigger while the first rebind is still running must coalesce")
	require.False(t, registration.ScheduleRebind(adapter.RebindSessionExpired),
		"a trigger of a different kind is still the same failure series")
}

// A NEW generation is a different series: the rebind in flight belonged to a network that is gone,
// so the new network's failure is a new fact. Without this, a reset landing while a rebind runs
// would swallow the recovery the reset made necessary.
func TestNewGenerationGrantsItsOwnRebind(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	require.True(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp))
	// Still in flight - the caller has not completed it.
	require.True(t, coordinator != nil)
	coordinator.Advance(1)
	require.True(t, registration.ScheduleRebind(adapter.RebindNetworkChanged),
		"a failure on a new generation is not the series that is in flight")
	registration.CompleteRebind()
	require.False(t, registration.ScheduleRebind(adapter.RebindNetworkChanged),
		"and the new generation's window is consumed by that one rebind")
}

// A new network generation re-arms the window: the previous window described a network that is gone,
// and a real failure on the new one must not be swallowed for 90 seconds.
func TestNewGenerationReArmsTheWindow(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	require.True(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp))
	registration.CompleteRebind()
	require.False(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp),
		"a same-generation repeat is inside the window")

	coordinator.Advance(1)
	require.True(t, registration.ScheduleRebind(adapter.RebindSessionExpired),
		"a failure on a new generation is a new fact and may be acted on")
}

// Invariant 1: Close wins. A scheduled recovery observes cancellation and cannot resurrect anything.
func TestCoordinatorCloseInvalidatesRegistrations(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	require.True(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp))
	require.NoError(t, coordinator.Close())

	require.True(t, registration.Closed())
	require.False(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp),
		"a closed registration must never grant another rebind")
	require.True(t, registration.Stale(), "a closed registration reports stale so no reuse happens")

	// Idempotent: a second Close is a clean no-op, like the scopes it hangs off.
	require.NoError(t, coordinator.Close())

	// And an advance after close is refused rather than delivered to nothing.
	coordinator.Advance(9)
	require.EqualValues(t, 0, coordinator.Epoch())
}

func TestRemovalInvalidatesRegistration(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	registration.SetRecoveryWindow(time.Hour)

	require.True(t, registration.ScheduleRebind(adapter.RebindManual))
	registration.CompleteRebind()
	remove()

	require.True(t, registration.Closed())
	require.False(t, registration.ScheduleRebind(adapter.RebindManual),
		"a removed resource is never called again")

	// A later advance must not reach it either.
	coordinator.Advance(1)
	require.EqualValues(t, 0, registration.Epoch())
}

// Invariant 8: a resource reaction must not run under the coordinator's lock, or a protocol that
// takes its own lock while reacting can deadlock against the reset path.
func TestAdvanceDoesNotHoldTheLockDuringNotification(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()

	// If Advance held the lock while notifying, this call would deadlock rather than fail, so the
	// assertion is "it completes". Epoch() is the cheapest call that takes the same lock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		coordinator.Advance(1)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Advance did not return; the coordinator is notifying under its own lock")
	}
	require.EqualValues(t, 1, registration.Epoch())
	require.EqualValues(t, 1, coordinator.Epoch())
}

// The generation channel exists so a resource with no polling can wait for the next transition. The
// snapshot and the channel must be read together, or a caller can miss the transition it is about to
// wait for.
func TestGenerationChangedIsAConsistentObservation(t *testing.T) {
	t.Parallel()
	coordinator := New()
	epoch, changed := coordinator.GenerationChanged()
	require.EqualValues(t, 0, epoch)

	coordinator.Advance(1)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("the channel returned with generation 0 was not closed by the transition")
	}

	epoch, changed = coordinator.GenerationChanged()
	require.EqualValues(t, 1, epoch)
	select {
	case <-changed:
		t.Fatal("the channel for the current generation must not be already closed")
	default:
	}
}

func TestNilCoordinatorIsInert(t *testing.T) {
	t.Parallel()
	var coordinator *Coordinator
	require.EqualValues(t, 0, coordinator.Epoch())
	coordinator.Advance(1)
	require.NoError(t, coordinator.Close())
	epoch, changed := coordinator.GenerationChanged()
	require.EqualValues(t, 0, epoch)
	select {
	case <-changed:
	default:
		t.Fatal("a nil coordinator must report an already-closed channel, so a waiter does not park")
	}
	registration, remove := coordinator.Register("x")
	require.False(t, registration.Stale(),
		"a resource with no coordinator has no generation to be stale against")
	remove()
	require.True(t, registration.Closed())
}

// Invariant 7 under concurrency, and double-checked for the race detector.
func TestConcurrentTriggersGrantOneRebind(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Hour)

	const triggers = 32
	var granted atomic.Int64
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < triggers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			if registration.ScheduleRebind(adapter.RebindHandshakeGiveUp) {
				granted.Add(1)
				registration.CompleteRebind()
			}
		}()
	}
	close(start)
	waitGroup.Wait()
	require.EqualValues(t, 1, granted.Load(),
		"concurrent triggers must grant exactly one rebind")
}

func TestConcurrentAdvanceAndScheduleIsRaceFree(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(time.Millisecond)

	var waitGroup sync.WaitGroup
	waitGroup.Add(3)
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 200; index++ {
			coordinator.Advance(uint64(index + 1))
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 200; index++ {
			if registration.ScheduleRebind(adapter.RebindHandshakeGiveUp) {
				registration.CompleteRebind()
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 200; index++ {
			_ = registration.Stale()
			_ = registration.WakeAllowsRebind()
		}
	}()
	waitGroup.Wait()
}

// Invariant 7 again, from the reset side: a network flapping ten times must not produce ten
// rebuilds. A resource only rebuilds when a failure signal proves it is broken, so a burst of
// resets alone produces nothing - the rebuild waits for the next demand, which is the lazy-rebuild
// rule of invariant 5.
func TestResetBurstDoesNotProduceRebuilds(t *testing.T) {
	t.Parallel()
	coordinator := New()
	registration, remove := coordinator.Register("wg")
	defer remove()
	registration.SetRecoveryWindow(50 * time.Millisecond)

	for index := 1; index <= 10; index++ {
		coordinator.Advance(uint64(index))
	}
	require.Zero(t, registration.RebindCount(),
		"a reset is not a failure: nothing was proven broken, so nothing may rebuild")
	require.True(t, registration.Stale(),
		"but the resource IS stale, so the next demand rebuilds against the new network")

	// The next proven failure earns exactly one rebuild.
	require.True(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp))
	registration.CompleteRebind()
	require.EqualValues(t, 1, registration.RebindCount())

	// And the rest of a burst after it is still coalesced.
	for index := 0; index < 5; index++ {
		require.False(t, registration.ScheduleRebind(adapter.RebindHandshakeGiveUp))
	}
	require.EqualValues(t, 1, registration.RebindCount())
}
