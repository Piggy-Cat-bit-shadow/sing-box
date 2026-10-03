package route

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/winpowrprof"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// The reset entry-point matrix, exercised rather than read.
//
// # The entries and what each one holds
//
//	resetNetworkLocked      callers MUST hold resetRunAccess
//	ResetNetwork            takes resetRunAccess itself (control plane, ReleaseMemory, power suspend)
//	updateInterface         holds the lock, calls the inner function once for all its reasons
//	power resume goroutine  takes the lock in the goroutine, then calls the inner function
//	postUpdateNetworkEnv    takes no lock, calls the exported form
//
// Each of these was previously verified by reading it. Two of them - the Windows power path and
// ReleaseMemory - were explicitly listed as untested residual risk, and a self-deadlock in exactly
// this area was found by running the suite rather than by reasoning about it. So the matrix is
// asserted here.
//
// # What these tests do NOT claim
//
// They do not exercise the real Windows or PowerManagement APIs; the host is not Windows. They
// exercise the reset decision each entry point makes, which is where the locking lives and where a
// deadlock would be.

// newPowerHarness builds a started manager able to receive power events.
func newPowerHarness(t *testing.T) *NetworkManager {
	t.Helper()
	manager := &NetworkManager{
		router:   newCountingRouter(),
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()
	manager.pauseManager = &noopPauseManager{}
	return manager
}

// TestWindowsPowerSuspendAndResumeDoNotDeadlock drives the power path end to end.
//
// Suspend resets through the exported form on the calling goroutine; resume dispatches a goroutine
// that takes the lock itself and then calls the inner form. Those are opposite lock disciplines, so
// getting either wrong deadlocks - which is exactly the failure mode that is invisible to a reader.
func TestWindowsPowerSuspendAndResumeDoNotDeadlock(t *testing.T) {
	manager := newPowerHarness(t)
	router := manager.router.(*countingRouter)
	generationBefore := manager.NetworkResetGeneration()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A suspend resets immediately.
		manager.notifyWindowsPowerEvent(winpowrprof.EVENT_SUSPEND)
		// A resume wakes the device and resets from a fresh goroutine.
		manager.notifyWindowsPowerEvent(winpowrprof.EVENT_RESUME)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the Windows power path did not complete; suspend uses the exported reset and " +
			"resume uses the inner one under a freshly taken lock, so a mismatch between them is a " +
			"deadlock rather than a compile error")
	}

	// The resume goroutine runs asynchronously; wait for it to take the lock and finish rather than
	// sleeping on a guess.
	waitForResets(t, router, 2)
	require.GreaterOrEqual(t, manager.NetworkResetGeneration(), generationBefore+2,
		"suspend and resume are two genuinely independent events, so each performs its own reset")
}

// TestWindowsPowerResumeWithoutSuspendIsIgnored covers the guard: a resume with the device not paused
// and not marked automatic must do nothing.
func TestWindowsPowerResumeWithoutSuspendIsIgnored(t *testing.T) {
	manager := newPowerHarness(t)
	router := manager.router.(*countingRouter)
	before := dnsResetCount(router)

	manager.notifyWindowsPowerEvent(winpowrprof.EVENT_RESUME)

	require.Equal(t, before, dnsResetCount(router),
		"a resume while the device was never paused is not a network event and must not reset")
}

// TestReleaseMemoryResetsWithoutDeadlock drives the exported entry used by the memory-pressure path.
func TestReleaseMemoryResetsWithoutDeadlock(t *testing.T) {
	manager := newPowerHarness(t)
	router := manager.router.(*countingRouter)
	before := dnsResetCount(router)

	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.ReleaseMemory(context.Background())
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ReleaseMemory did not complete; it calls the exported reset without holding the " +
			"lock, so taking the lock inside it must not self-deadlock")
	}
	require.Equal(t, before+1, dnsResetCount(router),
		"ReleaseMemory performs exactly one reset")
}

// TestAllResetEntriesShareOneSerialisation is the serialisation invariant across the whole matrix.
//
// Resets dispatched from every entry at once must never overlap: the generation would then describe
// a state no single reset produced.
func TestAllResetEntriesShareOneSerialisation(t *testing.T) {
	manager := newPowerHarness(t)
	router := manager.router.(*countingRouter)

	const perEntry = 4
	var waitGroup sync.WaitGroup
	start := make(chan struct{})

	// The exported form, as the control plane and ReleaseMemory use it.
	for i := 0; i < perEntry; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			manager.ResetNetwork(manager.startedCtx)
		}()
	}
	// The inner form, as updateInterface and the power goroutine use it.
	for i := 0; i < perEntry; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			manager.resetRunAccess.Lock()
			manager.resetNetworkLocked(manager.startedCtx)
			manager.resetRunAccess.Unlock()
		}()
	}
	// The environment entry, which takes the lock itself.
	for i := 0; i < perEntry; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			manager.setWIFIStateForTest("SSID-" + string(rune('a'+i)))
			manager.postUpdateNetworkEnvironment()
		}()
	}

	close(start)

	finished := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("reset entries from different lock disciplines did not all finish; one of them " +
			"waits for a lock another holds")
	}

	require.EqualValues(t, 0, router.maxSeen.Load()-1,
		"two resets overlapped: CloseAll, the InterfaceUpdated callbacks and the DNS reset would "+
			"then interleave in an order belonging to neither run")
}

// waitForResets blocks until the router has observed at least n resets, or fails.
//
// The power resume path dispatches a goroutine, so the test has to join on the work. It joins on the
// router's own signal - published by the reset as it runs - rather than polling the count, so the
// wait is ordered by the reset instead of by how long the test guessed it would take. The timeout is
// a watchdog against a hang, not the synchroniser.
func waitForResets(t *testing.T, router *countingRouter, n int) {
	t.Helper()
	if !router.waitForCount(n, 10*time.Second) {
		t.Fatalf("expected at least %d reset(s), saw %d", n, router.count())
	}
}

// setWIFIStateForTest publishes a Wi-Fi SSID so the environment fingerprint moves.
//
// It is a test-only setter for the state the monitor would normally report; the production path reads
// it through ReadWIFIState, which a fixture does not have.
func (r *NetworkManager) setWIFIStateForTest(ssid string) {
	r.stateAccess.Lock()
	r.wifiState = adapter.WIFIState{SSID: ssid}
	r.stateAccess.Unlock()
}

// noopPauseManager satisfies the pause manager the power path calls into.
type noopPauseManager struct {
	paused bool
}

func (m *noopPauseManager) DevicePause()          { m.paused = true }
func (m *noopPauseManager) DeviceWake()           { m.paused = false }
func (m *noopPauseManager) NetworkPause()         {}
func (m *noopPauseManager) NetworkWake()          {}
func (m *noopPauseManager) IsDevicePaused() bool  { return m.paused }
func (m *noopPauseManager) IsNetworkPaused() bool { return false }
func (m *noopPauseManager) IsPaused() bool        { return m.paused }
func (m *noopPauseManager) WaitActive()           {}
func (m *noopPauseManager) RegisterCallback(pause.Callback) *list.Element[pause.Callback] {
	return nil
}
func (m *noopPauseManager) UnregisterCallback(*list.Element[pause.Callback]) {}

var _ pause.Manager = (*noopPauseManager)(nil)
