package clashmode

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SetMode persistence ordering
// ---------------------------------------------------------------------------
//
// # The two windows this file pins, both read off the source
//
// `SetMode` publishes the new mode atomically, RELEASES the control lock, and only then persists. Two
// independent defects live in that gap, and they need different evidence because a fix for one does not
// close the other.
//
// WINDOW A - the ticket is claimed after the publication.
//
//	m.updateAccess.Lock()             // publish + compare under the lock
//	m.mode.Store(newMode)
//	m.updateAccess.Unlock()
//	sequence := m.modeSequence.Add(1) // <- the claim, in the open
//	... hooks / ClearCache ...
//	m.persistMode(newMode, sequence)
//
// A switch that publishes first can be descheduled before it claims its ticket, so it claims a HIGHER
// ticket than a switch that published after it. The ordering evidence then says the older switch is the
// newer one, and the older value wins - the exact inversion the ticket exists to prevent. This window is
// closed by claiming the ticket inside the critical section that publishes the mode.
//
// WINDOW B - the write is not atomic with the check.
//
//	m.modeSequence.Load() == sequence   // checked
//	                                    // <- a newer switch claims its ticket and writes here
//	cacheFile.StoreMode(newMode)        // an OLD value reaches the backend after a NEW one
//
// Re-reading the ticket just before the call does not close this: the read and the call are still two
// steps, and a switch that is already inside the backend cannot be called back. Closing it needs a gate
// the newer switch must also take before it may write, with the ticket read from inside that gate.
//
// # Why the barrier sits BEFORE the commit
//
// `recordingCacheFile` parks its first store before it mutates anything, and says so on `entered` and
// `commits` separately. That matters: a stub that writes and THEN parks cannot show the difference,
// because the value is already on "disk" by the time the test looks. Parking in front of the mutation is
// what makes the difference between "the older call wrote" and "the older call never got to write"
// observable rather than inferable.

// recordingCacheFile is an adapter.CacheFile whose StoreMode can be parked BEFORE it commits, and which
// records both the calls it entered and the values it actually committed.
//
// The interface is embedded rather than implemented: the manager only ever calls LoadMode and StoreMode,
// and embedding makes any OTHER call a loud nil panic instead of a silent stub that hides a wiring
// change.
type recordingCacheFile struct {
	adapter.CacheFile

	access    sync.Mutex
	persisted string
	writes    []string

	// entered receives the mode of every StoreMode call as it ENTERS, so a test can observe that the
	// backend was reached without waiting for any call to finish.
	entered chan string
	// commits receives the mode of every StoreMode call that got past its pre-commit barrier, in the
	// order the values actually landed. This is the only channel that says a value reached the backend.
	commits chan string

	// parkFirst, when non-nil, parks the FIRST store that reaches the pre-commit barrier until it is
	// closed. Later stores are not parked, so a test can observe what a newer switch does while an older
	// one is held inside the backend.
	parkFirst chan struct{}
	parkOnce  sync.Once

	// storeErr, when non-nil, refuses the write without committing anything.
	storeErr error

	loadMode   string
	loadCalled atomic.Int64
}

func newRecordingCacheFile(initial string) *recordingCacheFile {
	return &recordingCacheFile{
		persisted: initial,
		entered:   make(chan string, 16),
		commits:   make(chan string, 16),
	}
}

func (c *recordingCacheFile) LoadMode() string {
	c.loadCalled.Add(1)
	c.access.Lock()
	defer c.access.Unlock()
	if c.loadMode != "" {
		return c.loadMode
	}
	return c.persisted
}

func (c *recordingCacheFile) StoreMode(mode string) error {
	// Announce that the backend was reached, before any blocking.
	select {
	case c.entered <- mode:
	default:
	}
	// The pre-commit barrier. Everything the caller does before this point is observable, and nothing it
	// asked for has happened yet: the store has not mutated a byte.
	if c.parkFirst != nil {
		c.parkOnce.Do(func() { <-c.parkFirst })
	}
	if c.storeErr != nil {
		return c.storeErr
	}
	// The commit.
	c.access.Lock()
	c.persisted = mode
	c.writes = append(c.writes, mode)
	c.access.Unlock()
	select {
	case c.commits <- mode:
	default:
	}
	return nil
}

func (c *recordingCacheFile) persistedMode() string {
	c.access.Lock()
	defer c.access.Unlock()
	return c.persisted
}

func (c *recordingCacheFile) writeOrder() []string {
	c.access.Lock()
	defer c.access.Unlock()
	out := make([]string, len(c.writes))
	copy(out, c.writes)
	return out
}

// committedModes drains the commit channel without blocking. It is what lets a test distinguish "the
// call was reached" from "the value landed", which is the difference the pre-commit barrier is for.
func (c *recordingCacheFile) committedModes() []string {
	var out []string
	for {
		select {
		case mode := <-c.commits:
			out = append(out, mode)
		default:
			return out
		}
	}
}

// clock is the watchdog for every wait in this file. It only prevents a hang; no assertion is derived
// from how long anything took.
const clock = 20 * time.Second

// subscribe returns a live update-hook subscriber plus the channel its events arrive on. The event
// channel is the observable-control-plane contract the daemon and the Clash API already rely on.
func subscribe(t *testing.T) (*observable.Subscriber[struct{}], <-chan struct{}) {
	t.Helper()
	subscriber := observable.NewSubscriber[struct{}](4)
	t.Cleanup(func() { _ = subscriber.Close() })
	events, _ := subscriber.Subscription()
	return subscriber, events
}

func (c *recordingCacheFile) setStoreErr(err error) {
	c.access.Lock()
	defer c.access.Unlock()
	c.storeErr = err
}

func newManagerWithCacheFile(t *testing.T, cacheFile adapter.CacheFile) *Manager {
	t.Helper()
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cacheFile)
	return NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Global", "Direct"})
}

// awaitEntered waits for the backend to be reached with the given mode.
func awaitEntered(t *testing.T, cacheFile *recordingCacheFile, mode string) {
	t.Helper()
	deadline := time.After(clock)
	for {
		select {
		case got := <-cacheFile.entered:
			if got == mode {
				return
			}
		case <-deadline:
			t.Fatalf("the switch to %q never reached StoreMode", mode)
		}
	}
}

// awaitDone waits for a switch goroutine, with a watchdog that only prevents a hang.
func awaitDone(t *testing.T, name string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(clock):
		t.Fatalf("switch %s never returned", name)
	}
}

// assertConverged is the contract, asserted identically by every interleaving in this file: whatever the
// runtime holds at the end is what the next process start will restore.
func assertConverged(t *testing.T, manager *Manager, cacheFile *recordingCacheFile, context string) {
	t.Helper()
	runtimeMode := manager.Mode()
	persistedMode := cacheFile.persistedMode()
	require.Contains(t, []string{"Global", "Direct"}, runtimeMode,
		"the runtime must hold a mode that was actually requested, not %q (%s)", runtimeMode, context)
	require.Equal(t, runtimeMode, persistedMode,
		"the persisted mode must agree with the runtime mode: they disagree whenever an OLDER StoreMode "+
			"commits after a newer one, and the next process start would then restore a mode the user "+
			"already left (context: %s, writes: %d)", context, len(cacheFile.writeOrder()))
}

// ---------------------------------------------------------------------------
// WINDOW B - an older write must not land after a newer one
// ---------------------------------------------------------------------------

// TestOlderStoreParkedBeforeCommitCannotOverwriteANewerSwitch is the highest-priority reproduction.
//
// Timeline, driven by channels and not by sleeps:
//
//	A: switch to Global, reach StoreMode("Global"), park BEFORE the commit
//	B: switch to Direct and publish it
//	[release A] - A may now commit
//
// The first store is parked in front of its mutation, so this is precisely "an older switch is already
// inside the backend when a newer one is accepted". On a build where the ticket check and the write are
// not one step, A's commit lands last and the persisted value is Global while the runtime is Direct.
func TestOlderStoreParkedBeforeCommitCannotOverwriteANewerSwitch(t *testing.T) {
	park := make(chan struct{})
	cacheFile := newRecordingCacheFile("Rule")
	cacheFile.parkFirst = park
	manager := newManagerWithCacheFile(t, cacheFile)

	require.Equal(t, "Rule", manager.Mode())
	require.Equal(t, "Rule", cacheFile.persistedMode())

	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		manager.SetMode("Global")
	}()
	awaitEntered(t, cacheFile, "Global")
	require.Equal(t, "Global", manager.Mode(),
		"the switch must be visible to routing before its persistence runs, which is what makes the gap "+
			"a gap")

	// B switches while A is parked inside the backend, and publishes. Its publication must not wait for
	// A's disk write - that property is pinned separately by TestAParkedStoreDoesNotBlockTheRoutingRead.
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		manager.SetMode("Direct")
	}()
	require.Eventually(t, func() bool { return manager.Mode() == "Direct" }, 5*time.Second, time.Millisecond,
		"a newer switch must become visible to routing while an older one is parked in the backend")

	// Release the parked write. Whether B has finished persisting by now is a property of the
	// implementation and not of the contract, so it is not asserted here - see the note below.
	close(park)
	awaitDone(t, "A", aDone)
	awaitDone(t, "B", bDone)

	assertConverged(t, manager, cacheFile, "older store parked before commit")
	require.Equal(t, "Direct", manager.Mode())
	require.Equal(t, "Direct", cacheFile.persistedMode())

	// The sharp form of the same statement: the backend must not be LEFT holding the superseded mode.
	// Whether the older call wrote first and was corrected, or never wrote at all, is an implementation
	// choice - the contract is about what the backend holds once everything has quiesced, and about the
	// value a following startup would restore.
	require.NotEqual(t, "Global", cacheFile.persistedMode())
}

// TestASupersededSwitchStillLeavesTheBackendOnTheAcceptedMode pins the case that the skip rule got
// wrong: the newer switch runs to completion WHILE the older one is inside the backend.
//
// Timeline:
//
//	A: switch to Global, reach StoreMode, park before the commit
//	B: switch to Direct and fully return - its own persistence sees the gate busy
//	[release A]
//
// A build that skips the stale write and relies on B to have written converges only by luck here: B's
// call was already past its own ticket check when it met the gate. The backend must end on Direct.
func TestASupersededSwitchStillLeavesTheBackendOnTheAcceptedMode(t *testing.T) {
	park := make(chan struct{})
	cacheFile := newRecordingCacheFile("Rule")
	cacheFile.parkFirst = park
	manager := newManagerWithCacheFile(t, cacheFile)

	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		manager.SetMode("Global")
	}()
	awaitEntered(t, cacheFile, "Global")

	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		manager.SetMode("Direct")
	}()

	// B publishes immediately. It is allowed to be waiting on the write gate, so only the publication is
	// required here.
	require.Eventually(t, func() bool { return manager.Mode() == "Direct" }, 5*time.Second, time.Millisecond)

	close(park)
	awaitDone(t, "A", aDone)
	awaitDone(t, "B", bDone)

	require.Equal(t, "Direct", manager.Mode())
	require.Equal(t, "Direct", cacheFile.persistedMode(),
		"after a superseded store completes, the backend must hold the mode the runtime holds")
}

// TestASupersededSwitchNeverClaimsPersistence is the control for the sequential case: with no
// concurrency, each accepted switch writes exactly once and writes its own value.
func TestASupersededSwitchNeverClaimsPersistence(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	manager := newManagerWithCacheFile(t, cacheFile)

	manager.SetMode("Direct")
	require.Equal(t, "Direct", cacheFile.persistedMode())
	require.Equal(t, []string{"Direct"}, cacheFile.writeOrder())

	manager.SetMode("Global")
	manager.SetMode("Direct")
	assertConverged(t, manager, cacheFile, "sequential switches stay ordered")
	require.Equal(t, []string{"Direct", "Global", "Direct"}, cacheFile.writeOrder(),
		"each accepted switch writes once, in switch order, with no correction passes")
}

// ---------------------------------------------------------------------------
// WINDOW A - the ticket must be claimed with the mode it numbers
// ---------------------------------------------------------------------------

// TestTheHookNeverObservesAModeWithoutItsClaim pins the ORDER of the two state changes that must be one
// step. `modeSequence` is exported to this package's tests, so the check is direct: an update hook runs
// after the critical section that publishes the mode, and by then the ticket for that publication must
// already exist.
//
// This is a sanity clamp rather than the interleaving proof - the window it describes is a scheduling
// gap, and a test that could demand the exact instant would have to instrument the critical section
// itself. The interleaving that makes the claim load-bearing is driven by channels in
// TestOlderStoreParkedBeforeCommitCannotOverwriteANewerSwitch.
func TestTheHookNeverObservesAModeWithoutItsClaim(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	manager := newManagerWithCacheFile(t, cacheFile)

	// A hook that samples the ticket for every publication it is told about.
	type observation struct {
		mode     string
		sequence uint64
	}
	observed := make(chan observation, 4)
	subscriber := observable.NewSubscriber[struct{}](4)
	t.Cleanup(func() { _ = subscriber.Close() })
	events, _ := subscriber.Subscription()
	manager.AddUpdateHook(subscriber)
	go func() {
		for range events {
			observed <- observation{mode: manager.Mode(), sequence: manager.modeSequence.Load()}
		}
	}()

	manager.SetMode("Global")
	select {
	case got := <-observed:
		require.Equal(t, "Global", got.mode)
		require.NotZero(t, got.sequence,
			"a published mode had no ticket at the moment its notification ran: the claim is trailing "+
				"the publication it is supposed to order")
	case <-time.After(clock):
		t.Fatal("the update hook never fired")
	}

	manager.SetMode("Direct")
	select {
	case got := <-observed:
		require.Equal(t, "Direct", got.mode)
		require.Greater(t, got.sequence, uint64(0))
	case <-time.After(clock):
		t.Fatal("the second update hook never fired")
	}
	assertConverged(t, manager, cacheFile, "claim ordering")
}

// TestConcurrentSwitchesConvergeOnTheFinalRuntimeMode drives two controllers that both start from a
// published state with no barrier at all, repeated, so the ordering is exercised rather than described.
//
// This is the interleaving the ticket sequence exists for. It does not assume a particular winner - it
// requires only that whoever wins the runtime also wins the backend.
func TestConcurrentSwitchesConvergeOnTheFinalRuntimeMode(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	manager := newManagerWithCacheFile(t, cacheFile)

	for round := 0; round < 200; round++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			manager.SetMode("Global")
		}()
		go func() {
			defer wg.Done()
			manager.SetMode("Direct")
		}()
		wg.Wait()
		assertConverged(t, manager, cacheFile, "concurrent pair")
	}
}

// TestThreeWaySwitchStormConverges runs the three-switch shape from the construction order with no
// barrier: A->B->C published concurrently, then the final mode must be persisted.
func TestThreeWaySwitchStormConverges(t *testing.T) {
	for round := 0; round < 200; round++ {
		cacheFile := newRecordingCacheFile("Rule")
		ctx := service.ContextWith[adapter.CacheFile](context.Background(), cacheFile)
		manager := NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Global", "Direct", "Rule"})

		var wg sync.WaitGroup
		for _, mode := range []string{"Global", "Direct", "Rule"} {
			wg.Add(1)
			go func(mode string) {
				defer wg.Done()
				manager.SetMode(mode)
			}(mode)
		}
		wg.Wait()
		require.Equal(t, manager.Mode(), cacheFile.persistedMode(),
			"round %d: the persisted mode must agree with the runtime mode", round)
	}
}

// ---------------------------------------------------------------------------
// Properties any fix must respect
// ---------------------------------------------------------------------------

// TestAParkedStoreDoesNotBlockTheRoutingRead keeps the property the lock-free Mode() exists for: a
// controller stuck in a disk write must not stall routing.
//
// This is the constraint that rules out the obvious answer ("put StoreMode back inside updateAccess"),
// and it is pinned here so a fix that reintroduces the stall fails.
func TestAParkedStoreDoesNotBlockTheRoutingRead(t *testing.T) {
	park := make(chan struct{})
	cacheFile := newRecordingCacheFile("Rule")
	cacheFile.parkFirst = park
	manager := newManagerWithCacheFile(t, cacheFile)

	switched := make(chan struct{})
	go func() {
		defer close(switched)
		manager.SetMode("Global")
	}()
	awaitEntered(t, cacheFile, "Global")

	// The store is parked. Routing must still read the mode promptly.
	readDone := make(chan string, 1)
	go func() { readDone <- manager.Mode() }()
	select {
	case mode := <-readDone:
		require.Equal(t, "Global", mode)
	case <-time.After(2 * time.Second):
		t.Fatal("Mode() blocked while a persistence call was parked: the routing path must not wait " +
			"on the control plane")
	}

	// And a second switch must still PUBLISH while the first is parked. Note what is observed: the
	// publication, not the return. Completing SetMode requires passing the same write gate, so requiring
	// B to RETURN here would demand something a correct serialising fix is entitled to prevent.
	go func() { manager.SetMode("Direct") }()
	require.Eventually(t, func() bool { return manager.Mode() == "Direct" }, 5*time.Second, time.Millisecond,
		"a concurrent switch never became visible to routing while another was parked in persistence: "+
			"publishing a mode must not wait on a disk write")

	close(park)
	awaitDone(t, "A", switched)
	assertConverged(t, manager, cacheFile, "parked store")
	require.Equal(t, "Direct", manager.Mode())
	require.Equal(t, "Direct", cacheFile.persistedMode(),
		"the parked older switch must not leave its value in the backend after a newer switch was accepted")
}

// TestStoreModeFailureDoesNotFakeSuccess pins the failure contract: a refused write must be visible as a
// divergence rather than reported as a success, and a following switch must still be able to persist.
func TestStoreModeFailureDoesNotFakeSuccess(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	cacheFile.storeErr = errStoreFailed
	manager := newManagerWithCacheFile(t, cacheFile)

	manager.SetMode("Global")
	require.Equal(t, "Global", manager.Mode(),
		"a failed persist must not roll back a switch the controller already made")
	require.Equal(t, "Rule", cacheFile.persistedMode(),
		"and it must not pretend the write succeeded")

	// The backend recovers, and the NEXT switch must persist. The value left behind by the failure is the
	// old one, which is the honest state: the disk never accepted the switch.
	cacheFile.setStoreErr(nil)
	manager.SetMode("Direct")
	require.Equal(t, "Direct", manager.Mode())
	require.Equal(t, "Direct", cacheFile.persistedMode())
}

// TestNoCacheFileIsNotAnError keeps the manager usable without persistence, which is a supported shape.
func TestNoCacheFileIsNotAnError(t *testing.T) {
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), &minimalDNSRouter{})
	manager := NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Global", "Direct"})
	manager.SetMode("Global")
	require.Equal(t, "Global", manager.Mode())
}

// TestSequentialSwitchesPersistInOrder is the control: with no concurrency, persistence follows the
// switch order and nothing is written twice or skipped. A fix that broke this would be worse than the
// bug it closes.
func TestSequentialSwitchesPersistInOrder(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	manager := newManagerWithCacheFile(t, cacheFile)

	manager.SetMode("Global")
	manager.SetMode("Direct")
	manager.SetMode("Global")

	require.Equal(t, "Global", manager.Mode())
	require.Equal(t, "Global", cacheFile.persistedMode())
	require.Equal(t, []string{"Global", "Direct", "Global"}, cacheFile.writeOrder(),
		"sequential switches must persist in the order they happened, exactly once each")
}

// TestRedundantAndInvalidSwitchesDoNotPersist keeps the existing acceptance rules.
func TestRedundantAndInvalidSwitchesDoNotPersist(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	manager := newManagerWithCacheFile(t, cacheFile)

	manager.SetMode("Rule")       // redundant
	manager.SetMode("NoSuchMode") // refused
	require.Empty(t, cacheFile.writeOrder(),
		"a redundant or invalid switch must not reach persistence")

	manager.SetMode("direct") // case-normalised
	require.Equal(t, "Direct", manager.Mode())
	require.Equal(t, []string{"Direct"}, cacheFile.writeOrder())
}

// TestStartRestoresThePersistedMode keeps the read side of the contract.
func TestStartRestoresThePersistedMode(t *testing.T) {
	cacheFile := newRecordingCacheFile("Direct")
	manager := newManagerWithCacheFile(t, cacheFile)
	require.Equal(t, "Rule", manager.Mode(), "the constructor seeds the configured default")

	require.NoError(t, manager.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())))
	require.Equal(t, "Direct", manager.Mode(),
		"Start must restore what was persisted, which is why a stale persisted value matters")
	require.Empty(t, cacheFile.writeOrder(),
		"a restore reads the backend and must not write a value it may already have been superseded on")
}

// TestRestoreRoundTripsTheFinalMode is the end-to-end statement the whole file exists for: whatever the
// runtime ends on, a following process start restores exactly that.
//
// It is the round trip rather than a single interleaving, so it holds for any implementation that keeps
// the contract and fails for any that lets an older write land after a newer one.
func TestRestoreRoundTripsTheFinalMode(t *testing.T) {
	for round := 0; round < 100; round++ {
		cacheFile := newRecordingCacheFile("Rule")
		manager := newManagerWithCacheFile(t, cacheFile)

		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			manager.SetMode("Global")
		}()
		go func() {
			defer waitGroup.Done()
			manager.SetMode("Direct")
		}()
		waitGroup.Wait()

		finalMode := manager.Mode()
		restarted := newManagerWithCacheFile(t, cacheFile)
		require.NoError(t, restarted.Start(adapter.StartStateStart,
			adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())))
		require.Equal(t, finalMode, restarted.Mode(),
			"round %d: the next process start restored a mode the user had already left", round)
	}
}

// TestStartLeavesNewerSwitchesAlone pins the restore's acceptance rule under a publication that lands
// concurrently with it: the restore may not undo a mode the controller switched to.
func TestStartLeavesNewerSwitchesAlone(t *testing.T) {
	for round := 0; round < 200; round++ {
		cacheFile := newRecordingCacheFile("Direct")
		manager := newManagerWithCacheFile(t, cacheFile)

		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			_ = manager.Start(adapter.StartStateStart,
				adapter.NewScope(context.Background(), log.NewNOPFactory().Logger()))
		}()
		go func() {
			defer waitGroup.Done()
			manager.SetMode("Global")
		}()
		waitGroup.Wait()

		// Either order is legitimate: the switch may precede the restore, in which case the restore must
		// not undo it, or follow it, in which case the switch wins by being later. What is not legitimate
		// is a runtime mode that disagrees with the backend once both have returned.
		require.Equal(t, manager.Mode(), cacheFile.persistedMode(),
			"round %d: the restore and the switch left the runtime and the backend disagreeing", round)
	}
}

// TestInvalidPersistedModeIsIgnored keeps the acceptance rule on the restore path.
func TestInvalidPersistedModeIsIgnored(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	cacheFile.loadMode = "NoSuchMode"
	manager := newManagerWithCacheFile(t, cacheFile)
	require.NoError(t, manager.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())))
	require.Equal(t, "Rule", manager.Mode())
}

// TestHookReentryDuringSwitch does not deadlock and keeps the last accepted mode persisted. The hooks run
// outside the control lock and outside the write gate precisely so that a subscriber may switch again.
func TestHookReentryDuringSwitch(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	manager := newManagerWithCacheFile(t, cacheFile)

	reentered := atomic.Bool{}
	subscriber := observable.NewSubscriber[struct{}](4)
	t.Cleanup(func() { _ = subscriber.Close() })
	events, _ := subscriber.Subscription()
	manager.AddUpdateHook(subscriber)
	go func() {
		if _, ok := <-events; ok && reentered.CompareAndSwap(false, true) {
			manager.SetMode("Direct")
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.SetMode("Global")
	}()
	awaitDone(t, "reentrant switch", done)
	require.Eventually(t, func() bool { return manager.Mode() == "Direct" }, 5*time.Second, time.Millisecond,
		"the reentrant switch never became the accepted mode")
	require.Equal(t, "Direct", cacheFile.persistedMode())
}

// TestLoggerIsOptional keeps the manager usable with no logger, which several embedders rely on.
func TestLoggerIsOptional(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cacheFile)
	manager := NewManager(ctx, nil, "Rule", []string{"Global", "Direct"})
	manager.SetMode("Global")
	require.Equal(t, "Global", manager.Mode())
	require.Equal(t, "Global", cacheFile.persistedMode())
}

// TestModeListIsCaseInsensitiveOnRestore keeps the existing restore acceptance rules.
func TestModeListIsCaseInsensitiveOnRestore(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule")
	cacheFile.loadMode = "direct"
	manager := newManagerWithCacheFile(t, cacheFile)
	require.NoError(t, manager.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())))
	require.True(t, strings.EqualFold("Direct", manager.Mode()),
		"a persisted mode that differs only in case is accepted, as the switch path accepts it")
}

// errStoreFailed stands in for a persistence backend that refuses the write.
var errStoreFailed = errors.New("test: store mode failed")

// minimalDNSRouter satisfies the context slot the manager reads. The persistence tests do not need a
// resolver, and one that did nothing observable would only add noise.
type minimalDNSRouter struct {
	adapter.DNSRouter
}

func (r *minimalDNSRouter) ClearCache() {}
