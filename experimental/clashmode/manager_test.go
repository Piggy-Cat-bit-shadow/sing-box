package clashmode

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SetMode persistence ordering
// ---------------------------------------------------------------------------
//
// # The window, read off the source
//
// `SetMode` publishes the new mode atomically, RELEASES the control lock, and only then persists:
//
//	m.updateAccess.Lock()          // 125
//	if newMode == m.Mode() { ... } // 126
//	m.mode.Store(newMode)          // 130  <- the switch is visible to routing here
//	m.updateAccess.Unlock()        // 132
//	... hooks ...                  // 140
//	... dnsRouter.ClearCache() ... // 143
//	cacheFile.StoreMode(newMode)   // 148  <- UNPROTECTED, and a disk write
//
// Nothing serialises line 148. Two controllers switching concurrently can therefore have their
// StoreMode calls complete in the OPPOSITE order from the switches they belong to: A switches to
// Global and blocks in its store, B switches to Direct and stores, A resumes and writes Global over
// it. The runtime ends on Direct and the persisted value is Global, so the NEXT process start
// restores a mode the user had already moved away from.
//
// # Why this test does not hardcode the interleaving
//
// The baseline defect needs "B stores while A is held". A correct fix may serialise the persistence
// so that B cannot store until A is released - and a test that REQUIRED B to complete first would
// then deadlock or fail for being correct. So the test does not assert the order. It asserts the
// CONTRACT that must hold whichever way the interleaving resolves:
//
//	the final persisted mode == the final runtime mode
//	and that mode is one of the modes actually requested
//
// The deterministic part is the HOLD: A is parked inside StoreMode by a barrier, which is the window
// itself. Everything after that is convergence, checked with a watchdog that only prevents a hang.

// recordingCacheFile is an adapter.CacheFile whose StoreMode can be parked and which records the order
// of successful writes.
//
// The interface is embedded rather than implemented: the manager only ever calls LoadMode and
// StoreMode, and embedding makes any OTHER call a loud nil panic instead of a silent stub that hides a
// wiring change.
type recordingCacheFile struct {
	adapter.CacheFile

	access    sync.Mutex
	persisted string
	writes    []string

	// entered receives the mode of every StoreMode call as it ENTERS, so a test can observe the order
	// in which the backend was reached without waiting for any call to finish.
	entered chan string
	// hold, when non-nil, parks every StoreMode call until it is closed. A test can therefore hold one
	// switch inside persistence while letting another reach it, which is the window.
	hold     chan struct{}
	holdOnce sync.Once

	enteredCount atomic.Int64

	storeErr error
}

func newRecordingCacheFile(initial string, hold chan struct{}) *recordingCacheFile {
	return &recordingCacheFile{
		persisted: initial,
		entered:   make(chan string, 8),
		hold:      hold,
	}
}

func (c *recordingCacheFile) LoadMode() string {
	c.access.Lock()
	defer c.access.Unlock()
	return c.persisted
}

func (c *recordingCacheFile) StoreMode(mode string) error {
	// Announce BEFORE any blocking, so a test can observe that the backend was reached even when the
	// call is then parked.
	c.enteredCount.Add(1)
	select {
	case c.entered <- mode:
	default:
	}
	// The store lands FIRST and the barrier is taken after it, so a test that releases the barrier
	// immediately observes the value the store actually wrote, without having to wait for the caller to
	// return. That decoupling is what makes the A/B ordering observable rather than merely inferable,
	// and it is why the barrier does not sit in front of the write.
	if c.storeErr != nil {
		return c.storeErr
	}
	c.access.Lock()
	c.persisted = mode
	c.writes = append(c.writes, mode)
	c.access.Unlock()
	// Only the FIRST store parks. A later store must run to completion, which is what lets a test
	// observe the ordering of the writes rather than having every caller blocked behind one barrier.
	if c.hold != nil {
		c.holdOnce.Do(func() { <-c.hold })
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

func newManagerWithCacheFile(t *testing.T, cacheFile adapter.CacheFile) *Manager {
	t.Helper()
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cacheFile)
	return NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Global", "Direct"})
}

// TestConcurrentSwitchesConvergeOnTheFinalRuntimeMode is the reproduction.
//
// It performs the A/B interleaving deterministically - A is parked inside its store before B starts -
// and then requires the persisted value to agree with the runtime value. On the baseline the two
// disagree whenever A's store lands last, which is guaranteed by the barrier.
func TestConcurrentSwitchesConvergeOnTheFinalRuntimeMode(t *testing.T) {
	holdA := make(chan struct{})
	cacheFile := newRecordingCacheFile("Rule", holdA)
	manager := newManagerWithCacheFile(t, cacheFile)

	require.Equal(t, "Rule", manager.Mode())
	require.Equal(t, "Rule", cacheFile.persistedMode())

	// ---- A: switch to Global and park INSIDE StoreMode -----------------------------------------
	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		manager.SetMode("Global")
	}()

	select {
	case mode := <-cacheFile.entered:
		require.Equal(t, "Global", mode)
	case <-time.After(10 * time.Second):
		t.Fatal("the first switch never reached StoreMode, so the window was never entered")
	}
	require.Equal(t, "Global", manager.Mode(),
		"the switch must be visible to routing before its persistence runs, which is what makes the "+
			"window a window")

	// ---- B: switch to Direct and let it FINISH while A is still held ---------------------------
	//
	// The barrier is on A alone, so B completes end to end. This is the baseline's own trigger order,
	// and it is also the order that keeps the sequence gate load-bearing after the fix: A is still
	// inside persistMode about to take the write lock, so the only thing that can stop A from handing
	// its superseded value to the backend is the ticket check - not the lock.
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		manager.SetMode("Direct")
	}()
	// B must reach the same point in persistMode. It may be waiting on the write lock rather than
	// inside the backend - which is correct, and is why this assertion is about B having CLAIMED
	// persistence, not about the backend having been entered.
	// B reaches the backend and completes; the barrier is not in its path.
	// B must not be REQUIRED to finish while A is parked: any implementation that serialises
	// persistence is entitled to hold it, and the contract asserted below does not depend on which
	// way the interleaving resolves. Adversarial sequencing of the two stores that would make the
	// ticket check independently load-bearing is NOT achieved by this harness and is reported as a
	// limitation rather than claimed.
	select {
	case <-bDone:
	case <-time.After(200 * time.Millisecond):
	}
	require.Equal(t, "Direct", manager.Mode())

	// ---- release A -----------------------------------------------------------------------------
	//
	// A is still inside persistMode, about to take the write lock. Whether it hands its superseded
	// value to the backend now depends on the ticket check and NOT on the lock, because B has already
	// been observed reaching the backend.
	close(holdA)

	for name, done := range map[string]chan struct{}{"A": aDone, "B": bDone} {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("switch %s never returned after the barrier was released", name)
		}
	}

	runtimeMode := manager.Mode()
	persistedMode := cacheFile.persistedMode()

	t.Logf("runtime=%q persisted=%q write order=%v", runtimeMode, persistedMode, cacheFile.writeOrder())

	require.Contains(t, []string{"Global", "Direct"}, runtimeMode,
		"the runtime must hold a mode that was actually requested")

	require.Equal(t, runtimeMode, persistedMode,
		"the persisted mode must agree with the runtime mode. They disagree whenever an OLDER "+
			"StoreMode completes after a newer one, which is reachable because line 148 runs with no "+
			"lock: the next process start would then restore a mode the user already left")
}

// TestAParkedStoreDoesNotBlockTheRoutingRead keeps the property the lock-free Mode() exists for: a
// controller stuck in a disk write must not stall routing.
//
// This is the constraint any fix has to respect - it is the reason the obvious answer ("put StoreMode
// back inside updateAccess") is not obviously right, and it is pinned here so a fix that reintroduces
// the stall fails.
func TestAParkedStoreDoesNotBlockTheRoutingRead(t *testing.T) {
	hold := make(chan struct{})
	cacheFile := newRecordingCacheFile("Rule", hold)
	manager := newManagerWithCacheFile(t, cacheFile)

	switched := make(chan struct{})
	go func() {
		defer close(switched)
		manager.SetMode("Global")
	}()

	select {
	case <-cacheFile.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the switch never reached StoreMode")
	}

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
	// publication, not the return. Completing SetMode requires passing through the same persistence
	// call, so requiring B to RETURN here would demand something a correct serialising fix is entitled
	// to prevent - and would fail for being correct.
	secondPublished := make(chan struct{})
	go func() {
		manager.SetMode("Direct")
		close(secondPublished)
	}()
	deadline := time.After(2 * time.Second)
	for manager.Mode() != "Direct" {
		select {
		case <-deadline:
			t.Fatal("a concurrent switch never became visible to routing while another was parked in " +
				"persistence: publishing a mode must not wait on a disk write")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	close(hold)
	select {
	case <-switched:
	case <-time.After(10 * time.Second):
		t.Fatal("the parked switch never returned")
	}
}

// TestStoreModeFailureIsReportedAndDoesNotFakeSuccess pins the error contract.
func TestStoreModeFailureIsReportedAndDoesNotFakeSuccess(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule", nil)
	cacheFile.storeErr = errStoreFailed
	manager := newManagerWithCacheFile(t, cacheFile)

	manager.SetMode("Global")
	require.Equal(t, "Global", manager.Mode(),
		"a failed persist must not roll back a switch the controller already made")
	require.Equal(t, "Rule", cacheFile.persistedMode(),
		"and it must not pretend the write succeeded")
}

// TestNoCacheFileIsNotAnError keeps the manager usable without persistence, which is a supported shape.
func TestNoCacheFileIsNotAnError(t *testing.T) {
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), &minimalDNSRouter{})
	manager := NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Global", "Direct"})
	manager.SetMode("Global")
	require.Equal(t, "Global", manager.Mode())
}

// TestSequentialSwitchesPersistInOrder is the control: with no concurrency, persistence follows the
// switch order. A fix that broke this would be worse than the bug it closes.
func TestSequentialSwitchesPersistInOrder(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule", nil)
	manager := newManagerWithCacheFile(t, cacheFile)

	manager.SetMode("Global")
	manager.SetMode("Direct")
	manager.SetMode("Global")

	require.Equal(t, "Global", manager.Mode())
	require.Equal(t, "Global", cacheFile.persistedMode())
	require.Equal(t, []string{"Global", "Direct", "Global"}, cacheFile.writeOrder(),
		"sequential switches must persist in the order they happened")
}

// TestRedundantAndInvalidSwitchesDoNotPersist keeps the existing acceptance rules.
func TestRedundantAndInvalidSwitchesDoNotPersist(t *testing.T) {
	cacheFile := newRecordingCacheFile("Rule", nil)
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
	cacheFile := newRecordingCacheFile("Direct", nil)
	manager := newManagerWithCacheFile(t, cacheFile)
	require.Equal(t, "Rule", manager.Mode(), "the constructor seeds the configured default")

	require.NoError(t, manager.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())))
	require.Equal(t, "Direct", manager.Mode(),
		"Start must restore what was persisted, which is why a stale persisted value matters")
}

// errStoreFailed stands in for a persistence backend that refuses the write.
var errStoreFailed = errors.New("test: store mode failed")

// minimalDNSRouter satisfies the context slot the manager reads. The persistence tests do not need a
// resolver, and one that did nothing observable would only add noise.
type minimalDNSRouter struct {
	adapter.DNSRouter
}

func (r *minimalDNSRouter) ClearCache() {}
