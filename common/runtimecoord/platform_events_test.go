package runtimecoord

import (
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// # What this file is
//
// The policy in platform_events.go decides what a platform fact means; this file drives it with an
// in-process model of the core it acts on. There is no device, no network and no clock involved, so
// every behaviour the Android work must guarantee - screen-off costs nothing, a trim cannot dial, a
// background round cannot wake a suspended endpoint, a Close wins over a late callback - is provable
// here rather than on a phone.
//
// # Why the model is a model and not a mock
//
// A mock that records "TrimMemory was called" proves only that the policy called a method. The
// counters that matter are the ones the PRODUCT observes: how many dials happened, how many sessions
// were reconnected, whether a suspended endpoint woke. So the fake implements the same semantics the
// real actors have - a progressive trim closes reusable pools and cannot dial, a reset-shaped release
// retires every transport, a background round fails against a suspended endpoint - and the assertions
// are about those consequences.

// fakePlatform is the in-process core the policy acts on.
//
// Every method is safe under the policy's lock discipline (the policy never calls a target while
// holding its own lock), and the mutex here is only so the stress test can read counters from the
// test goroutine while callbacks run.
type fakePlatform struct {
	access sync.Mutex

	// idlePools is reusable state that a progressive trim may drop.
	idlePools int
	// liveSessions is resource carrying user traffic. A trim and a pause must never touch it; a
	// reset-shaped release retires it, which is why that action costs reconnects.
	liveSessions int
	// suspended is the count of on-demand endpoints that the idle policy released.
	suspended int
	// devicePaused mirrors the core's pause state, so a demand path can tell whether the resource it
	// wants was released.
	devicePaused bool

	dials      int
	reconnects int
	urlTests   int
	trims      int
	releases   int
	pauses     int
	wakes      int
}

func (f *fakePlatform) TrimMemory(level TrimLevel) {
	f.access.Lock()
	defer f.access.Unlock()
	f.trims++
	f.idlePools = 0
	// Deliberately nothing else. A trim that dialled, resumed a suspended endpoint or touched a live
	// session would be a reconnect trigger wearing a memory-management name.
}

func (f *fakePlatform) ReleaseMemory(level TrimLevel) {
	f.access.Lock()
	defer f.access.Unlock()
	f.releases++
	f.idlePools = 0
	// The reset-shaped pass retires every transport, so each live session is re-dialled. That is the
	// cost that makes this action only justifiable against pressure that is about to end the process.
	f.reconnects += f.liveSessions
	f.dials += f.liveSessions
}

func (f *fakePlatform) DevicePause() {
	f.access.Lock()
	defer f.access.Unlock()
	f.pauses++
	f.devicePaused = true
	// Idle ON-DEMAND endpoints are eligible for suspension; a flow that is carrying traffic is not.
	// The model makes that explicit: liveSessions is untouched.
	if f.idlePools > 0 {
		f.suspended += f.idlePools
		f.idlePools = 0
	}
}

func (f *fakePlatform) DeviceWake() {
	f.access.Lock()
	defer f.access.Unlock()
	f.wakes++
	f.devicePaused = false
	// Marking eligible is not dialling: nothing is re-dialled here. The model's suspended endpoints
	// stay suspended until a real demand, which is the "rebuild lazily" rule.
}

// demand is a real flow: it wakes a suspended endpoint, and only that one.
func (f *fakePlatform) demand() {
	f.access.Lock()
	defer f.access.Unlock()
	if f.suspended > 0 {
		f.suspended--
		f.dials++
		return
	}
	f.dials++
}

// backgroundRound is a periodic health check. Against a suspended endpoint it must fail without
// waking it - the same contract adapter.ErrResourceSuspended gives the real health layer.
func (f *fakePlatform) backgroundRound() (measured bool) {
	f.access.Lock()
	defer f.access.Unlock()
	f.urlTests++
	if f.suspended > 0 {
		return false
	}
	f.dials++
	return true
}

// manualRound is a measurement a person asked for. It is demand in the product sense and may wake a
// suspended resource.
func (f *fakePlatform) manualRound() {
	f.access.Lock()
	defer f.access.Unlock()
	f.urlTests++
	if f.suspended > 0 {
		f.suspended--
	}
	f.dials++
}

// openPool adds reusable state for a later trim to drop.
func (f *fakePlatform) openPool(count int) {
	f.access.Lock()
	defer f.access.Unlock()
	f.idlePools += count
}

// platformSnapshot is a lock-free copy of the counters, so a test can compare two observations
// with require.Equal without copying the mutex (which vet rightly refuses).
type platformSnapshot struct {
	idlePools    int
	liveSessions int
	suspended    int
	devicePaused bool
	dials        int
	reconnects   int
	urlTests     int
	trims        int
	releases     int
	pauses       int
	wakes        int
}

func (f *fakePlatform) snapshot() platformSnapshot {
	f.access.Lock()
	defer f.access.Unlock()
	return platformSnapshot{
		idlePools:    f.idlePools,
		liveSessions: f.liveSessions,
		suspended:    f.suspended,
		devicePaused: f.devicePaused,
		dials:        f.dials,
		reconnects:   f.reconnects,
		urlTests:     f.urlTests,
		trims:        f.trims,
		releases:     f.releases,
		pauses:       f.pauses,
		wakes:        f.wakes,
	}
}

func (f *fakePlatform) counts() (dials, reconnects, urlTests, pools int) {
	s := f.snapshot()
	return s.dials, s.reconnects, s.urlTests, s.idlePools + s.suspended
}

// TestTrimLevelClassifiesOnlyGenuinePressureAndLifecycleFacts is the mapping table as a test.
//
// It is written as a table rather than as prose because the mapping is the deliverable: a reader must
// be able to see, for each level, whether it trims, releases or is ignored, and a new level added to
// the platform must be a visible new row.
func TestTrimLevelClassifiesOnlyGenuinePressureAndLifecycleFacts(t *testing.T) {
	for _, testCase := range []struct {
		level  TrimLevel
		action TrimAction
		why    string
	}{
		{TrimRunningModerate, TrimIgnore, "advisory: the system is low and this process is not a kill candidate"},
		{TrimRunningLow, TrimProgressive, "the process is asked to release; only reusable state goes"},
		{TrimRunningCritical, TrimRelease, "documented as kill-if-not-released for this process"},
		{TrimUIHidden, TrimIgnore, "a lifecycle fact, not a memory reading"},
		{TrimBackground, TrimProgressive, "background LRU pressure"},
		{TrimModerate, TrimProgressive, "background LRU pressure"},
		{TrimComplete, TrimProgressive, "about to be killed anyway; a reset would shed nothing worth keeping"},
		{TrimLevelUnspecified, TrimIgnore, "no trim was reported"},
		{TrimLevel(999), TrimIgnore, "an unknown level is not a fact we can act on"},
	} {
		require.Equal(t, testCase.action, testCase.level.Action(), "level %d: %s", testCase.level, testCase.why)
	}
}

// TestPlatformTrimClosesPoolsWithoutDialling is the first invariant.
func TestPlatformTrimClosesPoolsWithoutDialling(t *testing.T) {
	platform := &fakePlatform{liveSessions: 3}
	policy := NewPlatformEvents(platform)
	platform.openPool(4)

	dialsBefore, _, _, poolsBefore := platform.counts()
	policy.MemoryTrim(TrimRunningLow)

	dialsAfter, reconnectsAfter, _, poolsAfter := platform.counts()
	require.Less(t, poolsAfter, poolsBefore, "a trim must reduce the reusable resource count")
	require.Equal(t, dialsBefore, dialsAfter, "a trim must never dial")
	require.Zero(t, reconnectsAfter, "a trim must never reconnect a live session")
	require.Equal(t, 3, platform.snapshot().liveSessions, "a trim must not touch a flow that is carrying traffic")
}

// TestPlatformCriticalTrimIsTheOnlyRelease proves the severe row actually reaches the reset-shaped
// action, and that it is coalesced so a repeated system-state reading cannot become a reconnect storm.
func TestPlatformCriticalTrimIsTheOnlyRelease(t *testing.T) {
	platform := &fakePlatform{liveSessions: 2}
	policy := NewPlatformEvents(platform)

	policy.MemoryTrim(TrimRunningCritical)
	require.EqualValues(t, 1, policy.Stats().Releases)
	require.Equal(t, 2, platform.snapshot().reconnects, "the reset-shaped pass retires the live sessions")

	// RUNNING_CRITICAL is a state the system stays in, not an instant: the platform repeats it. Each
	// repeat must not advance the network generation again.
	for range 10 {
		policy.MemoryTrim(TrimRunningCritical)
	}
	require.EqualValues(t, 1, policy.Stats().Releases, "one emergency is one release")
	require.EqualValues(t, 10, policy.Stats().Coalesced)
	require.Equal(t, 2, platform.snapshot().reconnects, "a repeated reading must not reconnect again")
}

// TestPlatformRepeatedProgressiveTrimCoalesces: identical repeats are one logical event, and a
// different (escalating or de-escalating) level is a new fact.
func TestPlatformRepeatedProgressiveTrimCoalesces(t *testing.T) {
	policy := NewPlatformEvents(&fakePlatform{})
	policy.MemoryTrim(TrimRunningLow)
	policy.MemoryTrim(TrimRunningLow)
	require.EqualValues(t, 1, policy.Stats().Trims)
	require.EqualValues(t, 1, policy.Stats().Coalesced)

	policy.MemoryTrim(TrimBackground)
	require.EqualValues(t, 2, policy.Stats().Trims, "a different level is a new fact, not a repeat")
}

// TestPlatformLifecycleScenario is the Task 7 scenario end to end:
//
//	foreground -> traffic -> screen off -> background -> memory trim -> network change -> screen on -> traffic
func TestPlatformLifecycleScenario(t *testing.T) {
	platform := &fakePlatform{liveSessions: 1}
	policy := NewPlatformEvents(platform)

	// Foreground: the user is in the app.
	policy.SetScreenOn(true)
	policy.SetAppForeground(true)
	require.EqualValues(t, 0, policy.Stats().Pauses)

	// Real traffic starts a flow through a suspended on-demand endpoint.
	platform.openPool(3)
	platform.demand()

	// Screen off, then the app is backgrounded.
	policy.SetScreenOn(false)
	policy.SetAppForeground(false)
	require.EqualValues(t, 1, policy.Stats().Pauses)
	platform.openPool(3)

	// The platform reports memory pressure while everything is idle.
	policy.MemoryTrim(TrimRunningLow)

	// A network change is the network manager's business; the policy has no part in it, and the point
	// of the step is that no lifecycle fact is fabricated by it.
	platform.openPool(2)

	// Screen on, then the app comes forward: eligible again, lazily.
	policy.SetScreenOn(true)
	policy.SetAppForeground(true)

	// Real traffic at the end.
	platform.demand()

	dials, reconnects, urlTests, pools := platform.counts()
	t.Logf("scenario counters: dials=%d reconnects=%d urlTests=%d pools=%d", dials, reconnects, urlTests, pools)
	require.Zero(t, reconnects, "no step in this scenario may reconnect a session")
	require.Zero(t, urlTests, "no health round ran")
	require.Equal(t, 1, platform.snapshot().liveSessions, "the flow carrying traffic survived the whole scenario")
	require.Equal(t, 1, platform.snapshot().trims, "the trim ran exactly once")
}

// TestPlatformScreenOffAndOnIsNearZeroActivity is the "screen off + no traffic -> near-zero activity"
// assertion, with the activity being counted rather than described.
func TestPlatformScreenOffAndOnIsNearZeroActivity(t *testing.T) {
	platform := &fakePlatform{liveSessions: 1}
	policy := NewPlatformEvents(platform)
	policy.SetScreenOn(true)
	policy.SetAppForeground(true)

	dialsBefore, reconnectsBefore, urlTestsBefore, _ := platform.counts()

	policy.SetScreenOn(false)
	// Repeated screen-off facts are coalesced: an Android receiver can deliver the same broadcast
	// twice, and the second must not be a second pause.
	policy.SetScreenOn(false)
	policy.SetScreenOn(false)

	midDials, midReconnects, midURLTests, _ := platform.counts()
	require.Equal(t, dialsBefore, midDials)
	require.Equal(t, reconnectsBefore, midReconnects)
	require.Equal(t, urlTestsBefore, midURLTests)
	require.EqualValues(t, 1, policy.Stats().Pauses, "three screen-off facts are one pause")

	policy.SetScreenOn(true)
	policy.SetAppForeground(true)
	policy.SetScreenOn(true)

	_, _, _, _ = platform.counts()
	require.Zero(t, platform.snapshot().dials-dialsBefore,
		"a screen off/on cycle with no traffic must not dial: %d", platform.snapshot().dials)
	require.Zero(t, platform.snapshot().reconnects-reconnectsBefore)
	require.EqualValues(t, 1, policy.Stats().Wakes, "screen-on may nudge once, and only once")
}

// TestPlatformBackgroundRoundCannotWakeASuspendedEndpoint is the Phase 1.5 marker held from the
// lifecycle side: an automatic round under a screen-off/background policy still cannot wake.
func TestPlatformBackgroundRoundCannotWakeASuspendedEndpoint(t *testing.T) {
	platform := &fakePlatform{}
	policy := NewPlatformEvents(platform)
	policy.SetScreenOn(true)
	policy.SetAppForeground(true)
	platform.openPool(2)
	policy.SetScreenOn(false)
	policy.SetAppForeground(false)
	require.Equal(t, 2, platform.snapshot().suspended)

	dialsBefore, _, _, _ := platform.counts()
	// The real chain marks the round with adapter.ContextWithBackgroundProbe; the lifecycle state
	// must not be what decides it, and conversely must not accidentally make it demand.
	require.False(t, platform.backgroundRound(), "a background round must report 'not measured'")
	require.False(t, platform.backgroundRound())
	dialsAfter, _, urlTests, _ := platform.counts()
	require.Equal(t, dialsBefore, dialsAfter, "a background round against a suspended endpoint must not wake it")
	require.Equal(t, 2, urlTests)

	// A measurement a person asked for is demand, and may wake it - once.
	platform.manualRound()
	require.Equal(t, 1, platform.snapshot().suspended, "a manual round wakes the resource it measures")
	dialsManual, _, _, _ := platform.counts()
	require.Equal(t, dialsAfter+1, dialsManual)
}

// TestPlatformScreenOnDefersTheWakeUntilTheAppIsInFront proves the two axes are not one boolean.
//
// Screen on with the app still in the background is the normal state of a VPN - the user is in
// another app - and it must not run a rebind nudge on behalf of an app nobody is looking at. The
// nudge is deferred, not dropped, and is released once when the user comes back.
func TestPlatformScreenOnDefersTheWakeUntilTheAppIsInFront(t *testing.T) {
	platform := &fakePlatform{}
	policy := NewPlatformEvents(platform)
	policy.SetScreenOn(true)
	policy.SetAppForeground(true)
	policy.SetScreenOn(false)
	policy.SetAppForeground(false)
	require.EqualValues(t, 1, policy.Stats().Pauses)

	// Screen back on, app still backgrounded.
	policy.SetScreenOn(true)
	require.EqualValues(t, 0, policy.Stats().Wakes, "no nudge for an app that is not in front")
	require.False(t, policy.AppForeground())

	// The app comes forward: exactly one deferred nudge.
	policy.SetAppForeground(true)
	require.EqualValues(t, 1, policy.Stats().Wakes)
	policy.SetAppForeground(true)
	policy.SetScreenOn(true)
	require.EqualValues(t, 1, policy.Stats().Wakes, "a repeated foreground fact is not a second nudge")

	// And with the app already in front, a later screen-on is immediate.
	policy.SetScreenOn(false)
	policy.SetScreenOn(true)
	require.EqualValues(t, 2, policy.Stats().Wakes)
}

// TestPlatformExplicitDeviceWakeIsAuthoritative: an unlock event is the LX 041 trigger, so it forces
// the nudge even when the app axis has not caught up.
func TestPlatformExplicitDeviceWakeIsAuthoritative(t *testing.T) {
	platform := &fakePlatform{}
	policy := NewPlatformEvents(platform)
	policy.SetScreenOn(false)

	policy.DeviceWake()
	policy.DeviceWake()
	require.EqualValues(t, 1, platform.snapshot().wakes, "the nudge runs for the wake, not for every repeated fact")
	require.EqualValues(t, 1, policy.Stats().Coalesced)
	on, known := policy.ScreenOn()
	require.True(t, on)
	require.True(t, known)
}

// TestPlatformCloseIsAFloor proves a fact after Close is a counted no-op rather than a resurrection,
// and that Close waits for a target call that is already in flight.
func TestPlatformCloseIsAFloor(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	platform := &blockingTarget{entered: entered, release: release}
	policy := NewPlatformEvents(platform)

	done := make(chan struct{})
	go func() {
		// Passes the closed check and blocks inside the target call.
		policy.MemoryTrim(TrimRunningLow)
		close(done)
	}()
	<-entered

	closed := make(chan struct{})
	go func() {
		policy.Close()
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("Close returned while a target call was still in flight: the core could be mutated after teardown returned")
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	<-done
	<-closed

	before := policy.Stats()
	policy.MemoryTrim(TrimRunningLow)
	policy.SetScreenOn(false)
	policy.SetAppForeground(true)
	policy.DeviceWake()
	after := policy.Stats()
	require.Equal(t, before.Trims, after.Trims, "a fact after Close must not trim")
	require.Equal(t, before.Releases, after.Releases, "a fact after Close must not release")
	require.Equal(t, before.Pauses, after.Pauses, "a fact after Close must not pause")
	require.Equal(t, before.Wakes, after.Wakes, "a fact after Close must not wake")
	require.Equal(t, before.AfterClose+4, after.AfterClose, "each ignored fact is counted")
	policy.Close() // idempotent
}

type blockingTarget struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingTarget) TrimMemory(TrimLevel) {
	close(b.entered)
	<-b.release
}
func (b *blockingTarget) ReleaseMemory(TrimLevel) {}
func (b *blockingTarget) DevicePause()            {}
func (b *blockingTarget) DeviceWake()             {}

// TestPlatformStaleCallbackFromAnOldBoxCannotTouchANewOne is the resurrection case.
//
// Two policies stand for two Boxes. The old one is closed, the new one is live, and a callback that
// was already on its way from the old platform is delivered. It must touch neither the new core nor
// the old one.
func TestPlatformStaleCallbackFromAnOldBoxCannotTouchANewOne(t *testing.T) {
	oldPlatform := &fakePlatform{liveSessions: 1}
	newPlatform := &fakePlatform{liveSessions: 1}
	oldPolicy := NewPlatformEvents(oldPlatform)
	newPolicy := NewPlatformEvents(newPlatform)

	oldPolicy.SetScreenOn(false)
	oldPolicy.Close()

	newPolicy.SetScreenOn(true)
	newPolicy.SetAppForeground(true)
	newBefore := newPlatform.snapshot()

	// The stale callback: the old platform drops a screen-on and a trim on us after teardown.
	oldPolicy.SetScreenOn(true)
	oldPolicy.MemoryTrim(TrimRunningLow)
	oldPolicy.SetAppForeground(true)

	require.Equal(t, newBefore, newPlatform.snapshot(), "a stale callback mutated a Box it does not own")
	require.GreaterOrEqual(t, oldPolicy.Stats().AfterClose, uint64(3))
	require.Zero(t, newPolicy.Stats().AfterClose)
}

// TestPlatformStress runs the cycles the Android lifecycle produces in the field and asserts the
// invariants that a per-event bug would break: no reconnect storm, no resurrection, no unbounded
// growth.
func TestPlatformStress(t *testing.T) {
	runtime.GC()
	goroutinesBefore := runtime.NumGoroutine()

	platform := &fakePlatform{liveSessions: 2}
	policy := NewPlatformEvents(platform)
	policy.SetScreenOn(true)
	policy.SetAppForeground(true)

	for range 100 {
		policy.SetScreenOn(false)
		policy.SetScreenOn(true)
		policy.SetAppForeground(true)
	}
	for range 50 {
		policy.SetAppForeground(false)
		policy.SetAppForeground(true)
	}
	policy.SetScreenOn(false)
	policy.SetAppForeground(false)
	for range 50 {
		policy.MemoryTrim(TrimRunningLow)
		platform.openPool(2)
	}

	// A burst of repeated screen-on facts, which is what a ConnectivityManager burst looks like from
	// the lifecycle side: several deliveries for one real transition. The policy has no connectivity
	// API at all - a network change is the network manager's generation machinery, and that machinery
	// is what absorbs the burst. What is asserted here is the negative: the repeated facts neither
	// fabricate a pause nor dial, and the deferred wake they owe is released exactly ONCE when the
	// user actually comes back.
	pausesBefore := policy.Stats().Pauses
	wakesBefore := policy.Stats().Wakes
	dialsBefore, reconnectsBefore, _, _ := platform.counts()
	for range 25 {
		policy.SetScreenOn(true)
	}
	require.Equal(t, pausesBefore, policy.Stats().Pauses)
	require.Equal(t, wakesBefore, policy.Stats().Wakes, "a repeated screen-on fact is not a nudge")
	require.Equal(t, dialsBefore, platform.snapshot().dials)
	require.Equal(t, reconnectsBefore, platform.snapshot().reconnects)

	policy.SetAppForeground(true)
	require.Equal(t, wakesBefore+1, policy.Stats().Wakes,
		"the deferred nudge is released once, not once per repeated fact")

	// A trim during a transition: the trim still only reduces.
	platform.openPool(4)
	policy.MemoryTrim(TrimBackground)
	require.Zero(t, platform.snapshot().reconnects)

	// Close while an event callback is in flight, from a second policy.
	entered := make(chan struct{})
	release := make(chan struct{})
	closingPolicy := NewPlatformEvents(&blockingTarget{entered: entered, release: release})
	go closingPolicy.MemoryTrim(TrimRunningLow)
	<-entered
	closed := make(chan struct{})
	go func() {
		closingPolicy.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close did not wait for the in-flight release")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	<-closed

	// No reconnect storm: the only resets were the ones the reset-shaped levels earned, and each
	// stress phase coalesced its repeats.
	require.LessOrEqual(t, platform.snapshot().releases, 1)

	policy.Close()
	runtime.GC()
	require.LessOrEqual(t, runtime.NumGoroutine(), goroutinesBefore+2,
		"the policy must not leave a goroutine behind: %d -> %d", goroutinesBefore, runtime.NumGoroutine())
}

// TestPlatformPolicyCreatesNoGoroutineOrTimer is the structural half of the no-polling requirement.
//
// Go exposes no timer count through runtime/metrics, so a numerical assertion would be a guess. The
// policy's source is parsed instead: no `go` statement, no time.AfterFunc/NewTimer/NewTicker and no
// package-level channel that a worker could be reading. That is a property of the file, so it cannot
// regress silently the way a claim in a comment can.
func TestPlatformPolicyCreatesNoGoroutineOrTimer(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "platform_events.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err)

	var banned []string
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.GoStmt:
			banned = append(banned, "go statement")
		case *ast.CallExpr:
			selector, isSelector := typed.Fun.(*ast.SelectorExpr)
			if !isSelector {
				return true
			}
			packageName, isIdent := selector.X.(*ast.Ident)
			if !isIdent || packageName.Name != "time" {
				return true
			}
			switch selector.Sel.Name {
			case "AfterFunc", "NewTimer", "NewTicker", "Tick", "After", "Sleep":
				banned = append(banned, "time."+selector.Sel.Name)
			}
		}
		return true
	})
	require.Empty(t, banned, "the platform policy must stay event-driven: %s", strings.Join(banned, ", "))
}

// TestPlatformNoTargetIsInert: a platform with no runtime must not panic.
func TestPlatformNoTargetIsInert(t *testing.T) {
	policy := NewPlatformEvents(nil)
	policy.SetScreenOn(false)
	policy.SetScreenOn(true)
	policy.SetAppForeground(true)
	policy.MemoryTrim(TrimRunningCritical)
	policy.DeviceWake()
	policy.Close()
	require.EqualValues(t, 1, policy.Stats().Releases)
}
