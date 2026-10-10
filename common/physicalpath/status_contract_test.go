package physicalpath

// P3: the StatusView's RECEIVER contract, its LOCK discipline, and its TEARDOWN rule.
//
// Every test in this file is written to be RED against the code it was written for, and each one
// states in its own comment what it would mean if it passed vacuously. The three properties are:
//
//	receiver     a nil *StatusView is a legal value, and asking it for a status must answer UNKNOWN
//	             rather than dereference it. An "if v != nil" that is followed by an unconditional
//	             v.something is worse than no check at all: it reads as handled to every reader.
//	lock         a reporter is any legal adapter implementation, and nothing stops one from calling
//	             back into the view it is being read by. A mutex held across that call is a
//	             self-deadlock that no documentation can prevent, so the lock may only exist if it
//	             protects state a walk actually writes.
//	teardown     Disconnect and an in-flight snapshot need a linearisation rule, and the rule must
//	             make "a torn observation presented as the current path" unrepresentable.
//
// # On the liveness guards in this file
//
// Three tests below can only fail by NOT RETURNING - a lost wakeup, a self-deadlock, a teardown that
// waits for a walk. Without a bound such a failure is a ten-minute `go test` timeout panic, which is
// a worse signal than an assertion. The guards are bounded WAITS ON A CHANNEL, never a sleep used to
// open a window: the assertions themselves are ordering assertions on channel handoffs and do not
// depend on any elapsed time. A pass therefore never depends on the clock.

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// livenessGuard bounds a wait that can only fail by hanging. It is deliberately generous: it exists
// to turn a deadlock into a named test failure, not to time anything.
const livenessGuard = 20 * time.Second

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// reentrantLeaf is a hop whose FIRST status read calls back into the very view that is reading it.
//
// This is the shape the view's documentation claimed was impossible ("a reporter held no reference to
// one when it was configured"). A reporter is an interface implementation supplied by an outbound
// adapter, and an adapter that also wants to report a path - a urltest that names its own hop - holds
// a view legitimately. The only question that matters is what the view does when it happens.
type reentrantLeaf struct {
	reportingLeaf

	view     *StatusView
	resolver *Resolver

	// reads counts every StatusState call. The callback is taken on the FIRST one only, so the
	// recursion is bounded at one level and a stack overflow cannot be confused with a deadlock.
	reads int32
	// inner is the answer the re-entrant call returned. The test goroutine reads it only after the
	// outer call has been received from a channel, so the handoff is ordered.
	inner PathStatus
	// innerErr records whether the re-entrant call panicked, without letting the panic escape.
	innerPanicked bool
}

func (l *reentrantLeaf) StatusState() LifecycleState {
	if atomic.AddInt32(&l.reads, 1) == 1 {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					l.innerPanicked = true
				}
			}()
			l.inner = l.view.SnapshotStatus(l.resolver, TagOrOutbound{Tag: l.tag}, Options{Network: N.NetworkTCP})
		}()
	}
	return LifecycleStateReady
}

// gatedLeaf holds a hop read open until the test releases it.
//
// It is how every teardown and overlap test below takes control of the interleaving: the walk is
// provably INSIDE a hop read when the test acts, because the goroutine doing the walk announced it
// on a channel and cannot proceed until the test says so.
type gatedLeaf struct {
	reportingLeaf
	entered chan struct{}
	release chan struct{}
}

func (l *gatedLeaf) StatusState() LifecycleState {
	l.entered <- struct{}{}
	<-l.release
	return l.reportingLeaf.StatusState()
}

// panickingLeaf panics from one reporter interface at a time, so a test can remove exactly one
// capability and see what the view does without it.
type panickingLeaf struct {
	reportingLeaf
	panicState bool
	panicError bool
	panicMTU   bool
	panicValue any
}

func (l *panickingLeaf) StatusState() LifecycleState {
	if l.panicState {
		panic(l.panicValue)
	}
	return l.reportingLeaf.StatusState()
}

func (l *panickingLeaf) StatusLastError() (error, FailurePhase, bool) {
	if l.panicError {
		panic(l.panicValue)
	}
	return l.reportingLeaf.StatusLastError()
}

func (l *panickingLeaf) PortMTU() uint32 {
	if l.panicMTU {
		panic(l.panicValue)
	}
	return l.reportingLeaf.PortMTU()
}

// panickingGroup panics while publishing its decision, which is the other external call the view
// makes under its own snapshot.
type panickingGroup struct {
	testGroup
	panicReferences bool
}

func (g *panickingGroup) References() []string {
	if g.panicReferences {
		panic("group references: socks5://user:hunter2@proxy.example:1080 is unreachable")
	}
	return g.testGroup.References()
}

// readyRegistry is the fixture most tests here want: one hop that says it is ready.
func readyRegistry(tag string) (*reportingLeaf, *testRegistry) {
	leaf := &reportingLeaf{testLeaf: *tcpLeaf(tag), reportsState: true, state: LifecycleStateReady}
	return leaf, newReportingRegistry(leaf)
}

// recoveredFrom runs one call and returns the value it panicked with, if any.
//
// It is here so a RED test reports a panic as a failed assertion that NAMES the panic value, instead of
// dereferencing nil and aborting the whole test binary - which would hide every other test in the
// package and make the failure much harder to read than the defect it is reporting.
func recoveredFrom(run func()) (panicked any, didPanic bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = recovered
			didPanic = true
		}
	}()
	run()
	return nil, false
}

// ---------------------------------------------------------------------------
// P3.1 - the receiver: a nil *StatusView is a value, not a crash
// ---------------------------------------------------------------------------

// snapshotter is the smallest interface a *StatusView satisfies. It exists so a typed-nil can reach
// the methods THROUGH an interface, which is a different call shape from a plain nil pointer and the
// second path the same defect can be reached by.
type snapshotter interface {
	SnapshotStatus(resolver *Resolver, root TagOrOutbound, options Options) PathStatus
	Connected() bool
	Disconnect()
}

// TestANilStatusViewAnswersUnknownInsteadOfCrashing is P3.1.
//
// The code this was written against reads:
//
//	if v != nil && !v.Connected() { ... }
//	v.walk.Lock()                       // reached even when v == nil
//
// so a nil view passes the check and is then dereferenced. The check is not merely useless, it is
// actively misleading: a reader sees "nil is handled" and stops looking.
//
// The contract chosen here is the one the rest of this package already keeps - Build contains a panic
// and reports it, a hop that cannot be read is UNKNOWN with a reason - so a view that does not exist
// answers UNKNOWN with a reason and can never be mistaken for a healthy path.
func TestANilStatusViewAnswersUnknownInsteadOfCrashing(t *testing.T) {
	_, registry := readyRegistry("hop")

	var view *StatusView

	// SnapshotStatus is called FIRST, before any other method, so a receiver defect is caught exactly
	// where it lives rather than behind an assertion on a different call.
	var status PathStatus
	if panicked, didPanic := recoveredFrom(func() {
		status = view.SnapshotStatus(registry.resolver(), TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	}); didPanic {
		t.Fatalf("a nil *StatusView was dereferenced instead of answering: %v", panicked)
	}

	require.False(t, view.Connected(),
		"a view that does not exist is not attached to an object graph; reporting true would be a lie")

	require.True(t, status.HasUnknown(), "there is no view, so nothing was established: that is an unknown")
	require.False(t, status.Ready(), "and an absent view must never produce a READY path")
	require.Empty(t, status.Hops, "no hop was read, so none may be reported")
	require.NotEmpty(t, status.Unknowns[0].Reason)
	require.Contains(t, status.Unknowns[0].Reason, "view",
		"the reason must name WHAT was missing, so an operator can tell 'no view' from 'no path'")
	require.Equal(t, "hop", status.Root, "the root the caller asked about is still reported back")
	require.Equal(t, N.NetworkTCP, status.Network)

	if panicked, didPanic := recoveredFrom(func() { view.Disconnect() }); didPanic {
		t.Fatalf("Disconnect must be safe on a nil receiver, and it panicked: %v", panicked)
	}

	// The fixture must be able to fail: the SAME call on a real view is a real snapshot. Without this
	// assertion every check above would also pass if the whole view were broken.
	live := NewStatusView()
	liveStatus := live.SnapshotStatus(registry.resolver(), TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	require.False(t, liveStatus.HasUnknown(), "this fixture resolves: the unknown above is about the VIEW")
	require.True(t, liveStatus.Ready())
}

// TestATypedNilStatusViewReachesTheSameContract is the interface path of the same defect.
//
// `var view *StatusView; var api snapshotter = view` is non-nil as an interface and nil as a
// receiver, so a caller that type-asserted or stored the view in a field gets the method called on a
// nil pointer. Nothing about the interface says the value is absent, so the method has to be the
// thing that is safe.
func TestATypedNilStatusViewReachesTheSameContract(t *testing.T) {
	_, registry := readyRegistry("hop")

	var view *StatusView
	var api snapshotter = view

	// The interface itself is NOT nil - that is the whole point of this test - so a caller that checks
	// `api != nil` before using it passes the check and still reaches a nil receiver.
	require.False(t, api == nil, "a typed nil in an interface is a non-nil interface")

	var status PathStatus
	if panicked, didPanic := recoveredFrom(func() {
		status = api.SnapshotStatus(registry.resolver(), TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	}); didPanic {
		t.Fatalf("a typed-nil StatusView was dereferenced instead of answering: %v", panicked)
	}

	if panicked, didPanic := recoveredFrom(func() { api.Connected() }); didPanic {
		t.Fatalf("Connected on a typed-nil view panicked: %v", panicked)
	}
	if panicked, didPanic := recoveredFrom(func() { api.Disconnect() }); didPanic {
		t.Fatalf("Disconnect on a typed-nil view panicked: %v", panicked)
	}
	require.False(t, api.Connected(), "Disconnect on an absent view stays absent")

	require.True(t, status.HasUnknown())
	require.False(t, status.Ready())
	require.Empty(t, status.Hops)
}

// TestANilViewIsNotSilentlyReady is the negative control for the failure mode that matters most.
//
// "Handle nil" must not be implemented as "return an empty PathStatus": an empty PathStatus has no
// unknowns and no hops, and Ready() would be false only because len(Hops) == 0 - a caller that
// checked Readiness per hop, or that rendered the status, would see an empty, apparently clean path.
// The absent view must be an EXPLICIT unknown.
func TestANilViewIsNotSilentlyReady(t *testing.T) {
	var view *StatusView
	var status PathStatus
	if panicked, didPanic := recoveredFrom(func() {
		status = view.SnapshotStatus(nil, TagOrOutbound{Tag: "anything"}, Options{Network: N.NetworkTCP})
	}); didPanic {
		t.Fatalf("a nil *StatusView was dereferenced instead of answering: %v", panicked)
	}

	require.False(t, status.Ready())
	require.NotEmpty(t, status.Unknowns,
		"the absent view must SAY it established nothing; an answer with no unknowns describes a path "+
			"that was walked and found clean, which is the opposite of what happened")
	require.Empty(t, status.Failure, "and it must not invent a failure either")
}

// ---------------------------------------------------------------------------
// P3.2 - the lock: what it protects, and what it costs
// ---------------------------------------------------------------------------

// TestAReentrantReporterDoesNotDeadlockTheView is P3.2's second question.
//
// The view called reporter methods while holding `walk`. A reporter is an interface implementation
// supplied from outside this package, and there is nothing in the type system, the interface or the
// documentation that stops one from calling back into the same view - an adapter that wants to report
// its own path is the obvious case. `sync.Mutex` is not reentrant, so that call waits for a lock the
// waiting goroutine already holds: the view deadlocks on a legal implementation.
//
// "The interface does not say you may" is documentation, not a proof, and it is not a control.
func TestAReentrantReporterDoesNotDeadlockTheView(t *testing.T) {
	leaf := &reentrantLeaf{
		reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
	}
	registry := newRegistry(leaf)
	view := NewStatusView()
	leaf.view = view
	leaf.resolver = registry.resolver()

	outer := make(chan PathStatus, 1)
	go func() {
		outer <- view.SnapshotStatus(leaf.resolver, TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	}()

	var status PathStatus
	select {
	case status = <-outer:
	case <-time.After(livenessGuard):
		t.Fatalf("the view never returned: a reporter that calls back into the view it is being read by "+
			"deadlocked it. Liveness guard fired after %s", livenessGuard)
	}

	require.False(t, leaf.innerPanicked, "the re-entrant call must complete, not panic")
	require.EqualValues(t, 2, atomic.LoadInt32(&leaf.reads),
		"the reporter must have been asked exactly twice: once outside and once inside the callback")
	require.False(t, leaf.inner.HasUnknown(),
		"the inner snapshot is a normal snapshot of the same path and must report it")
	require.True(t, leaf.inner.Ready())
	require.False(t, status.HasUnknown(), "and the outer one must finish normally around it")
	require.Len(t, status.Hops, 1)
}

// TestOneViewsSnapshotsDoNotSerialiseBehindEachOther is P3.2's first question, measured rather than
// argued.
//
// If `walk` is still held across a hop read, N snapshots of ONE view cannot be inside their hop reads
// at the same time: the first holds the lock, the rest wait for it. That is not a performance
// preference - it is the property that makes the lock's cost real, and the property a caller relies
// on when it says "two concurrent snapshots of the same view are independent".
//
// The fixture proves overlap directly: every worker announces its hop read on a channel and then
// blocks. Nothing can release them until ALL of them have arrived, so the test can only pass if all N
// are inside a hop read simultaneously - a lost wakeup cannot fake it.
func TestOneViewsSnapshotsDoNotSerialiseBehindEachOther(t *testing.T) {
	const workers = 3

	leaf := &gatedLeaf{
		reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
		entered:       make(chan struct{}, workers),
		release:       make(chan struct{}),
	}
	registry := newRegistry(leaf)
	view := NewStatusView()
	resolver := registry.resolver()

	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			view.SnapshotStatus(resolver, TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
		}()
	}

	arrived := 0
	guard := time.After(livenessGuard)
	for arrived < workers {
		select {
		case <-leaf.entered:
			arrived++
		case <-guard:
			close(leaf.release)
			wait.Wait()
			t.Fatalf("only %d of %d snapshots of ONE view reached their hop read: the view serialises "+
				"snapshots that do not share anything writable", arrived, workers)
		}
	}
	close(leaf.release)
	wait.Wait()
}

// TestOneResolverSeveralViewsUnderRace is the shared-structure half of the same question, and it is
// the test that says whether the lock protected anything in the first place.
//
// A Resolver is documented as safe for concurrent use, and the per-walk state - the network this call
// answers for and the decision each group gave - lives in the walkScope Build creates and drops. If
// any of that were still on the Resolver, several views sharing one would corrupt each other and the
// race detector would say so here. The fixture makes every worker assert its OWN network's member, so
// a contaminated walk fails the assertion as well as the detector.
func TestOneResolverSeveralViewsUnderRace(t *testing.T) {
	tcpMember := tcpLeaf("tcp-member")
	udpMember := &testLeaf{tag: "udp-member", leafType: "test", networks: []string{N.NetworkUDP}}
	group := newPerNetworkGroup("sel", []string{"tcp-member", "udp-member"},
		[]string{N.NetworkTCP, N.NetworkUDP},
		map[string]adapter.Outbound{N.NetworkTCP: tcpMember, N.NetworkUDP: udpMember})
	registry := newRegistry(tcpMember, udpMember, group)

	// ONE Resolver, several views: the lock the views each had was per-view, so it never protected
	// the Resolver at all - this test is what makes that visible instead of assumed.
	resolver := registry.resolver()
	const workers = 4
	const rounds = 200

	want := map[string]string{N.NetworkTCP: "tcp-member", N.NetworkUDP: "udp-member"}
	start := make(chan struct{})
	failures := make(chan string, workers*rounds)

	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		network := N.NetworkTCP
		if worker%2 == 1 {
			network = N.NetworkUDP
		}
		view := NewStatusView()
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for round := 0; round < rounds; round++ {
				status := view.SnapshotStatus(resolver, TagOrOutbound{Tag: "sel"}, Options{Network: network})
				if len(status.Hops) != 1 {
					failures <- network + ": " + itoa(len(status.Hops)) + " hops"
					return
				}
				if status.Hops[0].Tag != want[network] {
					failures <- network + ": reported " + status.Hops[0].Tag + " instead of " + want[network]
					return
				}
			}
		}()
	}
	close(start)
	wait.Wait()
	close(failures)
	require.Empty(t, collectFailures(failures),
		"one Resolver shared by several views must answer each view for the view's own network")
}

// ---------------------------------------------------------------------------
// P3.3 - the teardown rule
// ---------------------------------------------------------------------------

// TestASnapshotStartedAfterDisconnectReportsDisconnected is the first half of the rule, and it is
// deliberately started AFTER Disconnect has returned - not concurrently with it - so no scheduling
// window is involved and no barrier is needed to make it true.
func TestASnapshotStartedAfterDisconnectReportsDisconnected(t *testing.T) {
	_, registry := readyRegistry("hop")
	resolver := registry.resolver()

	view := NewStatusView()
	require.True(t, view.Connected())

	// The positive control comes FIRST, on the same view and the same fixture: this exact call is a
	// real snapshot until the teardown lands. Without it, the assertions below would also pass if the
	// fixture simply could not produce a path.
	before := view.SnapshotStatus(resolver, TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	require.False(t, before.HasUnknown(), "the fixture must resolve, or the disconnected answer proves nothing")
	require.True(t, before.Ready())

	view.Disconnect()
	require.False(t, view.Connected())

	after := view.SnapshotStatus(resolver, TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})

	require.True(t, after.HasUnknown(),
		"a call that STARTS after Disconnect returned must report the view as disconnected")
	require.Contains(t, after.Unknowns[0].Reason, "disconnected")
	require.Empty(t, after.Hops, "and it must not re-serve the path it read before the teardown")
	require.False(t, after.Ready())
	require.Nil(t, after.Failure, "a disconnected view must not report a failure of a dead graph")
}

// TestASnapshotWhoseObservationStraddlesDisconnectIsDiscarded is the second half, and it is the half
// the pre-check alone does not cover.
//
// The walk is held open INSIDE a hop read when Disconnect lands, so the observation provably straddles
// the teardown: the path was built before it and this hop's state was read after it. Presenting that
// mixture as the current path is exactly what the Disconnect contract exists to make unrepresentable,
// and a check that only runs before the walk cannot see it.
//
// The rule implemented is the pre/post generation check: the answer is published only if the view was
// connected both before and after the observation.
func TestASnapshotWhoseObservationStraddlesDisconnectIsDiscarded(t *testing.T) {
	leaf := &gatedLeaf{
		reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
		entered:       make(chan struct{}, 1),
		release:       make(chan struct{}),
	}
	registry := newRegistry(leaf)
	view := NewStatusView()

	results := make(chan PathStatus, 1)
	go func() {
		results <- view.SnapshotStatus(registry.resolver(), TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	}()

	select {
	case <-leaf.entered:
	case <-time.After(livenessGuard):
		t.Fatal("the snapshot never reached its hop read")
	}

	// The walk is provably in flight and provably past its own pre-check.
	view.Disconnect()
	require.False(t, view.Connected())
	close(leaf.release)

	var status PathStatus
	select {
	case status = <-results:
	case <-time.After(livenessGuard):
		t.Fatal("the in-flight snapshot never returned after its hop was released")
	}

	require.True(t, status.HasUnknown(),
		"a snapshot whose observation straddled the teardown must be DISCARDED, not presented as the "+
			"current path: its hop states may come from either side of the teardown")
	require.Contains(t, status.Unknowns[0].Reason, "disconnected")
	require.Empty(t, status.Hops, "and it must not hand back the half-observed path")
	require.False(t, status.Ready())
}

// TestASnapshotThatDoesNotOverlapDisconnectStillReportsThePath is the negative control for the rule
// above: an ordinary snapshot of a connected view is unaffected, so the recheck cannot be implemented
// as "always report disconnected after any Disconnect exists".
func TestASnapshotThatDoesNotOverlapDisconnectStillReportsThePath(t *testing.T) {
	_, registry := readyRegistry("hop")

	for round := 0; round < 3; round++ {
		view := NewStatusView()
		status := view.SnapshotStatus(registry.resolver(), TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
		require.False(t, status.HasUnknown())
		require.Len(t, status.Hops, 1)
		require.True(t, status.Ready())

		// And a disconnect that happens strictly AFTER the snapshot returned cannot retroactively
		// invalidate the value the caller already holds.
		view.Disconnect()
		require.True(t, status.Ready(),
			"the PathStatus is a value: teardown must not rewrite an answer already handed out")
	}
}

// TestDisconnectDoesNotWaitForASlowReporter is the liveness half of the teardown rule.
//
// Disconnect publishes one flag. If it ever waited for in-flight walks - the obvious way to make the
// rule airtight - then a reporter that is slow, blocked on its own I/O, or simply wedged would block
// teardown, and teardown runs on the box's shutdown path where blocking is not recoverable.
func TestDisconnectDoesNotWaitForASlowReporter(t *testing.T) {
	leaf := &gatedLeaf{
		reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
		entered:       make(chan struct{}, 1),
		release:       make(chan struct{}),
	}
	registry := newRegistry(leaf)
	view := NewStatusView()

	finished := make(chan PathStatus, 1)
	go func() {
		finished <- view.SnapshotStatus(registry.resolver(), TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	}()

	select {
	case <-leaf.entered:
	case <-time.After(livenessGuard):
		t.Fatal("the snapshot never reached its hop read")
	}

	disconnected := make(chan struct{})
	go func() {
		view.Disconnect()
		close(disconnected)
	}()

	select {
	case <-disconnected:
	case <-time.After(livenessGuard):
		t.Fatal("Disconnect did not return while a snapshot was in flight: teardown must not wait for a " +
			"reporter, which may be slow or wedged")
	}

	// The positive control: the snapshot really is still inside its hop read, so the assertion above
	// is about Disconnect returning EARLY rather than about the fixture never having blocked.
	select {
	case <-finished:
		t.Fatal("the in-flight snapshot finished before its hop was released: the fixture cannot fail")
	default:
	}

	require.False(t, view.Connected(), "and the flag is published before Disconnect returns")

	close(leaf.release)
	select {
	case <-finished:
	case <-time.After(livenessGuard):
		t.Fatal("the released snapshot never returned")
	}
}

// ---------------------------------------------------------------------------
// A reporter that panics
// ---------------------------------------------------------------------------

// TestAReporterThatPanicsIsReportedAsUnknownAndNeverAsReady is the panic policy, and the policy is
// fail-unknown: the panic is contained and REPORTED, never propagated (a read-only diagnostic must
// not take down the control plane that asked it a question) and never swallowed into a healthy
// answer (a hop that could not be read is not a hop that is up).
//
// The fixture makes the case adversarial on purpose: every panicking hop CLAIMS to be ready first, so
// a containment that kept the claim would report READY for a hop whose status could not be read.
func TestAReporterThatPanicsIsReportedAsUnknownAndNeverAsReady(t *testing.T) {
	cases := []struct {
		name  string
		build func() *panickingLeaf
	}{
		{
			name: "StatusState panics",
			build: func() *panickingLeaf {
				return &panickingLeaf{
					reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
					panicState:    true, panicValue: "state provider exploded",
				}
			},
		},
		{
			name: "StatusLastError panics",
			build: func() *panickingLeaf {
				return &panickingLeaf{
					reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
					panicError:    true, panicValue: "error provider exploded",
				}
			},
		},
		{
			name: "PortMTU panics",
			build: func() *panickingLeaf {
				return &panickingLeaf{
					reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
					panicMTU:      true, panicValue: "mtu provider exploded",
				}
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			leaf := testCase.build()
			registry := newRegistry(leaf)

			var status PathStatus
			if panicked, didPanic := recoveredFrom(func() {
				status = NewStatusView().SnapshotStatus(registry.resolver(),
					TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
			}); didPanic {
				t.Fatalf("a reporter's panic escaped SnapshotStatus: %v; a read-only diagnostic must "+
					"contain it exactly as Build contains a malformed graph's", panicked)
			}

			require.Len(t, status.Hops, 1, "the hop is still a hop: it exists and it could not be read")
			require.Equal(t, ReadinessUnknown, status.Hops[0].Readiness,
				"a hop whose status could not be read is UNKNOWN, and the claim it made before panicking "+
					"is NOT evidence")
			require.False(t, status.Ready())
			require.Contains(t, status.Hops[0].Reason, "panic",
				"the reason must say what happened, so the failure is reported rather than swallowed")
			require.Empty(t, status.Hops[0].LastError,
				"a panic must not leave a half-read failure behind for the path report to pick up")
			require.Nil(t, status.Failure)
		})
	}

	// The negative control: the same fixture with the panic switched off is a READY hop, so the
	// assertions above are about the panic and not about the fixture being unable to report anything.
	healthy := &panickingLeaf{
		reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
	}
	registry := newRegistry(healthy)
	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	require.False(t, status.HasUnknown())
	require.True(t, status.Ready())
}

// TestAPanickingReporterCannotLeakACredentialThroughItsPanicValue is the redaction rule applied to
// the new free-text field the panic policy introduces.
//
// A panic value is arbitrary data from an adapter, and an adapter's panic is exactly the moment it is
// most likely to be quoting what it was doing - a URL, a header, a key. If containment adds a field
// that is not redacted, containment becomes a new leak.
func TestAPanickingReporterCannotLeakACredentialThroughItsPanicValue(t *testing.T) {
	leaf := &panickingLeaf{
		reportingLeaf: reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady},
		panicState:    true,
		panicValue: "dial socks5://operator:hunter2@proxy.example:1080 failed: " +
			"Authorization: Bearer sk-live-0123456789abcdef",
	}
	registry := newRegistry(leaf)

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})

	require.Contains(t, status.Hops[0].Reason, "panic")
	for _, forbidden := range []string{"hunter2", "sk-live-0123456789abcdef"} {
		require.NotContains(t, status.Hops[0].Reason, forbidden,
			"a panic value is external text and must go through the same redaction as an error: %q", forbidden)
	}
}

// TestAGroupThatPanicsWhilePublishingIsReportedWithoutADecision is the same policy for the other
// external call the view makes: reading a group's published selection.
func TestAGroupThatPanicsWhilePublishingIsReportedWithoutADecision(t *testing.T) {
	leaf := &reportingLeaf{testLeaf: *dualLeaf("leaf"), reportsState: true, state: LifecycleStateReady}
	// panicReferences MUST be set: a fixture that cannot panic would let this test pass while the
	// defect it describes is live, which is worse than having no test.
	group := &panickingGroup{testGroup: *tcpGroup("sel", "leaf", "leaf"), panicReferences: true}
	registry := newRegistry(leaf, group)
	group.lookup = registry.objects

	var status PathStatus
	if panicked, didPanic := recoveredFrom(func() {
		status = NewStatusView().SnapshotStatus(registry.resolver(),
			TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	}); didPanic {
		t.Fatalf("a group's panic escaped SnapshotStatus: %v", panicked)
	}

	require.Len(t, status.Controls, 1)
	require.Empty(t, status.Controls[0].Decision,
		"a group that panicked published nothing, and the view must not have invented a decision")
	require.False(t, status.Controls[0].Committed)
	require.Contains(t, status.Controls[0].Reason, "panic")
	require.NotContains(t, status.Controls[0].Reason, "hunter2",
		"and the panic value is redacted like any other external text")

	// The negative control: with the panic off, the same group publishes its committed decision.
	quiet := &panickingGroup{testGroup: *tcpGroup("sel", "leaf", "leaf")}
	quietRegistry := newRegistry(leaf, quiet)
	quiet.lookup = quietRegistry.objects
	quietStatus := NewStatusView().SnapshotStatus(quietRegistry.resolver(),
		TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.Equal(t, "leaf", quietStatus.Controls[0].Decision)
	require.True(t, quietStatus.Controls[0].Committed)
}

// ---------------------------------------------------------------------------
// Redaction, including the shapes a keyword denylist misses
// ---------------------------------------------------------------------------

// TestRedactionCoversTheQuotedAndPrefixedForms is the adversarial half of redaction.
//
// The denylist matches `keyword` immediately followed by `=` or `:`. Two extremely common renderings
// are not covered by that shape, and both are forms a real error message takes:
//
//	"password":"hunter2"     a JSON body echoed into an error
//	password="hunter2"       an ini/env rendering, where the value is quoted
//
// A backstop that misses the quoted form is a backstop against the tidy case only.
func TestRedactionCoversTheQuotedAndPrefixedForms(t *testing.T) {
	cases := []struct {
		detail  string
		secret  string
		keyword string
	}{
		{detail: `{"password":"hunter2"} rejected`, secret: "hunter2", keyword: "password"},
		{detail: `password="hunter2" rejected`, secret: "hunter2", keyword: "password"},
		{detail: `{"token":"abc123def456"} expired`, secret: "abc123def456", keyword: "token"},
		{detail: `config: api_key="sk-live-0123456789abcdef"`, secret: "sk-live-0123456789abcdef", keyword: "api_key"},
		{detail: `access_token=ya29.a0AfH6SMBexample`, secret: "ya29.a0AfH6SMBexample", keyword: "access_token"},
		{detail: `refresh_token=1//0gExampleRefreshToken`, secret: "1//0gExampleRefreshToken", keyword: "refresh_token"},
		{detail: `db_password=hunter2 refused`, secret: "hunter2", keyword: "db_password"},
		{detail: `password='hunter2' refused`, secret: "hunter2", keyword: "single-quoted value"},
		{detail: `Authorization: Bearer sk-live-0123456789abcdef`, secret: "sk-live-0123456789abcdef", keyword: "authorization"},
		// The header form behind an underscore prefix is the case that decides whether the two matchers
		// share one boundary rule. If the header path refused it and the keyword path accepted it, the
		// keyword path would redact the word "Bearer" and leave the credential itself in the message.
		{detail: `X_Authorization: Bearer sk-live-0123456789abcdef`,
			secret: "sk-live-0123456789abcdef", keyword: "prefixed authorization header"},
		{detail: `socks5://user:hunter2@proxy.example:1080`, secret: "hunter2", keyword: "userinfo"},
		{detail: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----",
			secret: "b3BlbnNzaC1rZXk", keyword: "PEM"},
	}

	for _, testCase := range cases {
		t.Run(testCase.keyword, func(t *testing.T) {
			redacted := redactDetail(testCase.detail)
			require.NotContains(t, redacted, testCase.secret,
				"the %s form must be redacted", testCase.keyword)
			require.Contains(t, strings.ToLower(redacted), "[redacted",
				"and the replacement must be visible, so a reader knows something was removed")
		})
	}

	// The negative control: a message that carries no secret must survive redaction unchanged, or the
	// assertions above would also pass if redaction simply destroyed every message.
	for _, clean := range []string{
		"dial tcp 10.0.0.1:443: connect: connection refused",
		"lookup node.example: no such host",
		"context deadline exceeded",
		"mypassword=not-a-secret-field",
	} {
		require.Equal(t, clean, redactDetail(clean),
			"redaction must not destroy a message that carries no secret")
	}
}
