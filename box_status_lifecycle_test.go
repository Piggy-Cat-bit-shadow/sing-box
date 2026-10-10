package box

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/physicalpath"
	"github.com/sagernet/sing-box/log"
	boxGroup "github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The Box LIFECYCLE half of the read-only status surface.
//
// # What these tests exercise, and what they deliberately do not
//
// `box_status_test.go` (package box_test) drives the real `New` through the real configuration
// loader, which is the only way to show that a Box built the ordinary way owns a view at all. What
// it cannot do is control WHEN a hop's reporter is entered: no production outbound implements
// `physicalpath.HopStatusReporter`, so nothing in a real object graph can be made to block, to
// re-enter the view, or to report an arbitrary selection state.
//
// These tests therefore drive the SAME surface `New` builds - `newStatusSurface`, the production
// constructor - over a fixture object graph. The lifecycle property under test is the Box's, not the
// model's: `close` reaches `Disconnect` before it tears anything down, exactly once, from any number
// of concurrent callers, and a snapshot that was in flight across that point publishes nothing.

// statusTimeout bounds every wait in this file. A test that fails by hanging tells a reader nothing;
// these bounds are what convert a deadlock into a named assertion.
const statusTimeout = 10 * time.Second

var errStatusNoDial = errStatusTest("the read-only status path must never dial")

type errStatusTest string

func (e errStatusTest) Error() string { return string(e) }

// statusBarrier holds a hop's own status read open until the test releases it. It is how a snapshot
// is placed INSIDE a reporter - the one place a teardown must not wait for.
//
// It is armed by default; a test that wants a control read to complete first disarms it, takes the
// control, and arms it again.
type statusBarrier struct {
	armed     atomic.Bool
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
}

func newStatusBarrier() *statusBarrier {
	barrier := &statusBarrier{entered: make(chan struct{}), release: make(chan struct{})}
	barrier.armed.Store(true)
	return barrier
}

func (b *statusBarrier) hold() {
	if !b.armed.Load() {
		return
	}
	b.enterOnce.Do(func() { close(b.entered) })
	<-b.release
}

// statusTestLeaf is a physical hop. It implements exactly the interfaces the walk reads, plus the
// optional lifecycle reporter - so a hop that reports nothing is expressed by the zero value of
// `state`, which is physicalpath.LifecycleStateUnknown.
//
// The embedded nil adapter.Outbound is deliberate: it makes the fixture satisfy the interface while
// leaving every method this test does not care about un-overridden, and the walk's own panic
// containment turns an accidental call into a reported failure rather than a silent answer.
type statusTestLeaf struct {
	adapter.Outbound
	tag       string
	leafType  string
	networks  []string
	dependsOn []string
	state     physicalpath.LifecycleState
	barrier   *statusBarrier
	onReport  func()
}

func (l *statusTestLeaf) Type() string           { return l.leafType }
func (l *statusTestLeaf) Tag() string            { return l.tag }
func (l *statusTestLeaf) Network() []string      { return l.networks }
func (l *statusTestLeaf) Dependencies() []string { return l.dependsOn }
func (l *statusTestLeaf) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errStatusNoDial
}
func (l *statusTestLeaf) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errStatusNoDial
}

// StatusState is the hop's OWN report, which is what a barrier or a re-entrant read is attached to.
func (l *statusTestLeaf) StatusState() physicalpath.LifecycleState {
	if l.barrier != nil {
		l.barrier.hold()
	}
	if l.onReport != nil {
		l.onReport()
	}
	return l.state
}

// statusTestGroup is a control node that publishes its own selection state.
//
// References mirrors the real contract exactly - it publishes the COMMITTED member and nothing else -
// because that is the property the Box's answer must not contradict.
type statusTestGroup struct {
	adapter.Outbound
	tag      string
	members  []string
	report   boxGroup.SelectionReport
	selected adapter.Outbound
}

func (g *statusTestGroup) Type() string                      { return "test-group" }
func (g *statusTestGroup) Tag() string                       { return g.tag }
func (g *statusTestGroup) Network() []string                 { return nil }
func (g *statusTestGroup) Dependencies() []string            { return g.members }
func (g *statusTestGroup) All() []string                     { return g.members }
func (g *statusTestGroup) Selected(string) adapter.Outbound  { return g.selected }
func (g *statusTestGroup) AttachConnection(io.Closer) func() { return func() {} }
func (g *statusTestGroup) SelectionStatus() boxGroup.SelectionReport {
	return g.report
}
func (g *statusTestGroup) References() []string {
	if g.report.State != boxGroup.SelectionCommitted {
		return nil
	}
	return []string{g.report.Committed}
}

// statusTestBox assembles a Box that owns the production status surface over a fixture graph.
//
// It uses `newStatusSurface` rather than `physicalpath.NewStatusView` so the instrument IS the
// production construction: a defect in what `New` builds would be a defect here too.
func statusTestBox(objects ...adapter.Outbound) (*Box, *adapter.Scope) {
	lookup := make(map[string]adapter.Outbound, len(objects))
	for _, object := range objects {
		lookup[object.Tag()] = object
	}
	ctx := context.Background()
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	statusView, statusResolver := newStatusSurface(func(tag string) (adapter.Outbound, bool) {
		object, loaded := lookup[tag]
		return object, loaded
	})
	return &Box{
		ctx:            ctx,
		scope:          scope,
		statusView:     statusView,
		statusResolver: statusResolver,
	}, scope
}

// TestCloseDisconnectsTheStatusViewBeforeTheObjectGraphIsTornDown is the barrier, and it pins three
// things at once: the ORDER of the linearisation point, that Close does not wait for a snapshot in
// flight, and that the snapshot which straddled the teardown publishes nothing.
func TestCloseDisconnectsTheStatusViewBeforeTheObjectGraphIsTornDown(t *testing.T) {
	barrier := newStatusBarrier()
	entry := &statusTestLeaf{tag: "entry", leafType: "test", state: physicalpath.LifecycleStateReady, barrier: barrier}
	exit := &statusTestLeaf{tag: "exit", leafType: "test", state: physicalpath.LifecycleStateReady, dependsOn: []string{"entry"}}
	instance, scope := statusTestBox(entry, exit)

	// The teardown itself is the witness. A scope cleanup runs inside Scope.Close, which is the
	// first thing `close` does AFTER Disconnect - so if the cleanup can still see a connected view,
	// the disconnect either never happened or happened after the graph started coming apart.
	var connectedDuringTeardown atomic.Bool
	connectedDuringTeardown.Store(true)
	scope.Add(func() error {
		connectedDuringTeardown.Store(instance.statusView.Connected())
		return nil
	})

	var (
		snapshotDone atomic.Bool
		snapshot     physicalpath.PathStatus
		waitGroup    sync.WaitGroup
	)
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		snapshot = instance.Status("exit", "tcp")
		snapshotDone.Store(true)
	}()

	select {
	case <-barrier.entered:
	case <-time.After(statusTimeout):
		t.Fatal("the snapshot never reached the hop reporter, so the barrier proves nothing about " +
			"the teardown it is supposed to straddle")
	}
	require.NoError(t, instance.Close(), "closing a Box whose status read is blocked must not fail")
	require.False(t, snapshotDone.Load(),
		"Close must NOT wait for a snapshot that is inside a reporter: a reporter may be slow or "+
			"wedged, and Close runs on the teardown path where blocking is not recoverable")
	require.False(t, connectedDuringTeardown.Load(),
		"the view must already be disconnected by the time the scope tears the object graph down, "+
			"or a caller can read a path whose hops are being closed and publish it as current")

	close(barrier.release)
	waitGroup.Wait()
	require.True(t, snapshotDone.Load(), "releasing the reporter must let the snapshot finish")
	require.Empty(t, snapshot.Hops,
		"the observation straddled the teardown, so it must be DISCARDED rather than published as "+
			"the current path of a box that no longer exists")
	require.True(t, snapshot.HasUnknown(), "a discarded observation is an UNKNOWN, not a blank")
	require.Contains(t, snapshot.Unknowns[0].Reason, "disconnected")
	require.False(t, snapshot.Ready(), "a hop that claimed READY before the teardown is not evidence")

	// And the answer stays disconnected, for ever and from any caller.
	later := instance.Status("exit", "tcp")
	require.Empty(t, later.Hops)
	require.Contains(t, later.Unknowns[0].Reason, "disconnected")
}

// TestStatusIsDisconnectedAfterConcurrentCloses pins that idempotence and concurrency do not open a
// window: the disconnect is inside closeOnce, so it is reached exactly once and cannot be skipped by
// a second caller joining the first.
func TestStatusIsDisconnectedAfterConcurrentCloses(t *testing.T) {
	for _, closers := range []int{2, 10} {
		t.Run("closers="+itoaForTest(closers), func(t *testing.T) {
			leaf := &statusTestLeaf{tag: "hop", leafType: "test", state: physicalpath.LifecycleStateReady}
			instance, _ := statusTestBox(leaf)
			require.True(t, instance.Status("hop", "tcp").Ready(),
				"the control: before Close the path is genuinely readable")

			var (
				waitGroup sync.WaitGroup
				start     = make(chan struct{})
				results   = make([]error, closers)
			)
			for index := 0; index < closers; index++ {
				waitGroup.Add(1)
				go func(index int) {
					defer waitGroup.Done()
					<-start
					results[index] = instance.Close()
				}(index)
			}
			close(start)
			waitGroup.Wait()
			for index, err := range results {
				require.NoError(t, err, "closer %d", index)
			}
			require.False(t, instance.statusView.Connected())
			after := instance.Status("hop", "tcp")
			require.Empty(t, after.Hops,
				"after %d closes the path must not be reported as current", closers)
			require.True(t, after.HasUnknown())
			require.False(t, after.Ready())
		})
	}
}

// TestAReentrantStatusReporterDoesNotDeadlock pins the re-entrancy contract the model states: a hop
// reporter may read the status view from inside its own report.
//
// The failure this pins is a lock. Nothing in the view protects the WALK - the per-walk state lives
// in the scope Build creates - so holding a mutex across a call into an adapter this package does
// not control would be a self-deadlock waiting for a legal implementation.
func TestAReentrantStatusReporterDoesNotDeadlock(t *testing.T) {
	var (
		instance      *Box
		innerStatus   physicalpath.PathStatus
		innerFinished atomic.Bool
		nesting       atomic.Int32
	)
	leaf := &statusTestLeaf{tag: "hop", leafType: "test", state: physicalpath.LifecycleStateReady}
	leaf.onReport = func() {
		// Exactly one level of nesting: enough to re-enter the view, bounded so a broken
		// implementation reports a timeout instead of overflowing the stack.
		if !nesting.CompareAndSwap(0, 1) {
			return
		}
		defer nesting.Store(0)
		innerStatus = instance.Status("hop", "tcp")
		innerFinished.Store(true)
	}
	instance, _ = statusTestBox(leaf)

	outer := make(chan physicalpath.PathStatus, 1)
	go func() { outer <- instance.Status("hop", "tcp") }()

	select {
	case status := <-outer:
		require.True(t, status.Ready(), "the outer read must still answer")
	case <-time.After(statusTimeout):
		t.Fatal("a reporter that read the status view from inside its own report deadlocked the " +
			"view; the view must hold no lock across a call into a hop")
	}
	require.True(t, innerFinished.Load(),
		"the nested read must run: the state a walk needs belongs to the call, so an inner walk "+
			"neither sees nor disturbs the outer one")
	require.True(t, innerStatus.Ready(), "and the nested read answers for itself")
}

// TestStatusMarksCommittedOnlyForACommittedSelection is the mapping rule, stated as a table.
//
// # Why a configuration default and a stored preference are in the same table
//
// They are the two ways a group can name a member without having committed to it, and they are the
// two ways a status answer can describe a route the traffic does not take. Both must come back
// not-committed, with an empty decision and a reason that says which one it is.
func TestStatusMarksCommittedOnlyForACommittedSelection(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		report     boxGroup.SelectionReport
		committed  bool
		decision   string
		wantReason string
	}{
		{
			name:      "a committed selection is committed",
			report:    boxGroup.SelectionReport{State: boxGroup.SelectionCommitted, Tag: "b", Committed: "b"},
			committed: true,
			decision:  "b",
		},
		{
			name: "a configuration default is a preference",
			report: boxGroup.SelectionReport{
				State: boxGroup.SelectionConfigured, Tag: "b", ConfiguredDefault: "b",
			},
			wantReason: "configured",
		},
		{
			name: "a historical selection is a preference",
			report: boxGroup.SelectionReport{
				State: boxGroup.SelectionPersisted, Tag: "b", Persisted: "b",
			},
			wantReason: "persisted",
		},
		{
			name:       "no evidence at all",
			report:     boxGroup.SelectionReport{},
			wantReason: "unknown",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			member := &statusTestLeaf{tag: "b", leafType: "test", state: physicalpath.LifecycleStateReady}
			group := &statusTestGroup{tag: "sel", members: []string{"b"}, report: testCase.report}
			if testCase.committed {
				group.selected = member
			}
			instance, _ := statusTestBox(member, group)

			status := instance.Status("sel", "tcp")
			require.Len(t, status.Controls, 1, "the group decided, so it is a control node")
			node := status.Controls[0]
			require.Equal(t, "sel", node.Tag)
			require.Equal(t, testCase.committed, node.Committed)
			require.Equal(t, testCase.decision, node.Decision,
				"the decision field names what the traffic takes, so a preference must leave it empty")
			if testCase.committed {
				require.Empty(t, node.Reason)
				require.False(t, status.HasUnknown())
				require.True(t, status.Ready())
				require.Len(t, status.Hops, 1)
				require.Equal(t, "b", status.Hops[0].Tag)
				return
			}
			require.Contains(t, node.Reason, testCase.wantReason,
				"the reason must name WHICH of the three not-committed states this is")
			require.Empty(t, status.Hops,
				"a group that committed nothing must not be walked to a member it merely prefers")
			require.True(t, status.HasUnknown())
			require.False(t, status.Ready())
		})
	}
}

// TestTwoBoxesHaveIndependentStatusViews pins that the view is per Box rather than per process: a
// teardown must not detach a Box that is still running.
func TestTwoBoxesHaveIndependentStatusViews(t *testing.T) {
	firstLeaf := &statusTestLeaf{tag: "hop", leafType: "test", state: physicalpath.LifecycleStateReady}
	secondLeaf := &statusTestLeaf{tag: "hop", leafType: "test", state: physicalpath.LifecycleStateReady}
	first, _ := statusTestBox(firstLeaf)
	second, _ := statusTestBox(secondLeaf)

	require.True(t, first.Status("hop", "tcp").Ready())
	require.True(t, second.Status("hop", "tcp").Ready())

	require.NoError(t, first.Close())
	require.Empty(t, first.Status("hop", "tcp").Hops, "the closed Box answers disconnected")
	require.True(t, second.Status("hop", "tcp").Ready(),
		"closing one Box must not detach the status view of another: the view is owned by the Box "+
			"that built it, and a new Box must be independent of an old one")
	require.NoError(t, second.Close())
}

// TestStatusOnABoxWithoutAViewIsAnAbsentAnswer pins the receiver contract at the Box level: a Box
// that never reached the status construction still answers, and answers honestly.
func TestStatusOnABoxWithoutAViewIsAnAbsentAnswer(t *testing.T) {
	var instance Box
	status := instance.Status("hop", "tcp")
	require.True(t, status.HasUnknown(),
		"a Box with no view must say so: an empty PathStatus has no unknowns and no hops, which "+
			"reads as a path that was walked and found clean")
	require.Contains(t, status.Unknowns[0].Reason, "no status view here")
	require.Empty(t, status.Hops)
	require.False(t, status.Ready())

	// And Close still works, which is what keeps a Box assembled by a test - or one that failed
	// before the status construction - closing without a status surface.
	ctx := context.Background()
	instance.scope = adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	require.NoError(t, instance.Close())
	require.Contains(t, instance.Status("hop", "tcp").Unknowns[0].Reason, "no status view here")
}

// TestStatusConcurrentWithClosePublishesNoHalfClosedPath is the short-window race: reads and a Close
// interleaved, with the first hop's reporter held open so the teardown lands in the middle of an
// observation.
//
// The property is a dichotomy rather than an equality, because both answers are legal and only the
// mixture is not: a path whose hops were all read from a live graph, or a disconnected UNKNOWN. What
// must never appear is a path carrying hops AND the teardown it straddled.
func TestStatusConcurrentWithClosePublishesNoHalfClosedPath(t *testing.T) {
	barrier := newStatusBarrier()
	barrier.armed.Store(false)
	entry := &statusTestLeaf{tag: "entry", leafType: "test", state: physicalpath.LifecycleStateReady, barrier: barrier}
	exit := &statusTestLeaf{tag: "exit", leafType: "test", state: physicalpath.LifecycleStateReady, dependsOn: []string{"entry"}}
	instance, _ := statusTestBox(entry, exit)

	// The other half of the dichotomy, taken first: a read that finishes before the teardown is a
	// complete observation of a live graph. Without this the test could only ever see discards.
	live := instance.Status("exit", "tcp")
	require.Len(t, live.Hops, 2)
	require.False(t, live.HasUnknown())
	require.True(t, live.Ready())
	barrier.armed.Store(true)

	const readers = 8
	var (
		waitGroup sync.WaitGroup
		start     = make(chan struct{})
		answers   = make([]physicalpath.PathStatus, readers)
	)
	for index := 0; index < readers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			answers[index] = instance.Status("exit", "tcp")
		}(index)
	}
	close(start)
	// Let the reads reach the held reporter, then tear the box down under them and release.
	select {
	case <-barrier.entered:
	case <-time.After(statusTimeout):
		t.Fatal("no read reached the reporter, so the window this test is about never opened")
	}
	require.NoError(t, instance.Close())
	close(barrier.release)
	waitGroup.Wait()

	for index, status := range answers {
		switch {
		case len(status.Hops) == 0:
			require.True(t, status.HasUnknown(), "answer %d: a discarded read must say why", index)
			require.Contains(t, status.Unknowns[0].Reason, "disconnected")
			require.False(t, status.Ready())
		case len(status.Hops) == 2:
			require.False(t, status.HasUnknown(),
				"answer %d: a path that carries hops must be a complete observation, never a half "+
					"one published next to the teardown it straddled", index)
			require.True(t, status.Ready())
		default:
			t.Fatalf("answer %d carries %d hops, which is neither a complete path nor a discarded "+
				"observation", index, len(status.Hops))
		}
	}
}

// itoaForTest names a subtest without pulling strconv into an assertion message.
func itoaForTest(value int) string {
	return strconv.Itoa(value)
}
