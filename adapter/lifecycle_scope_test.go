package adapter

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for the Scope.Start x Scope.Close x Scope.Add contract.
//
// # Why the contract needs one
//
// Scope.Close() cancels the context, takes the cleanup queue and then runs it OUTSIDE the lock,
// while Scope.Start() looks the child scope up under the lock and calls the component's Start
// outside it. Two windows follow, and both are reachable in the product:
//
//   - A component's Start can call scope.Add after Close has already taken the queue. On the
//     original Scope the cleanup was appended to a slice nobody would ever walk, so the resource it
//     owned was leaked permanently - silently, because Add had no way to report anything.
//
//   - Start can return success for a Scope that was closed while the component was starting. The
//     caller then believes a live component exists when its resources have already been released.
//
// The Box layer does not serialise these away. box.go is explicit that Close is exported and "an
// embedder may call it from any goroutine - including while Start is still running, which the daemon
// deliberately allows". The dynamic sub-scopes are worse: dns/transport/local, service/resolved and
// the openvpn/openconnect/tailscale DNS resolvers each build a fresh scope at RUNTIME and start
// transports into it while the Box stays open, so Scope.Start and Scope.Close are concurrent by
// design and not only during a Box shutdown.
//
// The tests here drive the real *Scope. The components are small doubles because the contract under
// test belongs to the Scope, not to any one component.

// lifecycleFunc adapts a function to the Lifecycle interface.
type lifecycleFunc struct {
	name  string
	start func(stage StartStage, scope *Scope) error
}

func (f *lifecycleFunc) Start(stage StartStage, scope *Scope) error {
	return f.start(stage, scope)
}

func newContractScope() *Scope {
	return NewScope(context.Background(), log.NewNOPFactory().Logger())
}

func noopCleanup(counter *atomic.Int32) func() error {
	return func() error {
		counter.Add(1)
		return nil
	}
}

// TestScopeRunsCleanupAddedWhileClosing is the leak window, forced deterministically.
//
// The component blocks inside its own Start (which the Scope calls outside its lock), Close takes
// the queue and finishes, and only then does the component register the cleanup for the resource it
// just acquired. Nothing will walk the queue again, so the only correct answer is to run the
// cleanup at the moment it is registered.
func TestScopeRunsCleanupAddedWhileClosing(t *testing.T) {
	scope := newContractScope()
	var added atomic.Int32

	entered := make(chan struct{})
	release := make(chan struct{})
	component := &lifecycleFunc{name: "blocking", start: func(stage StartStage, child *Scope) error {
		close(entered)
		<-release
		child.Add(noopCleanup(&added))
		return nil
	}}

	startDone := make(chan error, 1)
	go func() { startDone <- scope.Start("blocking", component, StartStateStart) }()

	<-entered
	require.NoError(t, scope.Close(), "Close must not wait on the in-flight Start")
	close(release)
	<-startDone

	require.Equal(t, int32(1), added.Load(),
		"a cleanup registered after the Scope closed must still run. Appending it to a queue that "+
			"has already been taken leaks the resource it owns, permanently and silently")
}

// TestScopeStartDoesNotReportSuccessAfterClose is the second window.
//
// A component that was starting while the Scope closed has had its resources released. Reporting
// success tells the caller a live component exists when none does.
func TestScopeStartDoesNotReportSuccessAfterClose(t *testing.T) {
	scope := newContractScope()
	var added atomic.Int32

	entered := make(chan struct{})
	release := make(chan struct{})
	component := &lifecycleFunc{name: "blocking", start: func(stage StartStage, child *Scope) error {
		close(entered)
		<-release
		client := child
		client.Add(noopCleanup(&added))
		return nil
	}}

	startDone := make(chan error, 1)
	go func() { startDone <- scope.Start("blocking", component, StartStateStart) }()

	<-entered
	require.NoError(t, scope.Close())
	close(release)

	require.Error(t, <-startDone,
		"Start must not report success for a Scope that closed while the component was starting; "+
			"the caller would treat a released component as a live one")
	require.Equal(t, int32(1), added.Load(), "and its cleanup must still have run")
}

// TestScopeAddRacingCloseRunsEachCleanupExactlyOnce is the barrier stress from the work order.
//
// Neither ordering is an error: Add may land before Close takes the queue or after. Exactly once is
// the invariant, and zero is the leak. A plain Sleep would only make the race less likely to be
// observed, so the two goroutines are released from one barrier.
func TestScopeAddRacingCloseRunsEachCleanupExactlyOnce(t *testing.T) {
	const iterations = 10000
	for i := 0; i < iterations; i++ {
		scope := newContractScope()
		var ran atomic.Int32
		start := make(chan struct{})
		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			<-start
			scope.Add(noopCleanup(&ran))
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			_ = scope.Close()
		}()
		close(start)
		waitGroup.Wait()
		require.Equal(t, int32(1), ran.Load(),
			"iteration %d: the cleanup must run exactly once whether Add landed before or after "+
				"Close took the queue", i)
	}
}

// TestScopeConcurrentCloseReturnsTheSameResult requires both closers to end up with the same answer.
//
// The cleanup queue is taken under the lock, so exactly one caller can run it. If the other returns
// immediately it reports SUCCESS for a teardown that has not happened and may still fail - the
// caller cannot tell a clean close from a failed one.
func TestScopeConcurrentCloseReturnsTheSameResult(t *testing.T) {
	scope := newContractScope()
	var completed atomic.Int32
	closeErr := errors.New("cleanup failed")

	scope.Add(func() error {
		completed.Add(1)
		return closeErr
	})

	results := make([]error, 2)
	var waitGroup sync.WaitGroup
	for i := range results {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			results[index] = scope.Close()
		}(i)
	}
	waitGroup.Wait()

	require.Equal(t, int32(1), completed.Load(), "the cleanup runs exactly once")
	require.ErrorIs(t, results[0], closeErr)
	require.ErrorIs(t, results[1], closeErr,
		"both concurrent Closes must report the same result. A second closer that returns SUCCESS "+
			"while the first is still tearing down hides a real teardown failure")
	require.Equal(t, results[0].Error(), results[1].Error())
}

// TestScopeStartFailureRollsBackEveryAcquiredResource is invariant #5.
//
// A component that acquires three resources and then fails must leave none of them behind. The Box
// relies on closing the Scope to do this, so the Scope has to run cleanups registered by a Start
// that then returned an error.
func TestScopeStartFailureRollsBackEveryAcquiredResource(t *testing.T) {
	scope := newContractScope()
	var first, second, third atomic.Int32

	component := &lifecycleFunc{name: "failing", start: func(stage StartStage, child *Scope) error {
		child.Add(noopCleanup(&first))
		child.Add(noopCleanup(&second))
		child.Add(noopCleanup(&third))
		return errors.New("start failed after acquiring three resources")
	}}

	require.Error(t, scope.Start("failing", component, StartStateStart))
	require.NoError(t, scope.Close())

	require.Equal(t, int32(1), first.Load())
	require.Equal(t, int32(1), second.Load())
	require.Equal(t, int32(1), third.Load())
}

// TestScopeCloseIsIdempotentAndOrdered pins the two ordering properties the teardown depends on:
// cleanups run in reverse registration order, and a repeated Close runs nothing twice.
func TestScopeCloseIsIdempotentAndOrdered(t *testing.T) {
	scope := newContractScope()
	var order []int
	scope.Add(func() error { order = append(order, 1); return nil })
	scope.Add(func() error { order = append(order, 2); return nil })
	scope.Add(func() error { order = append(order, 3); return nil })

	require.NoError(t, scope.Close())
	require.Equal(t, []int{3, 2, 1}, order, "cleanups run in reverse registration order")

	require.NoError(t, scope.Close())
	require.Equal(t, []int{3, 2, 1}, order, "a repeated Close must run nothing twice")
}

// TestScopeRefusesToRestartAfterClose is invariants #5 and #6: a closed Scope must not be revived.
//
// A restart has to build a NEW instance. Reusing the closed one would publish components onto a
// context that is already done, and nothing would ever close them.
func TestScopeRefusesToRestartAfterClose(t *testing.T) {
	scope := newContractScope()
	component := &lifecycleFunc{name: "component", start: func(stage StartStage, child *Scope) error {
		child.Add(func() error { return nil })
		return nil
	}}
	require.NoError(t, scope.Start("component", component, StartStateInitialize))
	require.NoError(t, scope.Close())

	require.Error(t, scope.Start("component", component, StartStateStart),
		"a closed Scope must refuse to start anything: any resource it acquired would have no owner")

	// A new instance is the supported restart, and it works.
	restarted := newContractScope()
	require.NoError(t, restarted.Start("component", component, StartStateInitialize))
	require.NoError(t, restarted.Close())
}

// TestScopeSpawnsNoGoroutines is the "no immortal goroutine" bound.
//
// The contract is implemented with a mutex, a channel and the context - no per-resource timer, no
// polling loop and no background cleanup. A Scope that spawned a goroutine per cleanup, or left one
// behind per Close, would grow the count with every start/stop cycle.
func TestScopeSpawnsNoGoroutines(t *testing.T) {
	runCycle := func() {
		scope := newContractScope()
		component := &lifecycleFunc{name: "component", start: func(stage StartStage, child *Scope) error {
			child.Add(func() error { return nil })
			child.Add(func() error { return nil })
			return nil
		}}
		for _, stage := range ListStartStages {
			require.NoError(t, scope.Start("component", component, stage))
		}
		require.NoError(t, scope.Close())
	}

	// Warm up so one-time allocations and the test binary's own goroutines are not counted.
	for i := 0; i < 50; i++ {
		runCycle()
	}
	runtime.GC()
	before := runtime.NumGoroutine()

	for i := 0; i < 500; i++ {
		runCycle()
	}
	runtime.GC()
	after := runtime.NumGoroutine()

	require.LessOrEqual(t, after, before,
		"500 start/close cycles must not leave goroutines behind: before=%d after=%d", before, after)
}

// TestScopeConcurrentAddAndCloseStress runs Add and Close concurrently with several cleanups so a
// double-run would be visible as a count above one, which a single-cleanup test cannot distinguish
// from a legitimate once.
func TestScopeConcurrentAddAndCloseStress(t *testing.T) {
	const (
		iterations = 2000
		perRound   = 4
	)
	for i := 0; i < iterations; i++ {
		scope := newContractScope()
		var ran atomic.Int32
		start := make(chan struct{})
		var waitGroup sync.WaitGroup
		waitGroup.Add(perRound + 1)
		for j := 0; j < perRound; j++ {
			go func() {
				defer waitGroup.Done()
				<-start
				scope.Add(noopCleanup(&ran))
			}()
		}
		go func() {
			defer waitGroup.Done()
			<-start
			_ = scope.Close()
		}()
		close(start)
		waitGroup.Wait()
		require.Equal(t, int32(perRound), ran.Load(),
			"iteration %d: every registered cleanup must run exactly once, none twice and none "+
				"dropped", i)
	}
}
