package adapter

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"github.com/stretchr/testify/require"
)

// Tests for the exact COMPLETION BOUNDARY of Scope.Close.
//
// # The boundary
//
// Scope.Close() joins the cleanup drain that has already started: it runs the cleanup queue in
// reverse registration order and, if another goroutine got there first, waits on closeDone for that
// drain and returns ITS result. What it does NOT do is wait for a component Start that is already
// running and has not reached Add yet. Nothing bounds how long a component's Start may take, so
// Close cannot wait for one without becoming unbounded; that window is closed from the other side
// instead, by Add running the caller's cleanup synchronously once the queue is gone.
//
// Two consequences follow, and both are asserted here rather than described:
//
//   - Close does not wait for that Start, so a cleanup registered after Close returned runs AFTER
//     Close returned. That is the leak-prevention path, not a teardown guarantee.
//   - The late cleanup's error is logged by Add and is not folded into the closeErr the
//     already-returned Close handed out. A later Close does not pick it up either: closeErr is
//     final. A caller that needs to know the late release failed has to read the log; the close
//     result cannot tell it.
//
// The tests drive the real *Scope through the real Scope.Start child-scope path - the component
// receives the child scope and registers into it, exactly as protocol/tun and protocol/masque do -
// so the child scope reaching its own closed state is part of what is being exercised.

// lateCleanupLogger records what the close path reports, including the Error line Add emits for a
// cleanup that arrives after the queue is gone. The embedded interface is nil and only the methods
// the close path uses are overridden.
type lateCleanupLogger struct {
	log.ContextLogger
	access sync.Mutex
	lines  []string
}

func (l *lateCleanupLogger) record(args ...any) {
	l.access.Lock()
	l.lines = append(l.lines, F.ToString(args...))
	l.access.Unlock()
}

func (l *lateCleanupLogger) Trace(args ...any) { l.record(args...) }
func (l *lateCleanupLogger) Debug(args ...any) { l.record(args...) }
func (l *lateCleanupLogger) Warn(args ...any)  { l.record(args...) }
func (l *lateCleanupLogger) Error(args ...any) { l.record(args...) }

func (l *lateCleanupLogger) captured() string {
	l.access.Lock()
	defer l.access.Unlock()
	var joined string
	for _, line := range l.lines {
		joined += line + "\n"
	}
	return joined
}

// lateCleanupResult is everything the caller can observe after driving a Close while a Start is
// still in flight.
type lateCleanupResult struct {
	closeErr        error
	secondCloseErr  error
	startErr        error
	runsAfterFirst  int32
	runsAfterSecond int32
	ranAfterClose   bool
	lateCleanupErr  error
	logger          *lateCleanupLogger
}

// runLateCleanupCase blocks a component inside its own Start before it calls Add, returns from
// Close while that Start is still blocked, and only then lets the component acquire and register.
//
// The ordering is enforced by the test, not by timing: the component can only reach Add after the
// test closes `release`, and the test closes it after Close has returned.
func runLateCleanupCase(t *testing.T, lateCleanupErr error) lateCleanupResult {
	t.Helper()
	logger := &lateCleanupLogger{}
	scope := NewScope(context.Background(), logger)

	var (
		cleanupRuns   atomic.Int32
		closeDone     atomic.Bool
		ranAfterClose atomic.Bool
	)

	entered := make(chan struct{})
	release := make(chan struct{})
	component := &lifecycleFunc{name: "late", start: func(stage StartStage, child *Scope) error {
		close(entered)
		<-release
		// The Scope's queue is gone by now, so this runs here and now, on this goroutine.
		child.Add(func() error {
			cleanupRuns.Add(1)
			if closeDone.Load() {
				ranAfterClose.Store(true)
			}
			return lateCleanupErr
		})
		return nil
	}}

	startDone := make(chan error, 1)
	go func() { startDone <- scope.Start("late", component, StartStateStart) }()

	<-entered
	closeErr := scope.Close()
	closeDone.Store(true)
	close(release)
	startErr := <-startDone

	result := lateCleanupResult{
		closeErr:       closeErr,
		startErr:       startErr,
		runsAfterFirst: cleanupRuns.Load(),
		ranAfterClose:  ranAfterClose.Load(),
		lateCleanupErr: lateCleanupErr,
		logger:         logger,
	}
	// closeErr is final: a repeated Close reports the same result and runs nothing again.
	result.secondCloseErr = scope.Close()
	result.runsAfterSecond = cleanupRuns.Load()
	return result
}

// TestScopeCloseDoesNotWaitForAnInFlightStart is the exact completion boundary.
//
// Close joins the drain, not the Start. The component is still inside Start when Close returns, and
// the cleanup it registers afterwards runs on its own goroutine, after the caller already holds the
// Close result. A report claiming "after Box.Close() every in-flight Start has terminated" is wrong
// by exactly this much.
func TestScopeCloseDoesNotWaitForAnInFlightStart(t *testing.T) {
	result := runLateCleanupCase(t, nil)

	require.NoError(t, result.closeErr, "the drain itself had nothing to report")
	require.Error(t, result.startErr,
		"Start must not report success: the Scope closed while the component was starting, so the "+
			"caller would treat a released component as a live one")
	require.ErrorIs(t, result.startErr, context.Canceled,
		"the failure Start reports is the cancellation of the child scope it was handed")
	require.Equal(t, int32(1), result.runsAfterFirst,
		"the late cleanup must still run, exactly once: Add releases it synchronously once the "+
			"queue is gone, which is what keeps the resource from leaking permanently")
	require.Equal(t, int32(1), result.runsAfterSecond,
		"a repeated Close must not run it a second time")
	require.True(t, result.ranAfterClose,
		"the late cleanup observed the already-returned Close: Close returns WITHOUT waiting for a "+
			"Start that had not reached Add")
}

// TestScopeCloseDoesNotFoldInALateCleanupError is the honest half of §7: the late release really can
// fail, and its failure is not part of the result Close already handed out.
//
// The error goes to the log line Add emits; closeErr stays final. Both the first and any later Close
// report the drain's own result, so a caller cannot learn about the late failure from Close at all.
func TestScopeCloseDoesNotFoldInALateCleanupError(t *testing.T) {
	lateErr := errors.New("remove route: operation not permitted")
	result := runLateCleanupCase(t, lateErr)

	require.NoError(t, result.closeErr,
		"the late cleanup's error must NOT be folded into the Close result that was already "+
			"returned: Close reported the drain it joined, and that drain never saw this cleanup")
	require.NoError(t, result.secondCloseErr,
		"closeErr is final - a later Close must not retroactively pick up a post-drain failure")
	require.NotErrorIs(t, result.closeErr, lateErr)
	require.Equal(t, int32(1), result.runsAfterSecond)

	captured := result.logger.captured()
	require.Contains(t, captured, "cleanup registered after close: ",
		"the late failure must still be observable somewhere: the log line Add emits is the only "+
			"place it can appear")
	require.Contains(t, captured, lateErr.Error(),
		"and that log line must carry the real error, not a generic message")
}

// TestScopeLateCleanupIsLoggedRegardlessOfErrorKind keeps the boundary independent of the error
// vocabulary: the drain filter that treats CLOSED and CANCELLED errors as expected does not apply
// here, because a late cleanup never reaches the drain. Whatever it returns is logged and nothing
// else.
func TestScopeLateCleanupIsLoggedRegardlessOfErrorKind(t *testing.T) {
	for _, lateErr := range []error{
		context.Canceled,
		E.Cause(errors.New("close listener"), "already gone"),
	} {
		result := runLateCleanupCase(t, lateErr)
		require.NoError(t, result.closeErr, "late error %v must not reach the close result", lateErr)
		require.Equal(t, int32(1), result.runsAfterSecond)
		require.Contains(t, result.logger.captured(), "cleanup registered after close: ",
			"late error %v must be logged", lateErr)
		require.Contains(t, result.logger.captured(), lateErr.Error())
	}
}

// TestScopeCloseJoinsAnAlreadyStartedDrain is the other half of the boundary, stated positively.
//
// When Close arrives while a drain is already running, it waits for that drain and returns its
// result rather than reporting success for a teardown that has not finished. The second closer is
// released only after the first drain completes, and what it returns is the drain's result, not a
// default nil.
func TestScopeCloseJoinsAnAlreadyStartedDrain(t *testing.T) {
	scope := newContractScope()
	closeErr := errors.New("unmount route: operation not permitted")

	drainEntered := make(chan struct{})
	releaseDrain := make(chan struct{})
	scope.Add(func() error {
		close(drainEntered)
		<-releaseDrain
		return closeErr
	})

	var firstResult error
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		firstResult = scope.Close()
	}()

	// The drain only runs after the state is set to closing, so once this cleanup is executing, a
	// second Close must join it.
	<-drainEntered
	secondDone := make(chan error, 1)
	go func() { secondDone <- scope.Close() }()

	// Bounded observation in the safe direction: a second Close that returned here would have
	// reported the teardown as finished while it was still running. Exceeding the bound only makes
	// this check less sensitive; it can never fail the test spuriously.
	select {
	case early := <-secondDone:
		t.Fatalf("the second Close returned while the first drain was still in progress: %v", early)
	case <-time.After(250 * time.Millisecond):
	}

	close(releaseDrain)
	<-firstDone
	require.ErrorIs(t, <-secondDone, closeErr,
		"the second closer must return the drain's result, not success for a teardown that had not "+
			"finished when it arrived")
	require.ErrorIs(t, firstResult, closeErr)
}

// TestScopeCloseDoesNotWaitForAStartThatNeverRegistered is the same boundary without a late
// cleanup: even a component that registers NOTHING is not waited for.
//
// This is what makes the boundary worth stating. There is no cleanup to run late, so nothing at all
// marks the in-flight Start from the Scope's side: Close returns, the caller may destroy the state
// the component is still using, and no error anywhere records it.
func TestScopeCloseDoesNotWaitForAStartThatNeverRegistered(t *testing.T) {
	scope := newContractScope()

	entered := make(chan struct{})
	release := make(chan struct{})
	var stillInside atomic.Bool
	component := &lifecycleFunc{name: "unregistered", start: func(stage StartStage, child *Scope) error {
		stillInside.Store(true)
		close(entered)
		<-release
		stillInside.Store(false)
		return nil
	}}

	startDone := make(chan error, 1)
	go func() { startDone <- scope.Start("unregistered", component, StartStateStart) }()

	<-entered
	require.NoError(t, scope.Close())
	require.True(t, stillInside.Load(),
		"the component is still inside Start when Close has already returned - Close does not and "+
			"cannot wait for it")
	close(release)
	require.ErrorIs(t, <-startDone, context.Canceled)
}

// TestScopeReentrantCloseFromItsOwnCleanupWouldDeadlock documents, as an executable statement, why
// the re-entrancy that Scope.Close's doc comment calls unsupported is unsupported: a cleanup
// calling Close on the SAME Scope waits for a drain it is itself inside.
//
// The test does not provoke the deadlock. It pins the mechanism - a cleanup runs while the state is
// already scopeClosing, so a nested Close takes the `scopeClosing` branch and waits on the very
// drain that is executing the cleanup - and leaves the hang itself out of the suite, where it could
// only wedge the run.
func TestScopeReentrantCloseFromItsOwnCleanupWouldDeadlock(t *testing.T) {
	scope := newContractScope()
	var reentrantState scopeState
	var reentrantDone chan struct{}

	scope.Add(func() error {
		scope.access.Lock()
		reentrantState = scope.state
		reentrantDone = scope.closeDone
		scope.access.Unlock()
		return nil
	})
	require.NoError(t, scope.Close())

	require.Equal(t, scopeClosing, reentrantState,
		"a cleanup runs while the Scope is in scopeClosing, so a Close from inside it cannot take "+
			"the drain-owning branch")
	require.NotNil(t, reentrantDone)
	require.True(t, channelClosed(reentrantDone),
		"and the channel it would wait on is the one its own drain closes last")
}

// channelClosed reports whether a completion channel is already closed.
func channelClosed(done chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
