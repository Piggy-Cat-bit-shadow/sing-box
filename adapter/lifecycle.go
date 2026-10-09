package adapter

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

type SimpleLifecycle interface {
	Start() error
	Close() error
}

type StartStage uint8

const (
	StartStateInitialize StartStage = iota
	StartStateStart
	StartStatePostStart
	StartStateStarted
)

var ListStartStages = []StartStage{
	StartStateInitialize,
	StartStateStart,
	StartStatePostStart,
	StartStateStarted,
}

func (s StartStage) String() string {
	switch s {
	case StartStateInitialize:
		return "initialize"
	case StartStateStart:
		return "start"
	case StartStatePostStart:
		return "post-start"
	case StartStateStarted:
		return "finish-start"
	default:
		panic("unknown stage")
	}
}

type Lifecycle interface {
	Start(stage StartStage, scope *Scope) error
}

type LifecycleService interface {
	Name() string
	Lifecycle
}

// scopeState is the Scope's lifecycle state. It exists because Start, Add and Close are called from
// different goroutines and the product relies on the outcome of every interleaving:
//
//   - A component's Start runs OUTSIDE the Scope's lock, so Close can take the cleanup queue and
//     finish while that Start is still running. Anything the component registers afterwards would be
//     appended to a queue nobody walks again, so Add has to know the queue is gone.
//   - Close is exported and, as box.go notes, an embedder may call it from any goroutine while Start
//     is still running - which the daemon deliberately allows. A second Close must therefore join the
//     first instead of reporting SUCCESS for a teardown that has not finished.
type scopeState uint8

const (
	// scopeOpen accepts new cleanups and new starts.
	scopeOpen scopeState = iota
	// scopeClosing has taken the cleanup queue and is running it. New cleanups are released
	// immediately and new starts are refused.
	scopeClosing
	// scopeClosed has finished. closeErr is final.
	scopeClosed
)

type Scope struct {
	ctx    context.Context
	cancel context.CancelFunc
	logger log.ContextLogger

	access   sync.Mutex
	state    scopeState
	cleanups []func() error
	// closeDone is closed when the drain the first Close started has finished. A later Close waits
	// on it rather than returning before the result is known. It is a channel, not a goroutine: no
	// goroutine is created to wait and none can be abandoned.
	closeDone chan struct{}
	closeErr  error
	children  map[Lifecycle]*Scope
}

func NewScope(ctx context.Context, logger log.ContextLogger) *Scope {
	ctx, cancel := context.WithCancel(ctx)
	return &Scope{
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		children: make(map[Lifecycle]*Scope),
	}
}

func (s *Scope) Context() context.Context {
	return s.ctx
}

// Add hands a cleanup to the Scope.
//
// While the Scope is open the cleanup is queued and runs when Close drains the queue in reverse
// registration order.
//
// Once the Scope has begun closing the queue has been taken and nothing will walk it again, so the
// cleanup runs HERE, on the caller's goroutine, before Add returns. Dropping it would leak the
// resource it owns permanently and without a diagnostic - and the case is reachable rather than
// theoretical: box.go allows Close to run while Start is still in flight, and every dynamic
// sub-scope in this tree (the DNS resolvers of openvpn/openconnect/tailscale, the systemd-resolved
// and DHCP server scopes) starts transports into a scope that another goroutine may be replacing.
//
// The cleanup is never run while the lock is held: it is an external Close and may take locks of its
// own, which is a reentrancy the original code was careful to avoid as well.
func (s *Scope) Add(cleanup func() error) {
	s.access.Lock()
	if s.state == scopeOpen {
		s.cleanups = append(s.cleanups, cleanup)
		s.access.Unlock()
		return
	}
	s.access.Unlock()
	err := cleanup()
	if err != nil && s.logger != nil {
		s.logger.Error("cleanup registered after close: ", err)
	}
}

func (s *Scope) Start(name string, component Lifecycle, stage StartStage) error {
	s.access.Lock()
	err := s.ctx.Err()
	if err != nil {
		s.access.Unlock()
		return err
	}
	child, loaded := s.children[component]
	if !loaded {
		child = NewScope(s.ctx, s.logger)
		s.children[component] = child
		s.cleanups = append(s.cleanups, func() error {
			done := LogElapsed(s.logger, "close ", name)
			monitor := taskmonitor.New(s.logger, C.StopTimeout)
			monitor.Start("close ", name)
			closeErr := child.Close()
			monitor.Finish()
			done()
			if closeErr != nil {
				return E.Cause(closeErr, "close ", name)
			}
			return nil
		})
	}
	s.access.Unlock()
	done := LogElapsed(s.logger, stage, " ", name)
	monitor := taskmonitor.New(s.logger, C.StartTimeout)
	monitor.Start(stage, " ", name)
	err = component.Start(stage, child)
	monitor.Finish()
	done()
	if err != nil {
		return E.Cause(err, stage, " ", name)
	}
	// The component must not report success for a Scope that was cancelled while it was starting.
	//
	// Close does not wait for an in-flight Start, because nothing bounds how long a component's
	// Start may take. Whatever that component registered has already been released - Add on a
	// closing Scope runs the cleanup immediately - so a nil return here would tell the caller a live
	// component exists when none does, and the caller would go on to use it.
	if ctxErr := child.Context().Err(); ctxErr != nil {
		return E.Cause(ctxErr, stage, " ", name)
	}
	return nil
}

// Close releases everything the Scope owns and marks it closed.
//
// It is safe to call concurrently and repeatedly. The first caller cancels the context, takes the
// cleanup queue and runs it in reverse registration order; every later caller waits for that drain
// and returns its result. That is what makes two concurrent Closes agree: a closer that returned
// early would report SUCCESS for a teardown that had not happened and might still fail, leaving the
// caller unable to tell a clean close from a broken one.
//
// # The completion boundary
//
// Close waits for the drain, and for nothing else. When it returns, every cleanup that was in the
// queue has run and closeErr is final. It does NOT wait for a Start that is already running and has
// not reached Add yet, because nothing bounds how long a component's Start may take and waiting for
// one would make Close unbounded. The return of Close therefore must NOT be read as "every in-flight
// Start has terminated":
//
//   - a component still inside Start when Close returns carries on running, and can acquire - and
//     then release - resources after Close returned;
//   - the cleanup such a component registers afterwards runs synchronously inside Add, on that
//     caller's goroutine. That is what stops those resources from leaking permanently, but it
//     happens AFTER Close returned, so it is not part of the teardown Close reported;
//   - if that late cleanup returns an error, Add logs it and does nothing else. The error is not
//     folded into the closeErr that was already returned, and closeErr is final, so a later Close
//     does not pick it up either. Only the log records it.
//
// A Start that was in flight is told the Scope is gone through its own context and must report
// failure rather than success; see Scope.Start.
//
// The wait is bounded by the drain itself and creates no goroutine, so there is nothing to abandon if
// a cleanup blocks. Close is NOT reentrant from a cleanup running on the SAME Scope: such a call
// would be waiting for the drain it is itself inside. Closing a nested Scope from a parent's cleanup
// is the supported direction and is what every dynamic sub-scope in this tree does.
func (s *Scope) Close() error {
	s.access.Lock()
	switch s.state {
	case scopeClosed:
		err := s.closeErr
		s.access.Unlock()
		return err
	case scopeClosing:
		done := s.closeDone
		s.access.Unlock()
		<-done
		s.access.Lock()
		err := s.closeErr
		s.access.Unlock()
		return err
	}
	s.state = scopeClosing
	s.cancel()
	cleanups := s.cleanups
	s.cleanups = nil
	s.children = nil
	s.closeDone = make(chan struct{})
	done := s.closeDone
	s.access.Unlock()
	// Expand each cleanup's result before judging it.
	//
	// A single cleanup can return an aggregate. Judging that aggregate as a unit would discard a
	// real failure merely because a closed or cancelled error travelled with it, which is the one
	// way a filter this narrow is able to hide a fault.
	var (
		cleanupErrors []error
		err           error
	)
	for _, cleanup := range slices.Backward(cleanups) {
		cleanupErrors = append(cleanupErrors, E.Expand(cleanup())...)
	}
	for _, cleanupErr := range cleanupErrors {
		if cleanupErr == nil {
			continue
		}
		// Scope.Close is a DECLARED close context. A resource that is already gone, or one whose
		// context was cancelled, reports the expected outcome of closing rather than a failure of
		// it; aggregating those into the result makes an orderly shutdown look like a fault, which
		// is the same rule this project applies elsewhere - a local cancellation is not a remote
		// failure.
		//
		// The filter is narrow and local on purpose. The same errors on a business I/O path are not
		// harmless, and nothing outside this function filters them.
		if E.IsClosed(cleanupErr) || E.IsCanceled(cleanupErr) {
			// Removing an error from the RESULT is a decision about what the caller can act on, not
			// a reason to lose the observation: the record of what the close saw is what makes a
			// double release or an unexpected cancellation visible at all.
			if s.logger != nil {
				s.logger.Debug("cleanup observed during close: ", cleanupErr)
			}
			continue
		}
		err = E.Errors(err, cleanupErr)
	}
	s.access.Lock()
	s.closeErr = err
	s.state = scopeClosed
	s.access.Unlock()
	close(done)
	return err
}

func LogElapsed(logger log.ContextLogger, description ...any) func() {
	prefix := F.ToString(description...)
	startTime := time.Now()
	timer := time.AfterFunc(time.Second, func() {
		logger.Trace(prefix, "...")
	})
	return func() {
		if timer.Stop() {
			return
		}
		logger.Trace(prefix, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
	}
}
