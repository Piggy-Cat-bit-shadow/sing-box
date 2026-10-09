package box

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Close must be idempotent and safe to call concurrently.
//
// # The failure this pins
//
// Box.Close unregistered the pause callback, closed the governor and walked the teardown scope
// with no guard at all. The daemon serialises its own stop against start, but Close is exported
// and the daemon deliberately allows a stop to arrive while Start is still running, so an
// embedder calling Close from a lifecycle callback - or two Closes racing - unregistered the
// same list element twice, closed the same governor twice and walked a scope whose cleanups had
// already been consumed. The scope nil-s the cleanup list on the first Close, which turns a
// repeat into either a silent nothing or a panic depending on which component is reached.
func TestBoxCloseIsIdempotentAndRaceFree(t *testing.T) {
	var cleanups atomic.Int64
	newTestBox := func() *Box {
		ctx := context.Background()
		scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
		scope.Add(func() error {
			cleanups.Add(1)
			return nil
		})
		return &Box{
			ctx:   ctx,
			scope: scope,
		}
	}

	t.Run("sequential", func(t *testing.T) {
		cleanups.Store(0)
		box := newTestBox()
		require.NoError(t, box.Close())
		require.NoError(t, box.Close())
		require.NoError(t, box.Close())
		require.EqualValues(t, 1, cleanups.Load(),
			"teardown must run exactly once however many times Close is called")
	})

	t.Run("concurrent", func(t *testing.T) {
		cleanups.Store(0)
		box := newTestBox()
		const closers = 8
		var (
			waitGroup sync.WaitGroup
			start     = make(chan struct{})
			errs      = make([]error, closers)
		)
		for index := 0; index < closers; index++ {
			waitGroup.Add(1)
			go func(index int) {
				defer waitGroup.Done()
				<-start
				errs[index] = box.Close()
			}(index)
		}
		close(start)
		waitGroup.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}
		require.EqualValues(t, 1, cleanups.Load(),
			"a concurrent second Close must join the first, not tear down again")
	})
}

// The first Close's error is reported to every caller, so a repeated Close does not look like a
// clean shutdown when teardown actually failed.
//
// The injected error is a real teardown failure rather than a cancellation. The two are not
// interchangeable here: Scope.Close deliberately does NOT report an already-closed or cancelled
// cleanup as a failure, because that is the expected outcome of closing during a network transition
// and reporting it makes an orderly shutdown look like a fault. A value chosen merely to be "some
// error" therefore has to be one the close path is supposed to report, or the test would be
// asserting the opposite of the contract. The cancellation case is pinned explicitly below.
func TestBoxCloseRepeatsTheFirstResult(t *testing.T) {
	teardownErr := errors.New("remove route: operation not permitted")

	ctx := context.Background()
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	scope.Add(func() error {
		return teardownErr
	})
	box := &Box{ctx: ctx, scope: scope}

	firstErr := box.Close()
	require.ErrorIs(t, firstErr, teardownErr)
	require.ErrorIs(t, box.Close(), teardownErr)
}

// A close path that a network transition already tore down is not a failure, and a real failure
// travelling with it still is.
//
// Scope.Close is a declared close context: "already closed" and "cancelled" are what closing is
// supposed to produce, so they are filtered from the result - which is what stops an orderly
// shutdown from reporting a fault. The filter is narrow, and this pins both halves at the Box level:
// it must not swallow a real teardown failure, and it must not let a cancellation masquerade as one.
func TestBoxCloseDistinguishesCancellationFromTeardownFailure(t *testing.T) {
	t.Run("cancellation alone is not a failure", func(t *testing.T) {
		ctx := context.Background()
		scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
		scope.Add(func() error { return context.Canceled })
		scope.Add(func() error { return net.ErrClosed })
		box := &Box{ctx: ctx, scope: scope}

		require.NoError(t, box.Close(),
			"a teardown that only observed cancellation and already-closed resources must not be "+
				"reported as a failure")
		require.NoError(t, box.Close(), "and the repeated result is the same")
	})

	t.Run("a real failure survives alongside a cancellation", func(t *testing.T) {
		teardownErr := errors.New("flush cache: no space left on device")

		ctx := context.Background()
		scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
		scope.Add(func() error { return teardownErr })
		scope.Add(func() error { return net.ErrClosed })
		scope.Add(func() error { return context.Canceled })
		box := &Box{ctx: ctx, scope: scope}

		closeErr := box.Close()
		require.ErrorIs(t, closeErr, teardownErr,
			"filtering the expected cancellation must not hide a real teardown failure")
		require.NotErrorIs(t, closeErr, context.Canceled)
		require.NotErrorIs(t, closeErr, net.ErrClosed)
		require.ErrorIs(t, box.Close(), teardownErr, "and every caller sees that failure")
	})
}
