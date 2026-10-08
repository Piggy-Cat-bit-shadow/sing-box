package box

import (
	"context"
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
func TestBoxCloseRepeatsTheFirstResult(t *testing.T) {
	ctx := context.Background()
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	scope.Add(func() error {
		return context.Canceled
	})
	box := &Box{ctx: ctx, scope: scope}

	firstErr := box.Close()
	require.ErrorIs(t, firstErr, context.Canceled)
	require.ErrorIs(t, box.Close(), context.Canceled)
}
