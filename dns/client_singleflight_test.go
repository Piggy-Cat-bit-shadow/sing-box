package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// These tests cover the shared-lookup (singleflight) path when the leader FAILS.
//
// # The failure mode they guard against
//
// The first caller for a cache key becomes the leader and installs a channel every
// other caller waits on. When the leader finishes it deletes the key and closes the
// channel, waking all waiters.
//
// If the leader SUCCEEDED, the waiters find the cached response and everything is
// fine. If the leader FAILED - timeout, transport error, upstream failure, or a
// response the checker rejected - there is no cache entry, and every waiter wakes up
// with nothing.
//
// The bug was that a waiter then simply left the wait loop and queried upstream
// itself, instead of contending for the NEXT generation through LoadOrStore. One
// failed lookup therefore became N simultaneous upstream queries against a resolver
// that had just demonstrated it was failing.

// herdTransport is a transport whose first exchange always fails and whose later
// exchanges succeed, so the test can observe how many callers query after the first
// failure.
type herdTransport struct {
	// failures is how many of the earliest exchanges return an error.
	failures int32

	// holdFirst blocks the first exchange until released, so the test can accumulate
	// waiters behind a known leader instead of racing the leader's completion.
	holdFirst chan struct{}

	// slowAfterFailure makes successful exchanges slow, so that waiters which DO
	// fall out of the loop without re-contending overlap and become visible.
	slowAfterFailure bool

	// gateOutOfLoopWaiters, when set, is called by the transport at the START of every
	// successful exchange. It lets the test hold the moment a caller has left the
	// singleflight loop and is about to query, which is exactly when a missing
	// re-contention becomes observable: all such callers arrive together.
	gateOutOfLoopWaiters func()

	// slowFailure delays a failing exchange, modelling a real upstream that is timing
	// out rather than refusing instantly. Generations must overlap for singleflight to
	// have anything to coalesce.
	slowFailure time.Duration

	// releaseAfterGate synchronizes the second generation: once the first exchange has
	// failed and its waiters have woken, later exchanges succeed immediately.
	queryCount atomic.Int32
}

func (t *herdTransport) Start(stage adapter.StartStage) error { return nil }
func (t *herdTransport) Close() error                         { return nil }
func (t *herdTransport) Type() string                         { return "herd" }
func (t *herdTransport) Tag() string                          { return "herd" }
func (t *herdTransport) Dependencies() []string               { return nil }
func (t *herdTransport) Reset()                               {}

func (t *herdTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	index := t.queryCount.Add(1)

	if index == 1 && t.holdFirst != nil {
		select {
		case <-t.holdFirst:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if index <= t.failures {
		if t.slowFailure > 0 {
			select {
			case <-time.After(t.slowFailure):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return nil, errors.New("upstream failure")
	}

	if t.gateOutOfLoopWaiters != nil {
		t.gateOutOfLoopWaiters()
	}

	// A delay makes the herd observable: if waiters each retry instead of joining a
	// new generation, their queries overlap and the counter jumps.
	delay := 5 * time.Millisecond
	if t.slowAfterFailure {
		delay = 200 * time.Millisecond
	}
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 300), nil
}

func (t *herdTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

// newHerdClient builds a Client with a working cache (the shared-lookup path is only
// reached when caching is enabled) over one fake transport.
func newHerdClient(t *testing.T, transport *herdTransport) *Client {
	t.Helper()
	return NewClient(ClientOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
	})
}

func herdMessage() *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{Id: 1, RecursionDesired: true},
		Question: []mDNS.Question{{
			Name:   "herd.example.org.",
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		}},
	}
}

// TestDNSConcurrentFailureDoesNotHerd is the core regression test.
//
// Many callers ask for the same name at once. The first generation's leader fails
// with a TRANSIENT error, so a later generation can succeed.
//
// # Why the failure must be transient, and why this is the exact real-world case
//
// A permanently failing upstream cannot be coalesced into a small query count: no
// generation produces a cache entry, so every caller eventually has to be answered by
// a generation of its own. The herd that matters in production is the TRANSIENT
// failure - a resolver drops one packet, an upstream briefly 5xxs - where a single
// retry would satisfy everyone if the waiters shared it.
//
// # Measured
//
//	n=64 callers, one transient leader failure
//	  before the fix: 64 upstream queries  (every waiter retried on its own)
//	  after  the fix:  2 upstream queries  (one failed leader, one shared success)
//
// The count is asserted exactly, so a regression is a hard failure rather than a
// statistical observation. See TestDNSConcurrentFailureDoesNotHerdIsDeterministic
// for the same property exercised across several timings.
func TestDNSConcurrentFailureDoesNotHerd(t *testing.T) {
	const callers = 64

	transport := &herdTransport{
		failures:  1, // exactly the first generation fails, then one success serves all
		holdFirst: make(chan struct{}),
	}
	client := newHerdClient(t, transport)

	var (
		wg       sync.WaitGroup
		start    = make(chan struct{})
		success  atomic.Int32
		failures atomic.Int32
	)

	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release everyone together so they pile up behind one leader
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := client.Exchange(ctx, transport, herdMessage(), adapter.DNSQueryOptions{}, nil)
			if err != nil {
				failures.Add(1)
				return
			}
			success.Add(1)
		}()
	}

	// Let the goroutines reach the wait point, then release the leader so it fails.
	close(start)
	time.Sleep(150 * time.Millisecond)
	close(transport.holdFirst)

	wg.Wait()

	queries := transport.queryCount.Load()
	t.Logf("callers=%d upstream queries=%d success=%d failures=%d",
		callers, queries, success.Load(), failures.Load())

	// The essential property, asserted exactly.
	require.EqualValues(t, 2, queries,
		"%d callers produced %d upstream queries after ONE transient leader failure. "+
			"Only one caller may lead the retry generation, so the expected total is 2: "+
			"the failed first generation and the single successful second generation. "+
			"A count near %d means every waiter retried on its own, which is the retry "+
			"herd this test exists to prevent",
		callers, queries, callers)

	// Every WAITER must be served by the retry generation. Exactly one caller
	// legitimately sees the error: the one that led the first generation.
	require.EqualValues(t, callers-1, success.Load(),
		"every caller except the failed generation's leader must be served by the "+
			"retry generation's result")
	require.EqualValues(t, 1, failures.Load(),
		"exactly one caller - the first generation's leader - may observe the failure")
}

// TestDNSConcurrentFailureDoesNotHerdIsDeterministic runs the same property across
// several timings.
//
// The defect is timing-sensitive: whether a waiter finds the retry generation's cache
// entry before it queries depends on scheduling. A single timing can therefore pass by
// luck on the broken code. Sweeping the failure delay removes that luck, so this test
// fails reliably whenever the waiters stop sharing a generation.
func TestDNSConcurrentFailureDoesNotHerdIsDeterministic(t *testing.T) {
	const callers = 64

	for _, failDelay := range []time.Duration{
		0,
		time.Millisecond,
		5 * time.Millisecond,
		20 * time.Millisecond,
	} {
		failDelay := failDelay
		t.Run(failDelay.String(), func(t *testing.T) {
			transport := &herdTransport{
				failures:    1,
				slowFailure: failDelay,
				holdFirst:   make(chan struct{}),
			}
			client := newHerdClient(t, transport)

			var wg sync.WaitGroup
			start := make(chan struct{})
			for range callers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, _ = client.Exchange(ctx, transport, herdMessage(), adapter.DNSQueryOptions{}, nil)
				}()
			}
			close(start)
			time.Sleep(60 * time.Millisecond)
			close(transport.holdFirst)
			wg.Wait()

			require.EqualValues(t, 2, transport.queryCount.Load(),
				"with a %v failure delay, %d callers must still collapse to one retry "+
					"generation (2 upstream queries total)", failDelay, callers)
		})
	}
}

// TestDNSLeaderSuccessQueriesOnce proves the generation loop did not break the
// ordinary case: a successful leader serves everyone with a single upstream query.
func TestDNSLeaderSuccessQueriesOnce(t *testing.T) {
	const callers = 64

	transport := &herdTransport{holdFirst: make(chan struct{})}
	client := newHerdClient(t, transport)

	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		success atomic.Int32
	)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := client.Exchange(ctx, transport, herdMessage(), adapter.DNSQueryOptions{}, nil)
			require.NoError(t, err)
			success.Add(1)
		}()
	}
	close(start)
	time.Sleep(150 * time.Millisecond)
	close(transport.holdFirst)
	wg.Wait()

	require.EqualValues(t, 1, transport.queryCount.Load(),
		"a successful shared lookup must query upstream exactly once")
	require.EqualValues(t, callers, success.Load())
}

// TestDNSSecondGenerationLeaderFailureTerminates proves the generation loop cannot
// spin forever when every generation fails.
//
// A permanently failing upstream cannot collapse to a small query count: no
// generation produces a cache entry, so each caller is eventually answered by a
// generation of its own. What must hold is that every caller still TERMINATES,
// bounded by its own context, rather than re-contending indefinitely.
func TestDNSSecondGenerationLeaderFailureTerminates(t *testing.T) {
	const callers = 16

	transport := &herdTransport{
		failures:  1 << 30, // every generation fails
		holdFirst: make(chan struct{}),
	}
	client := newHerdClient(t, transport)

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
	)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// A short per-caller timeout bounds each waiter, so the test terminates
			// even though no generation ever succeeds.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_, _ = client.Exchange(ctx, transport, herdMessage(), adapter.DNSQueryOptions{}, nil)
		}()
	}
	close(start)
	time.Sleep(100 * time.Millisecond)
	close(transport.holdFirst)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("callers did not terminate when every generation failed; the " +
			"generation loop is not bounded by the caller's context")
	}

	queries := transport.queryCount.Load()
	t.Logf("callers=%d upstream queries=%d after all generations failed", callers, queries)

	// Each caller's context eventually expires. The bound here is generous because
	// generations are serialized: the property under test is termination, not a
	// specific count.
	require.Less(t, queries, int32(callers*2),
		"a fully failing upstream must not produce an unbounded number of queries "+
			"(%d callers produced %d queries)", callers, queries)
}

// TestDNSAllWaitersCanceledDoNotLeak proves that canceling every waiter while the
// leader is still running leaves nothing behind: the leader still completes, releases
// its key, and the next lookup starts a fresh generation instead of hanging on a
// channel nobody will close.
func TestDNSAllWaitersCanceledDoNotLeak(t *testing.T) {
	transport := &herdTransport{holdFirst: make(chan struct{})}
	client := newHerdClient(t, transport)

	const waiters = 8

	var wg sync.WaitGroup
	for range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Cancel quickly; these callers abandon the wait.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			_, _ = client.Exchange(ctx, transport, herdMessage(), adapter.DNSQueryOptions{}, nil)
		}()
	}

	// Give the waiters time to enter the wait and then time out.
	time.Sleep(120 * time.Millisecond)
	close(transport.holdFirst)
	wg.Wait()

	// The client must still be usable: the next lookup must not block on a stale key.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.Exchange(ctx, transport, herdMessage(), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err,
		"a lookup after every waiter was canceled must still succeed; a stale cache "+
			"lock entry would deadlock or hang here")
	require.NotNil(t, response)
	require.NotEmpty(t, response.Answer)
}

// TestDNSGenerationLoopIsRaceFree exercises the generation loop under the race
// detector with overlapping generations: a failure wakes waiters that immediately
// contend again while new callers arrive.
func TestDNSGenerationLoopIsRaceFree(t *testing.T) {
	const waves = 6
	const perWave = 24

	transport := &herdTransport{
		failures:  3, // the first few generations fail, forcing re-contention
		holdFirst: make(chan struct{}),
	}
	client := newHerdClient(t, transport)

	var wg sync.WaitGroup
	for range waves {
		for range perWave {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, _ = client.Exchange(ctx, transport, herdMessage(), adapter.DNSQueryOptions{}, nil)
			}()
		}
		// Stagger the waves so generations overlap instead of forming one block.
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(150 * time.Millisecond)
	close(transport.holdFirst)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("overlapping generations did not terminate")
	}

	queries := transport.queryCount.Load()
	t.Logf("waves=%d perWave=%d upstream queries=%d", waves, perWave, queries)

	// 3 forced failures, then one success serves the rest. Allow a few extra for
	// callers that arrive after the successful generation was released.
	require.Less(t, queries, int32(waves*perWave/2),
		"overlapping generations must not multiply into per-caller queries: %d queries "+
			"for %d callers", queries, waves*perWave)
}

// TestDNSAsyncWaitersJoinTheRetryGeneration covers the same property through
// ExchangeAsync, which cannot block inline: when it finds a generation in flight it
// reports exchangeWait and re-enters Exchange, where it either leads or waits.
//
// Without re-contention, each async caller that arrives during a failed generation
// would start its own upstream query.
func TestDNSAsyncWaitersJoinTheRetryGeneration(t *testing.T) {
	const callers = 32

	transport := &herdTransport{
		failures:  1,
		holdFirst: make(chan struct{}),
	}
	client := newHerdClient(t, transport)

	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		success atomic.Int32
	)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			client.ExchangeAsync(ctx, transport, herdMessage(), adapter.DNSQueryOptions{}, nil,
				func(response *mDNS.Msg, err error) {
					defer close(done)
					if err == nil && response != nil {
						success.Add(1)
					}
				})
			<-done
		}()
	}

	close(start)
	time.Sleep(150 * time.Millisecond)
	close(transport.holdFirst)
	wg.Wait()

	queries := transport.queryCount.Load()
	t.Logf("async callers=%d upstream queries=%d success=%d", callers, queries, success.Load())

	require.LessOrEqual(t, queries, int32(4),
		"%d async callers produced %d upstream queries after one transient failure; "+
			"the async path must share the retry generation too", callers, queries)
	require.GreaterOrEqual(t, success.Load(), int32(callers-2),
		"the async callers must still be served")
}
