package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// TD-014: what the serial pool actually does under a concurrent burst, and why.
//
// The audit's item asked for the pool to reuse ONE connection under a burst. That
// is not implementable together with this fork's documented contract, which
// serial_lifecycle_test.go §8 pins as a requirement: concurrent callers are NOT
// queued behind one socket, because queueing them turns a burst into a sequence.
// The pool therefore holds one outstanding query PER CONNECTION (correctness: a
// resolver that refuses pipelining must never see two queries on one socket) and
// allows up to N connections for N concurrent queries.
//
// What the establishment cap does bound is dialing itself: at most MaxInflight
// handshakes are in progress at any moment (see
// TestConnPoolOrderedSerialisesEstablishment). What it does not do, and was never
// meant to do, is turn the burst into one connection.
//
// These tests measure that shape so the trade-off is recorded rather than
// rediscovered: the connection count for a burst, and the fact that no connection
// is ever handed to two callers at once. They are deliberately counts, not
// durations.
// ---------------------------------------------------------------------------

// TestConnPoolOrderedBurstOpensOneConnectionPerCaller records the burst shape: N
// concurrent callers that hold their connection each get their own socket, and
// establishment is serialised behind the cap.
//
// If a future change makes this pool reuse a single connection for concurrent
// callers, this test fails -- deliberately. Reconsidering it means reconsidering
// §8 of serial_lifecycle_test.go, not editing a number here.
func TestConnPoolOrderedBurstOpensOneConnectionPerCaller(t *testing.T) {
	var (
		dials      atomic.Int32
		concurrent atomic.Int32
		peak       atomic.Int32
	)
	pool := NewConnPool(ConnPoolOptions[*int]{
		Mode:        ConnPoolOrdered,
		MaxInflight: 1,
		IsAlive:     func(conn *int) bool { return conn != nil },
		Close:       func(conn *int, cause error) {},
	})
	defer pool.Close()

	dial := func(ctx context.Context) (*int, error) {
		dials.Add(1)
		inFlight := concurrent.Add(1)
		defer concurrent.Add(-1)
		for {
			seen := peak.Load()
			if inFlight <= seen || peak.CompareAndSwap(seen, inFlight) {
				break
			}
		}
		return new(int), nil
	}

	const burst = 8
	start := make(chan struct{})
	var group sync.WaitGroup
	held := make([]*int, burst)
	for index := range burst {
		index := index
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			conn, _, err := pool.Acquire(context.Background(), dial)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			held[index] = conn
			// The query the connection is held for. Every caller is inside this window at
			// the same time, which is what makes it a burst.
			time.Sleep(20 * time.Millisecond)
			pool.Release(conn, true)
		}()
	}
	close(start)
	group.Wait()

	if got := dials.Load(); got != burst {
		t.Fatalf("dials = %d for %d concurrent callers; the serial pool holds one outstanding query per connection, "+
			"so a burst of held queries opens one connection each", got, burst)
	}
	if got := peak.Load(); got != 1 {
		t.Fatalf("peak concurrent establishment = %d, want 1: MaxInflight must serialise handshakes", got)
	}
	// No connection may be handed to two callers at once.
	seen := make(map[*int]bool, burst)
	for index, conn := range held {
		if conn == nil {
			t.Fatalf("caller %d received no connection", index)
		}
		if seen[conn] {
			t.Fatalf("the same connection was handed to two concurrent callers at index %d", index)
		}
		seen[conn] = true
	}
}

// TestConnPoolOrderedReusesASequentialConnection is the other half of the shape:
// sequential callers DO reuse, which is the reuse the serial pool exists for.
func TestConnPoolOrderedReusesASequentialConnection(t *testing.T) {
	var dials atomic.Int32
	pool := NewConnPool(ConnPoolOptions[*int]{
		Mode:        ConnPoolOrdered,
		MaxInflight: 1,
		IsAlive:     func(conn *int) bool { return conn != nil },
		Close:       func(conn *int, cause error) {},
	})
	defer pool.Close()

	dial := func(ctx context.Context) (*int, error) {
		dials.Add(1)
		return new(int), nil
	}

	for query := 0; query < 16; query++ {
		conn, _, err := pool.Acquire(context.Background(), dial)
		if err != nil {
			t.Fatalf("query %d: %v", query, err)
		}
		pool.Release(conn, true)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("16 sequential queries opened %d connections; a sequential resolver is reused", got)
	}
}

// TestConnPoolOrderedInvalidatedConnectionIsRedialed is the correctness guard for
// the reuse above: a connection the pool was told to drop must never be handed out
// again, and the next caller must dial a replacement.
func TestConnPoolOrderedInvalidatedConnectionIsRedialed(t *testing.T) {
	var dials atomic.Int32
	pool := NewConnPool(ConnPoolOptions[*int]{
		Mode:        ConnPoolOrdered,
		MaxInflight: 1,
		IsAlive:     func(conn *int) bool { return conn != nil },
		Close:       func(conn *int, cause error) {},
	})
	defer pool.Close()

	dial := func(ctx context.Context) (*int, error) {
		dials.Add(1)
		return new(int), nil
	}

	first, _, err := pool.Acquire(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}
	// The query failed on a stale socket: the connection must not be handed to the next
	// caller.
	pool.Invalidate(first, context.Canceled)

	second, _, err := pool.Acquire(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}
	pool.Release(second, true)
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want 2 (the invalidated connection must be replaced)", got)
	}
}

// TestConnPoolOrderedCapBoundsConcurrentEstablishment is the property the cap does
// provide: a burst of callers on a cold pool does not turn into a burst of
// simultaneous handshakes.
func TestConnPoolOrderedCapBoundsConcurrentEstablishment(t *testing.T) {
	var (
		concurrent atomic.Int32
		peak       atomic.Int32
		dials      atomic.Int32
	)
	pool := NewConnPool(ConnPoolOptions[*int]{
		Mode:        ConnPoolOrdered,
		MaxInflight: 1,
		IsAlive:     func(conn *int) bool { return conn != nil },
		Close:       func(conn *int, cause error) {},
	})
	defer pool.Close()

	dialStarted := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	dial := func(ctx context.Context) (*int, error) {
		dials.Add(1)
		inFlight := concurrent.Add(1)
		defer concurrent.Add(-1)
		for {
			seen := peak.Load()
			if inFlight <= seen || peak.CompareAndSwap(seen, inFlight) {
				break
			}
		}
		once.Do(func() { close(dialStarted) })
		<-release
		return new(int), nil
	}

	const burst = 6
	var group sync.WaitGroup
	for range burst {
		group.Add(1)
		go func() {
			defer group.Done()
			conn, _, err := pool.Acquire(context.Background(), dial)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			pool.Release(conn, true)
		}()
	}
	<-dialStarted
	// Give the other callers every chance to pile in behind the cap.
	time.Sleep(50 * time.Millisecond)
	if got := peak.Load(); got != 1 {
		t.Fatalf("peak concurrent establishment = %d while one dial was in flight, want 1", got)
	}
	close(release)
	group.Wait()
	// The burst is bounded by the cap (one at a time) but every caller is served.
	if got := dials.Load(); got != burst {
		t.Fatalf("dials = %d, want %d: each concurrent caller is served its own connection", got, burst)
	}
}

// TestTCPTransportBurstUsesOneConnectionPerCaller measures the same shape end to
// end, through the real transport and a resolver that refuses pipelining.
func TestTCPTransportBurstUsesOneConnectionPerCaller(t *testing.T) {
	t.Parallel()
	listener, accepted := newSequentialDNSServer(t)
	transport := newTestTCPTransport(t, listener)

	const burst = 4
	start := make(chan struct{})
	results := make(chan error, burst)
	for range burst {
		go func() {
			<-start
			message := new(mDNS.Msg)
			message.SetQuestion("example.com.", mDNS.TypeA)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := transport.Exchange(ctx, message)
			results <- err
		}()
	}
	close(start)

	for range burst {
		if err := <-results; err != nil {
			t.Fatalf("burst query: %v", err)
		}
	}
	// The queries may be answered on shared or separate connections depending on
	// scheduling; what must hold is the bound: no more connections than callers.
	if got := settle(accepted); got > burst {
		t.Fatalf("%d concurrent queries opened %d connections; the pool must never exceed one per caller", burst, got)
	}
}
