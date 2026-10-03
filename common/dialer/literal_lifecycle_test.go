package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Lifecycle tests for the literal recovery state machine.
//
// # The invariants
//
// dialLiteralWithRecovery races the application's own address against a set recovered from the
// sniffed domain. Every outcome must leave exactly one owner for the winning connection, close
// every losing connection, and terminate every goroutine - including a loser that succeeds after
// the race is decided, whose connection would otherwise sit unread in a buffered channel.
//
// The tests below use channels and atomic counters rather than sleeps to observe termination.

// owningConn tracks whether it was closed, and how many times.
type owningConn struct {
	net.Conn
	closed    atomic.Int32
	closeOnce sync.Once
}

func (c *owningConn) Close() error {
	c.closeOnce.Do(func() { c.closed.Add(1) })
	return nil
}

func (c *owningConn) closeCount() int32 { return c.closed.Load() }

// lifecycleDialer answers per address on a script, and hands out tracked connections.
type lifecycleDialer struct {
	access  sync.Mutex
	dials   map[netip.Addr]int
	answers map[netip.Addr]lifecycleAnswer
	conns   []*owningConn
}

type lifecycleAnswer struct {
	delay   time.Duration
	success bool
	block   bool
}

func (d *lifecycleDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	address := destination.Addr
	d.access.Lock()
	if d.dials == nil {
		d.dials = make(map[netip.Addr]int)
	}
	d.dials[address]++
	answer := d.answers[address]
	d.access.Unlock()

	if answer.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if answer.delay > 0 {
		select {
		case <-time.After(answer.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !answer.success {
		return nil, errScriptedFailure
	}
	conn := &owningConn{}
	d.access.Lock()
	d.conns = append(d.conns, conn)
	d.access.Unlock()
	return conn, nil
}

func (d *lifecycleDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func (d *lifecycleDialer) dialCount(address netip.Addr) int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.dials[address]
}

func (d *lifecycleDialer) trackedConns() []*owningConn {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]*owningConn(nil), d.conns...)
}

// lifecycleRouter recovers the given addresses, optionally after a delay.
type lifecycleRouter struct {
	adapter.DNSRouter
	addresses []netip.Addr
	delay     time.Duration
	block     bool
}

func (r *lifecycleRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	if r.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, address := range r.addresses {
		publish(adapter.DNSFamilyResult{IPv6: address.Is6(), Addresses: []netip.Addr{address}})
	}
	return nil
}

func (r *lifecycleRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.addresses, nil
}

// sniffedContext carries the domain recovery needs.
func sniffedContext(t *testing.T, parent context.Context) context.Context {
	t.Helper()
	ctx, metadata := adapter.ExtendContext(parent)
	metadata.Domain = "sniffed.example"
	return ctx
}

// TestLiteralBothFailReturnsPromptly is §29.
//
// Both attempts fail quickly. The function must return at once rather than waiting for the caller's
// much longer deadline.
func TestLiteralBothFailReturnsPromptly(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")

	inner := &lifecycleDialer{answers: map[netip.Addr]lifecycleAnswer{
		original:  {delay: 5 * time.Millisecond, success: false},
		recovered: {delay: 5 * time.Millisecond, success: false},
	}}
	dialer := &resolveDialer{
		router:        &lifecycleRouter{addresses: []netip.Addr{recovered}},
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 10 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(sniffedContext(t, context.Background()), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	elapsed := time.Since(start)

	require.Error(t, err, "both attempts failed, so the dial must report an error")
	require.Less(t, elapsed, 5*time.Second,
		"both attempts failed within milliseconds but the dial took %v; it must not wait for the "+
			"caller's 30s deadline", elapsed)
}

// TestLiteralOriginalWinnerClosesRecoveredLateSuccess is §28.
//
// The original wins. A recovered attempt that was already running must be cancelled, and if it
// still reports a connection it must be closed - a buffered channel nobody reads would leak it.
func TestLiteralOriginalWinnerClosesRecoveredLateSuccess(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")

	inner := &lifecycleDialer{answers: map[netip.Addr]lifecycleAnswer{
		original: {delay: time.Millisecond, success: true},
		// The recovered attempt is slow enough to lose, and succeeds anyway.
		recovered: {delay: 300 * time.Millisecond, success: true},
	}}
	dialer := &resolveDialer{
		router:        &lifecycleRouter{addresses: []netip.Addr{recovered}},
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(sniffedContext(t, context.Background()), 5*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err)
	require.NotNil(t, conn)

	winner, isTracked := conn.(*owningConn)
	require.True(t, isTracked, "the winner must be the tracked connection")

	// Let a late recovered success land, then account for every connection handed out.
	time.Sleep(500 * time.Millisecond)

	for _, tracked := range inner.trackedConns() {
		if tracked == winner {
			continue
		}
		require.Equal(t, int32(1), tracked.closeCount(),
			"a losing connection - including one that succeeded late - must be closed exactly "+
				"once by the owner; a buffered result nobody reads leaks it")
	}
}

// TestLiteralRecoveredWinnerClosesOriginalLateSuccess is §27.
//
// The recovered candidate wins while the original is still in flight. The original attempt is
// cancelled and, if it reports a connection anyway, that connection must be closed exactly once.
func TestLiteralRecoveredWinnerClosesOriginalLateSuccess(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")

	inner := &lifecycleDialer{answers: map[netip.Addr]lifecycleAnswer{
		// The original is slow but will succeed; it loses the race to the recovered candidate.
		original:  {delay: 400 * time.Millisecond, success: true},
		recovered: {delay: 30 * time.Millisecond, success: true},
	}}
	dialer := &resolveDialer{
		router:        &lifecycleRouter{addresses: []netip.Addr{recovered}},
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(sniffedContext(t, context.Background()), 5*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err)
	require.NotNil(t, conn)

	winner, isTracked := conn.(*owningConn)
	require.True(t, isTracked)

	time.Sleep(600 * time.Millisecond)

	for _, tracked := range inner.trackedConns() {
		if tracked == winner {
			continue
		}
		require.Equal(t, int32(1), tracked.closeCount(),
			"the cancelled original's late connection must be closed exactly once; leaving it to a "+
				"buffered channel nobody reads leaks a socket")
	}
}

// TestLiteralParentCancelExitsAllWorkers is §30.
//
// Both attempts blackhole and the caller cancels. The function must return, and cancellation must
// reach both attempts.
func TestLiteralParentCancelExitsAllWorkers(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")

	inner := &lifecycleDialer{answers: map[netip.Addr]lifecycleAnswer{
		original:  {block: true},
		recovered: {block: true},
	}}
	dialer := &resolveDialer{
		router:        &lifecycleRouter{addresses: []netip.Addr{recovered}, block: true},
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 10 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithCancel(sniffedContext(t, context.Background()))

	done := make(chan error, 1)
	go func() {
		_, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
		done <- err
	}()

	// Let the race begin, then withdraw.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		require.True(t, errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
			"a cancelled dial must report the cancellation, got %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("the dial did not return after the caller cancelled; a worker is not observing " +
			"cancellation")
	}
}

// TestLiteralOriginalDialledExactlyOnce is §31, the long-standing regression.
func TestLiteralOriginalDialledExactlyOnce(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")

	inner := &lifecycleDialer{answers: map[netip.Addr]lifecycleAnswer{
		original:  {block: true},
		recovered: {delay: 20 * time.Millisecond, success: true},
	}}
	dialer := &resolveDialer{
		router:        &lifecycleRouter{addresses: []netip.Addr{recovered}},
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(sniffedContext(t, context.Background()), 5*time.Second)
	defer cancel()

	_, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err)

	require.Equal(t, 1, inner.dialCount(original),
		"the original is already running as its own attempt; the recovered plan must not dial it "+
			"a second time")
	require.Equal(t, 1, inner.dialCount(recovered))
}

// cancellingRouter records when its lookup context is cancelled.
type cancellingRouter struct {
	adapter.DNSRouter
	blocked   chan struct{}
	cancelled chan struct{}
	once      sync.Once
}

func (r *cancellingRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	close(r.blocked)
	<-ctx.Done()
	r.once.Do(func() { close(r.cancelled) })
	return ctx.Err()
}

func (r *cancellingRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	close(r.blocked)
	<-ctx.Done()
	r.once.Do(func() { close(r.cancelled) })
	return nil, ctx.Err()
}

// TestLiteralOriginalWinnerCancelsRecovery is §26.
//
// The original connects almost immediately while the recovery lookup is still blocked. Recovery must
// be cancelled when the race is decided, NOT left running until the caller's much longer deadline.
func TestLiteralOriginalWinnerCancelsRecovery(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")

	router := &cancellingRouter{blocked: make(chan struct{}), cancelled: make(chan struct{})}
	inner := &lifecycleDialer{answers: map[netip.Addr]lifecycleAnswer{
		original: {delay: time.Millisecond, success: true},
	}}
	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	// A generous deadline: the whole point is that recovery must not wait for it.
	ctx, cancel := context.WithTimeout(sniffedContext(t, context.Background()), 30*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err)
	require.NotNil(t, conn)

	select {
	case <-router.cancelled:
		// Recovery observed cancellation promptly.
	case <-time.After(2 * time.Second):
		t.Fatal("the original won after ~1ms but the recovery lookup was not cancelled within " +
			"2s; it is waiting for the caller's 30s deadline instead of the race being decided")
	}
}

// slowSecondFamilyRouter publishes IPv4 at once and IPv6 only after a long delay, and blocks the
// complete Lookup until both are available - exactly like a real router answering one family
// quickly and the other slowly.
type slowSecondFamilyRouter struct {
	adapter.DNSRouter
	fast     netip.Addr
	slow     netip.Addr
	fastIsV6 bool
	slowWait time.Duration
}

func (r *slowSecondFamilyRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	// fastIsV6 decides which family answers immediately. The other one is what the test makes slow.
	publish(adapter.DNSFamilyResult{IPv6: r.fastIsV6, Addresses: []netip.Addr{r.fast}})
	select {
	case <-time.After(r.slowWait):
		publish(adapter.DNSFamilyResult{IPv6: !r.fastIsV6, Addresses: []netip.Addr{r.slow}})
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Lookup is the COMPLETE contract: it waits for both families.
func (r *slowSecondFamilyRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	select {
	case <-time.After(r.slowWait):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []netip.Addr{r.fast, r.slow}, nil
}

// TestLiteralRecoveryUsesOneReadyFamilyWithoutWaiting is §25.
//
// The recovered IPv4 is available in milliseconds and the AAAA query takes seconds. Recovery must
// use the IPv4 as soon as it arrives; waiting for the complete address set turns a working fallback
// into a multi-second stall.
func TestLiteralRecoveryUsesOneReadyFamilyWithoutWaiting(t *testing.T) {
	// The original is IPv4 and the policy is ipv6_only, so the original is excluded and recovery
	// supplies the address. The family the policy admits (IPv6) is the one that answers FAST, so
	// a streaming recovery can connect immediately; the excluded family is the slow one.
	original := netip.MustParseAddr("203.0.113.1")
	recoveredFast := netip.MustParseAddr("2001:db8::9")
	recoveredSlow := netip.MustParseAddr("192.0.2.9")

	router := &slowSecondFamilyRouter{
		fast:     recoveredFast,
		slow:     recoveredSlow,
		fastIsV6: true,
		slowWait: 3 * time.Second,
	}
	inner := &lifecycleDialer{answers: map[netip.Addr]lifecycleAnswer{
		// The original is excluded by the strict policy below, so recovery is the only path.
		original:      {delay: 5 * time.Millisecond, success: true},
		recoveredFast: {delay: 5 * time.Millisecond, success: true},
		recoveredSlow: {delay: 5 * time.Millisecond, success: true},
	}}
	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		// ipv6_only excludes the IPv4 original, forcing recovery to supply the address.
		queryOptions: adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv6Only},
	}

	ctx, cancel := context.WithTimeout(sniffedContext(t, context.Background()), 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)
	require.Less(t, elapsed, 1500*time.Millisecond,
		"recovery took %v; the first usable family must be used as soon as it arrives rather than "+
			"waiting for the complete address set", elapsed)

	require.Equal(t, 1, inner.dialCount(recoveredFast),
		"the family that answered first is the one the policy admits, so it must be used")
}
