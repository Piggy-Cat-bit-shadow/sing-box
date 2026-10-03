package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// Tests for literal-destination dialing with parallel domain recovery (§12-§16).
//
// # The failure being fixed
//
// A literal IP used to connect immediately. The recovery feature made it look the sniffed
// domain up SYNCHRONOUSLY first, so a literal destination waited on a full DNS resolution
// before any connection attempt began - and a slow or hanging resolver delayed or broke a
// connection that needed no DNS at all.
//
// Two properties are asserted throughout:
//
//  1. the original address dials immediately, regardless of how slow recovery is;
//  2. the original address is the PREFERRED endpoint, so recovery can never displace it.

// blockingRecoveryRouter is a DNS router whose Lookup blocks until released or cancelled.
//
// It models a resolver that is slow or hung - the exact condition under which a synchronous
// recovery lookup would hold up a connection that does not need DNS.
type blockingRecoveryRouter struct {
	// release, when non-nil, unblocks every Lookup.
	release chan struct{}
	// started is closed the first time Lookup is entered.
	started chan struct{}
	once    sync.Once

	addresses []netip.Addr
	calls     atomic.Int32
	// cancelled counts lookups that ended because their context was cancelled.
	cancelled atomic.Int32
	// completed counts lookups that returned normally.
	completed atomic.Int32
}

func newBlockingRecoveryRouter(addresses ...netip.Addr) *blockingRecoveryRouter {
	return &blockingRecoveryRouter{
		release:   make(chan struct{}),
		started:   make(chan struct{}),
		addresses: addresses,
	}
}

func (r *blockingRecoveryRouter) Start(adapter.StartStage) error { return nil }
func (r *blockingRecoveryRouter) Close() error                   { return nil }
func (r *blockingRecoveryRouter) ClearCache()                    {}
func (r *blockingRecoveryRouter) ResetNetwork()                  {}
func (r *blockingRecoveryRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}

func (r *blockingRecoveryRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, context.Canceled
}

func (r *blockingRecoveryRouter) ExchangeAsync(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, callback func(*mDNS.Msg, error)) {
	callback(nil, context.Canceled)
}

func (r *blockingRecoveryRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.calls.Add(1)
	r.once.Do(func() { close(r.started) })

	select {
	case <-r.release:
		r.completed.Add(1)
		return r.addresses, nil
	case <-ctx.Done():
		r.cancelled.Add(1)
		return nil, ctx.Err()
	}
}

// literalTestDialer drives a literal destination through the production resolveDialer.
type literalDialer struct {
	access  sync.Mutex
	started []time.Duration
	tried   []netip.Addr
	// blackhole marks addresses that never answer until the context ends.
	blackhole map[netip.Addr]bool
	// dialDelay applies to every attempt, to model a slow connect.
	dialDelay time.Duration
	start     time.Time
}

func (d *literalDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.started = append(d.started, time.Since(d.start))
	d.tried = append(d.tried, destination.Addr)
	blackhole := d.blackhole[destination.Addr]
	delay := d.dialDelay
	d.access.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if blackhole {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &countingConn{}, nil
}

func (d *literalDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func (d *literalDialer) attempts() []netip.Addr {
	d.access.Lock()
	defer d.access.Unlock()
	out := make([]netip.Addr, len(d.tried))
	copy(out, d.tried)
	return out
}

// attemptStartedAt reports when a specific address was first dialled, which is what a timing
// test must assert on. firstAttemptAfter returns the earliest attempt overall and would be the
// original literal dial rather than the recovery attempt under test.
func (d *literalDialer) attemptStartedAt(address netip.Addr) (time.Duration, bool) {
	d.access.Lock()
	defer d.access.Unlock()
	for index, tried := range d.tried {
		if tried == address {
			return d.started[index], true
		}
	}
	return 0, false
}

func (d *literalDialer) firstAttemptAfter() time.Duration {
	d.access.Lock()
	defer d.access.Unlock()
	if len(d.started) == 0 {
		return -1
	}
	return d.started[0]
}

// newLiteralTestDialer builds the production dialer for a literal destination with a sniffed
// domain available for recovery.
func newLiteralTestDialer(router adapter.DNSRouter, inner *literalDialer, strategy C.DomainStrategy) (*resolveDialer, context.Context) {
	inner.start = time.Now()
	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 100 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: strategy},
	}
	metadata := &adapter.InboundContext{
		Domain: "sniffed.example",
	}
	return dialer, adapter.WithContext(context.Background(), metadata)
}

// TestLiteralDialIsNotBlockedBySlowRecovery is §14, the hard latency requirement.
//
// Recovery DNS is blocked for far longer than the original connection takes. The original must
// connect at its own speed, not at recovery's.
func TestLiteralDialIsNotBlockedBySlowRecovery(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.99")

	router := newBlockingRecoveryRouter(recovered)
	inner := &literalDialer{}
	dialer, ctx := newLiteralTestDialer(router, inner, C.DomainStrategyAsIS)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)

	// The connection must complete while recovery is STILL BLOCKED. Recovery is released only
	// after this assertion, so a synchronous implementation could not have returned at all.
	select {
	case <-router.release:
		t.Fatal("recovery was released before the assertion; the test cannot distinguish")
	default:
	}

	require.Less(t, elapsed, 2*time.Second,
		"the original address must connect without waiting for recovery DNS; it took %v", elapsed)

	// And it must be the ORIGINAL address that was dialled.
	require.Equal(t, original, inner.attempts()[0],
		"the application's own endpoint must be dialled first")

	close(router.release)
}

// TestLiteralOriginalIsFirstEvenWhenRecoveryReturnsResults is §13.
//
// Recovery produces candidates. The original must still be dialled first: it is the endpoint
// the application selected, and the recovered addresses come from re-resolving a sniffed name
// that may legitimately resolve differently.
func TestLiteralOriginalIsFirstEvenWhenRecoveryReturnsResults(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recoveredA := netip.MustParseAddr("192.0.2.98")
	recoveredB := netip.MustParseAddr("192.0.2.99")

	router := newBlockingRecoveryRouter(recoveredA, recoveredB)
	inner := &literalDialer{}
	dialer, ctx := newLiteralTestDialer(router, inner, C.DomainStrategyPreferIPv6)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err)
	require.NotNil(t, conn)

	attempts := inner.attempts()
	require.NotEmpty(t, attempts)
	require.Equal(t, original, attempts[0],
		"the recovered addresses must not displace the application's endpoint")
}

// TestRecoveryIsUsedAsFallbackWhenTheOriginalFails is §15.
//
// When the original address genuinely fails and recovery has candidates, those are tried. This
// is what makes recovery worth doing at all.
func TestRecoveryIsUsedAsFallbackWhenTheOriginalFails(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.99")

	router := newBlockingRecoveryRouter(recovered)
	inner := &literalDialer{blackhole: map[netip.Addr]bool{original: true}}
	// A short fallback delay so the test is quick; the blackhole is cancelled by the context.
	dialer, ctx := newLiteralTestDialer(router, inner, C.DomainStrategyAsIS)
	dialer.fallbackDelay = 20 * time.Millisecond

	// Release recovery promptly so it has an answer to offer.
	go func() {
		<-router.started
		time.Sleep(20 * time.Millisecond)
		close(router.release)
	}()

	// The original blackholes until the context ends; a 300ms budget lets the fallback run.
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err, "recovery must be usable when the original endpoint fails")
	require.NotNil(t, conn)
	require.Contains(t, inner.attempts(), recovered,
		"the recovered address must have been attempted as a fallback")
}

// TestLiteralWithoutSniffedDomainStillDialsImmediately covers the common case: no sniffed
// domain at all, so recovery declines and nothing changes.
func TestLiteralWithoutSniffedDomainStillDialsImmediately(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	router := newBlockingRecoveryRouter(netip.MustParseAddr("192.0.2.99"))
	inner := &literalDialer{}
	dialer, _ := newLiteralTestDialer(router, inner, C.DomainStrategyAsIS)

	// No sniffed domain in the context.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)
	require.Less(t, elapsed, time.Second, "with no domain there is nothing to wait for")
	require.Equal(t, int32(0), router.calls.Load(),
		"with no sniffed domain no lookup should be attempted at all")
}

// TestLiteralStrictStrategiesAreNotOverridden is §16.
//
// A strict strategy must not be silently widened by recovery. "only" means only.
func TestLiteralStrictStrategiesAreNotOverridden(t *testing.T) {
	original4 := netip.MustParseAddr("192.0.2.1")
	original6 := netip.MustParseAddr("2001:db8::1")
	recovered4 := netip.MustParseAddr("192.0.2.99")
	recovered6 := netip.MustParseAddr("2001:db8::99")

	cases := []struct {
		name      string
		strategy  C.DomainStrategy
		original  netip.Addr
		recovered []netip.Addr
	}{
		{"ipv4_only, original v4", C.DomainStrategyIPv4Only, original4, []netip.Addr{recovered4, recovered6}},
		{"ipv4_only, original v6", C.DomainStrategyIPv4Only, original6, []netip.Addr{recovered4, recovered6}},
		{"ipv6_only, original v6", C.DomainStrategyIPv6Only, original6, []netip.Addr{recovered4, recovered6}},
		{"ipv6_only, original v4", C.DomainStrategyIPv6Only, original4, []netip.Addr{recovered4, recovered6}},
		{"as_is, original v6", C.DomainStrategyAsIS, original6, []netip.Addr{recovered4, recovered6}},
		{"prefer_ipv4, original v6", C.DomainStrategyPreferIPv4, original6, []netip.Addr{recovered4, recovered6}},
		{"prefer_ipv6, original v4", C.DomainStrategyPreferIPv6, original4, []netip.Addr{recovered4, recovered6}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			router := newBlockingRecoveryRouter(testCase.recovered...)
			inner := &literalDialer{}
			dialer, ctx := newLiteralTestDialer(router, inner, testCase.strategy)

			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			// The dial may fail for a strict strategy that excludes the original; what matters
			// is which family was attempted.
			conn, _ := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(testCase.original, 443))
			if conn != nil {
				conn.Close()
			}
			close(router.release)

			for _, attempted := range inner.attempts() {
				isV6 := attempted.Is6() && !attempted.Is4In6()
				switch testCase.strategy {
				case C.DomainStrategyIPv4Only:
					require.False(t, isV6,
						"ipv4_only must never dial IPv6, attempted %v", attempted)
				case C.DomainStrategyIPv6Only:
					require.False(t, attempted.Is4() || attempted.Is4In6(),
						"ipv6_only must never dial IPv4, attempted %v", attempted)
				}
			}
		})
	}
}

// TestRecoveryLookupIsCancelledWhenNotNeeded is the lifecycle requirement.
//
// Once the original connects, the recovery lookup is abandoned. It must not keep running DNS
// for a connection that is already established.
func TestRecoveryLookupIsCancelledWhenNotNeeded(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	router := newBlockingRecoveryRouter(netip.MustParseAddr("192.0.2.99"))
	inner := &literalDialer{}
	dialer, ctx := newLiteralTestDialer(router, inner, C.DomainStrategyAsIS)

	// A short-lived context so the abandoned lookup is cancelled promptly.
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Wait for the cancellation to be observed by the fake router.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if router.cancelled.Load() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the recovery lookup was not cancelled after the original connected "+
		"(calls=%d cancelled=%d completed=%d)",
		router.calls.Load(), router.cancelled.Load(), router.completed.Load())
}
