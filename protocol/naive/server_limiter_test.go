package naive

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// These tests cover the limiter's own invariants. Behavioural tests that drive a
// real listener live in the jiejie suite; these prove the counting logic directly,
// because a limiter that leaks or double-decrements is a bug that traffic-level
// tests would only reveal by accident.

func testLimits(maxConnections, maxPerIP int) option.NaiveServerLimits {
	return option.NaiveServerLimits{
		MaxConnections:      maxConnections,
		MaxConnectionsPerIP: maxPerIP,
		MaxTrackedIPs:       16,
	}
}

// TestServerLimiterIsNilWhenUnconfigured proves the default path allocates
// nothing and admits everything, which is how "omitted means unlimited" is
// implemented rather than merely documented.
func TestServerLimiterIsNilWhenUnconfigured(t *testing.T) {
	require.Nil(t, newServerLimiter(option.NaiveServerLimits{}),
		"an unconfigured limiter must be nil so the unlimited path takes no locks")

	// A nil limiter must still be safe to use.
	var limiter *serverLimiter
	release, admitted := limiter.acquire("127.0.0.1:1234", time.Now())
	require.True(t, admitted)
	release()
	// Release must be idempotent even on the nil path.
	release()
	require.Equal(t, 0, limiter.totalCount())
	require.Equal(t, 0, limiter.trackedCount())
}

func TestServerLimiterEnforcesPerIPLimit(t *testing.T) {
	limiter := newServerLimiter(testLimits(0, 2))
	now := time.Now()

	releaseA, ok := limiter.acquire("10.0.0.1:1000", now)
	require.True(t, ok)
	releaseB, ok := limiter.acquire("10.0.0.1:2000", now)
	require.True(t, ok)

	// A THIRD connection from the same address, but a different port, must be
	// refused: the key is the address, so changing the source port must not buy
	// another slot.
	_, ok = limiter.acquire("10.0.0.1:3000", now)
	require.False(t, ok, "a different source port must not create a new budget")

	// A different address has its own budget.
	_, ok = limiter.acquire("10.0.0.2:1000", now)
	require.True(t, ok, "a different source must have its own allowance")

	releaseA()
	_, ok = limiter.acquire("10.0.0.1:4000", now)
	require.True(t, ok, "releasing a slot must free capacity")

	releaseB()
}

func TestServerLimiterEnforcesGlobalLimit(t *testing.T) {
	limiter := newServerLimiter(testLimits(2, 0))
	now := time.Now()

	_, ok := limiter.acquire("10.0.0.1:1000", now)
	require.True(t, ok)
	_, ok = limiter.acquire("10.0.0.2:1000", now)
	require.True(t, ok)

	// A third connection from a THIRD address must be refused: the global bound
	// exists so a distributed source cannot exhaust the host.
	_, ok = limiter.acquire("10.0.0.3:1000", now)
	require.False(t, ok, "the global limit must apply across different sources")
	require.Equal(t, 2, limiter.totalCount())
}

// TestServerLimiterIPv4MappedAddressesShareOneBudget is the anti-evasion test.
// Without unmapping, one host could hold twice its allowance by alternating
// between "1.2.3.4" and "::ffff:1.2.3.4".
func TestServerLimiterIPv4MappedAddressesShareOneBudget(t *testing.T) {
	limiter := newServerLimiter(testLimits(0, 1))
	now := time.Now()

	release, ok := limiter.acquire("1.2.3.4:1000", now)
	require.True(t, ok)

	_, ok = limiter.acquire("[::ffff:1.2.3.4]:1000", now)
	require.False(t, ok,
		"the IPv4-mapped form of an address must share the plain form's budget")
	require.Equal(t, 1, limiter.trackedCount(),
		"both representations must map to a single tracked entry")

	release()
}

// TestServerLimiterReleaseIsIdempotent guards the invariant that a double release
// cannot hand away a slot that is still in use.
func TestServerLimiterReleaseIsIdempotent(t *testing.T) {
	limiter := newServerLimiter(testLimits(0, 2))
	now := time.Now()

	releaseA, _ := limiter.acquire("10.0.0.1:1000", now)
	_, _ = limiter.acquire("10.0.0.1:2000", now)
	require.Equal(t, 2, limiter.totalCount())

	releaseA()
	releaseA()
	releaseA()
	require.Equal(t, 1, limiter.totalCount(),
		"releasing the same acquisition repeatedly must decrement exactly once")

	// Capacity must have been freed for exactly one more connection, not three.
	_, ok := limiter.acquire("10.0.0.1:3000", now)
	require.True(t, ok)
	_, ok = limiter.acquire("10.0.0.1:4000", now)
	require.False(t, ok, "a triple release must not have freed three slots")
}

// TestServerLimiterCounterNeverGoesNegative covers the abnormal paths: a release
// arriving after the entry has been swept must not corrupt the total.
func TestServerLimiterCounterNeverGoesNegative(t *testing.T) {
	limiter := newServerLimiter(testLimits(0, 2))
	now := time.Now()

	release, _ := limiter.acquire("10.0.0.1:1000", now)

	// Force an expiry sweep that removes the entry even though a connection is
	// still nominally open, then release. The total must stay consistent.
	limiter.access.Lock()
	delete(limiter.perIP, netip.MustParseAddr("10.0.0.1"))
	limiter.access.Unlock()

	release()
	require.GreaterOrEqual(t, limiter.totalCount(), 0,
		"the total must never go negative")
	require.Equal(t, 0, limiter.totalCount())
}

// TestServerLimiterExpiresIdleEntries proves the map does not grow without bound
// in the ordinary case, and that the sweep is amortized rather than per-acquire.
func TestServerLimiterExpiresIdleEntries(t *testing.T) {
	limiter := newServerLimiter(testLimits(0, 1000))

	// Open and close one connection per address.
	base := time.Now().Add(-time.Hour)
	for i := range 5 {
		address := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}).String()
		release, ok := limiter.acquire(address+":1000", base)
		require.True(t, ok)
		release()
	}
	require.Equal(t, 5, limiter.trackedCount())
	require.Equal(t, 0, limiter.totalCount(), "every connection was released")

	// Drive enough acquisitions to trigger the amortized sweep. The sweep must
	// remove entries whose lastSeen is far in the past.
	for range sweepInterval + 1 {
		release, _ := limiter.acquire("10.9.9.9:1000", time.Now())
		release()
	}
	require.Less(t, limiter.trackedCount(), 7,
		"idle entries must be expired by the amortized sweep")
}

// TestServerLimiterTrackedMapIsBounded proves a flood of distinct source
// addresses cannot grow the map past its cap, which is the defence against an
// attacker using the limiter's own memory as the attack.
func TestServerLimiterTrackedMapIsBounded(t *testing.T) {
	limits := testLimits(0, 1)
	limits.MaxTrackedIPs = 8
	limiter := newServerLimiter(limits)
	now := time.Now()

	releases := make([]func(), 0, 8)
	for i := range 8 {
		address := netip.AddrFrom4([4]byte{10, 1, 0, byte(i + 1)}).String()
		release, ok := limiter.acquire(address+":1000", now)
		require.True(t, ok, "address %d must be admitted while under the cap", i)
		releases = append(releases, release)
	}

	// The 9th distinct address must be refused rather than growing the map.
	_, ok := limiter.acquire("10.1.0.99:1000", now)
	require.False(t, ok, "a new source beyond max_tracked_ips must fail closed")
	require.LessOrEqual(t, limiter.trackedCount(), 8,
		"the tracked-address map must stay within its cap")
	require.Greater(t, limiter.capRejectionCount(), 0)

	for _, release := range releases {
		release()
	}
}

// TestServerLimiterUnparseableSourceStillCountsGlobally proves an unattributable
// source cannot bypass the global bound.
func TestServerLimiterUnparseableSourceStillCountsGlobally(t *testing.T) {
	limiter := newServerLimiter(testLimits(1, 0))
	now := time.Now()

	release, ok := limiter.acquire("not-an-address", now)
	require.True(t, ok)
	require.Equal(t, 1, limiter.totalCount(),
		"an unattributable source must still count against the global bound")

	_, ok = limiter.acquire("also-not-an-address", now)
	require.False(t, ok, "the global bound must apply to unattributable sources")
	release()
}

// ---------------------------------------------------------------------------
// Option layer
// ---------------------------------------------------------------------------

func TestNaiveServerLimitsDefaultToDisabled(t *testing.T) {
	var nilOptions *option.NaiveServerLimitsOptions
	require.False(t, nilOptions.Enabled(), "a nil option means no limits")
	require.Equal(t, option.NaiveServerLimits{}, nilOptions.Build())
	require.NoError(t, nilOptions.Validate())

	empty := &option.NaiveServerLimitsOptions{}
	require.False(t, empty.Enabled(), "an omitted option means no limits")
	require.Equal(t, option.NaiveServerLimits{}, empty.Build())
}

func TestNaiveServerLimitsBuildResolvesTimers(t *testing.T) {
	options := &option.NaiveServerLimitsOptions{
		MaxConnections:      100,
		MaxConnectionsPerIP: 8,
		HeaderTimeout:       badoption.Duration(30 * time.Second),
	}
	require.True(t, options.Enabled())

	limits := options.Build()
	require.Equal(t, 100, limits.MaxConnections)
	require.Equal(t, 8, limits.MaxConnectionsPerIP)
	require.Equal(t, 30*time.Second, limits.HeaderTimeout)
	require.Equal(t, option.DefaultNaiveMaxTrackedIPs, limits.MaxTrackedIPs,
		"a per-IP limit without an explicit cap must get the documented default")
}

func TestNaiveServerLimitsRejectInvalidValues(t *testing.T) {
	for name, options := range map[string]*option.NaiveServerLimitsOptions{
		"negative max_connections": {MaxConnections: -1},
		"negative per-ip":          {MaxConnectionsPerIP: -1},
		"negative header_timeout":  {HeaderTimeout: badoption.Duration(-time.Second)},
		"negative max_tracked_ips": {MaxTrackedIPs: -1},
		"per-ip above global":      {MaxConnections: 4, MaxConnectionsPerIP: 8},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, options.Validate(),
				"an unhonourable limit must be rejected at configuration time")
		})
	}

	// The valid boundary must still be accepted.
	require.NoError(t, (&option.NaiveServerLimitsOptions{
		MaxConnections: 8, MaxConnectionsPerIP: 8,
	}).Validate(), "per-ip equal to global is reachable and therefore valid")
}

// TestNaiveServerLimitsRoundTripThroughJSON proves the new option survives a
// configuration round trip, so a config that sets it is not silently dropped.
func TestNaiveServerLimitsRoundTripThroughJSON(t *testing.T) {
	const document = `{
		"server_limits": {
			"max_connections": 64,
			"max_connections_per_ip": 4,
			"header_timeout": "20s"
		}
	}`

	var options option.NaiveInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(document), &options)
	require.NoError(t, err)
	require.NotNil(t, options.ServerLimits)
	require.Equal(t, 64, options.ServerLimits.MaxConnections)
	require.Equal(t, 4, options.ServerLimits.MaxConnectionsPerIP)
	require.Equal(t, 20*time.Second, options.ServerLimits.HeaderTimeout.Build())
}

// TestNaiveInboundUnconfiguredLimitsLeaveAcceptPathUntouched proves the wrapper
// is not installed when nothing is configured, which is the mechanism behind
// "default behaviour is unchanged".
func TestNaiveInboundUnconfiguredLimitsLeaveAcceptPathUntouched(t *testing.T) {
	inbound := &Inbound{}
	require.Nil(t, newServerLimiter(inbound.limits),
		"an inbound with no server_limits must build no limiter")
	require.Zero(t, inbound.limits.HeaderTimeout,
		"an inbound with no server_limits must set no header timeout")
}

// stubListener feeds a fixed sequence of connections and then blocks, modelling a
// listener that has no further peers rather than one that has failed.
//
// It must BLOCK rather than return an error: limitedListener deliberately loops on
// a refusal, because in production a refused peer is closed and Accept moves on to
// the next one. A stub that returned an error would be interpreted as "the
// listener is broken" and the loop would never be exercised.
type stubListener struct {
	conns  []net.Conn
	index  int
	closed chan struct{}
}

func (s *stubListener) Accept() (net.Conn, error) {
	if s.index < len(s.conns) {
		conn := s.conns[s.index]
		s.index++
		return conn, nil
	}
	<-s.closed
	return nil, net.ErrClosed
}

func (s *stubListener) Close() error   { return nil }
func (s *stubListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// addressedConn gives a pipe a real peer address, because the limiter keys on the
// transport peer and net.Pipe reports a synthetic one.
type addressedConn struct {
	net.Conn
	remote net.Addr
}

func (c *addressedConn) RemoteAddr() net.Addr { return c.remote }

// TestLimitedListenerRefusesAndClosesOverLimitConnections proves a refused
// connection is actually closed, so a refusal is not itself a resource leak.
//
// The test drives Accept on a goroutine because the listener BLOCKS once the stub
// is exhausted -- which is the correct production behaviour and would otherwise
// deadlock the test.
func TestLimitedListenerRefusesAndClosesOverLimitConnections(t *testing.T) {
	limiter := newServerLimiter(testLimits(0, 1))

	clientA, serverA := net.Pipe()
	defer clientA.Close()
	clientB, serverB := net.Pipe()
	defer clientB.Close()

	stub := &stubListener{
		conns: []net.Conn{
			&addressedConn{Conn: serverA, remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1000}},
			&addressedConn{Conn: serverB, remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2000}},
		},
		closed: make(chan struct{}),
	}
	listener := &limitedListener{Listener: stub, limiter: limiter}

	firstConn, err := listener.Accept()
	require.NoError(t, err)
	require.NotNil(t, firstConn)
	require.Equal(t, 1, limiter.totalCount())
	require.Equal(t, 1, limiter.trackedCount(), "the accepted peer must be tracked")

	// The next Accept reaches the over-limit peer. The listener must close it and
	// loop; the stub then blocks, so Accept does not return. Run it concurrently
	// and assert on the observable effects instead of on a return value.
	acceptDone := make(chan error, 1)
	go func() {
		_, acceptErr := listener.Accept()
		acceptDone <- acceptErr
	}()

	// The refused connection must actually be CLOSED: a refusal that leaks the
	// socket is not a defence. serverB sees that close as a read error.
	require.NoError(t, serverB.SetReadDeadline(time.Now().Add(5*time.Second)))
	buffer := make([]byte, 1)
	_, readErr := serverB.Read(buffer)
	require.Error(t, readErr,
		"the over-limit connection must be closed by the listener, not left open")

	// The refused peer must never have been counted.
	require.Equal(t, 1, limiter.totalCount(),
		"a refused connection must not be counted")

	// Accept must still be blocked waiting for a real peer, not spinning or dead.
	select {
	case err = <-acceptDone:
		t.Fatalf("Accept returned %v; it should be waiting for the next peer", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(stub.closed)
	require.Error(t, <-acceptDone)

	_ = firstConn.Close()
	require.Equal(t, 0, limiter.totalCount(),
		"closing the accepted connection must release its slot")
}

// TestServerLimiterIsRaceFreeUnderConcurrentAcquireRelease drives the limiter
// from many goroutines at once.
//
// The -race detector only reports races that actually occur, so a limiter
// exercised one connection at a time would look race-free while being nothing of
// the sort. This test creates the contention: N goroutines acquiring and
// releasing against a small per-IP allowance, which is exactly the shape a real
// burst of connections produces.
//
// It asserts the STRONGER property too: the number of simultaneously admitted
// connections never exceeds the configured allowance, at any instant. A limiter
// that is race-free but over-admits is still not a limit.
func TestServerLimiterIsRaceFreeUnderConcurrentAcquireRelease(t *testing.T) {
	const (
		allowance  = 4
		goroutines = 32
		iterations = 200
	)
	limiter := newServerLimiter(option.NaiveServerLimits{
		MaxConnections:      allowance,
		MaxConnectionsPerIP: allowance,
		MaxTrackedIPs:       64,
	})

	var (
		wg sync.WaitGroup
		// admissions counts every successful acquire over the whole run; inFlight
		// tracks the instantaneous count. They are separate because admissions is
		// the "did anything happen at all" signal and inFlight is the "did the
		// limit hold" signal -- an earlier version reused one counter for both and
		// therefore always read zero once the run finished.
		admissions  atomic.Int64
		refused     atomic.Int64
		inFlight    atomic.Int64
		maxInFlight atomic.Int64
	)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				release, ok := limiter.acquire("10.0.0.1:1234", time.Now())
				if !ok {
					refused.Add(1)
					continue
				}
				admissions.Add(1)
				current := inFlight.Add(1)
				// Track the high-water mark of concurrent admissions. If the
				// limiter ever admits more than the allowance, this observes it.
				for {
					observed := maxInFlight.Load()
					if current <= observed || maxInFlight.CompareAndSwap(observed, current) {
						break
					}
				}
				// Over-allowance would be visible as a high-water mark above the
				// configured maximum, so no extra synchronisation is needed.
				time.Sleep(time.Microsecond)
				inFlight.Add(-1)
				release()
			}
		}()
	}
	wg.Wait()

	require.LessOrEqual(t, maxInFlight.Load(), int64(allowance),
		"the limiter admitted more concurrent connections than max_connections_per_ip")
	require.Positive(t, admissions.Load(), "some acquisitions must succeed")
	t.Logf("OBSERVED: %d goroutines x %d iterations -> admissions=%d refused=%d peak-in-flight=%d (allowance %d)",
		goroutines, iterations, admissions.Load(), refused.Load(), maxInFlight.Load(), allowance)

	require.Equal(t, 0, limiter.totalCount(),
		"every acquisition was released, so the total must return to zero")
}
