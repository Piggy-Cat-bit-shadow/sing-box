package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Ownership tests for the literal-recovery race.
//
// # What is being pinned
//
// raceWithPendingOriginal runs two attempts and returns one connection. The contract it claims
// is that nothing is left running and nothing is left unclosed:
//
//	exactly one connection is returned
//	the losing attempt is cancelled
//	a loser that succeeded anyway is closed
//	both workers have exited before the function returns
//
// The previous implementation used the CONNECTION context for the recovered race, kept no
// WaitGroup, and never closed a late success. So when the original won, the recovered attempt
// kept dialling for the life of the connection, and if it eventually succeeded its connection
// was simply dropped on a buffered channel - leaked, unclosed, with no owner.
//
// Every test below therefore counts Close calls on the specific connection, not merely goroutine
// exit: a goroutine can exit while its connection stays open, which is exactly the bug.

// closeCountingConn records how many times it was closed.
//
// A counter rather than a bool, because both "never closed" and "closed twice" are bugs and a
// bool cannot tell them apart.
type closeCountingConn struct {
	closes atomic.Int32
	// label identifies which attempt produced this connection in failure output.
	label string
}

func (c *closeCountingConn) Read([]byte) (int, error)    { return 0, net.ErrClosed }
func (c *closeCountingConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeCountingConn) LocalAddr() net.Addr         { return nil }
func (c *closeCountingConn) RemoteAddr() net.Addr        { return nil }
func (c *closeCountingConn) SetDeadline(time.Time) error { return nil }
func (c *closeCountingConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *closeCountingConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return nil
}

// owningDialer models a dialer whose per-address behaviour the test controls, and which hands
// back an identifiable connection per address so the test can inspect that exact connection.
type owningDialer struct {
	access sync.Mutex

	// outcome maps an address to how the attempt behaves.
	outcome map[netip.Addr]owningOutcome

	// conns records the connection handed out for each address.
	conns map[netip.Addr]*closeCountingConn

	// start is unused by the assertions; kept so the fixture can log timings if needed.
	start time.Time
}

type owningOutcome struct {
	// delay is how long the attempt takes before answering.
	delay time.Duration
	// success reports whether it returns a connection.
	success bool
	// blockUntilCancel makes the attempt wait for its context instead of a delay.
	blockUntilCancel bool
}

func newOwningDialer() *owningDialer {
	return &owningDialer{
		outcome: make(map[netip.Addr]owningOutcome),
		conns:   make(map[netip.Addr]*closeCountingConn),
	}
}

func (d *owningDialer) setOutcome(address string, outcome owningOutcome) {
	d.access.Lock()
	defer d.access.Unlock()
	d.outcome[netip.MustParseAddr(address)] = outcome
}

func (d *owningDialer) connectionFor(address string) *closeCountingConn {
	d.access.Lock()
	defer d.access.Unlock()
	return d.conns[netip.MustParseAddr(address)]
}

func (d *owningDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	address := destination.Addr

	d.access.Lock()
	outcome, configured := d.outcome[address]
	d.access.Unlock()

	if !configured {
		// An unconfigured address fails immediately, which keeps a test honest: an address it
		// forgot to describe cannot silently behave like a success.
		return nil, errOwningUnconfigured
	}

	if outcome.blockUntilCancel {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if outcome.delay > 0 {
		select {
		case <-time.After(outcome.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !outcome.success {
		return nil, errOwningFailed
	}

	conn := &closeCountingConn{label: address.String()}
	d.access.Lock()
	d.conns[address] = conn
	d.access.Unlock()
	return conn, nil
}

func (d *owningDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

// waitForConnection blocks until the given address has produced a connection, or fails.
//
// # Why a poll rather than a WaitGroup
//
// The scheduler starts candidates progressively, so a dial can be added after a WaitGroup has
// already been observed as settled. Waiting on "no dials in flight" is therefore not a reliable
// barrier - the observer can win that race and conclude the attempt never happened. Waiting for
// the specific connection this test cares about is a direct observation and cannot be fooled.
func (d *owningDialer) waitForConnection(t *testing.T, address string, timeout time.Duration) *closeCountingConn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if conn := d.connectionFor(address); conn != nil {
			return conn
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("no connection for %s within %v; the attempt never produced one", address, timeout)
	return nil
}

// waitForClosedConnection waits for an address to produce a connection AND for that connection
// to be closed, up to the timeout.
//
// A fixed settle sleep would be a guess about how long cleanup takes, and on a loaded machine
// that guess can be wrong - the counter is then read before the race has closed the loser and
// the test reports a leak that did not happen. Polling the actual condition removes the guess.
func (d *owningDialer) waitForClosedConnection(t *testing.T, address string, timeout time.Duration) *closeCountingConn {
	t.Helper()
	conn := d.waitForConnection(t, address, timeout)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if conn.closes.Load() > 0 {
			return conn
		}
		time.Sleep(2 * time.Millisecond)
	}
	return conn
}

// recoveryContext supplies the sniffed domain that makes recovery possible.
//
// recoverCandidates returns nothing without a validated sniffed domain, so a test that omits it
// never reaches raceWithPendingOriginal at all - and would then "pass" without exercising the
// ownership code it claims to cover.
func recoveryContext() context.Context {
	return adapter.WithContext(context.Background(), &adapter.InboundContext{
		Domain: "sniffed.example",
	})
}

var (
	errOwningUnconfigured = errTest("address was not configured in the test dialer")
	errOwningFailed       = errTest("configured to fail")
)

type errTest string

func (e errTest) Error() string { return string(e) }

// staticRecoveryRouter answers each family on its own schedule, so recovery can be made to
// arrive either before or after the original.
type staticRecoveryRouter struct {
	adapter.DNSRouter

	addressesA    []netip.Addr
	addressesAAAA []netip.Addr
	delayA        time.Duration
	delayAAAA     time.Duration
}

func (r *staticRecoveryRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)

	run := func(ipv6 bool, delay time.Duration, addresses []netip.Addr) {
		defer waitGroup.Done()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				publish(adapter.DNSFamilyResult{IPv6: ipv6, Err: ctx.Err()})
				return
			}
		}
		publish(adapter.DNSFamilyResult{IPv6: ipv6, Addresses: addresses})
	}

	go run(false, r.delayA, r.addressesA)
	go run(true, r.delayAAAA, r.addressesAAAA)
	waitGroup.Wait()
	return nil
}

func (r *staticRecoveryRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return append(append([]netip.Addr{}, r.addressesA...), r.addressesAAAA...), nil
}

func (r *staticRecoveryRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, nil
}

// buildOwnershipDialer wires a resolveDialer for a literal destination with recovery available.
func buildOwnershipDialer(inner *owningDialer, router adapter.DNSRouter, original string, fallbackDelay time.Duration) *resolveDialer {
	return &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: fallbackDelay,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
		// The original literal is the destination; recovery re-resolves the sniffed name.
	}
}

// TestOriginalWinnerLeavesNoUnownedRecoveredConnection is §2 Case A and §4.
//
// # What the contract actually is
//
// The race returns exactly one connection, and when the ORIGINAL wins the recovered side must not
// leave anything behind. Two outcomes are acceptable for the recovered side, and both are
// checked here:
//
//	it was cancelled before completing  -> no connection exists at all
//	it completed anyway                 -> that connection was closed by the race
//
// What is NOT acceptable, and what the previous implementation did, is a recovered connection
// sitting in a buffered channel with nobody to close it while the recovered worker keeps
// dialling for the life of the connection. The assertion below therefore fails if a recovered
// connection exists in any state other than "closed exactly once".
//
// # Why the original is made slow but successful
//
// raceWithPendingOriginal is only reached when recovery produces candidates while the original is
// still PENDING. The original must outlast the recovery lookup and the head-start timer, then
// succeed - which is precisely the case where a second, unowned success can appear.
func TestOriginalWinnerLeavesNoUnownedRecoveredConnection(t *testing.T) {
	original := "192.0.2.1"
	recovered := "192.0.2.2"

	inner := newOwningDialer()
	// Pending past the head start, then succeeds: it wins the race.
	inner.setOutcome(original, owningOutcome{delay: 30 * time.Millisecond, success: true})
	// Slow enough that the original wins first.
	inner.setOutcome(recovered, owningOutcome{delay: 100 * time.Millisecond, success: true})

	router := &staticRecoveryRouter{addressesA: []netip.Addr{netip.MustParseAddr(recovered)}}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 20 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(original+":443"))
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Wait for the recovered attempt's fate to be observable.
	//
	// The fixed implementation cancels and waits for that attempt, so it either never produces a
	// connection or produces one the race has already closed. The previous implementation did
	// neither: it left the attempt running on the connection's context, so the connection
	// appeared LATE - after this function had already returned - and was never closed.
	//
	// Waiting for it to appear is therefore what makes this test discriminating. Checking
	// immediately would read the map before a leaked connection exists and skip the assertion.
	var recoveredConn *closeCountingConn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if recoveredConn = inner.connectionFor(recovered); recoveredConn != nil {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	originalConn := inner.connectionFor(original)
	require.NotNil(t, originalConn, "the original won and must have produced the returned connection")
	require.Same(t, originalConn, conn)
	require.EqualValues(t, 0, originalConn.closes.Load(),
		"the winner must still be open; the caller owns it")

	if recoveredConn != nil {
		inner.waitForClosedConnection(t, recovered, 5*time.Second)
		require.EqualValues(t, 1, recoveredConn.closes.Load(),
			"a recovered connection that completed after losing the race must be closed exactly "+
				"once; leaving it open leaks a connection nobody owns")
	}

	require.NoError(t, conn.Close())
}

// TestRecoveredWinnerWinsAndIsLeftOpen is §3 Case B.
//
// Recovery answers first and wins. The returned connection must be the recovered one and must
// still be open, while the cancelled original leaves nothing behind.
func TestRecoveredWinnerWinsAndIsLeftOpen(t *testing.T) {
	original := "192.0.2.1"
	recovered := "192.0.2.2"

	inner := newOwningDialer()
	// The original never answers within the test's window; it is cancelled.
	inner.setOutcome(original, owningOutcome{delay: 2 * time.Second, success: true})
	inner.setOutcome(recovered, owningOutcome{delay: 2 * time.Millisecond, success: true})

	router := &staticRecoveryRouter{addressesA: []netip.Addr{netip.MustParseAddr(recovered)}}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 20 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(original+":443"))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)
	require.Less(t, elapsed, time.Second,
		"the recovered candidate won and must be returned without waiting for the slow original")

	recoveredConn := inner.connectionFor(recovered)
	require.NotNil(t, recoveredConn)
	require.Same(t, recoveredConn, conn, "the recovered connection won and must be returned")
	require.EqualValues(t, 0, recoveredConn.closes.Load(),
		"the winner must be left open for the caller")

	// The original was cancelled mid-dial, so it must not have produced a connection at all.
	require.Nil(t, inner.connectionFor(original),
		"the cancelled original must not leave a connection behind")

	require.NoError(t, conn.Close())
}

// TestParentCancellationLeavesNoWorkerOrConnection is §10.
func TestParentCancellationLeavesNoWorkerOrConnection(t *testing.T) {
	original := "192.0.2.1"
	recovered := "192.0.2.2"

	inner := newOwningDialer()
	// Both attempts block until cancelled, so the only way out is the parent context.
	inner.setOutcome(original, owningOutcome{blockUntilCancel: true})
	inner.setOutcome(recovered, owningOutcome{blockUntilCancel: true})

	router := &staticRecoveryRouter{addressesA: []netip.Addr{netip.MustParseAddr(recovered)}}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 10 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 120*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(original+":443"))
	elapsed := time.Since(start)

	require.Error(t, err, "a cancelled parent must fail the dial")
	require.Less(t, elapsed, 3*time.Second, "cancellation must be honoured promptly")

	// Both workers must return, and no connection may exist to leak. The race must have waited
	// for them before returning, so no settle delay is needed here - that is the assertion.
	require.Nil(t, inner.connectionFor(original),
		"a cancelled attempt must not hand back a connection")
	require.Nil(t, inner.connectionFor(recovered))
}

// TestBothAttemptsFailLeavesNoWorker is §32.
func TestBothAttemptsFailLeavesNoWorker(t *testing.T) {
	original := "192.0.2.1"
	recovered := "192.0.2.2"

	inner := newOwningDialer()
	// The original is pending past the head start and then fails, so the race is entered.
	inner.setOutcome(original, owningOutcome{delay: 60 * time.Millisecond, success: false})
	inner.setOutcome(recovered, owningOutcome{delay: 30 * time.Millisecond, success: false})

	router := &staticRecoveryRouter{addressesA: []netip.Addr{netip.MustParseAddr(recovered)}}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 10 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(original+":443"))
	require.Error(t, err, "both attempts failed, so the dial must fail")

	require.Nil(t, inner.connectionFor(original))
	require.Nil(t, inner.connectionFor(recovered))
}

// TestRaceReturnsExactlyOneConnection is §4.
//
// Whatever the outcome, every successful connection except the returned one must be closed, and
// no buffered channel may be holding an unowned success.
func TestRaceReturnsExactlyOneConnection(t *testing.T) {
	original := "192.0.2.1"
	recovered := "192.0.2.2"

	inner := newOwningDialer()
	// Both succeed; the original wins on timing, after the head start so the race is entered.
	inner.setOutcome(original, owningOutcome{delay: 60 * time.Millisecond, success: true})
	inner.setOutcome(recovered, owningOutcome{delay: 180 * time.Millisecond, success: true})

	router := &staticRecoveryRouter{addressesA: []netip.Addr{netip.MustParseAddr(recovered)}}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 10 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(original+":443"))
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Whatever the outcome, the caller must hold exactly one OPEN connection and nothing may be
	// left dangling. This is the property the leak violated: a second successful connection
	// existed with no owner.
	open := 0
	for _, address := range []string{original, recovered} {
		if c := inner.connectionFor(address); c != nil {
			if c.closes.Load() == 0 {
				open++
			}
		}
	}

	require.Equal(t, 1, open,
		"exactly one connection may still be open when the race returns - the one given to the "+
			"caller; a second open connection is the leak")

	require.EqualValues(t, 0, inner.connectionFor(original).closes.Load(),
		"the returned connection must not be closed by the race")

	require.NoError(t, conn.Close())
}
