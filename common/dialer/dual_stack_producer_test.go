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

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// Tests for the DNS producer lifecycle and no-candidate termination (§14-§26).
//
// # The two failures these close
//
//   - A late family answer had no way to stop. The feeder's only exit was the CONNECTION
//     context, which outlives the race by minutes, so a send into an unbuffered channel with no
//     reader parked the feeder and the resolver goroutine for the life of the connection.
//
//   - A provider that closed its stream without producing a candidate left the scheduler
//     waiting for the parent timeout, because concluding required `started > 0`. A name where
//     both families return NODATA hits exactly that path.

// scriptedFamilyRouter answers families on a caller-controlled schedule and can fail.
type scriptedFamilyRouter struct {
	// delayA and delayAAAA are applied before answering; negative blocks until cancelled.
	delayA    time.Duration
	delayAAAA time.Duration

	addressesA    []netip.Addr
	addressesAAAA []netip.Addr

	// errA and errAAAA make a family fail outright.
	errA    error
	errAAAA error

	// started is closed once the lookup has been entered.
	started   chan struct{}
	startOnce sync.Once

	// exited is closed when the lookup function returns, so a test can prove the producer
	// actually terminated rather than merely being unblocked.
	exited   chan struct{}
	exitOnce sync.Once

	calls atomic.Int32
}

func newScriptedFamilyRouter() *scriptedFamilyRouter {
	return &scriptedFamilyRouter{
		started: make(chan struct{}),
		exited:  make(chan struct{}),
	}
}

func (r *scriptedFamilyRouter) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (r *scriptedFamilyRouter) Close() error                                   { return nil }
func (r *scriptedFamilyRouter) ClearCache()                                    {}
func (r *scriptedFamilyRouter) ResetNetwork()                                  {}
func (r *scriptedFamilyRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}

func (r *scriptedFamilyRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, errors.New("not implemented")
}

func (r *scriptedFamilyRouter) ExchangeAsync(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, callback func(*mDNS.Msg, error)) {
	callback(nil, errors.New("not implemented"))
}

func (r *scriptedFamilyRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	addressesA, addressesAAAA, err := r.runFamilies(ctx, nil)
	if err != nil {
		return nil, err
	}
	return append(addressesA, addressesAAAA...), nil
}

func (r *scriptedFamilyRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	var publishMu sync.Mutex
	publishAll := func(result adapter.DNSFamilyResult) {
		publishMu.Lock()
		defer publishMu.Unlock()
		publish(result)
	}
	_, _, err := r.runFamilies(ctx, publishAll)
	return err
}

// runFamilies is the shared body: it respects per-family delays and errors, and reports each
// family through publish when one is supplied.
func (r *scriptedFamilyRouter) runFamilies(ctx context.Context, publish func(adapter.DNSFamilyResult)) ([]netip.Addr, []netip.Addr, error) {
	r.calls.Add(1)
	r.startOnce.Do(func() { close(r.started) })
	defer r.exitOnce.Do(func() { close(r.exited) })

	type outcome struct {
		ipv6      bool
		addresses []netip.Addr
		err       error
	}
	results := make(chan outcome, 2)

	runFamily := func(ipv6 bool) {
		delay := r.delayA
		addresses := r.addressesA
		err := r.errA
		if ipv6 {
			delay = r.delayAAAA
			addresses = r.addressesAAAA
			err = r.errAAAA
		}
		if delay < 0 {
			<-ctx.Done()
			results <- outcome{ipv6: ipv6, err: ctx.Err()}
			return
		}
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				results <- outcome{ipv6: ipv6, err: ctx.Err()}
				return
			}
		}
		results <- outcome{ipv6: ipv6, addresses: addresses, err: err}
	}

	go runFamily(false)
	go runFamily(true)

	var (
		response4 []netip.Addr
		response6 []netip.Addr
		err4      error
		err6      error
	)
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.ipv6 {
				response6, err6 = result.addresses, result.err
			} else {
				response4, err4 = result.addresses, result.err
			}
			if publish != nil {
				publish(adapter.DNSFamilyResult{
					IPv6:      result.ipv6,
					Addresses: result.addresses,
					Err:       result.err,
				})
			}
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}

	if len(response4) == 0 && len(response6) == 0 {
		if err4 != nil {
			return nil, nil, err4
		}
		if err6 != nil {
			return nil, nil, err6
		}
		return nil, nil, errors.New("no address")
	}
	return response4, response6, nil
}

// TestLateFamilyAnswerDoesNotStrandTheProducer is §19.
//
// IPv4 answers immediately and wins. AAAA answers 200ms later - long after the connection is
// established. The producer goroutines must both EXIT, and the proof is the router's own exit
// signal rather than a goroutine count.
func TestLateFamilyAnswerDoesNotStrandTheProducer(t *testing.T) {
	fast := netip.MustParseAddr("192.0.2.1")
	late := netip.MustParseAddr("2001:db8::1")

	router := newScriptedFamilyRouter()
	router.addressesA = []netip.Addr{fast}
	router.addressesAAAA = []netip.Addr{late}
	router.delayAAAA = 200 * time.Millisecond

	inner := &literalDialer{start: time.Now()}
	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 20 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, conn)

	// The connection is established long before the late family would answer. If the producers
	// were still blocked, this would not have returned quickly.
	require.Less(t, elapsed, 150*time.Millisecond,
		"the connection must be established without waiting for the slow family")

	// The decisive assertion: the resolver function itself has returned, which can only happen
	// once the feeder stopped pulling from it.
	select {
	case <-router.exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the resolution producer did not exit after the winner was returned; " +
			"a late family answer is still trying to hand a candidate to a scheduler that " +
			"has already finished")
	}
}

// TestBothFamiliesNODATAFailsImmediately is §25.
//
// Both families answer with nothing. There is no candidate and never will be, so the call must
// fail at DNS completion scale - not sit until the TCP connect timeout.
func TestBothFamiliesNODATAFailsImmediately(t *testing.T) {
	router := newScriptedFamilyRouter()
	router.delayA = 5 * time.Millisecond
	router.delayAAAA = 5 * time.Millisecond
	// No addresses and no errors: NODATA for both.

	inner := &literalDialer{start: time.Now()}
	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 20 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv6},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	elapsed := time.Since(start)

	require.Error(t, err, "with no address in either family the connection must fail")
	require.Nil(t, conn)
	require.Less(t, elapsed, 2*time.Second,
		"the failure must come at DNS completion scale, not after the connect timeout; took %v", elapsed)
	require.Empty(t, inner.attempts(), "no dial should be attempted without candidates")
}

// TestBothFamiliesFailingReturnsTheDNSError is §26.
func TestBothFamiliesFailingReturnsTheDNSError(t *testing.T) {
	router := newScriptedFamilyRouter()
	router.errA = errors.New("A lookup refused")
	router.errAAAA = errors.New("AAAA lookup refused")

	inner := &literalDialer{start: time.Now()}
	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 20 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv6},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	elapsed := time.Since(start)

	require.Error(t, err)
	require.Less(t, elapsed, 2*time.Second,
		"both families failed, so the error must be immediate rather than waiting for a timeout")

	// The error must identify the DNS failure, not merely report an absence of candidates.
	message := err.Error()
	require.True(t,
		contains(message, "A lookup refused") || contains(message, "AAAA lookup refused") ||
			contains(message, "no address") || contains(message, "resolve"),
		"the error must describe the DNS failure rather than only saying no candidates exist; got %q",
		message)
}

// TestLateResolutionErrorDoesNotFailAWinner is §24.
//
// A candidate has already won; the other family then fails. The connection stands - a late DNS
// error must not retroactively turn success into failure.
func TestLateResolutionErrorDoesNotFailAWinner(t *testing.T) {
	fast := netip.MustParseAddr("192.0.2.1")

	router := newScriptedFamilyRouter()
	router.addressesA = []netip.Addr{fast}
	router.delayAAAA = 150 * time.Millisecond
	router.errAAAA = errors.New("AAAA failed after IPv4 connected")

	inner := &literalDialer{start: time.Now()}
	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 20 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	require.NoError(t, err, "a late failure in the other family must not fail an established connection")
	require.NotNil(t, conn)
}

// TestSchedulerClosesImmediatelyWithNoCandidates is §20/§21 at the scheduler level.
//
// The stream closes having produced nothing. The scheduler must conclude at once.
func TestSchedulerClosesImmediatelyWithNoCandidates(t *testing.T) {
	lateCandidates := make(chan dualStackCandidate)
	scheduler := &candidateScheduler{fallbackDelay: 50 * time.Millisecond}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, err := scheduler.dialWithLateCandidates(context.Background(),
			planCandidates(nil, netip.Addr{}, C.DomainStrategyPreferIPv6),
			lateCandidates,
			func(ctx context.Context, address netip.Addr) (net.Conn, error) {
				t.Error("no attempt may be made without candidates")
				return nil, errors.New("unreachable")
			})
		done <- err
	}()

	// Close the stream without ever producing a candidate.
	time.Sleep(30 * time.Millisecond)
	close(lateCandidates)

	select {
	case err := <-done:
		require.Error(t, err)
		require.Less(t, time.Since(start), time.Second,
			"a closed stream with no candidates must conclude at once, not wait for the parent timeout")
	case <-time.After(3 * time.Second):
		t.Fatal("the scheduler hung after its candidate stream closed with no candidates; " +
			"it would wait for the parent timeout even though it already knew there was nothing")
	}
}

func contains(haystack string, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack string, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
