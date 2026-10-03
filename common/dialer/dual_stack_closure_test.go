package dialer

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Final closure tests: the connection fallback timescale, and the effective DNS strategy.

// --- P1a: the two time scales must not be confused (§12-§15) ---------------------------

func TestFallbackDelayDefaultIsTheConnectionTimescale(t *testing.T) {
	// The default must be the CONNECTION stagger interval, not the DNS resolution grace.
	//
	// These answer different questions: the grace decides how long the resolver holds a
	// non-preferred family; this delay decides how long the original literal attempt gets before
	// recovery races it. Borrowing the 50ms resolution constant made recovery start about six
	// times sooner than the rest of the dialer staggers candidates, so a healthy-but-slow
	// original could be raced before it had a realistic chance.
	fallbackDialer := &resolveDialer{}
	require.Equal(t, N.DefaultFallbackDelay, fallbackDialer.fallbackDelayOrDefault(),
		"the default connection fallback delay must be N.DefaultFallbackDelay")

	require.NotEqual(t, preferredFamilyGrace, fallbackDialer.fallbackDelayOrDefault(),
		"the DNS preferred-family grace must never be the connection fallback default")
}

func TestFallbackDelayDefaultValues(t *testing.T) {
	require.Equal(t, 300*time.Millisecond, N.DefaultFallbackDelay,
		"the project standard connection fallback delay")
	require.Equal(t, 50*time.Millisecond, preferredFamilyGrace,
		"the DNS resolution grace, which is a different scale entirely")
}

func TestFallbackDelayOverrideStillWins(t *testing.T) {
	// An explicit override must be respected; the default only applies when unset.
	overridden := &resolveDialer{fallbackDelay: 7 * time.Millisecond}
	require.Equal(t, 7*time.Millisecond, overridden.fallbackDelayOrDefault())
}

// TestLiteralRecoveryStartsAtTheConnectionTimescale is §15.
//
// With the default configuration and a blackholed original, the recovery candidate must start
// near N.DefaultFallbackDelay - not near the 50ms DNS grace.
func TestLiteralRecoveryStartsAtTheConnectionTimescale(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.99")

	// The recovery lookup answers immediately; the original blackholes until cancelled.
	router := newImmediateRecoveryRouter(recovered)
	inner := &literalDialer{
		blackhole: map[netip.Addr]bool{original: true},
		start:     time.Now(),
	}
	dialer, ctx := newLiteralTestDialer(router, inner, C.DomainStrategyAsIS)
	// No explicit fallback delay: this exercises the default under test.
	dialer.fallbackDelay = 0

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	require.NoError(t, err)
	require.NotNil(t, conn)

	// The recovered candidate must have been attempted, and it is the ATTEMPT TIME OF THE
	// RECOVERED ADDRESS that matters - not the first attempt overall, which is the original
	// literal dial at t≈0 and would make this assertion meaningless.
	startedAt, found := inner.attemptStartedAt(recovered)
	require.True(t, found, "the recovery candidate must have been dialled; attempted: %v", inner.attempts())

	require.GreaterOrEqual(t, startedAt, N.DefaultFallbackDelay-40*time.Millisecond,
		"recovery must wait for the connection fallback delay (300ms), not the 50ms DNS grace; "+
			"the recovered candidate started after only %v", startedAt)
}

// --- P1b: the effective strategy decides the preference (§16-§22) ----------------------
//
// # How these tests stay deterministic
//
// The feeder holds a non-preferred family for at most preferredFamilyGrace, so an assertion of
// the form "the preferred family is dialled first" is only guaranteed while the preferred family
// arrives inside that window. Under the race detector a 15ms delivery can exceed 50ms of wall
// clock, so such a test is a timing race, not a contract test.
//
// These tests therefore arrange arrival so the grace cannot decide the outcome:
//
//	the PREFERRED family arrives FIRST  -> it is fed immediately, nothing is held
//	the NON-preferred family arrives LAST -> it is fed when the stream ends
//
// Under that arrangement the order is decided purely by which family the implementation
// considers preferred, with no timer involved. That is exactly the decision under test, and it
// is also the arrangement in which the bug is visible: reading the raw AsIS option makes IPv4
// preferred, so IPv4 is fed first even though the resolver's effective strategy is prefer_ipv6.

// immediateRecoveryRouter answers a recovery lookup without delay, so the timing under test is
// the dialer's fallback delay rather than the resolver's.
type immediateRecoveryRouter struct {
	adapter.DNSRouter
	addresses []netip.Addr
}

func newImmediateRecoveryRouter(addresses ...netip.Addr) *immediateRecoveryRouter {
	return &immediateRecoveryRouter{addresses: addresses}
}

func (r *immediateRecoveryRouter) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (r *immediateRecoveryRouter) Close() error                                   { return nil }
func (r *immediateRecoveryRouter) ClearCache()                                    {}
func (r *immediateRecoveryRouter) ResetNetwork()                                  {}
func (r *immediateRecoveryRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}
func (r *immediateRecoveryRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, nil
}
func (r *immediateRecoveryRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.addresses, nil
}

// effectiveStrategyRouter reports a fixed effective strategy alongside each family, which is
// what the real Router does after applying its own default.
type effectiveStrategyRouter struct {
	adapter.DNSRouter

	effective C.DomainStrategy

	// delayA and delayAAAA control arrival order.
	delayA    time.Duration
	delayAAAA time.Duration

	addressesA    []netip.Addr
	addressesAAAA []netip.Addr
}

func (r *effectiveStrategyRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)

	run := func(ipv6 bool, delay time.Duration, addresses []netip.Addr) {
		defer waitGroup.Done()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				publish(adapter.DNSFamilyResult{IPv6: ipv6, Err: ctx.Err(), EffectiveStrategy: r.effective})
				return
			}
		}
		publish(adapter.DNSFamilyResult{
			IPv6:              ipv6,
			Addresses:         addresses,
			EffectiveStrategy: r.effective,
		})
	}

	go run(false, r.delayA, r.addressesA)
	go run(true, r.delayAAAA, r.addressesAAAA)
	waitGroup.Wait()
	return nil
}

func (r *effectiveStrategyRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return append(append([]netip.Addr{}, r.addressesA...), r.addressesAAAA...), nil
}

// TestAsISFollowsRouterPreferIPv6 is §17, the defect this fixes.
//
// The dialer asks with AsIS; the DNS router's default is prefer_ipv6. IPv6 arrives first and
// must be the first candidate. An implementation reading the raw AsIS option treats IPv4 as
// preferred, feeds IPv4 first, and holds IPv6 - the opposite of the configuration.
func TestAsISFollowsRouterPreferIPv6(t *testing.T) {
	address4 := netip.MustParseAddr("192.0.2.1")
	address6 := netip.MustParseAddr("2001:db8::1")

	inner := &literalDialer{start: time.Now()}
	router := &effectiveStrategyRouter{
		effective: C.DomainStrategyPreferIPv6,
		// The preferred family answers first, so nothing is ever held and no timer is involved.
		delayA:        40 * time.Millisecond,
		delayAAAA:     1 * time.Millisecond,
		addressesA:    []netip.Addr{address4},
		addressesAAAA: []netip.Addr{address6},
	}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		// The dialer supplies AsIS - it has no preference of its own.
		queryOptions: adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	_, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	require.NoError(t, err)

	attempts := inner.attempts()
	require.NotEmpty(t, attempts)
	require.Equal(t, address6, attempts[0],
		"the resolver's effective strategy is prefer_ipv6, so IPv6 must lead; reading the raw "+
			"AsIS option would have preferred IPv4")
}

// TestAsISFollowsRouterPreferIPv4 is §18, the mirror.
func TestAsISFollowsRouterPreferIPv4(t *testing.T) {
	address4 := netip.MustParseAddr("192.0.2.1")
	address6 := netip.MustParseAddr("2001:db8::1")

	inner := &literalDialer{start: time.Now()}
	router := &effectiveStrategyRouter{
		effective:     C.DomainStrategyPreferIPv4,
		delayA:        1 * time.Millisecond,
		delayAAAA:     40 * time.Millisecond,
		addressesA:    []netip.Addr{address4},
		addressesAAAA: []netip.Addr{address6},
	}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	_, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	require.NoError(t, err)

	attempts := inner.attempts()
	require.NotEmpty(t, attempts)
	require.Equal(t, address4, attempts[0],
		"the resolver's effective strategy is prefer_ipv4, so IPv4 must lead even though the "+
			"dialer supplied AsIS")
}

// TestAsISWithoutResolverDefaultKeepsTheCallerOption is §22.
//
// When nothing overrides AsIS the previous behaviour must stand rather than a third
// interpretation being invented.
func TestAsISWithoutResolverDefaultKeepsTheCallerOption(t *testing.T) {
	address4 := netip.MustParseAddr("192.0.2.1")
	address6 := netip.MustParseAddr("2001:db8::1")

	inner := &literalDialer{start: time.Now()}
	router := &effectiveStrategyRouter{
		effective:     C.DomainStrategyAsIS,
		delayA:        1 * time.Millisecond,
		delayAAAA:     40 * time.Millisecond,
		addressesA:    []netip.Addr{address4},
		addressesAAAA: []netip.Addr{address6},
	}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	_, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	require.NoError(t, err)

	attempts := inner.attempts()
	require.NotEmpty(t, attempts)
	require.Equal(t, address4, attempts[0],
		"an AsIS effective strategy means no opinion was expressed, so the existing IPv4-first "+
			"behaviour is kept rather than inventing a preference")
}

// TestNonAsISCallerOptionStillHonoured confirms a real caller preference is used, and that the
// reported effective strategy does not have to disagree with it.
func TestNonAsISCallerOptionStillHonoured(t *testing.T) {
	address4 := netip.MustParseAddr("192.0.2.1")
	address6 := netip.MustParseAddr("2001:db8::1")

	inner := &literalDialer{start: time.Now()}
	router := &effectiveStrategyRouter{
		effective:     C.DomainStrategyPreferIPv6,
		delayA:        40 * time.Millisecond,
		delayAAAA:     1 * time.Millisecond,
		addressesA:    []netip.Addr{address4},
		addressesAAAA: []netip.Addr{address6},
	}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv6},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
	defer cancel()

	_, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	require.NoError(t, err)

	require.Equal(t, address6, inner.attempts()[0])
}
