package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the order in which families reach the dial scheduler.
//
// # What is being protected
//
// "prefer IPv6" must mean the preferred family leads. Without a grace window the first family to
// ANSWER takes the first launch slot, so a fast IPv4 answer would silently turn the preference
// into "whichever replied first".
//
// The window is bounded in both directions: the non-preferred family is held for at most
// preferredFamilyGrace, so a preferred family that never answers cannot withhold an answer already
// in hand.

// timedFamilyRouter publishes families on a schedule.
type timedFamilyRouter struct {
	adapter.DNSRouter

	v4       netip.Addr
	v6       netip.Addr
	delayV4  time.Duration
	delayV6  time.Duration
	strategy C.DomainStrategy

	// neverV6 makes the IPv6 family never be published, modelling a resolver that has not
	// answered for it.
	neverV6 bool
}

func (r *timedFamilyRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	var waitGroup sync.WaitGroup
	if r.v4.IsValid() {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if r.delayV4 > 0 {
				select {
				case <-time.After(r.delayV4):
				case <-ctx.Done():
					return
				}
			}
			publish(adapter.DNSFamilyResult{
				IPv6: false, Addresses: []netip.Addr{r.v4}, EffectiveStrategy: r.strategy,
			})
		}()
	}
	if r.v6.IsValid() && !r.neverV6 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if r.delayV6 > 0 {
				select {
				case <-time.After(r.delayV6):
				case <-ctx.Done():
					return
				}
			}
			publish(adapter.DNSFamilyResult{
				IPv6: true, Addresses: []netip.Addr{r.v6}, EffectiveStrategy: r.strategy,
			})
		}()
	}
	waitGroup.Wait()
	return nil
}

func (r *timedFamilyRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if r.v4.IsValid() {
		addresses = append(addresses, r.v4)
	}
	if r.v6.IsValid() && !r.neverV6 {
		addresses = append(addresses, r.v6)
	}
	return addresses, nil
}

// dialOrderDialer records the ORDER in which addresses are dialled.
type dialOrderDialer struct {
	access sync.Mutex
	order  []netip.Addr
	start  time.Time
	times  []time.Duration

	// blackhole makes every dial block until the context ends, so the FIRST dial launched wins the
	// ordering observation without any of them succeeding.
	blackhole bool
}

func (d *dialOrderDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.order = append(d.order, destination.Addr)
	d.times = append(d.times, time.Since(d.start))
	d.access.Unlock()

	if d.blackhole {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &countingConn{}, nil
}

func (d *dialOrderDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func (d *dialOrderDialer) firstDialled() (netip.Addr, bool) {
	d.access.Lock()
	defer d.access.Unlock()
	if len(d.order) == 0 {
		return netip.Addr{}, false
	}
	return d.order[0], true
}

func (d *dialOrderDialer) dialTimes() []time.Duration {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]time.Duration(nil), d.times...)
}

// TestPreferredFamilyArrivingWithinGraceIsDialledFirst is §18, §19.
func TestPreferredFamilyArrivingWithinGraceIsDialledFirst(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")

	for _, testCase := range []struct {
		name          string
		strategy      C.DomainStrategy
		fastDelay     time.Duration
		slowDelay     time.Duration
		fastIsV6      bool
		wantFirstIsV6 bool
	}{
		{
			name:          "prefer_ipv6, IPv4 answers first, IPv6 within grace",
			strategy:      C.DomainStrategyPreferIPv6,
			fastDelay:     0,
			slowDelay:     preferredFamilyGrace / 5,
			fastIsV6:      false,
			wantFirstIsV6: true,
		},
		{
			name:          "prefer_ipv4, IPv6 answers first, IPv4 within grace",
			strategy:      C.DomainStrategyPreferIPv4,
			fastDelay:     0,
			slowDelay:     preferredFamilyGrace / 5,
			fastIsV6:      true,
			wantFirstIsV6: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router := &timedFamilyRouter{v4: v4, v6: v6, strategy: testCase.strategy}
			if testCase.fastIsV6 {
				router.delayV6 = testCase.fastDelay
				router.delayV4 = testCase.slowDelay
			} else {
				router.delayV4 = testCase.fastDelay
				router.delayV6 = testCase.slowDelay
			}

			// Blackhole every dial so no connection completes: the ordering of LAUNCHES is what is
			// under test, and a success would end the race before the second candidate starts.
			inner := &dialOrderDialer{start: time.Now(), blackhole: true}

			dialer := &resolveDialer{
				router:   router,
				dialer:   inner,
				parallel: true,
				// Longer than the grace window AND longer than the preferred family's arrival, so
				// the scheduler's own cadence cannot start a dial before the preferred family
				// arrives. That leaves the grace release as the only mechanism under test -
				// otherwise the test would be measuring the fallback cadence instead.
				fallbackDelay: preferredFamilyGrace * 2,
				queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
			}

			// Long enough for the grace window plus the fallback cadence, short enough that the
			// blackholed dial ending on the deadline does not dominate the run.
			ctx, cancel := context.WithTimeout(recoveryContext(), 400*time.Millisecond)
			defer cancel()

			_, _ = dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))

			first, haveFirst := inner.firstDialled()
			require.True(t, haveFirst, "at least one candidate must be dialled")

			firstIsV6 := first.Is6() && !first.Is4In6()
			require.Equal(t, testCase.wantFirstIsV6, firstIsV6,
				"the preferred family answered within the grace window, so it must take the first "+
					"launch slot; got %v first out of %v", first, inner.order)
		})
	}
}

// TestNonPreferredFamilyIsReleasedAfterBoundedGrace is §20.
//
// The preferred family never answers. The non-preferred answer already in hand must be released
// after about one grace period, not held until the lookup finishes.
func TestNonPreferredFamilyIsReleasedAfterBoundedGrace(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")

	router := &timedFamilyRouter{
		v4:       v4,
		v6:       netip.MustParseAddr("2001:db8::1"),
		neverV6:  true,
		strategy: C.DomainStrategyPreferIPv6,
	}
	inner := &dialOrderDialer{start: time.Now(), blackhole: true}

	dialer := &resolveDialer{
		router:        router,
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 5 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 400*time.Millisecond)
	defer cancel()

	_, _ = dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))

	first, haveFirst := inner.firstDialled()
	require.True(t, haveFirst,
		"a non-preferred answer already in hand must be released after a bounded grace; holding "+
			"it until the preferred family answers would stall every connection to a resolver "+
			"that is slow for one family")
	require.False(t, first.Is6() && !first.Is4In6(),
		"with no IPv6 answer at all, the IPv4 address must be used; got %v", first)

	// Bounded: released on the grace timer, not on the lookup finishing.
	require.Less(t, inner.dialTimes()[0], 3*preferredFamilyGrace,
		"the release must be governed by the grace window, not by the lookup's own duration")
}

// TestFeederEmitsThePreferredFamilyFirst is §18's mechanism test.
//
// The scheduler launches the first candidate it receives, so the preference is expressed by the
// ORDER the feeder writes to the candidate stream. This observes that order directly, which
// isolates the feeder from the scheduler's own cadence.
func TestFeederEmitsThePreferredFamilyFirst(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")

	for _, testCase := range []struct {
		name        string
		strategy    C.DomainStrategy
		firstIsV6   bool
		wantFirstV6 bool
	}{
		{"prefer_ipv6 with IPv4 answering first", C.DomainStrategyPreferIPv6, false, true},
		{"prefer_ipv4 with IPv6 answering first", C.DomainStrategyPreferIPv4, true, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router := &timedFamilyRouter{v4: v4, v6: v6, strategy: testCase.strategy}
			if testCase.firstIsV6 {
				router.delayV6 = 0
				router.delayV4 = preferredFamilyGrace / 5
			} else {
				router.delayV4 = 0
				router.delayV6 = preferredFamilyGrace / 5
			}

			inner := &dialOrderDialer{start: time.Now(), blackhole: true}
			dialer := &resolveDialer{
				router:   router,
				dialer:   inner,
				parallel: true,
				// Long enough that the scheduler's cadence cannot start a second candidate before
				// the preferred family arrives; the feeder's order is what is under test.
				fallbackDelay: preferredFamilyGrace * 2,
				queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
			}

			ctx, cancel := context.WithTimeout(recoveryContext(), 400*time.Millisecond)
			defer cancel()

			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
			}()

			// Wait for the FIRST dial to be observed rather than for the context to expire:
			// the ordering is decided the moment the first candidate starts.
			require.Eventually(t, func() bool {
				_, observed := inner.firstDialled()
				return observed
			}, 300*time.Millisecond, 2*time.Millisecond, "a candidate must be dialled")

			first, haveFirst := inner.firstDialled()
			require.True(t, haveFirst, "a candidate must be dialled")

			firstIsV6 := first.Is6() && !first.Is4In6()
			require.Equal(t, testCase.wantFirstV6, firstIsV6,
				"the preferred family answered inside the grace window, so the feeder must emit it "+
					"first; got %v ahead of the preferred family", first)

			cancel()
			<-done
		})
	}
}
