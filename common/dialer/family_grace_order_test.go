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

// graceOrderDeadline bounds the blackholed dial in the grace-order tests.
//
// It is also the yardstick for the fallback cadence in those tests: "longer than the deadline" is
// what makes the cadence unable to start a candidate at all, and expressing the cadence in terms of
// this constant keeps the two in step if the deadline is ever changed.
const graceOrderDeadline = 400 * time.Millisecond

// graceOrderOutOfReachCadence is a fallback delay the test cannot reach.
//
// The two tests below are about WHICH mechanism takes the first launch slot: the grace release,
// which waits for the preferred family, or the fallback cadence, which does not. Giving the cadence
// a delay the test never reaches is what makes that a statement about the product rather than about
// the host: the cadence cannot fire, so the only way any candidate is launched is the grace
// release, and the ordering assertion cannot be decided by which timer the scheduler happened to
// serve first.
const graceOrderOutOfReachCadence = 10 * graceOrderDeadline

// timedFamilyRouter publishes families on a schedule.
type timedFamilyRouter struct {
	adapter.DNSRouter

	v4       netip.Addr
	v6       netip.Addr
	strategy C.DomainStrategy

	// delayV4 and delayV6 publish a family after a sleep. They are for scenarios where a family's
	// schedule is itself the subject.
	//
	// They must NOT be used to place the preferred family inside the grace window: the window is a
	// wall-clock 50ms and a sleep is a wall-clock delay, so a loaded host decides the outcome. Use
	// immediatePreferred for that scenario.
	delayV4 time.Duration
	delayV6 time.Duration

	// neverV6 makes the IPv6 family never be published, modelling a resolver that has not
	// answered for it.
	neverV6 bool

	// immediatePreferred publishes the NON-preferred family and then the preferred one back to
	// back from a single goroutine, instead of giving each its own sleep. It is what makes "the
	// preferred family answered within the grace window" true by construction; see
	// publishNonPreferredThenPreferred.
	immediatePreferred bool
}

// publishNonPreferredThenPreferred publishes the non-preferred family first and the preferred
// family immediately after it, from one goroutine and with no sleep between them.
//
// # Why the scenario cannot be built from a sleep
//
// The product holds the non-preferred family for preferredFamilyGrace (50ms) and releases the
// preferred family ahead of it when it arrives. A fixture that publishes the preferred family after
// a sleep of grace/5 = 10ms leaves 40ms of room, so a host that stretches that sleep past 40ms
// turns the scenario into "the preferred family did NOT answer in time" - and dialling the
// non-preferred family first is then CORRECT product behaviour that the test reports as a failure.
//
// That is not hypothetical. With the fallback cadence already moved out of reach, this test still
// failed 2 runs in 150 at 1-minute load ~450, and the failure message showed a single dialled
// candidate - which, with the cadence unable to fire, can only be the grace timer releasing the
// non-preferred family before the 10ms sleep had elapsed.
//
// Publishing the two back to back takes the sleep out of the scenario: the preferred family's
// arrival is one channel send behind the non-preferred one, so what can still separate them is a
// stall inside the dialer's own feeder between two adjacent receives, rather than a timer the
// fixture set racing a timer the product set.
func (r *timedFamilyRouter) publishNonPreferredThenPreferred(publish func(adapter.DNSFamilyResult)) {
	nonPreferred, nonPreferredIsV6 := r.v4, false
	preferred, preferredIsV6 := r.v6, true
	if r.strategy == C.DomainStrategyPreferIPv4 {
		nonPreferred, nonPreferredIsV6 = r.v6, true
		preferred, preferredIsV6 = r.v4, false
	}
	if nonPreferred.IsValid() && !(nonPreferredIsV6 && r.neverV6) {
		publish(adapter.DNSFamilyResult{
			IPv6: nonPreferredIsV6, Addresses: []netip.Addr{nonPreferred}, EffectiveStrategy: r.strategy,
		})
	}
	if preferred.IsValid() && !(preferredIsV6 && r.neverV6) {
		publish(adapter.DNSFamilyResult{
			IPv6: preferredIsV6, Addresses: []netip.Addr{preferred}, EffectiveStrategy: r.strategy,
		})
	}
}

func (r *timedFamilyRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	if r.immediatePreferred {
		r.publishNonPreferredThenPreferred(publish)
		return nil
	}
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
		wantFirstIsV6 bool
	}{
		{
			name:          "prefer_ipv6, IPv4 answers first, IPv6 within grace",
			strategy:      C.DomainStrategyPreferIPv6,
			wantFirstIsV6: true,
		},
		{
			name:          "prefer_ipv4, IPv6 answers first, IPv4 within grace",
			strategy:      C.DomainStrategyPreferIPv4,
			wantFirstIsV6: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// The non-preferred family is published first and the preferred one immediately
			// after, so "the preferred family answered within the grace window" holds however
			// slow the host is. The scenario used to be a 10ms sleep for the preferred family
			// against the product's 50ms window, which left 40ms of room for the host to turn
			// this into "the preferred family did not answer in time" - a case in which dialling
			// the non-preferred family first is correct.
			router := &timedFamilyRouter{
				v4: v4, v6: v6, strategy: testCase.strategy, immediatePreferred: true,
			}

			// Blackhole every dial so no connection completes: the ordering of LAUNCHES is what is
			// under test, and a success would end the race before the second candidate starts.
			inner := &dialOrderDialer{start: time.Now(), blackhole: true}

			dialer := &resolveDialer{
				router:   router,
				dialer:   inner,
				parallel: true,
				// Out of reach, so the scheduler's own cadence cannot start a dial before the
				// preferred family arrives - or at all. That leaves the grace release as the ONLY
				// mechanism under test, which is what the assertion below is about.
				//
				// The previous value, preferredFamilyGrace*2 = 100ms, did not achieve that: it
				// left a 90ms race between the cadence and the grace release (the preferred family
				// answers at grace/5 = 10ms), so a host loaded enough to delay the grace path past
				// the cadence let the NON-preferred family take the first launch slot and failed
				// this test with the product behaving correctly. Reproduced under load at
				// 1-minute loads of 632 and 229-243; the cadence-out-of-reach form was validated
				// at 300/300 in that same band. Evidence:
				// /tmp/jb/reports/S06b-dns-wallclock.md, Part E.
				fallbackDelay: graceOrderOutOfReachCadence,
				queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
			}

			// Long enough for the grace window, short enough that the blackholed dial ending on
			// the deadline does not dominate the run. The cadence is deliberately far beyond it.
			ctx, cancel := context.WithTimeout(recoveryContext(), graceOrderDeadline)
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
		wantFirstV6 bool
	}{
		{"prefer_ipv6 with IPv4 answering first", C.DomainStrategyPreferIPv6, true},
		{"prefer_ipv4 with IPv6 answering first", C.DomainStrategyPreferIPv4, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// Same construction as the test above: the non-preferred family first, the preferred
			// one immediately behind it, so the feeder's order is not decided by the host.
			router := &timedFamilyRouter{
				v4: v4, v6: v6, strategy: testCase.strategy, immediatePreferred: true,
			}

			inner := &dialOrderDialer{start: time.Now(), blackhole: true}
			dialer := &resolveDialer{
				router:   router,
				dialer:   inner,
				parallel: true,
				// Out of reach for the same reason as the test above: with the cadence able to
				// fire, this test decided the feeder's order by which timer won a 90ms race, and
				// the feeder's order is the thing it exists to observe.
				fallbackDelay: graceOrderOutOfReachCadence,
				queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
			}

			ctx, cancel := context.WithTimeout(recoveryContext(), graceOrderDeadline)
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
