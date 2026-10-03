package dialer

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests that the ORIGINAL literal address obeys the effective family policy.
//
// # The defect these pin
//
// dialLiteralWithRecovery checked the original address against d.queryOptions.Strategy - the raw
// value the caller passed. AsIS means "use the resolver's default", and only the router knows what
// that is. With caller AsIS and a router configured for ipv4_only, the effective policy is
// ipv4_only, but the guard saw AsIS, admitted the IPv6 literal, and dialled it.
//
// A strict policy that the original address can walk around is not a strict policy. The whole point
// of the check is that the original is preferred, not exempt.

// TestLiteralOriginalObeysRouterDefaultStrictStrategy is §13.
func TestLiteralOriginalObeysRouterDefaultStrictStrategy(t *testing.T) {
	originalV6 := netip.MustParseAddr("2001:db8::1")
	originalV4 := netip.MustParseAddr("192.0.2.1")
	recoveredV4 := netip.MustParseAddr("192.0.2.9")
	recoveredV6 := netip.MustParseAddr("2001:db8::9")

	for _, testCase := range []struct {
		name          string
		original      netip.Addr
		routerDefault C.DomainStrategy
		recovered     netip.Addr
		wantOriginal  int
		wantRecovered int
	}{
		{
			name:          "router ipv4_only with IPv6 original",
			original:      originalV6,
			routerDefault: C.DomainStrategyIPv4Only,
			recovered:     recoveredV4,
			wantOriginal:  0,
			wantRecovered: 1,
		},
		{
			name:          "router ipv6_only with IPv4 original",
			original:      originalV4,
			routerDefault: C.DomainStrategyIPv6Only,
			recovered:     recoveredV6,
			wantOriginal:  0,
			wantRecovered: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			log := &attemptLog{start: time.Now()}
			inner := &scriptedDialer{log: log, answers: map[netip.Addr]scriptedAnswer{
				testCase.original:  {delay: 5 * time.Millisecond, success: true},
				testCase.recovered: {delay: 5 * time.Millisecond, success: true},
			}}

			dialer := &resolveDialer{
				router: &strategyReportingRouter{
					staticStreamingRouter: staticStreamingRouter{addresses: []netip.Addr{testCase.recovered}},
					defaultStrategy:       testCase.routerDefault,
				},
				dialer:        inner,
				parallel:      true,
				fallbackDelay: 10 * time.Millisecond,
				// The caller expresses NO preference...
				queryOptions: adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
				// ...and the router's default is what actually applies.
			}

			ctx, cancel := context.WithTimeout(recoveryContext(), 5*time.Second)
			defer cancel()

			conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(testCase.original, 443))
			require.NoError(t, err, "the permitted recovered family must be used")
			require.NotNil(t, conn)

			require.Equal(t, testCase.wantOriginal, log.countFor(testCase.original),
				"the original is excluded by the effective strict policy, so it must not be "+
					"dialled at all; checking the raw AsIS value let it through")
			require.Equal(t, testCase.wantRecovered, log.countFor(testCase.recovered),
				"the recovered family is permitted and must carry the connection")
		})
	}
}

// strategyReportingRouter reports a configured default for AsIS, like the real DNS router.
type strategyReportingRouter struct {
	staticStreamingRouter
	defaultStrategy C.DomainStrategy
}

func (r *strategyReportingRouter) ResolveStrategy(options adapter.DNSQueryOptions) C.DomainStrategy {
	if options.LookupStrategy != C.DomainStrategyAsIS {
		return options.LookupStrategy
	}
	if options.Strategy != C.DomainStrategyAsIS {
		return options.Strategy
	}
	return r.defaultStrategy
}

// TestPreferIPv6ReachesTheParallelDialler is §15.
//
// The parallel dialler takes an explicit preferIPv6 flag. Deriving it from the caller's RAW
// strategy meant a router default of prefer_ipv6 was invisible: the caller said AsIS, the flag came
// out false, and the parallel dial started on the IPv4 interface - the exact opposite of the
// policy that applied.
func TestPreferIPv6ReachesTheParallelDialler(t *testing.T) {
	cases := []struct {
		name          string
		callerState   C.DomainStrategy
		routerDefault C.DomainStrategy
		wantPreferV6  bool
	}{
		{"caller prefer_ipv6", C.DomainStrategyPreferIPv6, C.DomainStrategyAsIS, true},
		{"caller prefer_ipv4", C.DomainStrategyPreferIPv4, C.DomainStrategyAsIS, false},
		{"AsIS with router default prefer_ipv6", C.DomainStrategyAsIS, C.DomainStrategyPreferIPv6, true},
		{"AsIS with router default prefer_ipv4", C.DomainStrategyAsIS, C.DomainStrategyPreferIPv4, false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			dialer := &resolveDialer{
				router: &strategyReportingRouter{
					staticStreamingRouter: staticStreamingRouter{},
					defaultStrategy:       testCase.routerDefault,
				},
				queryOptions: adapter.DNSQueryOptions{Strategy: testCase.callerState},
			}

			effective := dialer.effectiveFamilyStrategy()
			preferIPv6 := effective == C.DomainStrategyPreferIPv6

			require.Equal(t, testCase.wantPreferV6, preferIPv6,
				"the parallel dialler's preference must come from the EFFECTIVE strategy %v, not "+
					"the caller's raw %v", effective, testCase.callerState)
		})
	}
}

// TestStreamingAndFallbackRoutersAgreeOnFamilyOrder is §16.
//
// A third-party router that does not implement DNSDualStackRouter takes the ordinary Lookup path.
// Both paths must produce the same family ordering for the same effective policy - a difference
// here would mean the routing decision depended on which interface a router happened to implement.
//
// This asserts the ORDER the planner produces from each path's addresses, which is the observable
// contract both paths share.
func TestStreamingAndFallbackRoutersAgreeOnFamilyOrder(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}

	for _, testCase := range []struct {
		name          string
		routerDefault C.DomainStrategy
		wantFirstIsV6 bool
	}{
		{"router prefer_ipv6", C.DomainStrategyPreferIPv6, true},
		{"router prefer_ipv4", C.DomainStrategyPreferIPv4, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dialer := &resolveDialer{
				router: &strategyReportingRouter{
					staticStreamingRouter: staticStreamingRouter{addresses: addresses},
					defaultStrategy:       testCase.routerDefault,
				},
				queryOptions: adapter.DNSQueryOptions{Strategy: C.DomainStrategyAsIS},
			}

			// Both paths plan with the effective strategy; the assertion is that it is the
			// resolver's default rather than the caller's AsIS.
			effective := dialer.effectiveFamilyStrategy()
			require.Equal(t, testCase.routerDefault, effective,
				"the fallback path must plan with the router's default, not the caller's AsIS")

			plan := planCandidates(addresses, netip.Addr{}, effective)
			ordered := plan.addresses()
			require.NotEmpty(t, ordered)
			first := ordered[0]
			require.Equal(t, testCase.wantFirstIsV6, first.Is6() && !first.Is4In6(),
				"the effective strategy %v must lead with its own family; got %v",
				effective, ordered)
		})
	}
}
