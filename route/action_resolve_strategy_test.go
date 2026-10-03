package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	R "github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

// Tests for the strategy that actionResolve hands to the candidate planner.
//
// # The defect these pin
//
// A resolve action carries its own strategy, defaulting to AsIS, which means "use the resolver's
// default". The lookup honours that: the DNS router applies its configured default and returns
// addresses in the corresponding order. But the candidate planner was then called with the action's
// RAW strategy. For AsIS the planner has a rule - "keep the application's own family first, because
// a recovery is a fallback and not an override" - so it promoted the original's family and
// discarded the preference the resolver had actually applied.
//
// Net effect: a router configured for prefer_ipv6 with an IPv4 original produced an IPv4-first
// plan. The effective policy was resolved in one layer and re-interpreted in the next.
//
// The planner cannot distinguish "AsIS because the caller expressed no preference" from "AsIS
// because that is the literal value that arrived", so the fix belongs at the call site: resolve the
// effective strategy first, then plan with it.

// TestActionResolvePlansByEffectiveStrategy is §17.
func TestActionResolvePlansByEffectiveStrategy(t *testing.T) {
	originalV4 := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.4"), 443)
	originalV6 := M.SocksaddrFrom(netip.MustParseAddr("2001:db8::4"), 443)
	resolved := []netip.Addr{
		netip.MustParseAddr("192.0.2.8"),
		netip.MustParseAddr("2001:db8::8"),
	}

	for _, testCase := range []struct {
		name        string
		original    M.Socksaddr
		effective   C.DomainStrategy
		wantFirstV6 bool
	}{
		{
			name:        "router prefer_ipv6, IPv4 original",
			original:    originalV4,
			effective:   C.DomainStrategyPreferIPv6,
			wantFirstV6: true,
		},
		{
			name:        "router prefer_ipv4, IPv6 original",
			original:    originalV6,
			effective:   C.DomainStrategyPreferIPv4,
			wantFirstV6: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// This is what actionResolve must do: plan with the strategy that actually applied.
			plan := mergeOriginalDestination(testCase.original, resolved, testCase.effective)
			require.NotEmpty(t, plan)

			first := plan[0]
			require.Equal(t, testCase.wantFirstV6, first.Is6() && !first.Is4In6(),
				"the effective strategy is %v, so the plan must lead with that family; got %s first "+
					"out of %v", testCase.effective, first, plan)
		})
	}
}

// TestRawAsISWouldDiscardTheRouterDefault is the negative control.
//
// It demonstrates the drift being fixed, so the test above cannot silently stop meaning anything:
// passing the raw AsIS value produces the OPPOSITE ordering, which is exactly the bug.
func TestRawAsISWouldDiscardTheRouterDefault(t *testing.T) {
	originalV4 := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.4"), 443)
	resolved := []netip.Addr{
		netip.MustParseAddr("192.0.2.8"),
		netip.MustParseAddr("2001:db8::8"),
	}

	asIS := mergeOriginalDestination(originalV4, resolved, C.DomainStrategyAsIS)
	effective := mergeOriginalDestination(originalV4, resolved, C.DomainStrategyPreferIPv6)

	require.False(t, asIS[0].Is6() && !asIS[0].Is4In6(),
		"raw AsIS keeps the original's IPv4 family first - this is the drift")
	require.True(t, effective[0].Is6() && !effective[0].Is4In6(),
		"prefer_ipv6 leads with IPv6")
	require.NotEqual(t, asIS[0], effective[0],
		"the two orderings must differ, otherwise this control proves nothing")
}

// TestActionResolveUsesRouterDefaultEndToEnd drives the REAL actionResolve against a router whose
// configured default is prefer_ipv6.
//
// This is the discriminator for the drift: the resolve action's own strategy is AsIS and the
// application's destination is IPv4, so a raw-strategy planner would lead with IPv4. The assertion
// reads the DestinationAddresses actionResolve actually wrote.
func TestActionResolveUsesRouterDefaultEndToEnd(t *testing.T) {
	resolved := []netip.Addr{
		netip.MustParseAddr("192.0.2.8"),
		netip.MustParseAddr("2001:db8::8"),
	}

	resolver := &strategyReportingDNS{
		defaultStrategy: C.DomainStrategyPreferIPv6,
		addresses:       resolved,
	}
	router := &Router{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		dns:    resolver,
	}

	metadata := &adapter.InboundContext{
		Destination: M.SocksaddrFrom(netip.MustParseAddr("192.0.2.4"), 443),
		Domain:      "sniffed.example",
	}

	action := &R.RuleActionResolve{}
	require.Equal(t, C.DomainStrategyAsIS, action.Strategy,
		"this test is only meaningful while the action's own strategy is AsIS")

	err := router.actionResolve(context.Background(), metadata, action)
	require.NoError(t, err)
	require.NotEmpty(t, metadata.DestinationAddresses)

	first := metadata.DestinationAddresses[0]
	require.True(t, first.Is6() && !first.Is4In6(),
		"the router default is prefer_ipv6, so actionResolve must lead with IPv6; got %v",
		metadata.DestinationAddresses)
}

// strategyReportingDNS reports a configured default for AsIS, like the real router.
type strategyReportingDNS struct {
	adapter.DNSRouter
	defaultStrategy C.DomainStrategy
	addresses       []netip.Addr
}

func (r *strategyReportingDNS) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.addresses, nil
}

func (r *strategyReportingDNS) ResolveStrategy(options adapter.DNSQueryOptions) C.DomainStrategy {
	if options.LookupStrategy != C.DomainStrategyAsIS {
		return options.LookupStrategy
	}
	if options.Strategy != C.DomainStrategyAsIS {
		return options.Strategy
	}
	return r.defaultStrategy
}
