package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Route-options parity between the pre-match decision and the full match path.
//
// # The defect these pin
//
// PreMatch applied only override_address, override_port and udp_timeout, while the full match path
// applied eleven options. The gap was harmless until the Direct Fast Path began deciding in
// pre-match: a connection whose rule set tls_fragment, udp_connect or a network strategy was
// judged eligible before those fields had been recorded, so it took the native path and the
// user's explicit configuration was silently discarded.
//
// # Why these drive the real rule action
//
// Setting metadata.TLSFragment by hand and then calling the predicate would test the predicate
// against a state the production code might never produce - which is exactly the bug. These tests
// go through applyRouteOptionsMetadata as the router calls it, so a field that pre-match forgets
// is a field these tests cannot set.
//
// The route options are applied through the production helper directly rather than by constructing
// an *option.RuleActionRoute, because that type can only be built by the route/rule package and a
// test here cannot import it without a cycle. The helper IS the code path both callers use.

// optionsFixture builds an eligible Router plus the metadata a fast-path candidate would carry.
func optionsFixture(t *testing.T) (*Router, adapter.InboundContext, M.Socksaddr) {
	t.Helper()
	router, _ := eligibleRouter(t)
	router.dnsTransport = &verdictDNSTransport{}
	router.dns = &verdictDNSRouter{}

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	return router, metadata, destination
}

// bypassWithOptions applies the options exactly as the router does, then asks for a verdict.
//
// This mirrors the router's own sequence: apply the route options, then decide.
func bypassWithOptions(router *Router, metadata *adapter.InboundContext, destination M.Socksaddr, options *R.RuleActionRouteOptions) adapter.PreMatchResult {
	applyRouteOptionsMetadata(metadata, options)
	return router.preMatchFlow(context.Background(), metadata, destination, nil, "")
}

// TestRouteOptionsDisableTheFastPath is the parity matrix.
//
// Each option must survive into pre-match, because each one describes behaviour the native path
// does not perform.
func TestRouteOptionsDisableTheFastPath(t *testing.T) {
	networkStrategy := C.NetworkStrategyDefault

	cases := map[string]*R.RuleActionRouteOptions{
		"tls_fragment": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{TLSFragment: true}
		}(),
		"tls_record_fragment": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{TLSRecordFragment: true}
		}(),
		"tls_spoof": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{TLSSpoof: "example.com"}
		}(),
		"udp_connect": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{UDPConnect: true}
		}(),
		"network_strategy": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{NetworkStrategy: &networkStrategy}
		}(),
		"network_type": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{NetworkType: []C.InterfaceType{C.InterfaceTypeWIFI}}
		}(),
		"fallback_network_type": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{FallbackNetworkType: []C.InterfaceType{C.InterfaceTypeCellular}}
		}(),
		"fallback_delay": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{FallbackDelay: 250000000}
		}(),
		"udp_timeout": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{UDPTimeout: 30000000000}
		}(),
		"udp_disable_domain_unmapping": func() *R.RuleActionRouteOptions {
			return &R.RuleActionRouteOptions{UDPDisableDomainUnmapping: true}
		}(),
	}

	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			router, metadata, destination := optionsFixture(t)

			// Without the option the connection is eligible, which makes the test meaningful:
			// the option is the only thing that can change the verdict.
			baseline := bypassWithOptions(router, &metadata, destination, &R.RuleActionRouteOptions{})
			require.Equal(t, adapter.PreMatchBypass, baseline.Action,
				"the fixture must be eligible before the option is applied")

			router, metadata, destination = optionsFixture(t)
			result := bypassWithOptions(router, &metadata, destination, options)

			require.NotEqual(t, adapter.PreMatchBypass, result.Action,
				"%s is configured, so the connection must not take the native path; the option "+
					"would be silently discarded", name)
		})
	}
}

// TestRouteOptionsStillAllowBypassWhenIrrelevant confirms the parity work did not simply disable
// the fast path for every route action.
func TestRouteOptionsStillAllowBypassWhenIrrelevant(t *testing.T) {
	router, metadata, destination := optionsFixture(t)

	options := &R.RuleActionRouteOptions{}
	result := bypassWithOptions(router, &metadata, destination, options)

	require.Equal(t, adapter.PreMatchBypass, result.Action,
		"an empty route action leaves the connection eligible")
}

// TestOverrideStillRewritesTheDestination confirms the pre-existing behaviour is preserved.
func TestOverrideStillRewritesTheDestination(t *testing.T) {
	router, metadata, destination := optionsFixture(t)

	options := &R.RuleActionRouteOptions{
		OverrideAddress: M.ParseSocksaddr("93.184.216.99"),
	}
	result := bypassWithOptions(router, &metadata, destination, options)

	require.Equal(t, M.ParseSocksaddr("93.184.216.99:443"), metadata.Destination,
		"the override must still be applied")
	require.True(t, metadata.RouteOriginalDestination.IsValid(),
		"the pre-rewrite destination must be recorded")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a rewritten destination must not take the native path")
}
