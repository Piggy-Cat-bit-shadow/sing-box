package route

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsspoof"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Route-option semantic equivalence between the pre-match pass and the full match pass.
//
// # What the existing tests could not see
//
// route_options_parity_test.go proves that every FIELD of RuleActionRouteOptions reaches the
// pre-match metadata, and route_options_completeness_test.go proves by reflection that every field
// is handled. Both apply the options themselves, so neither can see the decision each pass makes
// about WHICH ACTIONS contribute options - and that decision was made in two places, with two
// different rules:
//
//	pre-match   applied a bypass action's options unconditionally
//	full match  applied them only when the bypass action named an outbound
//
// # How the divergence is observed from outside
//
// PreMatch takes the metadata BY VALUE, so a caller cannot see what the pass did to it. The pass
// hands its own working copy to each rule's Match, though, so a rule placed after the action in the
// same rule set sees exactly the metadata the action produced. That is the observation point these
// tests use: the verdict from the pass, and the metadata as the next rule received it.
//
// # Why equality is asserted on a snapshot rather than the whole context
//
// The two passes legitimately differ in stage-specific state - the tracker, the chain, sniffing
// state, pre-match bookkeeping - so comparing the two InboundContexts wholesale would be wrong and
// would have to be relaxed into meaninglessness. What must be equal is the POLICY state: the effects
// of the route options, which is what decides how the flow is handled.

// routePolicySnapshot is the policy-relevant state a route action can produce.
//
// Every field of RuleActionRouteOptions has an entry here, and the reflection case below fails if a
// field is added without one, so this cannot silently fall behind the option struct.
type routePolicySnapshot struct {
	Destination               string
	RouteOriginalDestination  string
	DestinationAddresses      []string
	UDPTimeout                time.Duration
	NetworkStrategy           string
	NetworkType               []string
	FallbackNetworkType       []string
	FallbackDelay             time.Duration
	UDPDisableDomainUnmapping bool
	UDPConnect                bool
	TLSFragment               bool
	TLSFragmentFallbackDelay  time.Duration
	TLSRecordFragment         bool
	TLSSpoof                  string
	TLSSpoofMethod            int
	OriginDestinationIsSet    bool
	FakeIP                    bool
}

func snapshotRoutePolicy(metadata *adapter.InboundContext) routePolicySnapshot {
	return routePolicySnapshot{
		Destination:               metadata.Destination.String(),
		RouteOriginalDestination:  metadata.RouteOriginalDestination.String(),
		DestinationAddresses:      addrStrings(metadata.DestinationAddresses),
		UDPTimeout:                metadata.UDPTimeout,
		NetworkStrategy:           networkStrategyString(metadata.NetworkStrategy),
		NetworkType:               interfaceTypeStrings(metadata.NetworkType),
		FallbackNetworkType:       interfaceTypeStrings(metadata.FallbackNetworkType),
		FallbackDelay:             metadata.FallbackDelay,
		UDPDisableDomainUnmapping: metadata.UDPDisableDomainUnmapping,
		UDPConnect:                metadata.UDPConnect,
		TLSFragment:               metadata.TLSFragment,
		TLSFragmentFallbackDelay:  metadata.TLSFragmentFallbackDelay,
		TLSRecordFragment:         metadata.TLSRecordFragment,
		TLSSpoof:                  metadata.TLSSpoof,
		TLSSpoofMethod:            int(metadata.TLSSpoofMethod),
		OriginDestinationIsSet:    metadata.OriginDestination.IsValid(),
		FakeIP:                    metadata.FakeIP,
	}
}

// networkStrategyString renders the strategy, which is a pointer because "unset" is a state the
// router distinguishes from "default".
func networkStrategyString(strategy *C.NetworkStrategy) string {
	if strategy == nil {
		return ""
	}
	return strategy.String()
}

func addrStrings(addresses []netip.Addr) []string {
	if len(addresses) == 0 {
		return nil
	}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.String())
	}
	return result
}

func interfaceTypeStrings(types []C.InterfaceType) []string {
	if len(types) == 0 {
		return nil
	}
	result := make([]string, 0, len(types))
	for _, interfaceType := range types {
		result = append(result, interfaceType.String())
	}
	return result
}

// fixedRule matches everything and carries one action.
type fixedRule struct {
	action adapter.RuleAction
}

func (r *fixedRule) Match(*adapter.InboundContext) bool { return true }
func (r *fixedRule) String() string                     { return "fixed" }
func (r *fixedRule) Type() string                       { return "fixed" }
func (r *fixedRule) Action() adapter.RuleAction         { return r.action }
func (r *fixedRule) Start() error                       { return nil }
func (r *fixedRule) Close() error                       { return nil }

// recordingRule matches everything and keeps the metadata the pass was working on.
//
// It is the observation point: a rule after the action sees the same working copy the action
// mutated, which is the only way to see what a by-value pass did.
type recordingRule struct {
	seen adapter.InboundContext
}

func (r *recordingRule) Match(metadata *adapter.InboundContext) bool {
	r.seen = *metadata
	return true
}
func (r *recordingRule) String() string             { return "recorder" }
func (r *recordingRule) Type() string               { return "recorder" }
func (r *recordingRule) Action() adapter.RuleAction { return &R.RuleActionSniff{} }
func (r *recordingRule) Start() error               { return nil }
func (r *recordingRule) Close() error               { return nil }

// preMatchVerdict runs the real pre-match pass over the given actions and reports its verdict.
//
// It is the observation for actions the pass RETURNS from - route and bypass - because no later
// rule runs and there is nothing else to see. The verdict still discriminates: the pass refuses a
// bypass whose destination was rewritten, so a rewrite shows up as a continue.
func preMatchVerdict(t *testing.T, destination M.Socksaddr, actions ...adapter.RuleAction) adapter.PreMatchResult {
	t.Helper()
	router, _, _ := optionsFixture(t)
	rules := make([]adapter.Rule, 0, len(actions))
	for _, action := range actions {
		rules = append(rules, &fixedRule{action: action})
	}
	router.rules = rules
	return router.PreMatch(fastBypassMetadata(N.NetworkTCP, destination), nil)
}

// preMatchThroughActions runs the real pre-match pass over the given actions and reports the verdict
// plus the policy state as the actions left it.
func preMatchThroughActions(t *testing.T, destination M.Socksaddr, actions ...adapter.RuleAction) (adapter.PreMatchResult, routePolicySnapshot) {
	t.Helper()
	router, _, _ := optionsFixture(t)
	recorder := &recordingRule{}
	rules := make([]adapter.Rule, 0, len(actions)+1)
	for _, action := range actions {
		rules = append(rules, &fixedRule{action: action})
	}
	rules = append(rules, recorder)
	router.rules = rules

	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	result := router.PreMatch(metadata, nil)
	return result, snapshotRoutePolicy(&recorder.seen)
}

// fullPathSnapshot is what the full match path produces for the same actions.
//
// It calls the same per-action application the full match path calls, in the same order, which is
// what makes the comparison an equivalence rather than a comparison of two test helpers. The wiring
// guard below fails if either pass stops using that helper.
func fullPathSnapshot(destination M.Socksaddr, actions ...adapter.RuleAction) routePolicySnapshot {
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	for _, action := range actions {
		applyActionRouteOptions(&metadata, action)
	}
	return snapshotRoutePolicy(&metadata)
}

// bypassActionWithOverride is a bypass action carrying one override.
func bypassActionWithOverride(outbound string) adapter.RuleAction {
	return &R.RuleActionBypass{
		Outbound: outbound,
		RuleActionRouteOptions: R.RuleActionRouteOptions{
			OverrideAddress: M.SocksaddrFrom(netip.MustParseAddr("10.0.0.1"), 0),
		},
	}
}

// TestPreMatchAndFullMatchAgreeOnBypassWithoutOutbound is the divergence this file exists for.
//
// A bypass action with no outbound routes nothing: there is no route for override_address to
// configure, and the packet destination guard treats the same action as "not a decision". If the
// pre-match pass applies its options anyway, it rewrites the destination before computing the
// verdict, the verdict's own "still the packet's destination" test fails, and a rule the operator
// wrote to bypass traffic silently does nothing - while the full match path applies nothing at all.
func TestPreMatchAndFullMatchAgreeOnBypassWithoutOutbound(t *testing.T) {
	destination := M.ParseSocksaddr("93.184.216.34:443")
	action := bypassActionWithOverride("")

	verdict := preMatchVerdict(t, destination, action)

	// The pass returns from this action, so no later rule can observe the metadata; the verdict
	// is what carries the information. A bypass verdict means nothing rewrote the destination,
	// because the verdict's own guard refuses when the destination is no longer the packet's.
	require.Equal(t, destination.String(), fullPathSnapshot(destination, action).Destination,
		"the full match path applies nothing for this action")
	require.Equal(t, routePolicySnapshot{Destination: destination.String(), RouteOriginalDestination: ":0"},
		fullPathSnapshot(destination, action),
		"and the pre-match side must apply nothing either, which the verdict below proves")
	require.Equal(t, adapter.PreMatchBypass, verdict.Action,
		"the bypass verdict must survive; a rewrite is what suppresses it")
}

// TestPreMatchAndFullMatchAgreeOnBypassWithOutbound is the other direction, so the rule cannot be
// "a bypass action never applies its options": with an outbound there is a route to configure.
func TestPreMatchAndFullMatchAgreeOnBypassWithOutbound(t *testing.T) {
	destination := M.ParseSocksaddr("93.184.216.34:443")
	action := bypassActionWithOverride("direct")

	verdict := preMatchVerdict(t, destination, action)

	require.Equal(t, "10.0.0.1:443", fullPathSnapshot(destination, action).Destination,
		"the full match path configures the outbound's route")
	require.NotEqual(t, adapter.PreMatchBypass, verdict.Action,
		"a rewritten destination is no longer the packet's destination, so this cannot bypass")
}

// TestPreMatchAndFullMatchAgreeOnEveryOption drives each field of RuleActionRouteOptions through
// both passes and compares the policy state.
//
// The field list is reflection-checked for the same reason the completeness guard is: a new field
// upstream must not be able to arrive with no case here and still leave these tests green.
func TestPreMatchAndFullMatchAgreeOnEveryOption(t *testing.T) {
	destination := M.ParseSocksaddr("93.184.216.34:443")
	networkStrategy := C.NetworkStrategyHybrid

	type optionCase struct {
		options R.RuleActionRouteOptions
		// verify asserts the field's OWN effect, so a field that is silently dropped fails here
		// even though both passes would still agree with each other.
		verify func(t *testing.T, snapshot routePolicySnapshot)
	}

	options := map[string]optionCase{
		"OverrideAddress": {
			options: R.RuleActionRouteOptions{
				OverrideAddress: M.SocksaddrFrom(netip.MustParseAddr("10.0.0.1"), 0),
			},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, "10.0.0.1:443", snapshot.Destination)
				require.NotEqual(t, ":0", snapshot.RouteOriginalDestination,
					"the pre-rewrite destination is what a later rule needs")
			},
		},
		"OverridePort": {
			options: R.RuleActionRouteOptions{OverridePort: 8443},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, "93.184.216.34:8443", snapshot.Destination)
			},
		},
		"UDPTimeout": {
			options: R.RuleActionRouteOptions{UDPTimeout: 30 * time.Second},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, 30*time.Second, snapshot.UDPTimeout)
			},
		},
		"NetworkStrategy": {
			options: R.RuleActionRouteOptions{NetworkStrategy: &networkStrategy},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, networkStrategy.String(), snapshot.NetworkStrategy)
			},
		},
		"NetworkType": {
			options: R.RuleActionRouteOptions{NetworkType: []C.InterfaceType{C.InterfaceTypeWIFI}},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, []string{C.InterfaceTypeWIFI.String()}, snapshot.NetworkType)
			},
		},
		"FallbackNetworkType": {
			options: R.RuleActionRouteOptions{FallbackNetworkType: []C.InterfaceType{C.InterfaceTypeCellular}},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, []string{C.InterfaceTypeCellular.String()}, snapshot.FallbackNetworkType)
			},
		},
		"FallbackDelay": {
			options: R.RuleActionRouteOptions{FallbackDelay: 250 * time.Millisecond},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, 250*time.Millisecond, snapshot.FallbackDelay)
			},
		},
		"UDPDisableDomainUnmapping": {
			options: R.RuleActionRouteOptions{UDPDisableDomainUnmapping: true},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.True(t, snapshot.UDPDisableDomainUnmapping)
			},
		},
		"UDPConnect": {
			options: R.RuleActionRouteOptions{UDPConnect: true},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.True(t, snapshot.UDPConnect)
			},
		},
		"TLSFragment": {
			options: R.RuleActionRouteOptions{TLSFragment: true},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.True(t, snapshot.TLSFragment)
			},
		},
		"TLSFragmentFallbackDelay": {
			options: R.RuleActionRouteOptions{TLSFragment: true, TLSFragmentFallbackDelay: 100 * time.Millisecond},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, 100*time.Millisecond, snapshot.TLSFragmentFallbackDelay,
					"the delay only means anything alongside the fragment it follows")
			},
		},
		"TLSRecordFragment": {
			options: R.RuleActionRouteOptions{TLSRecordFragment: true},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.True(t, snapshot.TLSRecordFragment)
			},
		},
		"TLSSpoof": {
			options: R.RuleActionRouteOptions{TLSSpoof: "example.com"},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, "example.com", snapshot.TLSSpoof)
			},
		},
		"TLSSpoofMethod": {
			options: R.RuleActionRouteOptions{TLSSpoof: "example.com", TLSSpoofMethod: tlsspoof.MethodWrongAcknowledgment},
			verify: func(t *testing.T, snapshot routePolicySnapshot) {
				require.Equal(t, int(tlsspoof.MethodWrongAcknowledgment), snapshot.TLSSpoofMethod)
			},
		},
	}

	optionFields := make(map[string]bool)
	structType := reflect.TypeOf(R.RuleActionRouteOptions{})
	for i := 0; i < structType.NumField(); i++ {
		optionFields[structType.Field(i).Name] = true
	}
	for name := range options {
		require.True(t, optionFields[name], "case %q does not name a field of RuleActionRouteOptions", name)
		delete(optionFields, name)
	}
	require.Empty(t, optionFields,
		"RuleActionRouteOptions has fields with no equivalence case: %v", optionFields)

	for name, testCase := range options {
		t.Run(name, func(t *testing.T) {
			// The standalone route-options action is used here rather than route(): the pass falls
			// through it instead of returning, so a later rule can observe the metadata, and it
			// reaches the same decision function route() does.
			action := &R.RuleActionRouteOptions{}
			*action = testCase.options

			_, preMatch := preMatchThroughActions(t, destination, action)
			fullMatch := fullPathSnapshot(destination, action)

			require.Equal(t, fullMatch, preMatch, "the passes disagree about %s", name)
			testCase.verify(t, preMatch)
			testCase.verify(t, fullMatch)
		})
	}
}

// TestPreMatchAndFullMatchAgreeOnCombinedOptions covers field interaction, which a per-field matrix
// cannot: an override_address that also has to clear a resolved address list, a port override that
// must keep the address, and fragment options alongside a strategy.
func TestPreMatchAndFullMatchAgreeOnCombinedOptions(t *testing.T) {
	destination := M.ParseSocksaddr("93.184.216.34:443")
	networkStrategy := C.NetworkStrategyFallback

	// All three are non-returning, so the recorder observes the combined effect. They reach the
	// same decision function the returning actions do.
	combined := []adapter.RuleAction{
		&R.RuleActionRouteOptions{OverrideAddress: M.SocksaddrFrom(netip.MustParseAddr("10.0.0.1"), 0)},
		&R.RuleActionRouteOptions{OverridePort: 8443},
		&R.RuleActionRouteOptions{
			NetworkStrategy:     &networkStrategy,
			TLSFragment:         true,
			UDPConnect:          true,
			FallbackNetworkType: []C.InterfaceType{C.InterfaceTypeCellular},
		},
	}

	_, preMatch := preMatchThroughActions(t, destination, combined...)
	fullMatch := fullPathSnapshot(destination, combined...)

	require.Equal(t, fullMatch, preMatch)
	require.Equal(t, "10.0.0.1:8443", preMatch.Destination,
		"the address from the first rule and the port from the second")
	require.True(t, preMatch.TLSFragment)
	require.True(t, preMatch.UDPConnect)
}

// TestOverrideAddressClearsResolvedAddressesInBothPasses pins the ordering hazard inside the shared
// applier: a resolved address list belongs to the pre-rewrite destination, so it must be invalidated
// when the destination is overridden - in both passes, not just one.
func TestOverrideAddressClearsResolvedAddressesInBothPasses(t *testing.T) {
	destination := M.ParseSocksaddrHostPort("example.com", 443)

	build := func() adapter.InboundContext {
		metadata := fastBypassMetadata(N.NetworkTCP, destination)
		metadata.DestinationAddresses = []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("93.184.216.35"),
		}
		return metadata
	}

	action := &R.RuleActionRouteOptions{
		OverrideAddress: M.SocksaddrFrom(netip.MustParseAddr("10.0.0.1"), 0),
	}

	fullMetadata := build()
	require.True(t, applyActionRouteOptions(&fullMetadata, action))
	require.Empty(t, fullMetadata.DestinationAddresses,
		"a rewritten destination must not keep the addresses resolved for the old one")

	router, _, _ := optionsFixture(t)
	recorder := &recordingRule{}
	router.rules = []adapter.Rule{&fixedRule{action: action}, recorder}
	preMatchMetadata := build()
	router.PreMatch(preMatchMetadata, nil)
	require.Empty(t, recorder.seen.DestinationAddresses,
		"and the pre-match pass must not keep them either")

	require.Equal(t,
		snapshotRoutePolicy(&fullMetadata),
		snapshotRoutePolicy(&recorder.seen),
		"the two passes must agree about the destination and its addresses")
}

// TestBothPassesShareTheActionDecision is the wiring guard for the arrangement above.
//
// The equivalence tests compare the pre-match pass against applyActionRouteOptions. That comparison
// only means something if the full match path also applies options through it, and if neither pass
// applies any action's options by another route: a second decision site is exactly the defect this
// file was written for. This is a source check because the property is about which function the two
// call sites reach, not about a behaviour a unit test can observe.
func TestBothPassesShareTheActionDecision(t *testing.T) {
	source := readRouteSource(t, "route.go")

	require.Contains(t, source, "func routeOptionsForAction(",
		"the action-to-options decision must exist in one place")
	require.Contains(t, source, "func applyActionRouteOptions(",
		"and be applied through one function")

	// One definition, one call from the full match path, and three from the pre-match pass's
	// action switch - the three action types that can carry options.
	require.Equal(t, 1, countOccurrences(source, "func applyActionRouteOptions("))
	require.Equal(t, 1, countOccurrences(source, "applyActionRouteOptions(metadata, currentRule.Action())"),
		"the full match path applies options through the shared decision")
	require.Equal(t, 3, countOccurrences(source, "applyActionRouteOptions(&metadata, action)"),
		"and the pre-match pass does so for each action that can carry options")

	// The field-level applier has one implementation and one caller: the shared decision. A second
	// caller is how the two passes diverged in the first place.
	require.Equal(t, 1, countOccurrences(source, "func applyRouteOptionsMetadata("))
	require.Equal(t, 1, countOccurrences(source, "applyRouteOptionsMetadata(metadata, routeOptions)"),
		"only the shared decision may apply options")
}

func countOccurrences(source string, needle string) int {
	return strings.Count(source, needle)
}
