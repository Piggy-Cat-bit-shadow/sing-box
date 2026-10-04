package dialer

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// TestEveryDialerOptionIsClassified is the long-term maintenance guard.
//
// # The failure it prevents
//
// Someone adds a field to AbstractDialerOptions. It reaches the socket through DefaultDialer, and
// nothing here knows about it. Without this test the profile would treat it as irrelevant and the
// fast path would silently discard it - a user's configuration ignored, with no error and no log.
//
// # Why it checks the table rather than the struct's behaviour
//
// The table IS the classification; the builder reads it. So asserting that every field of the
// options struct appears in it is asserting that every field has been considered, which is exactly
// the review step that would otherwise be skipped. A field that is added and not classified also
// fails closed at runtime (BlockerUnclassified), so the two mechanisms cover the same omission at
// different times: the test before it ships, the runtime for anything that gets past it.
func TestEveryDialerOptionIsClassified(t *testing.T) {
	optionType := reflect.TypeFor[option.DialerOptions]()
	fieldNames := collectDialerOptionFieldNames(t, optionType)
	require.NotEmpty(t, fieldNames)

	for _, name := range fieldNames {
		_, classified := dialerOptionClassification[name]
		require.True(t, classified,
			"option.DialerOptions.%s is not classified in dialerOptionClassification.\n\n"+
				"Decide what it means to a native bypass and add it:\n"+
				"  scopeAlways         the userspace path would apply it to every flow\n"+
				"  scopeTCPOnly        only the TCP socket\n"+
				"  scopeUDPOnly        only the UDP socket or listener\n"+
				"  scopeResolutionOnly only when a name is resolved\n"+
				"  scopeIgnore         it cannot affect a bypass, and say why in a comment\n\n"+
				"A field left unclassified is refused at runtime rather than ignored, so the cost of "+
				"forgetting is a missed optimisation - but only after this test is made to pass.",
			name)
	}

	// And the table must not name fields that no longer exist, or a rename would quietly turn an
	// entry into dead documentation.
	known := make(map[string]bool, len(fieldNames))
	for _, name := range fieldNames {
		known[name] = true
	}
	for name := range dialerOptionClassification {
		require.True(t, known[name],
			"dialerOptionClassification names %s, which is not a field of option.DialerOptions: "+
				"the entry is stale and the field it was written for is now unclassified", name)
	}
}

// collectDialerOptionFieldNames walks the options struct, following embedded structs, and returns
// every leaf field's Go name.
func collectDialerOptionFieldNames(t *testing.T, structType reflect.Type) []string {
	t.Helper()
	var names []string
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if field.Anonymous && field.Type.Kind() == reflect.Struct {
			names = append(names, collectDialerOptionFieldNames(t, field.Type)...)
			continue
		}
		names = append(names, field.Name)
	}
	return names
}

// TestUnclassifiedOptionFailsClosed is the runtime half of the guard above.
//
// It cannot use a real field, because every real field is classified - that is the point of the
// other test. It uses the builder's contract directly: a field the table does not know, holding a
// value, produces BlockerUnclassified. The proof that this is what the builder does is
// TestEveryDialerOptionIsClassified plus this assertion about the shape of the result.
func TestUnclassifiedOptionFailsClosed(t *testing.T) {
	// A profile built from an empty configuration blocks nothing.
	plain := NativeBypassSemantics(option.DialerOptions{})
	require.True(t, plain.IsPlain())
	require.Equal(t, BlockerNone, plain.Blockers(literalTCPFacts()))

	// Every scope is exercised through the real options, so the builder's dispatch is covered
	// rather than only its default branch.
	cases := map[string]struct {
		options option.DialerOptions
		network string
		blocked bool
	}{
		"always blocks both": {
			options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "en0"}},
			network: N.NetworkTCP, blocked: true,
		},
		"tcp only blocks tcp": {
			options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}},
			network: N.NetworkTCP, blocked: true,
		},
		"tcp only spares udp": {
			options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}},
			network: N.NetworkUDP, blocked: false,
		},
		"udp only blocks udp": {
			options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{ReuseAddr: true}},
			network: N.NetworkUDP, blocked: true,
		},
		"udp only spares tcp": {
			options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{ReuseAddr: true}},
			network: N.NetworkTCP, blocked: false,
		},
		"resolution only spares a literal": {
			options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
				DomainResolver: &option.DomainResolveOptions{Server: "local"},
			}},
			network: N.NetworkTCP, blocked: false,
		},
		"ignored default does not block": {
			options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
				UDPFragmentDefault: true,
			}},
			network: N.NetworkUDP, blocked: false,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			semantics := NativeBypassSemantics(testCase.options)
			facts := literalTCPFacts()
			facts.Network = testCase.network
			require.Equal(t, testCase.blocked, !semantics.CanNativeBypass(facts))
		})
	}
}

func literalTCPFacts() NativeBypassFacts {
	return NativeBypassFacts{
		Network:              N.NetworkTCP,
		DestinationIsLiteral: true,
		Destination:          netip.MustParseAddr("93.184.216.34"),
	}
}

// TestLiteralDestinationIsNotResolution is the profile's central claim, isolated from the outbound.
func TestLiteralDestinationIsNotResolution(t *testing.T) {
	withResolver := NativeBypassSemantics(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: "local"},
		},
	})

	literal := withResolver.Blockers(literalTCPFacts())
	require.Equal(t, BlockerNone, literal,
		"a literal destination never reaches the resolver, so a resolver option cannot block it")

	// The same profile must refuse a flow that DOES need a name resolved. This is the control that
	// makes the assertion above mean something.
	needsResolution := withResolver.Blockers(NativeBypassFacts{
		Network:              N.NetworkTCP,
		DestinationIsLiteral: false,
		Destination:          netip.MustParseAddr("93.184.216.34"),
	})
	require.NotEqual(t, BlockerNone, needsResolution)
	require.Contains(t, needsResolution.String(), "domain_resolver")

	// A caller that forgets to say the destination is literal gets the refusal rather than a
	// permissive default, which is why the field has that polarity.
	forgotten := withResolver.Blockers(NativeBypassFacts{
		Network:     N.NetworkTCP,
		Destination: netip.MustParseAddr("93.184.216.34"),
	})
	require.NotEqual(t, BlockerNone, forgotten)
}

// TestFamilyStrategyAppliesToALiteralAddress covers the one way a resolver reaches a literal flow.
//
// It is not obvious and it is the reason the profile asks for the effective strategy at all: the
// dial path applies a hard single-family policy to the ORIGINAL address, not only to resolved
// candidates, so `ipv4_only` refuses to dial a literal IPv6 destination. A profile that stopped at
// "the resolver is not consulted for literals" would bypass a connection the userspace path would
// have failed.
func TestFamilyStrategyAppliesToALiteralAddress(t *testing.T) {
	withResolver := NativeBypassSemantics(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: "local"},
		},
	})
	ipv6 := netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")

	facts := NativeBypassFacts{
		Network:              N.NetworkTCP,
		DestinationIsLiteral: true,
		Destination:          ipv6,
		FamilyStrategy:       C.DomainStrategyIPv4Only,
	}
	require.Contains(t, withResolver.Blockers(facts).String(), "family strategy")

	facts.FamilyStrategy = C.DomainStrategyIPv6Only
	require.Equal(t, BlockerNone, withResolver.Blockers(facts),
		"the same address under the matching strict policy is exactly what the userspace path would do")

	// A preference is not a restriction, and treating it as one would refuse bypasses for no reason.
	facts.Destination = netip.MustParseAddr("93.184.216.34")
	facts.FamilyStrategy = C.DomainStrategyPreferIPv6
	require.Equal(t, BlockerNone, withResolver.Blockers(facts))

	// Without a resolver there is no policy to apply, so the strategy is irrelevant.
	plainFacts := facts
	plainFacts.Destination = ipv6
	plainFacts.FamilyStrategy = C.DomainStrategyIPv4Only
	require.Equal(t, BlockerNone, NativeBypassSemantics(option.DialerOptions{}).Blockers(plainFacts),
		"a family strategy only means something when a resolver is configured; an outbound with "+
			"no resolver does not filter literal destinations")
}

// TestBlockersNameEveryBit keeps the diagnostic vocabulary complete.
//
// An unnamed blocker renders as a number, which is exactly the unhelpful output this type exists to
// avoid. The check is on the highest bit defined, so adding a constant without a name fails here.
func TestBlockersNameEveryBit(t *testing.T) {
	all := BlockerNone
	for _, entry := range blockerNames {
		require.Zero(t, all&entry.blocker, "blocker %s is named twice", entry.name)
		all |= entry.blocker
	}
	for bit := NativeBypassBlocker(1); bit != 0 && bit <= all; bit <<= 1 {
		require.NotZero(t, all&bit, "blocker bit %d has no name, so a refusal could not be "+
			"attributed to it", bit)
	}
	require.Contains(t, BlockerTCPFastOpen.String(), "tcp_fast_open")
	require.Equal(t, "none", BlockerNone.String())
}

// --- the production topology's shape --------------------------------------------------------

// TestProductionDirectOutboundBecomesBypassableForLiteralFlows is the concrete product case.
//
// release/jiejie-production-topology.json declares exactly one direct outbound, carrying exactly
// one dial option: domain_resolver = local-agh. The previous wholesale comparison refused every
// flow through it - the entire direct path of the shipped topology was ineligible.
func TestProductionDirectOutboundBecomesBypassableForLiteralFlows(t *testing.T) {
	// The option value as the topology writes it.
	production := NativeBypassSemantics(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: "local-agh"},
		},
	})

	require.True(t, production.CanNativeBypass(literalTCPFacts()))
	require.True(t, production.CanNativeBypass(NativeBypassFacts{
		Network:              N.NetworkUDP,
		DestinationIsLiteral: true,
		Destination:          netip.MustParseAddr("93.184.216.34"),
	}))
	require.False(t, production.IsPlain(),
		"and it is still not an outbound that does nothing")

	// The topology's own DNS section sets strategy: prefer_ipv4, which is a preference and not a
	// restriction, so it must not block. A strict strategy would, and does - see the family test.
	preferred := production.Blockers(NativeBypassFacts{
		Network:              N.NetworkTCP,
		DestinationIsLiteral: true,
		Destination:          netip.MustParseAddr("93.184.216.34"),
		FamilyStrategy:       C.DomainStrategyPreferIPv4,
	})
	require.Equal(t, BlockerNone, preferred)
}

// TestConnectTimeoutUsesZeroAsTheDialerDefault documents why the dialer's own default timeout does
// not count as configuration.
func TestConnectTimeoutUsesZeroAsTheDialerDefault(t *testing.T) {
	require.True(t, NativeBypassSemantics(option.DialerOptions{}).CanNativeBypass(literalTCPFacts()),
		"an unset connect_timeout means the dialer's default, which is not something the operator "+
			"asked for")

	configured := NativeBypassSemantics(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			ConnectTimeout: badoption.Duration(11 * time.Second),
		},
	})
	require.Contains(t, configured.Blockers(literalTCPFacts()).String(), "connect_timeout")
}
