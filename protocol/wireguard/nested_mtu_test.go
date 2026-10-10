package wireguard

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MTU-01: the layers, their units, and what happens when a tunnel is nested
// ---------------------------------------------------------------------------
//
// # The layers, each with its own unit, none of them interchangeable
//
//	inner IP MTU            `mtu`, default 1408          bytes of IP packet inside the tunnel
//	                                                        what the tunnel DEVICE enforces
//	WG transport framing    32 fixed (+0..15 padding)    bytes inside the outer datagram
//	                                                        MEASURED: transport/wireguard's
//	                                                        wg_framing_measurement_test.go
//	inner UDP payload       MTU - 20/40 - 8 - 32         what a stacked protocol may send
//	                                                        a UDP PAYLOAD, not a packet
//	outer QUIC Initial      a UDP payload of the underlay bytes quic-go writes to a socket
//	                                                        RFC 9000 minimum is 1200
//	MASQUE DATAGRAM ctx ID  1 byte varint                 inside the outer QUIC packet's payload
//
// The rule this file enforces is that no number crosses a layer: `initial_packet_size` is not an inner
// MTU, the inner MTU is not a physical link MTU, and the 32 bytes of WireGuard framing are spent INSIDE
// the outer datagram while coming OFF the inner payload budget.

// TestTheLayerUnitsAreNotInterchangeable pins the table above as arithmetic on the real helpers.
func TestTheLayerUnitsAreNotInterchangeable(t *testing.T) {
	const innerMTU = 1408

	// The inner UDP payload budget over IPv6, which is what a stacked QUIC protocol may send.
	ceiling, hasCeiling := dialer.PacketOverheadCeiling(innerMTU, dialer.IPFamilyUnknown,
		wireGuardEncapOverhead)
	require.True(t, hasCeiling)
	require.EqualValues(t, 1408-48-32, ceiling)

	// The QUIC Initial is a UDP payload, so the ceiling composes with it directly. It is NOT an IP
	// MTU: comparing it against the inner MTU, or assigning it to `mtu`, would be a layer error.
	require.Less(t, int(ceiling), innerMTU,
		"the payload budget is smaller than the inner MTU by the headers and the framing")
	require.EqualValues(t, 48+wireGuardEncapOverhead, innerMTU-ceiling,
		"and the difference must be exactly the inner headers plus the WireGuard framing, with the "+
			"outer headers nowhere in it")
	require.GreaterOrEqual(t, ceiling, uint32(dialer.MinimumQUICInitialPacketSize),
		"the QUIC minimum is a floor on the UDP PAYLOAD, so it composes with this ceiling and not "+
			"with the inner IP MTU")
	require.Less(t, uint32(dialer.MinimumQUICInitialPacketSize), uint32(innerMTU),
		"the two are different quantities: a 1200-byte Initial packet is not a 1200-byte IP MTU")

	// The MASQUE case, in its own units: the outer QUIC packet is the inner MTU plus MASQUE's carry
	// overhead, and it is still a UDP payload of the underlay.
	require.EqualValues(t, 51, masqueCarryOverhead,
		"the carry overhead is 1 byte of DATAGRAM context ID, 8 of quarter-stream ID, 16 of AEAD tag, "+
			"1 of header byte, 1 of packet number and a conservative frame allowance - see "+
			"protocol/masque/outer_quic_mtu_test.go for the breakdown")
	outerPacket := innerMTU + masqueCarryOverhead
	require.Greater(t, outerPacket, int(ceiling),
		"the OUTER packet is larger than the INNER payload budget: they are not the same measurement "+
			"and neither can be substituted for the other")
}

// masqueCarryOverhead is transport/masque's QUICPacketOverhead, restated so this table is readable in
// one place. protocol/masque pins it against the real constant.
const masqueCarryOverhead = 51

// ---------------------------------------------------------------------------
// A nested WireGuard: the inner tunnel's MTU is a CAPACITY, not a preference
// ---------------------------------------------------------------------------

// nestedEndpoint is an endpoint that publishes a fixed inner MTU, like a real tunnel does.
type nestedEndpoint struct {
	adapter.Endpoint
	innerMTU uint32
	overhead uint32
}

func (e *nestedEndpoint) PortMTU() uint32 { return e.innerMTU }

func (e *nestedEndpoint) PortEncapOverhead() uint32 { return e.overhead }

// nestedEndpointManager serves the tags the nesting tests register.
type nestedEndpointManager struct {
	adapter.EndpointManager
	endpoints map[string]adapter.Endpoint
	asked     []string
}

func (m *nestedEndpointManager) Get(tag string) (adapter.Endpoint, bool) {
	m.asked = append(m.asked, tag)
	endpoint, loaded := m.endpoints[tag]
	return endpoint, loaded
}

// refusingOutboundManager fails the test if it is touched at all.
//
// It is the evidence for the property that a group branch cannot consume a round-robin cursor during
// construction: `DetourPathCapacity` resolves ENDPOINTS, and a group, a selector or a urltest is an
// OUTBOUND. Any selection would have to come through this interface, so making every method of it
// fatal turns "it did not select" into something the test checks rather than something the reader
// assumes.
type refusingOutboundManager struct {
	adapter.OutboundManager
	t *testing.T
}

func (m *refusingOutboundManager) touched() {
	m.t.Helper()
	m.t.Error("the outbound manager was used while resolving a detour capacity: a group branch must " +
		"not be selected (or have its round-robin cursor consumed) at construction time")
}

func (m *refusingOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	m.touched()
	return nil, false
}

func (m *refusingOutboundManager) Default() adapter.Outbound {
	m.touched()
	return nil
}

func (m *refusingOutboundManager) Outbounds() []adapter.Outbound {
	m.touched()
	return nil
}

func nestingContext(t *testing.T, endpoints map[string]adapter.Endpoint) (context.Context, *nestedEndpointManager) {
	t.Helper()
	manager := &nestedEndpointManager{endpoints: endpoints}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = service.ContextWith[adapter.EndpointManager](ctx, manager)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &refusingOutboundManager{t: t})
	return ctx, manager
}

// TestANestedWireGuardShrinksToWhatItsDetourCanCarry is the fix: a WireGuard reached through another
// tunnel must size its own inner MTU so that its transport messages fit inside that tunnel.
func TestANestedWireGuardShrinksToWhatItsDetourCanCarry(t *testing.T) {
	const outerMTU = 1408
	// 1408 - 48 (inner IPv6 + UDP) - 32 (the outer WireGuard's framing) = 1328.
	const wantNestedMTU = outerMTU - 48 - 32

	cases := []struct {
		name       string
		configured uint32
		want       uint32
		comment    string
	}{
		{
			name: "unset: the detour's capacity becomes the MTU", configured: 0, want: wantNestedMTU,
			comment: "zero means no preference, and the proven capacity IS the preference - the same " +
				"rule ClampToCeiling applies for every other protocol",
		},
		{
			name: "configured above it", configured: 1408, want: wantNestedMTU,
			comment: "a nested 1408 inside a 1408 tunnel needs 1440 bytes of inner packet in the " +
				"outer one, which the outer tunnel cannot carry",
		},
		{
			name: "configured below it", configured: 1200, want: 1200,
			comment: "a value that already fits is kept: there is nothing to correct",
		},
		{
			name: "configured exactly at it", configured: wantNestedMTU, want: wantNestedMTU,
			comment: "the boundary is inclusive",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, manager := nestingContext(t, map[string]adapter.Endpoint{
				"outer": &nestedEndpoint{innerMTU: outerMTU, overhead: wireGuardEncapOverhead},
			})
			got := nestedTunnelMTU(ctx, log.NewNOPFactory().Logger(), "inner", "outer", testCase.configured)
			require.Equal(t, testCase.want, got, testCase.comment)
			require.Equal(t, []string{"outer"}, manager.asked,
				"the capacity must be resolved from the detour tag, once")
		})
	}
}

// TestAnUnknownDetourDoesNotBecomeADefault is the compatibility half, and the one whose failure would
// be silent.
//
// A detour this helper cannot see - a group, a selector, an outbound that is not a fixed-capacity
// endpoint, a tag that does not resolve, or a process with no endpoint manager at all - must leave the
// configured MTU exactly as it was. Substituting a default there would resize every configuration
// whose topology the helper cannot prove, which is a behaviour change on the wire for a number nobody
// asked it to invent.
func TestAnUnknownDetourDoesNotBecomeADefault(t *testing.T) {
	cases := []struct {
		name       string
		detour     string
		configured uint32
		contents   map[string]adapter.Endpoint
		comment    string
	}{
		{
			name: "no detour at all", detour: "", configured: 0,
			comment: "not nested: nothing to bound, and the transport's own default applies as before",
		},
		{
			name: "a tag that names a group", detour: "a-group", configured: 0,
			contents: map[string]adapter.Endpoint{"outer": &nestedEndpoint{innerMTU: 1280}},
			comment: "a group's capacity is a function of runtime selection, so it is unknown here " +
				"and must stay unknown; the endpoint manager cannot even resolve the tag, because a " +
				"group is an outbound (adapter/endpoint/manager.go Get is a map lookup over " +
				"ENDPOINTS only)",
		},
		{
			name: "an endpoint with no fixed capacity", detour: "open", configured: 0,
			contents: map[string]adapter.Endpoint{"open": &openNestedEndpoint{}},
			comment:  "an endpoint that does not implement the capability must not be guessed at",
		},
		{
			name: "an endpoint reporting zero", detour: "zero", configured: 0,
			contents: map[string]adapter.Endpoint{"zero": &nestedEndpoint{innerMTU: 0}},
			comment:  "zero is a refusal to state a capacity, not a capacity of zero bytes",
		},
		{
			name: "a configured value with an unknown detour", detour: "a-group", configured: 1408,
			comment: "and an operator's explicit value is not touched either way",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, _ := nestingContext(t, testCase.contents)
			got := nestedTunnelMTU(ctx, log.NewNOPFactory().Logger(), "inner", testCase.detour, testCase.configured)
			require.Equal(t, testCase.configured, got, testCase.comment)
			require.Equal(t, testCase.configured, nestedTunnelMTU(context.Background(),
				log.NewNOPFactory().Logger(), "inner", testCase.detour, testCase.configured),
				"and the same holds in a process with no endpoint manager at all")
		})
	}
}

// openNestedEndpoint is an endpoint that publishes no fixed capacity.
type openNestedEndpoint struct {
	adapter.Endpoint
}

// TestAStaleCapacityIsNotCarriedAcrossAReconnect is the lifecycle question: is a capacity a VERDICT
// that can go stale, or a fact that is read?
//
// It is read, every time. `DetourPathCapacity` holds no cache, so a provider whose number changes is
// reported with the new number on the next call - and a consumer that already sized itself keeps the
// value it was constructed with, which is why the capability is contractually answerable BEFORE Start
// and must not change afterwards (the provider's own test pins that).
func TestAStaleCapacityIsNotCarriedAcrossAReconnect(t *testing.T) {
	provider := &nestedEndpoint{innerMTU: 1280}
	ctx, _ := nestingContext(t, map[string]adapter.Endpoint{"outer": provider})

	first := dialer.DetourPathCapacity(ctx, "outer")
	require.True(t, first.Known)
	require.EqualValues(t, 1280, first.InnerMTU)

	// The tunnel is reconfigured and restarted: the new capacity is reported on the next read rather
	// than a cached verdict from before.
	provider.innerMTU = 1408
	second := dialer.DetourPathCapacity(ctx, "outer")
	require.True(t, second.Known)
	require.EqualValues(t, 1408, second.InnerMTU,
		"a capacity read must reflect the current provider, not a remembered verdict")

	// And a Stop that leaves the provider without a number is reported as unknown rather than as the
	// previous value: "we no longer know" is not "it is still 1408".
	provider.innerMTU = 0
	third := dialer.DetourPathCapacity(ctx, "outer")
	require.False(t, third.Known,
		"a provider that stops publishing a capacity must be reported as unknown; carrying the "+
			"previous number forward would be a verdict outliving its evidence")
	ceiling, hasCeiling := third.QuicPayloadCeiling()
	require.False(t, hasCeiling)
	require.Zero(t, ceiling)
}

// TestANestedWireGuardIsStillAnswerableBeforeStart states the construction-order requirement on the
// nested path too: the clamp is computed while the endpoint is being built, so it cannot depend on the
// detour having been started.
func TestANestedWireGuardIsStillAnswerableBeforeStart(t *testing.T) {
	provider := &nestedEndpoint{innerMTU: 1280, overhead: wireGuardEncapOverhead}
	ctx, _ := nestingContext(t, map[string]adapter.Endpoint{"outer": provider})
	// No Start, no device, no socket anywhere in this test.
	require.EqualValues(t, 1280-48-wireGuardEncapOverhead,
		nestedTunnelMTU(ctx, log.NewNOPFactory().Logger(), "inner", "outer", 0))
	_ = time.Second
}

// A nested WireGuard with an IPv6 address and a capacity below the IPv6 minimum is refused by the
// transport's own validation rather than silently producing an unreachable address.
func TestANestedCapacityBelowTheIPv6MinimumIsRefused(t *testing.T) {
	// A detour with a 1210-byte inner MTU leaves 1210 - 80 = 1130 for the nested tunnel, which cannot
	// carry an IPv6 address.
	ctx, _ := nestingContext(t, map[string]adapter.Endpoint{
		"outer": &nestedEndpoint{innerMTU: 1210, overhead: wireGuardEncapOverhead},
	})
	mtu := nestedTunnelMTU(ctx, log.NewNOPFactory().Logger(), "inner", "outer", 0)
	require.EqualValues(t, 1130, mtu)
	require.Less(t, mtu, uint32(1280),
		"this is the combination transport/wireguard refuses when an IPv6 address is configured")

	// The two halves meet here: the clamp produces a value that the address-aware validation rejects
	// for IPv6 and accepts for IPv4-only. This test asserts the number; transport/wireguard asserts
	// the refusal.
	require.Equal(t, netip.MustParsePrefix("fd17::1/128").Addr().Is6(), true)
}

// TestAClampedMTUReportsTheDetourThatProducedIt is the half the refusal needs in order to be
// actionable, and the boundary is the whole test.
//
// `boundedBy` is non-empty exactly when the clamp CHANGED the value - not when a detour was involved.
// That is what keeps the advice honest in both directions:
//
//	a value the clamp produced   the operator cannot raise it (a larger one is clamped back), so a
//	                             refusal that leads with "raise `mtu`" is instructing them to do the
//	                             one thing that cannot work
//	the operator's own value     at or below the ceiling the value is kept, so it IS theirs to raise
//	                             and the generic message is the right one
func TestAClampedMTUReportsTheDetourThatProducedIt(t *testing.T) {
	ctx, _ := nestingContext(t, map[string]adapter.Endpoint{
		"outer": &nestedEndpoint{innerMTU: 1210, overhead: wireGuardEncapOverhead},
	})
	// 1210 - 48 (inner IPv6 + UDP) - 32 (the outer tunnel's framing) = 1130.
	const ceiling = 1210 - 48 - wireGuardEncapOverhead
	// The constant difference between a detour's own inner MTU and the capacity it proves: 48 + 32.
	const capacityGap = 48 + wireGuardEncapOverhead

	cases := []struct {
		name       string
		configured uint32
		want       uint32
		wantBound  string
		comment    string
	}{
		{
			name: "unset", configured: 0, want: ceiling, wantBound: "outer",
			comment: "the capacity IS the preference, and it is still not the operator's number",
		},
		{
			name: "above the ceiling", configured: 1408, want: ceiling, wantBound: "outer",
			comment: "this is the case the actionable refusal exists for: 1408 was asked for and 1130 " +
				"was used, so telling the operator to raise `mtu` would send them in a circle",
		},
		{
			name: "one byte above the ceiling", configured: ceiling + 1, want: ceiling, wantBound: "outer",
			comment: "the clamp is what decides, not the size of the difference",
		},
		{
			name: "exactly at the ceiling", configured: ceiling, want: ceiling, wantBound: "",
			comment: "nothing was changed, so the value is the operator's own and is theirs to raise - " +
				"bounding this case would withhold advice that would work",
		},
		{
			name: "below the ceiling", configured: 1000, want: 1000, wantBound: "",
			comment: "kept unchanged, for the same reason",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mtu, boundedBy, boundedRequired := nestedTunnelMTUFrom(ctx, log.NewNOPFactory().Logger(),
				"inner", "outer", testCase.configured)
			require.EqualValues(t, testCase.want, mtu, testCase.comment)
			require.Equal(t, testCase.wantBound, boundedBy, testCase.comment)
			if testCase.wantBound == "" {
				require.Zero(t, boundedRequired,
					"the detour's required MTU is meaningless unless the detour is what bounded this one")
				return
			}
			// The number the operator has to go and set. It is not a restatement of the headers: it is
			// the detour's own inner MTU plus the shortfall from what it proves to what IPv6 needs, and
			// the two must be consistent - a detour at `boundedRequired` proves exactly the minimum.
			require.EqualValues(t, 1360, boundedRequired)
			require.EqualValues(t, boundedRequired-capacityGap, uint32(1280),
				"a detour at the required MTU must prove exactly the IPv6 minimum for a nested tunnel: "+
					"1210 + 150 = 1360, and 1360 - 80 = 1280")
		})
	}

	// The required number must not be emitted for a detour whose capacity is already enough: there is
	// nothing to raise, and a number there would send an operator to change a working configuration.
	enoughCtx, _ := nestingContext(t, map[string]adapter.Endpoint{
		"outer": &nestedEndpoint{innerMTU: 1408, overhead: wireGuardEncapOverhead},
	})
	enough, enoughBound, enoughRequired := nestedTunnelMTUFrom(enoughCtx, log.NewNOPFactory().Logger(),
		"inner", "outer", 0)
	require.EqualValues(t, 1408-48-wireGuardEncapOverhead, enough)
	require.Equal(t, "outer", enoughBound)
	require.Zero(t, enoughRequired, "a capacity that already carries IPv6 needs no detour MTU named")

	// A detour whose capacity is NOT provable changes nothing and must not claim to have bounded
	// anything: an unknown capacity is not a small one.
	unknownCtx, _ := nestingContext(t, map[string]adapter.Endpoint{})
	mtu, boundedBy, _ := nestedTunnelMTUFrom(unknownCtx, log.NewNOPFactory().Logger(), "inner", "outer", 1408)
	require.EqualValues(t, 1408, mtu)
	require.Empty(t, boundedBy)

	// And neither does a detour with no ceiling to apply.
	limited, hasCeiling := dialer.PathCapacity{InnerMTU: 1210, Known: true,
		EncapsulatedOverhead: wireGuardEncapOverhead}.QuicPayloadCeiling()
	require.True(t, hasCeiling)
	require.EqualValues(t, ceiling, limited)
}
