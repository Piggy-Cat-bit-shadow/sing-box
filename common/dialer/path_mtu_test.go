package dialer

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The arithmetic between an inner IP MTU and a QUIC UDP payload
// ---------------------------------------------------------------------------
//
// These numbers are the reason the file exists. A 1280-byte inner tunnel carries a 1232-byte UDP payload
// over IPv6 and a 1252-byte one over IPv4, and the 20-byte difference is the whole IPv6 header. Every
// value below is derived from RFC 8200 / RFC 768 sizes rather than measured, so the test is checking the
// ARITHMETIC and its boundaries; the wire behaviour those numbers produce is measured separately in
// transport/device (inner IP fragmentation) and protocol/hysteria2 (the actual first datagram).

func TestPacketOverheadCeilingByFamily(t *testing.T) {
	cases := []struct {
		name    string
		inner   uint32
		family  IPFamily
		want    uint32
		wantOK  bool
		comment string
	}{
		{
			name: "1280 over IPv6", inner: 1280, family: IPFamilyIPv6,
			want: 1232, wantOK: true,
			comment: "40 + 8 = 48 of overhead; this is the MASQUE default inner MTU",
		},
		{
			name: "1280 over IPv4", inner: 1280, family: IPFamilyIPv4,
			want: 1252, wantOK: true,
			comment: "20 + 8 = 28 of overhead",
		},
		{
			name: "1280 with an undecided family", inner: 1280, family: IPFamilyUnknown,
			want: 1232, wantOK: true,
			comment: "unknown takes the IPv6 budget, because if it MIGHT go over IPv6 then " +
				"IPv6 is the only safe number to size against",
		},
		{
			name: "1280 with no family recorded at all", inner: 1280, family: 0,
			want: 1232, wantOK: true,
			comment: "the zero value is IPFamilyUnknown, and it must not mean IPv4",
		},
		{
			name: "1500 over IPv6", inner: 1500, family: IPFamilyIPv6,
			want: 1452, wantOK: true,
			comment: "an ordinary Ethernet-sized tunnel",
		},
		{
			name: "1500 over IPv4", inner: 1500, family: IPFamilyIPv4,
			want: 1472, wantOK: true,
			comment: "the classic 1472-byte ping payload",
		},
		{
			name: "an unknown inner MTU", inner: 0, family: IPFamilyIPv6,
			wantOK: false,
			comment: "a direct dial has no lower tunnel, and this must stay unknown rather than " +
				"become a default",
		},
		{
			name: "an inner MTU of exactly the IPv6 overhead", inner: 48, family: IPFamilyIPv6,
			wantOK: false,
			comment: "no payload fits; that is a configuration-level impossibility, not a value to " +
				"clamp",
		},
		{
			name: "an inner MTU below the IPv6 overhead", inner: 40, family: IPFamilyIPv6,
			wantOK:  false,
			comment: "underflow must be refused, never wrapped",
		},
		{
			name: "an inner MTU below the IPv4 overhead", inner: 25, family: IPFamilyIPv4,
			wantOK:  false,
			comment: "the same for the smaller header",
		},
		{
			name: "one byte above the IPv6 overhead", inner: 49, family: IPFamilyIPv6,
			want: 1, wantOK: true,
			comment: "the boundary is inclusive of a single byte of payload",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := PacketOverheadCeiling(testCase.inner, testCase.family, 0)
			require.Equal(t, testCase.wantOK, ok, testCase.comment)
			if testCase.wantOK {
				require.Equal(t, testCase.want, got)
				require.Equal(t, testCase.inner, got+uint32(overheadFor(testCase.family)),
					"the ceiling and the overhead must account for the inner MTU exactly")
			} else {
				require.Zero(t, got, "a refused ceiling must not report a number a caller could use")
			}
		})
	}
}

// TestUnknownFamilyIsNeverTheSmallerBudget is the sharp form of the rule above, written separately
// because it is the one whose failure mode is silent: an IPv4-sized packet on an IPv6 path is 20 bytes
// over and fragments, and nothing reports it.
func TestUnknownFamilyIsNeverTheSmallerBudget(t *testing.T) {
	ipv4Ceiling, ok4 := PacketOverheadCeiling(1280, IPFamilyIPv4, 0)
	unknownCeiling, okUnknown := PacketOverheadCeiling(1280, IPFamilyUnknown, 0)
	require.True(t, ok4)
	require.True(t, okUnknown)
	require.Less(t, unknownCeiling, ipv4Ceiling,
		"the undecided family must produce the SMALLER budget; equal would mean it silently chose IPv4")
	require.Equal(t, ipv6HeaderLength-ipv4HeaderLength, int(ipv4Ceiling-unknownCeiling),
		"and the gap must be exactly the IPv6/IPv4 header difference")
}

// ---------------------------------------------------------------------------
// Applying a ceiling to a configured value
// ---------------------------------------------------------------------------

func TestClampToCeiling(t *testing.T) {
	const ceiling = uint32(1232)

	cases := []struct {
		name       string
		configured int
		hasCeiling bool
		want       int
		comment    string
	}{
		{
			name: "no ceiling, nothing configured", configured: 0, hasCeiling: false, want: 0,
			comment: "a direct dial keeps the library default, exactly as before this helper existed",
		},
		{
			name: "no ceiling, something configured", configured: 1500, hasCeiling: false, want: 1500,
			comment: "an operator's value is untouched when there is no proven capacity to violate",
		},
		{
			name: "a ceiling, nothing configured", configured: 0, hasCeiling: true, want: int(ceiling),
			comment: "zero means no preference, and the ceiling IS the preference",
		},
		{
			name: "a ceiling, and the operator asked for less", configured: 1200, hasCeiling: true, want: 1200,
			comment: "a value that already fits is kept: there is nothing to correct",
		},
		{
			name: "a ceiling, and the operator asked for more", configured: 1400, hasCeiling: true, want: int(ceiling),
			comment: "a physical capacity is a correctness constraint, so it beats a preference",
		},
		{
			name: "a ceiling, and the operator asked for exactly it", configured: int(ceiling), hasCeiling: true, want: int(ceiling),
			comment: "the boundary is inclusive",
		},
		{
			name: "a ceiling, one byte over", configured: int(ceiling) + 1, hasCeiling: true, want: int(ceiling),
			comment: "one byte over is still over",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want,
				ClampToCeiling(testCase.configured, ceiling, testCase.hasCeiling), testCase.comment)
		})
	}
}

// ---------------------------------------------------------------------------
// Finding the capacity of a detour
// ---------------------------------------------------------------------------

// fixedMTUEndpoint answers PortMTU with a fixed number, before it is ever started - which is the point:
// an upper protocol is constructed before the tunnel it stacks on is started.
type fixedMTUEndpoint struct {
	adapter.Endpoint
	mtu uint32
}

func (e *fixedMTUEndpoint) PortMTU() uint32 { return e.mtu }

// openEndpoint is an endpoint with no fixed capacity: it does not implement PortMTUProvider.
type openEndpoint struct {
	adapter.Endpoint
}

// fixedEncapEndpoint is a fixed-MTU endpoint that ALSO declares the framing its transport adds inside
// the inner IP packet it carries - the WireGuard shape. Both capabilities are optional and independent:
// a QUIC tunnel implements only the first.
type fixedEncapEndpoint struct {
	fixedMTUEndpoint
	overhead uint32
}

func (e *fixedEncapEndpoint) PortEncapOverhead() uint32 { return e.overhead }

// endpointManagerStub serves the tags a test registers.
type endpointManagerStub struct {
	adapter.EndpointManager
	endpoints map[string]adapter.Endpoint
}

func (m *endpointManagerStub) Get(tag string) (adapter.Endpoint, bool) {
	endpoint, loaded := m.endpoints[tag]
	return endpoint, loaded
}

func capacityContext(endpoints map[string]adapter.Endpoint) context.Context {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	return service.ContextWith[adapter.EndpointManager](ctx, &endpointManagerStub{endpoints: endpoints})
}

func TestDetourPathCapacity(t *testing.T) {
	cases := []struct {
		name     string
		detour   string
		contents map[string]adapter.Endpoint
		want     uint32
		known    bool
		comment  string
	}{
		{
			name:   "no detour at all",
			detour: "",
			want:   0, known: false,
			comment: "a direct dial has no lower tunnel and must stay unknown",
		},
		{
			name:   "a fixed-MTU endpoint",
			detour: "masque-us",
			contents: map[string]adapter.Endpoint{
				"masque-us": &fixedMTUEndpoint{mtu: 1280},
			},
			want: 1280, known: true,
			comment: "this is the case the whole helper exists for: a concrete inner-IP tunnel",
		},
		{
			name:   "an endpoint that publishes no fixed capacity",
			detour: "wg-1",
			contents: map[string]adapter.Endpoint{
				"wg-1": &openEndpoint{},
			},
			want: 0, known: false,
			comment: "an endpoint that does not implement the capability must not be guessed at",
		},
		{
			name:   "an endpoint reporting zero",
			detour: "masque-zero",
			contents: map[string]adapter.Endpoint{
				"masque-zero": &fixedMTUEndpoint{mtu: 0},
			},
			want: 0, known: false,
			comment: "zero is a value the endpoint refused to state, not a capacity of zero bytes",
		},
		{
			name:   "a tag that resolves to nothing",
			detour: "missing",
			contents: map[string]adapter.Endpoint{
				"something-else": &fixedMTUEndpoint{mtu: 1280},
			},
			want: 0, known: false,
			comment: "an unresolvable tag is a missing OPTIONAL capability here; the dependency " +
				"graph, not this helper, is what refuses a detour that names nothing",
		},
		{
			name:   "a tag naming an outbound rather than an endpoint",
			detour: "proxy",
			contents: map[string]adapter.Endpoint{
				"masque-us": &fixedMTUEndpoint{mtu: 1280},
			},
			want: 0, known: false,
			comment: "only endpoints are queried. A detour that names a GROUP, a selector or any " +
				"other outbound has a capacity that depends on runtime selection, and answering it " +
				"here would either take a wrong minimum or consume a selection",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			capacity := DetourPathCapacity(capacityContext(testCase.contents), testCase.detour)
			require.Equal(t, testCase.known, capacity.Known, testCase.comment)
			require.Equal(t, testCase.want, capacity.InnerMTU)
			ceiling, hasCeiling := capacity.QuicPayloadCeiling()
			require.Equal(t, testCase.known, hasCeiling,
				"a capacity that is not known must not produce a ceiling")
			if testCase.known {
				require.Equal(t, uint32(1232), ceiling,
					"a 1280-byte tunnel with an undecided family gives the IPv6 budget")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A lower path that encapsulates INSIDE the inner IP packet
// ---------------------------------------------------------------------------
//
// WireGuard is the case: a 1408-byte inner IP packet contains a WireGuard transport message, which
// contains the payload, so a protocol stacked on it must subtract the transport message's framing as
// well as the outer IP and UDP headers. The two numbers are kept apart - InnerMTU stays what the
// operator configured and what the tunnel device enforces, EncapsulatedOverhead is what this transport
// costs - and the composition happens once, in PacketOverheadCeiling.

// TestADeclaredEncapOverheadIsSubtractedFromTheBudget is the arithmetic half. The measured half - that
// 32 is really what the pinned WireGuard costs on the wire - is
// protocol/wireguard/mtu_budget_test.go.
func TestADeclaredEncapOverheadIsSubtractedFromTheBudget(t *testing.T) {
	// WireGuard's fixed framing: transport header 16 + Poly1305 tag 16.
	const wireGuardOverhead = 32

	cases := []struct {
		name     string
		innerMTU uint32
		family   IPFamily
		overhead uint32
		want     uint32
		wantOK   bool
		comment  string
	}{
		{
			name: "the WireGuard default inner MTU over IPv6", innerMTU: 1408,
			family: IPFamilyIPv6, overhead: wireGuardOverhead,
			want: 1408 - 48 - 32, wantOK: true,
			comment: "1328 bytes of QUIC payload: 40 + 8 of headers and 32 of WireGuard framing",
		},
		{
			name: "the WireGuard default inner MTU over IPv4", innerMTU: 1408,
			family: IPFamilyIPv4, overhead: wireGuardOverhead,
			want: 1408 - 28 - 32, wantOK: true,
			comment: "the IPv4 case is 20 bytes more generous, and that difference is the whole " +
				"reason the family is an argument",
		},
		{
			name: "the WireGuard default with an undecided family", innerMTU: 1408,
			family: IPFamilyUnknown, overhead: wireGuardOverhead,
			want: 1408 - 48 - 32, wantOK: true,
			comment: "an undecided family takes the IPv6 budget, as everywhere else in this file",
		},
		{
			name: "no declared overhead is the case that already worked", innerMTU: 1408,
			family: IPFamilyIPv6, overhead: 0,
			want: 1408 - 48, wantOK: true,
			comment: "a QUIC-based tunnel declares nothing, and its budget must be exactly what it " +
				"was before this capability existed",
		},
		{
			name: "a tunnel of exactly the headers plus the framing", innerMTU: 80,
			family: IPFamilyIPv6, overhead: wireGuardOverhead,
			want: 0, wantOK: false,
			comment: "80 == 48 + 32 exactly: no payload fits, so it must be refused rather than " +
				"reported as a usable zero",
		},
		{
			name: "one byte more than the headers plus the framing", innerMTU: 81,
			family: IPFamilyIPv6, overhead: wireGuardOverhead,
			want: 1, wantOK: true,
			comment: "the boundary is inclusive of a single byte of payload",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			capacity := PathCapacity{
				InnerMTU:             testCase.innerMTU,
				Family:               testCase.family,
				Known:                true,
				EncapsulatedOverhead: testCase.overhead,
			}
			got, ok := capacity.QuicPayloadCeiling()
			require.Equal(t, testCase.wantOK, ok, testCase.comment)
			if !testCase.wantOK {
				require.Zero(t, got, "a refused ceiling must not report a number a caller could use")
				return
			}
			require.Equal(t, testCase.want, got, testCase.comment)
			require.EqualValues(t,
				overheadFor(testCase.family)+int(testCase.overhead), testCase.innerMTU-got,
				"the ceiling, the IP and UDP headers and the declared framing must account for the "+
					"inner MTU exactly, with nothing left over and nothing double-counted")
		})
	}
}

// TestTheEncapOverheadCannotChangeAFamilyThatDeclaresNone is the compatibility control: the field is new
// and every existing provider leaves it zero, so no configuration that worked before may move.
func TestTheEncapOverheadCannotChangeAFamilyThatDeclaresNone(t *testing.T) {
	for _, family := range []IPFamily{IPFamilyUnknown, IPFamilyIPv4, IPFamilyIPv6} {
		for _, innerMTU := range []uint32{1280, 1408, 1500} {
			withZero, okWithZero := PacketOverheadCeiling(innerMTU, family, 0)
			require.True(t, okWithZero)
			require.Equal(t, withZero, innerMTU-uint32(overheadFor(family)),
				"with no declared encapsulation the ceiling must be exactly the pre-existing value")
		}
	}
}

// TestTheDetourReportsTheEncapOverhead is the discovery half: DetourPathCapacity has to carry the
// declared overhead through, or the subtraction above never happens for a real configuration.
func TestTheDetourReportsTheEncapOverhead(t *testing.T) {
	ctx := capacityContext(map[string]adapter.Endpoint{
		"wg-1":     &fixedEncapEndpoint{fixedMTUEndpoint: fixedMTUEndpoint{mtu: 1408}, overhead: 32},
		"masque-1": &fixedMTUEndpoint{mtu: 1280},
	})

	wireGuard := DetourPathCapacity(ctx, "wg-1")
	require.True(t, wireGuard.Known)
	require.EqualValues(t, 1408, wireGuard.InnerMTU,
		"the reported inner MTU stays the CONFIGURED one; the overhead must not be folded into it")
	require.EqualValues(t, 32, wireGuard.EncapsulatedOverhead)
	udpCeiling, hasCeiling := wireGuard.QuicPayloadCeiling()
	require.True(t, hasCeiling)
	require.EqualValues(t, 1408-48-32, udpCeiling)

	masque := DetourPathCapacity(ctx, "masque-1")
	require.True(t, masque.Known)
	require.Zero(t, masque.EncapsulatedOverhead,
		"a tunnel that does not implement the capability declares nothing, and nothing is assumed")
	masqueCeiling, masqueHasCeiling := masque.QuicPayloadCeiling()
	require.True(t, masqueHasCeiling)
	require.EqualValues(t, 1232, masqueCeiling,
		"and its own budget is unchanged by the existence of the new capability")
}

// TestDetourPathCapacityWithoutAManager keeps the helper usable in a process that has no endpoint
// manager at all - a library embedder constructing a dialer directly, and every unit test that does not
// register one. It must answer "unknown", not panic.
func TestDetourPathCapacityWithoutAManager(t *testing.T) {
	capacity := DetourPathCapacity(context.Background(), "masque-us")
	require.False(t, capacity.Known)
	require.Zero(t, capacity.InnerMTU)
}

// TestTheCapabilityIsAnswerableBeforeStart pins the lifecycle requirement in the type itself rather than
// in prose: the fixture below never starts, never initialises a device, and still answers.
//
// This mirrors the MASQUE endpoint defect that made the previous form unusable: `PortMTU()` returned
// `c.device.PortMTU()` while `c.device` was created in `StartStateInitialize`, so an upper protocol
// sizing itself at construction hit a nil interface. The regression test for that lives in
// protocol/masque; this one states the contract every provider must meet.
func TestTheCapabilityIsAnswerableBeforeStart(t *testing.T) {
	endpoint := &fixedMTUEndpoint{mtu: 1280}
	require.EqualValues(t, 1280, endpoint.PortMTU(),
		"a provider must answer before Start: the protocols stacked on it are constructed first")

	capacity := DetourPathCapacity(capacityContext(map[string]adapter.Endpoint{"tunnel": endpoint}), "tunnel")
	require.True(t, capacity.Known)
	require.EqualValues(t, 1280, capacity.InnerMTU)
}

// TestACeilingIsAConsumerContractNotAWireGuarantee records the one consumer in this tree that cannot
// apply the ceiling, and the arithmetic that makes it visible.
//
// # The contract this helper can and cannot keep
//
// `QuicPayloadCeiling` answers "what is the largest UDP payload that fits". Whether that number reaches
// the wire is decided by the protocol that consumes it, one layer down, inside its QUIC
// implementation's own configuration - so a ceiling that is computed and then overridden is not a
// ceiling at all. That is worth pinning here rather than discovering later, because the number this
// helper returns looks identical in both cases.
//
// # The consumer that overrides it: hysteria2 with ChromeParrot
//
// hysteria2 enables ChromeParrot by default. The pinned quic-go forces
// `initialPacketSize = chromeInitialPacketSize` whenever `Config.ChromeParrot` is set
// (config.go:105-125, `chrome_parrot.go:19 chromeInitialPacketSize = 1250`), so an explicit
// `initial_packet_size` is discarded. The measurement is protocol/hysteria2's
// chrome_parrot_first_datagram_test.go: every configured value, 1232 included, produces a 1250-byte
// first datagram.
//
// The consequence is arithmetic and it is stated in the units of each layer: 1250 is a UDP PAYLOAD, so
// over IPv6 it is 1250 + 40 + 8 = 1298 bytes on the wire, which does not fit a 1280-byte path - the
// exact case a proven 1280 ceiling exists for. Over IPv4 it is 1278 bytes, which does.
//
// # Why this is recorded and not fixed here
//
// There is no field of the pinned QUIC configuration that can lower the first flight after
// ChromeParrot's override: `Conn.maxPacketSize()` returns `config.InitialPacketSize` on the client
// while MTU discovery is inactive (connection.go:2905-2920) and that value is the overridden one;
// `MaxPacketBufferSize` is a buffer bound and 1250 is inside it. The only lever in this tree is
// disabling ChromeParrot, which abandons the fingerprint the hysteria2 outbound deliberately presents.
// That is a product decision with a wire-visible cost either way, so the measurement and the
// arithmetic are pinned and the item is reported BLOCKED on the pinned library, not worked around.
func TestACeilingIsAConsumerContractNotAWireGuarantee(t *testing.T) {
	// The number a proven 1280-byte tunnel hands to a stacked QUIC protocol.
	ceiling, hasCeiling := PacketOverheadCeiling(1280, IPFamilyUnknown, 0)
	require.True(t, hasCeiling)
	require.EqualValues(t, 1232, ceiling)

	// The number the Chrome-parroting client actually sends, from the pinned library's own constant.
	const chromeParrotInitialPacketSize = 1250

	require.Greater(t, chromeParrotInitialPacketSize, int(ceiling),
		"the override is LARGER than the ceiling, which is why the ceiling does not hold")
	require.EqualValues(t, ipv4HeaderLength+udpHeaderLength+chromeParrotInitialPacketSize, 1278,
		"over IPv4 the overridden payload is 1278 bytes on an IP path, which a 1280-byte path carries")
	require.EqualValues(t, ipv6HeaderLength+udpHeaderLength+chromeParrotInitialPacketSize, 1298,
		"over IPv6 it is 1298 bytes, which a 1280-byte path does NOT carry - so the ceiling is not "+
			"effective for this consumer over IPv6, and 1232 must not be reported as if it were")
	require.LessOrEqual(t, ipv4HeaderLength+udpHeaderLength+int(ceiling), 1280,
		"the ceiling itself does fit, in both families, which is what makes the override the whole "+
			"of the discrepancy")

	// And the layer rule the whole file turns on, restated where the counter-example is: the ceiling
	// is a UDP payload. Treating it as an IP packet size would compare it against the wrong thing.
	require.EqualValues(t, 1232, 1280-48)
	require.NotEqual(t, 1280, int(ceiling)+ipv6HeaderLength+udpHeaderLength-48,
		"a payload and a packet are different units and must never be substituted for each other")
}

// TestAnUnknownDetourNeverBecomesAConstructionError restates the rule that makes this helper safe to
// call: every failure mode returns "unknown" and NO error, so an outbound whose detour topology the
// helper cannot see keeps working exactly as it did.
func TestAnUnknownDetourNeverBecomesAConstructionError(t *testing.T) {
	ctx := capacityContext(nil)
	for _, detour := range []string{"", "missing", "a-group", "an-outbound"} {
		capacity := DetourPathCapacity(ctx, detour)
		require.False(t, capacity.Known,
			"detour %q must be reported unknown", detour)
		ceiling, hasCeiling := capacity.QuicPayloadCeiling()
		require.False(t, hasCeiling)
		require.Zero(t, ceiling)
		// And the composition keeps the configured value, which is the observable consequence.
		require.Equal(t, 1500, ClampToCeiling(1500, ceiling, hasCeiling),
			"with no proven ceiling the configured value must survive untouched")
	}
	_ = log.NewNOPFactory()
}
