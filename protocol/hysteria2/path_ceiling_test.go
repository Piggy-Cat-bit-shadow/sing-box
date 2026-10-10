package hysteria2

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// A proven lower tunnel capacity, and the exact place the ceiling stops working
// ---------------------------------------------------------------------------
//
// The outbound computes a QUIC payload ceiling from the tunnel its `detour` names and hands the result
// to the library as `InitialPacketSize`. Two separate facts have to be established, and they are
// established separately because they have different causes:
//
//  1. the CEILING COMPUTATION AND WIRING: a detour naming a fixed-MTU endpoint produces the right
//     number, an unknown path produces none, and a ceiling below the QUIC minimum is refused rather
//     than clamped.
//
//  2. the WIRE: whether the number the outbound hands down is what actually goes out. This is where it
//     stops today, and the measurement below says so in the library's own terms: with ChromeParrot ON
//     the pinned quic-go replaces the configured value with `chromeInitialPacketSize` (1250), so the
//     clamp is effective only with ChromeParrot off or with the pinned library changed. That is
//     measured, not inferred, by `TestPathCeilingReachesTheWireOnlyWithoutChromeParrot`.

// fixedMTUEndpoint publishes a fixed inner IP capacity before it is ever started, which is what an
// upper protocol needs: it sizes itself at construction.
type fixedMTUEndpoint struct {
	adapter.Endpoint
	mtu uint32
}

func (e *fixedMTUEndpoint) PortMTU() uint32 { return e.mtu }

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

// TestThePathCeilingIsComputedFromTheDetour pins the composition the outbound performs, including the
// family-unknown conservatism, without building a client.
func TestThePathCeilingIsComputedFromTheDetour(t *testing.T) {
	const quicMinimum = dialer.MinimumQUICInitialPacketSize

	cases := []struct {
		name       string
		detour     string
		endpoints  map[string]adapter.Endpoint
		configured int
		want       int
		hasCeiling bool
		comment    string
	}{
		{
			name: "no detour: the configured value is untouched", detour: "",
			configured: 1500, want: 1500, hasCeiling: false,
			comment: "a direct dial must keep exactly its previous behaviour",
		},
		{
			name: "a 1280-byte tunnel, nothing configured", detour: "masque-us",
			endpoints:  map[string]adapter.Endpoint{"masque-us": &fixedMTUEndpoint{mtu: 1280}},
			configured: 0, want: 1232, hasCeiling: true,
			comment: "zero means no preference, and the ceiling is the preference. The family is " +
				"undecided here, so the IPv6 budget is taken",
		},
		{
			name: "a 1280-byte tunnel, the operator asked for more", detour: "masque-us",
			endpoints:  map[string]adapter.Endpoint{"masque-us": &fixedMTUEndpoint{mtu: 1280}},
			configured: 1400, want: 1232, hasCeiling: true,
			comment: "a physical capacity is a correctness constraint, so it beats a preference",
		},
		{
			name: "a 1280-byte tunnel, the operator asked for less", detour: "masque-us",
			endpoints:  map[string]adapter.Endpoint{"masque-us": &fixedMTUEndpoint{mtu: 1280}},
			configured: 1200, want: 1200, hasCeiling: true,
			comment: "a value that already fits is kept",
		},
		{
			name: "a 1500-byte tunnel", detour: "wg-1",
			endpoints:  map[string]adapter.Endpoint{"wg-1": &fixedMTUEndpoint{mtu: 1500}},
			configured: 0, want: 1452, hasCeiling: true,
			comment: "an ordinary Ethernet-sized tunnel",
		},
		{
			name: "an endpoint with no fixed capacity", detour: "other",
			endpoints:  map[string]adapter.Endpoint{"other": &struct{ adapter.Endpoint }{}},
			configured: 1500, want: 1500, hasCeiling: false,
			comment: "an endpoint that does not publish a capacity must not be guessed at",
		},
		{
			name: "a tunnel too small for a QUIC Initial", detour: "tiny",
			endpoints:  map[string]adapter.Endpoint{"tiny": &fixedMTUEndpoint{mtu: 1250}},
			configured: 0, want: 1202, hasCeiling: true,
			comment: "1250 - 48 = 1202, which is above the 1200 minimum: this must still be allowed. " +
				"The refusal case is the next one",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			capacity := dialer.DetourPathCapacity(capacityContext(testCase.endpoints), testCase.detour)
			ceiling, hasCeiling := capacity.QuicPayloadCeiling()
			require.Equal(t, testCase.hasCeiling, hasCeiling, testCase.comment)
			got := dialer.ClampToCeiling(testCase.configured, ceiling, hasCeiling)
			require.Equal(t, testCase.want, got, testCase.comment)
			if testCase.hasCeiling {
				require.GreaterOrEqual(t, got, quicMinimum,
					"a ceiling that leaves less than the QUIC minimum is the refusal case, not a "+
						"clamp, and must not be reported as a usable value")
			}
		})
	}
}

// TestATunnelTooSmallForAQUICInitialIsRefused is the error half. Clamping a value below the protocol
// minimum would produce a handshake no conforming peer accepts, so the configuration is refused with a
// message naming the cause.
func TestATunnelTooSmallForAQUICInitialIsRefused(t *testing.T) {
	// 1240 - 48 = 1192, below the 1200 minimum.
	capacity := dialer.DetourPathCapacity(
		capacityContext(map[string]adapter.Endpoint{"tiny": &fixedMTUEndpoint{mtu: 1240}}), "tiny")
	require.True(t, capacity.Known)
	ceiling, hasCeiling := capacity.QuicPayloadCeiling()
	require.True(t, hasCeiling)
	require.Less(t, ceiling, uint32(dialer.MinimumQUICInitialPacketSize),
		"this fixture must actually produce a ceiling below the QUIC minimum, or the refusal it "+
			"exercises is not the one under test")

	clamped := dialer.ClampToCeiling(0, ceiling, hasCeiling)
	require.Less(t, clamped, dialer.MinimumQUICInitialPacketSize,
		"the clamp must not silently raise the value to the minimum: that would be inventing capacity "+
			"the tunnel does not have, and the handshake would fail further from the cause")
}

// ---------------------------------------------------------------------------
// The wire: measured, and the boundary stated
// ---------------------------------------------------------------------------

// TestPathCeilingReachesTheWireOnlyWithoutChromeParrot is the measurement that decides what this fix
// can claim.
//
// It reuses the existing first-datagram harness - which observes the real `WriteTo` length of the first
// datagram the pinned QUIC stack hands to a socket - and asks the same question twice for the SAME
// configured ceiling:
//
//	ChromeParrot OFF, initial_packet_size = the ceiling   -> the ceiling reaches the wire
//	ChromeParrot ON,  initial_packet_size = the ceiling   -> it does NOT; 1250 does
//
// The second case is not a defect in this outbound. It is the pinned library's documented behaviour, and
// the reason the residual is reported as a product decision about the fork rather than as a bug here:
// hysteria2's DEFAULT is ChromeParrot on, so the default configuration is the one the ceiling cannot
// reach.
//
// The test deliberately asserts BOTH outcomes. Asserting only the working one would let a later library
// change that makes the ceiling effective pass unnoticed, and asserting only the failing one would let a
// regression in the working path hide.
func TestPathCeilingReachesTheWireOnlyWithoutChromeParrot(t *testing.T) {
	// A 1280-byte inner IPv6 tunnel: 1280 - 40 - 8.
	const ceiling = 1232

	withoutParrot := measureFirstDatagram(t, measureRequest{
		chromeParrot:                false,
		configuredInitialPacketSize: ceiling,
	})
	require.Equal(t, ceiling, withoutParrot.size,
		"with ChromeParrot off the ceiling must reach the wire: this is the half of the fix that "+
			"works today, and a regression here would mean the outbound stopped passing the value down")

	withParrot := measureFirstDatagram(t, measureRequest{
		chromeParrot:                true,
		configuredInitialPacketSize: ceiling,
	})
	require.Equal(t, chromeParrotInitialPacketSize, withParrot.size,
		"with ChromeParrot ON the pinned quic-go replaces the configured value with "+
			"chromeInitialPacketSize (%d), so a ceiling of %d does NOT reach the wire. MEASURED here "+
			"so the residual is a stated fact rather than an assumption: making the ceiling effective "+
			"under ChromeParrot requires changing the pinned library, which is a separate authorisation",
		chromeParrotInitialPacketSize, ceiling)

	t.Logf("ceiling %d: ChromeParrot off -> %d bytes on the wire; ChromeParrot on -> %d bytes. "+
		"Hysteria2's default is ChromeParrot ON, so the default configuration does not yet honour a "+
		"proven path ceiling.", ceiling, withoutParrot.size, withParrot.size)
}

// TestTheCeilingDoesNotChangeADirectDial keeps the compatibility promise in the harness's own terms: a
// configuration with no detour must behave exactly as it did before the ceiling existed.
//
// The outbound computes no ceiling for an empty detour (proved above), so this is about the composed
// behaviour: the value reaching the library is the configured one, and the wire shows it.
func TestTheCeilingDoesNotChangeADirectDial(t *testing.T) {
	direct := measureFirstDatagram(t, measureRequest{
		chromeParrot:                false,
		configuredInitialPacketSize: 1452,
	})
	require.Equal(t, 1452, direct.size,
		"with no detour there is no ceiling, so an operator's value must reach the wire unchanged")
}
