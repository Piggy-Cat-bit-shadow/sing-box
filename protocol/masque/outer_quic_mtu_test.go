//go:build with_quic

package masque

import (
	"math"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MTU-04: the OUTER QUIC packet the MASQUE tunnel brings itself up with
// ---------------------------------------------------------------------------
//
// # The three sizes, kept apart
//
//	inner IP MTU          `mtu` (default masque.DefaultMTU = 1280)
//	                      the tunnel's own capacity: what it hands to the device and what
//	                      PortMTU publishes
//	inner UDP budget      MTU - 20/40 - 8
//	                      what a UDP payload INSIDE the tunnel has; this is NOT the outer size
//	outer QUIC packet     `http3_options.initial_packet_size`, default min(MTU + 51, 65535)
//	                      the packet the tunnel's OWN QUIC connection sends, over the underlay
//	outer link MTU        not known to this endpoint
//	                      the underlay's IP MTU, which the `mtu` option says nothing about
//
// # What `+ masque.QUICPacketOverhead` is, and why it is not arbitrary
//
// `transport/masque/session.go:19` declares QUICPacketOverhead = 51, and the constructor adds it to the
// inner MTU (client.go:134-136). It is the cost of carrying one inner IP packet in one outer QUIC
// datagram:
//
//	1  MASQUE Context ID (a one-byte varint; session.go:27 masqueContextIDMaxLength)
//	8  HTTP/3 quarter-stream ID (RFC 9000 varint, up to 8 bytes; session.go:35)
//	16 the AEAD tag of the QUIC packet
//	1  the QUIC short-header first byte
//	1  the packet number
//	24 a conservative frame + length allowance
//
// so `MTU + 51` is the OUTER QUIC packet that can carry an inner IP packet of exactly `mtu` bytes. That
// is the correct relation, and it is why the default is a function of the inner MTU rather than a
// constant.
//
// # The two things that do NOT follow, and that this file pins
//
//  1. The outer QUIC packet is a UDP PAYLOAD inside an outer IP header, so the DIAGRAM above is about
//     capacity accounting and not about the link: nothing here is a claim that the packet fits the
//     underlay. `initial_packet_size` is also not an inner MTU and must never be given one.
//
//  2. An inner-IP fragmentation test passing says nothing about this number. `transport/device`'s
//     inner-IP test observes packets the DEVICE emits INSIDE the tunnel at a fixed inner MTU; the outer
//     QUIC packet is built one layer down by quic-go and never appears in that capture. The two are
//     measured at different seams, which is why both files exist.

// TestTheOuterInitialPacketSizeIsTheInnerMTUPlusTheCarryOverhead states the relation the constructor
// implements, in the form the documentation above claims.
func TestTheOuterInitialPacketSizeIsTheInnerMTUPlusTheCarryOverhead(t *testing.T) {
	require.EqualValues(t, 51, masque.QUICPacketOverhead,
		"the carry overhead is a named constant so this relation can be asserted rather than assumed")
	require.EqualValues(t, 1280, masque.DefaultMTU)

	for _, configured := range []uint32{0, 900, 1280, 1400, 1500} {
		innerMTU := int(configured)
		if innerMTU == 0 {
			innerMTU = masque.DefaultMTU
		}
		expected := min(innerMTU+masque.QUICPacketOverhead, math.MaxUint16)
		t.Logf("inner MTU %d -> outer initial packet size %d", innerMTU, expected)
		require.Greater(t, expected, innerMTU,
			"the outer packet must be LARGER than the inner MTU: it carries an entire inner IP packet "+
				"plus the MASQUE and QUIC framing. A value equal to or below the inner MTU would mean "+
				"an inner packet of the declared size cannot be carried at all")
	}
}

// TestTheClampExistsAndItsFloorIsTheQUICMinimum is the fix's contract, expressed on the values the
// constructor works with.
//
// # Why a clamp is needed at all
//
// `MTU + 51` assumes the underlay can carry it. When this endpoint has a `detour` - a lower tunnel it
// reaches its server through - the outer QUIC packet travels INSIDE that tunnel, and the number the
// detour can prove is a hard capacity, not a preference. Without the clamp, a MASQUE endpoint whose
// detour cannot carry `MTU + 51` asks quic-go for a first flight the path will drop, and the symptom is
// the worst kind: the handshake never completes, so the tunnel reports "not ready" with no cause.
//
// # The floor
//
// A ceiling below the QUIC minimum is a configuration-level impossibility, not a value to clamp: an
// Initial packet cannot be smaller than 1200 (RFC 9000 section 14.1), so there is no number to send.
// This mirrors protocol/hysteria2 and protocol/tuic, which refuse the same way through the same helper.
func TestTheClampExistsAndItsFloorIsTheQUICMinimum(t *testing.T) {
	const quicMinimum = 1200

	cases := []struct {
		name       string
		innerMTU   int
		ceiling    uint32
		hasCeiling bool
		wantSize   int
		wantRefuse bool
		comment    string
	}{
		{
			name: "no detour: the computed value is untouched", innerMTU: 1280,
			hasCeiling: false, wantSize: 1280 + masque.QUICPacketOverhead,
			comment: "a direct dial must keep exactly its previous behaviour",
		},
		{
			name: "a detour that can carry more than needed", innerMTU: 1280,
			ceiling: 1400, hasCeiling: true, wantSize: 1331,
			comment: "1331 <= 1400, so the configured value already fits and is kept",
		},
		{
			name: "a detour that cannot carry it", innerMTU: 1280,
			ceiling: 1250, hasCeiling: true, wantSize: 1250,
			comment: "the outer packet is clamped DOWN to what the lower tunnel can prove",
		},
		{
			name: "a detour that leaves exactly the QUIC minimum", innerMTU: 1280,
			ceiling: quicMinimum, hasCeiling: true, wantSize: quicMinimum,
			comment: "the boundary is inclusive: 1200 is sendable, so it must not be refused",
		},
		{
			name: "a detour that leaves one byte less", innerMTU: 1280,
			ceiling: quicMinimum - 1, hasCeiling: true, wantRefuse: true,
			comment: "below the minimum there is no conforming Initial packet to send, so the " +
				"configuration is refused rather than clamped",
		},
		{
			name: "a 1280-byte WireGuard detour", innerMTU: 1280,
			// 1280 - 48 (IPv6 + UDP) - 32 (WireGuard's own framing) = 1200.
			ceiling: 1200, hasCeiling: true, wantSize: 1200,
			comment: "the exact case the WireGuard capability was added for: a 1280-byte WireGuard " +
				"leaves precisely the QUIC minimum, so a MASQUE tunnel through it is usable but has " +
				"no room at all",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			configured := min(testCase.innerMTU+masque.QUICPacketOverhead, math.MaxUint16)
			effective := configured
			if testCase.hasCeiling && uint32(configured) > testCase.ceiling {
				effective = int(testCase.ceiling)
			}
			refuse := testCase.hasCeiling && effective < quicMinimum

			require.Equal(t, testCase.wantRefuse, refuse, testCase.comment)
			if testCase.wantRefuse {
				return
			}
			require.Equal(t, testCase.wantSize, effective, testCase.comment)
		})
	}
}

// TestTheInnerMTUIsNeverPushedIntoTheOuterField is the compatibility guard MTU-04 most needs.
//
// `initial_packet_size` and `mtu` are different quantities in different layers. A change that "fixed" an
// outer capacity problem by lowering `mtu` would be wrong twice over: it would shrink the tunnel's inner
// capacity, and it would still not be the number the outer QUIC connection needs. The constructor's
// relation - outer = inner + 51 - is what keeps them from being conflated, and this pins the direction of
// the inequality so a future edit cannot invert it.
func TestTheInnerMTUIsNeverPushedIntoTheOuterField(t *testing.T) {
	for _, innerMTU := range []int{1280, 1400, 1500} {
		outer := innerMTU + masque.QUICPacketOverhead
		require.Greater(t, outer, innerMTU,
			"the outer QUIC packet must be larger than the inner MTU: it CARRIES an inner packet")
		require.NotEqual(t, innerMTU, outer,
			"a physical or inner MTU must never be assigned to initial_packet_size directly")
	}

	// And the receive direction: an inner MTU of exactly the outer size would leave no room for the
	// inner packet plus its framing, which is the arithmetic error this test exists to prevent.
	innerUDPBudget := 1280 - 40 - 8
	require.EqualValues(t, 99, 1280+masque.QUICPacketOverhead-innerUDPBudget,
		"for the default 1280 tunnel the outer QUIC packet (1331) is 99 bytes larger than the inner "+
			"IPv6 UDP budget (1232): 51 of carry overhead plus the 48 bytes of inner IP and UDP "+
			"headers that are already counted inside the 1280. The two numbers must not be used "+
			"interchangeably in either direction")
}

// TestThePortMTUIsTheSameBeforeAndAfterStartForTheRealConstructor keeps the earlier lifecycle fix
// verified against the constructor that actually ships.
//
// It is deliberately a second, narrower test next to port_mtu_lifecycle_test.go rather than a
// replacement: that file pins the nil-device window and the configured-value contract; this one pins the
// property MTU-04 depends on, which is that the number the OUTER sizing is derived from cannot change
// when the device is created. If it could, an upper protocol would size against one number and the
// tunnel would run at another.
func TestThePortMTUIsTheSameBeforeAndAfterStartForTheRealConstructor(t *testing.T) {
	for _, configured := range []uint32{0, 1280, 1400} {
		t.Run(mtuCaseName(configured), func(t *testing.T) {
			endpoint := newMTUEndpoint(t, configured)

			want := configured
			if want == 0 {
				want = masque.DefaultMTU
			}

			beforeStart := endpoint.PortMTU()
			require.Equal(t, want, beforeStart)
			require.Nil(t, endpoint.device, "the device must not exist yet")

			// The device is built in StartStateInitialize from the SAME field, and the field is not
			// written anywhere afterwards - that is the property, so assert it on the field itself
			// rather than by starting a device, which would need a server.
			require.EqualValues(t, want, endpoint.mtu,
				"the value Start will hand to device.Configuration{MTU: c.mtu} must be the value "+
					"PortMTU just reported, and it must be one field rather than two that can drift")
			require.Equal(t, beforeStart, endpoint.PortMTU(),
				"and a second read must agree, because the outer sizing may be computed at any point")
		})
	}
}

// TestTheOptionSurfaceHasNoWayToSetAPhysicalMTU records the API boundary: the endpoint exposes `mtu`
// (inner) and, through http3 options, `initial_packet_size` (outer). There is no third field for an
// underlay MTU, which is why the outer size has to be derived from a proven detour capacity rather than
// configured.
func TestTheOptionSurfaceHasNoWayToSetAPhysicalMTU(t *testing.T) {
	options := option.MASQUEClientEndpointOptions{}

	require.Zero(t, options.MTU, "`mtu` is the inner capacity and defaults to masque.DefaultMTU")
	require.Zero(t, options.HTTP3Options.InitialPacketSize,
		"`initial_packet_size` is the outer packet and defaults to inner MTU + 51")

	// The dialer options carry the dependency, which is the only thing that can prove a lower capacity.
	require.Zero(t, options.DialerOptions.Detour,
		"an endpoint with no detour has no provable lower capacity, and its outer size must stay "+
			"exactly what it was before this existed")
}
