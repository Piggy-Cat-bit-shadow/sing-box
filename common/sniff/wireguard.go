package sniff

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// WireGuard message geometry, taken from the wire format itself and nothing else.
//
// Every WireGuard message starts with a one-byte type followed by three reserved bytes that the
// protocol mandates be zero. The type then fixes the total length for the three handshake
// messages; only transport data is variable, and it still carries the fixed 16-byte header plus
// the 16-byte Poly1305 tag, so 32 bytes is the floor even for an empty keepalive.
const (
	wireGuardMessageTypeInitiation   = 1
	wireGuardMessageTypeResponse     = 2
	wireGuardMessageTypeCookieReply  = 3
	wireGuardMessageTypeTransport    = 4
	wireGuardHandshakeInitiationSize = 148
	wireGuardHandshakeResponseSize   = 92
	wireGuardCookieReplySize         = 64
	wireGuardTransportMinSize        = 32
)

// WireGuard detects a plain WireGuard message from its header alone.
//
// This sniffer exists to stop a concrete false positive, not to fingerprint WireGuard traffic.
// A handshake initiation begins 01 00 00 00 and is 148 bytes long, which is a shape the uTP
// heuristic in UTP accepts unconditionally: uTP reads its version from the low nibble of the
// first byte (0x01 -> version 1, type 0), reads its extension chain from the second byte (0x00,
// an empty chain) and then claims the packet for BitTorrent without ever looking at the rest.
// Because UTP is a weak length-and-two-nibbles check, anything that is structurally stronger must
// be tried first; see defaultPacketSniffers for where this sits and why.
//
// The check is deliberately structural and cannot be otherwise: WireGuard payloads are encrypted
// and authenticated, so there is no magic value, no plaintext field and no length-independent
// marker to match. Deciding "not WireGuard" from the outside is therefore always a statement
// about the header, and the reserved bytes are the only part of that header with no degrees of
// freedom to guess at.
//
// # The residual, and why it is not a gap
//
// A 148-byte uTP ST_DATA packet whose extension byte is 0 and whose connection id is 0x0000 is
// still claimed as WireGuard: it begins 01 00 00 00, exactly a handshake initiation's type byte
// and mandatory zero reserved field, and it has exactly the initiation's length. That is roughly a
// 1-in-2^16 coincidence on top of a 148-byte datagram, and it is classified
// PROVEN-INHERENT-AMBIGUITY rather than left as an open risk; the proof is
// TestSniffWireGuardUTPAmbiguityIsStructural, and the shape of it is worth stating here because it
// is what rules out every proposed narrowing:
//
//   - WireGuard's whole check lives in bytes 0-3 and the total length. Bytes 4-147 are a random
//     sender index, an ephemeral public key, three AEAD ciphertexts and two keyed MACs, all
//     uniformly random from outside. There is no consistency to demand of them that a real
//     initiation also supplies. The one candidate, mac2, is all-zero only until the responder
//     demands a cookie, so requiring it either way drops real handshakes.
//   - uTP's whole check lives in bytes 0-19 and the extension chain, and those bytes are what the
//     two protocols disagree about LEAST: uTP reads bytes 1-3 as an empty extension chain and
//     connection id 0, which is precisely WireGuard's zero reserved field. uTP imposes no
//     cross-field invariant on bytes 4-19, and it cannot acquire one that separates the two,
//     because a genuine initiation puts random bytes there while a genuine uTP ST_DATA sender can
//     put anything there it likes. A rule that rejects the ambiguous packet therefore rejects real
//     initiations too, which is the trade this sniffer must not make.
//   - Ordering cannot help either. WireGuard must run before uTP, because every real initiation is
//     also a legal uTP packet; the preference for the WireGuard reading is not arbitrary, it is the
//     better explanation of the same bytes - the WireGuard reading explains all of them, while the
//     uTP reading additionally needs the datagram to be 148 bytes with a zero connection id.
//
// The alternative to accepting this residual is losing WireGuard detection for a uTP false positive
// that is two orders of magnitude rarer than the handshakes it would stop being seen.
func WireGuard(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	// Four bytes are needed even to name the type; a shorter datagram cannot be WireGuard, and
	// indexing packet[1:4] below would panic on it.
	if len(packet) < 4 {
		return os.ErrInvalid
	}

	// The reserved bytes are checked before the type so that a coincidental type byte in payload
	// data is rejected here rather than after a length comparison. They are always zero on the
	// wire and are what a sender cannot vary: they turn a 1-in-256 first-byte match into a
	// 1-in-2^32 one, which is the property that keeps type 4 from swallowing unrelated datagrams.
	if packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
		return os.ErrInvalid
	}

	// Each type is matched against its exact length. Type 1 is the length that matters for the
	// uTP bug, but accepting it while leaving 2, 3 and 4 to fall through would let a handshake
	// response or a cookie reply be claimed by whatever weak sniffer runs next, which is the same
	// bug one message later.
	switch packet[0] {
	case wireGuardMessageTypeInitiation:
		if len(packet) != wireGuardHandshakeInitiationSize {
			return os.ErrInvalid
		}
	case wireGuardMessageTypeResponse:
		if len(packet) != wireGuardHandshakeResponseSize {
			return os.ErrInvalid
		}
	case wireGuardMessageTypeCookieReply:
		if len(packet) != wireGuardCookieReplySize {
			return os.ErrInvalid
		}
	case wireGuardMessageTypeTransport:
		// Transport data is padded to a 16-byte boundary on the wire, but padding is a property
		// of a sender, not of the frame, so it is not asserted here. Only the floor is structural.
		if len(packet) < wireGuardTransportMinSize {
			return os.ErrInvalid
		}
	default:
		return os.ErrInvalid
	}

	metadata.Protocol = C.ProtocolWireGuard
	return nil
}
