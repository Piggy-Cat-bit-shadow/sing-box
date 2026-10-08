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
