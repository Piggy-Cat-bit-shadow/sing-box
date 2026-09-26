package masque

import (
	"net/netip"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
)

func packetAddresses(packet []byte) (netip.Addr, netip.Addr, uint8, bool) {
	protocol, valid := tun.IPTransportProtocol(packet)
	if !valid {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	if header.IPVersion(packet) == header.IPv4Version {
		ipHeader := header.IPv4(packet)
		return ipHeader.SourceAddr(), ipHeader.DestinationAddr(), protocol, true
	}
	ipHeader := header.IPv6(packet)
	return ipHeader.SourceAddr(), ipHeader.DestinationAddr(), protocol, true
}

func isControlProtocol(protocol uint8) bool {
	return protocol == uint8(header.ICMPv4ProtocolNumber) || protocol == uint8(header.ICMPv6ProtocolNumber)
}

func decrementHopLimit(packet []byte) bool {
	// Every length check here is DEFENSIVE, not a fix for a reachable bug: both
	// call sites are preceded by packetAddresses, which rejects a packet shorter
	// than its headers, so today a truncated packet never arrives.
	//
	// It is still worth making this function total, because its failure mode is a
	// panic rather than an error, and the fuzzer (FuzzMasqueIPPacketParser) found
	// two distinct ways to produce one:
	//
	//   - a 4-byte IPv4 prefix: header.IPv4(packet).TTL() indexes byte 8 with no
	//     length check;
	//   - a packet whose version nibble is neither 4 nor 6, such as 0xA0. The
	//     original code treated "not IPv4" as "IPv6", so a 10-byte buffer was
	//     handed to the IPv6 view and the checksum walk sliced past the end.
	//
	// The second is the subtle one and it is why the version is now matched
	// explicitly rather than negated. header.IPVersion returns the raw 4-bit value,
	// so 10 is a perfectly possible return that means neither protocol.
	//
	// Returning false means "do not forward": the caller converts it into ICMP Hop
	// Limit Exceeded, which is the same outcome an exhausted hop limit produces and
	// is a safe answer for a packet that cannot be parsed.
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return false
		}
		ipHeader := header.IPv4(packet)
		// The declared header length must be BOTH coherent and present.
		//
		// Two separate hazards, both found by the fuzzer:
		//
		//   - the IHL nibble can claim more bytes than the packet contains, so the
		//     declared length must be within the buffer;
		//   - it can also claim FEWER than the fixed header. The input 41 30 30 ...
		//     has IHL 1, which is 4 bytes, and CalculateChecksum then slices
		//     b[:12] against a header it believes ends at 4 - an inverted slice
		//     bounds panic. A declared length below IPv4MinimumSize is not a short
		//     packet, it is a malformed one, and the RFC 791 minimum for the field
		//     is 5 words.
		headerLength := int(ipHeader.HeaderLength())
		if headerLength < header.IPv4MinimumSize || len(packet) < headerLength {
			return false
		}
		if ipHeader.TTL() <= 1 {
			return false
		}
		ipHeader.SetTTL(ipHeader.TTL() - 1)
		ipHeader.SetChecksum(0)
		ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
		return true

	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize {
			return false
		}
		ipHeader := header.IPv6(packet)
		if ipHeader.HopLimit() <= 1 {
			return false
		}
		ipHeader.SetHopLimit(ipHeader.HopLimit() - 1)
		return true

	default:
		// Not an IP packet at all. Refusing is the only safe answer.
		return false
	}
}

func buildICMPError(packet []byte, errorType tun.ICMPError, inet4Source netip.Addr, inet6Source netip.Addr, mtu int, headroom int) (*buf.Buffer, bool) {
	source := inet4Source
	if header.IPVersion(packet) == header.IPv6Version {
		source = inet6Source
	}
	reply, built := tun.BuildICMPError(packet, errorType, source, uint32(mtu), headroom)
	if !built {
		return nil, false
	}
	buffer := buf.As(reply)
	buffer.Advance(headroom)
	return buffer, true
}

// buildICMPErrorTo builds the same ICMP error as buildICMPError but addresses it
// to an explicitly chosen destination instead of the quoted packet's source.
//
// It exists for the CONNECT-IP endpoint's Packet Too Big path, where the packet
// that did not fit is one the endpoint was SENDING INTO a tunnel rather than one
// that arrived FROM a peer. The upstream builder has no destination parameter and
// always answers the quoted packet's source, which in that direction is frequently
// the endpoint itself, so the error would be addressed to the wrong host entirely.
// See serverSession.handlePacketTooBig for the full reasoning and the measurement.
//
// The destination is rewritten on the constructed packet rather than passed down,
// because the header checksum covers the addresses: changing a destination without
// recomputing the checksum produces an error packet that the peer's stack discards,
// which would look exactly like the delivery failure this function exists to fix.
// IPv4 and IPv6 checksum differently (IPv6 has no header checksum at all), so each
// family is handled explicitly rather than assumed to be uniform.
func buildICMPErrorTo(packet []byte, errorType tun.ICMPError, inet4Source netip.Addr, inet6Source netip.Addr, destination netip.Addr, mtu int, headroom int) (*buf.Buffer, bool) {
	buffer, built := buildICMPError(packet, errorType, inet4Source, inet6Source, mtu, headroom)
	if !built {
		return nil, false
	}
	bytes := buffer.Bytes()
	switch header.IPVersion(bytes) {
	case header.IPv4Version:
		if !destination.Is4() || len(bytes) < header.IPv4MinimumSize {
			buffer.Release()
			return nil, false
		}
		// SetDestinationAddressWithChecksumUpdate maintains the header checksum
		// itself, which is required: the IPv4 checksum covers the addresses, so a
		// plain SetDestinationAddress would leave the error packet failing its own
		// checksum at the peer and looking exactly like the delivery failure this
		// function exists to fix.
		header.IPv4(bytes).SetDestinationAddressWithChecksumUpdate(tcpip.AddrFrom4(destination.As4()))
	case header.IPv6Version:
		if !destination.Is6() || len(bytes) < header.IPv6MinimumSize {
			buffer.Release()
			return nil, false
		}
		ipHeader := header.IPv6(bytes)
		ipHeader.SetDestinationAddress(tcpip.AddrFrom16(destination.As16()))
		// IPv6 has no header checksum, but the ICMPv6 checksum covers the
		// addresses through the pseudo-header, so it must be recomputed AFTER the
		// address is in place and from the packet's own (rewritten) addresses.
		icmpHeader := header.ICMPv6(ipHeader.Payload())
		if len(icmpHeader) < header.ICMPv6MinimumSize {
			buffer.Release()
			return nil, false
		}
		icmpHeader.SetChecksum(0)
		icmpHeader.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHeader,
			Src:    ipHeader.SourceAddressSlice(),
			Dst:    ipHeader.DestinationAddressSlice(),
		}))
	default:
		buffer.Release()
		return nil, false
	}
	return buffer, true
}
