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

// decrementHopLimit decrements the packet's TTL/hop limit, reporting false when the packet
// cannot be forwarded because that limit is already exhausted.
//
// It validates the header length against the slice before touching it. The version nibble
// does not imply how many bytes are present: an IPv4 header declares its own size in IHL,
// and CalculateChecksum slices b[:HeaderLength()]. BOTH ends of that declared length
// therefore have to be checked - an IHL of 0 makes the slice bounds inverted, and an IHL
// beyond the slice overruns it. A 20-byte packet with IHL set to 6 passes a bare minimum
// size check while still declaring a 24-byte header, which is exactly the shape that
// overruns the checksum computation below.
//
// The length is peer-controlled on the MASQUE data path, so an unchecked header here panics
// the serving goroutine, which is a remote denial of service. A packet that does not contain
// the header it claims is not forwardable, so rejecting it is both the safe and the correct
// answer; callers report it through their existing not-forwardable path.
func decrementHopLimit(packet []byte) bool {
	if header.IPVersion(packet) == header.IPv4Version {
		if len(packet) < header.IPv4MinimumSize {
			return false
		}
		ipHeader := header.IPv4(packet)
		headerLength := int(ipHeader.HeaderLength())
		if headerLength < header.IPv4MinimumSize || headerLength > len(packet) {
			return false
		}
		if ipHeader.TTL() <= 1 {
			return false
		}
		ipHeader.SetTTL(ipHeader.TTL() - 1)
		ipHeader.SetChecksum(0)
		ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
		return true
	}
	if len(packet) < header.IPv6MinimumSize {
		return false
	}
	ipHeader := header.IPv6(packet)
	if ipHeader.HopLimit() <= 1 {
		return false
	}
	ipHeader.SetHopLimit(ipHeader.HopLimit() - 1)
	return true
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

// buildICMPErrorTo builds the same ICMP error as buildICMPError but addresses it to an
// explicit destination instead of the quoted packet's source.
//
// It exists for the endpoint's Packet Too Big path, where the packet that did not fit is
// one the endpoint was sending into a tunnel rather than one that arrived from a peer. The
// upstream builder has no destination parameter and answers the quoted packet's source,
// which in that direction is frequently the endpoint itself, so the error would be
// addressed to the wrong host.
//
// The destination is rewritten on the constructed packet because the checksum covers the
// addresses: IPv4 covers them in the header checksum and ICMPv6 covers them through the
// pseudo-header, so a rewrite without recomputation produces an error the peer discards.
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
		header.IPv4(bytes).SetDestinationAddressWithChecksumUpdate(tcpip.AddrFrom4(destination.As4()))
	case header.IPv6Version:
		if !destination.Is6() || len(bytes) < header.IPv6MinimumSize {
			buffer.Release()
			return nil, false
		}
		ipHeader := header.IPv6(bytes)
		ipHeader.SetDestinationAddress(tcpip.AddrFrom16(destination.As16()))
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
