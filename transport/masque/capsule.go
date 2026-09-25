package masque

import (
	"net/netip"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"

	"go4.org/netipx"
)

const (
	capsuleTypeAddressAssign      = 0x01
	capsuleTypeAddressRequest     = 0x02
	capsuleTypeRouteAdvertisement = 0x03
)

type AssignedAddress struct {
	RequestID uint64
	Prefix    netip.Prefix
}

type AddressRange struct {
	Start    netip.Addr
	End      netip.Addr
	Protocol uint8
}

func (r AddressRange) Contains(address netip.Addr) bool {
	return address.BitLen() == r.Start.BitLen() && r.Start.Compare(address) <= 0 && address.Compare(r.End) <= 0
}

// OverlapsProtocol reports whether two ranges describe any of the same traffic.
//
// Two ranges conflict when their ADDRESS ranges intersect AND their protocols
// can both match the same packet. Protocol 0 matches every protocol in
// RoutesContain, so it conflicts with any other protocol over an intersecting
// range - that is the case the ordering-based check used to miss.
//
// Ranges of different IP versions never conflict, because Contains requires the
// address length to match.
func (r AddressRange) OverlapsProtocol(other AddressRange) bool {
	if r.Start.BitLen() != other.Start.BitLen() {
		return false
	}
	if r.End.Compare(other.Start) < 0 || other.End.Compare(r.Start) < 0 {
		return false
	}
	// Protocol 0 is "all protocols", so it conflicts with anything.
	return r.Protocol == 0 || other.Protocol == 0 || r.Protocol == other.Protocol
}

func parseAddresses(payload []byte) ([]AssignedAddress, error) {
	var addresses []AssignedAddress
	for len(payload) > 0 {
		requestID, requestIDLength, valid := transportHTTP.DecodeVarint(payload)
		if !valid {
			return nil, E.New("truncated request ID")
		}
		payload = payload[requestIDLength:]
		addressLength, err := parseVersion(payload)
		if err != nil {
			return nil, err
		}
		if len(payload) < 1+addressLength+1 {
			return nil, E.New("truncated address")
		}
		address, _ := netip.AddrFromSlice(payload[1 : 1+addressLength])
		prefixLength := int(payload[1+addressLength])
		payload = payload[1+addressLength+1:]
		if prefixLength > address.BitLen() {
			return nil, E.New("invalid prefix length: ", prefixLength)
		}
		prefix := netip.PrefixFrom(address, prefixLength)
		if prefix.Masked() != prefix {
			return nil, E.New("prefix has host bits set: ", prefix)
		}
		addresses = append(addresses, AssignedAddress{RequestID: requestID, Prefix: prefix})
	}
	return addresses, nil
}

func parseVersion(payload []byte) (int, error) {
	if len(payload) < 1 {
		return 0, E.New("truncated IP version")
	}
	switch payload[0] {
	case 4:
		return 4, nil
	case 6:
		return 16, nil
	default:
		return 0, E.New("invalid IP version: ", payload[0])
	}
}

func parseRoutes(payload []byte) ([]AddressRange, error) {
	var routes []AddressRange

	// perProtocolHighWater tracks, for each protocol seen so far at the current
	// IP version, the range that ends furthest. It is what makes the overlap
	// check linear instead of quadratic.
	//
	// Why the ordering checks are not enough on their own: RFC 9484 section
	// 4.2.1 requires the ranges to be non-overlapping and states the ordering as
	// a SEPARATE requirement. The ordering rule only compares consecutive
	// ranges, and it skips the comparison whenever the protocol differs - so
	// every cross-protocol overlap was accepted.
	//
	// That is a real gap rather than a theoretical one, because protocol 0 means
	// ALL protocols rather than "no protocol": RoutesContain matches with
	// `route.Protocol == 0 || route.Protocol == protocol`. Advertising
	// 192.0.2.0-192.0.2.255 at protocol 0 and then the same range at protocol 6
	// therefore describes the same traffic twice, and whichever entry a lookup
	// reaches first decides.
	//
	// Because the input is sorted by (version, protocol, start), the only ranges
	// that can reach into the current one are:
	//
	//   - the range at the SAME protocol that ends furthest, which the ordering
	//     check already compares; and
	//   - for each OTHER protocol, the range that ends furthest.
	//
	// So a high-water mark per protocol suffices, and the scan stays linear in
	// the number of ranges. An earlier version of this fix compared every earlier
	// range and was correct but quadratic: a crafted 1 MiB capsule of
	// single-address ranges took over 13 seconds to reject, against 16ms for the
	// ordering-only check. That is a CPU denial-of-service, so the linear form is
	// not an optimisation but a requirement.
	highWater := make(map[uint8]AddressRange, 4)

	for len(payload) > 0 {
		addressLength, err := parseVersion(payload)
		if err != nil {
			return nil, err
		}
		if len(payload) < 1+addressLength*2+1 {
			return nil, E.New("truncated address range")
		}
		start, _ := netip.AddrFromSlice(payload[1 : 1+addressLength])
		end, _ := netip.AddrFromSlice(payload[1+addressLength : 1+addressLength*2])
		route := AddressRange{Start: start, End: end, Protocol: payload[1+addressLength*2]}
		payload = payload[1+addressLength*2+1:]
		if start.Compare(end) > 0 {
			return nil, E.New("invalid address range: ", start, "-", end)
		}
		if len(routes) > 0 {
			previous := routes[len(routes)-1]
			switch {
			case previous.Start.BitLen() > start.BitLen():
				return nil, E.New("address ranges are not ordered by IP version")
			case previous.Start.BitLen() < start.BitLen():
				// A new IP version begins. Ranges of another version can never
				// conflict, because Contains requires the address length to
				// match, so the marks from the previous version are dropped.
				clear(highWater)
			case previous.Protocol > route.Protocol:
				return nil, E.New("address ranges are not ordered by IP protocol")
			}

			// The same-protocol neighbour is still checked directly, because
			// that is the published ordering rule and its error message is the
			// one callers already expect.
			if previous.Protocol == route.Protocol && previous.End.Compare(start) >= 0 {
				return nil, E.New("address ranges overlap: ", previous.End, " and ", start)
			}

			// Then every protocol that could still match this range.
			//
			// Protocol 0 matches everything, so it is compared against the
			// current range whichever side it is on.
			for protocol, candidate := range highWater {
				if protocol != route.Protocol && !protocolConflicts(protocol, route.Protocol) {
					continue
				}
				if candidate.OverlapsProtocol(route) {
					return nil, E.New("address ranges overlap: ", candidate.Start, "-",
						candidate.End, " protocol ", candidate.Protocol, " and ",
						start, "-", end, " protocol ", route.Protocol)
				}
			}
		}

		// Record the high-water mark for this protocol. Only the range ending
		// furthest matters, because any earlier range at the same protocol ended
		// at or before it.
		if existing, loaded := highWater[route.Protocol]; !loaded || existing.End.Compare(route.End) < 0 {
			highWater[route.Protocol] = route
		}
		routes = append(routes, route)
	}
	return routes, nil
}

// protocolConflicts reports whether two route protocols can both match one packet.
//
// Protocol 0 is the wildcard: RoutesContain matches a route when
// `route.Protocol == 0 || route.Protocol == protocol`, so 0 conflicts with
// everything and any other pair conflicts only when the values are equal.
func protocolConflicts(first uint8, second uint8) bool {
	return first == 0 || second == 0 || first == second
}

func appendAddress(payload []byte, address netip.Addr) []byte {
	if address.Is4() {
		payload = append(payload, 4)
	} else {
		payload = append(payload, 6)
	}
	return append(payload, address.AsSlice()...)
}

func newCapsule(capsuleType uint64, payload []byte) *buf.Buffer {
	capsule := buf.NewSize(transportHTTP.VarintLen(capsuleType) + transportHTTP.VarintLen(uint64(len(payload))) + len(payload))
	transportHTTP.PutVarint(capsule.Extend(transportHTTP.VarintLen(capsuleType)), capsuleType)
	transportHTTP.PutVarint(capsule.Extend(transportHTTP.VarintLen(uint64(len(payload)))), uint64(len(payload)))
	capsule.Write(payload)
	return capsule
}

func newAddressCapsule(capsuleType uint64, addresses []AssignedAddress) *buf.Buffer {
	var payload []byte
	for _, address := range addresses {
		var requestID [8]byte
		payload = append(payload, requestID[:transportHTTP.PutVarint(requestID[:], address.RequestID)]...)
		payload = appendAddress(payload, address.Prefix.Addr())
		payload = append(payload, byte(address.Prefix.Bits()))
	}
	return newCapsule(capsuleType, payload)
}

func newRouteCapsule(routes []AddressRange) *buf.Buffer {
	var payload []byte
	for _, route := range routes {
		payload = appendAddress(payload, route.Start)
		payload = append(payload, route.End.AsSlice()...)
		payload = append(payload, route.Protocol)
	}
	return newCapsule(capsuleTypeRouteAdvertisement, payload)
}

func RangesFromPrefixes(prefixes []netip.Prefix, protocol uint8) ([]AddressRange, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}
	ipSet, err := builder.IPSet()
	if err != nil {
		return nil, err
	}
	ipRanges := ipSet.Ranges()
	routes := make([]AddressRange, 0, len(ipRanges))
	for _, ipRange := range ipRanges {
		routes = append(routes, AddressRange{Start: ipRange.From(), End: ipRange.To(), Protocol: protocol})
	}
	return routes, nil
}
