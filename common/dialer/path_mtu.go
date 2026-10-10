// Package dialer's path-capacity helpers: what a lower tunnel can CARRY, and what a protocol stacked on
// top of it may therefore SEND.
//
// # The division of responsibility
//
// A lower layer publishes only what it owns: the inner IP MTU it will carry. It does not know, and must
// not be told, which protocol is stacked on it - MASQUE has no business knowing about Hysteria2.
//
// The upper protocol owns its own overhead, because it is the only layer that knows its encapsulation:
// a QUIC-based protocol subtracts an IP header and a UDP header, WireGuard subtracts its own transport
// overhead, and neither needs the other's numbers.
//
// The consequence, and the reason this is a shared helper rather than one line in each protocol: the
// IPv4/IPv6 header difference is the same fact for every protocol that puts a UDP datagram inside the
// tunnel, so it is computed once, here. A protocol that re-derived it would be a second source of truth
// for the same arithmetic, which is how two protocols end up disagreeing about where a boundary is.
package dialer

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// Transport-independent sizes, from RFC 8200 and RFC 768.
//
// They are named constants rather than literals because the whole point of this file is that these three
// numbers are the ONLY ones the boundary depends on, and a reader should be able to see that at once.
const (
	ipv4HeaderLength = 20
	ipv6HeaderLength = 40
	udpHeaderLength  = 8
)

// IPFamily is the address family an upper protocol's packets will actually travel in.
//
// The distinction is not cosmetic: an IPv6 header is 20 bytes larger than an IPv4 one, so the same inner
// MTU yields a 20-byte smaller UDP payload budget over IPv6. A protocol that assumed IPv4 would overshoot
// by exactly that much on an IPv6 path.
type IPFamily uint8

const (
	// IPFamilyUnknown means the family is not decided yet.
	//
	// It exists so the conservative answer is expressible, and it is deliberately the zero value: an
	// upper protocol that has not determined its family gets the IPv6 budget, because if it MIGHT
	// travel over IPv6 then IPv6 is the only safe number to size against. An unknown family must never
	// silently mean IPv4.
	IPFamilyUnknown IPFamily = iota
	// IPFamilyIPv4 is a four-byte-header path.
	IPFamilyIPv4
	// IPFamilyIPv6 is a sixteen-byte-header path.
	IPFamilyIPv6
)

// overheadFor returns the header bytes a UDP payload travels behind on this family.
//
// Unknown resolves to the IPv6 overhead, which is the larger of the two. The asymmetry is the point: a
// wrong guess in the other direction produces a packet that does not fit and fragments, silently.
func overheadFor(family IPFamily) int {
	switch family {
	case IPFamilyIPv4:
		return ipv4HeaderLength + udpHeaderLength
	default:
		return ipv6HeaderLength + udpHeaderLength
	}
}

// PacketOverheadCeiling computes the largest transport payload a protocol may emit over a lower tunnel
// with the given inner IP MTU.
//
// It returns ok=false when there is no usable answer, and the caller must then PRESERVE ITS EXISTING
// BEHAVIOUR rather than substitute a default. That rule is load-bearing: "we could not find out" and
// "we found out it is 1280" are different facts, and treating the first as the second would change the
// wire behaviour of every configuration whose topology this helper cannot see.
//
// ok is false when:
//   - the lower MTU is not known (0), which is every direct dial and every topology whose capacity is
//     not a fixed, provable number - a dynamic group, an unknown detour, a transport that discovers
//     its own MTU;
//   - the lower MTU is smaller than the headers alone, so no payload fits at all. That is a
//     configuration-level impossibility rather than a value to clamp, and reporting it as a number
//     would be inventing capacity that does not exist.
func PacketOverheadCeiling(innerMTU uint32, family IPFamily) (uint32, bool) {
	if innerMTU == 0 {
		return 0, false
	}
	overhead := uint32(overheadFor(family))
	if innerMTU <= overhead {
		return 0, false
	}
	return innerMTU - overhead, true
}

// PathCapacity is what a lower path can carry, together with whether that is actually known.
//
// The two fields are separate rather than one value with a zero meaning unknown, because zero is not a
// distinguishable answer: a caller that read `MTU == 0` as "unknown" would be one refactor away from
// reading it as "no capacity" and refusing a working configuration.
type PathCapacity struct {
	// InnerMTU is the inner IP MTU the lower path carries. Meaningful only when Known is true.
	InnerMTU uint32
	// Family is the family the lower path's packets travel in, or IPFamilyUnknown.
	Family IPFamily
	// Known reports whether the capacity was actually proven.
	Known bool
}

// PortMTUProvider is implemented by a lower layer that has a FIXED inner IP capacity it can state.
//
// It is deliberately a one-method capability rather than an interface in adapter: a transport that
// discovers its own MTU (TCP-based dialers), or one whose capacity is a function of runtime conditions,
// must NOT implement it. Implementing it is a claim that the number is fixed and provable, and the
// consumers of this helper treat it as exactly that.
type PortMTUProvider interface {
	// PortMTU reports the inner IP MTU. It must be answerable BEFORE the provider is Started, because
	// the protocols stacked on top of it are constructed first and size themselves at construction.
	PortMTU() uint32
}

// DetourPathCapacity resolves the capacity of the tunnel a `detour` names, if that detour is a fixed
// inner-IP tunnel this fork can prove a number for.
//
// # What it deliberately does not do
//
// It resolves an ENDPOINT, by tag, and only when that endpoint implements PortMTUProvider. It does not
// evaluate a group, walk a nested detour chain, or ask a dynamic outbound what it might select - and
// that restraint is the design, not a first cut.
//
// The reason is that a group's capacity is a function of which member is selected, and selection is
// runtime state: the round-robin cursor, health, urltest results. Answering "what is this group's MTU"
// at construction would mean either taking a min over reachable leaves - which is a DIFFERENT number
// from what any actual flow will get, and would cap a fast member because a slow one exists - or
// consuming a selection to find out, which would advance a cursor during construction. Neither is
// acceptable, so a group is reported as unknown and the upper protocol keeps its existing behaviour.
//
// # Errors
//
// A detour tag that does not resolve produces Known=false and no error. That is deliberate: this helper
// exists to find an OPTIONAL capability, and a missing capability must not turn a working configuration
// into a construction failure. A detour that names nothing is caught by the outbound dependency graph at
// Start, which is where that failure belongs.
func DetourPathCapacity(ctx context.Context, detourTag string) PathCapacity {
	if detourTag == "" {
		return PathCapacity{}
	}
	endpointManager := service.FromContext[adapter.EndpointManager](ctx)
	if endpointManager == nil {
		return PathCapacity{}
	}
	endpoint, loaded := endpointManager.Get(detourTag)
	if !loaded {
		return PathCapacity{}
	}
	provider, isProvider := endpoint.(PortMTUProvider)
	if !isProvider {
		return PathCapacity{}
	}
	innerMTU := provider.PortMTU()
	if innerMTU == 0 {
		return PathCapacity{}
	}
	return PathCapacity{InnerMTU: innerMTU, Family: IPFamilyUnknown, Known: true}
}

// QuicPayloadCeiling returns the largest QUIC UDP payload that fits a proven lower path, and whether a
// ceiling applies at all.
//
// It is the composition of the two facts above: the lower capacity, and this protocol's own overhead.
// Returning ok=false for an unknown path is the whole contract - see PacketOverheadCeiling.
func (c PathCapacity) QuicPayloadCeiling() (uint32, bool) {
	if !c.Known {
		return 0, false
	}
	return PacketOverheadCeiling(c.InnerMTU, c.Family)
}

// ClampToCeiling applies a proven ceiling to a configured value.
//
// The semantics, stated once because they are the product decision:
//
//   - no ceiling: the configured value is returned unchanged, so a direct dial keeps exactly the
//     behaviour it had before this helper existed;
//   - a configured value of zero, with a ceiling: the ceiling is used. Zero means "no preference", and
//     the ceiling IS the preference;
//   - a configured value below the ceiling: it is kept. The operator asked for something smaller, and
//     there is no reason to override a value that already fits;
//   - a configured value above the ceiling: it is clamped DOWN. A physical capacity is a correctness
//     constraint, not a preference, so it wins over a value that would produce a packet the path
//     cannot carry.
func ClampToCeiling(configured int, ceiling uint32, hasCeiling bool) int {
	if !hasCeiling {
		return configured
	}
	if configured <= 0 {
		return int(ceiling)
	}
	if uint32(configured) > ceiling {
		return int(ceiling)
	}
	return configured
}
