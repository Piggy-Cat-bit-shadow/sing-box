// Package dialer's dual-stack candidate planning.
//
// # What this file owns, and what it deliberately does not
//
// This is the single place that decides WHICH address to attempt and WHEN. It knows about
// addresses, families, timing and recent family health. It knows nothing about QUIC, TUIC,
// Hysteria, MASQUE or any other protocol, and it must stay that way: the protocols disagree
// about what "success" means, and that disagreement belongs to them.
//
//	planner    decides when to start which candidate
//	executor   decides what counts as success
//
// Conflating the two is how a transport ends up accepting a UDP socket as proof that a
// network path works. A socket being created proves the kernel made a socket; it says
// nothing about whether anything on the far side will answer.
//
// # Why interleaving rather than family blocks
//
// TCCR/RFC 8305 style racing does not try every IPv6 address before trying any IPv4
// address. A single unreachable address in the preferred family would then cost the whole
// family's timeout before the healthy family was even attempted. Interleaving means the
// first candidate of each family is tried early:
//
//	prefer IPv6:  v6#1  v4#1  v6#2  v4#2  v6#3
//	prefer IPv4:  v4#1  v6#1  v4#2  v6#2  v6#3
//
// Resolver order WITHIN a family is preserved, because the resolver's ordering carries
// information (priority, weight, or the authoritative server's intent) that this package
// has no basis to second-guess.
package dialer

import (
	"net/netip"

	C "github.com/sagernet/sing-box/constant"
)

// addressFamily is which stack an address belongs to.
type addressFamily uint8

const (
	familyInvalid addressFamily = iota
	familyIPv4
	familyIPv6
)

func (f addressFamily) String() string {
	switch f {
	case familyIPv4:
		return "ipv4"
	case familyIPv6:
		return "ipv6"
	default:
		return "invalid"
	}
}

// classifyAddress reports which family an address belongs to.
//
// An IPv4-mapped IPv6 address (::ffff:1.2.3.4) is treated as IPv4. It is a representation
// of an IPv4 address, and treating it as IPv6 would mean attempting an IPv4 destination
// over the IPv6 stack - which does not work, and would look like an IPv6 failure.
//
// Invalid addresses return familyInvalid and are excluded from racing entirely. Attempting
// to dial the zero Addr produces a confusing error at best.
func classifyAddress(address netip.Addr) addressFamily {
	if !address.IsValid() {
		return familyInvalid
	}
	if address.Is4() || address.Is4In6() {
		return familyIPv4
	}
	return familyIPv6
}

// unmapAddress returns the canonical form of an address, so an IPv4-mapped IPv6 address
// and its IPv4 form are recognised as the same destination during deduplication.
func unmapAddress(address netip.Addr) netip.Addr {
	if address.Is4In6() {
		return address.Unmap()
	}
	return address
}

// dualStackCandidate is one address the planner may attempt.
type dualStackCandidate struct {
	address netip.Addr
	family  addressFamily
	// original marks the address the application actually selected, before any recovery.
	// It is carried so a fallback can prefer to stay on the application's own choice when
	// the strategy expresses no preference, and so diagnostics can say where a candidate
	// came from.
	original bool
}

// candidatePlan is the ordered result of planning.
type candidatePlan struct {
	candidates []dualStackCandidate
	// preferIPv6 records the family the strategy asked for, so the executor does not have
	// to re-derive it from the ordering.
	preferIPv6 bool
}

// addresses returns the planned addresses in attempt order.
func (p candidatePlan) addresses() []netip.Addr {
	addresses := make([]netip.Addr, len(p.candidates))
	for i, candidate := range p.candidates {
		addresses[i] = candidate.address
	}
	return addresses
}

// planCandidates orders addresses for dual-stack racing.
//
// strategy is the caller's preference. originalDestination, when valid, is the address the
// application chose before any recovery; it is included in the plan and deduplicated
// against the resolved addresses.
func planCandidates(addresses []netip.Addr, originalDestination netip.Addr, strategy C.DomainStrategy) candidatePlan {
	preferIPv6 := strategy == C.DomainStrategyPreferIPv6

	// Hard single-family strategies must never produce a candidate of the other family.
	// "only" means only; admitting the other family because the original destination
	// happened to be in it would silently turn a strict policy into a preference.
	switch strategy {
	case C.DomainStrategyIPv4Only:
		return candidatePlan{
			candidates: collectFamily(addresses, familyIPv4, false),
			preferIPv6: false,
		}
	case C.DomainStrategyIPv6Only:
		return candidatePlan{
			candidates: collectFamily(addresses, familyIPv6, false),
			preferIPv6: true,
		}
	}

	// AsIS with no explicit preference: keep the application's own family first. A recovery
	// exists to provide a FALLBACK, not to overrule the choice the application already made
	// when nothing has been shown to be wrong.
	if strategy == C.DomainStrategyAsIS && originalDestination.IsValid() {
		preferIPv6 = classifyAddress(originalDestination) == familyIPv6
	}

	preferred := collectFamily(addresses, familyFor(preferIPv6), false)
	other := collectFamily(addresses, familyFor(!preferIPv6), false)

	// The original destination is appended to its own family, at that family's end, unless
	// the resolver already returned it. Appending rather than prepending keeps the resolver's
	// ordering authoritative within the family; it is a recovery candidate, not a preferred
	// one.
	if originalDestination.IsValid() {
		original := unmapAddress(originalDestination)
		if !containsAddress(preferred, original) && !containsAddress(other, original) {
			candidate := dualStackCandidate{
				address:  original,
				family:   classifyAddress(originalDestination),
				original: true,
			}
			if candidate.family == familyFor(preferIPv6) {
				preferred = append(preferred, candidate)
			} else {
				other = append(other, candidate)
			}
		}
	}

	return candidatePlan{
		candidates: interleaveCandidates(preferred, other),
		preferIPv6: preferIPv6,
	}
}

func familyFor(preferIPv6 bool) addressFamily {
	if preferIPv6 {
		return familyIPv6
	}
	return familyIPv4
}

// collectFamily selects one family's candidates in input order, deduplicating.
//
// Deduplication is by canonical address, so an IPv4-mapped form and its IPv4 form count as
// the same destination and are attempted once.
func collectFamily(addresses []netip.Addr, family addressFamily, original bool) []dualStackCandidate {
	candidates := make([]dualStackCandidate, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if classifyAddress(address) != family {
			continue
		}
		canonical := unmapAddress(address)
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		candidates = append(candidates, dualStackCandidate{
			address:  canonical,
			family:   family,
			original: original,
		})
	}
	return candidates
}

func containsAddress(candidates []dualStackCandidate, address netip.Addr) bool {
	for _, candidate := range candidates {
		if candidate.address == address {
			return true
		}
	}
	return false
}

// interleaveCandidates alternates the two families so the first candidate of each family is
// attempted early.
//
// The shallow copy at the end matters: the caller's slices are not retained, so a plan
// cannot be mutated by a later append on the same backing array.
func interleaveCandidates(preferred []dualStackCandidate, other []dualStackCandidate) []dualStackCandidate {
	if len(other) == 0 {
		return append([]dualStackCandidate(nil), preferred...)
	}
	if len(preferred) == 0 {
		return append([]dualStackCandidate(nil), other...)
	}
	ordered := make([]dualStackCandidate, 0, len(preferred)+len(other))
	for index := 0; index < len(preferred) || index < len(other); index++ {
		if index < len(preferred) {
			ordered = append(ordered, preferred[index])
		}
		if index < len(other) {
			ordered = append(ordered, other[index])
		}
	}
	return ordered
}
