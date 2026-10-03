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

// MergeOriginalDestination combines resolved candidates with the address the client chose.
//
// It is exported because the router needs the same ordering rules the dialer will apply, so
// that the list it publishes on the metadata is already in the order the scheduler will use.
// Having the router build the list one way and the scheduler reorder it another is exactly
// the kind of split this package exists to remove.
func MergeOriginalDestination(original netip.Addr, resolved []netip.Addr, strategy C.DomainStrategy) []netip.Addr {
	return planCandidates(resolved, original, strategy).addresses()
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
	// The original-promotion rule below applies to ONE family's internal order, which is
	// orthogonal to excluding a family entirely. A strict strategy must therefore still place
	// the application's own address first WITHIN the family it admits - the early returns here
	// used to skip that, so `ipv4_only` with original 192.0.2.4 and resolved
	// [192.0.2.8, 192.0.2.4] produced [.8, .4] instead of [.4, .8].
	//
	// The original is still never admitted to a family the strategy excludes: it is only
	// promoted when it already belongs to the collected family.
	switch strategy {
	case C.DomainStrategyIPv4Only:
		return candidatePlan{
			candidates: promoteOriginal(collectFamily(addresses, familyIPv4, false), familyIPv4, originalDestination),
			preferIPv6: false,
		}
	case C.DomainStrategyIPv6Only:
		return candidatePlan{
			candidates: promoteOriginal(collectFamily(addresses, familyIPv6, false), familyIPv6, originalDestination),
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

	// The original destination goes FIRST among its family's candidates.
	//
	// It is the endpoint the application actually selected, and it outranks anything this
	// package recovered by re-resolving a sniffed name. The application's address may come from
	// its own DNS cache, a hosts file, split-horizon or enterprise DNS, a CDN selection, or an
	// earlier legitimate answer - and re-resolving the sniffed name can legitimately return a
	// DIFFERENT address for the same name.
	//
	// Appending it instead, which an earlier version did, meant a recovery lookup could push
	// the application's own endpoint behind addresses it never asked for. On a slow path that
	// is the difference between connecting immediately and connecting after several failed
	// attempts, and it silently overrules the application's choice.
	//
	// Being first WITHIN its family is what keeps the configured preference intact: with
	// prefer_ipv4 the IPv4 family still leads overall, and the original leads within whichever
	// family it belongs to.
	// The application's own address leads within its family; see promoteOriginal.
	preferred = promoteOriginal(preferred, familyFor(preferIPv6), originalDestination)
	other = promoteOriginal(other, familyFor(!preferIPv6), originalDestination)

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

// promoteOriginal makes the application's own address lead the family it belongs to.
//
// # Two cases, one rule
//
// The rule is "the original leads its family". It covers two situations that look different but
// must produce the same ordering:
//
//   - the original is ABSENT from the resolved list and must be ADDED to its family. This is
//     the recovery case: with AsIS and an IPv6 original while only IPv4 resolved, the IPv6
//     slice is empty and the application's endpoint must still appear in it.
//
//   - the original is ALREADY in the resolved list and must be MOVED to the front of its
//     family. A cached or split-horizon answer frequently contains it, and a presence check
//     would leave a re-resolved address in front of the endpoint the application chose:
//
//     original = 192.0.2.4
//     resolved = [192.0.2.8, 192.0.2.4, 192.0.2.9]
//     plan     = [192.0.2.8, 192.0.2.4, 192.0.2.9]   <- the bug this replaces
//
// Removal is stable, so every other address keeps its relative resolver order and no duplicate
// can result.
//
// # Why the target family is a parameter
//
// The caller knows which family's slice it is holding, and it passes the slice even when that
// slice is empty - which is exactly the recovery case above. Inferring the family from the
// slice contents would fail on an empty slice and drop the original entirely, and inspecting
// family[0] would only ever be a guess about the caller's intent.
//
// A slice for a different family is returned untouched, so a strict strategy cannot be widened
// by the presence of the application's address.
func promoteOriginal(family []dualStackCandidate, forFamily addressFamily, originalDestination netip.Addr) []dualStackCandidate {
	if !originalDestination.IsValid() || forFamily == familyInvalid {
		return family
	}
	original := unmapAddress(originalDestination)
	if classifyAddress(originalDestination) != forFamily {
		// The original belongs to the other family. Admitting it here would turn a strict
		// single-family strategy into a preference, so it is not this slice's business.
		return family
	}

	// Already leading: nothing to move, and re-prepending would be wasted work on the hot path.
	if len(family) > 0 && family[0].address == original && family[0].original {
		return family
	}

	family = removeAddress(family, original)
	return append([]dualStackCandidate{{
		address:  original,
		family:   forFamily,
		original: true,
	}}, family...)
}

// removeAddress returns candidates without the given canonical address, preserving the
// relative order of everything else.
//
// A stable remove is what keeps this fix from reordering the resolver's answers: only the
// original moves, and every other address stays exactly where the resolver put it. The
// alternative - rebuilding the slice from a filtered copy - would risk silently rotating the
// remaining candidates, which is a different bug in the same function.
func removeAddress(candidates []dualStackCandidate, address netip.Addr) []dualStackCandidate {
	removed := false
	for index, candidate := range candidates {
		if candidate.address == address {
			removed = true
			candidates = append(candidates[:index], candidates[index+1:]...)
			break
		}
	}
	if !removed {
		return candidates
	}
	return candidates
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
