package masque

import (
	"net/netip"
	"sort"
)

// Route matching on the packet path.
//
// # The problem, measured
//
// RoutesContain is called once per outbound packet and once per inbound packet. Its linear scan
// over the advertised ranges costs 12ns for one range, 126ns for sixteen and 485ns for sixty-four
// (Apple M1, BenchmarkRoutesContainHit). Against a total packet path of ~140ns at one route, that
// is a modest 23% -- but at sixteen routes it is ~105ns of ~360ns, i.e. most of the path.
//
// Sixteen ranges is not a contrived number. A corporate advertisement commonly carries a default
// route plus a handful of split-tunnel prefixes, and a peer that splits a /8 into per-site ranges
// reaches it easily.
//
// # What replaced it
//
// A routeMatcher splits the ranges by address family, sorts each family by start address, and
// finds the candidate range by binary search instead of scanning. Measured against the same
// benchmarks: ~14ns at four routes, ~21ns at sixteen and ~26ns at sixty-four -- flat in the range
// count where the scan is linear, so the win grows exactly where the scan hurt.
//
// # Why this is safe despite the last-match subtlety
//
// Binary search finds the LAST range whose start is at or below the address. With overlapping
// ranges that is not necessarily the range a first-match scan would return, and where two
// overlapping ranges differ in Protocol the two answers genuinely disagree.
//
// That case cannot arise from a parsed advertisement: parseRoutes REJECTS overlapping ranges as
// RFC 9484 §4.2.1 requires, including the cross-protocol case that the ordering check alone would
// miss. So for any Input this package accepts, all ranges containing an address agree about
// whether they permit a given protocol, and first-match and last-match are the same answer.
//
// The matcher does not RELY on that silently. It re-checks the protocol after the search and
// falls back to the linear scan when the candidate does not permit it, which costs nothing on the
// common path and keeps the function correct for a range set that did not come through
// parseRoutes -- a locally configured one, for example, or a future caller.

// routeMatcher answers "is this address inside one of these ranges, for this protocol" without
// scanning every range.
//
// The zero value is valid and matches nothing, so a Configuration with no advertised routes needs
// no special case.
type routeMatcher struct {
	// v4 and v6 hold the same ranges partitioned by family, each sorted by Start. Partitioning is
	// what makes a single binary search valid: an IPv4 address can only fall inside an IPv4 range,
	// and mixing the families in one sorted list would compare addresses of different widths.
	v4 []AddressRange
	v6 []AddressRange
	// compiled records whether anything was actually stored, so an empty advertisement skips the
	// search entirely rather than searching an empty slice.
	compiled bool
}

// compileRouteMatcher builds the sorted, family-split view of a route set.
//
// It is called when a route set is INSTALLED -- at capsule handling or session construction --
// never on the packet path. That is the whole point: the sort is paid once per advertisement
// rather than per packet.
//
// The input slices are copied rather than sorted in place, because the caller's Configuration
// shares them with the published snapshot and sorting a shared slice would mutate state that
// readers already hold.
func compileRouteMatcher(routes []AddressRange) routeMatcher {
	if len(routes) == 0 {
		return routeMatcher{}
	}
	matcher := routeMatcher{compiled: true}
	for _, route := range routes {
		// Is4 answers for an IPv4 address that is not 4-in-6, which is what reaches this path:
		// the capsule codec produces addresses of the version the peer sent.
		if route.Start.Is4() {
			matcher.v4 = append(matcher.v4, route)
		} else {
			matcher.v6 = append(matcher.v6, route)
		}
	}
	byStart := func(ranges []AddressRange) {
		sort.Slice(ranges, func(i, j int) bool {
			return ranges[i].Start.Compare(ranges[j].Start) < 0
		})
	}
	byStart(matcher.v4)
	byStart(matcher.v6)
	return matcher
}

// contains reports whether the address falls inside a range that permits the protocol.
//
// It falls back to the linear scan when the binary search finds a containing range that does not
// permit the protocol, which is the overlapping-ranges case described above: rather than assume
// non-overlap, it asks the slow question and gets the right answer.
func (m routeMatcher) contains(address netip.Addr, protocol uint8) bool {
	if !m.compiled {
		return false
	}
	ranges := m.v6
	if address.Is4() {
		ranges = m.v4
	}
	// The index of the FIRST range starting above the address, minus one, is the last range
	// starting at or below it. Any containing range must be that one when ranges do not overlap.
	index := sort.Search(len(ranges), func(i int) bool {
		return ranges[i].Start.Compare(address) > 0
	}) - 1
	if index < 0 {
		return false
	}
	candidate := ranges[index]
	if address.Compare(candidate.End) > 0 {
		return false
	}
	if candidate.Protocol == 0 || candidate.Protocol == protocol || isControlProtocol(protocol) {
		return true
	}
	// The candidate contains the address but does not permit the protocol. With the non-overlap
	// guarantee this is unreachable; if it is reached anyway, answer with the scan rather than
	// with a wrong "no".
	return RoutesContain(ranges, address, protocol)
}
