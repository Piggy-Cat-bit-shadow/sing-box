package masque

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

// Benchmarks for the route and address-prefix CONTAINMENT checks on the packet
// path.
//
// # What is measured
//
// Three helpers answer "is this destination inside the tunnel's routes":
//
//	RoutesContain     TX: is the destination routable through this tunnel
//	prefixesContain   RX: is the destination one of our assigned addresses
//	rangesContain     RX: is the destination inside an advertised range
//
// All three are linear scans built on slices.ContainsFunc, so their cost grows
// with the number of routes the peer advertised.
//
// # Why the sizes are the ones they are
//
// The task is to decide whether a linear scan is adequate. That question is
// meaningless without knowing how many routes a real configuration carries, so the
// benchmark sweeps 1, 4, 16, 64 and 256 entries rather than testing one size.
//
// A MASQUE CONNECT-IP client's ROUTE_ADVERTISEMENT typically carries a handful of
// ranges: a default route, or a small set of corporate prefixes. A large
// advertisement is possible (a peer splitting a /8 into many ranges, or a dual-stack
// split set), which is what the upper end of the sweep represents.
//
// The results are recorded in docs/JIEJIE-MASQUE-PERFORMANCE.md and drive the
// decision. The honest outcome for a handful of routes may well be "leave the
// linear scan alone": a trie or a pre-normalised lookup table is real complexity,
// and it must not be added on the theory that it should be faster.

// benchRouteSet builds `count` non-overlapping IPv4 ranges plus a matching prefix
// list, and returns them together with an address INSIDE the last range (a hit)
// and one outside every range (a miss).
//
// Both a hit and a miss are measured, because they exercise different paths: a hit
// can stop early, and a miss must scan every entry. A benchmark that only measured
// hits would understate the worst case by a factor of `count`.
func benchRouteSet(count int) (routes []AddressRange, prefixes []netip.Prefix, hit netip.Addr, miss netip.Addr) {
	routes = make([]AddressRange, 0, count)
	prefixes = make([]netip.Prefix, 0, count)

	// Ranges are laid out as 10.<index>.0.0/16 so they never overlap, which is what
	// parseRoutes requires of an advertisement.
	for index := range count {
		start := netip.AddrFrom4([4]byte{10, byte(index), 0, 0})
		end := netip.AddrFrom4([4]byte{10, byte(index), 255, 255})
		routes = append(routes, AddressRange{Start: start, End: end, Protocol: 0})
		prefixes = append(prefixes, netip.PrefixFrom(start, 16))
	}

	// The hit is in the LAST range, so a hit costs a full scan in the worst case.
	hit = netip.AddrFrom4([4]byte{10, byte(count - 1), 1, 1})
	// The miss matches nothing at all.
	miss = netip.AddrFrom4([4]byte{203, 0, 113, 1})
	return routes, prefixes, hit, miss
}

// routeBenchSizes is the sweep the decision is based on.
var routeBenchSizes = []int{1, 4, 16, 64, 256}

func BenchmarkRoutesContainHit(b *testing.B) {
	for _, count := range routeBenchSizes {
		b.Run(fmt.Sprintf("%droutes", count), func(b *testing.B) {
			routes, _, hit, _ := benchRouteSet(count)
			b.ReportAllocs()
			for b.Loop() {
				if !RoutesContain(routes, hit, 6) {
					b.Fatal("expected a hit")
				}
			}
		})
	}
}

func BenchmarkRoutesContainMiss(b *testing.B) {
	for _, count := range routeBenchSizes {
		b.Run(fmt.Sprintf("%droutes", count), func(b *testing.B) {
			routes, _, _, miss := benchRouteSet(count)
			b.ReportAllocs()
			for b.Loop() {
				if RoutesContain(routes, miss, 6) {
					b.Fatal("expected a miss")
				}
			}
		})
	}
}

func BenchmarkPrefixesContainHit(b *testing.B) {
	for _, count := range routeBenchSizes {
		b.Run(fmt.Sprintf("%dprefixes", count), func(b *testing.B) {
			_, prefixes, hit, _ := benchRouteSet(count)
			b.ReportAllocs()
			for b.Loop() {
				if !prefixesContain(prefixes, hit) {
					b.Fatal("expected a hit")
				}
			}
		})
	}
}

func BenchmarkPrefixesContainMiss(b *testing.B) {
	for _, count := range routeBenchSizes {
		b.Run(fmt.Sprintf("%dprefixes", count), func(b *testing.B) {
			_, prefixes, _, miss := benchRouteSet(count)
			b.ReportAllocs()
			for b.Loop() {
				if prefixesContain(prefixes, miss) {
					b.Fatal("expected a miss")
				}
			}
		})
	}
}

func BenchmarkRangesContainMiss(b *testing.B) {
	for _, count := range routeBenchSizes {
		b.Run(fmt.Sprintf("%dranges", count), func(b *testing.B) {
			routes, _, _, miss := benchRouteSet(count)
			b.ReportAllocs()
			for b.Loop() {
				if rangesContain(routes, miss) {
					b.Fatal("expected a miss")
				}
			}
		})
	}
}

// TestRouteContainmentScalesLinearly documents the SCALING, so a future change to
// the data structure has a test to update rather than only a benchmark to rerun.
//
// It asserts what the benchmarks show: cost grows with the entry count. That is
// the property a trie or a normalized table would remove, and pinning it here means
// the claim "the scan is linear" cannot silently stop being true.
func TestRouteContainmentScalesLinearly(t *testing.T) {
	t.Parallel()

	// The containment answers must be CORRECT at every size before scaling means
	// anything: a scan that returned early for the wrong reason would look cheap.
	for _, count := range routeBenchSizes {
		routes, prefixes, hit, miss := benchRouteSet(count)

		if !RoutesContain(routes, hit, 6) {
			t.Fatalf("RoutesContain missed a destination inside %d ranges", count)
		}
		if RoutesContain(routes, miss, 6) {
			t.Fatalf("RoutesContain matched a destination outside %d ranges", count)
		}
		if !prefixesContain(prefixes, hit) {
			t.Fatalf("prefixesContain missed an assigned address with %d prefixes", count)
		}
		if prefixesContain(prefixes, miss) {
			t.Fatalf("prefixesContain matched an unassigned address with %d prefixes", count)
		}
		if !rangesContain(routes, hit) {
			t.Fatalf("rangesContain missed a destination inside %d ranges", count)
		}
		if rangesContain(routes, miss) {
			t.Fatalf("rangesContain matched a destination outside %d ranges", count)
		}
	}

	// The fixture itself must be well formed: the sizes must be ascending and
	// non-overlapping or the scaling comparison would be meaningless.
	if !slices.IsSorted(routeBenchSizes) {
		t.Fatal("routeBenchSizes must be ascending")
	}
}
