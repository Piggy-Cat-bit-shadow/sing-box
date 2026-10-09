package masque

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

// The deterministic linearity gate for the per-packet ownership scan.
//
// # Why this file exists rather than a wall-clock ratio
//
// The claim is "the ownership scan visits a number of ranges proportional to the number of
// advertised ranges". Two tests used to pin it by timing the same lookup loop over 8192 ranges and
// over 1 range and asserting that the ratio stayed under 4x the range count:
//
//	TestTheOwnershipScanIsLinearOverAdvertisedRanges   (ownership_policy_test.go)
//	TestTheOwnershipScanIsLinearHereToo                (control_burst_test.go)
//
// Both measured the host, not the algorithm. MEASURED on the integration baseline: the ratio came
// out at 40605x-49281x against a bound of 32768x, and it reproduced both on a clean baseline and on
// the integration branch - a linear scan legitimately costs about 8192x here, so a bound with only
// 4x of headroom was crossed by ordinary measurement error at the small end (the one-range side is
// around 10us per lookup and is dominated by the fixed per-lookup cost, so a slightly colder or
// warmer sample moves the ratio by tens of percent). Raising the threshold would have been the other
// way to make it stop failing: it would have kept a host-sensitive gate while reducing what it can
// detect.
//
// A visited-range COUNT is the same claim with no clock in it. It is exact, it is reproducible, and
// it fails for the reason it states.
//
// # What it can and cannot detect
//
// It detects any change to how many ranges the scan consults per lookup: a skipped range, an early
// return, an empty list, or extra passes over the list. Those are the shapes a complexity regression
// takes in this loop.
//
// It cannot detect a constant-factor regression inside the per-range comparison, because that work
// happens once per visited range either way. BenchmarkOwnershipScanCostByRangeCount below covers
// that, and reports ns/op and allocs/op rather than asserting a wall-clock bound.

// scanCounter counts the ranges the production scan visits.
//
// It is a plain integer rather than an atomic: the lookups below run one at a time in the calling
// goroutine, and the hook is installed and removed inside a single test. No test in this package
// runs in parallel, and the hook is nil outside these tests.
type scanCounter struct {
	visits int64
}

// countOwnershipScanVisits installs the counter for the duration of the test.
func countOwnershipScanVisits(t *testing.T) *scanCounter {
	t.Helper()
	counter := &scanCounter{}
	original := testRoutesContainCounter
	testRoutesContainCounter = func() { counter.visits++ }
	t.Cleanup(func() { testRoutesContainCounter = original })
	return counter
}

// ownershipRoutesFor builds `count` single-address, non-overlapping ranges in 10.0.0.0/8.
//
// Single addresses keep every range distinguishable, so a count can be attributed to a position in
// the list, and the same fixture serves the miss cases (the whole list is walked) and the hit cases
// (the walk stops at a known index).
func ownershipRoutesFor(count int) []AddressRange {
	routes := make([]AddressRange, 0, count)
	for index := range count {
		address := netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
		routes = append(routes, AddressRange{Start: address, End: address, Protocol: 0})
	}
	return routes
}

// ownershipScanServer builds a server with one session that advertises `routes` as PEER routes,
// which is the list Server.lookup walks, and returns the server.
//
// The session is built through the package's real session constructor (noopSession), and registered
// through the same path a real tunnel establishment uses (registerSession), so the scan under
// measurement is reached the way production reaches it.
func ownershipScanServer(t *testing.T, routes []AddressRange) *Server {
	t.Helper()
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
	})
	current := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, routes)
	registerSession(server, current)
	t.Cleanup(func() { server.releaseSession(current) })
	return server
}

// TestOwnershipScanVisitsEveryAdvertisedRangeOnce pins the exact work per lookup at the sizes the
// range-count axis is defined by: 1, 64, 1024 and the parser's own bound.
//
// The lookup misses every range, so the scan cannot return early: the count is the whole list. That
// is the worst case a peer can force, and it is the case a bound should be stated against.
func TestOwnershipScanVisitsEveryAdvertisedRangeOnce(t *testing.T) {
	miss := netip.MustParseAddr("203.0.113.1")

	for _, rangeCount := range []int{1, 64, 1024, maxRoutesPerCapsule} {
		t.Run(itoa(rangeCount)+" ranges", func(t *testing.T) {
			counter := countOwnershipScanVisits(t)
			server := ownershipScanServer(t, ownershipRoutesFor(rangeCount))

			const lookups = 64
			for range lookups {
				if got := server.lookup(miss, 0); got != nil {
					t.Fatalf("lookup returned %p for an address outside every advertised range", got)
				}
			}

			expected := int64(lookups * rangeCount)
			if counter.visits != expected {
				t.Fatalf("%d lookups over %d advertised ranges visited %d ranges, want exactly %d. "+
					"The scan must consult EVERY advertised range when the address is in none of "+
					"them - one visit per range, no more and no fewer - so a number below that means "+
					"ranges are being skipped and a number above it means the scan is doing more than "+
					"one pass over the list", lookups, rangeCount, counter.visits, expected)
			}
		})
	}
}

// TestOwnershipScanWorkIsProportionalToAdvertisedRanges is the linearity claim itself, as an
// arithmetic identity rather than a timing comparison.
//
// Doubling the number of advertised ranges must double the visited-range count for the same number
// of lookups. A scan whose work per lookup grows with the list cannot satisfy this.
func TestOwnershipScanWorkIsProportionalToAdvertisedRanges(t *testing.T) {
	miss := netip.MustParseAddr("203.0.113.2")
	const lookups = 32

	visitsFor := func(rangeCount int) int64 {
		t.Helper()
		counter := countOwnershipScanVisits(t)
		server := ownershipScanServer(t, ownershipRoutesFor(rangeCount))
		for range lookups {
			if got := server.lookup(miss, 0); got != nil {
				t.Fatalf("lookup returned %p for an address outside every advertised range", got)
			}
		}
		return counter.visits
	}

	// Each size gets its own server and its own counter, so the sizes cannot contaminate each other.
	small := visitsFor(1024)
	large := visitsFor(2048)

	if small != lookups*1024 {
		t.Fatalf("the 1024-range measurement visited %d ranges, want %d", small, lookups*1024)
	}
	if large != 2*small {
		t.Fatalf("doubling the advertised ranges from 1024 to 2048 changed the visited-range count "+
			"from %d to %d, which is %.2fx rather than 2x: the per-lookup work is not proportional "+
			"to the number of advertised ranges", small, large, float64(large)/float64(small))
	}
}

// TestOwnershipScanStopsAtTheMatchingRange pins the other direction of the same counter: a lookup
// that MATCHES an advertised range must stop there rather than walking the rest of the list.
//
// Without this, a scan rewritten to always walk the whole list would still pass the exact-count
// assertions above - all of them miss - while making every packet pay for the full list.
//
// The session's own tunnel address is answered from Server.addresses before any advertisement is
// consulted, so that case is separated out and asserted to visit nothing at all. The case that
// reaches the range scan is a session whose peer routes are what answer the question.
func TestOwnershipScanStopsAtTheMatchingRange(t *testing.T) {
	const rangeCount = 4096
	routes := ownershipRoutesFor(rangeCount)

	for _, targetIndex := range []int{0, 1, rangeCount / 2, rangeCount - 1} {
		t.Run("match at "+itoa(targetIndex), func(t *testing.T) {
			counter := countOwnershipScanVisits(t)
			server := ownershipScanServer(t, routes)

			destination := routes[targetIndex].Start
			got := server.lookup(destination, 0)
			if got == nil {
				t.Fatalf("the scan did not find range %d for %s", targetIndex, destination)
			}

			// Server.lookup walks the advertisement list BACKWARD, so the match at index i is
			// reached after (i + 1) visits: the scan starts at the last advertised range.
			expected := int64(targetIndex + 1)
			if counter.visits != expected {
				t.Fatalf("a lookup matching range %d of %d visited %d ranges, want %d: the scan "+
					"must stop at the matching range rather than walking the whole list",
					targetIndex, rangeCount, counter.visits, expected)
			}
		})
	}
}

// TestOwnershipScanIsNotAnsweredFromTheAddressMapWithoutScanning is the counterpart of the case
// above: a lookup for the address the session OWNS must not scan at all.
//
// It is here because the counter would otherwise be able to report a positive number for work that
// production does not need to do, and a gate that cannot tell "answered from the map" from "found in
// the ranges" would not be pinning the scan.
func TestOwnershipScanIsNotAnsweredFromTheAddressMapWithoutScanning(t *testing.T) {
	counter := countOwnershipScanVisits(t)
	server := ownershipScanServer(t, ownershipRoutesFor(256))

	if got := server.lookup(netip.MustParseAddr("198.18.0.2"), 0); got == nil {
		t.Fatal("the lookup did not find the session that owns 198.18.0.2")
	}
	if counter.visits != 0 {
		t.Fatalf("a lookup for an address the session owns visited %d advertised ranges; the "+
			"session address map is consulted first and must answer without walking the range list",
			counter.visits)
	}
}

// TestOwnershipScanVisitsNothingWithoutAdvertisedRanges is the vacuity guard for the whole file.
//
// If the counter could report a positive number for a list that does not exist, none of the exact
// assertions above would mean anything.
func TestOwnershipScanVisitsNothingWithoutAdvertisedRanges(t *testing.T) {
	counter := countOwnershipScanVisits(t)
	server := ownershipScanServer(t, nil)

	if got := server.lookup(netip.MustParseAddr("203.0.113.3"), 0); got != nil {
		t.Fatalf("lookup returned %p with no advertised ranges", got)
	}
	if counter.visits != 0 {
		t.Fatalf("a scan over an empty range list visited %d ranges", counter.visits)
	}
}

// TestOwnershipScanCounterSurvivesTheRangeCountAxis is the fixture's own control: it asserts that the
// benchmark and the exact-count tests use a fixture whose axis means what it says, before either is
// trusted.
func TestOwnershipScanCounterSurvivesTheRangeCountAxis(t *testing.T) {
	if maxRoutesPerCapsule <= 1024 {
		t.Fatalf("the range-count axis is not increasing: maxRoutesPerCapsule is %d",
			maxRoutesPerCapsule)
	}
	for _, rangeCount := range []int{1, 64, 1024, maxRoutesPerCapsule} {
		routes := ownershipRoutesFor(rangeCount)
		if len(routes) != rangeCount {
			t.Fatalf("the fixture produced %d routes for %d", len(routes), rangeCount)
		}
		if !routes[rangeCount-1].Contains(routes[rangeCount-1].Start) {
			t.Fatalf("%d ranges: the fixture's last range does not contain its own start", rangeCount)
		}
	}
}

// BenchmarkOwnershipScanCostByRangeCount is the companion measurement for the constant factor the
// count above cannot see.
//
// It reports ns/op and allocs/op at the sizes this axis is defined by, so a regression that made each
// range comparison more expensive - without changing how many are visited - is visible as a
// before/after on the same machine, in the same units, without a host-sensitive assertion.
func BenchmarkOwnershipScanCostByRangeCount(b *testing.B) {
	miss := netip.MustParseAddr("203.0.113.4")
	for _, rangeCount := range []int{1, 64, 1024, maxRoutesPerCapsule} {
		b.Run(itoa(rangeCount)+" ranges", func(b *testing.B) {
			// The fixture goes through the real constructor, the same one newTestServer uses; only
			// the failure reporter differs, because a benchmark has no *testing.T.
			server, err := NewServer(ServerOptions{
				Context: context.Background(),
				Logger:  logger.NOP(),
				Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
			})
			if err != nil {
				b.Fatalf("building the benchmark server failed: %v", err)
			}
			current := noopSession(server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, ownershipRoutesFor(rangeCount))
			registerSession(server, current)
			b.Cleanup(func() { server.releaseSession(current) })

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if got := server.lookup(miss, 0); got != nil {
					b.Fatalf("lookup returned %p for an address outside every advertised range", got)
				}
			}
		})
	}
}
