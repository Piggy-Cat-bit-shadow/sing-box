package masque

import (
	"net/netip"
	"testing"
	"time"
)

// ROUTE_ADVERTISEMENT overlap validation, per RFC 9484.
//
// RFC 9484 section 4.2.1 requires the address ranges in a ROUTE_ADVERTISEMENT to
// be non-overlapping, and specifies that they are ordered by IP version and then
// by IP protocol. The previous implementation enforced that ordering but derived
// non-overlap from it, which is not sufficient: the ordering check compares the
// previous range's PROTOCOL with the current one, and when they differ it accepts
// the pair without testing the ranges themselves.
//
// That matters because protocol 0 is not "no protocol" - it means ALL protocols.
// RoutesContain applies exactly that rule:
//
//	route.Protocol == 0 || route.Protocol == protocol || isControlProtocol(protocol)
//
// so "192.0.2.0-192.0.2.255 protocol=0" followed by the same range at protocol=6
// describes the same traffic twice, and a peer could rely on whichever entry the
// lookup happened to reach first.

// routeCapsulePayload encodes address ranges as a ROUTE_ADVERTISEMENT payload.
func routeCapsulePayload(entries []AddressRange) []byte {
	var payload []byte
	for _, entry := range entries {
		payload = appendAddress(payload, entry.Start)
		payload = append(payload, entry.End.AsSlice()...)
		payload = append(payload, entry.Protocol)
	}
	return payload
}

func mustRange(t *testing.T, start, end string, protocol uint8) AddressRange {
	t.Helper()
	return AddressRange{
		Start:    netip.MustParseAddr(start),
		End:      netip.MustParseAddr(end),
		Protocol: protocol,
	}
}

// TestRouteAdvertisementOverlapIsRejected covers the exact-overlap cases.
func TestRouteAdvertisementOverlapIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		routes []AddressRange
	}{
		{
			// The case the audit flagged: protocol 0 means all protocols, so a
			// protocol-specific range over the same addresses is contained in it.
			name: "protocol 0 then protocol 6 over the same range",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.255", 0),
				mustRange(t, "192.0.2.0", "192.0.2.255", 6),
			},
		},
		{
			name: "protocol 0 then protocol 17 over the same range",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.255", 0),
				mustRange(t, "192.0.2.0", "192.0.2.255", 17),
			},
		},
		{
			// Reversed order: the protocol-specific range is listed first, so the
			// ordering check cannot hide it either.
			name: "protocol 6 then protocol 0 over the same range",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.255", 6),
				mustRange(t, "192.0.2.0", "192.0.2.255", 0),
			},
		},
		{
			name: "protocol 0 then protocol 6, partial overlap",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.127", 0),
				mustRange(t, "192.0.2.64", "192.0.2.255", 6),
			},
		},
		{
			name: "IPv6 protocol 0 then protocol 6, identical range",
			routes: []AddressRange{
				mustRange(t, "2001:db8::", "2001:db8::ffff", 0),
				mustRange(t, "2001:db8::", "2001:db8::ffff", 6),
			},
		},
		{
			name: "protocol 0 nested inside protocol 0",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.255", 0),
				mustRange(t, "192.0.2.64", "192.0.2.128", 0),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRoutes(routeCapsulePayload(tc.routes))
			if err == nil {
				t.Fatalf("overlapping ranges were accepted: %+v", tc.routes)
			}
			t.Logf("rejected: %v", err)
		})
	}
}

// TestRouteAdvertisementValidListsAreAccepted is the control.
//
// Without it, the rejections above would also pass against a parser that refused
// every multi-entry advertisement, which would break the feature rather than
// validate it.
func TestRouteAdvertisementValidListsAreAccepted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		routes []AddressRange
	}{
		{
			name:   "single range",
			routes: []AddressRange{mustRange(t, "192.0.2.0", "192.0.2.255", 0)},
		},
		{
			name: "adjacent ranges do not overlap",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.127", 0),
				mustRange(t, "192.0.2.128", "192.0.2.255", 0),
			},
		},
		{
			name: "same range, different protocols - RFC ordering allows this only " +
				"when the ranges themselves do not overlap",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.127", 6),
				mustRange(t, "192.0.2.128", "192.0.2.255", 17),
			},
		},
		{
			name: "IPv4 then IPv6, ordered by version",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.255", 0),
				mustRange(t, "2001:db8::", "2001:db8::ffff", 0),
			},
		},
		{
			name: "ordered by protocol within one version",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.127", 0),
				mustRange(t, "192.0.2.128", "192.0.2.191", 6),
				mustRange(t, "192.0.2.192", "192.0.2.255", 17),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, err := parseRoutes(routeCapsulePayload(tc.routes))
			if err != nil {
				t.Fatalf("a valid advertisement was rejected: %v", err)
			}
			if len(routes) != len(tc.routes) {
				t.Fatalf("parsed %d routes, want %d", len(routes), len(tc.routes))
			}
		})
	}
}

// TestRouteAdvertisementOrderingStillEnforced guards the checks that already
// existed, so adding overlap validation cannot quietly remove them.
func TestRouteAdvertisementOrderingStillEnforced(t *testing.T) {
	for _, tc := range []struct {
		name   string
		routes []AddressRange
	}{
		{
			name: "IPv6 before IPv4 is out of order",
			routes: []AddressRange{
				mustRange(t, "2001:db8::", "2001:db8::ffff", 0),
				mustRange(t, "192.0.2.0", "192.0.2.255", 0),
			},
		},
		{
			name: "protocol descending is out of order",
			routes: []AddressRange{
				mustRange(t, "192.0.2.0", "192.0.2.127", 17),
				mustRange(t, "192.0.2.128", "192.0.2.255", 6),
			},
		},
		{
			name: "start after end",
			routes: []AddressRange{
				mustRange(t, "192.0.2.255", "192.0.2.0", 0),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRoutes(routeCapsulePayload(tc.routes)); err == nil {
				t.Fatalf("an out-of-order advertisement was accepted: %+v", tc.routes)
			}
		})
	}
}

// TestRouteAdvertisementValidationIsLinear pins the COST of the overlap check.
//
// The first version of the cross-protocol fix compared every earlier range with
// every new one. It was correct and it was a denial of service: a 1 MiB capsule
// of single-address ranges took 13.5 seconds to reject, against 16ms for the
// ordering-only check it replaced. Measuring that is what identified the problem,
// so the bound is asserted here rather than left to be rediscovered.
//
// The input is the worst case for a quadratic scan: many ranges that DO NOT
// overlap, so no early rejection shortens the work.
func TestRouteAdvertisementValidationIsLinear(t *testing.T) {
	var payload []byte
	const entrySize = 11 // version + two IPv4 addresses + protocol
	count := 0
	for len(payload)+entrySize <= 1<<20 {
		address := netip.AddrFrom4([4]byte{10, 0, byte(count >> 8), byte(count)})
		payload = appendAddress(payload, address)
		payload = append(payload, address.AsSlice()...)
		payload = append(payload, 0)
		count++
	}
	if count < 10000 {
		t.Fatalf("the fixture only produced %d ranges; it must be large enough "+
			"for a quadratic implementation to be slow", count)
	}

	// The fixture's ranges are not strictly ascending once the low bytes wrap,
	// so it is a realistic ordering-violation input rather than a valid
	// advertisement. Either outcome (parsed or rejected) exercises the scan.
	start := time.Now()
	_, _ = parseRoutes(payload)
	elapsed := time.Since(start)

	t.Logf("%d ranges over %d bytes validated in %v", count, len(payload), elapsed)

	// The bound is deliberately loose - a quadratic scan needs over ten seconds
	// on this input, so anything near a second is unambiguously linear. A tight
	// bound would be flaky on a loaded CI runner without catching anything the
	// loose one misses.
	if elapsed > 2*time.Second {
		t.Fatalf("validating %d ranges took %v, which indicates the overlap "+
			"check is no longer linear: a crafted capsule of this size must not "+
			"be able to occupy a server for seconds", count, elapsed)
	}
}
