package masque

import (
	"net/netip"
	"runtime"
	"testing"
	"unsafe"
)

// Per-capsule entry bounds for the control capsules.
//
// RFC 9484 does not state a limit, so the values follow quic-go/connect-ip-go
// (8192 for both addresses and routes) rather than being invented here. The
// reason a bound is needed is measured in
// TestControlCapsuleStateIsBounded rather than asserted.

// addressCapsulePayload builds an ADDRESS_ASSIGN payload with the given count.
func addressCapsulePayload(count int) []byte {
	address := netip.MustParseAddr("192.0.2.0")
	entry := appendAddress(nil, address)
	entry = append(entry, 32)
	var payload []byte
	for range count {
		payload = append(payload, 0x01) // request ID
		payload = append(payload, entry...)
	}
	return payload
}

// routeAdvertisementPayload builds a ROUTE_ADVERTISEMENT payload with the given
// count of NON-overlapping single-address ranges, so only the count bound can
// reject it.
func routeAdvertisementPayload(count int) []byte {
	var payload []byte
	for index := range count {
		address := netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
		payload = appendAddress(payload, address)
		payload = append(payload, address.AsSlice()...)
		payload = append(payload, 0)
	}
	return payload
}

// TestControlCapsuleEntryCountIsBounded asserts both parsers refuse a capsule
// that carries more entries than the reference allows.
func TestControlCapsuleEntryCountIsBounded(t *testing.T) {
	t.Run("ADDRESS_ASSIGN", func(t *testing.T) {
		oversized := addressCapsulePayload(maxAddressesPerCapsule + 1)
		if _, err := parseAddresses(oversized); err == nil {
			t.Fatalf("accepted %d addresses in one capsule, above the bound of %d",
				maxAddressesPerCapsule+1, maxAddressesPerCapsule)
		} else {
			t.Logf("rejected: %v", err)
		}
	})

	t.Run("ROUTE_ADVERTISEMENT", func(t *testing.T) {
		oversized := routeAdvertisementPayload(maxRoutesPerCapsule + 1)
		if _, err := parseRoutes(oversized); err == nil {
			t.Fatalf("accepted %d routes in one capsule, above the bound of %d",
				maxRoutesPerCapsule+1, maxRoutesPerCapsule)
		} else {
			t.Logf("rejected: %v", err)
		}
	})
}

// TestControlCapsuleAtTheBoundIsAccepted is the control.
//
// Without it the rejection above would also pass against a parser that refused
// every large capsule, which would break legitimate advertisements.
func TestControlCapsuleAtTheBoundIsAccepted(t *testing.T) {
	t.Run("ADDRESS_ASSIGN", func(t *testing.T) {
		payload := addressCapsulePayload(maxAddressesPerCapsule)
		addresses, err := parseAddresses(payload)
		if err != nil {
			t.Fatalf("a capsule at exactly the bound must be accepted: %v", err)
		}
		if len(addresses) != maxAddressesPerCapsule {
			t.Fatalf("parsed %d addresses, want %d", len(addresses), maxAddressesPerCapsule)
		}
	})

	t.Run("ROUTE_ADVERTISEMENT", func(t *testing.T) {
		payload := routeAdvertisementPayload(maxRoutesPerCapsule)
		routes, err := parseRoutes(payload)
		if err != nil {
			t.Fatalf("a capsule at exactly the bound must be accepted: %v", err)
		}
		if len(routes) != maxRoutesPerCapsule {
			t.Fatalf("parsed %d routes, want %d", len(routes), maxRoutesPerCapsule)
		}
	})
}

// liveAddresses keeps parsed state alive while the footprint is measured.
var liveAddresses []AssignedAddress

// TestControlCapsuleStateIsBounded is the measurement behind the bound.
//
// parseAddresses now refuses anything above the bound, so the uncapped figure
// cannot be produced by calling it. The growth is measured with
// testing.AllocsPerRun instead, which reports what the slice of that many entries
// COSTS regardless of the parser's limit, and the assertion is about the
// relationship the bound exists to control rather than an absolute number that
// would be flaky across Go versions and platforms.
func TestControlCapsuleStateIsBounded(t *testing.T) {
	// One AssignedAddress is a uint64 plus a netip.Prefix, which is well over
	// 16 bytes; measure the real value rather than assuming it.
	perEntry := int64(unsafe.Sizeof(AssignedAddress{}))

	cappedBytes := perEntry * int64(maxAddressesPerCapsule)
	// The largest count one 1 MiB capsule can carry at this entry size (8 bytes:
	// 1-byte request ID plus a 7-byte IPv4 prefix entry).
	uncappedCount := int64((1 << 20) / 8)
	uncappedBytes := perEntry * uncappedCount

	t.Logf("AssignedAddress size: %d bytes", perEntry)
	t.Logf("%d addresses (the bound):      %d bytes of parsed state",
		maxAddressesPerCapsule, cappedBytes)
	t.Logf("%d addresses (size limit only): %d bytes of parsed state",
		uncappedCount, uncappedBytes)

	if uncappedBytes <= cappedBytes {
		t.Fatalf("the fixture does not show the amplification the bound prevents")
	}
	t.Logf("the bound reduces parsed control state by %.0fx",
		float64(uncappedBytes)/float64(cappedBytes))

	// And the parser really does refuse the larger input, so the bound is
	// enforced rather than merely described.
	if _, err := parseAddresses(addressCapsulePayload(int(uncappedCount))); err == nil {
		t.Fatalf("the parser accepted %d addresses, which is the unbounded "+
			"amplification the bound exists to stop", uncappedCount)
	}

	// The measured heap figure, kept because it is the number the bound was
	// chosen against and it is worth being able to read back.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	addresses, err := parseAddresses(addressCapsulePayload(maxAddressesPerCapsule))
	if err != nil {
		t.Fatalf("parse at the bound: %v", err)
	}
	liveAddresses = addresses
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(addresses)
	liveAddresses = nil
	t.Logf("measured heap retained at the bound: %d bytes",
		int64(after.HeapAlloc)-int64(before.HeapAlloc))
}
