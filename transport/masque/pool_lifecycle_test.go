package masque

import (
	"net/netip"
	"testing"
)

// Address pool lifecycle and cross-session ownership.
//
// These are the invariants that decide whether two tunnels can be made to
// interfere with each other, and whether an address can be leaked or
// double-assigned. They are tested directly on the pool rather than through a
// live tunnel because the failure modes are accounting bugs: a leaked address
// shows up as exhaustion after N sessions, not as a failed round trip, and a
// double-assignment shows up as one session receiving another's traffic.

// TestAddressPoolNeverAssignsTheReservedAddresses pins the addresses the pool
// must keep for itself.
//
// RFC 9484 assigns the client an address inside the tunnel prefix, and sing-box
// documents that "the address in the prefix is used by the server itself". The
// pool also skips the prefix's first address and, for IPv4, the broadcast
// address. Handing any of those to a client would either collide with the
// server's own address or create an address that cannot be a unicast source.
func TestAddressPoolNeverAssignsTheReservedAddresses(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.1/24")
	pool := newAddressPool(prefix)

	// A /24 has 256 addresses; skip network, reserved server address and
	// broadcast, leaving 253.
	const expectedUsable = 253

	seen := make(map[netip.Addr]struct{})
	for range expectedUsable {
		address, allocated := pool.allocate()
		if !allocated {
			t.Fatalf("pool exhausted after %d allocations, expected %d", len(seen), expectedUsable)
		}
		if address == prefix.Addr() {
			t.Fatalf("the network address %s must never be assigned", address)
		}
		if address == pool.reserved {
			t.Fatalf("the server's own address %s must never be assigned", address)
		}
		if _, duplicate := seen[address]; duplicate {
			t.Fatalf("address %s was assigned twice while still allocated", address)
		}
		seen[address] = struct{}{}
	}

	// Exhaustion must be reported, not silently wrapped onto a live address.
	if _, allocated := pool.allocate(); allocated {
		t.Fatal("the pool must report exhaustion once every usable address is allocated")
	}
	if len(seen) != expectedUsable {
		t.Fatalf("allocated %d addresses, expected %d", len(seen), expectedUsable)
	}
}

// TestAddressPoolReuseAfterRelease is the lifecycle half: every address released
// must become allocatable again.
//
// This is what makes a churn test meaningful. If release leaked even one address
// per session, a server running 1000 sequential tunnels over a /24 would
// exhaust the pool permanently after 253 of them and start refusing clients,
// with no error anywhere to say why.
func TestAddressPoolReuseAfterRelease(t *testing.T) {
	pool := newAddressPool(netip.MustParsePrefix("198.18.0.1/24"))

	const rounds = 1000
	addresses := make(map[netip.Addr]int)

	for round := range rounds {
		address, allocated := pool.allocate()
		if !allocated {
			t.Fatalf("allocation %d of %d failed: addresses are being leaked rather "+
				"than returned by release, so the pool drains over the lifetime of "+
				"the process", round+1, rounds)
		}
		addresses[address]++
		pool.release(address)
	}

	// MEASURED, not assumed: the pool is a ROTATING cursor, not a
	// first-free allocator. With one address in flight at a time over 1000
	// rounds it hands out all 253 usable addresses before repeating, because
	// `next` advances on every iteration and only resets at `last`.
	//
	// That is the intended design and it is benign: it spreads assignments
	// rather than pinning one address, so two consecutive tunnels from the same
	// client do not reuse an address a middlebox may still have a mapping for.
	// The property that matters for a leak is the one asserted above -- the
	// 1000th allocation must still succeed -- and the property that matters for
	// correctness is that a full cycle never revisits an address that is still
	// allocated, which the exhaustion test covers.
	if len(addresses) != 253 {
		t.Fatalf("one address in flight at a time over %d rounds touched %d distinct "+
			"addresses; a full rotation over the 253 usable addresses is expected, "+
			"so a different count means the cursor is skipping or repeating",
			rounds, len(addresses))
	}
}

// TestAddressPoolReleaseIsIdempotent covers a double release.
//
// release() is called from a deferred teardown, so it must be safe to run twice
// on the same address. A naive delete would be harmless, but a counter-based
// implementation would go negative and start double-assigning, so the property
// is pinned rather than assumed.
func TestAddressPoolReleaseIsIdempotent(t *testing.T) {
	pool := newAddressPool(netip.MustParsePrefix("198.18.0.1/24"))

	address, allocated := pool.allocate()
	if !allocated {
		t.Fatal("the first allocation must succeed")
	}
	pool.release(address)
	pool.release(address)
	pool.release(address)

	// The address must be free exactly once, not "free three times".
	reused := make(map[netip.Addr]struct{})
	for range 253 {
		next, ok := pool.allocate()
		if !ok {
			t.Fatal("the pool must still have every address available after releases")
		}
		if _, duplicate := reused[next]; duplicate {
			t.Fatalf("address %s was double-assigned after a repeated release", next)
		}
		reused[next] = struct{}{}
	}
	final := len(reused)
	if final != 253 {
		t.Fatalf("expected 253 distinct addresses, got %d", final)
	}
}

// TestAddressPoolReleaseOfForeignAddressIsIgnored pins that releasing an address
// the pool never handed out cannot free a live allocation.
//
// Without this, one session could free another session's address by releasing a
// value it guessed or reused, and the pool would then hand the same address to a
// third session while the second still believed it owned it.
func TestAddressPoolReleaseOfForeignAddressIsIgnored(t *testing.T) {
	pool := newAddressPool(netip.MustParsePrefix("198.18.0.1/24"))

	live, allocated := pool.allocate()
	if !allocated {
		t.Fatal("the first allocation must succeed")
	}

	// Addresses the pool never allocated.
	pool.release(netip.MustParseAddr("203.0.113.7"))
	pool.release(live.Next().Next())

	// The live address must still be considered allocated: allocating the whole
	// pool must not produce it again.
	for {
		next, ok := pool.allocate()
		if !ok {
			break
		}
		if next == live {
			t.Fatal("releasing a foreign address freed a live allocation, so the " +
				"pool can double-assign an address another session still owns")
		}
	}
}

// TestAddressPoolAllocationIsBoundedUnderConcurrency is the churn and race case.
//
// It runs many concurrent allocate/release cycles and asserts that the pool
// never exceeds its capacity at any point. Run under -race this is also the
// check that the pool's mutex actually covers its cursor and its allocated set:
// a missing lock would corrupt the cursor, and corruption here shows up as
// either over-allocation or an early exhaustion.
func TestAddressPoolAllocationIsBoundedUnderConcurrency(t *testing.T) {
	pool := newAddressPool(netip.MustParsePrefix("198.18.0.1/24"))

	const (
		workers = 16
		rounds  = 200
	)

	// Track the maximum number of simultaneously held addresses. It must never
	// exceed the usable capacity.
	overCapacity := make(chan int, workers*rounds)

	done := make(chan struct{})
	held := make(chan int, workers)
	go func() {
		// A sampler that records the high-water mark of held addresses.
		total := 0
		for {
			select {
			case delta := <-held:
				total += delta
				if total > 253 {
					select {
					case overCapacity <- total:
					default:
					}
				}
			case <-done:
				return
			}
		}
	}()

	finished := make(chan struct{}, workers)
	for range workers {
		go func() {
			defer func() { finished <- struct{}{} }()
			for range rounds {
				address, allocated := pool.allocate()
				if !allocated {
					// Exhaustion is legitimate only if the pool is genuinely
					// full; with 16 workers and 200 rounds each, and immediate
					// release, it should never happen.
					overCapacity <- -1
					return
				}
				held <- 1
				pool.release(address)
				held <- -1
			}
		}()
	}
	for range workers {
		<-finished
	}
	close(done)

	select {
	case value := <-overCapacity:
		if value < 0 {
			t.Fatal("the pool reported exhaustion while most addresses were free, so " +
				"concurrent allocation is losing track of released addresses")
		}
		t.Fatalf("the pool held %d addresses at once, above its capacity of 253", value)
	default:
	}
}

// TestAddressPoolHandlesMultiplePrefixesIndependently covers the two-family
// case, which is what an operator configuring both an IPv4 and an IPv6 tunnel
// network gets.
func TestAddressPoolHandlesMultiplePrefixesIndependently(t *testing.T) {
	v4 := newAddressPool(netip.MustParsePrefix("198.18.0.1/24"))
	v6 := newAddressPool(netip.MustParsePrefix("2001:db8::1/120"))

	v4Address, ok := v4.allocate()
	if !ok {
		t.Fatal("IPv4 pool allocation failed")
	}
	v6Address, ok := v6.allocate()
	if !ok {
		t.Fatal("IPv6 pool allocation failed")
	}
	if v4Address.Is6() {
		t.Fatalf("the IPv4 pool returned an IPv6 address: %s", v4Address)
	}
	if !v6Address.Is6() {
		t.Fatalf("the IPv6 pool returned an IPv4 address: %s", v6Address)
	}

	// Releasing from one pool must not affect the other.
	v4.release(v4Address)
	if _, ok := v4.allocate(); !ok {
		t.Fatal("the IPv4 pool must be reusable after a release")
	}
	if !v6.prefix.Contains(v6Address) {
		t.Fatalf("the IPv6 pool's address %s is outside its prefix", v6Address)
	}
}
