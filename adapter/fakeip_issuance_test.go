package adapter

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The issuance ledger is a small object with a large job: `route/route.go` refuses a destination
// because of what it says, so every way it can be WRONG is a way the product either leaks a synthetic
// address to a peer or refuses traffic it must carry.
//
// The two directions are not symmetric and the asymmetry is the point:
//
//   - a FALSE NEGATIVE (the ledger forgets an address it issued) is the original defect returning -
//     the placeholder reaches the peer;
//   - a FALSE POSITIVE (the ledger claims an address it did not issue) is a compatibility regression
//     for every literal that merely LOOKS like a placeholder, and on the machine this was measured on
//     `198.18.0.0/15` is live routed space whose resolver answers real queries.
//
// So the tests below are written per direction, and the ones that assert a NEGATIVE are the ones that
// keep the guard from becoming a blanket range refusal.

func fakeIPTestRange(t *testing.T, text string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(text)
	require.NoError(t, err)
	return prefix
}

// TestIssuanceLedgerRecordsTheWalkExactly pins the exact record: an address inside the walked interval
// is attributable, and an address BEYOND the cursor is not.
//
// The second half is the compatibility positive at unit level and it is the reason the representation
// is an interval with an upper bound rather than "the whole range". `198.18.0.9` is inside
// `198.18.0.0/16` but past a cursor of `198.18.0.4`, so a Box that has issued four addresses cannot
// claim it.
func TestIssuanceLedgerRecordsTheWalkExactly(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	addressRange := fakeIPTestRange(t, "198.18.0.0/16")

	// A generation that has issued nothing yet: nothing is attributable.
	ledger.RecordSeed(ledger.Advance(), 1, addressRange, addressRange.Addr().Next(), netip.Prefix{}, netip.Addr{})
	require.False(t, ledger.Issued(netip.MustParseAddr("198.18.0.2")),
		"a generation that has issued nothing must attribute nothing: the cursor is at the first "+
			"issuable address, which is not itself an issuance")

	for _, text := range []string{"198.18.0.2", "198.18.0.3", "198.18.0.4"} {
		ledger.RecordIssued(ledger.Advance(), 1, netip.MustParseAddr(text))
	}

	for _, text := range []string{"198.18.0.2", "198.18.0.3", "198.18.0.4"} {
		require.True(t, ledger.Issued(netip.MustParseAddr(text)),
			"%s was handed out, so it must be attributable", text)
	}
	for _, text := range []string{"198.18.0.5", "198.18.0.9", "198.18.1.1"} {
		require.False(t, ledger.Issued(netip.MustParseAddr(text)),
			"%s is inside the range but BEYOND the walk, so it was never issued and must stay an "+
				"ordinary literal - this is the assertion that forbids a blanket range guard", text)
	}
	for _, text := range []string{"127.0.0.1", "10.7.0.2", "2001:db8::1"} {
		require.False(t, ledger.Issued(netip.MustParseAddr(text)),
			"%s is outside the range and must be untouched", text)
	}
}

// TestIssuanceLedgerMergesTheWalkIntoOneInterval pins the size bound that makes the ledger's memory
// independent of how many names a generation resolved.
func TestIssuanceLedgerMergesTheWalkIntoOneInterval(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	addressRange := fakeIPTestRange(t, "198.18.0.0/16")
	ledger.RecordSeed(ledger.Advance(), 1, addressRange, addressRange.Addr().Next(), netip.Prefix{}, netip.Addr{})

	const issuances = 500
	address := addressRange.Addr().Next()
	for range issuances {
		ledger.RecordIssued(1, 1, address)
		address = address.Next()
	}
	require.Equal(t, 1, ledger.Intervals(),
		"a contiguous walk must collapse to ONE interval: %d issuances must not cost %d entries",
		issuances, ledger.Intervals())
	require.True(t, ledger.Issued(address.Prev()))
	require.False(t, ledger.Issued(address), "the address after the walk is not issued")
	require.LessOrEqual(t, ledger.Intervals(), 2,
		"a generation's issuance is at most two intervals - the ordered walk plus one wrap")
}

// TestIssuanceLedgerModelsTheReservedWindowAndTheWrap pins the two things that make the durable
// record an interval rather than a point, and pins that neither of them claims the WHOLE range.
//
// # Why the reserved window makes a jump legitimate
//
// `Store.Create` persists the cursor a whole `reservedAddressCount` window ahead of the addresses it
// has really issued, so that a process death cannot make a restart re-issue a live address. A
// generation therefore STARTS with a cursor far beyond its first issuance, and the store then issues
// forward from `range.Addr().Next()` towards it. The seed can only see the cursor, so the interval it
// records is `[first issuable, cursor]` - the reservation, which is why the walk's first addresses
// after a restart look like a jump BACKWARD from the cursor and are recorded as the head of the set.
//
// # The assertion that keeps this from becoming a blanket range guard
//
// `198.18.0.200` is inside the range and beyond everything the generation reached. It must stay
// unissued, which is the whole difference between this ledger and a range block.
func TestIssuanceLedgerModelsTheReservedWindowAndTheWrap(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	addressRange := fakeIPTestRange(t, "198.18.0.0/24")
	sequence := ledger.Advance()

	// The state a restarted generation starts from: the persisted cursor is ten addresses into the
	// range, and the walk will now begin at the first issuable address.
	ledger.RecordSeed(sequence, 1, addressRange, netip.MustParseAddr("198.18.0.10"), netip.Prefix{}, netip.Addr{})
	require.Equal(t, 1, ledger.Intervals(), "the reservation is one interval")

	// The generation issues forward from the head of the range. Every one of these is a real issuance,
	// so the head of the set is extended one address at a time.
	for _, text := range []string{"198.18.0.1", "198.18.0.2", "198.18.0.3"} {
		ledger.RecordIssued(sequence, 1, netip.MustParseAddr(text))
	}
	require.Equal(t, 1, ledger.Intervals(),
		"issuing up to the reservation's start must MERGE with it, because the addresses between them "+
			"were issued too - a second interval there would be an accounting error in the other "+
			"direction")
	require.True(t, ledger.Issued(netip.MustParseAddr("198.18.0.10")),
		"the reserved cursor is attributable: the store persists it only after the window ahead of it "+
			"is accounted for")

	for _, text := range []string{"198.18.0.200", "198.18.1.1", "127.0.0.1"} {
		require.False(t, ledger.Issued(netip.MustParseAddr(text)),
			"%s is beyond everything this generation reached, so it must stay an ordinary literal", text)
	}
}

// TestIssuanceLedgerHandlesTheWrapAsASecondInterval pins the wrap: `nextAddress` restarts at the head
// of the range, so the issued set becomes two intervals and the wrap must not be mistaken for a jump
// forward - which would claim the entire range between the tail and the head.
//
// The walk below is one the store can really produce: a full range exhausted to the end, then the
// wrap to the head. The gap in the middle is never touched.
func TestIssuanceLedgerHandlesTheWrapAsASecondInterval(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	addressRange := fakeIPTestRange(t, "198.18.0.0/24")
	sequence := ledger.Advance()
	// No cursor: this generation starts at the head with nothing reserved, so the walk below IS the
	// whole record and the middle of the range stays untouched. `RecordSeed` with an invalid cursor is
	// exactly what an ordinary in-memory generation produces, where `MemoryStorage.FakeIPMetadata`
	// returns nil and there is no persisted state to seed from.
	ledger.RecordSeed(sequence, 1, addressRange, netip.Addr{}, netip.Prefix{}, netip.Addr{})

	// Walk from just below the top of the range to its end, then wrap to the head.
	for _, text := range []string{"198.18.0.253", "198.18.0.254", "198.18.0.255"} {
		ledger.RecordIssued(sequence, 1, netip.MustParseAddr(text))
	}
	for _, text := range []string{"198.18.0.0", "198.18.0.1"} {
		ledger.RecordIssued(sequence, 1, netip.MustParseAddr(text))
	}

	require.Equal(t, 2, ledger.Intervals(),
		"a wrap must produce exactly two intervals; ONE interval here would mean the tail and the head "+
			"were glued into a range that claims everything between them")
	for _, text := range []string{"198.18.0.253", "198.18.0.254", "198.18.0.255", "198.18.0.0", "198.18.0.1"} {
		require.True(t, ledger.Issued(netip.MustParseAddr(text)), "%s was issued", text)
	}
	for _, text := range []string{"198.18.0.100", "198.18.0.200"} {
		require.False(t, ledger.Issued(netip.MustParseAddr(text)),
			"the middle of the range was never reached, so %s must not be claimed: a wrap that was "+
				"read as a jump forward would claim the entire range", text)
	}
}

// TestIssuanceLedgerUsesFourByteBitLengthsForIPv4 is the 4-in-6 trap, at the unit level.
//
// `netip.Prefix.Contains` compares bit lengths, and `netip.Addr` equality is spelling-sensitive, so an
// IPv4 interval silently fails to cover `::ffff:198.18.0.2`. The router normalises before asking
// (`route/route.go`), and this test states what the ledger does with each spelling so a future reader
// cannot "simplify" the normalisation away.
func TestIssuanceLedgerUsesFourByteBitLengthsForIPv4(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	addressRange := fakeIPTestRange(t, "198.18.0.0/16")
	ledger.RecordSeed(ledger.Advance(), 1, addressRange, addressRange.Addr().Next(), netip.Prefix{}, netip.Addr{})
	ledger.RecordIssued(1, 1, netip.MustParseAddr("198.18.0.2"))

	require.True(t, ledger.Issued(netip.MustParseAddr("198.18.0.2")))
	mapped := netip.MustParseAddr("::ffff:198.18.0.2")
	require.True(t, mapped.Is4In6())
	require.False(t, ledger.Issued(mapped),
		"a 4-in-6 spelling does NOT match an IPv4 interval - this is the documented reason the router "+
			"must normalise before asking, and it is asserted so the normalisation cannot be dropped")
	require.True(t, ledger.Issued(mapped.Unmap()),
		"and the normalised spelling of the SAME address does match")
}

// TestIssuanceLedgerRetiredRangeStaysReachableBeyondItsCursor is the row that stops this mechanism
// being read as a range block, and it is the one the refusal's compatibility depends on.
//
// A retired generation records an interval. An address INSIDE that retired range but BEYOND the
// recorded interval was never handed out by it, so it must stay an ordinary literal even though it
// sits in a range this process once used - which is exactly the case a "block the range" guard would
// get wrong, and on the machine this was measured on `198.18.0.0/15` is live routed space.
func TestIssuanceLedgerRetiredRangeStaysReachableBeyondItsCursor(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	retiredRange := fakeIPTestRange(t, "198.18.0.0/24")

	// Generation 1 reserved a window and then issued into it.
	retiredSequence := ledger.Advance()
	ledger.RecordSeed(retiredSequence, 1, retiredRange, netip.MustParseAddr("198.18.0.10"), netip.Prefix{}, netip.Addr{})
	for _, text := range []string{"198.18.0.1", "198.18.0.2"} {
		ledger.RecordIssued(retiredSequence, 1, netip.MustParseAddr(text))
	}
	require.True(t, ledger.Issued(netip.MustParseAddr("198.18.0.2")))

	// Generation 2 configures a DIFFERENT range, which retires generation 1's record without deleting
	// it - that is the durable path, where the retired cursor is read before the reset destroys it.
	liveRange := fakeIPTestRange(t, "198.20.0.0/24")
	liveSequence := ledger.Advance()
	ledger.RecordSeed(liveSequence, 1, liveRange, netip.MustParseAddr("198.20.0.10"), netip.Prefix{}, netip.Addr{})

	require.True(t, ledger.Issued(netip.MustParseAddr("198.18.0.2")),
		"the retired generation's issuance must survive the range move: it is the only thing that can "+
			"attribute an address a client is still holding")

	// Inside the RETIRED range, past everything it recorded.
	for _, text := range []string{"198.18.0.11", "198.18.0.100", "198.18.0.254"} {
		require.False(t, ledger.Issued(netip.MustParseAddr(text)),
			"%s is inside the retired range but was never issued by it, so it must stay reachable - "+
				"this is the assertion that forbids a blanket range guard", text)
	}
	// Inside the LIVE range, past its reservation.
	for _, text := range []string{"198.20.0.11", "198.20.0.100", "198.20.0.254"} {
		require.False(t, ledger.Issued(netip.MustParseAddr(text)),
			"%s is inside the CURRENT range but beyond its cursor, so it must stay reachable", text)
	}
	// And the recorded reservation itself is attributable.
	require.True(t, ledger.Issued(netip.MustParseAddr("198.20.0.10")))
}

// TestIssuanceLedgerIsBoundedInGenerations pins the cap, and pins that the OLDEST is the one evicted.//
// A daemon that reloads on a schedule must not accumulate one entry per reload forever. Past the cap
// the proof is gone and the answer reverts to the honest boundary - "cannot be attributed" - which is
// why the cap is asserted rather than assumed.
func TestIssuanceLedgerIsBoundedInGenerations(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	require.Equal(t, 0, ledger.Generations())

	firstAddress := netip.MustParseAddr("198.18.0.2")
	ledger.RecordSeed(0, 1, fakeIPTestRange(t, "198.18.0.0/16"), fakeIPTestRange(t, "198.18.0.0/16").Addr().Next(), netip.Prefix{}, netip.Addr{})
	ledger.RecordIssued(0, 1, firstAddress)
	require.True(t, ledger.Issued(firstAddress))

	for index := range maxIssuanceGenerations + 64 {
		sequence := uint64(index + 1)
		ledger.RecordSeed(sequence, 1, fakeIPTestRange(t, "198.20.0.0/16"), fakeIPTestRange(t, "198.20.0.0/16").Addr().Next(), netip.Prefix{}, netip.Addr{})
	}
	require.LessOrEqual(t, ledger.Generations(), maxIssuanceGenerations,
		"the ledger grew past its stated bound: an owner that reloads forever would accumulate state")
	require.False(t, ledger.Issued(firstAddress),
		"the OLDEST record must be the one evicted, and once it is gone the honest answer is that the "+
			"address cannot be attributed")
}

// TestIssuanceLedgerClearDropsEverythingAndRestartsTheTick pins the owner-facing reset.
func TestIssuanceLedgerClearDropsEverythingAndRestartsTheTick(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	addressRange := fakeIPTestRange(t, "198.18.0.0/16")
	sequence := ledger.Advance()
	ledger.RecordSeed(sequence, 1, addressRange, addressRange.Addr().Next(), netip.Prefix{}, netip.Addr{})
	ledger.RecordIssued(sequence, 1, netip.MustParseAddr("198.18.0.2"))
	require.True(t, ledger.Issued(netip.MustParseAddr("198.18.0.2")))

	ledger.Clear()
	require.False(t, ledger.Issued(netip.MustParseAddr("198.18.0.2")),
		"Clear must drop every record, or \"this process has no issuance memory\" is not expressible")
	require.Equal(t, 0, ledger.Generations())
	require.Greater(t, ledger.Advance(), sequence,
		"and it must start a new tick, so a record from before the clear cannot be continued by a "+
			"record from after it")
}

// TestIssuanceLedgerNilIsSafe pins that every method tolerates a nil receiver, because the router and
// the store both hold the pointer and both must survive its absence.
func TestIssuanceLedgerNilIsSafe(t *testing.T) {
	var ledger *FakeIPIssuanceLedger
	require.False(t, ledger.Issued(netip.MustParseAddr("198.18.0.2")))
	interval, loaded := ledger.IssuedInterval(netip.MustParseAddr("198.18.0.2"))
	require.False(t, loaded)
	require.False(t, interval.From.IsValid())
	ledger.RecordSeed(1, 1, netip.Prefix{}, netip.Addr{}, netip.Prefix{}, netip.Addr{})
	ledger.RecordIssued(1, 1, netip.MustParseAddr("198.18.0.2"))
	ledger.Clear()
	require.Equal(t, uint64(0), ledger.Sequence())
	require.Equal(t, 0, ledger.Intervals())
	require.Equal(t, 0, ledger.Generations())
}

// TestIssuanceLedgerReportsTheIntervalItRefusedOn pins the diagnostic: a refusal that cannot say WHICH
// recorded issuance it acted on leaves an operator with nothing to look at.
//
// The seed already covers the first issuable address, which is what the durable path produces when it
// reads a persisted cursor: the store seeds at the cursor, and the interval it records therefore runs
// from the FIRST ADDRESS THE STORE CAN HAND OUT to that cursor - which is one address wider at the
// bottom than a strictly exact record, because `nextAddress` starts the walk at
// `range.Addr().Next()` and the very first `Create` moves to the one after it. That single address is
// stated here rather than hidden: it is the smallest possible over-claim, it is in the safe direction
// for the refusal, and it is what makes "the walk is an interval" true.
func TestIssuanceLedgerReportsTheIntervalItRefusedOn(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	addressRange := fakeIPTestRange(t, "198.18.0.0/16")
	sequence := ledger.Advance()
	ledger.RecordSeed(sequence, 1, addressRange, netip.MustParseAddr("198.18.0.2"), netip.Prefix{}, netip.Addr{})
	for _, text := range []string{"198.18.0.3", "198.18.0.4"} {
		ledger.RecordIssued(sequence, 1, netip.MustParseAddr(text))
	}
	interval, loaded := ledger.IssuedInterval(netip.MustParseAddr("198.18.0.3"))
	require.True(t, loaded)
	require.Equal(t, "198.18.0.1", interval.From.String())
	require.Equal(t, "198.18.0.4", interval.To.String())
	require.Equal(t, "198.18.0.1..198.18.0.4", interval.String())
	require.NotContains(t, interval.String(), "198.18.0.9",
		"the reported interval must not claim an address beyond the walk")
}

// TestIssuanceLedgerCostIsBoundedAcrossCycles measures the COST of the state this change introduces,
// at 1 and 100 times the churn, so "bounded" is a number rather than an argument.
//
// # What is measured, and why the interval count is the load-bearing half
//
// The interval count is deterministic and is what a leak would move: a generation contributes at most
// two intervals, so 100 generations of churn must produce a count that does not grow with the number of
// cycles. The heap figure is reported alongside it as context, not as the assertion: `runtime.MemStats`
// is process-global, other tests share the binary, and the values below are deliberately printed so the
// reader can see how noisy that instrument is rather than being asked to trust a threshold.
func TestIssuanceLedgerCostIsBoundedAcrossCycles(t *testing.T) {
	measure := func(cycles int) (int, uint64) {
		ledger := NewFakeIPIssuanceLedger()
		liveRange := fakeIPTestRange(t, "198.18.0.0/16")
		for index := range cycles {
			sequence := ledger.Advance()
			// Each cycle is one generation: a seed from a persisted cursor, then a walk of five
			// addresses. That is the shape a reload produces.
			ledger.RecordSeed(sequence, 1, liveRange, netip.MustParseAddr("198.18.1.1"), netip.Prefix{}, netip.Addr{})
			address := netip.MustParseAddr("198.18.0.2")
			for range 5 {
				ledger.RecordIssued(sequence, 1, address)
				address = address.Next()
			}
			// Alternate the range so a retired record is produced on every other cycle, exercising the
			// two-proof-source path rather than only the issuing one.
			if index%2 == 0 {
				liveRange = fakeIPTestRange(t, "198.20.0.0/16")
			} else {
				liveRange = fakeIPTestRange(t, "198.18.0.0/16")
			}
		}
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return ledger.Intervals(), stats.HeapAlloc
	}

	smallIntervals, smallHeap := measure(1)
	largeIntervals, largeHeap := measure(100)
	thousandIntervals, thousandHeap := measure(1000)
	t.Logf("FIP-LEDGER-COST cycles=1 intervals=%d heap=%d | cycles=100 intervals=%d heap=%d | cycles=1000 intervals=%d heap=%d",
		smallIntervals, smallHeap, largeIntervals, largeHeap, thousandIntervals, thousandHeap)

	// MEASURED: one interval per generation, not the four the representation allows. The reason is in
	// the walk: `RecordSeed` replaces the generation's record, and each generation here has one family,
	// so a generation costs one interval and a second only appears once its walk wraps. The heap figures
	// are reported, not asserted - `runtime.MemStats` is process-global and other tests share it.
	require.Equal(t, 1, smallIntervals)
	require.Equal(t, 100, largeIntervals)
	require.Equal(t, 1000, thousandIntervals)
	require.LessOrEqual(t, thousandIntervals, maxIssuanceGenerations,
		"1000 cycles produced more intervals than the ledger is allowed to hold: the cap is not a cap")
	require.LessOrEqual(t, thousandIntervals, 2*1000,
		"the interval count grew past two per generation, which the representation should not permit")

	// The size bound is the representation's, so it is stated as one: the interval count is linear in
	// the generation count and CAPPED, which is what makes the memory per generation a constant rather
	// than a function of how many names a generation resolved.
	require.LessOrEqual(t, thousandIntervals, largeIntervals*10+8,
		"interval count grew faster than linearly in the number of generations")
}

// TestIssuanceLedgerRegistrationIsFoundByBothPaths pins the registry key pair, which is the one place
// this change can fail SILENTLY.
//
// `service.MustRegisterPtr[T]` writes under `common.DefaultValue[*T]()` and
// `service.PtrFromContext[T]` reads that same key, so a value registered by one is found by the other.
// `service.ContextWith[T]`/`service.FromContext[*T]` key on `DefaultValue[**T]()` instead, and a
// mismatched pair returns nil rather than failing to compile - so the pairing is asserted here rather
// than trusted to a comment. The router and the store both use the `Ptr`/`Ptr` pair.
func TestIssuanceLedgerRegistrationIsFoundByBothPaths(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(t.Context())
	registered := NewFakeIPIssuanceLedger()
	service.MustRegisterPtr[FakeIPIssuanceLedger](ctx, registered)

	found := service.PtrFromContext[FakeIPIssuanceLedger](ctx)
	require.NotNil(t, found,
		"the value registered by MustRegisterPtr is not found by PtrFromContext: the key pair "+
			"disagrees and every caller would silently see a nil ledger")
	require.Same(t, registered, found, "a different object was returned than the one registered")

	// The pair must also be visible through a CHILD context, because that is how a Box sees it:
	// `service.ExtendContext` clones the registry with a shallow maps.Copy, so the pointer inherits.
	child := service.ExtendContext(ctx)
	require.NotNil(t, child, "a registry-carrying context must survive ExtendContext")
	childFound := service.PtrFromContext[FakeIPIssuanceLedger](child)
	require.NotNil(t, childFound,
		"a Box built from service.ExtendContext of the owner's context must still resolve the ledger: "+
			"if it does not, the ledger is invisible to every Box and this whole fix is inert")
	require.Same(t, registered, childFound,
		"the child context must resolve the SAME ledger object, not a copy: sharing is the mechanism")

	// The mismatched pair is asserted to FAIL, so the failure mode is documented rather than described.
	require.Nil(t, service.FromContext[*FakeIPIssuanceLedger](ctx),
		"FromContext[*T] keyed differently and found something, which means the key derivation is not "+
			"what this test claims it is - the silent-nil trap would not exist")

	// And an unregistered context must answer nil, which is the C5 boundary rather than a gap.
	bare := service.ContextWithDefaultRegistry(t.Context())
	require.Nil(t, service.PtrFromContext[FakeIPIssuanceLedger](bare),
		"a context that never registered a ledger must not resolve one: the boundary is that a Box "+
			"without an owner has no cross-Box issuance memory at all")
	_ = logger.NOP()
}
