package adapter

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// Agent F, round 5: D4 - the issuance ledger's BOUNDS.
//
// The three questions the refusal's safety rests on, each measured rather than reasoned about:
//
//  1. the 1024-generation cap: what happens at 1025, and does the caller learn that a record was
//     dropped rather than never made?
//  2. the wrap: does a wrapped generation's interval set become a blanket block over its range?
//  3. the reservation: how many never-issued addresses are refused in the worst case?
//
// The interval representation is the reason a blanket block is impossible (my round-3/round-4
// measurements), so anything that widens an interval without widening what was ISSUED is the failure
// this file is looking for.

// agentFConfigured is the range every case below uses.
var agentFConfigured = netip.MustParsePrefix("198.18.0.0/15")

// TestAgentFTheGenerationCapEvictsSilently measures question 1.
func TestAgentFTheGenerationCapEvictsSilently(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()

	// One address really issued by the OLDEST generation.
	issued := netip.MustParseAddr("198.18.0.7")
	ledger.RecordIssued(1, 1, issued)
	interval, known := ledger.IssuedInterval(issued)
	require.True(t, known, "precondition: the ledger must attribute an address it recorded")
	t.Logf("MEASURED before the cap: %s refused=%v interval=%v generations=%d",
		issued, known, interval, ledger.Generations())

	// Walk past the cap. Each generation is seeded, which is what a real restart sequence does.
	for generation := 2; generation <= 1025; generation++ {
		ledger.RecordSeed(uint64(generation), generation, agentFConfigured,
			agentFConfigured.Addr().Next(), netip.Prefix{}, netip.Addr{})
	}

	afterInterval, stillKnown := ledger.IssuedInterval(issued)
	t.Logf("MEASURED after %d generations: %s refused=%v interval=%v generations=%d",
		ledger.Generations(), issued, stillKnown, afterInterval, ledger.Generations())

	require.False(t, stillKnown,
		"the cap is expected to evict the OLDEST record, so an address the process really issued "+
			"stops being attributable once 1024 newer generations exist. If this now answers true the "+
			"cap behaviour changed and this finding must be re-derived")

	// THE POINT: the answer is indistinguishable from "never issued". There is no third state in the
	// public API, and the cap itself is an unexported constant, so a caller cannot even compute
	// "saturated" without hardcoding 1024.
	neverIssued := netip.MustParseAddr("198.18.200.200")
	_, neverKnown := ledger.IssuedInterval(neverIssued)
	require.Equal(t, neverKnown, stillKnown,
		"a dropped record and a record that was never made must be reported identically for this "+
			"finding to hold; if the API grew a third state, this test should assert it instead")
	t.Logf("MEASURED: 'evicted after the cap' and 'never issued' both answer (%v, false) - the caller "+
		"cannot tell them apart", afterInterval)
}

// TestAgentFTheReservationRefusesExactlyOneWindow measures question 3's worst case.
func TestAgentFTheReservationRefusesExactlyOneWindow(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	head := agentFConfigured.Addr().Next()

	// The persisted cursor leads the true high-water mark by a whole reservation window (the store
	// writes 1024 ahead). 1023 steps past the first issuable address is the largest window a seed can
	// describe WITHOUT leaving the range, so this is the worst case the design admits.
	const window = 1024
	worst := head
	for range window - 1 {
		worst = worst.Next()
	}
	ledger.RecordSeed(1, 1, agentFConfigured, worst, netip.Prefix{}, netip.Addr{})

	// Count what is refused, by probing every address in and around the window.
	refused := 0
	for address := head; ; address = address.Next() {
		if ledger.Issued(address) {
			refused++
		}
		if address == worst.Next() {
			break
		}
	}

	t.Logf("MEASURED seed at the reservation worst case (cursor %s): %d addresses refused as "+
		"placeholders, of which at most one was ever handed out; the address one past the cursor "+
		"(%s) is reachable=%v", worst, refused, worst.Next(), !ledger.Issued(worst.Next()))

	require.Equal(t, window, refused,
		"the refused window must be exactly the reservation the store writes, no wider")
	require.False(t, ledger.Issued(worst.Next()),
		"one address past the persisted cursor must stay reachable, or the over-approximation is not "+
			"bounded by the cursor")
	require.False(t, ledger.Issued(agentFConfigured.Addr()),
		"the range's own base address is never issuable and must stay reachable")
}

// TestAgentFTheLedgerDoesNotClampAJump measures the other half of question 3: the reservation is
// bounded by what the STORE passes, not by anything the ledger enforces.
func TestAgentFTheLedgerDoesNotClampAJump(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	head := agentFConfigured.Addr().Next()
	far := head
	for range 99999 {
		far = far.Next()
	}

	ledger.RecordIssued(1, 1, head)
	ledger.RecordIssued(1, 1, far)

	interval, known := ledger.IssuedInterval(far)
	require.True(t, known)
	mid := head
	for range 50000 {
		mid = mid.Next()
	}
	midRefused := ledger.Issued(mid)
	t.Logf("MEASURED two recorded addresses %s and %s: interval=%v, an address 50000 past the first "+
		"and never issued is refused=%v", head, far, interval, midRefused)

	require.True(t, midRefused,
		"a forward jump is expected to extend the interval to the jump target, so every address "+
			"between them is refused whether or not it was issued. Bounded, but the bound lives in "+
			"the caller: the ledger itself applies no clamp, so a far-ahead cursor - a hand-edited or "+
			"corrupt cachefile, say - widens the refused set to whatever it names")

	// The invariant that keeps this from being a range block: it still stops at the jump target.
	require.False(t, ledger.Issued(far.Next()),
		"the interval must end at the jump target, not at the end of the range")
}

// TestAgentFTheWrapStaysAtMostTwoIntervals measures question 2.
//
// The FAIL condition stated for this case is a wrapped interval that spans head-to-tail, i.e. a blanket
// block over the whole range wearing the ledger's name.
func TestAgentFTheWrapStaysAtMostTwoIntervals(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	head := agentFConfigured.Addr().Next()

	// The sequence a wrapping walk produces: it starts issuing at the head, walks forward, and after a
	// wrap issues at the head again. The intermediate addresses are NOT recorded one by one, which is
	// the shape that could make the representation lie.
	ledger.RecordSeed(1, 1, agentFConfigured, head, netip.Prefix{}, netip.Addr{})
	afterSeedIntervals := ledger.Intervals()
	ledger.RecordIssued(1, 1, head)
	ledger.RecordIssued(1, 1, head.Next())

	interval, _ := ledger.IssuedInterval(head)
	intervals := ledger.Intervals()
	t.Logf("MEASURED head-seeded generation with two issued addresses: published intervals=%d "+
		"(after the bare seed=%d), interval covering %s = %v", intervals, afterSeedIntervals, head, interval)

	require.LessOrEqual(t, intervals, 2*ledger.Generations()+1,
		"a generation may contribute at most two intervals (a wrapped tail and a head); a larger "+
			"published set would mean the reproduction above is wrong")

	// THE BLANKET-BLOCK CHECK: an address far from anything recorded must stay reachable.
	require.False(t, ledger.Issued(netip.MustParseAddr("198.19.9.9")),
		"an address nowhere near the recorded walk was refused: the interval set has become a block "+
			"over the range, which is the FAIL condition for this case")
	require.False(t, ledger.Issued(netip.MustParseAddr("198.18.9.9")),
		"an address in the middle of the configured range, never issued and never walked, was refused")
}
