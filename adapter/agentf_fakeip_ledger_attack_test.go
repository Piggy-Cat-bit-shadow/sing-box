package adapter

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// Agent F, round 3: the compatibility positive the whole cross-Box refusal is conditioned on.
//
// # The invariant under attack
//
// A's design forbids a blanket block on the configured FakeIP range. The refusal may fire only for an
// address THIS PROCESS handed out, identified by the interval the ledger recorded for it. So two
// addresses must stay reachable, and if either is refused the fix has become the very thing its
// contract forbids:
//
//   - an address BEYOND the recorded interval, even inside a range the ledger knows about; and
//   - a legitimate literal in a range this process never issued from.
//
// The over-approximations are A's own, stated rather than hidden: the persisted cursor leads the true
// high-water mark by up to a reservation window (RecordSeed's doc), and `intervalUpTo` starts one
// address below the first address `Create` can hand out. This file MEASURES where the boundary
// actually falls instead of assuming it, and then asserts the two positives above.
func TestAgentFIssuedIntervalLeavesUnissuedAddressesReachable(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	configured := netip.MustParsePrefix("198.18.0.0/15")
	cursor := netip.MustParseAddr("198.18.0.5")

	// The cursor is where the store has PERSISTED to, a reservation window ahead of what it handed
	// out. That is the over-approximation RecordSeed documents.
	ledger.RecordSeed(1, 1, configured, cursor, netip.Prefix{}, netip.Addr{})

	// Measure the boundary rather than guess it.
	type probe struct {
		label   string
		address string
	}
	for _, p := range []probe{
		{"range base", "198.18.0.0"},
		{"one below the first hand-out", "198.18.0.1"},
		{"inside the cursor window", "198.18.0.3"},
		{"the cursor itself", "198.18.0.5"},
		{"FIRST beyond the cursor", "198.18.0.6"},
		{"far inside the configured range", "198.18.9.9"},
		{"the last address of the configured range", "198.19.255.255"},
	} {
		address := netip.MustParseAddr(p.address)
		interval, issued := ledger.IssuedInterval(address)
		t.Logf("MEASURED seed with cursor .5: %-34s %-16s Issued=%v interval=%v",
			p.label, address, issued, interval)
	}

	// THE FIRST COMPATIBILITY POSITIVE: beyond the recorded interval, in a range the ledger knows
	// about, must stay reachable.
	require.False(t, ledger.Issued(netip.MustParseAddr("198.18.0.6")),
		"an address one past the persisted cursor was refused: the interval is being rounded up to "+
			"the whole configured range, which is the blanket block the contract forbids")

	// THE SECOND: a legitimate destination literal in a range this process never issued from.
	for _, literal := range []string{"93.184.216.34", "1.1.1.1", "10.0.0.1", "2001:db8::1"} {
		require.False(t, ledger.Issued(netip.MustParseAddr(literal)),
			"the ordinary destination %s was reported as a placeholder this process issued; every "+
				"literal in an unrelated range must stay reachable", literal)
	}

	// And the refusal must still work for what WAS handed out - otherwise the positives above are
	// satisfied by a ledger that never refuses anything.
	ledger.RecordIssued(1, 1, netip.MustParseAddr("198.18.0.9"))
	require.True(t, ledger.Issued(netip.MustParseAddr("198.18.0.9")),
		"an address the ledger recorded as issued must be refused; without this the two positives "+
			"above are satisfied by a ledger that refuses nothing")
}

// TestAgentFRetiredRangeStillRefusesItsOwnIssuanceOnly pins the retired-generation case, which is the
// shape the fix exists for: the operator changes `inet4_range` between two Boxes.
func TestAgentFRetiredRangeStillRefusesItsOwnIssuanceOnly(t *testing.T) {
	ledger := NewFakeIPIssuanceLedger()
	retired := netip.MustParsePrefix("198.18.0.0/15")
	current := netip.MustParsePrefix("198.19.0.0/16")

	// Generation 1 issued up to .9 in the retired range; generation 2 is configured with a new one.
	ledger.RecordSeed(1, 1, retired, netip.MustParseAddr("198.18.0.9"), netip.Prefix{}, netip.Addr{})
	ledger.RecordIssued(1, 1, netip.MustParseAddr("198.18.0.9"))
	ledger.RecordSeed(2, 2, current, current.Addr().Next(), netip.Prefix{}, netip.Addr{})

	// Inside the RETIRED generation's recorded interval: still refused, which is the point of keeping
	// retired generations at all.
	require.True(t, ledger.Issued(netip.MustParseAddr("198.18.0.9")),
		"an address the retired generation really handed out must still be refused; a restart that "+
			"forgot it would let the historic placeholder escape")

	// BEYOND the retired generation's interval: reachable, even though the range is one the ledger
	// knows about.
	require.False(t, ledger.Issued(netip.MustParseAddr("198.18.10.10")),
		"an address far past the retired generation's high-water mark was refused: the retired RANGE "+
			"is being blocked rather than the retired INTERVAL, which is a blanket block")

	// A legitimate literal outside every configured range stays reachable.
	require.False(t, ledger.Issued(netip.MustParseAddr("93.184.216.34")))
}

// TestAgentFNilLedgerIsTheDocumentedBoundary pins the shape the CLI, cmd_check, libbox and every test
// harness get - the boundary route/route.go:1112-1116 states rather than hides.
//
// It must be a NO-OP that answers "not issued", not a panic and not a refusal: an absent ledger means
// there is no cross-Box memory, and guessing from the address alone is the blanket guard the contract
// forbids.
func TestAgentFNilLedgerIsTheDocumentedBoundary(t *testing.T) {
	var ledger *FakeIPIssuanceLedger

	// Every accessor is safe on the nil receiver, which is what makes "no ledger" survivable rather
	// than a nil dereference on the routing path.
	require.False(t, ledger.Issued(netip.MustParseAddr("198.18.0.2")),
		"a nil ledger must report 'not issued': that is the documented boundary for a process with no "+
			"cross-Box memory, and a true here would refuse an address nothing can attribute")
	interval, issued := ledger.IssuedInterval(netip.MustParseAddr("198.18.0.2"))
	require.False(t, issued)
	require.Zero(t, interval)
	require.Zero(t, ledger.Sequence())
	require.Zero(t, ledger.Advance())
	require.Zero(t, ledger.Intervals())
	require.Zero(t, ledger.Generations())

	// The writers are no-ops too, so a Box that somehow calls one before the owner registered a
	// ledger does not take the process down.
	ledger.RecordSeed(1, 1, netip.MustParsePrefix("198.18.0.0/15"), netip.MustParseAddr("198.18.0.1"),
		netip.Prefix{}, netip.Addr{})
	ledger.RecordIssued(1, 1, netip.MustParseAddr("198.18.0.2"))
	ledger.Clear()
	t.Logf("MEASURED: a nil ledger answers false for every read and accepts every write without " +
		"panicking; the refusal is inert, which is the documented boundary")
}
