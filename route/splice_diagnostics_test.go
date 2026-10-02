package route

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for the splice diagnostics.
//
// The point of these counters is to let a real-device run answer "how many UDP
// sessions spliced, how many fell back, and where". Two things therefore have to be
// true and are asserted here: the counters record what actually happened, and
// adding them did not change any splice decision.

func TestSpliceDiagnostics_EmptySnapshot(t *testing.T) {
	var d spliceDiagnostics
	if got := d.total(); got != 0 {
		t.Fatalf("a fresh diagnostics set must be empty, got %d", got)
	}
	if snap := d.snapshot(); len(snap) != 0 {
		t.Fatalf("a fresh snapshot must be empty, got %v", snap)
	}
}

func TestSpliceDiagnostics_RecordsEachReason(t *testing.T) {
	var d spliceDiagnostics
	d.recordOutcome(spliceReasonSuccess)
	d.recordOutcome(spliceReasonSuccess)
	d.recordOutcome(spliceReasonSourceNotReplaceable)

	// Success is reported through successes(), NOT through the reason table. Listing it in
	// both places would double-count every spliced session and break the
	// Attempts == Successes + sum(Reasons) invariant the device report relies on.
	if _, present := d.snapshot()["success"]; present {
		t.Error("success must not appear in the reason table; it has its own accessor")
	}
	if d.successes() != 2 {
		t.Errorf("successes: want 2, got %d", d.successes())
	}
	if got := d.snapshot()["source_not_replaceable"]; got != 1 {
		t.Errorf("source_not_replaceable: want 1, got %d", got)
	}
	if d.total() != 3 {
		t.Errorf("total: want 3, got %d", d.total())
	}
}

func TestSpliceDiagnostics_ZeroReasonsAreOmitted(t *testing.T) {
	// A snapshot reports only what happened, so an absent key means "never seen"
	// rather than "seen zero times" - which keeps on-device output readable.
	var d spliceDiagnostics
	d.recordOutcome(spliceReasonTargetNoUpstream)
	snap := d.snapshot()
	if _, present := snap["success"]; present {
		t.Error("a reason that never occurred must not appear in the snapshot")
	}
	if len(snap) != 1 {
		t.Errorf("want exactly one reported reason, got %d", len(snap))
	}
}

func TestSpliceDiagnostics_OutOfRangeReasonIsIgnored(t *testing.T) {
	// Bounds check: a future reason added without widening spliceReasonCount must
	// not write out of bounds.
	var d spliceDiagnostics
	d.recordOutcome(spliceReason(200))
	if d.total() != 0 {
		t.Fatalf("an out-of-range reason must not be recorded, total=%d", d.total())
	}
}

func TestSpliceReason_StringsAreDistinct(t *testing.T) {
	// Every reason must have its own name; two reasons sharing one string would make
	// an on-device report ambiguous.
	seen := make(map[string]spliceReason, spliceReasonCount)
	for i := 0; i < spliceReasonCount; i++ {
		r := spliceReason(i)
		name := r.String()
		if name == "unknown" {
			t.Errorf("reason %d has no name", i)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("reasons %d and %d share the name %q", prev, i, name)
		}
		seen[name] = r
	}
	if got := spliceReason(200).String(); got != "unknown" {
		t.Errorf("out-of-range reason: want %q, got %q", "unknown", got)
	}
}

func TestSpliceSnapshot_Ratio(t *testing.T) {
	cases := []struct {
		name      string
		attempts  uint64
		successes uint64
		want      float64
	}{
		{"no attempts is zero rather than NaN", 0, 0, 0},
		{"all spliced", 10, 10, 1},
		{"none spliced", 10, 0, 0},
		{"half spliced", 10, 5, 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := SpliceSnapshot{Attempts: tc.attempts, Successes: tc.successes}
			if got := snap.Ratio(); got != tc.want {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestSameConn(t *testing.T) {
	// sameConn replaced a direct `any(a) != any(b)` comparison, which panics when a
	// dynamic type is not comparable. The panic would happen inside the splice
	// decision, so this guard matters.
	a := &socketConn{}
	b := &socketConn{}

	if !sameConn(a, a) {
		t.Error("an identical value must compare equal")
	}
	if sameConn(a, b) {
		t.Error("different pointers must not compare equal")
	}
	if !sameConn(nil, nil) {
		t.Error("two nils must compare equal")
	}
	if sameConn(a, nil) {
		t.Error("a value and nil must not compare equal")
	}
	// A slice is not comparable; the direct form would panic here.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("sameConn must not panic on an uncomparable type: %v", r)
			}
		}()
		if sameConn([]int{1}, []int{1}) {
			t.Error("distinct uncomparable values must not compare equal")
		}
	}()
}

// --- one outcome per session (§19) ----------------------------------------------

func TestSpliceDiagnostics_AttemptsInvariantHolds(t *testing.T) {
	// Attempts == Successes + sum(Reasons), by construction. This is the property that
	// makes a device report self-consistent: if a session could write two counters, or
	// none, the totals would drift and a ratio computed from them would be meaningless.
	var d spliceDiagnostics
	d.recordOutcome(spliceReasonSuccess)
	d.recordOutcome(spliceReasonSuccess)
	d.recordOutcome(spliceReasonSuccess)
	d.recordOutcome(spliceReasonSourceNotNAT)
	d.recordOutcome(spliceReasonSpliceRejected)
	d.recordOutcome(spliceReasonTargetNoUpstream)

	snapshot := SpliceSnapshot{
		Attempts:  d.total(),
		Successes: d.successes(),
		Reasons:   d.snapshot(),
	}

	require.EqualValues(t, 6, snapshot.Attempts)
	require.EqualValues(t, 3, snapshot.Successes)

	var reasonSum uint64
	for _, count := range snapshot.Reasons {
		reasonSum += count
	}
	// Reasons excludes success, so success plus reasons is the whole population.
	require.EqualValues(t, snapshot.Attempts, snapshot.Successes+reasonSum,
		"every session must contribute to exactly one bucket")

	// And success must not appear in the reason table, or it would be counted twice.
	_, successInReasons := snapshot.Reasons["success"]
	require.False(t, successInReasons, "success must not also be listed as a reason")
}

func TestSpliceDiagnostics_OutcomeCountsOneBucketOnly(t *testing.T) {
	// A single session must move exactly one counter.
	var d spliceDiagnostics
	d.recordOutcome(spliceReasonTargetNotReplaceable)

	require.EqualValues(t, 1, d.total())
	require.EqualValues(t, 0, d.successes())
	require.Len(t, d.snapshot(), 1)
}

// --- the device-readable summary (§20) ------------------------------------------

func TestSpliceSnapshot_SummaryFormatIsStable(t *testing.T) {
	snapshot := SpliceSnapshot{
		Attempts:  123,
		Successes: 100,
		Reasons: map[string]uint64{
			"source_not_replaceable": 5,
			"splice_rejected":        18,
		},
	}

	got := snapshot.SpliceSummary()
	require.Equal(t,
		"UDP splice diagnostics: attempts=123 successes=100 ratio=0.813 source_not_replaceable=5 splice_rejected=18",
		got)
}

func TestSpliceSnapshot_SummaryReasonOrderIsDeterministic(t *testing.T) {
	// The reason order must come from the enum, not from map iteration. A rotating order
	// would make two device logs hard to compare by eye or by diff, which is the only
	// thing this line is for.
	snapshot := SpliceSnapshot{
		Attempts:  3,
		Successes: 0,
		Reasons: map[string]uint64{
			"source_not_nat":     1,
			"target_no_upstream": 1,
			"splice_rejected":    1,
		},
	}

	first := snapshot.SpliceSummary()
	for i := 0; i < 50; i++ {
		require.Equal(t, first, snapshot.SpliceSummary(),
			"the summary must render identically every time")
	}
}

func TestSpliceSnapshot_SummaryOmitsZeroReasons(t *testing.T) {
	snapshot := SpliceSnapshot{Attempts: 2, Successes: 2, Reasons: map[string]uint64{}}
	require.Equal(t,
		"UDP splice diagnostics: attempts=2 successes=2 ratio=1.000",
		snapshot.SpliceSummary())
}

// --- sameConn without a recover-driven control flow (§21) -----------------------

func TestSameConn_UncomparableTypesDoNotPanic(t *testing.T) {
	// The previous implementation recovered from the panic that == raises on an
	// uncomparable dynamic type. Using a panic for ordinary control flow is expensive and
	// hides the intent; the answer here is simply that two distinct uncomparable values are
	// not the same connection.
	require.NotPanics(t, func() {
		require.False(t, sameConn([]int{1}, []int{1}))
		require.False(t, sameConn(map[string]int{"a": 1}, map[string]int{"a": 1}))
	})

	// Comparable values must still behave exactly as == would.
	shared := &socketConn{}
	require.True(t, sameConn(shared, shared), "the same pointer is the same connection")
	require.False(t, sameConn(&socketConn{}, &socketConn{}), "distinct pointers differ")
	require.True(t, sameConn(nil, nil))
	require.False(t, sameConn(shared, nil))
	require.False(t, sameConn(nil, shared))

	// Different types are never the same connection, even when both are nil-able.
	require.False(t, sameConn(&socketConn{}, 42))
}

func TestSameConn_ComparableStructs(t *testing.T) {
	// An interface holding a comparable but non-pointer type must compare by value, which
	// is what == would have done.
	type marker struct{ id int }
	require.True(t, sameConn(marker{1}, marker{1}))
	require.False(t, sameConn(marker{1}, marker{2}))
}

// --- no invented reasons (§18) --------------------------------------------------

func TestSpliceReason_NoInventedSpliceFailureReasons(t *testing.T) {
	// tun's Splice returns a bare bool covering platform support, NAT expressibility,
	// Attach refusal, socket conversion and family mismatch. sing-box cannot tell those
	// apart, so it must report one reason rather than guess between them.
	names := make([]string, 0, spliceReasonCount)
	for i := 0; i < spliceReasonCount; i++ {
		names = append(names, spliceReason(i).String())
	}

	require.Contains(t, names, "splice_rejected")
	require.NotContains(t, names, "attach_failed",
		"attach failure is not distinguishable from other Splice false paths")
	require.NotContains(t, names, "platform_unsupported",
		"platform support is not distinguishable from other Splice false paths")
}
