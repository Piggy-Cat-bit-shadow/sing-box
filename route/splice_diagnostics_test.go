package route

import (
	"testing"
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
	d.record(spliceReasonSuccess)
	d.record(spliceReasonSuccess)
	d.record(spliceReasonSourceNotReplaceable)

	snap := d.snapshot()
	if snap["success"] != 2 {
		t.Errorf("success: want 2, got %d", snap["success"])
	}
	if snap["source_not_replaceable"] != 1 {
		t.Errorf("source_not_replaceable: want 1, got %d", snap["source_not_replaceable"])
	}
	if d.total() != 3 {
		t.Errorf("total: want 3, got %d", d.total())
	}
}

func TestSpliceDiagnostics_ZeroReasonsAreOmitted(t *testing.T) {
	// A snapshot reports only what happened, so an absent key means "never seen"
	// rather than "seen zero times" - which keeps on-device output readable.
	var d spliceDiagnostics
	d.record(spliceReasonTargetNoUpstream)
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
	d.record(spliceReason(200))
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
