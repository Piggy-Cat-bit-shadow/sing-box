package oomkiller

import (
	"encoding/json"
	"testing"
)

// Tests for the OOM report's accounting semantics (§8, §9).

// TestObservedBudgetComesFromOneInstant is §8.
//
// The previous implementation returned PeakMemory + MinAvailable - two EXTREMA from different
// samples. Adding them describes a state the process may never have been in, and the result was
// presented as an instantaneous observation.
func TestObservedBudgetComesFromOneInstant(t *testing.T) {
	var recorder Recorder

	// Early: a large footprint while available memory is still generous.
	recorder.observeLocked(memorySample{usage: 90 << 20, available: 60 << 20, availableKnown: true})
	// Later: the footprint has been freed but available memory has collapsed.
	recorder.observeLocked(memorySample{usage: 30 << 20, available: 10 << 20, availableKnown: true})

	status := recorder.status

	// The largest budget ever observed at a single instant is 150 MB (90 + 60), and the
	// smallest is 40 MB (30 + 10).
	if status.MaxObservedBudget != 150<<20 {
		t.Errorf("max observed budget = %d, want %d", status.MaxObservedBudget, 150<<20)
	}
	if status.MinObservedBudget != 40<<20 {
		t.Errorf("min observed budget = %d, want %d", status.MinObservedBudget, 40<<20)
	}
	if status.LatestObservedBudget != 40<<20 {
		t.Errorf("latest observed budget = %d, want the last sample's %d",
			status.LatestObservedBudget, 40<<20)
	}

	// Peak + min-available would be 90 + 10 = 100 MB, which was never observed: at the moment
	// the footprint was 90 MB, available was 60 MB.
	peak := status.PeakMemory
	minAvailable := status.MinAvailable
	if peak+minAvailable == status.LatestObservedBudget {
		t.Fatal("the test no longer distinguishes same-instant from cross-sample arithmetic")
	}

	observed, ok := status.ObservedBudget()
	if !ok {
		t.Fatal("a known budget must be reported")
	}
	if observed != 40<<20 {
		t.Errorf("ObservedBudget = %d, want the same-instant %d rather than peak+min %d",
			observed, 40<<20, peak+minAvailable)
	}
}

// TestObservedBudgetUnknownWhenAvailableIsNeverKnown keeps the unknown case honest.
func TestObservedBudgetUnknownWhenAvailableIsNeverKnown(t *testing.T) {
	var recorder Recorder
	recorder.observeLocked(memorySample{usage: 90 << 20})

	if _, ok := recorder.status.ObservedBudget(); ok {
		t.Fatal("a budget must not be reported when available memory was never known")
	}
	if recorder.status.BudgetObserved {
		t.Fatal("BudgetObserved must stay false")
	}
}

// TestTimelineJSONDistinguishesKnownZeroFromUnknown is §9.
//
// The timeline used `availableBytes,omitempty` with no companion flag, so:
//
//	known, available = 0   -> field omitted
//	unknown                -> field omitted
//
// were indistinguishable in the report. Both facts are legitimate and they mean opposite
// things: one is a device genuinely out of memory, the other is a platform where the API does
// not exist.
func TestTimelineJSONDistinguishesKnownZeroFromUnknown(t *testing.T) {
	cases := []struct {
		name           string
		row            timelineRow
		wantKnown      bool
		wantFieldThere bool
	}{
		{
			name:           "unknown",
			row:            timelineRow{At: "t0", State: "normal", MemoryBytes: 100, AvailableKnown: false},
			wantKnown:      false,
			wantFieldThere: false,
		},
		{
			name:           "known zero",
			row:            timelineRow{At: "t1", State: "normal", MemoryBytes: 100, AvailableBytes: 0, AvailableKnown: true},
			wantKnown:      true,
			wantFieldThere: false, // omitempty still drops the zero VALUE...
		},
		{
			name:           "known non-zero",
			row:            timelineRow{At: "t2", State: "normal", MemoryBytes: 100, AvailableBytes: 4096, AvailableKnown: true},
			wantKnown:      true,
			wantFieldThere: true,
		},
	}

	seen := make(map[string]string, len(cases))
	for _, testCase := range cases {
		encoded, err := json.Marshal(testCase.row)
		if err != nil {
			t.Fatalf("%s: marshal: %v", testCase.name, err)
		}

		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("%s: unmarshal: %v", testCase.name, err)
		}

		knownValue, present := decoded["availableKnown"]
		if !present {
			t.Fatalf("%s: availableKnown must always be present, got %s", testCase.name, encoded)
		}
		if knownValue.(bool) != testCase.wantKnown {
			t.Fatalf("%s: availableKnown = %v, want %v", testCase.name, knownValue, testCase.wantKnown)
		}

		_, fieldPresent := decoded["availableBytes"]
		if fieldPresent != testCase.wantFieldThere {
			t.Fatalf("%s: availableBytes present = %v, want %v (encoded: %s)",
				testCase.name, fieldPresent, testCase.wantFieldThere, encoded)
		}

		// The three payloads must be pairwise distinct, which is the property that was broken.
		seen[testCase.name] = string(encoded)
	}

	if seen["unknown"] == seen["known zero"] {
		t.Fatalf("unknown and known-zero serialise identically (%s); the report cannot tell "+
			"a platform without the API from a device out of memory", seen["unknown"])
	}
	if seen["known zero"] == seen["known non-zero"] {
		t.Fatal("known-zero and known-non-zero serialise identically")
	}
	if seen["unknown"] == seen["known non-zero"] {
		t.Fatal("unknown and known-non-zero serialise identically")
	}

	// And a full round trip must preserve the distinction.
	var roundTripped timelineRow
	if err := json.Unmarshal([]byte(seen["known zero"]), &roundTripped); err != nil {
		t.Fatal(err)
	}
	if !roundTripped.AvailableKnown {
		t.Fatal("known-zero lost its AvailableKnown flag across a round trip")
	}
	if roundTripped.AvailableBytes != 0 {
		t.Fatalf("known-zero round-tripped to %d", roundTripped.AvailableBytes)
	}
}

// TestEventJSONDistinguishesKnownZeroFromUnknown is the same requirement for event records.
func TestEventJSONDistinguishesKnownZeroFromUnknown(t *testing.T) {
	unknown, err := json.Marshal(eventRecord{Type: eventTypeReport, MemoryBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	knownZero, err := json.Marshal(eventRecord{
		Type: eventTypeReport, MemoryBytes: 100, AvailableBytes: 0, AvailableKnown: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if string(unknown) == string(knownZero) {
		t.Fatalf("unknown and known-zero events serialise identically: %s", unknown)
	}

	var decoded eventRecord
	if err := json.Unmarshal(knownZero, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.AvailableKnown || decoded.AvailableBytes != 0 {
		t.Fatalf("known-zero event round-tripped to known=%v value=%d",
			decoded.AvailableKnown, decoded.AvailableBytes)
	}
}
