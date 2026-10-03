package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Tests for the derived summary.
//
// # What these prove
//
// The published figures must be a FUNCTION of the raw samples, not a transcription of a console
// output. The committed report previously disagreed with its own raw JSON by about 9% on the
// exact pause totals, which is the class of error a deterministic generator eliminates.
//
// The synthetic input makes the arithmetic checkable by hand, so a passing test means the
// generator computed the expected number rather than merely producing some number.

// syntheticSample builds one valid raw sample with predictable values.
func syntheticSample(setting string, benchmark string, throughput float64, pauseTotal uint64) sample {
	return sample{
		Setting:     setting,
		Benchmark:   benchmark,
		NsPerOp:     1_000_000,
		MBPerSec:    throughput,
		GCCycles:    10,
		PauseTotal:  pauseTotal,
		PauseMaxUB:  50_000,
		Continuous:  40 * 1024 * 1024,
		ContinuousT: 100,
		GOMemLimit:  40 * 1024 * 1024,
		GOGC:        100,
		SampleValid: true,
		MetricsSaw:  true,
	}
}

func TestSummariseComputesMedianMinMax(t *testing.T) {
	// Odd count: the median is an observed value.
	odd := summarise([]float64{10, 30, 20})
	if odd.Median != 20 || odd.Min != 10 || odd.Max != 30 || odd.Samples != 3 {
		t.Fatalf("odd-count summary = %+v, want median 20 min 10 max 30", odd)
	}

	// Even count: the median averages the two central values, so it can be a value no sample
	// took. This is exactly why the raw file must be published alongside the summary.
	even := summarise([]float64{10, 20, 30, 40})
	if even.Median != 25 {
		t.Fatalf("even-count median = %v, want 25 (the mean of 20 and 30)", even.Median)
	}
	if even.Min != 10 || even.Max != 40 {
		t.Fatalf("even-count min/max = %v/%v, want 10/40", even.Min, even.Max)
	}
}

// TestBuildReportDerivesFromRawSamples is the core requirement: every figure comes from the
// samples.
func TestBuildReportDerivesFromRawSamples(t *testing.T) {
	document := rawDocument{
		RequestedRuns: 5,
		Paired:        true,
		Runs: []sample{
			syntheticSample("A", "bench", 100, 1000),
			syntheticSample("A", "bench", 200, 2000),
			syntheticSample("A", "bench", 300, 3000),
			syntheticSample("A", "bench", 400, 4000),
			syntheticSample("A", "bench", 500, 5000),
		},
	}

	report, err := buildReport(document, "A", "bench")
	if err != nil {
		t.Fatal(err)
	}

	if report.Runs != 5 {
		t.Fatalf("runs = %d, want 5", report.Runs)
	}
	if report.ThroughputMBPerSec.Median != 300 {
		t.Fatalf("throughput median = %v, want 300", report.ThroughputMBPerSec.Median)
	}
	if report.ThroughputMBPerSec.Min != 100 || report.ThroughputMBPerSec.Max != 500 {
		t.Fatalf("throughput min/max = %v/%v, want 100/500",
			report.ThroughputMBPerSec.Min, report.ThroughputMBPerSec.Max)
	}
	if report.PauseTotalNsExact.Median != 3000 {
		t.Fatalf("pause median = %v, want 3000", report.PauseTotalNsExact.Median)
	}
	// The headroom is continuous peak minus the limit; equal values mean it sat exactly at the
	// limit, so the largest value is zero.
	if report.MaxOvershootBytesBelow != 0 {
		t.Fatalf("headroom = %d, want 0 when the peak equals the limit",
			report.MaxOvershootBytesBelow)
	}
}

// TestBuildReportRefusesIncompleteSet is §3 applied to the summary step.
func TestBuildReportRefusesIncompleteSet(t *testing.T) {
	document := rawDocument{
		RequestedRuns: 10,
		Runs: []sample{
			syntheticSample("A", "bench", 100, 1000),
			syntheticSample("A", "bench", 200, 2000),
		},
	}

	if _, err := buildReport(document, "A", "bench"); err == nil {
		t.Fatal("a summary over 2 of 10 requested samples must be refused")
	}
}

// TestBuildReportRefusesInvalidSample is the zero-throughput guard.
func TestBuildReportRefusesInvalidSample(t *testing.T) {
	valid := syntheticSample("A", "bench", 100, 1000)
	zeroThroughput := syntheticSample("A", "bench", 0, 2000)

	document := rawDocument{
		RequestedRuns: 2,
		Runs:          []sample{valid, zeroThroughput},
	}
	if _, err := buildReport(document, "A", "bench"); err == nil {
		t.Fatal("a zero-throughput sample must not be folded into a median")
	}

	// The same, when the sample is explicitly marked invalid.
	markedInvalid := syntheticSample("A", "bench", 300, 3000)
	markedInvalid.SampleValid = false
	document.Runs = []sample{valid, markedInvalid}
	if _, err := buildReport(document, "A", "bench"); err == nil {
		t.Fatal("a sample marked invalid must not be included")
	}
}

// TestBuildReportRefusesMixedRuntimeConfiguration guards against a row that silently combines
// two different configurations.
func TestBuildReportRefusesMixedRuntimeConfiguration(t *testing.T) {
	first := syntheticSample("A", "bench", 100, 1000)
	second := syntheticSample("A", "bench", 200, 2000)
	second.GOGC = 50 // a different configuration wearing the same label

	document := rawDocument{RequestedRuns: 2, Runs: []sample{first, second}}
	if _, err := buildReport(document, "A", "bench"); err == nil {
		t.Fatal("samples from different runtime configurations must not be summarised together")
	}
}

// TestBuildReportRefusesMissingContinuousSamples guards the peak's provenance: without
// continuous samples the reported peak describes an unobserved workload.
func TestBuildReportRefusesMissingContinuousSamples(t *testing.T) {
	bad := syntheticSample("A", "bench", 100, 1000)
	bad.ContinuousT = 0

	document := rawDocument{RequestedRuns: 1, Runs: []sample{bad}}
	if _, err := buildReport(document, "A", "bench"); err == nil {
		t.Fatal("a sample with no continuous observations must be refused")
	}
}

// TestSummaryRoundTripIsStable checks that the emitted JSON reproduces the computed values, so
// a reader can verify the published numbers against the file.
func TestSummaryRoundTripIsStable(t *testing.T) {
	document := rawDocument{
		RequestedRuns: 3,
		Runs: []sample{
			syntheticSample("A", "bench", 100, 1000),
			syntheticSample("A", "bench", 200, 2000),
			syntheticSample("A", "bench", 300, 3000),
		},
	}
	report, err := buildReport(document, "A", "bench")
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded settingReport
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ThroughputMBPerSec.Median != report.ThroughputMBPerSec.Median {
		t.Fatalf("median did not survive a round trip: %v -> %v",
			report.ThroughputMBPerSec.Median, decoded.ThroughputMBPerSec.Median)
	}
	if decoded.Runs != report.Runs {
		t.Fatalf("run count did not survive a round trip")
	}
}

// TestLoadRawRejectsEmptyDocument keeps the entry point from producing a summary of nothing.
func TestLoadRawRejectsEmptyDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte(`{"runs":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRaw(path); err == nil {
		t.Fatal("an empty raw document must be rejected")
	}
}

// TestPercentChange pins the reported deltas, including the direction convention.
func TestPercentChange(t *testing.T) {
	if got := percentChange(100, 110); got < 9.99 || got > 10.01 {
		t.Fatalf("percentChange(100,110) = %v, want +10", got)
	}
	if got := percentChange(100, 90); got < -10.01 || got > -9.99 {
		t.Fatalf("percentChange(100,90) = %v, want -10", got)
	}
	if got := percentChange(0, 100); got != 0 {
		t.Fatalf("percentChange(0,100) = %v, want 0 rather than a division by zero", got)
	}
}
