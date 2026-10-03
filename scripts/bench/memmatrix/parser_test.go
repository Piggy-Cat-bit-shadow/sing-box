package main

import "testing"

// Tests for benchmark output parsing.
//
// # The bug these pin
//
// "Did a benchmark run?" was decided with strings.Contains(output, "ns/op"). That substring can
// appear in output carrying no measurement at all, so runs were recorded as successful with
// NsPerOp and MBPerSec left at zero. Two such samples reached the committed evidence for the
// GOGC comparison, where a 0 MB/s sample sits inside a throughput median.

// TestParseBenchLineRequiresAnActualResult is the core regression.
func TestParseBenchLineRequiresAnActualResult(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantParsed bool
		wantNs     float64
	}{
		{
			name:       "a real benchmark line",
			line:       "BenchmarkShadowMemoryPressureMeasured-8   100   46677382 ns/op   5750.87 MB/s",
			wantParsed: true,
			wantNs:     46677382,
		},
		{
			name:       "the unit mentioned without a benchmark line",
			line:       "some log output mentioning ns/op in passing",
			wantParsed: false,
		},
		{
			name:       "a benchmark line with no timing",
			line:       "BenchmarkSomething-8   100   5750.87 MB/s",
			wantParsed: false,
		},
		{
			name:       "an empty line",
			line:       "",
			wantParsed: false,
		},
		{
			name:       "a truncated envelope",
			line:       `{"Action":"output","Output":"BenchmarkFoo-8   100  44`,
			wantParsed: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var result runResult
			parsed := parseBenchLine(testCase.line, &result)
			if parsed != testCase.wantParsed {
				t.Fatalf("parseBenchLine(%q) = %v, want %v", testCase.line, parsed, testCase.wantParsed)
			}
			if testCase.wantParsed && result.NsPerOp != testCase.wantNs {
				t.Fatalf("ns/op = %v, want %v", result.NsPerOp, testCase.wantNs)
			}
		})
	}
}

// TestParseOutputRejectsOutputWithoutAResult checks the caller no longer trusts a substring.
func TestParseOutputRejectsOutputWithoutAResult(t *testing.T) {
	// Output that mentions the unit and even the metrics prefix, but contains no benchmark
	// result line. The old substring test accepted this.
	output := `{"Action":"output","Output":"MEMMETRICS gogc=100 gomemlimit=41943040 managed_peak=1 pause_total_ns=1 pause_count=1 heap_live=1\n"}` + "\n" +
		`{"Action":"output","Output":"PASS\n"}` + "\n" +
		`{"Action":"output","Output":"this line merely mentions ns/op\n"}`

	benchmark := benchmark{name: "test", pkg: "./x", pattern: "BenchmarkX", pressure: true}
	if _, err := parseOutput(output, benchmark); err == nil {
		t.Fatal("output with no parsable benchmark result must be rejected")
	}
}

// TestParseOutputAcceptsACompleteResult is the positive control.
func TestParseOutputAcceptsACompleteResult(t *testing.T) {
	output := `{"Action":"output","Output":"MEMMETRICS gogc=100 gomemlimit=41943040 managed_start=1 managed_peak=2 managed_end=1 gc_cycles=3 pause_total_ns=4 pause_count=5 pause_max_upper_bound_ns=6 pause_upper_bound_total_ns=7 heap_live=8 continuous_peak=9 continuous_ticks=10\n"}` + "\n" +
		`{"Action":"output","Output":"BenchmarkX-8   100   1000 ns/op   500.5 MB/s   10 B/op   2 allocs/op\n"}`

	benchmark := benchmark{name: "test", pkg: "./x", pattern: "BenchmarkX", pressure: true}
	result, err := parseOutput(output, benchmark)
	if err != nil {
		t.Fatal(err)
	}
	if result.NsPerOp != 1000 || result.MBPerSec != 500.5 {
		t.Fatalf("parsed ns/op=%v MB/s=%v, want 1000 and 500.5", result.NsPerOp, result.MBPerSec)
	}
	if !result.MetricsSaw || result.ContinuousTicks != 10 {
		t.Fatalf("metrics were not captured: seen=%v ticks=%v", result.MetricsSaw, result.ContinuousTicks)
	}
}

// TestValidateSampleRejectsIncompleteMeasurements is the completeness gate.
func TestValidateSampleRejectsIncompleteMeasurements(t *testing.T) {
	setting := setting{
		name:      "40MiB/100",
		memLimit:  "41943040",
		gcPercent: "100",
	}
	benchmark := benchmark{name: "pressure", pkg: "./x", pattern: "BenchmarkX", pressure: true}

	complete := func() runResult {
		return runResult{
			NsPerOp:             1000,
			MBPerSec:            500,
			MetricsSaw:          true,
			ContinuousTicks:     10,
			ContinuousPeakBytes: 1024,
			GOGCPercent:         100,
			GOMEMLIMITBytes:     41943040,
		}
	}

	if err := validateSample(complete(), setting, benchmark); err != nil {
		t.Fatalf("a complete sample must validate: %v", err)
	}

	cases := map[string]func(*runResult){
		"zero throughput":       func(r *runResult) { r.MBPerSec = 0 },
		"zero ns/op":            func(r *runResult) { r.NsPerOp = 0 },
		"no metrics":            func(r *runResult) { r.MetricsSaw = false },
		"no continuous samples": func(r *runResult) { r.ContinuousTicks = 0 },
		"zero continuous peak":  func(r *runResult) { r.ContinuousPeakBytes = 0 },
		"wrong GOGC":            func(r *runResult) { r.GOGCPercent = 50 },
		"wrong GOMEMLIMIT":      func(r *runResult) { r.GOMEMLIMITBytes = 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			result := complete()
			mutate(&result)
			if err := validateSample(result, setting, benchmark); err == nil {
				t.Fatalf("a sample with %s must be rejected", name)
			}
		})
	}
}

// TestValidateSampleAcceptsUnlimitedGOMEMLIMIT covers the reference row.
//
// The runtime expresses "no limit" as the maximum int64, not as zero. Requiring zero would fail
// every unlimited row for the wrong reason.
func TestValidateSampleAcceptsUnlimitedGOMEMLIMIT(t *testing.T) {
	const unlimited = uint64(1<<63 - 1)
	setting := setting{name: "unlimited/100", memLimit: "off", gcPercent: "100"}
	benchmark := benchmark{name: "pressure", pkg: "./x", pattern: "BenchmarkX", pressure: true}

	result := runResult{
		NsPerOp:             1000,
		MBPerSec:            500,
		MetricsSaw:          true,
		ContinuousTicks:     10,
		ContinuousPeakBytes: 1024,
		GOGCPercent:         100,
		GOMEMLIMITBytes:     unlimited,
	}
	if err := validateSample(result, setting, benchmark); err != nil {
		t.Fatalf("the unlimited setting must validate with the runtime's expression of no limit: %v", err)
	}
}

// TestParseOutputReassemblesSplitEvents is the regression for the REAL root cause of the
// zero-throughput samples.
//
// `go test -json` does not emit one event per printed line. A benchmark result is long and
// arrives split at an arbitrary boundary:
//
//	event 1: "BenchmarkShadowMemoryPressureMeasured-8   \t"
//	event 2: "       6\t  48854389 ns/op\t5494.60 MB/s\t..."
//
// Parsing each event in isolation never sees a complete result, so a run was recorded as
// successful with ns/op and MB/s both zero. This test uses the exact shape observed in a real
// `go test -json` capture.
func TestParseOutputReassemblesSplitEvents(t *testing.T) {
	output := `{"Action":"start","Package":"x"}` + "\n" +
		`{"Action":"output","Package":"x","Test":"B","Output":"=== RUN   B\n"}` + "\n" +
		`{"Action":"output","Package":"x","Test":"B","Output":"MEMMETRICS gogc=100 gomemlimit=46137344 managed_start=1 managed_peak=2 managed_end=2 gc_cycles=13 pause_total_ns=529416 pause_count=26 pause_max_upper_bound_ns=98304 pause_upper_bound_total_ns=579584 heap_live=13393520 continuous_peak=42617096 continuous_ticks=294\n"}` + "\n" +
		`{"Action":"output","Package":"x","Test":"B","Output":"BenchmarkShadowMemoryPressureMeasured-8   \t"}` + "\n" +
		`{"Action":"output","Package":"x","Test":"B","Output":"       6\t  48854389 ns/op\t5494.60 MB/s\t22146078 B/op\t   17742 allocs/op\n"}` + "\n" +
		`{"Action":"output","Package":"x","Output":"PASS\n"}`

	benchmark := benchmark{name: "test", pkg: "./x", pattern: "BenchmarkShadowMemoryPressureMeasured", pressure: true}
	result, err := parseOutput(output, benchmark)
	if err != nil {
		t.Fatalf("a split benchmark result must still be parsed: %v", err)
	}

	if result.NsPerOp != 48854389 {
		t.Fatalf("ns/op = %v, want 48854389 (the value in the second event)", result.NsPerOp)
	}
	if result.MBPerSec != 5494.60 {
		t.Fatalf("MB/s = %v, want 5494.60", result.MBPerSec)
	}
	if result.AllocsPerOp != 17742 {
		t.Fatalf("allocs/op = %v, want 17742", result.AllocsPerOp)
	}

	// And the sample must validate, which is what the old data failed to do.
	setting := setting{name: "40MiB/100", memLimit: "46137344", gcPercent: "100"}
	if err := validateSample(result, setting, benchmark); err != nil {
		t.Fatalf("the reassembled sample must validate: %v", err)
	}
}
