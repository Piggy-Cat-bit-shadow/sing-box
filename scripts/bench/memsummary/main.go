// Command memsummary derives the GOGC comparison report from raw benchmark samples.
//
// # Why this is a separate step
//
// The summary used to be written by hand from a run's console output. That is how the committed
// report came to contain pause totals - 1,030,418 ns and 445,230 ns - that do not match the raw
// JSON beside it, whose medians are 942,021.5 ns and 430,707.5 ns. Two numbers, both plausible,
// both in the repository, disagreeing.
//
// A report that cannot be recomputed from its own evidence is not evidence. This command reads
// ONLY the committed raw samples and derives every published figure from them, so the summary is
// a view of the data rather than a transcription of it.
//
// # Fail closed
//
// An incomplete or invalid sample set aborts rather than producing a partial summary. Folding a
// zero into a median is how a fabricated 0 MB/s sample once reached the evidence for a release
// decision.
//
// Usage:
//
//	go run ./scripts/bench/memsummary -raw docs/fork/bench/gogc-...-raw.json -out docs/fork/bench/gogc-....json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/sagernet/sing-box/scripts/bench/benchstat"
)

// sample is one raw benchmark run, mirroring the harness's runResult for the fields this
// command consumes.
type sample struct {
	Setting     string  `json:"setting"`
	Benchmark   string  `json:"benchmark"`
	NsPerOp     float64 `json:"ns_per_op"`
	MBPerSec    float64 `json:"mb_per_sec"`
	GCCycles    uint64  `json:"gc_cycles"`
	PauseTotal  uint64  `json:"pause_total_ns"`
	PauseMaxUB  uint64  `json:"pause_max_upper_bound_ns"`
	Continuous  uint64  `json:"continuous_peak_bytes"`
	ContinuousT uint64  `json:"continuous_ticks"`
	GOMemLimit  uint64  `json:"gomemlimit_bytes"`
	GOGC        uint64  `json:"gogc_percent"`
	SampleValid bool    `json:"sample_valid"`
	MetricsSaw  bool    `json:"metrics_seen"`
}

type rawDocument struct {
	Runs          []sample `json:"runs"`
	RequestedRuns int      `json:"requested_runs"`
	Paired        bool     `json:"paired"`
}

// stats is the distribution of one quantity across samples.
type stats struct {
	Samples int     `json:"samples"`
	Median  float64 `json:"median"`
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
}

func summarise(values []float64) stats {
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	return stats{
		Samples: len(sorted),
		Median:  median(sorted),
		Min:     sorted[0],
		Max:     sorted[len(sorted)-1],
	}
}

// median returns the median of an already-sorted non-empty slice.
//
// It delegates to benchstat, which memmatrix also uses. The two tools derive the same statistic
// from the same raw samples, so they must agree byte for byte; keeping one implementation is
// what makes that a property of the code rather than of two authors remembering the same rule.
//
// For an even count it averages the two central values, which is why a median can be a value
// that no individual sample took - the raw file must be consulted for the actual observations.
func median(sorted []float64) float64 {
	return benchstat.MedianOfSorted(sorted)
}

// settingReport is everything the report claims about one configuration.
type settingReport struct {
	Setting                string `json:"setting"`
	Runs                   int    `json:"runs"`
	GOGCPercent            uint64 `json:"gogc_percent"`
	GOMEMLIMITBytes        uint64 `json:"gomemlimit_bytes"`
	ThroughputMBPerSec     stats  `json:"throughput_mb_per_sec"`
	NsPerOp                stats  `json:"ns_per_op"`
	GCCycles               stats  `json:"gc_cycles"`
	PauseTotalNsExact      stats  `json:"pause_total_ns_exact"`
	PauseMaxUpperBoundNs   stats  `json:"pause_max_upper_bound_ns"`
	ContinuousPeakBytes    stats  `json:"continuous_runtime_managed_peak_bytes"`
	MaxOvershootBytesBelow int64  `json:"max_headroom_below_gomemlimit_bytes"`
}

func main() {
	rawPath := flag.String("raw", "", "path to the raw samples JSON produced by memmatrix")
	outPath := flag.String("out", "", "path to write the derived summary JSON")
	settingA := flag.String("a", "40MiB/50", "the first setting to compare")
	settingB := flag.String("b", "40MiB/100", "the second setting to compare")
	benchmark := flag.String("benchmark", "SS2022-memory-pressure", "the benchmark to summarise")
	flag.Parse()

	if *rawPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "memsummary: -raw and -out are required")
		os.Exit(2)
	}

	document, err := loadRaw(*rawPath)
	if err != nil {
		fatal(err)
	}

	reportA, err := buildReport(document, *settingA, *benchmark)
	if err != nil {
		fatal(err)
	}
	reportB, err := buildReport(document, *settingB, *benchmark)
	if err != nil {
		fatal(err)
	}

	throughputDelta := percentChange(reportA.ThroughputMBPerSec.Median, reportB.ThroughputMBPerSec.Median)
	// Reductions are reported as POSITIVE magnitudes meaning "how much less".
	//
	// A field named gc_cycles_reduction_pct holding -56 would read as a 56% INCREASE to anyone
	// skimming the sign. The direction is carried by the word "reduction", so the number is the
	// size of the improvement.
	gcReduction := -percentChange(float64(reportA.GCCycles.Median), float64(reportB.GCCycles.Median))
	pauseReduction := -percentChange(float64(reportA.PauseTotalNsExact.Median), float64(reportB.PauseTotalNsExact.Median))

	summary := map[string]any{
		"description": "Derived entirely from the raw samples beside this file. Every figure " +
			"here can be recomputed from them; none was transcribed by hand.",
		"benchmark":                  *benchmark,
		"requested_runs_per_setting": document.RequestedRuns,
		"paired_alternating_order":   document.Paired,
		"metric_meanings": map[string]string{
			"pause_total_ns_exact": "Delta of runtime.MemStats.PauseTotalNs, an exact integer " +
				"nanosecond counter - NOT a histogram bucket estimate.",
			"pause_max_upper_bound_ns": "Largest histogram bucket UPPER BOUND among this run's " +
				"pauses. A bound, not a measured maximum; the runtime exposes no true maximum.",
			"continuous_runtime_managed_peak_bytes": "Peak of /memory/classes/total:bytes minus " +
				"/memory/classes/heap/released:bytes, sampled every 1 ms for the whole workload " +
				"rather than only at workload boundaries.",
			"max_headroom_below_gomemlimit_bytes": "Largest observed continuous peak minus the " +
				"soft limit. NEGATIVE means the limit was never exceeded. GOMEMLIMIT is a SOFT " +
				"limit and may be exceeded, so a positive value is not a failure - it is a fact " +
				"about the workload.",
		},
		"settings": map[string]any{
			*settingA: reportA,
			*settingB: reportB,
		},
		"comparison": map[string]any{
			"from":                            *settingA,
			"to":                              *settingB,
			"throughput_change_pct":           throughputDelta,
			"gc_cycles_reduction_pct":         gcReduction,
			"exact_pause_total_reduction_pct": pauseReduction,
		},
	}

	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o644); err != nil {
		fatal(err)
	}

	fmt.Printf("settings %s vs %s, %d runs each\n", *settingA, *settingB, reportA.Runs)
	fmt.Printf("  throughput medians      %.1f -> %.1f MB/s (%+.2f%%)\n",
		reportA.ThroughputMBPerSec.Median, reportB.ThroughputMBPerSec.Median, throughputDelta)
	fmt.Printf("  gc cycles medians       %.0f -> %.0f (reduction %.1f%%)\n",
		reportA.GCCycles.Median, reportB.GCCycles.Median, gcReduction)
	fmt.Printf("  exact pause medians     %.0f -> %.0f ns (reduction %.1f%%)\n",
		reportA.PauseTotalNsExact.Median, reportB.PauseTotalNsExact.Median, pauseReduction)
	fmt.Printf("wrote %s\n", *outPath)
}

func loadRaw(path string) (rawDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return rawDocument{}, err
	}
	var document rawDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return rawDocument{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(document.Runs) == 0 {
		return rawDocument{}, fmt.Errorf("%s contains no raw runs", path)
	}
	return document, nil
}

// buildReport derives one setting's figures from the raw samples.
//
// It refuses to summarise a set that is incomplete or contains an invalid sample. Skipping a bad
// sample would make the median describe a different number of runs than the report claims, and
// substituting zero - which is what an unparsed measurement used to become - is worse still.
func buildReport(document rawDocument, setting string, benchmark string) (settingReport, error) {
	var selected []sample
	for _, run := range document.Runs {
		if run.Setting == setting && run.Benchmark == benchmark {
			selected = append(selected, run)
		}
	}
	if len(selected) == 0 {
		return settingReport{}, fmt.Errorf("no raw samples for %s / %s", setting, benchmark)
	}
	if document.RequestedRuns > 0 && len(selected) != document.RequestedRuns {
		return settingReport{}, fmt.Errorf("%s has %d samples but %d were requested; "+
			"a summary over an incomplete set would misstate the sample count",
			setting, len(selected), document.RequestedRuns)
	}

	throughput := make([]float64, 0, len(selected))
	nsPerOp := make([]float64, 0, len(selected))
	gcCycles := make([]float64, 0, len(selected))
	pauseTotal := make([]float64, 0, len(selected))
	pauseMax := make([]float64, 0, len(selected))
	continuous := make([]float64, 0, len(selected))

	report := settingReport{Setting: setting, Runs: len(selected)}
	var maxDelta int64
	for index, run := range selected {
		if !run.SampleValid {
			return settingReport{}, fmt.Errorf("%s sample %d is marked invalid; refusing to "+
				"include it in a median", setting, index+1)
		}
		if run.MBPerSec <= 0 || run.NsPerOp <= 0 {
			return settingReport{}, fmt.Errorf("%s sample %d reports %v MB/s and %v ns/op; a "+
				"zero-throughput sample must never reach a median",
				setting, index+1, run.MBPerSec, run.NsPerOp)
		}
		if !run.MetricsSaw {
			return settingReport{}, fmt.Errorf("%s sample %d emitted no runtime metrics",
				setting, index+1)
		}
		if run.ContinuousT == 0 {
			return settingReport{}, fmt.Errorf("%s sample %d has no continuous samples",
				setting, index+1)
		}

		// Every sample must agree on the runtime configuration, or the row is a mixture of
		// configurations wearing one label.
		if index == 0 {
			report.GOGCPercent = run.GOGC
			report.GOMEMLIMITBytes = run.GOMemLimit
		} else if run.GOGC != report.GOGCPercent || run.GOMemLimit != report.GOMEMLIMITBytes {
			return settingReport{}, fmt.Errorf("%s mixes runtime configurations: sample %d has "+
				"GOGC=%d GOMEMLIMIT=%d, earlier samples have GOGC=%d GOMEMLIMIT=%d",
				setting, index+1, run.GOGC, run.GOMemLimit, report.GOGCPercent, report.GOMEMLIMITBytes)
		}

		throughput = append(throughput, run.MBPerSec)
		nsPerOp = append(nsPerOp, run.NsPerOp)
		gcCycles = append(gcCycles, float64(run.GCCycles))
		pauseTotal = append(pauseTotal, float64(run.PauseTotal))
		pauseMax = append(pauseMax, float64(run.PauseMaxUB))
		continuous = append(continuous, float64(run.Continuous))

		delta := int64(run.Continuous) - int64(run.GOMemLimit)
		if index == 0 || delta > maxDelta {
			maxDelta = delta
		}
	}

	report.ThroughputMBPerSec = summarise(throughput)
	report.NsPerOp = summarise(nsPerOp)
	report.GCCycles = summarise(gcCycles)
	report.PauseTotalNsExact = summarise(pauseTotal)
	report.PauseMaxUpperBoundNs = summarise(pauseMax)
	report.ContinuousPeakBytes = summarise(continuous)
	report.MaxOvershootBytesBelow = maxDelta
	return report, nil
}

// percentChange reports the change from one value to another, as a percentage of the first.
func percentChange(from float64, to float64) float64 {
	if from == 0 {
		return 0
	}
	return (to - from) / from * 100
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "memsummary: %v\n", err)
	os.Exit(1)
}
