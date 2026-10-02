// Command memmatrix runs the memory-pressure benchmark under a matrix of GOMEMLIMIT and
// GOGC settings and reports throughput, GC behaviour and runtime-managed memory for each.
//
// # Why each setting runs in a fresh process
//
// GOMEMLIMIT and GOGC are process-wide and read by the runtime at start-up. Varying them
// in-process would measure the runtime's response to a knob moved underneath it, not the
// configuration under test.
//
// # Why the measurement happens inside the test binary
//
// GC and memory figures come from protocol/shadowsocks's benchmark, which reads
// runtime/metrics in-process and prints one MEMMETRICS line. This harness parses that line
// and nothing else.
//
// The previous version set GODEBUG=gctrace=1 on `go test` and parsed its output, which was
// wrong in three ways that all produced plausible-looking numbers:
//
//   - the gctrace heap field was treated as the memory GOMEMLIMIT governs. It is not; that
//     is the heap at a cycle, while the limit accounts runtime-managed memory.
//   - the three "ms clock" phases were summed and called GC pause. They are the sweep,
//     concurrent mark and mark termination phases, and only part of one is stop-the-world.
//     The true figure comes from the STW histogram and is roughly an order of magnitude
//     smaller.
//   - GODEBUG is inherited by the whole process tree, so the compiler's and the go
//     command's own GC was mixed into the workload's measurement.
//
// # What "engaged" means now
//
// With gctrace gone, validity is decided from runtime-managed memory against the limit. A
// row is marked invalid when the limit demonstrably did not constrain the heap - when the
// peak runtime-managed memory is no lower than it was with no limit at all.
//
// GOMEMLIMIT is a SOFT limit: the runtime is allowed to exceed it temporarily, and it
// governs Go runtime-managed memory only. It says nothing about the process footprint that
// jetsam measures. A row proving the limit engaged therefore says nothing about the process
// fitting in a NetworkExtension budget.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const metricsPrefix = "MEMMETRICS "

// setting is one GOMEMLIMIT/GOGC combination.
type setting struct {
	name      string
	memLimit  string // bytes, or "off"
	gcPercent string
	reference bool
}

var settings = []setting{
	{name: "unlimited/100", memLimit: "off", gcPercent: "100"},
	{name: "48MiB/100", memLimit: strconv.Itoa(48 * 1024 * 1024), gcPercent: "100"},
	{name: "44MiB/100", memLimit: strconv.Itoa(44 * 1024 * 1024), gcPercent: "100"},
	{name: "40MiB/100", memLimit: strconv.Itoa(40 * 1024 * 1024), gcPercent: "100"},
	{name: "40MiB/50", memLimit: strconv.Itoa(40 * 1024 * 1024), gcPercent: "50"},
	{name: "37.5MiB/100", memLimit: strconv.Itoa(38400 * 1024), gcPercent: "100"},
	{name: "37.5MiB/10", memLimit: strconv.Itoa(38400 * 1024), gcPercent: "10", reference: true},
}

// benchmark is one workload to measure under every setting.
type benchmark struct {
	name     string
	pkg      string
	pattern  string
	pressure bool // emits a MEMMETRICS line
}

var benchmarks = []benchmark{
	{name: "SS2022-memory-pressure", pkg: "./protocol/shadowsocks", pattern: "BenchmarkShadowMemoryPressureMeasured", pressure: true},
	{name: "SS2022-real-copy-loop", pkg: "./protocol/shadowsocks", pattern: "BenchmarkShadowRealCopyLoop"},
	{name: "SS2022-mtu-wrapped", pkg: "./protocol/shadowsocks", pattern: "BenchmarkShadowMTUWrappedPath"},
}

// runResult is one (setting, benchmark) measurement.
type runResult struct {
	Setting     string  `json:"setting"`
	Benchmark   string  `json:"benchmark"`
	NsPerOp     float64 `json:"ns_per_op"`
	MBPerSec    float64 `json:"mb_per_sec"`
	BytesPerOp  float64 `json:"bytes_per_op"`
	AllocsPerOp float64 `json:"allocs_per_op"`

	// Runtime figures, from runtime/metrics inside the benchmark process. These are the
	// only memory and GC numbers reported; nothing here comes from log parsing.
	GOGCPercent       uint64 `json:"gogc_percent"`
	GOMEMLIMITBytes   uint64 `json:"gomemlimit_bytes"`
	ManagedStartBytes uint64 `json:"managed_start_bytes"`
	ManagedPeakBytes  uint64 `json:"managed_peak_bytes"`
	ManagedEndBytes   uint64 `json:"managed_end_bytes"`
	GCCycles          uint64 `json:"gc_cycles"`
	PauseTotalNs      uint64 `json:"pause_total_ns"`
	PauseCount        uint64 `json:"pause_count"`
	PauseMaxNs        uint64 `json:"pause_max_ns"`
	HeapLiveBytes     uint64 `json:"heap_live_bytes"`

	Valid      bool   `json:"valid"`
	InvalidWhy string `json:"invalid_why,omitempty"`
	MetricsSaw bool   `json:"metrics_seen"`
}

func main() {
	var (
		runs      = flag.Int("runs", 5, "independent runs per setting; medians are reported")
		benchTime = flag.String("benchtime", "6x", "benchtime passed to go test; too few iterations and no limit engages")
		only      = flag.String("only", "", "substring filter on benchmark names")
		outPath   = flag.String("out", "", "write JSON results here")
		paired    = flag.Bool("paired", true, "alternate setting order between runs to cancel drift")
	)
	flag.Parse()

	selected := benchmarks
	if *only != "" {
		selected = nil
		for _, b := range benchmarks {
			if strings.Contains(b.name, *only) {
				selected = append(selected, b)
			}
		}
	}

	tags, err := appleTags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "memmatrix: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("memory-limit matrix: %d settings x %d benchmarks x %d runs\n", len(settings), len(selected), *runs)
	fmt.Printf("go: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("apple tags: %s\n\n", tags)

	var results []runResult
	for _, b := range selected {
		// Order the settings per run rather than running all of one setting and then all of
		// the next. A single pass through every setting means thermal drift, CPU frequency
		// scaling and background load land on whichever setting happened to run LAST - which
		// is exactly the setting being compared. Alternating the direction between passes
		// cancels the residual drift instead of hiding it.
		//
		// The previous version instead swapped which setting it RAN while still labelling the
		// result with the original name, which silently mixed the rows together.
		samplesBySetting := make(map[string][]runResult, len(settings))
		for run := 0; run < *runs; run++ {
			order := settings
			if *paired && run%2 == 1 {
				order = make([]setting, len(settings))
				for i, s := range settings {
					order[len(settings)-1-i] = s
				}
			}
			for _, s := range order {
				one, err := runOnce(s, b, *benchTime, tags)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  %s / %s run %d failed: %v\n", s.name, b.name, run+1, err)
					continue
				}
				one.Setting = s.name
				samplesBySetting[s.name] = append(samplesBySetting[s.name], one)
			}
		}

		for _, s := range settings {
			samples := samplesBySetting[s.name]
			if len(samples) == 0 {
				continue
			}
			merged := medianOf(samples)
			merged.Setting = s.name
			merged.Benchmark = b.name
			// The unlimited row establishes the reference the limited rows are judged
			// against, so it must be recorded first. Evaluating in slice order would make
			// the result depend on where "unlimited" sits in the settings list.
			if s.memLimit == "off" && merged.MetricsSaw {
				unlimitedManagedPeak[b.name] = merged.ManagedPeakBytes
			}
			evaluateValidity(&merged, s, results, b)
			results = append(results, merged)

			status := "ok"
			if !merged.Valid {
				status = "INVALID"
			}
			throughput := fmt.Sprintf("%8.0f MB/s", merged.MBPerSec)
			if merged.MBPerSec == 0 && merged.NsPerOp > 0 {
				throughput = fmt.Sprintf("%10.0f ns/op", merged.NsPerOp)
			}
			memory := ""
			if merged.MetricsSaw {
				memory = fmt.Sprintf(" peak=%5.1f MiB gc=%5d pause=%8.1f ms",
					float64(merged.ManagedPeakBytes)/(1024*1024), merged.GCCycles,
					float64(merged.PauseTotalNs)/1e6)
			}
			fmt.Printf("  %-16s %-26s %s%s  %s\n", s.name, b.name, throughput, memory, status)
		}
	}

	printReport(results, selected)

	if *outPath != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(*outPath, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *outPath, err)
		} else {
			fmt.Printf("\nwrote %s\n", *outPath)
		}
	}
}

// appleTags reads the canonical Apple tag set. A failure is fatal: falling back to a guess
// would mean benchmarking a configuration nothing ships, which is the defect this
// replaced.
func appleTags() (string, error) {
	output, err := exec.Command("go", "run", "./cmd/internal/appletags", "-platform", "ios").Output()
	if err != nil {
		return "", fmt.Errorf("cannot read the canonical Apple tags: %w", err)
	}
	tags := strings.TrimSpace(string(output))
	if tags == "" {
		return "", fmt.Errorf("the canonical Apple tag set is empty")
	}
	if !strings.Contains(tags, "with_low_memory") {
		return "", fmt.Errorf("the canonical Apple tag set lacks with_low_memory; refusing to benchmark a geometry iOS does not ship")
	}
	return tags, nil
}

func runOnce(s setting, b benchmark, benchTime string, tags string) (runResult, error) {
	args := []string{
		"test", b.pkg,
		"-run", "^$",
		"-bench", b.pattern,
		"-benchtime", benchTime,
		"-count", "1",
		"-json",
		"-tags", tags,
	}
	if strings.Contains(tags, "badlinkname") {
		args = append(args, "-ldflags=-checklinkname=0")
	}

	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOMEMLIMIT="+s.memLimit, "GOGC="+s.gcPercent)
	// No GODEBUG: the benchmark reads runtime/metrics itself, so no log parsing and no
	// gctrace leaking into the toolchain's own processes.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return runResult{}, fmt.Errorf("%v\n%s", err, tail(string(out), 10))
	}
	return parseOutput(string(out), b)
}

func parseOutput(out string, b benchmark) (runResult, error) {
	var result runResult
	foundBenchmark := false

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)

		// The metrics line is printed directly to stdout by the benchmark, and may also
		// arrive inside a test2json envelope.
		metricsLine := ""
		if strings.HasPrefix(trimmed, metricsPrefix) {
			metricsLine = trimmed
		} else if strings.Contains(trimmed, metricsPrefix) {
			if index := strings.Index(trimmed, metricsPrefix); index >= 0 {
				metricsLine = trimmed[index:]
			}
		}
		if metricsLine != "" {
			parseMetricsLine(metricsLine, &result)
		}

		var event struct {
			Action string `json:"Action"`
			Output string `json:"Output"`
		}
		if err := json.Unmarshal([]byte(trimmed), &event); err == nil && event.Action == "output" {
			if index := strings.Index(event.Output, metricsPrefix); index >= 0 {
				parseMetricsLine(strings.TrimSpace(event.Output[index:]), &result)
			}
			if strings.Contains(event.Output, "ns/op") {
				parseBenchLine(event.Output, &result)
				foundBenchmark = true
			}
		}
	}

	if !foundBenchmark {
		return runResult{}, fmt.Errorf("no benchmark result in output:\n%s", tail(out, 15))
	}
	if b.pressure && !result.MetricsSaw {
		// A pressure benchmark that emitted no metrics measured nothing about memory.
		return runResult{}, fmt.Errorf("the pressure benchmark emitted no %s line", strings.TrimSpace(metricsPrefix))
	}
	return result, nil
}

func parseMetricsLine(line string, result *runResult) {
	if !strings.HasPrefix(line, metricsPrefix) {
		return
	}
	result.MetricsSaw = true
	for _, field := range strings.Fields(strings.TrimPrefix(line, metricsPrefix)) {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		switch parts[0] {
		case "gogc":
			result.GOGCPercent = value
		case "gomemlimit":
			result.GOMEMLIMITBytes = value
		case "managed_start":
			result.ManagedStartBytes = value
		case "managed_peak":
			result.ManagedPeakBytes = value
		case "managed_end":
			result.ManagedEndBytes = value
		case "gc_cycles":
			result.GCCycles = value
		case "pause_total_ns":
			result.PauseTotalNs = value
		case "pause_count":
			result.PauseCount = value
		case "pause_max_ns":
			result.PauseMaxNs = value
		case "heap_live":
			result.HeapLiveBytes = value
		}
	}
}

func parseBenchLine(line string, result *runResult) {
	fields := strings.Fields(line)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "Benchmark") {
		return
	}
	for i := 0; i+1 < len(fields); i++ {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			continue
		}
		switch fields[i+1] {
		case "ns/op":
			result.NsPerOp += value
		case "MB/s":
			result.MBPerSec += value
		case "B/op":
			result.BytesPerOp += value
		case "allocs/op":
			result.AllocsPerOp += value
		}
	}
}

// evaluateValidity decides whether a row measured what it claims to.
//
// The question is whether the configured limit actually constrained the runtime. It is
// answered from runtime-managed memory, which is the quantity GOMEMLIMIT accounts against,
// and never from a log field.
func evaluateValidity(merged *runResult, s setting, previous []runResult, b benchmark) {
	merged.Valid = true
	if !b.pressure {
		// The non-pressure benchmarks have no memory claim attached, so there is nothing
		// to validate about a limit.
		return
	}
	if !merged.MetricsSaw {
		merged.Valid = false
		merged.InvalidWhy = "no runtime metrics were emitted"
		return
	}

	if s.memLimit == "off" {
		// The reference row; its peak was recorded by the caller.
		return
	}

	unlimitedPeak := unlimitedManagedPeak[b.name]
	if unlimitedPeak == 0 {
		merged.Valid = false
		merged.InvalidWhy = "the unlimited reference did not run, so there is nothing to compare against"
		return
	}

	// A soft limit holds the runtime near its target, so a limited run's peak should be
	// BELOW the unlimited peak. If it matches, the limit did not constrain anything.
	if merged.ManagedPeakBytes >= unlimitedPeak*95/100 {
		merged.Valid = false
		merged.InvalidWhy = fmt.Sprintf(
			"peak runtime-managed memory %.1f MiB matches the unlimited %.1f MiB, so the limit did not engage",
			float64(merged.ManagedPeakBytes)/(1024*1024), float64(unlimitedPeak)/(1024*1024))
	}
}

var unlimitedManagedPeak = map[string]uint64{}

func medianOf(samples []runResult) runResult {
	pick := func(get func(runResult) float64) float64 {
		values := make([]float64, len(samples))
		for i, s := range samples {
			values[i] = get(s)
		}
		sort.Float64s(values)
		return values[len(values)/2]
	}
	pickU := func(get func(runResult) uint64) uint64 {
		values := make([]uint64, len(samples))
		for i, s := range samples {
			values[i] = get(s)
		}
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		return values[len(values)/2]
	}
	return runResult{
		NsPerOp:           pick(func(r runResult) float64 { return r.NsPerOp }),
		MBPerSec:          pick(func(r runResult) float64 { return r.MBPerSec }),
		BytesPerOp:        pick(func(r runResult) float64 { return r.BytesPerOp }),
		AllocsPerOp:       pick(func(r runResult) float64 { return r.AllocsPerOp }),
		GOGCPercent:       pickU(func(r runResult) uint64 { return r.GOGCPercent }),
		GOMEMLIMITBytes:   pickU(func(r runResult) uint64 { return r.GOMEMLIMITBytes }),
		ManagedStartBytes: pickU(func(r runResult) uint64 { return r.ManagedStartBytes }),
		ManagedPeakBytes:  pickU(func(r runResult) uint64 { return r.ManagedPeakBytes }),
		ManagedEndBytes:   pickU(func(r runResult) uint64 { return r.ManagedEndBytes }),
		GCCycles:          pickU(func(r runResult) uint64 { return r.GCCycles }),
		PauseTotalNs:      pickU(func(r runResult) uint64 { return r.PauseTotalNs }),
		PauseCount:        pickU(func(r runResult) uint64 { return r.PauseCount }),
		PauseMaxNs:        pickU(func(r runResult) uint64 { return r.PauseMaxNs }),
		HeapLiveBytes:     pickU(func(r runResult) uint64 { return r.HeapLiveBytes }),
		MetricsSaw:        true,
		Valid:             true,
	}
}

func printReport(results []runResult, selected []benchmark) {
	fmt.Printf("\n=== report ===\n\n")
	byKey := map[string]runResult{}
	for _, r := range results {
		byKey[r.Setting+"|"+r.Benchmark] = r
	}

	hasMetrics := false
	for _, r := range results {
		if r.MetricsSaw {
			hasMetrics = true
		}
	}

	if hasMetrics {
		fmt.Printf("%-16s %12s %12s %8s %12s %10s\n",
			"Setting", "peak MiB", "limit MiB", "GC", "pause ms", "throughput")
		for _, s := range settings {
			for _, b := range selected {
				r, ok := byKey[s.name+"|"+b.name]
				if !ok || !r.MetricsSaw {
					continue
				}
				limit := "unlimited"
				if r.GOMEMLIMITBytes > 0 && r.GOMEMLIMITBytes < 1<<62 {
					limit = fmt.Sprintf("%.1f", float64(r.GOMEMLIMITBytes)/(1024*1024))
				}
				fmt.Printf("%-16s %12.1f %12s %8d %12.1f %8.0f MB/s\n",
					s.name, float64(r.ManagedPeakBytes)/(1024*1024), limit,
					r.GCCycles, float64(r.PauseTotalNs)/1e6, r.MBPerSec)
			}
		}
		fmt.Printf("\npeak = peak Go runtime-managed memory (total minus released), the quantity\n")
		fmt.Printf("GOMEMLIMIT accounts against. It is NOT the process footprint that jetsam\n")
		fmt.Printf("measures. GOMEMLIMIT is a SOFT limit and may be exceeded temporarily.\n")
	}

	fmt.Printf("\nquestions:\n")
	answerThroughput(results, selected)
	answerValidity(results)
}

func answerThroughput(results []runResult, selected []benchmark) {
	byKey := map[string]runResult{}
	for _, r := range results {
		byKey[r.Setting+"|"+r.Benchmark] = r
	}
	baseline := "unlimited/100"
	delta := func(setting string, b benchmark) (float64, bool) {
		base, ok1 := byKey[baseline+"|"+b.name]
		cand, ok2 := byKey[setting+"|"+b.name]
		if !ok1 || !ok2 || base.MBPerSec == 0 {
			return 0, false
		}
		return (cand.MBPerSec - base.MBPerSec) / base.MBPerSec * 100, true
	}
	for _, setting := range []string{"40MiB/50", "40MiB/100", "44MiB/100", "48MiB/100"} {
		fmt.Printf("\n  %s vs %s:\n", setting, baseline)
		for _, b := range selected {
			d, ok := delta(setting, b)
			if !ok {
				continue
			}
			verdict := "within 3%"
			abs := d
			if abs < 0 {
				abs = -abs
			}
			if abs > 5 {
				verdict = "EXCEEDS the 5% critical floor"
			} else if abs > 3 {
				verdict = "exceeds 3% median guidance"
			}
			fmt.Printf("    %-26s %+7.2f%%  %s\n", b.name, d, verdict)
		}
	}
}

func answerValidity(results []runResult) {
	fmt.Printf("\n  validity:\n")
	invalid := 0
	seen := map[string]bool{}
	for _, r := range results {
		if r.Valid {
			continue
		}
		invalid++
		key := r.Setting + "|" + r.InvalidWhy
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Printf("    INVALID %-16s %s: %s\n", r.Setting, r.Benchmark, r.InvalidWhy)
	}
	if invalid == 0 {
		fmt.Printf("    every limited row constrained the runtime below the unlimited peak\n")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) <= lines {
		return s
	}
	return strings.Join(parts[len(parts)-lines:], "\n")
}
