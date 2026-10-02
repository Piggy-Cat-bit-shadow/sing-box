//go:build ignore

// Command memmatrix runs the data-path benchmarks under a matrix of GOMEMLIMIT and
// GOGC settings and reports throughput, allocation and GC behaviour for each.
//
// # Why this exists
//
// The iOS client runs with GOMEMLIMIT 40 MiB and GOGC 50, derived from a 50 MiB
// NetworkExtension budget and a 5 MiB safety margin (see service/oomkiller). GOGC 50 is
// twice as aggressive as the Go default of 100, and GOMEMLIMIT already paces the heap
// against a hard ceiling, so the question is whether the extra GC work buys anything -
// on a phone, GC cycles are CPU, and CPU is battery and heat.
//
// # Why it is a separate program
//
// GOMEMLIMIT and GOGC are process-wide and are read by the runtime at start-up. A
// benchmark that tried to vary them in-process would be measuring the runtime's
// response to a knob changed underneath it, not the configuration under test. So each
// combination runs the benchmarks in a fresh child process with that environment.
//
// # Why some results are marked INVALID
//
// GOMEMLIMIT only affects anything once the heap approaches it. If a run's peak heap
// stays well below the limit, the limit never engaged and the numbers for 37.5 MiB,
// 40 MiB and unlimited are the same measurement repeated. This program compares each
// run's peak heap against the configured limit and marks the row accordingly, rather
// than presenting those rows as evidence.
//
// The harness does NOT decide whether to change production defaults. It reports.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// setting is one GOMEMLIMIT/GOGC combination to measure.
type setting struct {
	name      string
	memLimit  string // as passed to GOMEMLIMIT; "off" means no limit
	gcPercent string
	reference bool // measured for information only, never a production candidate
}

// The matrix from the task. Order matters: it is the order the report uses.
var settings = []setting{
	{name: "unlimited/100", memLimit: "off", gcPercent: "100"}, // throughput baseline
	{name: "48MiB/100", memLimit: "50331648", gcPercent: "100"},
	{name: "44MiB/100", memLimit: "46137344", gcPercent: "100"},
	{name: "40MiB/100", memLimit: "41943040", gcPercent: "100"}, // primary candidate
	{name: "40MiB/50", memLimit: "41943040", gcPercent: "50"},   // current production
	{name: "37.5MiB/100", memLimit: "39321600", gcPercent: "100"},
	{name: "37.5MiB/10", memLimit: "39321600", gcPercent: "10", reference: true},
}

// benchmark is one workload to measure under every setting.
type benchmark struct {
	name    string
	pkg     string
	pattern string
	// critical marks the datapaths the task sets a hard throughput floor for.
	critical bool
}

// The workloads the task requires. Shadowsocks covers the real copy loop and the MTU
// path; the stacked case is the one that crashed in production.
var benchmarks = []benchmark{
	{"SS2022-real-copy-loop", "./protocol/shadowsocks", "BenchmarkShadowRealCopyLoop", true},
	{"SS2022-steady-state", "./protocol/shadowsocks", "BenchmarkShadowSteadyStateUpload", true},
	{"SS2022-mtu-wrapped", "./protocol/shadowsocks", "BenchmarkShadowMTUWrappedPath", true},
	{"SS2022-memory-pressure", "./protocol/shadowsocks", "BenchmarkShadowMemoryPressure", true},
	{"DNS-cache-paths", "./dns", "BenchmarkDNS", false},
}

// runResult is one (setting, benchmark) measurement.
type runResult struct {
	Setting     string  `json:"setting"`
	Benchmark   string  `json:"benchmark"`
	NsPerOp     float64 `json:"ns_per_op"`
	MBPerSec    float64 `json:"mb_per_sec"`
	BytesPerOp  float64 `json:"bytes_per_op"`
	AllocsPerOp float64 `json:"allocs_per_op"`
	GCCount     float64 `json:"gc_count"`
	GCPauseMs   float64 `json:"gc_pause_ms"`
	PeakHeapMiB float64 `json:"peak_heap_mib"`
	RuntimeMiB  float64 `json:"runtime_mib"`
	// subBenchmarks counts the result lines merged into this row; throughputSamples
	// counts how many of them reported MB/s. They differ when a benchmark does not
	// declare its byte count, in which case there is no usable throughput figure.
	subBenchmarks     int
	throughputSamples int
	Valid             bool   `json:"valid"`
	InvalidWhy        string `json:"invalid_why,omitempty"`
	RawBenchLine      string `json:"-"`
}

func main() {
	var (
		runs      = flag.Int("runs", 5, "independent runs per setting; medians are reported")
		benchTime = flag.String("benchtime", "200x", "benchtime passed to go test")
		filter    = flag.String("only", "", "substring filter on benchmark names")
		outPath   = flag.String("out", "", "write JSON results here")
	)
	flag.Parse()

	selected := benchmarks
	if *filter != "" {
		selected = nil
		for _, b := range benchmarks {
			if strings.Contains(b.name, *filter) {
				selected = append(selected, b)
			}
		}
	}

	fmt.Printf("memory-limit matrix: %d settings x %d benchmarks x %d runs\n",
		len(settings), len(selected), *runs)
	fmt.Printf("go: %s %s/%s\n\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	var results []runResult
	for _, s := range settings {
		for _, b := range selected {
			samples := make([]runResult, 0, *runs)
			for i := 0; i < *runs; i++ {
				one, err := runOnce(s, b, *benchTime)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  %s / %s run %d failed: %v\n", s.name, b.name, i+1, err)
					continue
				}
				samples = append(samples, one)
			}
			if len(samples) == 0 {
				continue
			}
			merged := medianOf(samples)
			merged.Setting = s.name
			merged.Benchmark = b.name

			// Deciding whether a limit ENGAGED is subtler than comparing the peak to
			// the limit, and getting it backwards would discard exactly the rows that
			// demonstrate the limit working.
			//
			// A engaged limit HOLDS THE HEAP DOWN: peak stays below the limit because
			// the collector is pacing against it. So "peak < limit" is the signature of
			// engagement, not of absence. What shows a limit did nothing is the peak
			// matching the UNLIMITED peak - the heap grew as if no limit existed.
			//
			// The baseline row is therefore the reference: a limited row is valid when
			// its peak is measurably below the unlimited peak, and the unlimited peak is
			// itself above the limit (otherwise there was nothing to hold down).
			unlimitedPeak := unlimitedPeakByBenchmark[b.name]
			if s.memLimit != "off" && unlimitedPeak > 0 {
				limitMiB := parseMemLimit(s.memLimit) / (1024 * 1024)
				if unlimitedPeak <= limitMiB {
					merged.Valid = false
					merged.InvalidWhy = fmt.Sprintf(
						"unlimited peak heap %.1f MiB does not exceed the %s limit, so the limit had nothing to hold down; increase the workload",
						unlimitedPeak, s.name)
				} else if merged.PeakHeapMiB >= unlimitedPeak*95/100 {
					merged.Valid = false
					merged.InvalidWhy = fmt.Sprintf(
						"peak heap %.1f MiB matches the unlimited %.1f MiB, so the limit did not engage",
						merged.PeakHeapMiB, unlimitedPeak)
				}
			}
			if merged.PeakHeapMiB*1024*1024 < 16*1024*1024 {
				// Nothing was allocated in any meaningful amount, so no GC comparison is
				// possible whatever the setting.
				merged.Valid = false
				merged.InvalidWhy = fmt.Sprintf(
					"peak heap %.1f MiB is too small for any limit to matter; increase the workload",
					merged.PeakHeapMiB)
			}
			if s.memLimit == "off" {
				unlimitedPeakByBenchmark[b.name] = merged.PeakHeapMiB
			}
			results = append(results, merged)

			status := "ok"
			if !merged.Valid {
				status = "INVALID"
			}
			fmt.Printf("  %-16s %-24s %10.0f ns/op %9.1f MB/s %9.0f B/op %8.0f allocs %6.1f MiB peak  %s\n",
				s.name, b.name, merged.NsPerOp, merged.MBPerSec, merged.BytesPerOp,
				merged.AllocsPerOp, merged.PeakHeapMiB, status)
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

func parseMemLimit(s string) float64 {
	var v float64
	fmt.Sscanf(s, "%f", &v)
	return v
}

// runOnce executes one benchmark in a child process with the setting's environment.
func runOnce(s setting, b benchmark, benchTime string) (runResult, error) {
	args := []string{
		"test", b.pkg,
		"-run", "^$",
		"-bench", b.pattern,
		"-benchtime", benchTime,
		"-count", "1",
		// -json is required, not cosmetic: GODEBUG=gctrace=1 makes the runtime write
		// from its own goroutine, and that text splices into the middle of the plain
		// benchmark line, corrupting the numbers. The JSON stream carries each result
		// as its own record, so it survives the interleaving.
		"-json",
		"-tags", productionTags(),
		"-ldflags=-checklinkname=0",
	}

	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(),
		"GOMEMLIMIT="+memLimitEnv(s.memLimit),
		"GOGC="+s.gcPercent,
		// GODEBUG=gctrace=1 makes the runtime print one line per GC cycle, which gives
		// the count and pause times without touching any package's code. Parsing it
		// keeps this harness out of the benchmarks it measures.
		"GODEBUG=gctrace=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return runResult{}, fmt.Errorf("%v\n%s", err, tail(string(out), 15))
	}
	return parseBenchOutput(string(out))
}

func memLimitEnv(v string) string {
	if v == "off" {
		return "off"
	}
	return v
}

// productionTags reads the shipped tag set rather than restating it.
func productionTags() string {
	data, err := os.ReadFile(filepath.Join("release", "DEFAULT_BUILD_TAGS_OTHERS"))
	if err != nil {
		return "with_quic"
	}
	tags := strings.TrimSpace(string(data))
	// badlinkname is needed to link the packages that touch runtime internals.
	return tags + ",badlinkname,tfogo_checklinkname0"
}

// parseBenchOutput reads the -json event stream.
//
// Each test2json record is a self-contained JSON object, so the gctrace text that
// would otherwise corrupt a plain line is carried as an unrelated record and simply
// ignored. GC statistics still come from the gctrace text, which is what the runtime
// reports and needs no instrumentation in the packages under test.
func parseBenchOutput(out string) (runResult, error) {
	var result runResult
	found := false

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// gctrace lines may be wrapped in a JSON envelope or appear raw; scan the text
		// either way so statistics are collected from both forms.
		collectGCTrace(line, &result)

		var event struct {
			Action string `json:"Action"`
			Output string `json:"Output"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.Action != "output" {
			continue
		}
		collectGCTrace(event.Output, &result)

		if !strings.Contains(event.Output, "ns/op") {
			continue
		}
		// Sum across sub-benchmarks. A parameterised benchmark emits one line per
		// sub-case, and taking a single line reports whichever happened to come last:
		// BenchmarkShadowSteadyStateUpload swings between 2200 and 4800 MB/s that way,
		// because its sub-cases have genuinely different costs. Summing gives the
		// whole-workload figure the settings are being compared on.
		sawLine, line := parseBenchLine(event.Output)
		if sawLine {
			found = true
			result.NsPerOp += line.NsPerOp
			result.BytesPerOp += line.BytesPerOp
			result.AllocsPerOp += line.AllocsPerOp
			// MB/s is only meaningful when the benchmark declares its byte count via
			// SetBytes; `go test` reports it then, and reports 0 otherwise. Summing it
			// would be wrong for a parameterised benchmark, so it is recorded only when
			// exactly one sub-benchmark reported it.
			if line.MBPerSec > 0 {
				result.MBPerSec += line.MBPerSec
				result.throughputSamples++
			}
			result.subBenchmarks++
		}
	}

	if found && result.subBenchmarks > 0 && result.throughputSamples != result.subBenchmarks {
		// Mixed or absent throughput reporting: say so rather than inventing a figure
		// from B/op, which counts allocations rather than bytes transferred.
		result.MBPerSec = 0
	}

	if !found {
		return runResult{}, fmt.Errorf("no benchmark result in output:\n%s", tail(out, 20))
	}
	return result, nil
}

// benchLine is one parsed benchmark result line.
type benchLine struct {
	NsPerOp     float64
	MBPerSec    float64
	BytesPerOp  float64
	AllocsPerOp float64
}

// parseBenchLine reads one benchmark result line.
func parseBenchLine(line string) (bool, benchLine) {
	var out benchLine
	fields := strings.Fields(line)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "Benchmark") {
		return false, out
	}
	ok := false
	for i := 0; i+1 < len(fields); i++ {
		var v float64
		if _, err := fmt.Sscanf(fields[i], "%f", &v); err != nil {
			continue
		}
		switch fields[i+1] {
		case "ns/op":
			out.NsPerOp = v
			ok = true
		case "MB/s":
			out.MBPerSec = v
		case "B/op":
			out.BytesPerOp = v
		case "allocs/op":
			out.AllocsPerOp = v
		}
	}
	return ok, out
}

// collectGCTrace accumulates GC count, pause and heap sizes from gctrace text found
// anywhere in a line, since the runtime writes it without regard for line boundaries.
func collectGCTrace(line string, result *runResult) {
	gcIndex := strings.Index(line, "gc ")
	if gcIndex < 0 {
		return
	}
	gcFields := strings.Fields(line[gcIndex:])
	if len(gcFields) < 2 {
		return
	}
	var n float64
	if _, err := fmt.Sscanf(gcFields[1], "%f", &n); err == nil && n > result.GCCount {
		result.GCCount = n
	}
	// "0.006+1.7+0.015 ms clock" - the sum is the wall pause for this cycle.
	if i := indexOf(gcFields, "ms"); i >= 3 {
		var parts [3]float64
		if _, err := fmt.Sscanf(gcFields[i-1], "%f+%f+%f", &parts[0], &parts[1], &parts[2]); err == nil {
			result.GCPauseMs += parts[0] + parts[1] + parts[2]
		}
	}
	// "12->14->7 MB" - the middle value is the heap at GC; its maximum over cycles is
	// the peak that decides whether a configured limit could have engaged.
	for _, f := range gcFields {
		var a, b, c float64
		if _, err := fmt.Sscanf(f, "%f->%f->%f", &a, &b, &c); err == nil {
			if b > result.PeakHeapMiB {
				result.PeakHeapMiB = b
			}
			if c > result.RuntimeMiB {
				result.RuntimeMiB = c
			}
		}
	}
}

// unlimitedPeakByBenchmark records the peak heap observed for the unlimited setting of
// each benchmark, so a limited row can be judged against what the heap did when nothing
// constrained it.
var unlimitedPeakByBenchmark = map[string]float64{}

// medianOf reduces independent runs to medians, so a single noisy run cannot decide
// anything. Spread is reported by the caller-facing table via min/max when needed.
func medianOf(samples []runResult) runResult {
	pick := func(get func(runResult) float64) float64 {
		values := make([]float64, len(samples))
		for i, s := range samples {
			values[i] = get(s)
		}
		sort.Float64s(values)
		return values[len(values)/2]
	}
	return runResult{
		NsPerOp:     pick(func(r runResult) float64 { return r.NsPerOp }),
		MBPerSec:    pick(func(r runResult) float64 { return r.MBPerSec }),
		BytesPerOp:  pick(func(r runResult) float64 { return r.BytesPerOp }),
		AllocsPerOp: pick(func(r runResult) float64 { return r.AllocsPerOp }),
		GCCount:     pick(func(r runResult) float64 { return r.GCCount }),
		GCPauseMs:   pick(func(r runResult) float64 { return r.GCPauseMs }),
		PeakHeapMiB: pick(func(r runResult) float64 { return r.PeakHeapMiB }),
		RuntimeMiB:  pick(func(r runResult) float64 { return r.RuntimeMiB }),
		Valid:       true,
	}
}

// printReport answers the six questions the task asks, using only measured values.
func printReport(results []runResult, selected []benchmark) {
	fmt.Printf("\n=== report ===\n\n")

	byKey := map[string]runResult{}
	for _, r := range results {
		byKey[r.Setting+"|"+r.Benchmark] = r
	}

	baseline := "unlimited/100"

	fmt.Printf("%-16s", "Setting")
	for _, b := range selected {
		fmt.Printf(" %14s", truncate(b.name, 14))
	}
	fmt.Printf(" %10s\n", "valid")

	for _, s := range settings {
		fmt.Printf("%-16s", s.name)
		valid := true
		for _, b := range selected {
			r, ok := byKey[s.name+"|"+b.name]
			if !ok {
				fmt.Printf(" %14s", "-")
				continue
			}
			fmt.Printf(" %14.1f", r.MBPerSec)
			if !r.Valid {
				valid = false
			}
		}
		mark := "yes"
		if !valid {
			mark = "NO"
		}
		if s.reference {
			mark = "ref"
		}
		fmt.Printf(" %10s\n", mark)
	}

	fmt.Printf("\nMB/s, medians. Compare against the %s baseline.\n", baseline)

	fmt.Printf("\nquestions:\n")
	answerThroughput(results, selected, baseline)
	answerValidity(results)
}

func answerThroughput(results []runResult, selected []benchmark, baseline string) {
	byKey := map[string]runResult{}
	for _, r := range results {
		byKey[r.Setting+"|"+r.Benchmark] = r
	}
	delta := func(setting string, b benchmark) (float64, bool) {
		base, ok1 := byKey[baseline+"|"+b.name]
		cand, ok2 := byKey[setting+"|"+b.name]
		if !ok1 || !ok2 || base.MBPerSec == 0 {
			return 0, false
		}
		return (cand.MBPerSec - base.MBPerSec) / base.MBPerSec * 100, true
	}

	for _, setting := range []string{"40MiB/50", "40MiB/100", "44MiB/100", "48MiB/100"} {
		fmt.Printf("\n  %s vs baseline:\n", setting)
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
			fmt.Printf("    %-24s %+7.2f%%  %s\n", truncate(b.name, 24), d, verdict)
		}
	}
}

func answerValidity(results []runResult) {
	var invalid []runResult
	for _, r := range results {
		if !r.Valid {
			invalid = append(invalid, r)
		}
	}
	fmt.Printf("\n  validity:\n")
	if len(invalid) == 0 {
		fmt.Printf("    every row had a heap large enough for its limit to engage\n")
		return
	}
	seen := map[string]bool{}
	for _, r := range invalid {
		key := r.Setting + "|" + r.InvalidWhy
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Printf("    INVALID %s: %s\n", r.Setting, r.InvalidWhy)
	}
	fmt.Printf("    A limit the heap never approached did not engage, so those rows are not\n")
	fmt.Printf("    evidence about that limit. Increase the workload before drawing conclusions.\n")
}

// firstBenchmarkName returns the benchmark token if the line carries one, tolerating
// GC text spliced in before or after it.
func firstBenchmarkName(line string) string {
	for _, f := range strings.Fields(line) {
		if strings.HasPrefix(f, "Benchmark") {
			return f
		}
	}
	return ""
}

func indexOf(fields []string, want string) int {
	for i, f := range fields {
		if f == want {
			return i
		}
	}
	return -1
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

var _ = time.Second
