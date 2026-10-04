package trafficsched

import (
	"testing"
	"time"
)

// The experiments. Each one answers a question the design turned on, and each one reports the
// receiver-visible number rather than an internal one.

// TestContentionSteadyState is the original comparison, re-run against the current modes.
//
// It establishes the design basis: models that only change WHEN a write starts do not move the
// receiver-visible p99, and shaping does.
func TestContentionSteadyState(t *testing.T) {
	if testing.Short() {
		t.Skip("contention experiment runs for several seconds")
	}

	const wireRate = 2_000_000.0

	baseline := defaultContentionConfig("A. no gate (baseline)")
	baseline.wireRate = wireRate
	baseline.gateBulk = false
	baseline.gateHigh = false

	inert := defaultContentionConfig("B. gate installed, no rate (production default)")
	inert.wireRate = wireRate
	inert.mode = ModePaced

	admission := defaultContentionConfig("C. ModeAdmission")
	admission.wireRate = wireRate
	admission.mode = ModeAdmission

	service := defaultContentionConfig("D. ModeService")
	service.wireRate = wireRate
	service.mode = ModeService

	pacedNormalOnly := defaultContentionConfig("E. ModePacedNormalOnly at 85% of nominal")
	pacedNormalOnly.wireRate = wireRate
	pacedNormalOnly.mode = ModePacedNormalOnly
	pacedNormalOnly.rate = wireRate * 0.85

	aggregate := defaultContentionConfig("F. ModePaced (aggregate) at 85% of nominal")
	aggregate.wireRate = wireRate
	aggregate.mode = ModePaced
	aggregate.rate = wireRate * 0.85

	aggregate95 := defaultContentionConfig("G. ModePaced (aggregate) at 95% of nominal")
	aggregate95.wireRate = wireRate
	aggregate95.mode = ModePaced
	aggregate95.rate = wireRate * 0.95

	aggregate70 := defaultContentionConfig("H. ModePaced (aggregate) at 70% of nominal")
	aggregate70.wireRate = wireRate
	aggregate70.mode = ModePaced
	aggregate70.rate = wireRate * 0.70

	configs := []contentionConfig{
		baseline, inert, admission, service, pacedNormalOnly, aggregate, aggregate95, aggregate70,
	}
	results := make([]contentionResult, 0, len(configs))
	for _, config := range configs {
		results = append(results, runContention(t, config))
	}

	t.Logf("receiver-visible delivery latency of a 256-byte high-priority message every 20 ms, "+
		"while %d NORMAL flows flood a %.2f MB/s shared FIFO wire through a %d KiB per-flow "+
		"acceptance window", baseline.bulkFlows, wireRate/1_000_000, baseline.window/1024)
	t.Log("")
	for _, result := range results {
		t.Logf("%-46s %s", result.label, summariseLatencies(result.highLatencies))
		t.Logf("%-46s bulk %5.2f MB/s  wire %5.2f MB/s  queue mean %3d KiB peak %3d KiB",
			"", result.bulkThroughput/1_000_000, result.wireThroughput/1_000_000,
			result.queueMean/1024, result.queueHigh/1024)
	}
	t.Log("")

	baselineP99 := p99(baseline.result(results).highLatencies)
	if baselineP99 < 50*time.Millisecond {
		t.Fatalf("the rig must contend before any comparison is meaningful: baseline p99 was %s",
			baselineP99)
	}

	for _, name := range []string{admission.label, service.label} {
		config := configFor(name, configs)
		candidateP99 := p99(config.result(results).highLatencies)
		t.Logf("p99 %-46s %s (baseline %s)", name, candidateP99.Round(time.Millisecond), baselineP99.Round(time.Millisecond))
		if candidateP99 < baselineP99*4/5 {
			t.Logf("NOTE: %s improved p99 from %s to %s, which the queue model does not predict; "+
				"re-examine the rig before trusting it", name, baselineP99, candidateP99)
		}
	}

	for _, name := range []string{aggregate.label, aggregate95.label, aggregate70.label} {
		config := configFor(name, configs)
		result := config.result(results)
		t.Logf("p99 %-46s %s   bulk %5.2f MB/s", name,
			p99(result.highLatencies).Round(time.Millisecond), result.bulkThroughput/1_000_000)
	}

	// The aggregate shaper must keep the queue out of the way at a rate the path actually sustains,
	// and must cost throughput when it is set below that rate. Both are the price side of the
	// trade, and both must be visible in the table rather than argued.
	if !(aggregate70.result(results).bulkThroughput < aggregate.result(results).bulkThroughput) {
		t.Errorf("shaping harder must cost bulk throughput: 85%% gave %.2f MB/s and 70%% gave %.2f MB/s",
			aggregate.result(results).bulkThroughput/1_000_000,
			aggregate70.result(results).bulkThroughput/1_000_000)
	}

	// The structural property is asserted on the QUEUE, not on the tail percentile. The tail is the
	// product number and it is logged above, but it is also the number a busy machine perturbs: a
	// scheduling hiccup on the host shows up as one slow sample, and a p99 over a hundred samples is
	// two samples. The queue depth is what the mechanism actually controls, and it is stable across
	// runs, so it is what the test is allowed to fail on.
	baselineQueue := baseline.result(results).queueMean
	shapedQueue := aggregate.result(results).queueMean
	if shapedQueue >= baselineQueue/4 {
		t.Errorf("shaping at a rate the path sustains must shrink the queue the high-priority "+
			"message waits behind: baseline %d KiB, shaped %d KiB",
			baselineQueue/1024, shapedQueue/1024)
	}

	// And the median, which a host hiccup does not move.
	baselineP50 := p50(baseline.result(results).highLatencies)
	shapedP50 := p50(aggregate.result(results).highLatencies)
	if shapedP50 >= baselineP50/4 {
		t.Errorf("shaping must collapse the median high-priority delivery time: baseline %s, "+
			"shaped %s", baselineP50, shapedP50)
	}
}

func configFor(label string, configs []contentionConfig) contentionConfig {
	for _, config := range configs {
		if config.label == label {
			return config
		}
	}
	panic("missing config " + label)
}

func (c contentionConfig) result(results []contentionResult) contentionResult {
	for _, result := range results {
		if result.label == c.label {
			return result
		}
	}
	panic("missing result for " + c.label)
}

// TestContentionColdStart is question A: does the design protect the FIRST interactive request
// after a long stretch of bulk-only traffic?
//
// The steady-state experiment cannot answer it, because it always has a high-priority write every
// 20 ms and therefore only ever measures a scheduler that is already reacting. The case that
// matters to a person is the opposite one: minutes of backup or sync, then one prompt.
//
// The mechanism being tested is the one that was changed for it. The ordering modes arm on
// high-priority activity, so during the gap they are disarmed and the acceptance windows fill; the
// paced modes shape continuously, so the windows never fill in the first place.
func TestContentionColdStart(t *testing.T) {
	if testing.Short() {
		t.Skip("cold-start experiment runs for tens of seconds")
	}

	const (
		wireRate = 2_000_000.0
		gap      = 1 * time.Second
		repeats  = 12
	)

	baseline := defaultContentionConfig("A. no gate (baseline)")
	baseline.wireRate = wireRate
	baseline.gateBulk = false
	baseline.gateHigh = false

	admission := defaultContentionConfig("B. ModeAdmission (arms on high-priority activity)")
	admission.wireRate = wireRate
	admission.mode = ModeAdmission

	pacedNormalOnly := defaultContentionConfig("C. ModePacedNormalOnly at 85%")
	pacedNormalOnly.wireRate = wireRate
	pacedNormalOnly.mode = ModePacedNormalOnly
	pacedNormalOnly.rate = wireRate * 0.85

	aggregate := defaultContentionConfig("D. ModePaced (aggregate) at 85%")
	aggregate.wireRate = wireRate
	aggregate.mode = ModePaced
	aggregate.rate = wireRate * 0.85

	configs := []contentionConfig{baseline, admission, pacedNormalOnly, aggregate}

	t.Logf("receiver-visible delivery latency of the FIRST 256-byte high-priority write after %s "+
		"of uninterrupted bulk upload, %d repetitions, %.2f MB/s wire",
		gap, repeats, wireRate/1_000_000)
	t.Log("")

	samples := make(map[string][]time.Duration, len(configs))
	for _, config := range configs {
		latencies := runColdStart(t, config, gap, repeats)
		samples[config.label] = latencies
		t.Logf("%-46s %s", config.label, summariseLatencies(latencies))
	}
	t.Log("")

	baselineSamples := samples[baseline.label]
	if len(baselineSamples) == 0 {
		t.Fatal("the cold-start rig produced no samples")
	}
	baselineP50 := p50(baselineSamples)
	t.Logf("first-request p50 by design (baseline %s):", baselineP50.Round(time.Millisecond))
	for _, config := range configs {
		t.Logf("  %-44s p50 %8s  max %8s", config.label,
			p50(samples[config.label]).Round(time.Millisecond),
			maxOf(samples[config.label]).Round(time.Millisecond))
	}

	// The finding this test exists for. An armed scheduler is disarmed during the gap, so the queue
	// is exactly as deep as it would be with no scheduler at all, and the first interactive request
	// pays for it in full.
	if p50(samples[admission.label]) < baselineP50/2 {
		t.Logf("NOTE: the arming design protected the first request after all (baseline p50 %s, "+
			"armed %s); the continuous-shaping rationale needs revisiting",
			baselineP50, p50(samples[admission.label]))
	}

	// And the mechanism that does protect it, on the first write, with no warm-up at all.
	for _, config := range []contentionConfig{pacedNormalOnly, aggregate} {
		firstP50 := p50(samples[config.label])
		if firstP50 >= baselineP50/4 {
			t.Errorf("%s must protect the FIRST request after the gap: baseline p50 %s, got %s",
				config.label, baselineP50, firstP50)
		}
	}
}

// TestContentionHighVersusHigh is question C: a high-priority flow doing BULK work, and a small
// high-priority interactive write arriving next to it.
//
// Shaping only the NORMAL lane leaves this hole wide open, and it is not a hypothetical: an
// outbound group is classified interactive by what the traffic is FOR, and a tagged flow can carry
// a large upload. If the bulk high-priority flow can fill the acceptance windows, the small
// high-priority write waits behind exactly the queue the NORMAL lane was just prevented from
// creating.
func TestContentionHighVersusHigh(t *testing.T) {
	if testing.Short() {
		t.Skip("contention experiment runs for several seconds")
	}

	const wireRate = 2_000_000.0

	baseline := defaultContentionConfig("A. no gate (baseline)")
	baseline.wireRate = wireRate
	baseline.bulkFlows = 0
	baseline.highBulkFlows = 2
	baseline.gateBulk = false
	baseline.gateHigh = false

	pacedNormalOnly := defaultContentionConfig("B. ModePacedNormalOnly at 85% (NORMAL lane only)")
	pacedNormalOnly.wireRate = wireRate
	pacedNormalOnly.bulkFlows = 0
	pacedNormalOnly.highBulkFlows = 2
	pacedNormalOnly.mode = ModePacedNormalOnly
	pacedNormalOnly.rate = wireRate * 0.85

	aggregate := defaultContentionConfig("C. ModePaced (aggregate) at 85%")
	aggregate.wireRate = wireRate
	aggregate.bulkFlows = 0
	aggregate.highBulkFlows = 2
	aggregate.mode = ModePaced
	aggregate.rate = wireRate * 0.85

	configs := []contentionConfig{baseline, pacedNormalOnly, aggregate}
	results := make([]contentionResult, 0, len(configs))
	for _, config := range configs {
		results = append(results, runContention(t, config))
	}

	t.Logf("receiver-visible latency of a 256-byte high-priority probe every 20 ms while %d "+
		"HIGH-priority flows upload bulk data at %.2f MB/s wire", baseline.highBulkFlows, wireRate/1_000_000)
	t.Log("")
	for _, result := range results {
		t.Logf("%-52s %s", result.label, summariseLatencies(result.highLatencies))
		t.Logf("%-52s bulk %5.2f MB/s  queue mean %3d KiB peak %3d KiB",
			"", result.bulkThroughput/1_000_000, result.queueMean/1024, result.queueHigh/1024)
	}
	t.Log("")

	baselineP99 := p99(baseline.result(results).highLatencies)
	normalOnlyResult := pacedNormalOnly.result(results)
	aggregateResult := aggregate.result(results)

	t.Logf("p99 baseline                    %s", baselineP99.Round(time.Millisecond))
	t.Logf("p99 NORMAL-lane-only shaper     %s  (bulk %.2f MB/s)",
		p99(normalOnlyResult.highLatencies).Round(time.Millisecond), normalOnlyResult.bulkThroughput/1_000_000)
	t.Logf("p99 aggregate shaper            %s  (bulk %.2f MB/s)",
		p99(aggregateResult.highLatencies).Round(time.Millisecond), aggregateResult.bulkThroughput/1_000_000)

	if baselineP99 < 50*time.Millisecond {
		t.Fatalf("the rig must contend: baseline p99 was %s", baselineP99)
	}

	// The hole, if it is one. This is logged rather than asserted in the failing direction: the
	// design decision is which shaper to ship, and a shaper that happens to cope here is a result
	// worth having rather than a bug.
	if p99(normalOnlyResult.highLatencies) > baselineP99/2 {
		t.Logf("CONFIRMED: shaping only the NORMAL lane leaves a HIGH-priority bulk flow free to "+
			"create the queue, and the small high-priority probe still waits %s",
			p99(normalOnlyResult.highLatencies).Round(time.Millisecond))
	}

	if p99(aggregateResult.highLatencies) >= baselineP99/4 {
		t.Errorf("aggregate shaping must also protect a small high-priority write from a "+
			"high-priority bulk flow: baseline p99 %s, aggregate %s",
			baselineP99, p99(aggregateResult.highLatencies))
	}
}

// TestOversizedWriteCannotEscapeShaping is question B at the rig level.
//
// The previous rule admitted any write larger than the bucket without charging it, on the grounds
// that such a write could never be covered and the alternative was a deadlock. That made the
// largest writes the only ones exempt from shaping, which is the worst possible set to exempt. The
// charge is now split - the shared bucket pays what the write had to see, the offending flow pays
// the rest in its own future - so an oversized write is inside the budget rather than outside it.
func TestOversizedWriteCannotEscapeShaping(t *testing.T) {
	if testing.Short() {
		t.Skip("oversized-write experiment runs for several seconds")
	}

	const wireRate = 2_000_000.0
	const oversized = 256 * 1024

	unshaped := defaultContentionConfig("A. no shaping (control)")
	unshaped.wireRate = wireRate
	unshaped.window = 1 << 20
	unshaped.bulkFlows = 1
	unshaped.bulkChunk = oversized
	unshaped.gateHigh = false

	shaped := defaultContentionConfig("B. aggregate shaping at 85%, writes 4x the bucket")
	shaped.wireRate = wireRate
	shaped.window = 1 << 20
	shaped.bulkFlows = 1
	shaped.bulkChunk = oversized
	shaped.gateHigh = false
	shaped.mode = ModePaced
	shaped.rate = wireRate * 0.85

	configs := []contentionConfig{unshaped, shaped}
	results := make([]contentionResult, 0, len(configs))
	for _, config := range configs {
		results = append(results, runContention(t, config))
	}

	t.Logf("one flow writing %d KiB at a time into a %d KiB bucket on a %.2f MB/s wire",
		oversized/1024, DefaultBurst/1024, wireRate/1_000_000)
	for _, result := range results {
		t.Logf("%-46s bulk %5.2f MB/s  queue mean %3d KiB peak %3d KiB",
			result.label, result.bulkThroughput/1_000_000, result.queueMean/1024, result.queueHigh/1024)
	}

	shapedResult := shaped.result(results)
	unshapedResult := unshaped.result(results)

	// The budget check is loose on purpose. The measurement window holds about a dozen writes at
	// this rate and size, so one write landing on either side of the boundary is worth several
	// percent; the exact accounting is pinned by unit tests instead, which can count bytes rather
	// than divide totals.
	budget := shaped.rate * 1.15
	if shapedResult.bulkThroughput > budget {
		t.Errorf("an oversized write escaped the shaping budget: admitted %.2f MB/s against a "+
			"configured %.2f MB/s", shapedResult.bulkThroughput/1_000_000, shaped.rate/1_000_000)
	}

	// What the rig can show reliably is the QUEUE, because that is what the two runs differ by an
	// order of magnitude on: the control lets a megabyte of oversized writes stand in front of the
	// wire and the shaper does not.
	if shapedResult.queueMean >= unshapedResult.queueMean/2 {
		t.Errorf("the control must show the oversized write reaching the wire unshaped, or the "+
			"comparison means nothing: control queue mean %d KiB, shaped %d KiB",
			unshapedResult.queueMean/1024, shapedResult.queueMean/1024)
	}
}
