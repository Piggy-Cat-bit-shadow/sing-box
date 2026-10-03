package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for limiter-engagement validity.
//
// # The defect these pin
//
// Engagement used to be judged from ManagedPeakBytes, a Recorder sampled at copy boundaries,
// against an unlimited baseline also taken from ManagedPeakBytes. Because that sampler misses a
// transient rising and falling inside one copy, the committed evidence read:
//
//	unlimited/100  continuous ~48.5 MiB   boundary ~33.7 MiB
//	40MiB/100      continuous ~40.8 MiB   boundary ~38.2 MiB
//
// The continuous data shows the limit clearly constrained the runtime. The boundary data shows
// the limited row apparently ABOVE the unlimited one, so the validator marked the row invalid
// with "the limit did not engage" - contradicting the instrument that actually measures the
// workload peak.
//
// The fix is to judge from ContinuousPeakBytes on both sides. These cases fix both directions,
// so the test cannot be satisfied by a validator that simply always reports "engaged".

const (
	mebibyte = 1024 * 1024
	// pressureBenchmarkName is the key the reference map is indexed by. It must match in the
	// reference row and the judged row, as it does in the real run loop.
	pressureBenchmarkName = "SS2022-memory-pressure"
)

// pressureBenchmark is the benchmark kind that carries a memory claim.
func pressureBenchmark() benchmark {
	return benchmark{name: pressureBenchmarkName, pressure: true}
}

// limitedSetting is a GOMEMLIMIT-constrained configuration.
func limitedSetting() setting {
	return setting{name: "40MiB/100", memLimit: "40MiB", gcPercent: "100"}
}

// TestLimiterEngagementUsesContinuousPeak is the primary regression.
func TestLimiterEngagementUsesContinuousPeak(t *testing.T) {
	// The unlimited reference, recorded exactly as the run loop records it.
	unlimited := runResult{
		Setting:             "unlimited/100",
		Benchmark:           pressureBenchmarkName,
		MetricsSaw:          true,
		ManagedPeakBytes:    34 * mebibyte, // boundary: LOW
		ContinuousPeakBytes: 49 * mebibyte, // continuous: the real workload peak
	}
	unlimitedContinuousPeak[unlimited.Benchmark] = unlimited.ContinuousPeakBytes
	t.Cleanup(func() { delete(unlimitedContinuousPeak, unlimited.Benchmark) })

	// The limited row: its boundary peak is HIGHER than the unlimited row's, which is what made
	// the old logic conclude the limit did nothing.
	merged := runResult{
		Setting:             "40MiB/100",
		Benchmark:           pressureBenchmarkName,
		MetricsSaw:          true,
		ManagedPeakBytes:    38 * mebibyte, // boundary: HIGHER than unlimited - the trap
		ContinuousPeakBytes: 40 * mebibyte, // continuous: clearly below unlimited
	}

	evaluateValidity(&merged, limitedSetting(), []runResult{unlimited}, pressureBenchmark())

	require.True(t, merged.Valid,
		"the row must be valid: the continuous peak shows the limit engaged. Judging from the "+
			"boundary peak compared 38 MiB against 34 MiB and wrongly invalidated it")
	require.True(t, merged.LimitEngaged,
		"the continuous peak (40 MiB) is well under the unlimited continuous peak (49 MiB), "+
			"so the limit demonstrably engaged")
}

// TestLimiterNotEngagedStillReportsFalse is the inverse case.
//
// Without this, a validator that always returned "engaged" would pass the test above.
func TestLimiterNotEngagedStillReportsFalse(t *testing.T) {
	unlimited := runResult{
		Setting:             "unlimited/100",
		Benchmark:           pressureBenchmarkName,
		MetricsSaw:          true,
		ContinuousPeakBytes: 49 * mebibyte,
	}
	unlimitedContinuousPeak[unlimited.Benchmark] = unlimited.ContinuousPeakBytes
	t.Cleanup(func() { delete(unlimitedContinuousPeak, unlimited.Benchmark) })

	// 48.5 is within 5% of 49, so the limit did not measurably constrain the runtime.
	merged := runResult{
		Setting:             "40MiB/100",
		Benchmark:           pressureBenchmarkName,
		MetricsSaw:          true,
		ContinuousPeakBytes: 48*mebibyte + mebibyte/2, // 48.5 MiB
	}

	evaluateValidity(&merged, limitedSetting(), []runResult{unlimited}, pressureBenchmark())

	require.False(t, merged.Valid,
		"a continuous peak within 5%% of the unlimited reference means the limit did not engage")
	require.False(t, merged.LimitEngaged)
	require.Contains(t, merged.InvalidWhy, "did not engage")
}

// TestBoundaryPeakIsNotConsultedForEngagement proves the boundary value is inert.
//
// Two rows with the SAME continuous peak but wildly different boundary peaks must reach the
// same verdict. If the boundary value leaked back into the comparison, these would differ.
func TestBoundaryPeakIsNotConsultedForEngagement(t *testing.T) {
	unlimited := runResult{
		Setting:             "unlimited/100",
		Benchmark:           pressureBenchmarkName,
		MetricsSaw:          true,
		ManagedPeakBytes:    10 * mebibyte,
		ContinuousPeakBytes: 50 * mebibyte,
	}
	unlimitedContinuousPeak[unlimited.Benchmark] = unlimited.ContinuousPeakBytes
	t.Cleanup(func() { delete(unlimitedContinuousPeak, unlimited.Benchmark) })

	low := runResult{
		Setting: "40MiB/100", Benchmark: pressureBenchmarkName, MetricsSaw: true,
		ManagedPeakBytes: 1 * mebibyte, ContinuousPeakBytes: 40 * mebibyte,
	}
	high := runResult{
		Setting: "40MiB/100", Benchmark: pressureBenchmarkName, MetricsSaw: true,
		ManagedPeakBytes: 999 * mebibyte, ContinuousPeakBytes: 40 * mebibyte,
	}

	evaluateValidity(&low, limitedSetting(), []runResult{unlimited}, pressureBenchmark())
	evaluateValidity(&high, limitedSetting(), []runResult{unlimited}, pressureBenchmark())

	require.Equal(t, low.Valid, high.Valid,
		"the boundary peak must not influence validity; only the continuous peak is judged")
	require.Equal(t, low.LimitEngaged, high.LimitEngaged)
	require.True(t, low.Valid)
}

// TestMissingUnlimitedReferenceIsInvalid confirms the guard still holds.
func TestMissingUnlimitedReferenceIsInvalid(t *testing.T) {
	delete(unlimitedContinuousPeak, pressureBenchmarkName)

	merged := runResult{
		Setting: "40MiB/100", Benchmark: pressureBenchmarkName, MetricsSaw: true,
		ContinuousPeakBytes: 40 * mebibyte,
	}
	evaluateValidity(&merged, limitedSetting(), nil, pressureBenchmark())

	require.False(t, merged.Valid)
	require.Contains(t, merged.InvalidWhy, "unlimited reference did not run")
}

// TestUnlimitedRowIsAlwaysTheReference confirms the reference row is not self-judged.
func TestUnlimitedRowIsAlwaysTheReference(t *testing.T) {
	merged := runResult{
		Setting: "unlimited/100", Benchmark: pressureBenchmarkName, MetricsSaw: true,
		ContinuousPeakBytes: 49 * mebibyte,
	}
	evaluateValidity(&merged, setting{name: "unlimited/100", memLimit: "off", gcPercent: "100"}, nil, pressureBenchmark())

	require.True(t, merged.Valid)
	require.False(t, merged.LimitEngaged, "the unlimited row has no limit to engage")
}
