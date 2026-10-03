// Package benchstat holds the statistical definitions shared by the benchmark tools.
//
// # Why this is a package rather than two copies
//
// memmatrix writes raw samples and a merged median for each setting; memsummary re-derives the
// report median from those same raw samples. Both call their result a "median", so if the two
// definitions differ the raw file and the generated report disagree about the same evidence -
// which is exactly what happened: memmatrix took the upper median for an even sample count and
// memsummary averaged the two central values, so the same ten samples produced 5665.92 in one
// file and 5653.5 in the other.
//
// A shared definition is the only way to make that impossible rather than merely fixed. The
// duplication was not a typo; it was two independent implementations of the same word.
package benchstat

import "sort"

// Median returns the median of the values, using the standard definition.
//
//	odd count:  the middle value
//	even count: the arithmetic mean of the two middle values
//
// The input is not modified. A nil or empty slice has no median and returns 0, which callers
// must not interpret as an observation - the raw files carry the sample count separately for
// exactly that reason.
func Median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	return MedianOfSorted(sorted)
}

// MedianOfSorted returns the median of an already-sorted slice.
//
// It exists so a caller that must sort anyway - or that needs several medians of the same
// sample set - does not pay for a second sort. The caller is responsible for the sort order.
func MedianOfSorted(sorted []float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

// MedianUint returns the median of integer observations as a float64.
//
// The float64 result is not a loss of precision to be tidied away: for an even sample count the
// median of integers is genuinely a half-integer. Truncating it back to an integer while still
// calling it a "median" would report 12 for a sample set whose median is 12.5, so the merged
// statistics that need a median are float64.
//
// The mean is computed as a/2 + b/2 rather than (a+b)/2 so that two large uint64 values cannot
// overflow before the division.
func MedianUint(values []uint64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]uint64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return MedianUintOfSorted(sorted)
}

// MedianUintOfSorted returns the median of an already-sorted slice of integers.
func MedianUintOfSorted(sorted []uint64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return float64(sorted[middle])
	}
	return float64(sorted[middle-1])/2 + float64(sorted[middle])/2
}
