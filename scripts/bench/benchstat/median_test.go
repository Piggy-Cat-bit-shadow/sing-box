package benchstat

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for the one median definition shared by memmatrix and memsummary.
//
// # Why this is a test and not a comment
//
// The two tools previously implemented the same word differently: memmatrix took the upper
// median for an even sample count, memsummary averaged the two central values. The same ten
// samples therefore produced 5665.92 in the raw file and 5653.5 in the generated report, both
// labelled "median". These cases fix the definition so that cannot recur.

func TestMedianOddCount(t *testing.T) {
	require.Equal(t, 2.0, Median([]float64{1, 2, 3}))
	require.Equal(t, 5.0, Median([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9}))
	require.Equal(t, 42.0, Median([]float64{42}))
}

func TestMedianEvenCountAveragesTheTwoCentralValues(t *testing.T) {
	require.Equal(t, 2.5, Median([]float64{1, 2, 3, 4}),
		"four samples must average the two middle values, not take the upper one")
	require.Equal(t, 5.5, Median([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
		"ten samples must average 5 and 6")
	require.Equal(t, 1.5, Median([]float64{1, 2}))
}

func TestMedianFourSamples(t *testing.T) {
	require.Equal(t, 2.5, Median([]float64{1, 2, 3, 4}))
	require.Equal(t, 3.5, Median([]float64{4, 1, 3, 6}))
}

func TestMedianTenRealBenchmarkValues(t *testing.T) {
	// The actual throughput samples from the committed comparison. An upper median would
	// report 5665.9 here; the standard median is the mean of the 5th and 6th values.
	samples := []float64{
		5509.1, 5622.4, 5631.1, 5632.2, 5641.1,
		5665.9, 5669.7, 5677.9, 5689.9, 5784.6,
	}

	require.Equal(t, (5641.1+5665.9)/2, Median(samples),
		"ten samples must average the two central values")
	require.NotEqual(t, 5665.9, Median(samples),
		"the upper median is exactly the definition this replaces")
}

func TestMedianIsIndependentOfInputOrder(t *testing.T) {
	original := []float64{5509.1, 5622.4, 5631.1, 5632.2, 5641.1, 5665.9, 5669.7, 5677.9, 5689.9, 5784.6}
	expected := Median(original)

	shuffled := append([]float64(nil), original...)
	random := rand.New(rand.NewSource(1))
	for attempt := 0; attempt < 50; attempt++ {
		random.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		require.Equal(t, expected, Median(shuffled),
			"the median must not depend on sample order")
	}
}

func TestMedianDoesNotModifyItsInput(t *testing.T) {
	input := []float64{3, 1, 2}
	_ = Median(input)
	require.Equal(t, []float64{3, 1, 2}, input,
		"the caller's slice must be left alone; silently sorting it would hide an ordering bug")
}

func TestMedianEmpty(t *testing.T) {
	require.Equal(t, 0.0, Median(nil))
	require.Equal(t, 0.0, Median([]float64{}))
}

// --- integer observations --------------------------------------------------------------

func TestMedianUintExactHalfInteger(t *testing.T) {
	// Twelve and thirteen GC cycles: the median is genuinely 12.5. Truncating to uint64 would
	// report 12 while still calling it a median, which is why the merged statistics are float64.
	require.Equal(t, 12.5, MedianUint([]uint64{12, 13}))
	require.Equal(t, 12.5, MedianUint([]uint64{10, 11, 12, 13, 14, 15}))
	require.Equal(t, 13.0, MedianUint([]uint64{12, 13, 14}))
	require.Equal(t, 7.0, MedianUint([]uint64{7}))
}

func TestMedianUintDoesNotOverflow(t *testing.T) {
	// (a+b)/2 would overflow here. The implementation halves before adding.
	const large = uint64(1) << 63
	require.Equal(t, float64(large), MedianUint([]uint64{large, large}))
	require.Equal(t, float64(large), MedianUint([]uint64{large - 1, large + 1}))
}

func TestMedianUintEmpty(t *testing.T) {
	require.Equal(t, 0.0, MedianUint(nil))
}

// --- the shared definition --------------------------------------------------------------

func TestMedianOfSortedMatchesMedian(t *testing.T) {
	samples := []float64{5509.1, 5622.4, 5631.1, 5632.2, 5641.1, 5665.9, 5669.7, 5677.9, 5689.9, 5784.6}
	sorted := append([]float64(nil), samples...)
	sortFloat64s(sorted)

	require.Equal(t, Median(samples), MedianOfSorted(sorted),
		"the sorted and unsorted entry points must agree; memsummary uses one and memmatrix "+
			"the other, so a divergence here is exactly the bug being fixed")
}

func TestMedianUintOfSortedMatchesMedianUint(t *testing.T) {
	samples := []uint64{12, 13}
	require.Equal(t, MedianUint(samples), MedianUintOfSorted([]uint64{12, 13}))
}

func sortFloat64s(values []float64) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
