//go:build !race

package bufgeom

// raceDetectorEnabled reports whether this test binary was built with -race. See the race-tagged
// file for why the allocation ceiling depends on it.
const raceDetectorEnabled = false
