//go:build race

package trafficsched

// raceEnabled reports whether the race detector is instrumenting this run.
//
// It exists because two kinds of test live in this package and only one of them survives
// instrumentation. The structural ones - ownership, capability, the arithmetic, the policy - are
// exactly what the detector is for. The measurement ones compare two SHORT timing windows, and the
// detector makes the host unrepresentative: every sleep, every lock and every allocation is slower,
// so a link that carries 2 MB/s uninstrumented carries a different number here, and a ratio between
// two such numbers is not evidence of anything.
//
// Skipping them is the honest option. Running them and relaxing their assertions until they pass
// would leave a test that no longer says what it claims.
const raceEnabled = true
