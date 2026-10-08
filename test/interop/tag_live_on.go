//go:build liveinterop

package interop

// liveInteropBuildTag records the gate's build-tag half at compile time.
//
// The gate is deliberately two-sided. A build tag alone would let a maintainer
// who happens to build the whole repository with `-tags liveinterop` start
// spawning reference processes; an environment variable alone would let a
// default `go test ./...` in a CI image that exports the variable by accident do
// the same. Requiring both means the live half runs only when someone asked for
// it twice, in two different vocabularies.
const liveInteropBuildTag = true
