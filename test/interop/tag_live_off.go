//go:build !liveinterop

package interop

// liveInteropBuildTag is false in the default build. The live tests are still
// COMPILED and still REGISTERED in this build — they are not hidden behind a
// build tag — because a skipped test that names the exact command to enable it
// is more useful than a test that does not exist. See live_test.go.
const liveInteropBuildTag = false
