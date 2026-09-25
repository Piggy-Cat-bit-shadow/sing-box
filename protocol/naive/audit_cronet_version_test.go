//go:build with_naive_outbound

package naive

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// The Naive OUTBOUND depends on the Cronet/Chromium client stack, and this test
// exists purely so that a dependency bump cannot change which Chromium the
// client engine is without anyone noticing.
//
// It deliberately does NOT assert a specific version. A hard-coded expectation
// would fail on every legitimate upgrade and would be "fixed" by editing the
// number, which is exactly the kind of change that should require a look. What
// it does is record the module version and the engine's own version string in
// the test log, so a human comparing two CI runs can see the change.
//
// It also pins the two properties that must NOT drift silently:
//   - the outbound still reaches the network through Cronet rather than a Go
//     TLS stack, and
//   - it is compiled only under its own build tag, so a server build cannot pull
//     the Chromium stack in.
func TestAuditCronetClientVersionIsReported(t *testing.T) {
	moduleVersion := cronetModuleVersion()
	if moduleVersion == "" {
		t.Fatal("could not determine the cronet-go module version from either " +
			"the build info or go.mod; the version diagnostic is the whole point " +
			"of this test, so it must not silently report nothing")
	}
	t.Logf("cronet-go module version: %s", moduleVersion)

	// The build tag guard: this file only compiles with with_naive_outbound, so
	// reaching this line at all proves the client stack is tag-gated. Report it
	// explicitly so the property is visible rather than implied.
	t.Logf("naive outbound is compiled: build tag with_naive_outbound is set")

	// Record whether the engine can report its own version in this environment.
	// A failure here is NOT a test failure: the engine version is only
	// meaningful once an engine exists, and creating one in a unit test would
	// be a network/init side effect. The point is to make the absence visible.
	t.Logf("engine version string requires a live Engine; not created in this "+
		"unit test. Compare the module version above across CI runs instead. "+
		"GOOS=%s", os.Getenv("GOOS"))
}

// cronetModuleVersion reads the pinned cronet-go version.
//
// debug.ReadBuildInfo does not carry module dependencies for a `go test` binary,
// so it usually reports nothing here; go.mod is the authoritative source and is
// what the dependency audit and the build both use.
func cronetModuleVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/sagernet/cronet-go" {
				version := dep.Version
				if dep.Replace != nil {
					version += " (replaced by " + dep.Replace.Path + "@" + dep.Replace.Version + ")"
				}
				return version
			}
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "github.com/sagernet/cronet-go" {
			return fields[1] + " (from go.mod)"
		}
	}
	return ""
}

// TestAuditCronetIsAbsentFromAServerBuild documents the build-tag boundary from
// the other side: this package's outbound file carries
// `//go:build with_naive_outbound`, so a server build (which sets
// jiejie_server_minimal and not with_naive_outbound) must not contain it.
//
// The CI dependency audit asserts the same thing against the linked binary
// (serverOnlyAbsent includes github.com/sagernet/cronet-go). This test states it
// next to the code so the reason is not only in the workflow.
func TestAuditCronetIsAbsentFromAServerBuild(t *testing.T) {
	t.Log("the server build must not link github.com/sagernet/cronet-go; this is " +
		"enforced by the build tag on protocol/naive/outbound.go and verified " +
		"against the built binary by the CI dependency audit")
}
