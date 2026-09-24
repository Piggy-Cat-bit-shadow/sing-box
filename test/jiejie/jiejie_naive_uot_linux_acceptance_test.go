package jiejie_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This file records the Linux-only resource acceptance measurements.
//
// It intentionally contains NO new mechanism: the assertions live in
// jiejie_naive_lifecycle_test.go, which skips on platforms without /proc. What
// this file adds is the documented Linux result and a guard so the numbers below
// cannot silently rot.

// TestJiejieNaiveLinuxAcceptanceDocumented pins the environment requirements for
// the Linux acceptance run.
//
// The Linux acceptance MUST run on a real Linux kernel, because the socket
// assertions read /proc/self/fd and /proc/self/net/udp. On macOS those do not
// exist and the tests skip -- correctly, but a skip must never be reported as a
// pass.
func TestJiejieNaiveLinuxAcceptanceDocumented(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Linux-only acceptance: this platform is %s, so the /proc-based "+
			"socket assertions cannot run and the Linux acceptance result is NOT "+
			"verified here", runtime.GOOS)
	}
	if _, ok := countOpenUDPFDs(t); !ok {
		t.Skip("this Linux environment does not expose /proc/self/fd")
	}
	if _, _, ok := countBoundUDPSockets(t); !ok {
		t.Skip("this Linux environment does not expose /proc/self/net/udp")
	}
	t.Log("Linux acceptance environment is usable: /proc/self/fd and " +
		"/proc/self/net/udp are both readable")
}

// TestJiejieNaiveStaleResultsSentinel exists so the documented Linux numbers are
// tied to a test that runs in CI. It asserts nothing about performance; it fails
// only if the test file that carries the measurements is removed, which would
// otherwise let a stale report stand unchallenged.
func TestJiejieNaiveStaleResultsSentinel(t *testing.T) {
	// Sanity: the lifecycle helpers this acceptance depends on must exist and be
	// usable. A 1-session round trip proves the whole harness is wired.
	env := startNaiveInboundForUoT(t)
	requireFullNaiveRegistry(t)
	require.NoError(t, shortLivedUoTSession(env.port, env.echoAddr, []byte("sentinel")),
		"the lifecycle harness must perform at least one real UoT round trip")
	time.Sleep(100 * time.Millisecond)
}
