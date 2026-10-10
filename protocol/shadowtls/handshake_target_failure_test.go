package shadowtls

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// A refused HANDSHAKE TARGET dial must be classified as a fault, using a real
// syscall error rather than a synthesised one.
//
// The unit matrix asserts the classification of hand-built errnos. This test goes
// one step further and produces a genuine connection refusal by dialling a port that
// nothing is listening on, so the classifier is shown to work against the error
// the kernel actually returns rather than against an approximation of it.
//
// This matters because the earlier classifier downgraded every *os.SyscallError,
// and a refused dial on the handshake target is exactly how a misconfigured or
// dead upstream presents: it would have been logged at debug, invisible.
func TestShadowTLSRealRefusedDialIsAFault(t *testing.T) {
	dialErr, address := refusedDial(t)

	// The kernel's refusal must be a real *os.SyscallError, which is the shape the
	// classifier keys on.
	var opErr *net.OpError
	require.ErrorAs(t, dialErr, &opErr, "a refused dial is a *net.OpError")
	require.Equal(t, "dial", opErr.Op)

	var syscallErr *os.SyscallError
	require.ErrorAs(t, dialErr, &syscallErr, "and it carries a *os.SyscallError")
	require.Error(t, syscallErr.Err, "the syscall error must carry the errno as its cause")

	// The safety property: it must NOT be downgraded to debug.
	require.False(t, shadowTLSErrorIsExpected(dialErr),
		"a refused handshake-target dial is an operator-visible fault and must "+
			"stay at error level; silently logging it at debug is how a dead "+
			"upstream goes unnoticed (dialled %s)", address)
}

// TestTheRefusalIsNotOneOfThePeerLifecycleErrnos pins WHY the classifier reaches the
// answer it reaches, instead of only that it does.
//
// `isPeerLifecycleErrno` is the ONLY path in `isExpectedShadowTLSProbeFailure` that can
// downgrade a syscall error, so "a refusal is not in that set" is the whole reason the
// fault stays visible. A test that asserted only `shadowTLSErrorIsExpected == false`
// would keep passing if the classifier were rewritten to downgrade everything by some
// other route; this one fails in that case.
//
// # Why the errno is NOT compared to syscall.ECONNREFUSED
//
// It was, and that made this test platform- and locale-dependent in two independent ways:
//
//	Windows   returns WSAECONNREFUSED (10061) from a TCP dial, not ECONNREFUSED (61).
//	          They are different values in two different errno spaces, so errors.Is
//	          against syscall.ECONNREFUSED is FALSE on Windows even though the refusal
//	          is genuine - which is exactly what this test reported before the fix.
//	          (Go serves WSAECONNREFUSED with `//go:generate stringer`, so on newer
//	          toolchains `syscall.ECONNREFUSED.String()` prints "WSAECONNREFUSED" while
//	          comparing equal to neither the POSIX value nor a platform-worded message.)
//	localized The errno's Error() text is LOCALIZED by the OS: on a non-English Windows
//	          the cause reads "No connection could be made because the target machine
//	          actively refused it." in the system language, so any substring match on
//	          English text fails for reasons that have nothing to do with the product.
//
// The assertion below avoids both: it checks the PROPERTY the classifier depends on
// (the errno is not a peer-lifecycle errno) and that the cause is a real syscall errno,
// which holds on every platform and in every locale.
func TestTheRefusalIsNotOneOfThePeerLifecycleErrnos(t *testing.T) {
	dialErr, _ := refusedDial(t)

	var opErr *net.OpError
	require.ErrorAs(t, dialErr, &opErr)
	var syscallErr *os.SyscallError
	require.ErrorAs(t, opErr.Err, &syscallErr)

	var errno syscall.Errno
	require.ErrorAs(t, syscallErr.Err, &errno,
		"the cause must be a syscall.Errno, which is what the classifier inspects")

	require.False(t, isPeerLifecycleErrno(syscallErr.Err),
		"a connection REFUSAL must not be in the peer-lifecycle set (%v); if it ever "+
			"is, a dead handshake target starts being logged at debug, which is the "+
			"defect this whole file exists for", errno)

	// And the negative control, so the assertion above cannot pass for a classifier
	// that simply returns false for everything.
	for _, lifecycle := range []syscall.Errno{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE} {
		require.True(t, isPeerLifecycleErrno(lifecycle),
			"%v must remain classified as a peer-lifecycle errno: the refusal above is "+
				"only meaningful because the classifier can still say yes to something",
			lifecycle)
	}
}

// refusedDialCount makes the released-port dials distinguishable in a failure message.
var refusedDialCount atomic.Int64

// refusedDial produces a genuine connection refusal by binding a port, releasing it and
// dialling it.
//
// # Why the port is released rather than never bound
//
// A port that was never bound is refused by some stacks and filtered by others, and a
// filtered port times out instead - a different error class entirely. Binding first and
// closing makes the refusal the expected outcome on every platform this repository
// builds for.
//
// # Why a connection that is ACCEPTED is a failure, not a skip
//
// Something else can win the released port between the close and the dial, and the
// previous version of this test skipped in that case. A skip here is indistinguishable
// from a pass in a CI summary, and the property under test - "a refusal stays visible" -
// is one this file exists to guarantee, so an unproducible refusal must be REPORTED. The
// window is narrowed by retrying a few ports before giving up, so the report is rare
// rather than routine.
func refusedDial(t *testing.T) (dialErr error, address string) {
	t.Helper()
	const attempts = 8
	for attempt := 0; attempt < attempts; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		address = listener.Addr().String()
		require.NoError(t, listener.Close())

		conn, err := net.Dial("tcp", address)
		if err != nil {
			refusedDialCount.Add(1)
			return err, address
		}
		_ = conn.Close()
	}
	t.Fatalf("could not produce a connection refusal in %d attempts: something accepted a "+
		"connection on every released port. This is not a skip - the property under test "+
		"(that a refused handshake target stays operator-visible) could not be exercised, "+
		"so it must be reported rather than silently passing", attempts)
	return nil, ""
}

// TestRefusedDialProducesARefusal keeps the FIXTURE honest.
//
// `refusedDial` is shared by both tests above, so if it ever stopped producing a real
// refusal they would both start asserting against some other error while still passing.
// This pins what the fixture actually produces, and it is the only place the shape of the
// refusal is described - deliberately loose, because the values differ by platform.
func TestRefusedDialProducesARefusal(t *testing.T) {
	dialErr, address := refusedDial(t)
	require.Error(t, dialErr)
	require.NotEmpty(t, address)

	var opErr *net.OpError
	require.ErrorAs(t, dialErr, &opErr, "a refused dial must be a *net.OpError")
	require.Equal(t, "dial", opErr.Op, "and it must be the DIAL that failed, not a later operation")
	require.Error(t, opErr.Err, "the dial must carry its cause")

	// A refusal is not a timeout: the classifier treats a dial TIMEOUT as a fault for the
	// same reason, but by a different branch, so a fixture that had drifted into timing
	// out would exercise the other branch while still looking correct.
	var netErr net.Error
	if errors.As(dialErr, &netErr) {
		require.False(t, netErr.Timeout(),
			"the fixture produced a TIMEOUT rather than a refusal; the two take different "+
				"branches in the classifier, so the tests above would not be testing what "+
				"they claim")
	}
}
