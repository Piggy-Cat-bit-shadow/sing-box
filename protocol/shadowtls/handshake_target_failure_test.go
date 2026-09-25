package shadowtls

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// A refused HANDSHAKE TARGET dial must be classified as a fault, using a real
// syscall error rather than a synthesised one.
//
// The unit matrix asserts the classification of hand-built errnos. This test goes
// one step further and produces a genuine ECONNREFUSED by dialling a port that
// nothing is listening on, so the classifier is shown to work against the error
// the kernel actually returns rather than against an approximation of it.
//
// This matters because the earlier classifier downgraded every *os.SyscallError,
// and a refused dial on the handshake target is exactly how a misconfigured or
// dead upstream presents: it would have been logged at debug, invisible.
func TestShadowTLSRealRefusedDialIsAFault(t *testing.T) {
	// Bind and immediately release a port so it is almost certainly free.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	conn, dialErr := net.Dial("tcp", address)
	if dialErr == nil {
		_ = conn.Close()
		t.Skip("something accepted the connection on the released port, so a " +
			"refusal could not be produced; this is a SKIP, not a pass")
	}

	// The kernel's refusal must be a real *os.SyscallError carrying ECONNREFUSED,
	// which is the shape the classifier keys on.
	var opErr *net.OpError
	require.ErrorAs(t, dialErr, &opErr, "a refused dial is a *net.OpError")
	require.Equal(t, "dial", opErr.Op)

	var syscallErr *os.SyscallError
	require.ErrorAs(t, dialErr, &syscallErr, "and it carries a *os.SyscallError")
	require.ErrorIs(t, syscallErr.Err, syscall.ECONNREFUSED,
		"the errno is ECONNREFUSED; if this ever changes the matrix must change "+
			"with it")

	// The safety property: it must NOT be downgraded to debug.
	require.False(t, shadowTLSErrorIsExpected(dialErr),
		"a refused handshake-target dial is an operator-visible fault and must "+
			"stay at error level; silently logging it at debug is how a dead "+
			"upstream goes unnoticed")
}
