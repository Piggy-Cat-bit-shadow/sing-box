package shadowtls

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// These tests pin the ShadowTLS probe-failure log classification.
//
// The ShadowTLS inbound sits directly behind the public TCP/443 front door. A
// scanner that sends something which is not a TLS ClientHello, or that sends a
// truncated record and disconnects, is routine traffic; logging each one at
// error level floods the log and buries real faults.

// TestShadowTLSProbeFailuresAreExpected covers the errors a prober produces.
func TestShadowTLSProbeFailuresAreExpected(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{name: "nil", err: nil},
		{name: "io.EOF", err: io.EOF},
		// A non-TLS probe that sends a partial record: the runtime shape is
		// "read client handshake: unexpected EOF".
		{
			name: "truncated record",
			err:  E.Cause(io.ErrUnexpectedEOF, "read client handshake"),
		},
		{name: "net.ErrClosed", err: net.ErrClosed},
		{name: "io.ErrClosedPipe", err: io.ErrClosedPipe},
		{name: "context canceled", err: context.Canceled},
		{name: "context deadline", err: context.DeadlineExceeded},
		{
			name: "read deadline exceeded",
			err:  &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
		},
		{
			// A real reset is a syscall.Errno, not a message string. The previous
			// version of this case built the error from errors.New, so it never
			// exercised the errno path and passed for the wrong reason.
			name: "peer reset",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.True(t, shadowTLSErrorIsExpected(testCase.err),
				"%v must be treated as an expected probe failure", testCase.err)
		})
	}
}

// TestUnexpectedShadowTLSFailuresStayErrors is the safety half: a real fault must
// never be swallowed. A handshake TARGET that is unreachable, for example, is an
// operator-visible problem and must stay at error level.
func TestUnexpectedShadowTLSFailuresStayErrors(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{name: "generic fault", err: errors.New("something genuinely went wrong")},
		{
			name: "handshake target unreachable",
			err:  E.Cause(errors.New("dial tcp 10.0.0.1:443: connect: network is unreachable"), "server handshake"),
		},
		{
			name: "no users configured",
			err:  E.New("missing users"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.False(t, shadowTLSErrorIsExpected(testCase.err),
				"%v is not a probe failure and must stay visible", testCase.err)
		})
	}
}

// TestShadowTLSClassificationIsNotStringBased proves the classifier keys on error
// TYPES, not message text. An error that merely looks like a truncated record
// must not be downgraded.
func TestShadowTLSClassificationIsNotStringBased(t *testing.T) {
	impostor := errors.New("read client handshake: unexpected EOF")
	require.False(t, shadowTLSErrorIsExpected(impostor),
		"an error that merely LOOKS like a truncated record must not be downgraded; "+
			"classification must use types, not message text")

	// The converse: a genuine typed timeout is recognised whatever it says.
	realTimeout := &net.OpError{Op: "read", Net: "tcp", Err: timeoutError{}}
	require.True(t, shadowTLSErrorIsExpected(realTimeout))
}

// timeoutError is a minimal net.Error whose Timeout method returns true.
type timeoutError struct{}

func (timeoutError) Error() string   { return "no useful message" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestShadowTLSErrnoClassification pins the errno matrix.
//
// The previous classifier downgraded ANY *os.SyscallError to debug. Because the
// inbound dials its handshake target, a failed dial arrives in exactly that shape:
//
//	*net.OpError{Op: "dial"} -> *os.SyscallError{connect, ECONNREFUSED}
//
// so a configured handshake target that was down or unreachable was silently
// logged at debug - the operator's own upstream failing, hidden as scanner noise.
// The matrix below is the contract: only errnos that describe the peer going away
// or the local lifecycle are downgraded.
func TestShadowTLSErrnoClassification(t *testing.T) {
	dialErr := func(errno syscall.Errno) error {
		return &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: &os.SyscallError{Syscall: "connect", Err: errno},
		}
	}
	readErr := func(errno syscall.Errno) error {
		return &net.OpError{
			Op:  "read",
			Net: "tcp",
			Err: &os.SyscallError{Syscall: "read", Err: errno},
		}
	}

	t.Run("handshake target dial failures stay visible", func(t *testing.T) {
		for _, testCase := range []struct {
			name  string
			errno syscall.Errno
		}{
			{"ECONNREFUSED", syscall.ECONNREFUSED},
			{"ENETUNREACH", syscall.ENETUNREACH},
			{"EHOSTUNREACH", syscall.EHOSTUNREACH},
			{"ETIMEDOUT", syscall.ETIMEDOUT},
			{"EACCES", syscall.EACCES},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				err := E.Cause(dialErr(testCase.errno), "server handshake")
				require.False(t, shadowTLSErrorIsExpected(err),
					"a handshake-target dial failure (%s) is an operator-visible "+
						"fault and must stay at error level", testCase.name)
			})
		}
	})

	t.Run("peer lifecycle errors are downgraded", func(t *testing.T) {
		for _, testCase := range []struct {
			name  string
			errno syscall.Errno
		}{
			{"ECONNRESET", syscall.ECONNRESET},
			{"ECONNABORTED", syscall.ECONNABORTED},
			{"EPIPE", syscall.EPIPE},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				require.True(t, shadowTLSErrorIsExpected(readErr(testCase.errno)),
					"%s describes the peer going away and is a routine probe "+
						"outcome", testCase.name)
			})
		}
	})

	t.Run("the same errno is judged the same in either direction", func(t *testing.T) {
		// ECONNRESET on a dial is unusual but still a peer-side outcome; the
		// classifier keys on the errno, not on the operation, so it must not
		// depend on Op.
		require.True(t, shadowTLSErrorIsExpected(dialErr(syscall.ECONNRESET)))
		require.False(t, shadowTLSErrorIsExpected(readErr(syscall.ECONNREFUSED)))
	})
}

// TestShadowTLSClassificationSurvivesWrapping proves the classifier sees through
// the exception chain the service actually produces.
//
// The service wraps its errors ("server handshake", "read client handshake"), so
// a classifier that only inspected the top-level error would misjudge everything.
func TestShadowTLSClassificationSurvivesWrapping(t *testing.T) {
	refused := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
	}
	wrapped := E.Cause(E.Cause(refused, "dial handshake target"), "server handshake")
	require.False(t, shadowTLSErrorIsExpected(wrapped),
		"a wrapped handshake-target refusal must still be visible")
}
