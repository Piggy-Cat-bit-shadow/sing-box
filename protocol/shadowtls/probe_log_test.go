package shadowtls

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
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
			name: "peer reset",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "read", Err: errors.New("connection reset by peer")},
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
