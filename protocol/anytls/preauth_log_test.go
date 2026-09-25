package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// These tests pin the pre-authentication log classification.
//
// The problem being solved: a public scanner that completes the TLS handshake
// and then sends nothing, or that disconnects mid-handshake, is routine traffic.
// Logging each one at error level turns ordinary scanning into an error-log
// flood and buries real faults. The classification must therefore be typed, not
// string-matched, and anything unrecognised must stay at error level.

// TestExpectedPreAuthFailuresAreDowngraded covers the errors a prober actually
// produces.
func TestExpectedPreAuthFailuresAreDowngraded(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{name: "nil", err: nil},
		{name: "io.EOF", err: io.EOF},
		{name: "io.ErrUnexpectedEOF", err: io.ErrUnexpectedEOF},
		{name: "net.ErrClosed", err: net.ErrClosed},
		{name: "io.ErrClosedPipe", err: io.ErrClosedPipe},
		{name: "context canceled", err: context.Canceled},
		{name: "context deadline", err: context.DeadlineExceeded},
		{
			name: "read deadline exceeded",
			err:  &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
		},
		{
			// The exact shape the one-shot pre-auth timeout produces, wrapped the
			// way the runtime wraps it.
			//
			// Note the argument order: E.Cause(cause, message...) keeps cause as
			// the UNWRAPPABLE error and prepends the message. Reversing the
			// arguments produces a causeError whose Unwrap returns the message
			// text instead, so errors.As/errors.Is find nothing -- which is how
			// an earlier version of this classifier silently missed the real
			// timeout.
			name: "wrapped pre-auth timeout",
			err: E.Cause(
				&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
				"anytls: read request",
			),
		},
		{
			// A real reset is a syscall.Errno, not a message string. The previous
			// version built this from errors.New, so it never exercised the errno
			// path and passed for the wrong reason.
			name: "peer reset",
			err:  &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.True(t, isExpectedPreAuthFailure(testCase.err),
				"%v must be treated as an expected pre-auth lifecycle event", testCase.err)
			require.False(t, preAuthFailureIsError(testCase.err),
				"%v must not be logged at error level", testCase.err)
		})
	}
}

// TestUnexpectedPreAuthFailuresStayErrors is the safety half: a real fault must
// never be swallowed by this classification. If this test starts failing because
// a new error was added to the "expected" set, that is a deliberate decision
// that needs justification, not a test to relax.
func TestUnexpectedPreAuthFailuresStayErrors(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{name: "generic fault", err: errors.New("something genuinely went wrong")},
		{name: "certificate failure", err: errors.New("tls: failed to find any PEM data in certificate input")},
		{name: "protocol corruption", err: E.New("anytls: unexpected padding scheme")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.False(t, isExpectedPreAuthFailure(testCase.err),
				"%v is not a recognised lifecycle event and must stay visible", testCase.err)
			require.True(t, preAuthFailureIsError(testCase.err),
				"%v must still be logged at error level", testCase.err)
		})
	}
}

// TestClassificationIsNotStringBased proves the classifier does not decide based
// on the error text. An error whose MESSAGE looks like a timeout but whose TYPE
// is not a net.Error must not be downgraded -- this is the anti-pattern the HTTP/3
// classifier in transport/http/h3_error_class.go also avoids.
func TestClassificationIsNotStringBased(t *testing.T) {
	impostor := errors.New("read tcp 127.0.0.1:1->127.0.0.1:2: i/o timeout")
	require.False(t, isExpectedPreAuthFailure(impostor),
		"an error that merely LOOKS like a timeout must not be downgraded; "+
			"classification must use types, not message text")
	require.True(t, preAuthFailureIsError(impostor))

	// And the converse: a genuine typed timeout with a different message is still
	// recognised.
	realTimeout := &net.OpError{Op: "read", Net: "tcp", Err: timeoutError{}}
	require.True(t, isExpectedPreAuthFailure(realTimeout),
		"a genuine typed timeout must be recognised regardless of its message")
}

// timeoutError is a minimal net.Error whose Timeout method returns true, used to
// prove the classifier keys on the interface rather than on a concrete type.
type timeoutError struct{}

func (timeoutError) Error() string   { return "some message that mentions nothing useful" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestPreAuthClassifierCoversTheRuntimeTimeout is an integration-flavoured guard:
// the real error produced by the one-shot read deadline must classify as
// expected, so the runtime path does not log it as an error.
func TestPreAuthClassifierCoversTheRuntimeTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := newFirstReadTimeoutConn(&plainTLSConn{Conn: server}, 100*time.Millisecond)

	readErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 8)
		_, err := wrapped.Read(buffer)
		readErr <- err
	}()

	select {
	case err := <-readErr:
		require.Error(t, err)
		require.True(t, isExpectedPreAuthFailure(err),
			"the runtime pre-auth timeout (%v) must classify as an expected event, "+
				"or every scanner that goes silent floods the error log", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the pre-auth read never timed out")
	}
}

// TestAnyTLSErrnoClassification pins the errno matrix.
//
// The previous classifier downgraded ANY *os.SyscallError to debug. AnyTLS dials
// its fallback backend, so a refused or unreachable backend arrives in exactly
// that shape - *net.OpError -> *os.SyscallError - and was silently logged at
// debug, hiding the operator's own failing upstream.
//
// The matrix is the contract: only errnos that describe the PEER going away are
// expected outcomes of a public scanner; anything describing a fault stays
// visible.
func TestAnyTLSErrnoClassification(t *testing.T) {
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

	t.Run("server-side faults stay visible", func(t *testing.T) {
		for _, testCase := range []struct {
			name  string
			errno syscall.Errno
		}{
			{"ECONNREFUSED", syscall.ECONNREFUSED},
			{"ENETUNREACH", syscall.ENETUNREACH},
			{"EHOSTUNREACH", syscall.EHOSTUNREACH},
			{"EACCES", syscall.EACCES},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				err := E.Cause(dialErr(testCase.errno), "dial fallback")
				require.False(t, isExpectedPreAuthFailure(err),
					"%s describes a fault the operator must see, not scanner noise",
					testCase.name)
				require.True(t, preAuthFailureIsError(err),
					"%s must be logged at error level", testCase.name)
			})
		}
	})

	t.Run("peer lifecycle errors are expected", func(t *testing.T) {
		for _, testCase := range []struct {
			name  string
			errno syscall.Errno
		}{
			{"ECONNRESET", syscall.ECONNRESET},
			{"ECONNABORTED", syscall.ECONNABORTED},
			{"EPIPE", syscall.EPIPE},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				require.True(t, isExpectedPreAuthFailure(readErr(testCase.errno)),
					"%s is a routine outcome when a public peer disconnects",
					testCase.name)
			})
		}
	})

	t.Run("a dial timeout is a fault, a read timeout is not", func(t *testing.T) {
		// A slow prober hitting the pre-auth read deadline is expected. A dial
		// that times out means the fallback backend did not answer, which is a
		// fault, so the same errno must be judged on the OPERATION.
		readTimeout := &net.OpError{Op: "read", Net: "tcp", Err: timeoutError{}}
		require.True(t, isExpectedPreAuthFailure(readTimeout),
			"a read timeout is the pre-auth timeout doing its job")

		dialTimeout := &net.OpError{Op: "dial", Net: "tcp", Err: timeoutError{}}
		require.False(t, isExpectedPreAuthFailure(dialTimeout),
			"a dial timeout means a configured backend is not answering and must "+
				"stay visible")
	})
}
