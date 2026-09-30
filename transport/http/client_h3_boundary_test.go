//go:build with_quic

package http

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
)

// Regression tests for the CLIENT TUNNEL error boundary.
//
// # Why this file exists separately from the classifier tables
//
// The classifier tests prove that normalizeStreamError classifies correctly. They do NOT prove
// that production calls it. Those are different claims, and the difference is where this bug
// lived:
//
//	classifier correct  !=  production path reaches the classifier
//
// The client tunnel returns *http3StreamConn to route/conn.go, which decides the log level with
//
//	if !E.IsClosedOrCanceled(err) {
//	    m.logger.ErrorContext(ctx, "connection upload closed: ", err)
//	}
//
// http3StreamConn.wrapError used to return the raw qtls.WrapError(err), and that wrapper cannot
// express "closed" precisely: every quic-go error type implements Unwrap() returning
// net.ErrClosed whatever its code is, so a real fault satisfied E.IsClosedOrCanceled and
// disappeared from the logs. The wrapper's own typed switch never ran, because its first line
// delegates to errors.Is on the raw error -- and even without that line, errors.Is would still
// traverse Unwrap().
//
// These tests therefore drive wrapError itself, which is the function on the production path.

// TestTunnelBoundaryExpectedClosuresStayQuiet pins the events that must not become ERROR noise.
func TestTunnelBoundaryExpectedClosuresStayQuiet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		err  error
		why  string
	}{
		{
			name: "peer cancels the request stream (H3_REQUEST_CANCELLED)",
			err:  &quic.StreamError{StreamID: 184, ErrorCode: 268, Remote: true},
			why:  "the peer abandoned one request stream; the connection stays usable",
		},
		{
			name: "local stream reset with no error",
			err:  &quic.StreamError{StreamID: 4, ErrorCode: 0, Remote: false},
			why:  "the client closed its own stream without raising a condition",
		},
		{
			name: "orderly transport close",
			err:  &quic.TransportError{ErrorCode: quic.NoError},
			why:  "no error code raised",
		},
		{
			name: "orderly application close",
			err:  &quic.ApplicationError{ErrorCode: 0},
			why:  "code 0 is the no-error value, not http3.ErrCodeNoError (0x100)",
		},
		{
			name: "idle timeout",
			err:  &quic.IdleTimeoutError{},
			why:  "the connection simply went inactive",
		},
		{
			name: "handshake timeout",
			err:  &quic.HandshakeTimeoutError{},
			why:  "the handshake never completed",
		},
		{
			name: "http3 no error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeNoError},
			why:  "orderly HTTP/3 shutdown",
		},
		{
			name: "http3 request cancelled",
			err:  &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled},
			why:  "same code as 268 in its http3.Error spelling",
		},
	}

	// A conn that is not closed, so wrapError takes the classification path rather than the
	// local "already closed" shortcut.
	conn := &http3StreamConn{}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			boundary := conn.wrapError(testCase.err)
			if !E.IsClosedOrCanceled(boundary) {
				t.Fatalf("the tunnel boundary must report this as an expected closure, otherwise "+
					"route/conn.go logs it at ERROR -- %s; got %v", testCase.why, boundary)
			}
		})
	}
}

// TestTunnelBoundaryRealFaultsStayVisible is the other half, and the one that was broken.
//
// Each of these is a genuine fault that unwraps to net.ErrClosed in quic-go. Before the boundary
// normalisation they all satisfied E.IsClosedOrCanceled and were erased from the logs.
func TestTunnelBoundaryRealFaultsStayVisible(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		err  error
		why  string
		// alreadyVisible marks a fault that never unwrapped to net.ErrClosed, and so was never
		// silenced. The premise guard below is skipped for those, because it asserts the very
		// property that made the others fail.
		alreadyVisible bool
	}{
		{
			name: "transport protocol violation",
			err:  &quic.TransportError{ErrorCode: 0xa, ErrorMessage: "PROTOCOL_VIOLATION"},
			why:  "the peer broke the transport protocol",
		},
		{
			name: "transport frame encoding error",
			err:  &quic.TransportError{ErrorCode: 0x7, ErrorMessage: "FRAME_ENCODING_ERROR"},
			why:  "a malformed frame is a fault, not a teardown",
		},
		{
			name: "application error with a fault code",
			err:  &quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeInternalError)},
			why:  "the peer reported a fault in its own code space",
		},
		{
			name: "stream internal error",
			err:  &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError)},
			why:  "the peer hit an internal error on this stream",
			// StreamError does NOT unwrap to net.ErrClosed; it was already visible. It is kept
			// here so the boundary is pinned for the whole fault surface, not only the part that
			// was broken.
			alreadyVisible: true,
		},
		{
			name: "stateless reset",
			err:  &quic.StatelessResetError{},
			why:  "the path was torn down without a close",
		},
		{
			name: "version negotiation failure",
			err:  &quic.VersionNegotiationError{},
			why:  "no usable QUIC version was agreed",
		},
		{
			name:           "http3 internal error",
			err:            &http3.Error{ErrorCode: http3.ErrCodeInternalError},
			why:            "an internal HTTP/3 fault",
			alreadyVisible: true,
		},
		{
			name:           "plain unclassified error",
			err:            errors.New("something genuinely went wrong"),
			why:            "an unknown error must never be assumed benign",
			alreadyVisible: true,
		},
	}

	conn := &http3StreamConn{}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if !testCase.alreadyVisible {
				// Guard the premise: if this error no longer unwraps to net.ErrClosed, the test
				// would pass for the wrong reason and stop detecting the bug it was written for.
				if !errors.Is(testCase.err, net.ErrClosed) {
					t.Fatalf("%s is expected to unwrap to net.ErrClosed; without that this test "+
						"no longer exercises the wrapping problem it exists for", testCase.name)
				}
				if !errors.Is(qtls.WrapError(testCase.err), net.ErrClosed) {
					t.Fatalf("%s: the shared wrapper is expected to still leak net.ErrClosed; if "+
						"that changed, this boundary work is redundant and should be reconsidered",
						testCase.name)
				}
			}

			boundary := conn.wrapError(testCase.err)
			if E.IsClosedOrCanceled(boundary) {
				t.Fatalf("the tunnel boundary silenced a real fault (%s): %v -- it would be "+
					"reported as an ordinary teardown and never reach the logs",
					testCase.why, boundary)
			}
			// The message must survive so an operator can still see WHAT failed.
			if boundary.Error() == "" {
				t.Fatalf("%s: the fault must keep a readable message", testCase.name)
			}
		})
	}
}

// TestTunnelBoundaryClosedConnShortCircuits pins the local shortcut.
//
// Once this conn is marked closed, its own state is the most specific fact available and the
// boundary reports a closure without re-classifying the underlying error.
func TestTunnelBoundaryClosedConnShortCircuits(t *testing.T) {
	t.Parallel()

	conn := &http3StreamConn{}
	conn.closed.Store(true)

	// Even a fault is reported as closed once this stream is known to be closed: the tunnel is
	// over, and the error is no longer actionable for this conn.
	fault := &quic.TransportError{ErrorCode: 0xa}
	if got := conn.wrapError(fault); !errors.Is(got, net.ErrClosed) {
		t.Fatalf("a closed conn must report closure, got %v", got)
	}
	if got := conn.wrapError(nil); got != nil {
		t.Fatalf("a nil error must stay nil, got %v", got)
	}
}

// TestTunnelBoundaryPreservesFaultIdentity proves the boundary does not fix visibility by
// destroying the error's type.
//
// Callers legitimately inspect the underlying condition -- the DNS-over-QUIC retry classifier is
// one -- so a fix that made faults visible by flattening them to strings would trade one bug for
// another. A visibleFault deliberately does not unwrap to the misleading sentinel, but it does
// expose the original through Cause().
func TestTunnelBoundaryPreservesFaultIdentity(t *testing.T) {
	t.Parallel()

	conn := &http3StreamConn{}
	fault := &quic.TransportError{ErrorCode: 0xa, ErrorMessage: "PROTOCOL_VIOLATION"}

	boundary := conn.wrapError(fault)

	var visible *visibleFault
	if !errors.As(boundary, &visible) {
		t.Fatalf("a real fault must be reported through visibleFault, got %T", boundary)
	}
	if visible.Cause() == nil {
		t.Fatal("the original error must remain reachable through Cause()")
	}
	if visible.Cause().Error() != fault.Error() {
		t.Fatalf("Cause() must preserve the original message: got %q, want %q",
			visible.Cause().Error(), fault.Error())
	}
	// And the sentinel must NOT be reachable, which is what makes the fault visible.
	var transportErr *quic.TransportError
	if errors.As(boundary, &transportErr) {
		t.Fatal("a visibleFault must not let errors.As reach the quic-go type, because that " +
			"traversal is one of the two paths by which the misleading net.ErrClosed leaked in")
	}
}
