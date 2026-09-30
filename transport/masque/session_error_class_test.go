//go:build with_quic

package masque

import (
	"context"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
)

// TestSessionFailureClassification pins how a finished tunnel is reported.
//
// session.run returns context.Cause, which carries whatever the capsule or datagram loop
// produced -- including a raw HTTP/3 stream error. The server decides the log level from that
// value, so the decision is asserted here rather than left to the classifier package.
//
// The generic closed/canceled test on its own is not sufficient: every quic-go error type
// unwraps to net.ErrClosed whatever its code is, so a protocol fault would be reported as an
// ordinary teardown and dropped to Debug.
func TestSessionFailureClassification(t *testing.T) {
	t.Parallel()

	// shouldLog reports whether the server logs this at ERROR. It calls the production helper
	// itself, so the test cannot drift from the decision it is pinning.
	shouldLog := func(err error) bool {
		return err != nil && !sessionErrorIsExpected(err)
	}

	expected := []struct {
		name string
		err  error
	}{
		{"context canceled", context.Canceled},
		{"context deadline", context.DeadlineExceeded},
		{"orderly transport close", &quic.TransportError{ErrorCode: quic.NoError}},
		{"orderly application close", &quic.ApplicationError{ErrorCode: 0}},
		{"idle timeout", &quic.IdleTimeoutError{}},
		{"handshake timeout", &quic.HandshakeTimeoutError{}},
		{"peer cancels the request stream", &quic.StreamError{ErrorCode: 268, Remote: true}},
		{"http3 no error", &http3.Error{ErrorCode: http3.ErrCodeNoError}},
		{"http3 request cancelled", &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled}},
	}
	for _, testCase := range expected {
		t.Run("quiet/"+testCase.name, func(t *testing.T) {
			if shouldLog(testCase.err) {
				t.Fatalf("an expected tunnel end must stay at Debug: %v", testCase.err)
			}
		})
	}

	faults := []struct {
		name string
		err  error
	}{
		{"transport protocol violation", &quic.TransportError{ErrorCode: 0xa}},
		{"transport frame encoding error", &quic.TransportError{ErrorCode: 0x7}},
		{"application error with a fault code", &quic.ApplicationError{ErrorCode: 0x102}},
		{"stream internal error", &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError)}},
		{"stateless reset", &quic.StatelessResetError{}},
		{"version negotiation failure", &quic.VersionNegotiationError{}},
		{"http3 internal error", &http3.Error{ErrorCode: http3.ErrCodeInternalError}},
	}
	for _, testCase := range faults {
		t.Run("visible/"+testCase.name, func(t *testing.T) {
			if !shouldLog(testCase.err) {
				t.Fatalf("a real tunnel fault must be operator-visible: %v", testCase.err)
			}
			// Report which cases the generic test alone would have silenced. Those are the ones
			// that actually needed the typed predicate; the others were already visible and are
			// pinned for completeness.
			if E.IsClosedOrCanceled(testCase.err) {
				t.Logf("%s: the generic closed/canceled test alone would have silenced this "+
					"fault; the typed predicate is what keeps it visible", testCase.name)
			}
		})
	}
}
