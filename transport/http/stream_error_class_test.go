//go:build with_quic

package http

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
)

// Regression tests for the client-side stream error classification.
//
// # The production symptom
//
// The logs were full of this, at ERROR level:
//
//	connection upload closed: stream 184 canceled by remote with error code 268
//	connection upload closed: stream 192 canceled by remote with error code 268
//
// 268 is 0x10c, H3_REQUEST_CANCELLED (RFC 9114 §8.1). It means the PEER abandoned ONE request
// stream. It says nothing about the HTTP/3 connection, which stays perfectly usable for every
// other multiplexed stream.
//
// # Why it was logged at ERROR
//
// The path is: http3StreamConn -> qtls.WrapError -> normalizingConn -> route/conn.go, which logs
// at ERROR unless E.IsClosedOrCanceled recognises the error.
//
// normalizeStreamError mapped `*quic.StreamError` to net.ErrClosed only when its code was 0. A
// peer-cancelled stream carries 268, so it fell through unchanged and route/conn.go logged it as
// a fault. The server-side classifier (classifyH3Error) already handled 268 correctly, so the two
// disagreed about the same error -- which is why these tests pin BOTH.
//
// # What must NOT change
//
// Silencing 268 by string or by blanket "any stream error is fine" would be wrong in the other
// direction: a genuine stream fault (a protocol error, an internal error) must still reach the
// logs. Every test here therefore has a companion assertion that a real fault is still visible.

// TestClientStreamCancellationIsNotAFault covers the exact error shape in the production log.
func TestClientStreamCancellationIsNotAFault(t *testing.T) {
	// The error as it actually arrives: a remote stream reset carrying H3_REQUEST_CANCELLED,
	// already wrapped by the client's own stream conn.
	remoteCancelled := &quic.StreamError{
		StreamID:  184,
		ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled),
		Remote:    true,
	}
	if http3.ErrCodeRequestCanceled != 0x10c {
		t.Fatalf("H3_REQUEST_CANCELLED must be 0x10c per RFC 9114 §8.1, got 0x%x",
			uint64(http3.ErrCodeRequestCanceled))
	}
	if remoteCancelled.Error() != "stream 184 canceled by remote with error code 268" {
		t.Fatalf("test does not reproduce the production error string: %q", remoteCancelled.Error())
	}

	normalized := normalizeStreamError(qtls.WrapError(remoteCancelled))
	if !E.IsClosedOrCanceled(normalized) {
		t.Fatalf("a peer cancelling one request stream must be an expected closure, otherwise "+
			"route/conn.go logs it at ERROR; got %v", normalized)
	}

	// The local variant (this client cancelling its own request) is equally expected.
	localCancelled := &quic.StreamError{
		StreamID:  192,
		ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled),
		Remote:    false,
	}
	if !E.IsClosedOrCanceled(normalizeStreamError(qtls.WrapError(localCancelled))) {
		t.Fatal("a locally cancelled request stream must be an expected closure")
	}

	// The http3.Error spelling of the same code must keep working.
	h3Cancelled := &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled, Remote: true}
	if !E.IsClosedOrCanceled(normalizeStreamError(h3Cancelled)) {
		t.Fatal("http3.Error carrying ErrCodeRequestCanceled must be an expected closure")
	}
}

// TestClientStreamFaultsAreStillReported is the other half: the fix must not silence real faults.
//
// Without this, "cancel everything quietly" would pass the test above while hiding the very
// failures the logs are supposed to surface.
func TestClientStreamFaultsAreStillReported(t *testing.T) {
	faults := []struct {
		name string
		err  error
	}{
		{
			name: "h3 internal error",
			err:  &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError), Remote: true},
		},
		{
			name: "h3 general protocol error",
			err:  &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeGeneralProtocolError), Remote: true},
		},
		{
			name: "h3 frame unexpected",
			err:  &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeFrameUnexpected), Remote: true},
		},
		{
			name: "h3 settings error",
			err:  &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeSettingsError), Remote: true},
		},
		{
			name: "http3 internal error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeInternalError, Remote: true},
		},
		{
			name: "http3 message error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeMessageError, Remote: true},
		},
		{
			name: "transport protocol violation",
			err:  &quic.TransportError{ErrorCode: quic.TransportErrorCode(0xa), ErrorMessage: "protocol violation"},
		},
		{
			name: "plain error",
			err:  errors.New("something genuinely went wrong"),
		},
	}
	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			normalized := normalizeStreamError(qtls.WrapError(fault.err))
			// route/conn.go re-tests the NORMALIZED error, so this is the production decision.
			if E.IsClosedOrCanceled(normalized) {
				t.Fatalf("%s must remain visible: a real stream fault that is classified as an "+
					"expected closure disappears from the logs entirely", fault.name)
			}
		})
	}
}

// TestClientIdleTimeoutIsNotAFault pins the OTHER production log line.
//
//	HTTP/3 CONNECT: read CONNECT response: http3: parsing frame failed:
//	timeout: no recent network activity
//
// "no recent network activity" is quic.StreamError-free: it is *qerr.IdleTimeoutError, whose
// Unwrap() returns net.ErrClosed. That means it was ALREADY classified as an expected closure
// before this change, so it was never the source of the ERROR-level noise -- a distinction worth
// pinning, because the obvious guess is that both log lines share one cause.
//
// It is still asserted here because the classification must survive: an idle timeout is a normal
// connection death, not a fault to shout about.
func TestClientIdleTimeoutIsNotAFault(t *testing.T) {
	idle := &quic.IdleTimeoutError{}
	if idle.Error() != "timeout: no recent network activity" {
		t.Fatalf("test does not reproduce the production error string: %q", idle.Error())
	}
	// It unwraps to net.ErrClosed on its own, which is exactly why it was already quiet.
	if !errors.Is(idle, net.ErrClosed) {
		t.Fatal("IdleTimeoutError is expected to unwrap to net.ErrClosed")
	}
	if !E.IsClosedOrCanceled(normalizeStreamError(idle)) {
		t.Fatal("an idle timeout must be an expected closure")
	}
	// Including through the http3 frame-parsing wrapper seen in the log.
	frameWrapped := errors.Join(errors.New("http3: parsing frame failed"), idle)
	if !E.IsClosedOrCanceled(normalizeStreamError(frameWrapped)) {
		t.Fatal("an idle timeout wrapped by the frame parser must still be an expected closure")
	}
}

// TestStreamAndConnectionClassifiersAgree is the drift guard.
//
// The client normalizes with classifyH3ErrorCode (via normalizeStreamError) and the server decides
// with classifyH3Error. When those two disagree about the same error, one side logs a fault the
// other considers routine -- which is precisely how this bug survived: the server already had the
// right table and the client did not consult it.
func TestStreamAndConnectionClassifiersAgree(t *testing.T) {
	codes := []http3.ErrCode{
		http3.ErrCodeNoError,
		http3.ErrCodeRequestCanceled,
		http3.ErrCodeRequestRejected,
		http3.ErrCodeRequestIncomplete,
		http3.ErrCodeVersionFallback,
		http3.ErrCodeInternalError,
		http3.ErrCodeGeneralProtocolError,
		http3.ErrCodeFrameUnexpected,
		http3.ErrCodeSettingsError,
		http3.ErrCodeMessageError,
	}
	for _, code := range codes {
		// Every spelling of one code must land in the same class on both paths.
		streamError := &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(code), Remote: true}
		h3Error := &http3.Error{ErrorCode: code, Remote: true}

		if classifyH3Error(streamError) != classifyH3Error(h3Error) {
			t.Fatalf("code 0x%x classifies differently as a StreamError (%v) and an http3.Error "+
				"(%v); the two spellings describe the same condition",
				uint64(code), classifyH3Error(streamError), classifyH3Error(h3Error))
		}

		// And the client normalizer must agree with the classifier about what is expected.
		expected := classifyH3Error(streamError) == h3ErrorExpected
		silenced := E.IsClosedOrCanceled(normalizeStreamError(streamError))
		if silenced != expected {
			t.Fatalf("code 0x%x: classifier says expected=%v but the client normalizer says "+
				"silenced=%v; a disagreement means one side logs a fault the other calls routine",
				uint64(code), expected, silenced)
		}
	}
}

// TestStreamErrorClassificationTable is the COMPLETE enumeration of the quic-go error surface.
//
// # Why a full table, rather than the cases that happened to come up
//
// The two previous rounds each fixed the type that had been observed in the logs, and each time
// the fix left a sibling type behind:
//
//	round 1  *quic.StreamError with code 0 was handled; code 268 was not
//	round 2  *quic.TransportError was handled; *quic.ApplicationError was not
//
// Both mistakes have the same shape: the classifier knew about the types someone had seen, and
// every OTHER quic-go type silently inherited "expected closure", because they all implement
// Unwrap() -> net.ErrClosed. A table over the whole surface is what stops that from recurring.
//
// Every quic-go error type in the pinned fork is listed: TransportError, ApplicationError,
// VersionNegotiationError, StatelessResetError, IdleTimeoutError and HandshakeTimeoutError.
func TestStreamErrorClassificationTable(t *testing.T) {
	transportViolation := &quic.TransportError{
		ErrorCode:    quic.TransportErrorCode(0xa),
		ErrorMessage: "PROTOCOL_VIOLATION",
	}
	applicationFault := &quic.ApplicationError{
		ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeInternalError),
	}

	testCases := []struct {
		name string
		err  error
		// quiet is the expected classification: true means "normal teardown, do not log as a
		// fault", false means "must remain visible".
		quiet bool
		// typedSemantics declares whether this error carries quic-go or HTTP/3 semantics, and
		// therefore whether the two classifiers MUST agree about it.
		//
		// This is declared per row rather than inferred. The previous revision inferred it with a
		// hand-written isQuicTyped() whitelist listing four types, which silently omitted
		// StatelessResetError, VersionNegotiationError, IdleTimeoutError and
		// HandshakeTimeoutError -- so those rows never executed the agreement assertion at all.
		// An inferred predicate that can be incomplete is exactly how a coverage hole hides; a
		// declared field cannot omit a row without the row visibly lacking it.
		typedSemantics bool
		why            string
	}{
		// ---- expected: the peer or the client ended things normally ----
		{
			name:           "stream reset H3_REQUEST_CANCELLED remote",
			typedSemantics: true,
			err:            &quic.StreamError{StreamID: 184, ErrorCode: 268, Remote: true},
			quiet:          true,
			why:            "the peer abandoned ONE request stream; the connection stays usable",
		},
		{
			name:           "stream reset H3_REQUEST_CANCELLED local",
			typedSemantics: true,
			err:            &quic.StreamError{StreamID: 184, ErrorCode: 268, Remote: false},
			quiet:          true,
			why:            "this client abandoned its own request",
		},
		{
			name:           "stream reset code 0",
			typedSemantics: true,
			err:            &quic.StreamError{StreamID: 4, ErrorCode: 0, Remote: false},
			quiet:          true,
			why:            "no-error stream close",
		},
		{
			name:           "transport error no-error code",
			typedSemantics: true,
			err:            &quic.TransportError{ErrorCode: quic.NoError},
			quiet:          true,
			why:            "orderly transport shutdown",
		},
		{
			name:           "application error no-error code",
			typedSemantics: true,
			err:            &quic.ApplicationError{ErrorCode: 0},
			quiet:          true,
			why:            "orderly application shutdown",
		},
		{
			name:           "idle timeout",
			typedSemantics: true,
			err:            &quic.IdleTimeoutError{},
			quiet:          true,
			why:            "the connection simply went inactive",
		},
		{
			name:           "handshake timeout",
			typedSemantics: true,
			err:            &quic.HandshakeTimeoutError{},
			quiet:          true,
			why:            "the handshake never completed",
		},
		{
			name:           "http3 ErrCodeNoError",
			typedSemantics: true,
			err:            &http3.Error{ErrorCode: http3.ErrCodeNoError, Remote: true},
			quiet:          true,
			why:            "orderly HTTP/3 shutdown",
		},
		{
			name:           "http3 ErrCodeRequestCanceled",
			typedSemantics: true,
			err:            &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled, Remote: true},
			quiet:          true,
			why:            "the same code as 268, in its http3.Error spelling",
		},
		{
			name:           "context canceled",
			typedSemantics: false,
			err:            context.Canceled,
			quiet:          true,
			why:            "the caller gave up",
		},
		{
			name:           "context deadline exceeded",
			typedSemantics: false,
			err:            context.DeadlineExceeded,
			quiet:          true,
			why:            "the caller's deadline expired",
		},
		{
			name:           "bare net.ErrClosed",
			typedSemantics: false,
			err:            net.ErrClosed,
			quiet:          true,
			why:            "a plain closed connection carries no quic-go fault semantics",
		},
		{
			name:           "io.EOF",
			typedSemantics: false,
			err:            io.EOF,
			quiet:          true,
			why:            "normal end of stream",
		},

		// ---- real faults: must stay visible ----
		{
			name:           "stream reset internal error",
			typedSemantics: true,
			err:            &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError), Remote: true},
			quiet:          false,
			why:            "the peer hit an internal error on this stream",
		},
		{
			name:           "stream reset general protocol error",
			typedSemantics: true,
			err:            &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeGeneralProtocolError), Remote: true},
			quiet:          false,
			why:            "a protocol violation",
		},
		{
			name:           "stream reset frame unexpected",
			typedSemantics: true,
			err:            &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeFrameUnexpected), Remote: true},
			quiet:          false,
			why:            "the peer sent a frame this state machine forbids",
		},
		{
			name:           "stream reset settings error",
			typedSemantics: true,
			err:            &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeSettingsError), Remote: true},
			quiet:          false,
			why:            "a SETTINGS exchange failure",
		},
		{
			name:           "transport PROTOCOL_VIOLATION",
			typedSemantics: true,
			err:            transportViolation,
			quiet:          false,
			why:            "a transport fault that unwraps to net.ErrClosed and would otherwise be erased",
		},
		{
			name:           "application error with a fault code",
			typedSemantics: true,
			err:            applicationFault,
			quiet:          false,
			why:            "the peer reported a fault in its own code space",
		},
		{
			name:           "stateless reset",
			typedSemantics: true,
			err:            &quic.StatelessResetError{},
			quiet:          false,
			why:            "the path was torn down without a close; notable on an active tunnel",
		},
		{
			name:           "version negotiation failure",
			typedSemantics: true,
			err:            &quic.VersionNegotiationError{},
			quiet:          false,
			why:            "no usable QUIC version was agreed, so nothing was established",
		},
		{
			name:           "http3 ErrCodeInternalError",
			typedSemantics: true,
			err:            &http3.Error{ErrorCode: http3.ErrCodeInternalError, Remote: true},
			quiet:          false,
			why:            "an internal HTTP/3 fault",
		},
		{
			name:           "http3 ErrCodeMessageError",
			typedSemantics: true,
			err:            &http3.Error{ErrorCode: http3.ErrCodeMessageError, Remote: true},
			quiet:          false,
			why:            "a malformed HTTP/3 message",
		},
		{
			name:           "plain unclassified error",
			typedSemantics: false,
			err:            errors.New("something genuinely went wrong"),
			quiet:          false,
			why:            "an unknown error must never be assumed benign",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Both the wrapped and unwrapped spellings must classify identically: the client
			// always sees the qtls-wrapped form on the stream path, while the classifier sees
			// whichever the caller passes.
			for _, input := range []struct {
				label string
				err   error
			}{
				{"unwrapped", testCase.err},
				{"qtls-wrapped", qtls.WrapError(testCase.err)},
			} {
				normalized := normalizeStreamError(input.err)
				quiet := E.IsClosedOrCanceled(normalized)
				if quiet != testCase.quiet {
					t.Fatalf("%s (%s): quiet=%v, want %v -- %s",
						testCase.name, input.label, quiet, testCase.quiet, testCase.why)
				}

				// And the server-side classifier must agree, or one direction logs a fault the
				// other calls routine. This runs for EVERY row that declares quic-go or HTTP/3
				// semantics, so a type cannot be added to the table and silently skip it.
				if testCase.typedSemantics {
					if got := classifyH3Error(input.err) == h3ErrorExpected; got != testCase.quiet {
						t.Fatalf("%s (%s): the server classifier says quiet=%v but the client "+
							"normalizer says %v -- the two must not drift about the same error",
							testCase.name, input.label, got, quiet)
					}
				}
			}
		})
	}
}

// TestTypedClassificationPrecedesGenericNetErrClosed is the ordering guard.
//
// Every quic-go error type unwraps to net.ErrClosed. If any code path evaluates a generic
// `errors.Is(err, net.ErrClosed)` BEFORE the typed checks, a protocol violation is reported as an
// orderly teardown and disappears. That is the exact shape of both defects found so far, so the
// ordering is asserted directly rather than left implicit.
func TestTypedClassificationPrecedesGenericNetErrClosed(t *testing.T) {
	// A fault that is closed, generic and typed all at once. The typed meaning must win.
	faults := []error{
		&quic.TransportError{ErrorCode: quic.TransportErrorCode(0xa)},
		&quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeInternalError)},
		&quic.StatelessResetError{},
	}
	for _, fault := range faults {
		if !errors.Is(fault, net.ErrClosed) {
			t.Fatalf("%T is expected to unwrap to net.ErrClosed; this test is only meaningful if "+
				"the generic test would otherwise match it", fault)
		}
		normalized := normalizeStreamError(qtls.WrapError(fault))
		if E.IsClosedOrCanceled(normalized) {
			t.Fatalf("%T satisfies errors.Is(net.ErrClosed) but is a real fault: the typed "+
				"classification must run first, otherwise this fault is silently erased", fault)
		}
	}
}
