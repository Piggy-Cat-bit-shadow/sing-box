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
