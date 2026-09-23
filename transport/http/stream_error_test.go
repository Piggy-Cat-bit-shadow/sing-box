package http

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/quic-go/http3"
)

// TestNormalizeStreamErrorTranslatesNormalClosures covers the regression that
// produced "ERROR connection upload closed: H3 error (0x0)" for an ordinary
// HTTP/3 tunnel teardown.
func TestNormalizeStreamErrorTranslatesNormalClosures(t *testing.T) {
	expected := []struct {
		name string
		err  error
	}{
		{"h3 no error", &http3.Error{ErrorCode: http3.ErrCodeNoError}},
		{"h3 no error local", &http3.Error{ErrorCode: http3.ErrCodeNoError, Remote: false}},
		{"h3 request cancelled", &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled}},
		{"h3 request incomplete", &http3.Error{ErrorCode: http3.ErrCodeRequestIncomplete}},
		{"h3 request rejected", &http3.Error{ErrorCode: http3.ErrCodeRequestRejected}},
	}
	for _, testCase := range expected {
		t.Run(testCase.name, func(t *testing.T) {
			got := normalizeStreamError(testCase.err)
			if !errors.Is(got, net.ErrClosed) {
				t.Fatalf("%s must normalize to net.ErrClosed, got %v", testCase.name, got)
			}
		})
	}
}

// TestNormalizeStreamErrorKeepsRealFaults is the other half: a genuine fault must
// still be reported as one.
func TestNormalizeStreamErrorKeepsRealFaults(t *testing.T) {
	realFaults := []struct {
		name string
		err  error
	}{
		{"protocol error", &http3.Error{ErrorCode: http3.ErrCodeGeneralProtocolError}},
		{"internal error", &http3.Error{ErrorCode: http3.ErrCodeInternalError}},
		{"frame error", &http3.Error{ErrorCode: http3.ErrCodeFrameError}},
		{"settings error", &http3.Error{ErrorCode: http3.ErrCodeSettingsError}},
		{"message error", &http3.Error{ErrorCode: http3.ErrCodeMessageError}},
		{"connect error", &http3.Error{ErrorCode: http3.ErrCodeConnectError}},
		{"datagram error", &http3.Error{ErrorCode: http3.ErrCodeDatagramError}},
		{"qpack error", &http3.Error{ErrorCode: http3.ErrCodeQPACKDecompressionFailed}},
		{"generic error", errors.New("malformed frame")},
	}
	for _, testCase := range realFaults {
		t.Run(testCase.name, func(t *testing.T) {
			got := normalizeStreamError(testCase.err)
			if errors.Is(got, net.ErrClosed) {
				t.Fatalf("%s must NOT be normalized to net.ErrClosed", testCase.name)
			}
			if got == nil {
				t.Fatalf("%s must be returned unchanged", testCase.name)
			}
		})
	}
}

func TestNormalizeStreamErrorNilAndSentinels(t *testing.T) {
	if normalizeStreamError(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	// Already-recognised sentinels must pass through untouched.
	for _, sentinel := range []error{net.ErrClosed, io.EOF} {
		if got := normalizeStreamError(sentinel); got == nil {
			t.Fatalf("%v must not become nil", sentinel)
		}
	}
}

// TestNormalizingWriterDoesNotClaimHTTP3Interfaces is a guard for CONNECT-UDP.
//
// HTTP3StreamFunc type-asserts the ResponseWriter for http3.HTTPStreamer and
// http3.Settingser. If the normalizing wrapper ever claimed those interfaces (or
// if it were passed where the original is expected), the assertion would fail and
// datagrams would silently stop working.
func TestNormalizingWriterDoesNotClaimHTTP3Interfaces(t *testing.T) {
	recorder := httptest.NewRecorder()
	wrapped := normalizingResponseWriter{recorder}

	if _, isStreamer := any(wrapped).(http3.HTTPStreamer); isStreamer {
		t.Fatal("the normalizing writer must not claim http3.HTTPStreamer")
	}
	if _, isSettingser := any(wrapped).(http3.Settingser); isSettingser {
		t.Fatal("the normalizing writer must not claim http3.Settingser")
	}
	// It must still behave as a ResponseWriter and Flusher.
	var _ http.ResponseWriter = wrapped
	var _ http.Flusher = wrapped
	if unwrapped := wrapped.Unwrap(); unwrapped != recorder {
		t.Fatal("Unwrap must return the original writer")
	}
}
