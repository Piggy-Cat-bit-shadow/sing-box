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
)

// TestClassifyH3ErrorExpected covers the lifecycle events that must be quiet.
func TestClassifyH3ErrorExpected(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{name: "nil", err: nil},
		{name: "context canceled", err: context.Canceled},
		{name: "context deadline", err: context.DeadlineExceeded},
		{name: "io eof", err: io.EOF},
		{name: "net closed", err: net.ErrClosed},
		{name: "closed pipe", err: io.ErrClosedPipe},
		{
			name: "h3 no error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeNoError, Remote: true},
		},
		{
			name: "h3 no error local",
			err:  &http3.Error{ErrorCode: http3.ErrCodeNoError, Remote: false},
		},
		{
			name: "h3 request cancelled",
			err:  &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled, Remote: false},
		},
		{
			name: "h3 request rejected",
			err:  &http3.Error{ErrorCode: http3.ErrCodeRequestRejected, Remote: true},
		},
		{
			name: "h3 request incomplete",
			err:  &http3.Error{ErrorCode: http3.ErrCodeRequestIncomplete, Remote: true},
		},
		{
			name: "h3 version fallback",
			err:  &http3.Error{ErrorCode: http3.ErrCodeVersionFallback, Remote: true},
		},
		{
			name: "quic application no error",
			err:  &quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeNoError)},
		},
		{
			name: "quic application request cancelled",
			err:  &quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled)},
		},
		{
			name: "quic stream no error",
			err:  &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeNoError)},
		},
		{
			name: "quic stream request cancelled",
			err:  &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled)},
		},
		{name: "idle timeout", err: &quic.IdleTimeoutError{}},
		{name: "handshake timeout", err: &quic.HandshakeTimeoutError{}},
		{
			name: "wrapped normal close",
			err:  errors.Join(errors.New("context"), &http3.Error{ErrorCode: http3.ErrCodeNoError}),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if !isExpectedH3Closure(testCase.err) {
				t.Fatalf("%s must be classified as an expected closure", testCase.name)
			}
			if classifyH3Error(testCase.err) != h3ErrorExpected {
				t.Fatalf("%s must be classified as expected", testCase.name)
			}
		})
	}
}

// TestClassifyH3ErrorUnexpected is the other half of the contract: genuine
// faults must never be silenced.
func TestClassifyH3ErrorUnexpected(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{
			name: "h3 general protocol error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeGeneralProtocolError},
		},
		{
			name: "h3 internal error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeInternalError},
		},
		{
			name: "h3 stream creation error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeStreamCreationError},
		},
		{
			name: "h3 closed critical stream",
			err:  &http3.Error{ErrorCode: http3.ErrCodeClosedCriticalStream},
		},
		{
			name: "h3 frame unexpected",
			err:  &http3.Error{ErrorCode: http3.ErrCodeFrameUnexpected},
		},
		{
			name: "h3 frame error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeFrameError},
		},
		{
			name: "h3 excessive load",
			err:  &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad},
		},
		{
			name: "h3 id error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeIDError},
		},
		{
			name: "h3 settings error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeSettingsError},
		},
		{
			name: "h3 missing settings",
			err:  &http3.Error{ErrorCode: http3.ErrCodeMissingSettings},
		},
		{
			name: "h3 message error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeMessageError},
		},
		{
			name: "h3 connect error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeConnectError},
		},
		{
			name: "h3 datagram error",
			err:  &http3.Error{ErrorCode: http3.ErrCodeDatagramError},
		},
		{
			name: "qpack decompression failed",
			err:  &http3.Error{ErrorCode: http3.ErrCodeQPACKDecompressionFailed},
		},
		{
			name: "quic stream internal error",
			err:  &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError)},
		},
		{
			name: "quic stream protocol violation",
			err:  &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeGeneralProtocolError)},
		},
		{
			name: "generic error",
			err:  errors.New("something went wrong"),
		},
		{
			name: "transport protocol violation",
			err:  &quic.TransportError{ErrorCode: quic.TransportErrorCode(0x8)},
		},
		{
			name: "wrapped fault inside normal close",
			err:  errors.Join(errors.New("x"), errors.New("malformed frame")),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if isExpectedH3Closure(testCase.err) {
				t.Fatalf("%s must NOT be silenced: it is a real fault", testCase.name)
			}
			if classifyH3Error(testCase.err) != h3ErrorUnexpected {
				t.Fatalf("%s must be classified as unexpected", testCase.name)
			}
		})
	}
}

// TestClassifyH3ErrorCodeCoverage documents that the expected set is a small,
// explicit subset rather than a catch-all.
func TestClassifyH3ErrorCodeCoverage(t *testing.T) {
	expected := []http3.ErrCode{
		http3.ErrCodeNoError,
		http3.ErrCodeRequestCanceled,
		http3.ErrCodeRequestRejected,
		http3.ErrCodeRequestIncomplete,
		http3.ErrCodeVersionFallback,
	}
	for _, code := range expected {
		if classifyH3ErrorCode(code) != h3ErrorExpected {
			t.Fatalf("code %s must be expected", code)
		}
	}
	unexpected := []http3.ErrCode{
		http3.ErrCodeGeneralProtocolError,
		http3.ErrCodeInternalError,
		http3.ErrCodeStreamCreationError,
		http3.ErrCodeClosedCriticalStream,
		http3.ErrCodeFrameUnexpected,
		http3.ErrCodeFrameError,
		http3.ErrCodeExcessiveLoad,
		http3.ErrCodeIDError,
		http3.ErrCodeSettingsError,
		http3.ErrCodeMissingSettings,
		http3.ErrCodeMessageError,
		http3.ErrCodeConnectError,
		http3.ErrCodeDatagramError,
		http3.ErrCodeQPACKDecompressionFailed,
	}
	for _, code := range unexpected {
		if classifyH3ErrorCode(code) != h3ErrorUnexpected {
			t.Fatalf("code %s must NOT be silenced", code)
		}
	}
	// An unknown code must be treated as a fault, not silently ignored.
	if classifyH3ErrorCode(http3.ErrCode(0x7fff)) != h3ErrorUnexpected {
		t.Fatal("an unknown error code must be treated as unexpected")
	}
}

// TestClassifyH3ErrorNotSilencedByNetErrClosed is a regression guard for a
// real trap: quic-go's TransportError and ApplicationError both unwrap to
// net.ErrClosed. A classifier that tests closed-ness first would therefore
// silently downgrade every genuine QUIC fault to debug. Concrete quic-go types
// must be inspected before any net.ErrClosed check.
func TestClassifyH3ErrorNotSilencedByNetErrClosed(t *testing.T) {
	// Sanity: the trap really exists in the dependency.
	var transportErr *quic.TransportError
	err := error(&quic.TransportError{ErrorCode: quic.TransportErrorCode(0x8)})
	if !errors.As(err, &transportErr) {
		t.Fatal("precondition: expected a TransportError")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatal("precondition: quic-go's TransportError is expected to unwrap to net.ErrClosed")
	}
	applicationErr := error(&quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeInternalError)})
	if !errors.Is(applicationErr, net.ErrClosed) {
		t.Fatal("precondition: quic-go's ApplicationError is expected to unwrap to net.ErrClosed")
	}

	// Despite unwrapping to net.ErrClosed, these are faults and must stay
	// visible.
	if isExpectedH3Closure(err) {
		t.Fatal("a QUIC transport protocol violation must not be silenced by its net.ErrClosed unwrap")
	}
	if isExpectedH3Closure(applicationErr) {
		t.Fatal("an H3_INTERNAL_ERROR application error must not be silenced by its net.ErrClosed unwrap")
	}

	// A real orderly close is still quiet.
	if !isExpectedH3Closure(&quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeNoError)}) {
		t.Fatal("an orderly no-error close must remain quiet")
	}
}
