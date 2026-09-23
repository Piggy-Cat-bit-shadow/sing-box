package http

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	N "github.com/sagernet/sing/common/network"
)

// TestNormalizeStreamErrorTranslatesNormalClosures covers the regression that
// produced "ERROR connection upload closed: H3 error (0x0)" for an ordinary
// HTTP/3 tunnel teardown.
func TestNormalizeStreamErrorTranslatesNormalClosures(t *testing.T) {
	expected := []struct {
		name string
		err  error
	}{
		// ErrorCode 0 is what quic-go actually produces for an orderly tunnel
		// close; it formats as "H3 error (0x0)". It is NOT ErrCodeNoError.
		{"h3 zero code", &http3.Error{ErrorCode: 0}},
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

// TestNormalizingConnHidesUpstream is the guard for the bug that made two
// earlier attempts at this fix ineffective.
//
// sing's N.UnwrapReader and N.UnwrapWriter walk the Upstream() chain and
// bufio.Copy uses the fully unwrapped reader and writer, so a wrapper that
// exposes the inner connection's Upstream() is simply skipped. That is why
// wrapping request.Body alone did nothing: the copy path unwrapped straight past
// it and still saw the raw "H3 error (0x0)".
//
// normalizingConn therefore keeps the inner conn in a NAMED field so no method is
// promoted. This test pins that: the wrapper must not advertise itself as
// replaceable, and it must actually normalize what it passes through.
func TestNormalizingConnHidesUpstream(t *testing.T) {
	inner := &stubConn{readErr: &http3.Error{ErrorCode: 0}}
	wrapped := &normalizingConn{inner: inner}

	// It must not be unwrappable, otherwise bufio.Copy bypasses it.
	if _, isReplaceable := any(wrapped).(N.ReaderWithUpstream); isReplaceable {
		t.Fatal("normalizingConn must not be reader-replaceable, or the copy path skips it")
	}
	if _, isReplaceable := any(wrapped).(N.WriterWithUpstream); isReplaceable {
		t.Fatal("normalizingConn must not be writer-replaceable, or the copy path skips it")
	}
	if unwrapped := N.UnwrapReader(wrapped); unwrapped != any(wrapped) {
		t.Fatal("N.UnwrapReader must stop at normalizingConn")
	}

	// And it must normalize a zero-code HTTP/3 error, which is the value quic-go
	// actually produces for an orderly tunnel close.
	_, err := wrapped.Read(make([]byte, 1))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a zero-code H3 error must normalize to net.ErrClosed, got %v", err)
	}

	// Write and WriteBuffer must behave the same way.
	if _, err = wrapped.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write must normalize, got %v", err)
	}
}

// stubConn is a net.Conn whose operations return a fixed error.
type stubConn struct {
	readErr error
}

func (c *stubConn) Read(p []byte) (int, error)         { return 0, c.readErr }
func (c *stubConn) Write(p []byte) (int, error)        { return 0, c.readErr }
func (c *stubConn) Close() error                       { return nil }
func (c *stubConn) LocalAddr() net.Addr                { return nil }
func (c *stubConn) RemoteAddr() net.Addr               { return nil }
func (c *stubConn) SetDeadline(t time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(t time.Time) error { return nil }
