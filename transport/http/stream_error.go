package http

import (
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
)

// normalizeStreamError maps a transport-level stream error onto the sentinel
// errors sing-box's routing layer already recognises as "the peer went away".
//
// Why this exists: route/conn.go reports a copy failure with
//
//	if !E.IsClosedOrCanceled(err) {
//	    m.logger.ErrorContext(ctx, "connection upload closed: ", err)
//	}
//
// A normally-closed HTTP/3 tunnel surfaces as *http3.Error with ErrCodeNoError,
// which E.IsClosedOrCanceled does not recognise, so a perfectly ordinary tunnel
// teardown was logged at ERROR level. The routing layer is the wrong place to
// teach about HTTP/3, and route cannot import this package (it would be a cycle),
// so the translation happens here at the stream boundary instead.
//
// Only unambiguously normal conditions are translated. Anything that could
// indicate a real fault is returned unchanged so it still reaches the logs as an
// ERROR.
func normalizeStreamError(err error) error {
	if err == nil {
		return nil
	}
	// Already a recognised sentinel: leave it alone.
	if E.IsClosedOrCanceled(err) {
		return err
	}
	var h3Err *http3.Error
	if errors.As(err, &h3Err) {
		switch h3Err.ErrorCode {
		case http3.ErrCodeNoError, // orderly close
			http3.ErrCodeRequestCanceled,   // the peer abandoned the request
			http3.ErrCodeRequestIncomplete, // the peer went away mid-request
			http3.ErrCodeRequestRejected:   // the peer declined to serve it
			return net.ErrClosed
		}
		// Every other HTTP/3 code (protocol violations, frame and settings
		// errors, QPACK failures, internal errors) is a real fault and is
		// deliberately passed through unchanged.
		return err
	}
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		if streamErr.ErrorCode == 0 {
			return net.ErrClosed
		}
		return err
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	return err
}

// normalizingReadCloser wraps a response body so reads report normal closures as
// sentinels the routing layer understands.
type normalizingReadCloser struct {
	io.ReadCloser
}

func (r normalizingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	return n, normalizeStreamError(err)
}

// normalizingResponseWriter wraps a ResponseWriter so writes report normal
// closures the same way.
type normalizingResponseWriter struct {
	http.ResponseWriter
}

func (w normalizingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	return n, normalizeStreamError(err)
}

func (w normalizingResponseWriter) Flush() {
	if flusher, isFlusher := w.ResponseWriter.(http.Flusher); isFlusher {
		flusher.Flush()
	}
}

// Unwrap exposes the underlying writer.
//
// IMPORTANT: this wrapper deliberately implements ONLY http.ResponseWriter and
// http.Flusher. It must never be passed to code that type-asserts for
// http3.HTTPStreamer or http3.Settingser, because those assertions would fail
// and CONNECT-UDP datagrams would silently stop working. serveConnectUDP
// therefore keeps using the original writer; only the TCP CONNECT path is
// wrapped, which is the path that produced the spurious "H3 error (0x0)" ERROR.
//
// TestNormalizingWriterDoesNotClaimHTTP3Interfaces pins this.
func (w normalizingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// NormalizeStreamErrorForTest exposes the normalizer to the external integration
// test module, which cannot reach unexported identifiers. It exists only so the
// test/ module can assert the property the routing layer depends on, namely that
// a normally closed HTTP/3 stream satisfies E.IsClosedOrCanceled.
func NormalizeStreamErrorForTest(err error) error {
	return normalizeStreamError(err)
}
