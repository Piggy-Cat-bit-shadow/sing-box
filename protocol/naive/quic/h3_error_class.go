//go:build with_quic

package quic

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/logger"
)

// Typed QUIC / HTTP3 error classification for the Native Naive HTTP/3 boundary.
//
// # Why this exists
//
// Every quic-go error type implements Unwrap() returning net.ErrClosed whatever its error code
// is. A generic closed/canceled test run before a typed one therefore cannot tell an orderly
// shutdown from a PROTOCOL_VIOLATION, and the callers in this package decide log level with
// exactly such a test:
//
//	if sErr != nil && !E.IsClosedOrCanceled(sErr) { logger.Error(...) }
//
// The tunnel's own error path has the same shape: naive.WrapError is assigned qtls.WrapError
// here, and that shared wrapper cannot express "closed" precisely either -- its typed switch is
// unreachable because every raw quic-go error already satisfies net.ErrClosed.
//
// So classification happens at these boundaries, typed first, and a genuine fault is returned as
// a value that does NOT satisfy a closed/canceled test.

// naiveVisibleFault reports a real fault while hiding any misleading net.ErrClosed in its chain.
//
// Unwrap is deliberately NOT implemented: errors.Is/As cannot reach the quic-go type, which is
// what stops the sentinel leaking back in. The original error stays available through Cause for
// diagnostics.
type naiveVisibleFault struct {
	err error
}

func (f *naiveVisibleFault) Error() string { return f.err.Error() }

// Is matches only another naiveVisibleFault, so a fault never satisfies errors.Is(err, net.ErrClosed).
func (f *naiveVisibleFault) Is(target error) bool {
	other, isFault := target.(*naiveVisibleFault)
	return isFault && f.err.Error() == other.err.Error()
}

func (f *naiveVisibleFault) Cause() error { return f.err }

func asVisibleFault(err error) error {
	if err == nil {
		return nil
	}
	var already *naiveVisibleFault
	if errors.As(err, &already) {
		return err
	}
	return &naiveVisibleFault{err: err}
}

// classifyNaiveH3Error maps a QUIC or HTTP/3 error onto the expected/fault split.
//
// Typed semantics are examined FIRST. Only an error carrying no quic-go meaning at all falls
// through to the generic closed/canceled tests, and anything unclassifiable is a fault rather
// than being assumed benign.
func classifyNaiveH3Error(err error) (quiet bool) {
	if err == nil {
		return true
	}

	// Transport errors: the no-error code is an orderly close, everything else is a fault.
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		return transportErr.ErrorCode == quic.NoError
	}
	// Application errors carry the peer's own code space; 0 is its no-error value. This is NOT
	// http3.ErrCodeNoError (0x100), which is a different number.
	var applicationErr *quic.ApplicationError
	if errors.As(err, &applicationErr) {
		if applicationErr.ErrorCode == 0 {
			return true
		}
		return isExpectedH3Code(http3.ErrCode(applicationErr.ErrorCode))
	}
	// HTTP/3 application errors.
	var h3Err *http3.Error
	if errors.As(err, &h3Err) {
		if h3Err.ErrorCode == 0 {
			return true
		}
		return isExpectedH3Code(h3Err.ErrorCode)
	}
	// Stream resets: code 0 means no condition was raised; the rest go through the H3 table.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		if streamErr.ErrorCode == 0 {
			return true
		}
		return isExpectedH3Code(http3.ErrCode(streamErr.ErrorCode))
	}
	// A stateless reset tears the path down without a close, and a version-negotiation failure
	// means nothing was ever established. Both are notable, and both unwrap to net.ErrClosed.
	var statelessReset *quic.StatelessResetError
	if errors.As(err, &statelessReset) {
		return false
	}
	var versionErr *quic.VersionNegotiationError
	if errors.As(err, &versionErr) {
		return false
	}
	// Peers that simply go away.
	var idleTimeout *quic.IdleTimeoutError
	if errors.As(err, &idleTimeout) {
		return true
	}
	var handshakeTimeout *quic.HandshakeTimeoutError
	if errors.As(err, &handshakeTimeout) {
		return true
	}

	// No quic-go semantics in the chain: only now may a bare sentinel mean an orderly end.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	return false
}

// isExpectedH3Code is the shared code table for HTTP/3 application errors.
func isExpectedH3Code(code http3.ErrCode) bool {
	switch code {
	case http3.ErrCodeNoError, // normal close
		http3.ErrCodeRequestCanceled,   // the peer abandoned one request stream
		http3.ErrCodeRequestRejected,   // the server declined to serve it
		http3.ErrCodeRequestIncomplete, // the peer went away mid-request
		http3.ErrCodeVersionFallback:   // the peer asked to fall back
		return true
	default:
		return false
	}
}

// normalizeNaiveStreamError is installed as naive.WrapError. It classifies the wrapped error so
// the routing layer's closed/canceled test sees a genuine fault as a fault.
func normalizeNaiveStreamError(err error) error {
	if err == nil {
		return nil
	}
	if classifyNaiveH3Error(err) {
		// Return the error unchanged when it is already a recognised sentinel, so identity is
		// preserved for callers that match on it; otherwise report a plain closure.
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return net.ErrClosed
	}
	return asVisibleFault(err)
}

// naiveH3ServerLogHandler surfaces connection-level HTTP/3 faults that quic-go would otherwise
// discard.
//
// http3.Server handles each connection on its own goroutine and logs handleConn's error through
// s.Logger, then drops it; ServeListener returns only http.ErrServerClosed or the listener's own
// Accept error. With Logger unset a connection-level fault has no operator-visible signal at all.
type naiveH3ServerLogHandler struct {
	logger logger.Logger
}

func (h naiveH3ServerLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelDebug
}

func (h naiveH3ServerLogHandler) Handle(_ context.Context, record slog.Record) error {
	if h.logger == nil {
		return nil
	}
	// Only the connection-failure record carries a classifiable error; other records are
	// library-internal detail and are deliberately not mirrored.
	if record.Message != "handling connection failed" {
		return nil
	}
	var failure error
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "error" && attr.Value.Any() != nil {
			if asError, isError := attr.Value.Any().(error); isError {
				failure = asError
			}
			return false
		}
		return true
	})
	if failure == nil {
		return nil
	}
	if classifyNaiveH3Error(failure) {
		h.logger.Debug("naive http3 connection closed: ", failure)
		return nil
	}
	h.logger.Error("naive http3 connection failed: ", failure)
	return nil
}

func (h naiveH3ServerLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h naiveH3ServerLogHandler) WithGroup(_ string) slog.Handler      { return h }

// newNaiveH3ServerLogger builds the slog.Logger handed to the Native Naive http3.Server.
// A nil logger returns nil, leaving http3.Server with its default of no logging.
func newNaiveH3ServerLogger(serverLogger logger.Logger) *slog.Logger {
	if serverLogger == nil {
		return nil
	}
	return slog.New(naiveH3ServerLogHandler{logger: serverLogger})
}
