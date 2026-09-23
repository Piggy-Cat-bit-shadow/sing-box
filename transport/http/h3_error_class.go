//go:build with_quic

package http

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
)

// h3ErrorClass separates expected HTTP/3 and QUIC lifecycle events from real
// faults. Only errors that are unambiguously part of normal operation are
// downgraded to debug; everything unrecognised stays an error.
type h3ErrorClass int

const (
	// h3ErrorExpected is a normal shutdown, cancellation or peer-initiated
	// close that needs no operator attention.
	h3ErrorExpected h3ErrorClass = iota
	// h3ErrorUnexpected is anything that may indicate a real fault.
	h3ErrorUnexpected
)

// classifyH3Error inspects an error using quic-go's concrete types and error
// codes. It deliberately never inspects the error string: a message-based
// check would silently swallow new error variants and cannot be tested
// exhaustively against the real types.
func classifyH3Error(err error) h3ErrorClass {
	if err == nil {
		return h3ErrorExpected
	}
	// Concrete quic-go types are checked BEFORE any errors.Is test on
	// net.ErrClosed. quic-go's TransportError unwraps to net.ErrClosed, so a
	// closed-ness check first would classify a genuine transport fault such as
	// a protocol violation as an expected shutdown. Only a bare net.ErrClosed
	// with no quic-go type behind it counts as an expected closure.
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		// Any transport-level error is a real fault unless it is the
		// no-error code used for an orderly close.
		if transportErr.ErrorCode == quic.TransportErrorCode(0) {
			return h3ErrorExpected
		}
		return h3ErrorUnexpected
	}
	// An HTTP/3 application error carries a numeric code. A subset of those
	// codes describe ordinary client behaviour.
	var h3Err *http3.Error
	if errors.As(err, &h3Err) {
		return classifyH3ErrorCode(h3Err.ErrorCode)
	}
	// A QUIC application error carries a code as well.
	var applicationErr *quic.ApplicationError
	if errors.As(err, &applicationErr) {
		return classifyH3ErrorCode(http3.ErrCode(applicationErr.ErrorCode))
	}
	// A stream reset is routine when a client abandons a request.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return classifyH3ErrorCode(http3.ErrCode(streamErr.ErrorCode))
	}
	// Idle and handshake timeouts are reported for peers that simply go away,
	// including scanners that connect and vanish.
	var idleTimeout *quic.IdleTimeoutError
	if errors.As(err, &idleTimeout) {
		return h3ErrorExpected
	}
	var handshakeTimeout *quic.HandshakeTimeoutError
	if errors.As(err, &handshakeTimeout) {
		return h3ErrorExpected
	}
	// Context cancellation is always expected during shutdown.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return h3ErrorExpected
	}
	// Only now is a bare closed/EOS signal treated as an expected closure.
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return h3ErrorExpected
	}
	if E.IsClosed(err) {
		return h3ErrorExpected
	}
	return h3ErrorUnexpected
}

// classifyH3ErrorCode maps an HTTP/3 error code to a class.
func classifyH3ErrorCode(code http3.ErrCode) h3ErrorClass {
	switch code {
	case http3.ErrCodeNoError, // normal close
		http3.ErrCodeRequestCanceled,   // client cancelled the request
		http3.ErrCodeRequestRejected,   // server declined to serve it
		http3.ErrCodeRequestIncomplete, // client went away mid-request
		http3.ErrCodeVersionFallback:   // peer asked to fall back
		return h3ErrorExpected
	default:
		// Everything else, including protocol violations, frame errors,
		// settings errors, QPACK failures and internal errors, is a real
		// fault and must stay visible.
		return h3ErrorUnexpected
	}
}

// isExpectedH3Closure reports whether an HTTP/3 or QUIC error represents a
// normal lifecycle event rather than a fault.
func isExpectedH3Closure(err error) bool {
	return classifyH3Error(err) == h3ErrorExpected
}
