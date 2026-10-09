package http

// This file deliberately carries NO build constraint.
//
// # Why the HTTP/3 error classifier is compiled in every build
//
// It used to be gated on with_quic, which made three separate packages fail to COMPILE without
// the tag:
//
//	transport/http/client.go:239:33: undefined: http3LifecycleTracer
//	transport/http/stream_error.go:170:5: undefined: classifyH3ErrorCode
//	transport/http/stream_error.go:170:34: undefined: h3ErrorExpected
//	transport/masque/server.go:617:19: undefined: transportHTTP.CarriesQuicSemantics
//	transport/masque/server.go:618:24: undefined: transportHTTP.IsExpectedH3Closure
//
// None of those callers is optional:
//
//   - stream_error.go normalizes errors on the stream boundary of the HTTP/2 server and the
//     HTTP/2 tunnel as well (server_h2.go wraps its connections in normalizingConn), so it cannot
//     be gated without removing error normalization from builds that have no QUIC;
//   - transport/masque compiles and is TESTED without the tag: its capsule, route-matching, DNS
//     and IPv6-extension tests are untagged, and they call IsExpectedH3Closure and the
//     owned-datagram helpers directly.
//
// The classifier has no QUIC runtime dependency: it reads quic-go's concrete types and the
// http3.ErrCode constants, and both packages are ordinary importable modules in every build.
// classifyH3ErrorCode is a pure switch over constants. So "none" is the honest constraint for
// the table and for the classification built on it, while the *use* of HTTP/3 - the transports,
// listeners and dialers - stays gated on with_quic elsewhere in this package.
//
// Keeping ONE table is the point: the client normalizer, the server classifier and the MASQUE
// session error path must not be able to drift apart, which a second copy under !with_quic would
// guarantee.

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
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
	// A QUIC application error carries a code as well. Code 0 is the no-error
	// value used for an orderly shutdown, the same convention as TransportError
	// above; it is NOT http3.ErrCodeNoError (0x100), which is a different number.
	var applicationErr *quic.ApplicationError
	if errors.As(err, &applicationErr) {
		if applicationErr.ErrorCode == quic.ApplicationErrorCode(0) {
			return h3ErrorExpected
		}
		return classifyH3ErrorCode(http3.ErrCode(applicationErr.ErrorCode))
	}
	// A stream reset is routine when a client abandons a request. As above, a
	// zero code means no error was raised rather than an unlisted H3 code.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		if streamErr.ErrorCode == 0 {
			return h3ErrorExpected
		}
		return classifyH3ErrorCode(http3.ErrCode(streamErr.ErrorCode))
	}
	// A stateless reset means the peer or a middlebox declared the connection
	// gone without closing it. That is a real, notable event on an active path,
	// and it unwraps to net.ErrClosed, so it must be classified explicitly or a
	// later generic closed-ness test would call it routine.
	var statelessReset *quic.StatelessResetError
	if errors.As(err, &statelessReset) {
		return h3ErrorUnexpected
	}
	// Version negotiation failing means no usable QUIC version was agreed, so
	// nothing was ever established. Like the above it unwraps to net.ErrClosed.
	var versionErr *quic.VersionNegotiationError
	if errors.As(err, &versionErr) {
		return h3ErrorUnexpected
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

// IsExpectedH3Closure reports whether an HTTP/3 or QUIC error represents a normal lifecycle
// event rather than a fault.
//
// It is exported because other packages that handle the same wire protocols -- transport/masque
// among them -- decide log levels with a generic closed/canceled test that every quic-go error
// satisfies regardless of its code. They must apply the SAME typed classification rather than
// growing a second copy of the code table, which would drift.
//
// Callers must use this BEFORE any errors.Is(err, net.ErrClosed) style test.
func IsExpectedH3Closure(err error) bool {
	return classifyH3Error(err) == h3ErrorExpected
}

// isExpectedH3Closure is the internal spelling used within this package.
func isExpectedH3Closure(err error) bool {
	return IsExpectedH3Closure(err)
}

// serveErrorIsAFault reports whether a finished HTTP/3 server is worth an error line.
//
// # Why the generic closed test cannot come first
//
// quic-go's TransportError.Unwrap() returns net.ErrClosed alongside the real cause, so
// "errors.Is(err, net.ErrClosed)" is true for EVERY transport error - a protocol violation just
// as much as an orderly shutdown. A condition that tests closed-ness before the typed
// classification therefore swallows the faults it was written to surface, and this file's own
// rule (typed classification first, generic sentinels only as a fallback) is the opposite order
// for exactly that reason.
//
// So an error with quic-go/HTTP/3 semantics is decided by the typed classifier alone, and an
// error with no typed semantics falls back to the generic sentinels.
func serveErrorIsAFault(err error) bool {
	if err == nil {
		return false
	}
	if CarriesQuicSemantics(err) {
		return !IsExpectedH3Closure(err)
	}
	return !E.IsClosedOrCanceled(err)
}

// CarriesQuicSemantics reports whether the error chain contains a quic-go or HTTP/3 type.
//
// It exists so a caller can tell "this error has a typed meaning, so the typed classifier is
// authoritative" from "this is a bare sentinel, so a generic closed/canceled test is the best
// available answer". Without that distinction a caller writing `!typed && !generic` still lets
// the generic and permissive test win, because every quic-go type unwraps to net.ErrClosed.
func CarriesQuicSemantics(err error) bool {
	var (
		transportErr *quic.TransportError
		appErr       *quic.ApplicationError
		streamErr    *quic.StreamError
		h3Err        *http3.Error
		statelessErr *quic.StatelessResetError
		versionErr   *quic.VersionNegotiationError
		idleErr      *quic.IdleTimeoutError
		handshakeErr *quic.HandshakeTimeoutError
	)
	return errors.As(err, &transportErr) || errors.As(err, &appErr) ||
		errors.As(err, &streamErr) || errors.As(err, &h3Err) ||
		errors.As(err, &statelessErr) || errors.As(err, &versionErr) ||
		errors.As(err, &idleErr) || errors.As(err, &handshakeErr)
}
