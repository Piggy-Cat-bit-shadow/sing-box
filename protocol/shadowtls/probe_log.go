package shadowtls

import (
	"context"
	"errors"
	"io"
	"net"
	"os"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// Pre-authentication failures on the ShadowTLS inbound are expected lifecycle
// events, not faults.
//
// The ShadowTLS inbound sits directly behind the public TCP/443 front door. A
// scanner that opens the port and sends something that is not a TLS ClientHello
// -- or that sends a partial record and disconnects -- is routine traffic. The
// service reports those as "read client handshake" / "read request" errors, and
// logging each one at error level turns ordinary scanning into an error-log
// flood that buries real faults.
//
// Classification uses TYPED checks only. String matching on the error text is
// deliberately avoided: it silently swallows new error variants and cannot be
// tested exhaustively. This mirrors the classifier in
// transport/http/h3_error_class.go.
//
// Anything unrecognised stays at error level. "Unclassified" must never mean
// "suppressed".

// isExpectedShadowTLSProbeFailure reports whether err is a normal
// pre-authentication lifecycle event on a public ShadowTLS port.
func isExpectedShadowTLSProbeFailure(err error) bool {
	if err == nil {
		return true
	}
	// Truncated input: the peer announced a record length and then went away, or
	// sent fewer bytes than a TLS record header. This is what a non-TLS probe and
	// a half-open connection both look like.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	// A read deadline or an aborted connection at the TCP layer.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, os.ErrDeadlineExceeded) {
			return true
		}
		var syscallErr *os.SyscallError
		if errors.As(opErr.Err, &syscallErr) {
			return true
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if E.IsClosedOrCanceled(err) {
		return true
	}
	return false
}

// shadowTLSErrorIsExpected reports whether a ShadowTLS inbound error should be
// downgraded to debug. It exists so the decision is directly testable instead of
// being asserted through captured log output.
func shadowTLSErrorIsExpected(err error) bool {
	return isExpectedShadowTLSProbeFailure(err)
}

// logShadowTLSError emits an inbound error at the level its class warrants.
func logShadowTLSError(ctx context.Context, log logger.ContextLogger, source M.Socksaddr, err error) {
	if shadowTLSErrorIsExpected(err) {
		log.DebugContext(ctx, "connection closed: ", err)
		return
	}
	log.ErrorContext(ctx, E.Cause(err, "process connection from ", source))
}
