package shadowtls

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

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
	// A timeout is expected only when it is about THIS SERVER'S OWN socket with
	// the public peer - a slow or silent prober hitting a read deadline. A
	// timeout on a DIAL is different: it means the handshake target the operator
	// configured did not answer, which is a fault and must stay visible.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() && !isDialFailure(err) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, os.ErrDeadlineExceeded) {
			return true
		}
		// Classify the errno, do NOT downgrade every syscall error.
		//
		// Treating any *os.SyscallError as an expected probe hid real server
		// faults. The ShadowTLS inbound dials its handshake target, so a failed
		// dial surfaces as exactly this shape:
		//
		//	*net.OpError{Op: "dial"} -> *os.SyscallError{connect, ECONNREFUSED}
		//
		// ECONNREFUSED, ENETUNREACH and EHOSTUNREACH on the handshake target mean
		// the operator's configured upstream is down or unreachable - precisely
		// the condition that must stay visible. Only errors that are provably
		// about the PUBLIC PEER or the local lifecycle are downgraded.
		var syscallErr *os.SyscallError
		if errors.As(opErr.Err, &syscallErr) {
			return isPeerLifecycleErrno(syscallErr.Err)
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

// isDialFailure reports whether the error chain describes an outbound DIAL
// rather than I/O on an accepted connection.
//
// The distinction matters because the two mean different things: a read timeout
// is a slow prober, while a dial timeout is the configured handshake target not
// answering. net.OpError carries the operation, so this is a typed check.
func isDialFailure(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	return opErr.Op == "dial"
}

// isPeerLifecycleErrno reports whether an errno describes the peer going away or
// the local side shutting down, rather than a fault on this server.
//
// Only these are treated as expected:
//
//	ECONNRESET    the peer closed abruptly (a scanner disconnecting)
//	ECONNABORTED  the local side aborted the connection
//	EPIPE         the peer is gone and the write failed
//
// Everything else - ECONNREFUSED, ENETUNREACH, EHOSTUNREACH, ETIMEDOUT, EACCES -
// stays at error level. In particular a refused or unreachable HANDSHAKE TARGET
// is an operator-visible fault, not scanner noise, and silently logging it at
// debug is how a broken upstream goes unnoticed.
//
// The comparison is on syscall.Errno values, not on error strings.
func isPeerLifecycleErrno(err error) bool {
	for _, expected := range []syscall.Errno{
		syscall.ECONNRESET,
		syscall.ECONNABORTED,
		syscall.EPIPE,
	} {
		if errors.Is(err, expected) {
			return true
		}
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
