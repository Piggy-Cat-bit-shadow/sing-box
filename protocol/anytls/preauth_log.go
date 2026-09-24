package anytls

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

// Pre-auth failures on the AnyTLS inbound are expected lifecycle events, not
// faults. A public scanner that completes the TLS handshake and then sends
// nothing, or that disconnects mid-handshake, is routine traffic on an internet-
// facing port; logging each one at error level turns ordinary scanning into an
// error-log flood and buries real faults.
//
// Classification is done with TYPED checks only -- errors.As on the net error
// types and errors.Is on the sentinel values. String matching on the error text
// is deliberately not used: it silently swallows new error variants, cannot be
// tested exhaustively, and is exactly the anti-pattern the HTTP/3 classifier in
// transport/http/h3_error_class.go avoids.
//
// Anything unrecognised stays at error level. "Unclassified" must never mean
// "suppressed".

// isExpectedPreAuthFailure reports whether err is a normal pre-authentication
// lifecycle event for the AnyTLS inbound.
func isExpectedPreAuthFailure(err error) bool {
	if err == nil {
		return true
	}
	// A read deadline expiring is the one-shot pre-auth timeout doing its job:
	// the peer completed TLS and then sent nothing.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// The peer went away: orderly close, half-close, or an aborted connection.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	// A connection reset by the peer is a normal TCP outcome on a public port.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Any *net.OpError whose inner error is a syscall reset or a closed
		// descriptor is peer-driven rather than a server fault.
		if errors.Is(opErr.Err, os.ErrDeadlineExceeded) {
			return true
		}
		var syscallErr *os.SyscallError
		if errors.As(opErr.Err, &syscallErr) {
			return true
		}
	}
	// Context cancellation during shutdown.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// sing-box's own closed/cancelled helper, used throughout the codebase.
	if E.IsClosed(err) {
		return true
	}
	return false
}

// preAuthFailureIsError reports whether a pre-auth failure should be logged at
// error level. It exists so the decision is directly testable instead of being
// asserted through captured log output.
func preAuthFailureIsError(err error) bool {
	return !isExpectedPreAuthFailure(err)
}

// logPreAuthFailure emits a pre-authentication failure at the level its class
// warrants. Expected lifecycle events (scanner disconnects, the pre-auth read
// deadline firing) go to debug; anything unrecognised stays at error level so a
// real fault is never hidden by this classification.
func logPreAuthFailure(ctx context.Context, logger logger.ContextLogger, source M.Socksaddr, err error, stage string) {
	cause := E.Cause(err, "process connection from ", source)
	if stage != "" {
		cause = E.Cause(err, "process connection from ", source, ": ", stage)
	}
	if preAuthFailureIsError(err) {
		logger.ErrorContext(ctx, cause)
		return
	}
	logger.DebugContext(ctx, cause)
}
