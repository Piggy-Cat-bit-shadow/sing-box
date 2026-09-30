//go:build with_quic

package v2rayquic

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/sagernet/quic-go"
)

// visibleFault reports a genuine QUIC fault while hiding any misleading net.ErrClosed in its
// chain.
//
// # Why the accept loop needs this
//
// streamAcceptLoop returns qtls.WrapError(err) from conn.AcceptStream, and the accept goroutine
// then decides the log level with:
//
//	if hErr != nil && !E.IsClosedOrCanceled(hErr) {
//	    s.logger.ErrorContext(conn.Context(), hErr)
//	}
//
// Every quic-go error type implements Unwrap() returning net.ErrClosed whatever its code is, and
// qtls.WrapError forwards that, so a genuine fault -- PROTOCOL_VIOLATION, a stateless reset, a
// version-negotiation failure -- satisfies the closed/canceled test and is reported as an
// ordinary teardown. It disappears from the logs entirely.
//
// This type keeps the message and the original condition available through Cause, while
// deliberately NOT implementing Unwrap, so errors.Is/As cannot reach the misleading sentinel.
//
// # errors.As compatibility: intentionally blocked at this boundary
//
// errors.As(visibleFault, *quic.TransportError) returns FALSE. That is a deliberate compatibility
// change at this boundary, not an oversight, and it is unavoidable: the only way errors.As reaches
// the quic-go type is by traversing Unwrap, and that same traversal is the second path by which
// net.ErrClosed leaks in and re-silences the fault.
//
// The underlying error remains available through Cause() for diagnostics.
//
// The downstream callers were audited before accepting the change. The wrapped error is consumed
// only by the accept goroutine, on the line immediately after the call, for the closed/canceled
// test that decides the log level; it never leaves this package. A repository-wide search for
// errors.As against quic-go types finds exactly one other consumer, the DNS-over-QUIC retry
// classifier, and that path does not pass through this boundary at all: it dials with
// qtls.DialEarly directly and never wraps with qtls.WrapError, so it only ever sees raw quic-go
// errors whose typed identity is intact.
//
// # Why this is not a classifier table
//
// Deciding WHICH errors are expected is protocol policy and belongs in one place; duplicating the
// HTTP/3 code table here would create a second definition that could drift. This type only makes
// an already-decided fault visible, and is used by callers that have already established the
// error is not an expected closure.
type visibleFault struct {
	err error
}

func (f *visibleFault) Error() string {
	return f.err.Error()
}

// Is matches only another visibleFault, so a fault never satisfies errors.Is(err, net.ErrClosed).
func (f *visibleFault) Is(target error) bool {
	other, isVisibleFault := target.(*visibleFault)
	return isVisibleFault && f.err.Error() == other.err.Error()
}

// Cause exposes the underlying failure for diagnostics without making it reachable through
// errors.Is/errors.As.
func (f *visibleFault) Cause() error {
	return f.err
}

// asVisibleFault wraps err unless it is an expected closure or already wrapped.
//
// The expected cases are deliberately narrow: only the sentinels the QUIC layer itself uses for
// an orderly end. Anything carrying a quic-go type is treated as a fault, because quic-go's
// no-error conditions are already mapped to those sentinels upstream of this function.
func asVisibleFault(err error) error {
	if err == nil {
		return nil
	}
	var already *visibleFault
	if errors.As(err, &already) {
		return err
	}
	// A quic-go condition decides first: a non-zero code is a fault whatever closed-ness the
	// error also reports. This ordering is the whole point -- every quic-go type unwraps to
	// net.ErrClosed, so testing closed-ness first would call a protocol violation an orderly end.
	if hasQuicSemantics(err) {
		if isExpectedQuicClosure(err) {
			return err
		}
		return &visibleFault{err: err}
	}
	// No quic-go semantics: a bare sentinel is an orderly end. Context cancellation is included
	// because a cancelled server context is how this transport shuts down.
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &visibleFault{err: err}
}

// hasQuicSemantics reports whether the chain carries a quic-go error type at all.
func hasQuicSemantics(err error) bool {
	var (
		transportErr *quic.TransportError
		appErr       *quic.ApplicationError
		streamErr    *quic.StreamError
		idleTimeout  *quic.IdleTimeoutError
		handshakeErr *quic.HandshakeTimeoutError
		// StatelessResetError and VersionNegotiationError both unwrap to net.ErrClosed, so
		// omitting them here made hasQuicSemantics answer false for a real fault, which sent it
		// down the generic closed-ness path below and silenced it. They are listed explicitly
		// because the check is by TYPE, never by message.
		statelessErr *quic.StatelessResetError
		versionErr   *quic.VersionNegotiationError
	)
	return errors.As(err, &transportErr) || errors.As(err, &appErr) ||
		errors.As(err, &streamErr) || errors.As(err, &idleTimeout) ||
		errors.As(err, &handshakeErr) || errors.As(err, &statelessErr) ||
		errors.As(err, &versionErr)
}

// isExpectedQuicClosure reports the quic-go conditions that describe a peer simply going away, or
// a shutdown that raised no error code.
func isExpectedQuicClosure(err error) bool {
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		return transportErr.ErrorCode == quic.NoError
	}
	var applicationErr *quic.ApplicationError
	if errors.As(err, &applicationErr) {
		return applicationErr.ErrorCode == 0
	}
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		// Code 0 means no condition was raised. A remote reset carrying a code is decided by the
		// same no-error rule: only a zero code is an orderly end.
		return streamErr.ErrorCode == 0
	}
	var idleTimeout *quic.IdleTimeoutError
	if errors.As(err, &idleTimeout) {
		return true
	}
	var handshakeTimeout *quic.HandshakeTimeoutError
	if errors.As(err, &handshakeTimeout) {
		return true
	}
	// A stateless reset tears the path down without a close, and a version-negotiation failure
	// means nothing was ever established. Both are real faults: they are named here so the
	// intent is explicit rather than resting on the trailing return.
	var statelessReset *quic.StatelessResetError
	if errors.As(err, &statelessReset) {
		return false
	}
	var versionErr *quic.VersionNegotiationError
	if errors.As(err, &versionErr) {
		return false
	}
	return false
}
