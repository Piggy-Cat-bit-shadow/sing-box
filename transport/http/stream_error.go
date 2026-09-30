package http

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
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
//
// # The closed-ness check must come AFTER the quic-go types, not before
//
// quic-go's TransportError implements Unwrap() returning net.ErrClosed. That is convenient for
// callers who only want "is this connection finished", but it means a genuine transport fault --
// PROTOCOL_VIOLATION, FRAME_ENCODING_ERROR, a flow-control violation -- reports as closed.
//
// E.IsClosedOrCanceled consults net.ErrClosed, so a transport fault used to satisfy this
// function's early exit and be handed back untouched; route/conn.go then applied the SAME test
// and classified a protocol violation as an ordinary teardown, erasing it from the logs.
//
// The concrete quic-go types are therefore examined first, exactly as classifyH3Error does, and
// only a fault-free error may reach the closed-ness shortcut.
func normalizeStreamError(err error) error {
	if err == nil {
		return nil
	}
	// TYPED CLASSIFICATION COMES FIRST, ALWAYS.
	//
	// Every quic-go error type -- TransportError, ApplicationError, StatelessResetError,
	// VersionNegotiationError, IdleTimeoutError, HandshakeTimeoutError -- implements
	// Unwrap() returning net.ErrClosed, whatever its error code is. A generic
	// E.IsClosedOrCanceled test therefore answers "closed" for a PROTOCOL_VIOLATION just as
	// readily as for an orderly shutdown, and running it before the typed checks silently
	// erases real faults from the logs.
	//
	// So the concrete types are examined first, and only an error that carries no quic-go
	// semantics at all may reach the generic closed-ness shortcut below.
	if normalized, handled := normalizeTypedQuicError(err); handled {
		return normalized
	}
	// No quic-go type in the chain. A bare closed/canceled sentinel is a normal teardown.
	if E.IsClosedOrCanceled(err) {
		return err
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	// An unclassifiable error is a fault. It must not carry a spurious net.ErrClosed
	// in its chain, or the routing layer will silence it.
	return asVisibleFault(err)
}

// normalizeTypedQuicError classifies an error that carries a quic-go type.
//
// It reports handled=false when the chain contains no quic-go type at all, which is the signal
// for the caller to fall back to the generic closed-ness test.
//
// The order inside is deliberate: the more specific a type's code semantics, the earlier it is
// examined. Everything that reaches the final branch is an HTTP/3 code decided by the SHARED
// table (classifyH3ErrorCode), so the client normalizer and the server classifier cannot drift.
func normalizeTypedQuicError(err error) (error, bool) {
	// A transport-level error is a fault unless its code is the no-error code used for an
	// orderly close.
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		if transportErr.ErrorCode == quic.TransportErrorCode(0) {
			return net.ErrClosed, true
		}
		return asVisibleFault(err), true
	}
	// An APPLICATION error carries the peer's own code space. quic.NoError (0) is the orderly
	// shutdown; anything else is the peer reporting a fault and must stay visible.
	//
	// This branch previously did not exist, so an ApplicationError carrying a real fault code
	// fell through to the generic net.ErrClosed test and was reported as an ordinary teardown.
	var applicationErr *quic.ApplicationError
	if errors.As(err, &applicationErr) {
		if applicationErr.ErrorCode == quic.ApplicationErrorCode(0) {
			return net.ErrClosed, true
		}
		return asVisibleFault(err), true
	}
	// An HTTP/3 application error carries a numeric code. Zero means "no error"; the rest are
	// decided by the shared table.
	var h3Err *http3.Error
	if errors.As(err, &h3Err) {
		if h3Err.ErrorCode == 0 {
			// A zero code means "no QUIC-level error": the tunnel simply ended.
			// quic-go surfaces this as an *http3.Error with ErrorCode 0, which
			// formats as "H3 error (0x0)" — exactly the message that was being
			// logged at ERROR for an ordinary teardown. It is NOT
			// http3.ErrCodeNoError (0x100); the two are different values, which is
			// why an earlier attempt at this fix matched nothing.
			return net.ErrClosed, true
		}
		return classifyH3Code(h3Err.ErrorCode, err), true
	}
	// A stream reset. Matching only code 0 here was the original bug: a peer cancelling a
	// request sends H3_REQUEST_CANCELLED (0x10c = 268), which quic-go reports as
	// *quic.StreamError{Remote: true, ErrorCode: 268} and formats as
	//
	//	stream 184 canceled by remote with error code 268
	//
	// That is a stream-local cancellation, not a connection fault, but it used to fall through
	// and be logged at ERROR by route/conn.go. The numeric literal is deliberately not repeated
	// here: classifyH3ErrorCode owns it.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return classifyH3Code(http3.ErrCode(streamErr.ErrorCode), err), true
	}
	// A stateless reset means the peer or a middlebox told us the connection is gone without
	// shutting it down. That is a real, notable event on an active path -- not an orderly
	// teardown -- and it unwraps to net.ErrClosed, so it must be made visible explicitly.
	var statelessReset *quic.StatelessResetError
	if errors.As(err, &statelessReset) {
		return asVisibleFault(err), true
	}
	// Version negotiation failing means no usable QUIC version was agreed. Nothing was ever
	// established, so this is a dial-time fault worth reporting, not a closed connection.
	var versionErr *quic.VersionNegotiationError
	if errors.As(err, &versionErr) {
		return asVisibleFault(err), true
	}
	// Idle and handshake timeouts describe a peer that went away, which is routine.
	var idleTimeout *quic.IdleTimeoutError
	if errors.As(err, &idleTimeout) {
		return net.ErrClosed, true
	}
	var handshakeTimeout *quic.HandshakeTimeoutError
	if errors.As(err, &handshakeTimeout) {
		return net.ErrClosed, true
	}
	return nil, false
}

// classifyH3Code maps an HTTP/3 code onto the shared expected/unexpected split.
func classifyH3Code(code http3.ErrCode, err error) error {
	// Code 0 is "no error at all", which is how quic-go reports a stream or connection that
	// ended without anyone raising a condition. It is deliberately NOT part of
	// classifyH3ErrorCode's table -- that table speaks HTTP/3 codes, where the no-error value is
	// ErrCodeNoError (0x100), a different number. Treating 0 as a fault would log every ordinary
	// stream close, which is the very noise this function exists to remove.
	if code == 0 {
		return net.ErrClosed
	}
	if classifyH3ErrorCode(code) == h3ErrorExpected {
		return net.ErrClosed
	}
	return asVisibleFault(err)
}

// visibleFault reports a genuine fault while hiding any misleading net.ErrClosed in the chain.
//
// # Why a wrapper is needed at all
//
// quic-go's TransportError.Unwrap() returns net.ErrClosed whatever the error code is. That makes
// "the connection finished" indistinguishable from "the peer violated the protocol" to anything
// testing for closed-ness -- and route/conn.go decides the log level with exactly such a test:
//
//	if !E.IsClosedOrCanceled(err) {
//	    m.logger.ErrorContext(ctx, "connection upload closed: ", err)
//	}
//
// Returning the raw fault therefore does NOT get it logged: E.IsClosedOrCanceled sees the
// TransportError's net.ErrClosed and calls a PROTOCOL_VIOLATION an ordinary teardown, so it
// disappears from the logs.
//
// This type keeps the message and the original condition -- Unwrap is deliberately NOT
// implemented, so errors.Is/As cannot reach the misleading sentinel -- while exposing Cause for
// callers that want the underlying error.
type visibleFault struct {
	err error
}

func (f *visibleFault) Error() string {
	return f.err.Error()
}

// Is reports matching only against another visibleFault, so a fault never satisfies
// errors.Is(err, net.ErrClosed).
func (f *visibleFault) Is(target error) bool {
	other, isVisibleFault := target.(*visibleFault)
	return isVisibleFault && f.err.Error() == other.err.Error()
}

// Cause exposes the underlying failure for diagnostics without making it reachable through
// errors.Is/errors.As.
func (f *visibleFault) Cause() error {
	return f.err
}

func asVisibleFault(err error) error {
	if err == nil {
		return nil
	}
	var already *visibleFault
	if errors.As(err, &already) {
		return err
	}
	return &visibleFault{err: err}
}

// normalizingConn applies error normalization at the outermost connection
// boundary handed to the routing layer.
//
// The embedded field is deliberately a NAMED field rather than an anonymous
// embed. sing's N.UnwrapReader / N.UnwrapWriter walk the Upstream() chain and
// `bufio.Copy` uses the fully unwrapped reader and writer, so an anonymous embed
// would promote the inner conn's Upstream()/ReaderReplaceable()/WriterReplaceable()
// methods and let the copy path skip this wrapper entirely. Keeping the inner
// conn in a named field means those methods are not promoted, the unwrap chain
// stops here, and normalization actually applies.
type normalizingConn struct {
	inner net.Conn
}

// net.Conn surface, delegating explicitly so nothing is promoted accidentally.
func (c *normalizingConn) Read(p []byte) (int, error) {
	n, err := c.inner.Read(p)
	return n, normalizeStreamError(err)
}

func (c *normalizingConn) Write(p []byte) (int, error) {
	n, err := c.inner.Write(p)
	return n, normalizeStreamError(err)
}

func (c *normalizingConn) Close() error {
	return c.inner.Close()
}

func (c *normalizingConn) LocalAddr() net.Addr {
	return c.inner.LocalAddr()
}

func (c *normalizingConn) RemoteAddr() net.Addr {
	return c.inner.RemoteAddr()
}

func (c *normalizingConn) SetDeadline(t time.Time) error {
	return c.inner.SetDeadline(t)
}

func (c *normalizingConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}

func (c *normalizingConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}

// WriteBuffer and ReadBuffer carry the buffered copy path, which is what
// route/conn.go actually uses.
func (c *normalizingConn) WriteBuffer(buffer *buf.Buffer) error {
	extendedConn, isExtendedConn := c.inner.(N.ExtendedConn)
	if !isExtendedConn {
		return nil
	}
	return normalizeStreamError(extendedConn.WriteBuffer(buffer))
}

func (c *normalizingConn) ReadBuffer(buffer *buf.Buffer) error {
	extendedConn, isExtendedConn := c.inner.(N.ExtendedConn)
	if !isExtendedConn {
		return nil
	}
	return normalizeStreamError(extendedConn.ReadBuffer(buffer))
}

// ReadFrom is used by the copy path when the destination supports it.
func (c *normalizingConn) ReadFrom(reader io.Reader) (int64, error) {
	if readFrom, isReadFrom := c.inner.(io.ReaderFrom); isReadFrom {
		n, err := readFrom.ReadFrom(reader)
		return n, normalizeStreamError(err)
	}
	return io.Copy(struct{ io.Writer }{c}, reader)
}

// WriteTo is the mirror of ReadFrom.
func (c *normalizingConn) WriteTo(writer io.Writer) (int64, error) {
	if writeTo, isWriteTo := c.inner.(io.WriterTo); isWriteTo {
		n, err := writeTo.WriteTo(writer)
		return n, normalizeStreamError(err)
	}
	return io.Copy(writer, struct{ io.Reader }{c})
}

// CloseWrite forwards half-close, normalizing its error too. route/conn.go calls
// it through N.WriteCloser, so it is one of the paths an orderly close travels.
func (c *normalizingConn) CloseWrite() error {
	if writeCloser, isWriteCloser := c.inner.(N.WriteCloser); isWriteCloser {
		return normalizeStreamError(writeCloser.CloseWrite())
	}
	return nil
}

// NeedHandshakeForWrite forwards the optional handshake hint.
func (c *normalizingConn) NeedHandshakeForWrite() bool {
	return N.NeedHandshakeForWrite(c.inner)
}

// NormalizeStreamErrorForTest exposes the normalizer to the external integration
// test module, which cannot reach unexported identifiers. It exists so the test/
// module can assert the property the routing layer depends on: that a normally
// closed HTTP/3 stream satisfies E.IsClosedOrCanceled and is therefore not logged
// at ERROR.
func NormalizeStreamErrorForTest(err error) error {
	return normalizeStreamError(err)
}
