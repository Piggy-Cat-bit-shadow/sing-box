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
	// A transport-level error is a fault unless its code is the no-error code used for an
	// orderly close. This must be decided BEFORE any net.ErrClosed test, because TransportError
	// unwraps to net.ErrClosed regardless of how serious it is.
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		if transportErr.ErrorCode == quic.TransportErrorCode(0) {
			return net.ErrClosed
		}
		// A real transport fault. It is NOT enough to return it unchanged: TransportError's
		// Unwrap reports net.ErrClosed, and the outer quic-go wrapper forwards that, so the
		// routing layer's closed-ness test would still silence it. See visibleFault.
		return asVisibleFault(err)
	}
	// Already a recognised sentinel: leave it alone.
	if E.IsClosedOrCanceled(err) {
		return err
	}
	var h3Err *http3.Error
	if errors.As(err, &h3Err) {
		switch h3Err.ErrorCode {
		case 0:
			// A zero code means "no QUIC-level error": the tunnel simply ended.
			// quic-go surfaces this as an *http3.Error with ErrorCode 0, which
			// formats as "H3 error (0x0)" — exactly the message that was being
			// logged at ERROR for an ordinary teardown. It is NOT
			// http3.ErrCodeNoError (0x100); the two are different values, which is
			// why an earlier attempt at this fix matched nothing.
			return net.ErrClosed
		}
		// Delegate to the shared table so the expected/unexpected split cannot drift
		// between this client-side normalizer and the server-side classifier.
		if classifyH3ErrorCode(h3Err.ErrorCode) == h3ErrorExpected {
			return net.ErrClosed
		}
		// Every other HTTP/3 code (protocol violations, frame and settings
		// errors, QPACK failures, internal errors) is a real fault and is
		// deliberately passed through unchanged.
		return err
	}
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		// A stream reset is decided by the SAME code table the server side uses, so a
		// single definition of "expected" covers both directions.
		//
		// Matching only code 0 here was the bug: a peer cancelling a request sends
		// H3_REQUEST_CANCELLED (0x10c = 268), which quic-go reports as
		// *quic.StreamError{Remote: true, ErrorCode: 268} and formats as
		//
		//	stream 184 canceled by remote with error code 268
		//
		// That is a stream-local cancellation, not a connection fault, but it fell
		// through this branch and was logged at ERROR by route/conn.go. The numeric
		// literal is deliberately not repeated here: classifyH3ErrorCode owns it.
		if classifyH3ErrorCode(http3.ErrCode(streamErr.ErrorCode)) == h3ErrorExpected {
			return net.ErrClosed
		}
		return asVisibleFault(err)
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	// An unclassifiable error is a fault. It must not carry a spurious net.ErrClosed
	// in its chain, or the routing layer will silence it.
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
