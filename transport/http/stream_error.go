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
		case 0:
			// A zero code means "no QUIC-level error": the tunnel simply ended.
			// quic-go surfaces this as an *http3.Error with ErrorCode 0, which
			// formats as "H3 error (0x0)" — exactly the message that was being
			// logged at ERROR for an ordinary teardown. It is NOT
			// http3.ErrCodeNoError (0x100); the two are different values, which is
			// why an earlier attempt at this fix matched nothing.
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
