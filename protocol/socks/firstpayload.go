package socks

import (
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	singbufio "github.com/sagernet/sing/common/bufio"
)

// PreReadReader is the reader a handshake parser reads through. It is the
// buffer whose remaining bytes belong to the tunnel once the parser has
// consumed everything it owns.
//
// Both shapes in this tree satisfy it without an adapter: the inbound's own
// *bufio.Reader, and the http.Reader that embeds one.
type PreReadReader interface {
	io.Reader
	// Buffered reports how many bytes the reader already holds.
	Buffered() int
}

// ---------------------------------------------------------------------------
// The first payload of a tunnel that the handshake pre-read.
//
// # The problem
//
// A proxy client may write its first payload byte in the same segment as the
// handshake. A SOCKS client that forwards optimistically does exactly that, and
// so does a browser whose CONNECT request and TLS ClientHello arrive together.
// The handshake reads through a buffered reader, so one Read from the socket can
// pull in bytes that belong to the TUNNEL. Those bytes live in the reader, and
// the socks handshake wraps whatever connection it was given. Passing the bare
// connection therefore hands the routing layer a stream that is missing its
// first bytes, and the tunnel silently starts mid-stream.
//
// # Why the move is deferred to first use
//
// The bytes cannot be moved before the handshake runs: the version byte and the
// rest of the handshake are in that same buffer, and moving it early makes the
// parser read EOF. They cannot be moved after it either, because by then socks
// has already wrapped the connection it will forward.
//
// So this wrapper is what the handshake is given, and it forwards to the raw
// connection until the tunnel side first uses it. That first use is after the
// handshake has consumed everything it owns, so the buffer at that moment holds
// payload and nothing else. The handshake itself never reads through this
// wrapper -- it reads through the parser's reader -- so deferring costs no
// correctness.
//
// # Ownership
//
// The captured payload is a pooled buffer owned by this wrapper, and it is
// released exactly once: by the read that drains it, by WriteTo when it hands
// the bytes to the far side, or by Close when the session ends first. Read and
// Close are serialized by a mutex that is never held across socket I/O, so a
// Close can neither overtake a read that already took the buffer nor wait for a
// read that is blocked on the socket.
//
// # Cost when there is no early data
//
// Every method forwards straight to the embedded connection, so the routing
// layer receives a connection that still reports every real capability it has:
// syscall.Conn, io.ReaderFrom, io.WriterTo and CloseRead/CloseWrite all answer
// for the true underlying socket. The only addition is one branch per call on a
// wrapper that socks already wraps anyway.
// ---------------------------------------------------------------------------

type FirstPayloadConn struct {
	net.Conn
	// reader is the parser's reader, captured at construction. It is only
	// consulted on first use -- which is after the handshake -- so by then its
	// buffer holds tunnel payload and nothing else.
	reader PreReadReader
	// once publishes the capture to every later caller, and is what makes the
	// first use of this wrapper safe when the two copy directions reach it at
	// the same instant.
	once sync.Once
	// access guards pending and closed. It is never held across socket I/O.
	access sync.Mutex
	// pending is the captured payload, or nil when the reader held nothing, when
	// the payload has been handed out, or when the session was closed.
	pending *buf.Buffer
	// closed records that the session was closed, so a capture that races the
	// close is released instead of parked on a connection nobody will read from.
	closed bool
}

// NewFirstPayloadConn wraps conn so that the payload the parser's reader still
// holds is served to the tunnel side before the socket.
func NewFirstPayloadConn(conn net.Conn, reader PreReadReader) net.Conn {
	return &FirstPayloadConn{Conn: conn, reader: reader}
}

// resolve captures the reader's remaining bytes exactly once. It must be called
// before serving any read-side call, so that capability probes and data reads
// agree on what is serving them.
func (c *FirstPayloadConn) resolve() {
	c.once.Do(func() {
		if c.reader == nil {
			return
		}
		buffered := c.reader.Buffered()
		if buffered == 0 {
			return
		}
		buffer := buf.NewSize(buffered)
		if _, err := buffer.ReadFullFrom(c.reader, buffered); err != nil {
			buffer.Release()
			return
		}
		c.access.Lock()
		if c.closed {
			c.access.Unlock()
			buffer.Release()
			return
		}
		c.pending = buffer
		c.access.Unlock()
	})
}

// buffered reports whether payload is still waiting in front of the socket.
func (c *FirstPayloadConn) buffered() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.pending != nil
}

func (c *FirstPayloadConn) Read(p []byte) (int, error) {
	c.resolve()
	c.access.Lock()
	pending := c.pending
	if pending == nil {
		c.access.Unlock()
		return c.Conn.Read(p)
	}
	n, err := pending.Read(p)
	if err != nil {
		// The only error a buffer reports is io.EOF, which means it is empty.
		// Serving that to the caller would end the tunnel one read early: the
		// socket may still have data.
		c.pending = nil
		pending.Release()
		c.access.Unlock()
		return c.Conn.Read(p)
	}
	if pending.IsEmpty() {
		// The last buffered byte was handed out by this call. Releasing here --
		// rather than on the next call, which may never come -- is what makes
		// the reader replaceable as soon as nothing is buffered any more, and
		// what returns the pooled buffer on the normal path.
		c.pending = nil
		pending.Release()
	}
	c.access.Unlock()
	return n, nil
}

// Write deliberately does NOT resolve the capture.
//
// The handshake writes its reply before it has read the request, so at that
// moment the parser's buffer still holds handshake bytes that the parser has not
// consumed yet. Resolving there would move those bytes onto the connection and
// the parser would then read them twice. Writes do not need the buffered payload
// -- it is inbound data -- so the capture is confined to the read side, which the
// handshake never touches.
func (c *FirstPayloadConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p)
}

// WriteTo hands the captured payload to w and then copies the socket, which is
// the io.WriterTo contract over the whole remaining stream.
//
// The buffer is taken under the same lock a close takes, so the close can never
// release it while it is being written, and it is released exactly once even
// when the write fails: after a failed write the stream is broken, and holding
// the bytes back would only add a second owner.
func (c *FirstPayloadConn) WriteTo(w io.Writer) (int64, error) {
	c.resolve()
	c.access.Lock()
	pending := c.pending
	c.pending = nil
	c.access.Unlock()
	var n int64
	if pending != nil {
		written, err := pending.WriteTo(w)
		n += written
		pending.Release()
		if err != nil {
			return n, err
		}
	}
	copied, err := singbufio.Copy(w, c.Conn)
	return n + copied, err
}

// ReadFrom forwards to the socket. The buffered payload is inbound data, so a
// write-side copy neither consumes nor needs it.
func (c *FirstPayloadConn) ReadFrom(r io.Reader) (int64, error) {
	if readerFrom, isReaderFrom := c.Conn.(io.ReaderFrom); isReaderFrom {
		return readerFrom.ReadFrom(r)
	}
	return singbufio.Copy(struct{ io.Writer }{c.Conn}, r)
}

// CloseRead and CloseWrite forward to the socket without resolving the capture.
//
// Resolving here would drain the parser's reader from whichever goroutine closes
// the half-connection, which may be a different goroutine from the one the
// handshake is reading on. A half-close is a property of the socket, and the
// buffered payload is unaffected by it, so there is nothing to resolve for.
func (c *FirstPayloadConn) CloseRead() error {
	if closer, isCloser := c.Conn.(interface{ CloseRead() error }); isCloser {
		return closer.CloseRead()
	}
	return nil
}

func (c *FirstPayloadConn) CloseWrite() error {
	if closer, isCloser := c.Conn.(interface{ CloseWrite() error }); isCloser {
		return closer.CloseWrite()
	}
	return nil
}

// Close releases the captured payload -- exactly once -- and closes the socket.
//
// It does not resolve the capture: Close can be reached while the handshake is
// still reading through the parser's reader (a cancelled session, a rejected
// handshake), and draining that reader from this goroutine would race the parser
// and hand it EOF. Closing the socket is what ends such a session; the payload
// of a session that never reached the tunnel has no reader left to serve.
func (c *FirstPayloadConn) Close() error {
	c.access.Lock()
	c.closed = true
	pending := c.pending
	c.pending = nil
	c.access.Unlock()
	if pending != nil {
		pending.Release()
	}
	return c.Conn.Close()
}

// ReaderReplaceable and WriterReplaceable answer the two capability questions
// separately, because the buffered payload only affects one of them.
//
// # Read side
//
// A reader that still holds payload must report itself NOT replaceable: that is
// the signal the copy loop reads before it decides it may splice the raw socket,
// and a splice decided before the payload is consumed would skip it. Once
// nothing is buffered the answer is yes, which lets the walk descend through
// Upstream() to the socket and find whatever capability the socket really has --
// syscall.Conn, io.ReaderFrom, a splice-capable raw connection. Answering "yes"
// here is not a capability claim: Upstream() is what answers that.
//
// # Write side
//
// Writing never touches the buffered payload, so the write path must not be
// degraded by inbound buffering. Answering "yes" lets the write-side walk
// descend to the socket, exactly as it would if this wrapper were not in the
// chain. It does not resolve the capture either: the write answer does not
// depend on it, and resolving from the download goroutine would make that
// goroutine a second first-user of the wrapper for no reason.
func (c *FirstPayloadConn) ReaderReplaceable() bool {
	c.resolve()
	return !c.buffered()
}

func (c *FirstPayloadConn) WriterReplaceable() bool {
	return true
}

func (c *FirstPayloadConn) Upstream() any {
	return c.Conn
}
