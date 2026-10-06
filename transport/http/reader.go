package http

import (
	std_bufio "bufio"
	"io"
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
)

var errHeaderTooLarge = E.New("request header too large")

type Reader struct {
	*std_bufio.Reader
	limiter *readLimiter
}

func NewReader(conn net.Conn) *Reader {
	limiter := &readLimiter{reader: conn, remaining: -1}
	return &Reader{
		Reader:  std_bufio.NewReader(limiter),
		limiter: limiter,
	}
}

func (r *Reader) setLimit(limit int64) {
	r.limiter.remaining = limit
}

// BufferedConn returns a connection that yields the bytes already buffered by
// this reader before anything else, and nil when nothing is buffered.
//
// # When it may be called
//
// ONLY after the parser has consumed everything it owns. Peek() does not
// consume, so calling this before the handshake moves the handshake itself into
// the cache and the parser then reads EOF.
//
// # Why every parser needs it, and why it cannot live in the parsers
//
// Peek(1) and the handshake that follows read through a bufio.Reader, so a
// single Read from the socket can pull in bytes that belong to the TUNNEL and
// not to the handshake. A browser writes the CONNECT request and the TLS
// ClientHello into one segment, and an optimistic SOCKS client forwards the
// first payload byte the same way. Those bytes are held by THIS reader, so a
// parser that hands its own `conn` downstream silently truncates the stream.
//
// The HTTP/1 path used to be the only caller of the copy below. It is now
// shared, so the SOCKS path gets the same guarantee instead of the same bug.
//
// # Ownership
//
// The returned connection owns the copy: closing it releases the buffer back to
// the pool. The caller must not use this reader again afterwards.
//
// The data is COPIED, not referenced. Referencing the bufio.Reader's slice would
// be both incorrect (its region may start at a non-zero offset) and unsafe (the
// pool would reclaim storage that is still reachable). Correctness is worth one
// pooled allocation.
func (r *Reader) BufferedConn(conn net.Conn) net.Conn {
	buffered := r.Buffered()
	if buffered == 0 {
		return nil
	}
	buffer := buf.NewSize(buffered)
	_, err := buffer.ReadFullFrom(r, buffer.FreeLen())
	if err != nil {
		buffer.Release()
		return nil
	}
	return bufio.NewCachedConn(conn, buffer)
}

// cachedConn is the internal spelling used by the HTTP/1 and HTTP/2 servers,
// which always want a usable connection rather than an optional one.
func (r *Reader) cachedConn(conn net.Conn) net.Conn {
	if cached := r.BufferedConn(conn); cached != nil {
		return cached
	}
	return conn
}

type readLimiter struct {
	reader    io.Reader
	remaining int64
}

func (r *readLimiter) Read(p []byte) (int, error) {
	if r.remaining < 0 {
		return r.reader.Read(p)
	}
	if r.remaining == 0 {
		return 0, errHeaderTooLarge
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

var _ io.Reader = (*readLimiter)(nil)
