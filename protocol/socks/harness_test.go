package socks

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// A harness for the standalone SOCKS inbound.
//
// The inbound is driven through its real entry point (Inbound.NewConnection) and
// the routed connection is captured where the router receives it, so every
// assertion is made on the metadata and the stream the rest of the proxy would
// actually act on -- not on a helper's internal state.
// ---------------------------------------------------------------------------

type capturedConn struct {
	metadata adapter.InboundContext
	conn     net.Conn
	packet   N.PacketConn
	onClose  N.CloseHandlerFunc
}

type captureRouter struct {
	adapter.Router
	connection chan *capturedConn
	packet     chan *capturedConn
}

func newCaptureRouter() *captureRouter {
	return &captureRouter{
		connection: make(chan *capturedConn, 64),
		packet:     make(chan *capturedConn, 64),
	}
}

func (r *captureRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	select {
	case r.connection <- &capturedConn{metadata: metadata, conn: conn, onClose: onClose}:
	default:
	}
}

func (r *captureRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	select {
	case r.packet <- &capturedConn{metadata: metadata, packet: conn, onClose: onClose}:
	default:
	}
}

func (r *captureRouter) waitConnection(t *testing.T) *capturedConn {
	t.Helper()
	select {
	case entry := <-r.connection:
		return entry
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a routed connection")
		return nil
	}
}

// requireNoConnection proves a session was NOT routed, which is the assertion a
// rejection test needs.
func (r *captureRouter) requireNoConnection(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case entry := <-r.connection:
		t.Fatalf("connection was routed: destination %s user %q", entry.metadata.Destination, entry.metadata.User)
	case <-time.After(timeout):
	}
}

type inboundHarness struct {
	inbound *Inbound
	router  *captureRouter
}

func newInboundHarness(t *testing.T, users []auth.User) *inboundHarness {
	t.Helper()
	router := newCaptureRouter()
	created, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "socks-in", option.SocksInboundOptions{Users: users})
	if err != nil {
		t.Fatalf("NewInbound: %v", err)
	}
	inbound, isInbound := created.(*Inbound)
	if !isInbound {
		t.Fatalf("unexpected inbound type %T", created)
	}
	t.Cleanup(func() {
		if inbound.listener != nil {
			_ = inbound.listener.Close()
		}
	})
	return &inboundHarness{inbound: inbound, router: router}
}

func (h *inboundHarness) newConnection(ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc) {
	h.inbound.NewConnection(ctx, conn, adapter.InboundContext{Source: testSource()}, onClose)
}

func testSource() M.Socksaddr {
	return M.SocksaddrFrom(netip.MustParseAddr("192.0.2.10"), 40000)
}

// ---------------------------------------------------------------------------
// A scripted, capability-recording net.Conn double.
//
// The stream is delivered in the caller's chosen chunk sizes, so a test can
// control whether the handshake and the tunnel payload arrive in one read (the
// pipelining case) or in separate ones. A socket double cannot do this: it
// returns whatever the kernel happened to coalesce.
// ---------------------------------------------------------------------------

type scriptedConn struct {
	payload []byte
	reads   []int

	offset  int
	readIdx int
	done    bool

	delivered   int
	readCountMu sync.Mutex

	readDeadline atomic.Pointer[time.Time]

	mu     sync.Mutex
	writes [][]byte
	closed atomic.Int32

	closeRead  int
	closeWrite int

	// onRead is called before every read is served, which is what lets a test
	// sequence two sides without sleeping.
	onRead func()
}

func newScriptedConn(payload []byte, reads ...int) *scriptedConn {
	return &scriptedConn{payload: payload, reads: reads}
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if c.onRead != nil {
		c.onRead()
	}
	if c.done || c.offset >= len(c.payload) {
		if deadline := c.readDeadline.Load(); deadline != nil && !deadline.IsZero() {
			return 0, &timeoutError{}
		}
		c.done = true
		return 0, io.EOF
	}
	size := len(p)
	if c.readIdx < len(c.reads) {
		size = min(size, c.reads[c.readIdx])
		c.readIdx++
	}
	if remaining := len(c.payload) - c.offset; size > remaining {
		size = remaining
	}
	if size <= 0 {
		c.done = true
		return 0, io.EOF
	}
	n := copy(p[:size], c.payload[c.offset:c.offset+size])
	c.offset += n
	c.readCountMu.Lock()
	c.delivered += n
	c.readCountMu.Unlock()
	return n, nil
}

func (c *scriptedConn) bytesDelivered() int {
	c.readCountMu.Lock()
	defer c.readCountMu.Unlock()
	return c.delivered
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	if c.closed.Load() != 0 {
		return 0, io.ErrClosedPipe
	}
	copied := make([]byte, len(p))
	copy(copied, p)
	c.mu.Lock()
	c.writes = append(c.writes, copied)
	c.mu.Unlock()
	return len(p), nil
}

func (c *scriptedConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for _, write := range c.writes {
		out = append(out, write...)
	}
	return out
}

func (c *scriptedConn) Close() error {
	c.closed.Store(1)
	return nil
}

func (c *scriptedConn) CloseRead() error {
	c.mu.Lock()
	c.closeRead++
	c.mu.Unlock()
	return nil
}

func (c *scriptedConn) CloseWrite() error {
	c.mu.Lock()
	c.closeWrite++
	c.mu.Unlock()
	return nil
}

func (c *scriptedConn) halfCloses() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeRead, c.closeWrite
}

func (c *scriptedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}

func (c *scriptedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 40000}
}

func (c *scriptedConn) SetDeadline(t time.Time) error      { return nil }
func (c *scriptedConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *scriptedConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(&t)
	return nil
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// ---------------------------------------------------------------------------
// Handshake corpora
// ---------------------------------------------------------------------------

// socks5NoAuth builds a complete no-authentication SOCKS5 handshake: greeting,
// (no method selection reply is read from the double) and the CONNECT request.
func socks5NoAuth(domain string, port uint16) []byte {
	out := []byte{0x05, 0x01, 0x00}
	out = append(out, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	out = append(out, domain...)
	out = append(out, byte(port>>8), byte(port))
	return out
}

// socks5WithPassword builds the greeting plus the RFC 1929 sub-negotiation and
// the CONNECT request for the credentials given.
func socks5WithPassword(domain string, port uint16, username string, password string) []byte {
	out := []byte{0x05, 0x01, 0x02}
	out = append(out, 0x01, byte(len(username)))
	out = append(out, username...)
	out = append(out, byte(len(password)))
	out = append(out, password...)
	out = append(out, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	out = append(out, domain...)
	out = append(out, byte(port>>8), byte(port))
	return out
}

// socks4Connect builds the SOCKS4 CONNECT request, including a user id.
func socks4Connect(ip [4]byte, port uint16, userID string) []byte {
	out := []byte{0x04, 0x01, byte(port >> 8), byte(port), ip[0], ip[1], ip[2], ip[3]}
	out = append(out, userID...)
	out = append(out, 0x00)
	return out
}

// readExact drains exactly size bytes from a connection.
func readExact(conn net.Conn, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	buffer := make([]byte, 4096)
	for len(out) < size {
		n, err := conn.Read(buffer)
		if n > 0 {
			out = append(out, buffer[:n]...)
		}
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

var _ = bytes.Equal
var _ = auth.User{}
