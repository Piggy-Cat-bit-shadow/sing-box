package mixed

import (
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
// A scripted, fragmenting, capability-recording net.Conn double.
//
// The cooperative fast path's correctness is entirely about how many bytes one
// Read is allowed to return at a time, and about which optional interfaces
// survive the hand-off. A net.Pipe (or a real socket) hides both: it returns
// whatever the kernel happened to coalesce, and it cannot be made to expose or
// hide syscall.Conn / ReaderFrom / WriterTo / CloseRead / CloseWrite on demand.
// ---------------------------------------------------------------------------

type scriptedConn struct {
	payload []byte
	// reads is the chunk plan: the size of each successive Read. Repeated once
	// exhausted; empty means "return as much as fits".
	reads []int

	offset  int
	readIdx int
	done    bool
	// delivered counts every byte this double has handed to a Read. It is the
	// exact-once tripwire: a replay wrapper makes it larger than the stream.
	//
	// Reads happen on a single goroutine (the connection's owner); readCountMu
	// only exists so a test goroutine can observe the counter safely.
	delivered   int
	readCountMu sync.Mutex

	readDeadline  atomic.Pointer[time.Time]
	writeDeadline atomic.Pointer[time.Time]
	terminalErr   error

	mu          sync.Mutex
	writes      [][]byte
	deadlineLog []deadlineEvent
	closed      int
	closeRead   int
	closeWrite  int
}

type deadlineEvent struct {
	read  bool
	value time.Time
}

func newScriptedConn(payload []byte, reads ...int) *scriptedConn {
	return &scriptedConn{payload: payload, reads: reads}
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	// Data that is already available is returned BEFORE the read deadline is
	// consulted. A real socket behaves this way: a deadline bounds the wait for
	// new data, it does not discard data that has already arrived. Getting this
	// order wrong makes a double that enforces a deadline against buffered bytes
	// look exactly like a fast path that lost the payload.
	if c.done || c.offset >= len(c.payload) {
		if err := c.readDeadlineError(); err != nil {
			return 0, err
		}
		c.done = true
		return 0, c.err()
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
		return 0, c.err()
	}
	n := copy(p[:size], c.payload[c.offset:c.offset+size])
	c.offset += n
	c.readCountMu.Lock()
	c.delivered += n
	c.readCountMu.Unlock()
	return n, nil
}

// bytesDelivered is the number of bytes this double has handed to a Read.
func (c *scriptedConn) bytesDelivered() int {
	c.readCountMu.Lock()
	defer c.readCountMu.Unlock()
	return c.delivered
}

// newScriptedConnWithTail is a scripted connection whose reads continue past the
// point where a guard rejects, so a test can prove the rejection is sticky
// rather than a one-off.
func newScriptedConnWithTail(stream []byte) *scriptedConn {
	// reads=nil means "return as much as fits", which is what the guard sees on a
	// real socket that already has the whole request buffered.
	return newScriptedConn(append([]byte{}, stream...))
}

// appendPayload delivers more bytes to a connection that is already in use,
// which is how a test models a client that sends its payload only after the
// proxy has accepted the tunnel.
func (c *scriptedConn) appendPayload(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.payload = append(c.payload, data...)
	c.done = false
	c.terminalErr = nil
}

func (c *scriptedConn) err() error {
	if c.terminalErr != nil {
		return c.terminalErr
	}
	return io.EOF
}

func (c *scriptedConn) readDeadlineError() error {
	ptr := c.readDeadline.Load()
	if ptr == nil || ptr.IsZero() {
		return nil
	}
	if time.Now().After(*ptr) {
		return &timeoutError{}
	}
	return nil
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func (c *scriptedConn) Write(p []byte) (int, error) {
	ptr := c.writeDeadline.Load()
	if ptr != nil && !ptr.IsZero() && time.Now().After(*ptr) {
		return 0, &timeoutError{}
	}
	copied := make([]byte, len(p))
	copy(copied, p)
	c.mu.Lock()
	c.writes = append(c.writes, copied)
	c.mu.Unlock()
	return len(p), nil
}

func (c *scriptedConn) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}

func (c *scriptedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51000}
}

func (c *scriptedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
}

func (c *scriptedConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *scriptedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlineLog = append(c.deadlineLog, deadlineEvent{read: true, value: t})
	c.mu.Unlock()
	value := t
	c.readDeadline.Store(&value)
	return nil
}

func (c *scriptedConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlineLog = append(c.deadlineLog, deadlineEvent{read: false, value: t})
	c.mu.Unlock()
	value := t
	c.writeDeadline.Store(&value)
	return nil
}

// CloseRead / CloseWrite make the double look like a conn that has them, so a
// regression can prove whether the fast path preserved half-close.
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

func (c *scriptedConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for _, chunk := range c.writes {
		out = append(out, chunk...)
	}
	return out
}

func (c *scriptedConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func (c *scriptedConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *scriptedConn) pendingReadDeadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.deadlineLog) - 1; i >= 0; i-- {
		if c.deadlineLog[i].read {
			return c.deadlineLog[i].value, true
		}
	}
	return time.Time{}, false
}

// capabilityConn adds the optional interfaces a shared core looks for. It is a
// distinct type because Go embedding would expose them through the scriptedConn
// too, and the point is to test whether the fast path STRIPPED them.
type capabilityConn struct {
	*scriptedConn
	readFromCalls atomic.Int64
	writeToCalls  atomic.Int64
}

func (c *capabilityConn) ReadFrom(r io.Reader) (int64, error) {
	c.readFromCalls.Add(1)
	return io.Copy(io.Discard, r)
}

func (c *capabilityConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalls.Add(1)
	return 0, nil
}

func (c *capabilityConn) SyscallConn() (interface {
	Control(func(uintptr)) error
	Read(func(uintptr) bool) error
	Write(func(uintptr) bool) error
}, error) {
	return rawSyscallConn{}, nil
}

type rawSyscallConn struct{}

func (rawSyscallConn) Control(func(uintptr)) error   { return nil }
func (rawSyscallConn) Read(func(uintptr) bool) error { return nil }
func (rawSyscallConn) Write(func(uintptr) bool) error {
	return nil
}

// ---------------------------------------------------------------------------
// Router double: captures exactly what the fast path handed to the shared core.
// ---------------------------------------------------------------------------

type capturedConn struct {
	metadata adapter.InboundContext
	conn     net.Conn
	packet   N.PacketConn
	// onClose is what the fast path handed the routing layer. A test that wants
	// to model the routing layer finishing may call it.
	onClose N.CloseHandlerFunc
}

// captureRouter delivers every routed connection into a buffered channel. It
// records nothing outside that channel on the hot path: an earlier revision
// appended to a side slice, which meant a benchmark running a million iterations
// accumulated a million live entries and ended up measuring the harness's
// garbage instead of the code under test.
type captureRouter struct {
	adapter.Router
	connection chan *capturedConn
	packet     chan *capturedConn
}

// captureBuffer is deep enough that a burst of concurrent sessions never blocks
// a producer and a benchmark never fills it.
const captureBuffer = 1 << 16

func newCaptureRouter() *captureRouter {
	return &captureRouter{
		connection: make(chan *capturedConn, captureBuffer),
		packet:     make(chan *capturedConn, captureBuffer),
	}
}

func (r *captureRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	entry := &capturedConn{metadata: metadata, conn: conn, onClose: onClose}
	select {
	case r.connection <- entry:
	default:
	}
}

// drainRouted returns every connection routed so far. It is only safe once no
// producer is still running, which is what a test that waits for all its
// sessions guarantees.
func (r *captureRouter) drainRouted() []*capturedConn {
	var entries []*capturedConn
	for {
		select {
		case entry := <-r.connection:
			entries = append(entries, entry)
		default:
			return entries
		}
	}
}

func (r *captureRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	entry := &capturedConn{metadata: metadata, packet: conn, onClose: onClose}
	select {
	case r.packet <- entry:
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

func (r *captureRouter) waitPacket(t *testing.T) *capturedConn {
	t.Helper()
	select {
	case entry := <-r.packet:
		return entry
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a routed packet connection")
		return nil
	}
}

// ---------------------------------------------------------------------------
// Inbound construction
// ---------------------------------------------------------------------------

type inboundHarness struct {
	inbound *Inbound
	router  *captureRouter
}

func newInboundHarness(t *testing.T, users []auth.User) *inboundHarness {
	t.Helper()
	router := newCaptureRouter()
	created, err := NewInbound(context.Background(), router, testNOPLogger(), "mixed-in", httpMixedOptions(users))
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

// httpMixedOptions builds the inbound options used by every test and benchmark.
// ListenPort 0 keeps the options valid without binding a well-known port, and
// the listener is only created -- never started -- because these tests drive
// NewConnection directly.
func httpMixedOptions(users []auth.User) option.HTTPMixedInboundOptions {
	options := option.HTTPMixedInboundOptions{Users: users}
	options.ListenPort = 0
	return options
}

func testNOPLogger() log.ContextLogger {
	return log.NewNOPFactory().Logger()
}

func (h *inboundHarness) newConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.inbound.NewConnection(ctx, conn, adapter.InboundContext{Source: source}, onClose)
}

func testSource() M.Socksaddr {
	return M.SocksaddrFrom(netip.MustParseAddr("192.0.2.10"), 40000)
}

// closeRecorder records CloseHandlerFunc invocations so a regression can prove
// it ran exactly once.
//
// It also exposes a channel that is closed by the first invocation, so a test
// that expects a connection to be REJECTED can wait for the decision instead of
// sleeping for it. A rejection is asynchronous: the fast path writes the failure
// reply and then reports through onClose.
type closeRecorder struct {
	calls  atomic.Int32
	mu     sync.Mutex
	errs   []error
	closed chan struct{}
	once   sync.Once
}

func newCloseRecorder() *closeRecorder {
	return &closeRecorder{closed: make(chan struct{})}
}

func (c *closeRecorder) handler() N.CloseHandlerFunc {
	return func(err error) {
		c.calls.Add(1)
		c.mu.Lock()
		c.errs = append(c.errs, err)
		c.mu.Unlock()
		c.once.Do(func() { close(c.closed) })
	}
}

func (c *closeRecorder) count() int { return int(c.calls.Load()) }

// wait blocks until the connection is reported closed, or the deadline passes.
// countPlusWait returns the number of invocations after ensuring the decision
// has been made, so an assertion on an exact count is not a race against the
// rejection path.
func (c *closeRecorder) countPlusWait(timeout time.Duration) int {
	c.wait(timeout)
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.errs)
}

func (c *closeRecorder) wait(timeout time.Duration) bool {
	select {
	case <-c.closed:
		return true
	case <-time.After(timeout):
		return false
	}
}

// ---------------------------------------------------------------------------
// Handshake corpora
// ---------------------------------------------------------------------------

const httpConnectNoAuth = "CONNECT example.com:443 HTTP/1.1\r\n" +
	"Host: example.com:443\r\n" +
	"\r\n"

// httpConnectAuth carries Proxy-Authorization: Basic dXNlcjpwYXNz (user:pass).
const httpConnectAuth = "CONNECT example.com:443 HTTP/1.1\r\n" +
	"Host: example.com:443\r\n" +
	"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" +
	"\r\n"

func httpConnectTo(hostport string) string {
	return "CONNECT " + hostport + " HTTP/1.1\r\nHost: " + hostport + "\r\n\r\n"
}

// httpConnectAuthFor builds an authenticated CONNECT for hostport:443 using the
// u1/p1 credentials the auth tests configure.
func httpConnectAuthFor(host string) string {
	return "CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\n" +
		"Proxy-Authorization: Basic dTE6cDE=\r\n\r\n" // u1:p1
}

// socks5NoAuth is the complete SOCKS5 greeting + CONNECT + request for a domain.
func socks5NoAuth(domain string, port uint16, payload []byte) []byte {
	out := []byte{0x05, 0x01, 0x00}
	out = append(out, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	out = append(out, domain...)
	out = append(out, byte(port>>8), byte(port))
	return append(out, payload...)
}

// socks5NoAuthIPv4 is the complete SOCKS5 greeting + CONNECT for an IPv4 target.
func socks5NoAuthIPv4(ip [4]byte, port uint16, payload []byte) []byte {
	out := []byte{0x05, 0x01, 0x00}
	out = append(out, 0x05, 0x01, 0x00, 0x01)
	out = append(out, ip[:]...)
	out = append(out, byte(port>>8), byte(port))
	return append(out, payload...)
}

// socks5NoAuthIPv6 is the complete SOCKS5 greeting + CONNECT for an IPv6 target.
func socks5NoAuthIPv6(ip [16]byte, port uint16, payload []byte) []byte {
	out := []byte{0x05, 0x01, 0x00}
	out = append(out, 0x05, 0x01, 0x00, 0x04)
	out = append(out, ip[:]...)
	out = append(out, byte(port>>8), byte(port))
	return append(out, payload...)
}

// socks5Auth is greeting (user/pass offered) + RFC1929 sub-negotiation + CONNECT.
func socks5Auth(username, password, domain string, port uint16, payload []byte) []byte {
	out := []byte{0x05, 0x02, 0x00, 0x02}
	out = append(out, 0x01, byte(len(username)))
	out = append(out, username...)
	out = append(out, byte(len(password)))
	out = append(out, password...)
	out = append(out, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	out = append(out, domain...)
	out = append(out, byte(port>>8), byte(port))
	return append(out, payload...)
}

func socks4a(domain string, port uint16, userID string, payload []byte) []byte {
	out := []byte{0x04, 0x01, byte(port >> 8), byte(port), 0x00, 0x00, 0x00, 0x01}
	out = append(out, userID...)
	out = append(out, 0x00)
	out = append(out, domain...)
	out = append(out, 0x00)
	return append(out, payload...)
}

func socks4Stream(ip [4]byte, port uint16, userID string, payload []byte) []byte {
	out := []byte{0x04, 0x01, byte(port >> 8), byte(port), ip[0], ip[1], ip[2], ip[3]}
	out = append(out, userID...)
	out = append(out, 0x00)
	return append(out, payload...)
}

// readExact drains exactly size bytes from a routed connection.
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

// tlsClientHelloLike returns a plausible TLS ClientHello-shaped payload: the
// bytes that must survive the hand-off byte for byte.
func tlsClientHelloLike(size int) []byte {
	out := make([]byte, size)
	out[0] = 0x16 // handshake
	out[1] = 0x03
	out[2] = 0x01
	out[3] = byte((size - 5) >> 8)
	out[4] = byte(size - 5)
	if size > 5 {
		out[5] = 0x01 // client_hello
	}
	for i := 6; i < size; i++ {
		out[i] = byte(i * 7)
	}
	return out
}

// chunkPlan builds a chunk plan that splits total bytes according to a
// repeating pattern of read sizes.
func chunkPlan(total int, pattern ...int) []int {
	if len(pattern) == 0 {
		return nil
	}
	var plan []int
	pos := 0
	for pos < total {
		for _, size := range pattern {
			if pos >= total {
				break
			}
			if size <= 0 || size > total-pos {
				size = total - pos
			}
			plan = append(plan, size)
			pos += size
		}
	}
	return plan
}

// randomChunkPlan splits total bytes into pseudo-randomly sized reads with a
// fixed seed, so a failure is reproducible.
func randomChunkPlan(total int, seed uint32) []int {
	var plan []int
	pos := 0
	state := seed | 1
	for pos < total {
		state = state*1664525 + 1013904223
		size := int(state>>16)%7 + 1
		if size > total-pos {
			size = total - pos
		}
		plan = append(plan, size)
		pos += size
	}
	return plan
}
