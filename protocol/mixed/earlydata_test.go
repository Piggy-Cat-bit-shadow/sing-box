package mixed

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
)

// ---------------------------------------------------------------------------
// P0-2: early data.
//
// A proxy client is allowed to write the tunnel payload in the same TCP segment
// as the handshake, and a browser does exactly that: the CONNECT request and the
// TLS ClientHello routinely arrive in one read, and a SOCKS client with
// optimistic forwarding does the same. The user-space reader in front of the
// parser therefore holds bytes that belong to the TUNNEL, not the handshake.
//
// The contract these tests pin down:
//
//	bytes.Equal(sentPayload, routedPayload) == true
//
// for every fragmentation of the input, with the payload read EXACTLY once.
// ---------------------------------------------------------------------------

type earlyDataCase struct {
	name      string
	handshake []byte
	payload   []byte
}

func earlyDataCases() []earlyDataCase {
	payload32 := bytes.Repeat([]byte{0xA5}, 32)
	payload512 := bytes.Repeat([]byte{0x5A}, 512)
	payload16K := make([]byte, 16*1024)
	for i := range payload16K {
		payload16K[i] = byte(i)
	}
	hello := tlsClientHelloLike(517)

	var cases []earlyDataCase
	for _, payload := range []struct {
		name string
		data []byte
	}{
		{"32B", payload32},
		{"512B", payload512},
		{"ClientHello", hello},
		{"16KB", payload16K},
	} {
		cases = append(cases,
			earlyDataCase{
				name:      "http/" + payload.name,
				handshake: []byte(httpConnectNoAuth),
				payload:   payload.data,
			},
			earlyDataCase{
				name:      "socks5/" + payload.name,
				handshake: socks5NoAuth("example.com", 443, nil),
				payload:   payload.data,
			},
			earlyDataCase{
				name:      "socks4a/" + payload.name,
				handshake: socks4a("example.com", 443, "", nil),
				payload:   payload.data,
			},
		)
	}
	return cases
}

// fragmentations returns the read-chunk plans each case is driven with.
func fragmentations(total int) []struct {
	name string
	plan []int
} {
	return []struct {
		name string
		plan []int
	}{
		{"all-at-once", []int{total}},
		{"1-byte", chunkPlan(total, 1)},
		{"2-byte", chunkPlan(total, 2)},
		{"7-byte", chunkPlan(total, 7)},
		{"random", randomChunkPlan(total, 0x5EED)},
		{"kernelish", chunkPlan(total, 1448)},
	}
}

func TestEarlyDataIsDeliveredExactlyOnce(t *testing.T) {
	for _, testCase := range earlyDataCases() {
		testCase := testCase
		stream := append(append([]byte{}, testCase.handshake...), testCase.payload...)
		for _, fragmentation := range fragmentations(len(stream)) {
			fragmentation := fragmentation
			t.Run(testCase.name+"/"+fragmentation.name, func(t *testing.T) {
				harness := newInboundHarness(t, nil)
				conn := newScriptedConn(stream, fragmentation.plan...)
				recorder := newCloseRecorder()
				harness.newConnection(context.Background(), conn, testSource(), recorder.handler())

				routed := harness.router.waitConnection(t)
				payload, err := readExact(routed.conn, len(testCase.payload))
				if err != nil {
					t.Fatalf("read routed payload: %v (got %d/%d bytes)", err, len(payload), len(testCase.payload))
				}
				if !bytes.Equal(payload, testCase.payload) {
					t.Fatalf("payload mismatch\n got: %x\nwant: %x", payload, testCase.payload)
				}
				// Drained: the tunnel must now report EOF, not hand back the
				// same bytes a second time.
				extra := make([]byte, 512)
				n, _ := routed.conn.Read(extra)
				if n != 0 {
					t.Fatalf("payload read twice: %d extra bytes %x", n, extra[:n])
				}
				// Hard tripwire: a replay wrapper would have pulled more bytes
				// out of the double than the client ever wrote.
				if delivered := conn.bytesDelivered(); delivered > len(stream) {
					t.Fatalf("read %d bytes from a %d byte stream: bytes were replayed", delivered, len(stream))
				}
			})
		}
	}
}

// TestEarlyDataBoundarySplits splits the stream on the exact boundary between
// "the parser consumed this" and "this belongs to the tunnel", which is where an
// off-by-one replay wrapper shows up. Every boundary of every handshake shape is
// exercised, not just a chosen few.
func TestEarlyDataBoundarySplits(t *testing.T) {
	payload := bytes.Repeat([]byte{0xC3}, 64)
	streams := []struct {
		name      string
		handshake []byte
	}{
		{"http", []byte(httpConnectNoAuth)},
		{"socks5", socks5NoAuth("example.com", 443, nil)},
		{"socks4a", socks4a("example.com", 443, "", nil)},
	}
	for _, stream := range streams {
		stream := stream
		for boundary := 1; boundary < len(stream.handshake); boundary++ {
			boundary := boundary
			full := append(append([]byte{}, stream.handshake...), payload...)
			t.Run(stream.name+"/"+itoa(boundary), func(t *testing.T) {
				harness := newInboundHarness(t, nil)
				conn := newScriptedConn(full, boundary, len(full)-boundary)
				harness.newConnection(context.Background(), conn, testSource(), nil)
				routed := harness.router.waitConnection(t)
				got, err := readExact(routed.conn, len(payload))
				if err != nil {
					t.Fatalf("boundary %d: read payload: %v", boundary, err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("boundary %d: payload mismatch", boundary)
				}
			})
		}
	}
}

// TestHandshakeOnlyLeavesNoPhantomPayload proves the converse: when the client
// sends the handshake and NOTHING else, the routed connection must not invent
// bytes, and must report EOF once drained.
func TestHandshakeOnlyLeavesNoPhantomPayload(t *testing.T) {
	streams := []struct {
		name string
		data []byte
	}{
		{"http", []byte(httpConnectNoAuth)},
		{"socks5-domain", socks5NoAuth("example.com", 443, nil)},
		{"socks5-ipv4", socks5NoAuthIPv4([4]byte{192, 0, 2, 1}, 80, nil)},
		{"socks4a", socks4a("example.com", 443, "", nil)},
	}
	for _, stream := range streams {
		stream := stream
		t.Run(stream.name, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			conn := newScriptedConn(stream.data)
			harness.newConnection(context.Background(), conn, testSource(), nil)
			routed := harness.router.waitConnection(t)
			got := make([]byte, 512)
			n, err := routed.conn.Read(got)
			if n != 0 {
				t.Fatalf("phantom payload %x", got[:n])
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The same contract on a connection that BLOCKS instead of reporting EOF.
//
// A real proxy connection does not report EOF when the client pauses; it waits.
// A double that reports EOF immediately would let a broken implementation pass,
// because the parser would never have the chance to over-read the late payload.
// ---------------------------------------------------------------------------

// blockingConn returns the scripted stream, then blocks in Read until more data
// is appended (or the deadline expires). It is what proves that payload arriving
// AFTER the hand-off is not swallowed by the parser and dropped.
type blockingConn struct {
	mu      sync.Mutex
	cond    *sync.Cond
	payload []byte
	offset  int
	closed  bool

	readDeadline atomicTime
	mu2          sync.Mutex
	writes       [][]byte
}

func newBlockingConn(payload []byte) *blockingConn {
	conn := &blockingConn{payload: payload}
	conn.cond = sync.NewCond(&conn.mu)
	return conn
}

func (c *blockingConn) append(data []byte) {
	c.mu.Lock()
	c.payload = append(c.payload, data...)
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *blockingConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	for c.offset >= len(c.payload) {
		if c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		// The deadline only bounds the wait for NEW data, exactly as a socket
		// does. It is checked here rather than before the copy below so that
		// buffered data is never discarded by a deadline.
		if deadline, ok := c.readDeadline.load(); ok && !deadline.IsZero() {
			c.mu.Unlock()
			return 0, &timeoutError{}
		}
		c.cond.Wait()
	}
	n := copy(p, c.payload[c.offset:])
	c.offset += n
	c.mu.Unlock()
	return n, nil
}

func (c *blockingConn) Write(p []byte) (int, error) {
	copied := make([]byte, len(p))
	copy(copied, p)
	c.mu2.Lock()
	c.writes = append(c.writes, copied)
	c.mu2.Unlock()
	return len(p), nil
}

func (c *blockingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *blockingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51000}
}

func (c *blockingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
}

func (c *blockingConn) SetDeadline(t time.Time) error { return nil }
func (c *blockingConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.store(t)
	return nil
}
func (c *blockingConn) SetWriteDeadline(t time.Time) error { return nil }

type atomicTime struct {
	mu    sync.Mutex
	value time.Time
	set   bool
}

func (a *atomicTime) store(t time.Time) {
	a.mu.Lock()
	a.value = t
	a.set = true
	a.mu.Unlock()
}

func (a *atomicTime) load() (time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.value, a.set
}

func TestPayloadAfterHandoffIsNotSwallowed(t *testing.T) {
	late := bytes.Repeat([]byte{0x77}, 128)
	streams := []struct {
		name      string
		handshake []byte
	}{
		{"http", []byte(httpConnectNoAuth)},
		{"socks5", socks5NoAuth("example.com", 443, nil)},
	}
	for _, stream := range streams {
		stream := stream
		t.Run(stream.name, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			conn := newBlockingConn(stream.handshake)
			// The handshake does not complete until the whole client greeting has
			// arrived, so the payload that is meant to arrive AFTER the hand-off
			// has to be delivered from another goroutine: the fast path owns this
			// goroutine until it has routed.
			go func() {
				time.Sleep(50 * time.Millisecond)
				conn.append(late)
			}()
			harness.newConnection(context.Background(), conn, testSource(), nil)
			routed := harness.router.waitConnection(t)

			got, err := readExact(routed.conn, len(late))
			if err != nil {
				t.Fatalf("read late payload: %v (got %d/%d)", err, len(got), len(late))
			}
			if !bytes.Equal(got, late) {
				t.Fatalf("late payload mismatch\n got: %x\nwant: %x", got, late)
			}
			_ = conn.Close()
		})
	}
}

// ---------------------------------------------------------------------------
// P0-1: first-byte integrity and metadata correctness under fragmentation.
//
// The discriminator peeks one byte, and the same bytes must then be visible to
// the parser exactly once. These tests drive every protocol through extreme
// fragmentation and assert the metadata the parser produced.
// ---------------------------------------------------------------------------

func TestProtocolDetectionUnderFragmentation(t *testing.T) {
	type expected struct {
		domain string
		port   uint16
	}
	cases := []struct {
		name   string
		stream []byte
		expect expected
		user   string
	}{
		{
			name:   "http-domain",
			stream: []byte(httpConnectNoAuth),
			expect: expected{domain: "example.com", port: 443},
		},
		{
			name:   "http-ipv4",
			stream: []byte(httpConnectTo("192.0.2.7:8080")),
			expect: expected{domain: "192.0.2.7", port: 8080},
		},
		{
			name:   "http-ipv6",
			stream: []byte(httpConnectTo("[2001:db8::1]:8443")),
			expect: expected{domain: "2001:db8::1", port: 8443},
		},
		{
			name:   "http-ipv4-no-port",
			stream: []byte(httpConnectTo("192.0.2.8")),
			// An HTTP CONNECT with no port defaults to 443, which is the
			// existing semantic and must not change.
			expect: expected{domain: "192.0.2.8", port: 443},
		},
		{
			name:   "socks5-domain",
			stream: socks5NoAuth("example.org", 8443, nil),
			expect: expected{domain: "example.org", port: 8443},
		},
		{
			name:   "socks5-ipv4",
			stream: socks5NoAuthIPv4([4]byte{198, 51, 100, 9}, 3128, nil),
			expect: expected{domain: "198.51.100.9", port: 3128},
		},
		{
			name:   "socks5-ipv6",
			stream: socks5NoAuthIPv6([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42}, 9443, nil),
			expect: expected{domain: "2001:db8::42", port: 9443},
		},
		{
			name:   "socks4a-domain",
			stream: socks4a("socks4a.example", 1080, "alice", nil),
			expect: expected{domain: "socks4a.example", port: 1080},
			// A SOCKS4 user id is an IDENT claim, not a credential. It only
			// becomes metadata.User when an authenticator actually verified it.
			// With no users configured there is nothing to verify it against, so
			// it must not be reported as an authenticated user.
			user: "",
		},
		{
			name:   "socks4-ipv4",
			stream: socks4Stream([4]byte{203, 0, 113, 5}, 9050, "bob", nil),
			expect: expected{domain: "203.0.113.5", port: 9050},
			user:   "",
		},
	}

	for _, testCase := range cases {
		testCase := testCase
		for _, fragmentation := range fragmentations(len(testCase.stream)) {
			fragmentation := fragmentation
			t.Run(testCase.name+"/"+fragmentation.name, func(t *testing.T) {
				harness := newInboundHarness(t, nil)
				conn := newScriptedConn(testCase.stream, fragmentation.plan...)
				harness.newConnection(context.Background(), conn, testSource(), nil)
				routed := harness.router.waitConnection(t)

				metadata := routed.metadata
				if got := metadata.Destination.AddrString(); got != testCase.expect.domain {
					t.Fatalf("destination address = %q, want %q", got, testCase.expect.domain)
				}
				if metadata.Destination.Fqdn != "" && metadata.Destination.Addr.IsValid() {
					t.Fatalf("destination carries both a domain %q and an address %s", metadata.Destination.Fqdn, metadata.Destination.Addr)
				}
				if metadata.Destination.Port != testCase.expect.port {
					t.Fatalf("destination port = %d, want %d", metadata.Destination.Port, testCase.expect.port)
				}
				if metadata.Source.String() != testSource().String() {
					t.Fatalf("source = %s, want %s", metadata.Source, testSource())
				}
				if metadata.Inbound != "mixed-in" {
					t.Fatalf("inbound = %q", metadata.Inbound)
				}
				if metadata.InboundType != "Mixed" && metadata.InboundType != "mixed" {
					t.Fatalf("inbound type = %q", metadata.InboundType)
				}
				if metadata.User != testCase.user {
					t.Fatalf("user = %q, want %q", metadata.User, testCase.user)
				}
			})
		}
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

var _ = auth.User{}
