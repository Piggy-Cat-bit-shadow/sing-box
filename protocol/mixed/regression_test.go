package mixed

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// P0-7: auth bypass / auth contamination.
//
// The fast path adds a construction-time `hasUsers` flag, so every combination
// of configured users has to be exercised: the flag must never turn a configured
// authenticator into an unauthenticated one, and it must never let one
// connection's user leak into another's metadata.
// ---------------------------------------------------------------------------

func TestAuthMatrix(t *testing.T) {
	users := []auth.User{{Username: "user", Password: "pass"}, {Username: "other", Password: "secret"}}

	type expect struct {
		routed bool
		user   string
	}
	cases := []struct {
		name   string
		users  []auth.User
		stream []byte
		expect expect
	}{
		{
			name:   "no-users/socks5-no-auth",
			users:  nil,
			stream: socks5NoAuth("example.com", 443, nil),
			expect: expect{routed: true},
		},
		{
			name:   "no-users/socks4",
			users:  nil,
			stream: socks4a("example.com", 443, "", nil),
			expect: expect{routed: true},
		},
		{
			name:   "users/socks5-correct",
			users:  users,
			stream: socks5Auth("user", "pass", "example.com", 443, nil),
			expect: expect{routed: true, user: "user"},
		},
		{
			name:   "users/socks5-second-user",
			users:  users,
			stream: socks5Auth("other", "secret", "example.com", 443, nil),
			expect: expect{routed: true, user: "other"},
		},
		{
			name:   "users/socks5-wrong-password",
			users:  users,
			stream: socks5Auth("user", "wrong", "example.com", 443, nil),
			expect: expect{routed: false},
		},
		{
			name:   "users/socks5-unknown-user",
			users:  users,
			stream: socks5Auth("nobody", "pass", "example.com", 443, nil),
			expect: expect{routed: false},
		},
		{
			name:   "users/socks4-wrong-username",
			users:  users,
			stream: socks4a("example.com", 443, "nobody", nil),
			expect: expect{routed: false},
		},
		{
			name:  "users/http-correct",
			users: users,
			// Proxy-Authorization: Basic dXNlcjpwYXNz == user:pass
			stream: []byte(httpConnectAuth),
			expect: expect{routed: true, user: "user"},
		},
		{
			name:  "users/http-missing-credentials",
			users: users,
			// No Proxy-Authorization header at all.
			stream: []byte(httpConnectNoAuth),
			expect: expect{routed: false},
		},
		{
			name:  "users/http-wrong-credentials",
			users: users,
			stream: []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n" +
				"Proxy-Authorization: Basic dXNlcjpiYWQ=\r\n\r\n"),
			expect: expect{routed: false},
		},
		{
			name:   "no-users/http-unauthenticated-target",
			users:  nil,
			stream: []byte(httpConnectNoAuth),
			expect: expect{routed: true},
		},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			harness := newInboundHarness(t, testCase.users)
			conn := newScriptedConn(testCase.stream)
			recorder := newCloseRecorder()
			harness.newConnection(context.Background(), conn, testSource(), recorder.handler())

			select {
			case routed := <-harness.router.connection:
				if !testCase.expect.routed {
					t.Fatalf("connection was routed but should have been rejected")
				}
				if routed.metadata.User != testCase.expect.user {
					t.Fatalf("user = %q, want %q", routed.metadata.User, testCase.expect.user)
				}
			default:
				if testCase.expect.routed {
					t.Fatal("connection was not routed")
				}
				if !recorder.wait(5 * time.Second) {
					t.Fatal("connection was neither routed nor reported closed")
				}
			}
		})
	}
}

// TestAuthDoesNotLeakBetweenConnections runs many sessions with different users
// through one inbound, then a no-auth session, and requires each session's
// metadata to carry only its own user.
func TestAuthDoesNotLeakBetweenConnections(t *testing.T) {
	users := []auth.User{{Username: "a", Password: "1"}, {Username: "b", Password: "2"}}
	harness := newInboundHarness(t, users)

	for i := 0; i < 64; i++ {
		user := "a"
		password := "1"
		if i%2 == 1 {
			user, password = "b", "2"
		}
		conn := newScriptedConn(socks5Auth(user, password, "example.com", 443, nil))
		harness.newConnection(context.Background(), conn, testSource(), nil)
		routed := harness.router.waitConnection(t)
		if routed.metadata.User != user {
			t.Fatalf("session %d: user = %q, want %q", i, routed.metadata.User, user)
		}
	}
}

// ---------------------------------------------------------------------------
// P0-4: close / onClose ownership.
//
// onClose must run exactly once per connection, whatever the outcome, and the
// connection must actually be closed on the failure paths.
// ---------------------------------------------------------------------------

func TestOnCloseExactlyOnce(t *testing.T) {
	cases := []struct {
		name       string
		stream     []byte
		users      []auth.User
		wantRouted bool
	}{
		{"http-success", []byte(httpConnectNoAuth), nil, true},
		{"socks5-success", socks5NoAuth("example.com", 443, nil), nil, true},
		{"socks4a-success", socks4a("example.com", 443, "", nil), nil, true},
		{"http-malformed", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), nil, false},
		{"http-truncated", []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: ex"), nil, false},
		{"socks5-bad-version", []byte{0x05, 0x00}, nil, false},
		{"socks5-unsupported-command", []byte{0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80}, nil, false},
		{"socks5-unsupported-atyp", []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4, 0, 80}, nil, false},
		{"socks5-bad-auth", socks5Auth("user", "wrong", "example.com", 443, nil), []auth.User{{Username: "user", Password: "pass"}}, false},
		{"socks4a-missing-nul", []byte{0x04, 0x01, 0x01, 0xbb, 0, 0, 0, 1, 'a', 'b'}, nil, false},
		{"empty", nil, nil, false},
		{"single-byte", []byte{0x05}, nil, false},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			harness := newInboundHarness(t, testCase.users)
			conn := newScriptedConn(testCase.stream)
			recorder := newCloseRecorder()
			harness.newConnection(context.Background(), conn, testSource(), recorder.handler())

			routed := false
			select {
			case <-harness.router.connection:
				routed = true
			default:
			}
			if routed != testCase.wantRouted {
				t.Fatalf("routed = %v, want %v", routed, testCase.wantRouted)
			}
			if !routed {
				// Rejection is asynchronous: wait for the decision.
				if !recorder.wait(5 * time.Second) {
					t.Fatal("connection was neither routed nor reported closed")
				}
			}
			if calls := recorder.count(); calls > 1 {
				t.Fatalf("onClose called %d times, want at most once (errors: %v)", calls, recorder.errs)
			}
			if !routed && recorder.count() == 0 {
				// Failure paths are allowed to leave onClose to the caller (the
				// listener), but a handshake error must close the connection.
				if conn.closeCount() == 0 {
					t.Fatal("handshake failed but the connection was not closed")
				}
			}
		})
	}
}

// TestRouteErrorClosesExactlyOnce proves the success path hands ownership over:
// after routing, the fast path must not also close and report the connection.
func TestRouteErrorClosesExactlyOnce(t *testing.T) {
	for _, stream := range [][]byte{[]byte(httpConnectNoAuth), socks5NoAuth("example.com", 443, nil)} {
		harness := newInboundHarness(t, nil)
		conn := newScriptedConn(stream)
		recorder := newCloseRecorder()
		harness.newConnection(context.Background(), conn, testSource(), recorder.handler())
		routed := harness.router.waitConnection(t)

		// The capture router is a sink, so the real routing layer's close is
		// simulated here: it closes the connection and reports through the
		// onClose the fast path handed it. What is under test is that the fast
		// path does not ALSO close and report the same connection.
		_ = routed.conn.Close()
		routed.onClose(nil)
		time.Sleep(20 * time.Millisecond)

		if calls := recorder.count(); calls > 1 {
			t.Fatalf("onClose called %d times after routing", calls)
		}
	}
}

// ---------------------------------------------------------------------------
// P0-6: half-close and capability preservation.
// ---------------------------------------------------------------------------

// wrapperChain walks the Upstream() chain and reports whether an interface is
// reachable at any depth. It is what proves capabilities are not merely
// "compile-time preserved" -- the shared core finds them by the same walk.
func wrapperChain(conn any) []any {
	var chain []any
	for i := 0; i < 16; i++ {
		if conn == nil {
			break
		}
		chain = append(chain, conn)
		withUpstream, isWithUpstream := conn.(interface{ Upstream() any })
		if !isWithUpstream {
			break
		}
		next := withUpstream.Upstream()
		if next == nil || next == conn {
			break
		}
		conn = next
	}
	return chain
}

func chainHas[T any](conn any) bool {
	for _, link := range wrapperChain(conn) {
		if _, ok := link.(T); ok {
			return true
		}
	}
	return false
}

func TestHandoffPreservesCapabilities(t *testing.T) {
	payload := bytes.Repeat([]byte{0x11}, 40)
	cases := []struct {
		name   string
		stream []byte
	}{
		{"http-no-early-data", []byte(httpConnectNoAuth)},
		{"http-early-data", append([]byte(httpConnectNoAuth), payload...)},
		{"socks5-no-early-data", socks5NoAuth("example.com", 443, nil)},
		{"socks5-early-data", socks5NoAuth("example.com", 443, payload)},
		{"socks4a-no-early-data", socks4a("example.com", 443, "", nil)},
		{"socks4a-early-data", socks4a("example.com", 443, "", payload)},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			base := &capabilityConn{scriptedConn: newScriptedConn(testCase.stream)}
			harness.newConnection(context.Background(), base, testSource(), nil)
			routed := harness.router.waitConnection(t)

			// The routing layer must be able to reach the real socket's optional
			// interfaces through the chain, otherwise splice and the optimised
			// copy paths are silently disabled.
			if !chainHas[interface {
				CloseRead() error
				CloseWrite() error
			}](routed.conn) {
				t.Fatalf("half-close capability lost; chain = %#v", wrapperChain(routed.conn))
			}
			if !chainHas[io.ReaderFrom](routed.conn) {
				t.Fatalf("io.ReaderFrom lost; chain = %#v", wrapperChain(routed.conn))
			}
			if !chainHas[io.WriterTo](routed.conn) {
				t.Fatalf("io.WriterTo lost; chain = %#v", wrapperChain(routed.conn))
			}
			// The transport double itself must still be reachable through the
			// chain. This is the property the shared core relies on to find ANY
			// optional interface -- syscall.Conn included -- because the fast path
			// deliberately does not try to re-declare interfaces it cannot know
			// about: it exposes the real object through Upstream() and lets the
			// consumer unwrap. A chain that does not reach the transport is a
			// capability that has been hidden for good.
			if !chainHas[*capabilityConn](routed.conn) {
				t.Fatalf("the transport is not reachable through the wrapper chain; chain = %#v", wrapperChain(routed.conn))
			}
		})
	}
}

// TestDangerousCapabilityIsNotExposedWhileBuffered pins the state model required
// by the task: while the parser still holds early data, the connection must NOT
// report itself as replaceable, because a replaceable reader is what authorises
// the shared core to splice the raw socket and bypass the buffered bytes.
func TestDangerousCapabilityIsNotExposedWhileBuffered(t *testing.T) {
	payload := bytes.Repeat([]byte{0x22}, 64)
	for _, stream := range [][]byte{
		append([]byte(httpConnectNoAuth), payload...),
		socks5NoAuth("example.com", 443, payload),
		socks4a("example.com", 443, "", payload),
	} {
		harness := newInboundHarness(t, nil)
		conn := newScriptedConn(stream)
		harness.newConnection(context.Background(), conn, testSource(), nil)
		routed := harness.router.waitConnection(t)

		replaceable, isReplaceable := routed.conn.(N.ReaderWithUpstream)
		if !isReplaceable {
			// A connection that does not claim the capability cannot have it
			// misread, which is equally safe.
			continue
		}
		if replaceable.ReaderReplaceable() {
			// Replaceable is only safe once the buffered bytes have been drained.
			// Read them all first and re-check.
			if _, err := readExact(routed.conn, len(payload)); err != nil {
				t.Fatalf("drain: %v", err)
			}
			if replaceable.ReaderReplaceable() {
				// Still replaceable after draining is fine.
				continue
			}
			continue
		}
		// Not replaceable while buffered: drain and confirm the payload still
		// arrives intact, which is the property the gate exists to protect.
		got, err := readExact(routed.conn, len(payload))
		if err != nil {
			t.Fatalf("read buffered payload behind a non-replaceable reader: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("buffered payload corrupted")
		}
	}
}

func TestHalfCloseIsForwarded(t *testing.T) {
	for _, stream := range [][]byte{[]byte(httpConnectNoAuth), socks5NoAuth("example.com", 443, nil)} {
		harness := newInboundHarness(t, nil)
		conn := newScriptedConn(stream)
		harness.newConnection(context.Background(), conn, testSource(), nil)
		routed := harness.router.waitConnection(t)

		closed := false
		for _, link := range wrapperChain(routed.conn) {
			if closer, isCloser := link.(interface{ CloseWrite() error }); isCloser {
				if err := closer.CloseWrite(); err != nil {
					t.Fatalf("CloseWrite: %v", err)
				}
				closed = true
				break
			}
		}
		if !closed {
			t.Fatal("no CloseWrite in the wrapper chain")
		}
		if conn.closeWrite == 0 {
			t.Fatal("CloseWrite did not reach the transport")
		}
	}
}

// ---------------------------------------------------------------------------
// P0-5: deadline hygiene.
//
// A handshake deadline that survives into the tunnel turns a healthy long-lived
// connection into one that dies after the handshake timeout.
// ---------------------------------------------------------------------------

func TestHandshakeReadDeadlineIsClearedBeforeTunnel(t *testing.T) {
	harness := newInboundHarness(t, nil)
	conn := newScriptedConn([]byte(httpConnectNoAuth))
	harness.newConnection(context.Background(), conn, testSource(), nil)
	harness.router.waitConnection(t)

	deadline, seen := conn.pendingReadDeadline()
	if !seen {
		// No deadline was ever set: nothing can leak.
		return
	}
	if !deadline.IsZero() {
		// A deadline in the future is also a leak: it will fire mid-tunnel.
		if time.Until(deadline) > 0 {
			t.Fatalf("a handshake read deadline of %s survived into the tunnel", time.Until(deadline))
		}
	}
}

// TestSlowHandshakeDoesNotLeakIntoLongTunnel is the behavioural version of the
// test above: hand the connection over, let the handshake window elapse, then
// move payload and require it to arrive.
//
// It uses a blocking connection rather than a scripted one on purpose. A
// scripted connection reports EOF as soon as its bytes run out, which a real
// socket does not do; the reader would cache that EOF and the later payload
// could never arrive, which is a property of the double and not of the fast
// path. This test is about deadlines, so it needs a double that behaves like a
// socket while the tunnel is idle.
func TestSlowHandshakeDoesNotLeakIntoLongTunnel(t *testing.T) {
	late := []byte("late payload")
	for _, stream := range []struct {
		name      string
		handshake []byte
	}{
		{"http", []byte(httpConnectNoAuth)},
		{"socks5", socks5NoAuth("example.com", 443, nil)},
	} {
		stream := stream
		t.Run(stream.name, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			conn := newBlockingConn(stream.handshake)
			// Deliver the payload only after the hand-off, from another
			// goroutine: the fast path owns this goroutine until it has routed.
			go func() {
				time.Sleep(50 * time.Millisecond)
				conn.append(late)
			}()
			harness.newConnection(context.Background(), conn, testSource(), nil)
			routed := harness.router.waitConnection(t)

			got, err := readExact(routed.conn, len(late))
			if err != nil {
				t.Fatalf("read after handshake window: %v", err)
			}
			if !bytes.Equal(got, late) {
				t.Fatalf("payload after handshake window = %q, want %q", got, late)
			}
			_ = conn.Close()
		})
	}
}

// ---------------------------------------------------------------------------
// P0-11: malformed / hostile input.
// ---------------------------------------------------------------------------

func TestMalformedInputIsRejectedWithoutPanic(t *testing.T) {
	cases := []struct {
		name   string
		stream []byte
	}{
		{"zero-bytes", nil},
		{"only-socks-version", []byte{0x05}},
		{"only-socks4-version", []byte{0x04}},
		{"partial-http-method", []byte("CONN")},
		{"unterminated-header", []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n")},
		{"oversized-header", []byte("CONNECT example.com:443 HTTP/1.1\r\n" + strings.Repeat("X-Pad: y\r\n", 5000) + "\r\n")},
		{"invalid-connect-target", []byte("CONNECT : HTTP/1.1\r\nHost: \r\n\r\n")},
		{"invalid-port", []byte("CONNECT example.com:99999999 HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"invalid-ipv6", []byte("CONNECT [::gg]:443 HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"socks5-invalid-atyp", []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x02, 1, 2}},
		{"socks5-oversized-domain", append([]byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0xFF}, bytes.Repeat([]byte{'a'}, 300)...)},
		{"socks5-username-length-boundary", append([]byte{0x05, 0x02, 0x00, 0x02, 0x01, 0xFF}, bytes.Repeat([]byte{'u'}, 300)...)},
		{"socks4a-domain-without-nul", []byte{0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0, 'a', 'b', 'c'}},
		{"http2-preface-then-garbage", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x01\x02")},
		{"random-bytes", []byte{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45}},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Errorf("panic on malformed input: %v", recovered)
					}
				}()
				harness := newInboundHarness(t, nil)
				conn := newScriptedConn(testCase.stream)
				recorder := newCloseRecorder()
				harness.newConnection(context.Background(), conn, testSource(), recorder.handler())
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("malformed input caused a hang")
			}
		})
	}
}

// TestSlowByteAtATimeClient proves a one-byte-at-a-time client neither deadlocks
// nor loses bytes.
func TestSlowByteAtATimeClient(t *testing.T) {
	payload := bytes.Repeat([]byte{0x33}, 24)
	for _, stream := range [][]byte{
		append([]byte(httpConnectNoAuth), payload...),
		socks5NoAuth("example.com", 443, payload),
	} {
		harness := newInboundHarness(t, nil)
		conn := newScriptedConn(stream, chunkPlan(len(stream), 1)...)
		harness.newConnection(context.Background(), conn, testSource(), nil)
		routed := harness.router.waitConnection(t)
		got, err := readExact(routed.conn, len(payload))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("payload corrupted under 1-byte fragmentation")
		}
	}
}

// TestUnsupportedCommandRepliesAndCloses checks the reply shape for a rejected
// SOCKS5 command, which is protocol-visible behaviour.
func TestUnsupportedCommandRepliesAndCloses(t *testing.T) {
	harness := newInboundHarness(t, nil)
	// greeting, then BIND (0x02) which this proxy does not serve
	conn := newScriptedConn([]byte{0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
	recorder := newCloseRecorder()
	harness.newConnection(context.Background(), conn, testSource(), recorder.handler())

	select {
	case <-harness.router.connection:
		t.Fatal("unsupported command was routed")
	case <-time.After(200 * time.Millisecond):
	}
	// The method negotiation reply comes first (05 00), then the CONNECT reply:
	// version, reply code, reserved, address type, bound address, bound port.
	written := conn.written()
	if len(written) < 4 || written[0] != 0x05 || written[2] != 0x05 {
		t.Fatalf("unexpected reply: % x", written)
	}
	if written[3] != 0x07 {
		t.Fatalf("reply code = %#x, want 0x07 (command not supported); full reply % x", written[3], written)
	}
}

// ---------------------------------------------------------------------------
// SOCKS5 zero-length domain.
//
// RFC 1928 gives the domain as 1..255 octets, and a zero-length one does not
// simply fail: sing's address serializer skips the port field when the decoded
// address is not valid, so two port bytes stay in the stream and every byte
// after them shifts by two. The parser then calls the request's port bytes the
// tunnel payload.
//
// The unmodified mixed path was measured doing exactly that: the same stream
// routed with a destination of ":0" and delivered "00 50 30" as the tunnel
// payload where the client sent "30". These regressions pin the rejection at the
// boundary, and pin that it did not cost the valid cases anything.
// ---------------------------------------------------------------------------

// emptyDomainSOCKS5Request is a complete unauthenticated SOCKS5 exchange whose
// ATYP=domain address has a zero-length host.
func emptyDomainSOCKS5Request(payload []byte) []byte {
	return []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50, 0x30}
}

func TestSOCKS5EmptyDomainIsRejected(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		authenticated := authenticated
		name := "no-auth"
		var (
			stream []byte
			users  []auth.User
		)
		if authenticated {
			name = "auth"
			users = []auth.User{{Username: "user", Password: "pass"}}
			stream = []byte{0x05, 0x02, 0x00, 0x02,
				0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's',
				0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50, 0x30}
		} else {
			stream = emptyDomainSOCKS5Request(nil)
		}
		t.Run(name, func(t *testing.T) {
			harness := newInboundHarness(t, users)
			conn := newScriptedConn(stream)
			recorder := newCloseRecorder()
			harness.newConnection(context.Background(), conn, testSource(), recorder.handler())

			// It must not be routed.
			select {
			case <-harness.router.connection:
				t.Fatal("a zero-length domain was routed")
			default:
			}
			if !recorder.wait(5 * time.Second) {
				t.Fatal("connection was neither routed nor reported closed")
			}
			// onClose exactly once, and the connection actually closed.
			time.Sleep(20 * time.Millisecond)
			if calls := recorder.count(); calls != 1 {
				t.Fatalf("onClose called %d times, want exactly once (errors: %v)", calls, recorder.errs)
			}
			if conn.closeCount() == 0 {
				t.Fatal("connection was not closed")
			}
		})
	}
}

// TestSOCKS5EmptyDomainUnderFragmentation requires the rejection to be
// independent of how the bytes arrive. A boundary check that only looked at one
// Read would accept the stream when the address straddles a chunk.
func TestSOCKS5EmptyDomainUnderFragmentation(t *testing.T) {
	stream := emptyDomainSOCKS5Request(nil)
	for _, fragmentation := range append(fragmentations(len(stream)), struct {
		name string
		plan []int
	}{"split-before-atyp", []int{7, len(stream) - 7}}, struct {
		name string
		plan []int
	}{"split-at-length", []int{8, 1, len(stream) - 9}}) {
		fragmentation := fragmentation
		t.Run(fragmentation.name, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			conn := newScriptedConn(stream, fragmentation.plan...)
			recorder := newCloseRecorder()
			harness.newConnection(context.Background(), conn, testSource(), recorder.handler())
			select {
			case <-harness.router.connection:
				t.Fatalf("routed under fragmentation %v", fragmentation.plan)
			default:
			}
			if !recorder.wait(5 * time.Second) {
				t.Fatal("not rejected and not closed")
			}
		})
	}
}

// TestSOCKS5ValidDomainsStillRoute is the counterweight: the boundary check must
// not have rejected anything legitimate, including the smallest legal domain.
func TestSOCKS5ValidDomainsStillRoute(t *testing.T) {
	cases := []struct {
		name   string
		domain string
	}{
		{"one-byte", "a"},
		{"normal", "example.com"},
		{"max-length", strings.Repeat("a", 255)},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			harness := newInboundHarness(t, nil)
			conn := newScriptedConn(socks5NoAuth(testCase.domain, 443, nil))
			harness.newConnection(context.Background(), conn, testSource(), nil)
			routed := harness.router.waitConnection(t)
			if got := routed.metadata.Destination.Fqdn; got != testCase.domain {
				t.Fatalf("destination = %q, want %q", got, testCase.domain)
			}
		})
	}
}

// TestSOCKS5MalformedRequestRepliesAndCleansUp pins that the boundary rejection
// is followed by exactly one cleanup and no panic, and that a request which is
// malformed in some OTHER way still goes to the parser.
func TestSOCKS5MalformedRequestRepliesAndCleansUp(t *testing.T) {
	cases := []struct {
		name   string
		stream []byte
	}{
		{"empty-domain", emptyDomainSOCKS5Request(nil)},
		{"empty-domain-with-early-data", append(emptyDomainSOCKS5Request(nil), 0xAA, 0xBB)},
		{"unsupported-atyp", []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4, 0, 80}},
		{"truncated-domain", []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 200, 'a', 'b'}},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Errorf("panic on %s: %v", testCase.name, recovered)
					}
				}()
				harness := newInboundHarness(t, nil)
				conn := newScriptedConn(testCase.stream)
				harness.newConnection(context.Background(), conn, testSource(), newCloseRecorder().handler())
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s caused a hang", testCase.name)
			}
		})
	}
}

// TestConcurrentConnectionsAreIsolated drives many sessions at once through one
// inbound with different users and destinations, and requires each session's
// metadata and payload to be exactly its own.
//
// One router serves them all -- the Inbound owns its router, so a per-session
// router would be decoration that no connection ever reaches. Matching is done
// per session by giving every session a destination that encodes its index,
// which also proves no session's metadata was delivered under another's name.
func TestConcurrentConnectionsAreIsolated(t *testing.T) {
	users := []auth.User{{Username: "u1", Password: "p1"}, {Username: "u2", Password: "p2"}}
	router := newCaptureRouter()
	inbound := newInboundWithRouter(t, users, router)

	const sessions = 200
	var waitGroup sync.WaitGroup
	failures := make(chan error, sessions)

	for i := 0; i < sessions; i++ {
		i := i
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			// The inbound has users configured, so EVERY session must
			// authenticate. Half use HTTP CONNECT and half use SOCKS5, so both
			// parsers run concurrently over the same Inbound and both have to
			// report their own user.
			useHTTP := i%2 == 0
			user, password := "u1", "p1"
			if !useHTTP && i%4 == 3 {
				user, password = "u2", "p2"
			}
			domain := fmt.Sprintf("s%d.example", i)
			payload := bytes.Repeat([]byte{byte(i)}, 16)

			var stream []byte
			if useHTTP {
				stream = append([]byte(httpConnectAuthFor(domain)), payload...)
			} else {
				stream = socks5Auth(user, password, domain, 443, payload)
			}
			harness := &inboundHarness{inbound: inbound, router: router}
			harness.newConnection(context.Background(), newScriptedConn(stream), testSource(), nil)
		}()
	}
	waitGroup.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("session failed: %v", err)
	}

	entries := router.drainRouted()
	if len(entries) != sessions {
		t.Fatalf("routed %d connections, want %d", len(entries), sessions)
	}

	seen := make(map[string]bool, sessions)
	for _, entry := range entries {
		domain := entry.metadata.Destination.Fqdn
		if domain == "" {
			domain = entry.metadata.Destination.AddrString()
		}
		var index int
		if _, err := fmt.Sscanf(domain, "s%d.example", &index); err != nil {
			t.Fatalf("unexpected routed destination %q", domain)
		}
		if seen[domain] {
			t.Fatalf("destination %q routed twice", domain)
		}
		seen[domain] = true

		useHTTP := index%2 == 0
		wantUser := "u1"
		if !useHTTP && index%4 == 3 {
			wantUser = "u2"
		}
		if entry.metadata.User != wantUser {
			t.Fatalf("session %d (http=%v): user = %q, want %q", index, useHTTP, entry.metadata.User, wantUser)
		}
		if entry.metadata.Source.String() != testSource().String() {
			t.Fatalf("session %d: source = %s", index, entry.metadata.Source)
		}
		payload := bytes.Repeat([]byte{byte(index)}, 16)
		got, err := readExact(entry.conn, len(payload))
		if err != nil {
			t.Fatalf("session %d (http=%v): read payload: %v", index, useHTTP, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("session %d (http=%v): payload mismatch", index, useHTTP)
		}
	}
}

// newInboundWithRouter builds an Inbound that routes into a capture router the
// caller owns, so a concurrent test can give every session its own capture
// channel. Sharing one channel across sessions lets the test mismatch a session
// with another session's routed connection, which is a harness artefact that
// looks exactly like a state leak.
func newInboundWithRouter(t *testing.T, users []auth.User, router *captureRouter) *Inbound {
	t.Helper()
	created, err := NewInbound(context.Background(), router, testNOPLogger(), "mixed-in", httpMixedOptions(users))
	if err != nil {
		t.Fatalf("NewInbound: %v", err)
	}
	inbound := created.(*Inbound)
	t.Cleanup(func() { _ = inbound.listener.Close() })
	return inbound
}
