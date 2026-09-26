package http

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// RFC 9931's client-side half, pinned on the wire.
//
// Section 8 of RFC 9931 requires a proxy CLIENT not to treat a tunnel as usable
// before the proxy has accepted it: a client must not forward application payload
// optimistically while the request is still unanswered. For HTTP/1 that means no
// TCP payload before a 2xx response, and no UDP payload before a 101 Switching
// Protocols response.
//
// # Why this is asserted on the wire rather than read from the code
//
// Reading transport/http/client.go shows `request.Write` then `ReadResponse` then a
// `StatusOK` check, and tunnel_client.go shows the same shape with a
// `StatusSwitchingProtocols` check. Both LOOK correct, and that is exactly why a
// code inspection is not evidence: the ordering that matters is an ordering of
// events on a socket, and a refactor that hoisted a write, batched it, or reused a
// pooled buffer could move payload earlier without changing the readable shape of
// those functions.
//
// So these tests run the real client against a real TCP listener that controls when
// the response is sent, and assert on what the listener actually RECEIVED. The
// listener holds the response open on a channel, so nothing here depends on a sleep
// being long enough: if the client sent payload early, the listener sees it during a
// window that is closed by explicit synchronisation.

// ---------------------------------------------------------------------------
// The controlled HTTP/1 proxy
// ---------------------------------------------------------------------------

// controlledProxy is a TCP listener that answers one HTTP request under the test's
// control.
//
// It reads the complete request headers, then blocks until the test releases the
// response. Everything the peer sends after the request is streamed into
// `observed`, so a test can ask "did any payload arrive before I answered?" without
// guessing how long to wait.
type controlledProxy struct {
	listener net.Listener

	// requestLine and requestHeaders are what the client actually sent.
	requestLine      string
	requestAuthority string
	requestHeaders   http.Header
	requestErr       error

	// released is closed by the test to let the handler send its response.
	released chan struct{}
	// responded is closed by the handler once it has written the response.
	responded chan struct{}
	// parsed is closed once the request headers have been read.
	parsed chan struct{}

	// observed holds every byte the peer sent after the request headers. Access is
	// guarded because the reader runs until the connection closes.
	observedAccess sync.Mutex
	observed       []byte

	responseStatus string
	responseHeader []string
}

// newControlledProxy starts the listener and reads one request in the background.
func newControlledProxy(t *testing.T) *controlledProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	proxy := &controlledProxy{
		listener:  listener,
		released:  make(chan struct{}),
		responded: make(chan struct{}),
		parsed:    make(chan struct{}),
	}
	t.Cleanup(func() {
		_ = listener.Close()
		// Unblock a handler that is still waiting, so a failed assertion cannot
		// leak a goroutine into the rest of the run.
		proxy.Release()
	})
	return proxy
}

func (p *controlledProxy) address() M.Socksaddr {
	return M.SocksaddrFromNet(p.listener.Addr()).Unwrap()
}

// Serve handles exactly one connection: read the request, wait for release, answer.
func (p *controlledProxy) Serve(t *testing.T) {
	t.Helper()
	go func() {
		conn, err := p.listener.Accept()
		if err != nil {
			p.requestErr = err
			close(p.parsed)
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		request, err := http.ReadRequest(reader)
		if err != nil {
			p.requestErr = err
			close(p.parsed)
			return
		}
		// # Critical: capture what ReadRequest BUFFERED
		//
		// http.ReadRequest reads through a bufio.Reader, which reads ahead. Any
		// payload the client sent eagerly is therefore already sitting in the
		// reader's buffer by the time the request is parsed, and would never be seen
		// by the later drain. Without this, an optimistic client looks identical to
		// a correct one - MEASURED: an injected early write produced observed=""
		// here until this drain was added.
		if buffered := reader.Buffered(); buffered > 0 {
			ahead := make([]byte, buffered)
			if _, readErr := io.ReadFull(reader, ahead); readErr == nil {
				p.record(ahead)
			}
		}

		p.requestLine = request.Method + " " + request.URL.RequestURI() + " " + request.Proto
		// For an HTTP/1 CONNECT, ReadRequest moves the authority into URL.Host and
		// clears Header["Host"], so the authority is read from whichever the parser
		// populated rather than assumed.
		p.requestAuthority = request.URL.Host
		if p.requestAuthority == "" {
			p.requestAuthority = request.Host
		}
		p.requestHeaders = request.Header.Clone()
		close(p.parsed)

		// Wait for the test to allow the response. Until this point the test may
		// inspect `observed`, which is the whole point: the window between the
		// request and the response is where optimistic payload would appear.
		<-p.released

		if p.responseStatus != "" {
			var builder strings.Builder
			builder.WriteString("HTTP/1.1 ")
			builder.WriteString(p.responseStatus)
			builder.WriteString("\r\n")
			for _, header := range p.responseHeader {
				builder.WriteString(header)
				builder.WriteString("\r\n")
			}
			builder.WriteString("\r\n")
			_, _ = conn.Write([]byte(builder.String()))
		}
		close(p.responded)

		// Keep draining so a client that writes payload is observed even after the
		// response, and so a close by the client is seen rather than resetting.
		buffer := make([]byte, 4096)
		for {
			n, readErr := reader.Read(buffer)
			if n > 0 {
				p.record(buffer[:n])
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					p.record(nil)
				}
				return
			}
		}
	}()
}

func (p *controlledProxy) record(data []byte) {
	p.observedAccess.Lock()
	p.observed = append(p.observed, data...)
	p.observedAccess.Unlock()
}

func (p *controlledProxy) observedBytes() []byte {
	p.observedAccess.Lock()
	defer p.observedAccess.Unlock()
	return append([]byte(nil), p.observed...)
}

// Release lets the handler send its response.
func (p *controlledProxy) Release() {
	select {
	case <-p.released:
	default:
		close(p.released)
	}
}

// awaitRequest blocks until the request headers have been read.
//
// This is the synchronisation that replaces a sleep: once it returns, the request
// has demonstrably reached the proxy, so any payload the client sends eagerly would
// already be on the wire.
func (p *controlledProxy) awaitRequest(t *testing.T) {
	t.Helper()
	select {
	case <-p.parsed:
	case <-time.After(10 * time.Second):
		t.Fatal("the client never sent its request to the proxy")
	}
	require.NoError(t, p.requestErr, "the proxy must be able to parse the request")
}

// ---------------------------------------------------------------------------
// HTTP/1 CONNECT (TCP)
// ---------------------------------------------------------------------------

// directDialer dials the proxy directly, which is what these fixtures need: the
// client must not resolve or route anywhere else.
type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return N.SystemDialer.DialContext(ctx, network, destination)
}

// ListenPacket is required by N.Dialer. It is never reached on these paths, which
// only dial TCP, so it delegates rather than panicking: a future caller that did
// reach it would get the system behaviour instead of a confusing nil.
func (directDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

// TestRFC9931ConnectTCPWaitsForSuccessResponse proves the client sends no TCP
// payload before the proxy answers 200.
func TestRFC9931ConnectTCPWaitsForSuccessResponse(t *testing.T) {
	proxy := newControlledProxy(t)
	proxy.Serve(t)

	client := newRFC9931TestClient(proxy.address())

	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultChannel := make(chan dialResult, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), "tcp",
			M.ParseSocksaddr("192.0.2.10:443"))
		resultChannel <- dialResult{conn: conn, err: err}
	}()

	proxy.awaitRequest(t)

	// The request is a CONNECT and it carries the destination.
	require.True(t, strings.HasPrefix(proxy.requestLine, "CONNECT "),
		"the client must send a CONNECT, got %q", proxy.requestLine)
	// An HTTP/1 CONNECT carries the authority in the Host header and leaves the
	// request target as "/" - that is the wire form of a CONNECT, so the
	// destination is asserted where it actually appears.
	require.Equal(t, "192.0.2.10:443", proxy.requestAuthority,
		"the CONNECT must name the destination as its authority")

	// # The assertion
	//
	// The proxy has read the request and has deliberately NOT answered. If the
	// client were optimistic it would already have written application payload.
	// Checked twice with the response still withheld, so a payload that arrived in
	// the meantime is also caught.
	require.Empty(t, proxy.observedBytes(),
		"the client sent payload before the proxy accepted the tunnel. RFC 9931 "+
			"section 8 forbids treating the tunnel as usable before the 2xx: that "+
			"payload has not been accepted by any proxy and must not be emitted")

	// DialContext must not have returned either, because there is no tunnel yet.
	select {
	case result := <-resultChannel:
		if result.conn != nil {
			_ = result.conn.Close()
		}
		t.Fatal("DialContext returned a connection before the proxy answered; a " +
			"caller could then write payload the proxy never accepted")
	case <-time.After(300 * time.Millisecond):
	}
	require.Empty(t, proxy.observedBytes(),
		"the client sent payload during the wait for the response")

	// Now accept, and the client may use the tunnel.
	proxy.responseStatus = "200 Connection Established"
	proxy.Release()

	var conn net.Conn
	select {
	case result := <-resultChannel:
		require.NoError(t, result.err,
			"the client must accept a 200 Connection Established")
		conn = result.conn
	case <-time.After(10 * time.Second):
		t.Fatal("DialContext did not return after the proxy answered 200")
	}
	require.NotNil(t, conn)
	defer conn.Close()

	// Payload sent now must arrive. This is the positive control: without it, a
	// client that never wrote anything at all would also pass the assertion above.
	_, err := conn.Write([]byte("rfc9931-after-200"))
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return strings.Contains(string(proxy.observedBytes()), "rfc9931-after-200")
	}, 10*time.Second, 20*time.Millisecond,
		"the payload written after the 200 must reach the proxy, proving the tunnel "+
			"is genuinely usable and the earlier emptiness was a wait rather than a "+
			"broken connection")
}

// TestRFC9931ConnectTCPDoesNotSendPayloadWhenRejected proves a rejected CONNECT
// yields an error and emits no payload.
func TestRFC9931ConnectTCPDoesNotSendPayloadWhenRejected(t *testing.T) {
	for _, status := range []string{
		"407 Proxy Authentication Required",
		"403 Forbidden",
	} {
		t.Run(status, func(t *testing.T) {
			proxy := newControlledProxy(t)
			proxy.Serve(t)
			proxy.responseStatus = status
			proxy.responseHeader = []string{"Content-Length: 0"}

			client := newRFC9931TestClient(proxy.address())

			// The rejection is pre-released, so this exercises the refusal path
			// rather than the wait.
			proxy.Release()
			go func() {
				proxy.awaitRequest(t)
			}()

			conn, err := client.DialContext(context.Background(), "tcp",
				M.ParseSocksaddr("192.0.2.10:443"))
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err,
				"a rejected CONNECT must be an error; returning a usable tunnel for a "+
					"proxy response that refused it would send payload into a tunnel "+
					"that does not exist")
			require.Nil(t, conn,
				"no connection may be exposed when the proxy refused the tunnel")

			require.Empty(t, proxy.observedBytes(),
				"the client must not send application payload after a rejection")
		})
	}
}

// ---------------------------------------------------------------------------
// HTTP/1 CONNECT-UDP (the upgrade path)
// ---------------------------------------------------------------------------

// TestRFC9931ConnectUDPWaitsForSwitchingProtocols proves the client sends no UDP
// payload before the proxy answers 101.
func TestRFC9931ConnectUDPWaitsForSwitchingProtocols(t *testing.T) {
	proxy := newControlledProxy(t)
	proxy.Serve(t)

	client := newRFC9931TestClient(proxy.address())
	request := rfc9931TunnelRequest(t)

	type openResult struct {
		stream DatagramStream
		conn   net.Conn
		err    error
	}
	resultChannel := make(chan openResult, 1)
	go func() {
		// openTunnelHTTP1 is called through the same helper the production HTTP/1
		// path uses; openTunnel itself would first try HTTP/3 and HTTP/2, and a
		// client without those transports configured would not exercise the upgrade
		// code these tests pin.
		tunnelConn, stream, err := openRFC9931Tunnel(t, client, request)
		resultChannel <- openResult{stream: stream, err: err, conn: tunnelConn}
	}()

	proxy.awaitRequest(t)

	// The upgrade request must be a GET carrying the three required headers.
	require.True(t, strings.HasPrefix(proxy.requestLine, "GET "),
		"a CONNECT-UDP upgrade is a GET with Upgrade, got %q", proxy.requestLine)
	require.Equal(t, "Upgrade", proxy.requestHeaders.Get("Connection"))
	require.Equal(t, "connect-udp", proxy.requestHeaders.Get("Upgrade"))
	require.Equal(t, "?1", proxy.requestHeaders.Get("Capsule-Protocol"))

	// # The assertion
	//
	// Nothing may have been sent. A DATAGRAM capsule or a raw payload byte here
	// would mean the client was willing to send UDP traffic into a tunnel the
	// proxy has not agreed to.
	require.Empty(t, proxy.observedBytes(),
		"the client sent UDP payload before the 101. RFC 9931 section 8 forbids "+
			"using the tunnel before the upgrade is accepted")

	select {
	case result := <-resultChannel:
		if result.stream != nil {
			_ = result.stream.Close()
		}
		t.Fatal("OpenTunnel returned before the proxy sent 101 Switching Protocols")
	case <-time.After(300 * time.Millisecond):
	}
	require.Empty(t, proxy.observedBytes(),
		"the client sent UDP payload while waiting for the upgrade response")

	proxy.responseStatus = "101 Switching Protocols"
	proxy.responseHeader = []string{
		"Connection: Upgrade",
		"Upgrade: connect-udp",
		"Capsule-Protocol: ?1",
	}
	proxy.Release()

	// On HTTP/1 the upgrade yields the raw connection; the caller frames payload as
	// DATAGRAM capsules over it. Both are captured so the positive control writes
	// through the real framing rather than a bare socket.
	var (
		tunnelConn net.Conn
		stream     DatagramStream
	)
	select {
	case result := <-resultChannel:
		require.NoError(t, result.err,
			"the client must accept a well-formed 101 Switching Protocols")
		tunnelConn, stream = result.conn, result.stream
	case <-time.After(10 * time.Second):
		t.Fatal("OpenTunnel did not return after the proxy sent 101")
	}
	if stream != nil {
		defer stream.Close()
	}
	require.NotNil(t, tunnelConn,
		"the HTTP/1 upgrade must yield the connection the tunnel is carried on")
	defer tunnelConn.Close()

	// Positive control: a capsule sent now must reach the proxy.
	capsule := buf.NewSize(len("rfc9931-after-101"))
	capsule.Write([]byte("rfc9931-after-101"))
	require.NoError(t, WriteDatagramCapsule(tunnelConn, capsule))

	require.Eventually(t, func() bool {
		return strings.Contains(string(proxy.observedBytes()), "rfc9931-after-101")
	}, 10*time.Second, 20*time.Millisecond,
		"the datagram sent after the 101 must reach the proxy, proving the tunnel "+
			"became usable and the earlier emptiness was a wait")
}

// TestRFC9931ConnectUDPDoesNotSendPayloadWhenRejected proves a rejected upgrade
// yields an error and emits no UDP payload.
func TestRFC9931ConnectUDPDoesNotSendPayloadWhenRejected(t *testing.T) {
	for _, status := range []string{
		"400 Bad Request",
		"407 Proxy Authentication Required",
	} {
		t.Run(status, func(t *testing.T) {
			proxy := newControlledProxy(t)
			proxy.Serve(t)
			proxy.responseStatus = status
			proxy.responseHeader = []string{"Content-Length: 0"}

			client := newRFC9931TestClient(proxy.address())
			request := rfc9931TunnelRequest(t)

			proxy.Release()
			go func() { proxy.awaitRequest(t) }()

			conn, stream, err := openRFC9931Tunnel(t, client, request)
			if conn != nil {
				_ = conn.Close()
			}
			if stream != nil {
				_ = stream.Close()
			}
			require.Error(t, err,
				"a rejected upgrade must be an error rather than a usable tunnel")
			require.Nil(t, stream,
				"no stream may be exposed when the proxy refused the upgrade")

			require.Empty(t, proxy.observedBytes(),
				"the client must not send UDP payload after a rejected upgrade")
		})
	}
}

// TestRFC9931ConnectUDPRejectsAMismatchedUpgradeHeader proves the client validates
// the protocol token rather than trusting the status code alone.
//
// A 101 that names a different protocol is not an accepted CONNECT-UDP tunnel. The
// client must refuse it, because the bytes that follow would otherwise be framed
// for a protocol the proxy is not speaking.
func TestRFC9931ConnectUDPRejectsAMismatchedUpgradeHeader(t *testing.T) {
	proxy := newControlledProxy(t)
	proxy.Serve(t)
	proxy.responseStatus = "101 Switching Protocols"
	proxy.responseHeader = []string{
		"Connection: Upgrade",
		"Upgrade: websocket",
		"Capsule-Protocol: ?1",
	}

	client := newRFC9931TestClient(proxy.address())
	request := rfc9931TunnelRequest(t)

	proxy.Release()
	go func() { proxy.awaitRequest(t) }()

	conn, stream, err := client.openTunnelHTTP1AndClose(context.Background(), mustDialProxy(t, proxy), request)
	if stream != nil {
		_ = stream.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err,
		"a 101 naming a different protocol must be refused; the tunnel would "+
			"otherwise be used with the wrong framing")
	require.Empty(t, proxy.observedBytes(),
		"the client must not send payload into a tunnel it rejected")
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

// newRFC9931TestClient builds a version-1 client pointed at the controlled proxy.
//
// Version 1 is forced and the HTTP/1 dialer is wired directly, so the client under
// test takes the HTTP/1 path these tests are about. Without that, a client that
// happened to reach for HTTP/2 or HTTP/3 would never exercise the code being
// pinned, and the tests would pass while proving nothing.
func newRFC9931TestClient(server M.Socksaddr) *Client {
	return &Client{
		http1Dialer:       directDialer{},
		server:            server,
		authorityOverride: server.String(),
		version:           1,
		headers:           make(http.Header),
	}
}

// rfc9931TunnelRequest is the CONNECT-UDP request the upgrade tests drive.
func rfc9931TunnelRequest(t *testing.T) tunnelRequest {
	t.Helper()
	requestURL, err := url.Parse("https://example.org/.well-known/masque/udp/192.0.2.10/443/")
	require.NoError(t, err)
	return tunnelRequest{
		protocol:            "connect-udp",
		url:                 requestURL,
		destination:         M.ParseSocksaddr("192.0.2.10:443"),
		originAuthorization: false,
	}
}

// mustDialProxy opens the TCP connection the caller then hands to openTunnelHTTP1,
// which is the internal entry point that does not re-dial.
func mustDialProxy(t *testing.T, proxy *controlledProxy) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxy.listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// openRFC9931Tunnel drives the HTTP/1 upgrade entry point directly.
//
// openTunnel would first attempt HTTP/3 and HTTP/2, which this fixture does not
// configure; routing through it would make these tests depend on version fallback
// rather than on the HTTP/1 upgrade code they exist to pin. The connection is dialled
// here and handed to openTunnelHTTP1AndClose, which is exactly what openTunnel does on
// its HTTP/1 branch.
func openRFC9931Tunnel(t *testing.T, client *Client, request tunnelRequest) (net.Conn, DatagramStream, error) {
	t.Helper()
	conn, err := client.http1Dialer.DialContext(context.Background(), N.NetworkTCP, client.server)
	if err != nil {
		return nil, nil, err
	}
	return client.openTunnelHTTP1AndClose(context.Background(), conn, request)
}
