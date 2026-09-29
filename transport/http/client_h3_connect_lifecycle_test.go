//go:build with_quic

package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Regression tests for the HTTP/3 CONNECT lifecycle.
//
// # The production failure these exist to prevent
//
// A CONNECT response is not the end of a request; the 200 is where the tunnel BEGINS. The stream
// then carries payload in both directions for as long as the tunnel lives, so its write side must
// stay open.
//
// An earlier refactor routed CONNECT through a primitive shared with ordinary HTTP requests,
// which closed the write side before reading the response. That is correct for an ordinary
// request -- its write side IS finished once sent -- and fatal for a tunnel: every proxy write
// then failed with "write on closed stream", which is the exact symptom seen in production.
//
// # Why these tests write REAL BYTES
//
// Asserting that a tunnel opened and returning a non-nil stream proves nothing about the defect.
// The bug appeared on the FIRST WRITE AFTER the 200, so a test that stops at the 200 passes
// against the broken code. Every test here therefore moves payload in both directions after the
// CONNECT has been answered.

// echoTunnelServer answers a CONNECT with 200 and then echoes tunnel payload back.
//
// It runs on a real quic-go HTTP/3 server, so the stream semantics under test are the real ones
// rather than a double's approximation of them.
type echoTunnelServer struct {
	address string
	server  *http3.Server
	closed  chan struct{}
	access  sync.Mutex
	// tunnelReads records what arrived on the tunnel AFTER the 200, which is the fact the
	// regression turned on.
	tunnelReads [][]byte
	conns       int
	tunnels     int
	// echo, when non-nil, transforms tunnel payload before it is written back.
	//
	// It is set once at construction and never mutated afterwards. That is deliberate: the
	// handler runs on the server's own goroutine, so a field the test could assign later would be
	// read concurrently with the write and the race detector would flag the TEST rather than the
	// product. Passing it to the constructor makes the ordering obvious instead of relying on the
	// test happening to assign before any request arrives.
	echo func(payload []byte) []byte
}

func (s *echoTunnelServer) counts() (conns int, tunnels int) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.conns, s.tunnels
}

func (s *echoTunnelServer) received() [][]byte {
	s.access.Lock()
	defer s.access.Unlock()
	out := make([][]byte, 0, len(s.tunnelReads))
	out = append(out, s.tunnelReads...)
	return out
}

func startEchoTunnelServer(t *testing.T, echo func(payload []byte) []byte) *echoTunnelServer {
	t.Helper()
	server := &echoTunnelServer{closed: make(chan struct{}), echo: echo}

	tlsConfig := testServerTLSConfig(t)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	server.address = packetConn.LocalAddr().String()

	server.server = &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			server.access.Lock()
			server.tunnels++
			server.access.Unlock()
			// Safe without the lock: echo is set before the server is started and never written
			// again, so this read cannot overlap a write.
			echo := server.echo

			// A CONNECT is answered 200 and the stream then becomes the tunnel. The handler MUST
			// NOT return, or the stream would be closed; it runs for the life of the tunnel.
			writer.WriteHeader(http.StatusOK)
			if flusher, isFlusher := writer.(http.Flusher); isFlusher {
				flusher.Flush()
			}
			// Everything past this point is tunnel payload.
			buffer := make([]byte, 4096)
			for {
				read, readErr := request.Body.Read(buffer)
				if read > 0 {
					payload := append([]byte(nil), buffer[:read]...)
					server.access.Lock()
					server.tunnelReads = append(server.tunnelReads, payload)
					server.access.Unlock()

					reply := payload
					if echo != nil {
						reply = echo(payload)
					}
					if _, writeErr := writer.Write(reply); writeErr != nil {
						return
					}
					if flusher, isFlusher := writer.(http.Flusher); isFlusher {
						flusher.Flush()
					}
				}
				if readErr != nil {
					return
				}
			}
		}),
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			server.access.Lock()
			server.conns++
			server.access.Unlock()
			return ctx
		},
	}
	go func() {
		_ = server.server.Serve(packetConn)
		close(server.closed)
	}()
	t.Cleanup(func() {
		_ = server.server.Close()
		<-server.closed
	})
	return server
}

// dialerForTunnel builds a real HTTP/3 client pointed at a loopback server.
//
// It is assembled from the client's own fields rather than through NewClientWithTLS, which
// resolves a full outbound dialer from the service registry -- a configuration-layer concern
// these tests do not exercise. What matters here is the TUNNEL and REQUEST paths, and both are
// reachable with the fields set, exactly as the other HTTP/3 tests in this package do it.
func dialerForTunnel(t *testing.T, address string) *Client {
	t.Helper()
	clientTLS, err := tls.NewSTDClient(t.Context(), logger.NOP(), "example.test",
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.test",
			Insecure:   true,
			ALPN:       []string{"h3"},
		})
	require.NoError(t, err)

	impl := &http3ClientImpl{
		dialer:    &connectedUDPDialer{},
		server:    M.ParseSocksaddr(address),
		authority: address,
		tlsConfig: clientTLS,
		quicConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		transport: &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}
	impl.connectCandidate = impl.connectCandidateAt

	return &Client{
		dialer:            &connectedUDPDialer{},
		http1Dialer:       &connectedUDPDialer{},
		authorityOverride: address,
		version:           3,
		server:            M.ParseSocksaddr(address),
		http3:             impl,
		// The request path validates the request's authority against this, so it has to name the
		// server the connection is really authenticated for.
		http3Authority: address,
	}
}

// connectedUDPDialer dials a CONNECTED UDP socket, which QUIC requires: an unconnected socket has
// no remote address and the handshake fails for a reason unrelated to the code under test.
type connectedUDPDialer struct{}

func (d *connectedUDPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(destination.Addr, destination.Port)))
}

func (d *connectedUDPDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

// ---------------------------------------------------------------------------
// The regression
// ---------------------------------------------------------------------------

// TestHTTP3CONNECTRemainsWritableAfter200 is THE regression test for the production failure.
//
// It is small and fast on purpose: it must run in the ordinary CI gate, because the defect it
// catches is one line of over-eager cleanup that no amount of "the tunnel opened successfully"
// assertion would notice.
func TestHTTP3CONNECTRemainsWritableAfter200(t *testing.T) {
	t.Parallel()

	server := startEchoTunnelServer(t, nil)
	client := dialerForTunnel(t, server.address)

	tunnel, err := client.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("target.example:443"))
	require.NoError(t, err, "the CONNECT must be accepted")
	defer tunnel.Close()

	// THE assertion. The write side must still be open after the 200.
	const payload = "hello-after-connect"
	_, err = tunnel.Write([]byte(payload))
	require.NoError(t, err,
		"a CONNECT stream must remain writable after its 200; closing the write side there produces 'write on closed stream' on the first payload byte")

	// And the bytes must actually arrive.
	buffer := make([]byte, len(payload))
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(tunnel, buffer)
	require.NoError(t, err)
	require.Equal(t, payload, string(buffer), "the server must receive what the tunnel carried")

	received := server.received()
	require.Len(t, received, 1)
	require.Equal(t, payload, string(received[0]))

	connections, tunnels := server.counts()
	require.Equal(t, 1, connections, "one QUIC connection")
	require.Equal(t, 1, tunnels, "one CONNECT tunnel")
}

// TestHTTP3CONNECTIsBidirectional proves payload flows both ways on one stream.
//
// A tunnel that can be written but not read is not a working proxy, and the two directions use
// different halves of the same stream, so both are exercised.
func TestHTTP3CONNECTIsBidirectional(t *testing.T) {
	t.Parallel()

	server := startEchoTunnelServer(t, func(payload []byte) []byte {
		// Transform the payload, so a test cannot pass by echoing on the CLIENT side.
		return append([]byte("echo:"), payload...)
	})
	client := dialerForTunnel(t, server.address)

	tunnel, err := client.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("target.example:443"))
	require.NoError(t, err)
	defer tunnel.Close()

	for _, message := range []string{"first", "second", "third"} {
		_, err = tunnel.Write([]byte(message))
		require.NoError(t, err, "writing %q must succeed after the 200", message)

		expected := "echo:" + message
		buffer := make([]byte, len(expected))
		_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadFull(tunnel, buffer)
		require.NoError(t, err)
		require.Equal(t, expected, string(buffer), "the tunnel must carry %q both ways", message)
	}

	require.Len(t, server.received(), 3, "every payload must have reached the server")
}

// TestHTTP3CONNECTThenDoHOnOneConnection is the coexist test.
//
// One connection carries a CONNECT tunnel and, at the same time, ordinary HTTP/3 requests. Each
// uses its own stream, and neither lifecycle may disturb the other: the tunnel must stay writable
// while requests run, and closing a request's response body must not touch the tunnel.
func TestHTTP3CONNECTThenDoHOnOneConnection(t *testing.T) {
	t.Parallel()

	server := startCoexistServer(t)
	client := dialerForTunnel(t, server.address)

	// Stream #1: the tunnel.
	tunnel, err := client.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("target.example:443"))
	require.NoError(t, err)
	defer tunnel.Close()

	_, err = tunnel.Write([]byte("tunnel-before"))
	require.NoError(t, err)
	buffer := make([]byte, len("tunnel-before"))
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(tunnel, buffer)
	require.NoError(t, err)

	// Streams #2..N: ordinary requests on the SAME connection.
	for index := range 8 {
		request, requestErr := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"https://"+server.address+"/dns-query", strings.NewReader("query"))
		require.NoError(t, requestErr)
		response, roundTripErr := client.RoundTripExistingHTTP3(context.Background(), request)
		require.NoError(t, roundTripErr, "request %d must use the existing connection", index)
		_, _ = io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
	}

	// The tunnel must still work afterwards: a request lifecycle that closed more than its own
	// stream would show up here.
	_, err = tunnel.Write([]byte("tunnel-after"))
	require.NoError(t, err,
		"the CONNECT tunnel must remain writable after ordinary requests ran on the same connection")
	buffer = make([]byte, len("tunnel-after"))
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(tunnel, buffer)
	require.NoError(t, err)

	connections, _ := server.counts()
	require.Equal(t, 1, connections,
		"the tunnel and every request must share ONE QUIC connection, which is the reuse the API exists to provide")
}

// startCoexistServer answers CONNECT with 200 and echoes tunnel payload, while also serving
// ordinary POSTs on the same listener.
func startCoexistServer(t *testing.T) *echoTunnelServer {
	t.Helper()
	server := &echoTunnelServer{closed: make(chan struct{})}

	tlsConfig := testServerTLSConfig(t)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	server.address = packetConn.LocalAddr().String()

	server.server = &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			server.access.Lock()
			server.tunnels++
			server.access.Unlock()

			if request.Method != http.MethodConnect {
				// An ordinary request: a complete response, then the handler returns.
				writer.Header().Set("Content-Type", "application/dns-message")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte("answer"))
				return
			}

			writer.WriteHeader(http.StatusOK)
			if flusher, isFlusher := writer.(http.Flusher); isFlusher {
				flusher.Flush()
			}
			buffer := make([]byte, 4096)
			for {
				read, readErr := request.Body.Read(buffer)
				if read > 0 {
					payload := append([]byte(nil), buffer[:read]...)
					server.access.Lock()
					server.tunnelReads = append(server.tunnelReads, payload)
					server.access.Unlock()
					if _, writeErr := writer.Write(payload); writeErr != nil {
						return
					}
					if flusher, isFlusher := writer.(http.Flusher); isFlusher {
						flusher.Flush()
					}
				}
				if readErr != nil {
					return
				}
			}
		}),
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			server.access.Lock()
			server.conns++
			server.access.Unlock()
			return ctx
		},
	}
	go func() {
		_ = server.server.Serve(packetConn)
		close(server.closed)
	}()
	t.Cleanup(func() {
		_ = server.server.Close()
		<-server.closed
	})
	return server
}
