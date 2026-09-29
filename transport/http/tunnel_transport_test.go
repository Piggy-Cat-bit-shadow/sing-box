//go:build with_quic

package http

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the tunnel transport report.
//
// # The three facts, and which one this covers
//
//	A. this client CAN speak HTTP/3                     (configuration)
//	B. it currently HOLDS a live HTTP/3 connection       (resource)
//	C. THIS tunnel session WAS ESTABLISHED over HTTP/3   (session truth)
//
// Only C answers the question MASQUE DNS has to ask. The other two are approximations that are
// wrong exactly when the tunnel path falls back: an HTTP/3 attempt fails, the session is
// established over HTTP/2, and a live HTTP/3 connection remains from an earlier success. A
// caller that inferred C from B would then send a DNS query on a connection the tunnel traffic
// does not share.
//
// These tests drive a REAL server and assert what openTunnel reports, so the fact is verified at
// the branch that decides it rather than reconstructed by a caller.

// countingTunnelTransportServer accepts CONNECT-IP requests over HTTP/3 and counts connections.
type countingTunnelTransportServer struct {
	address string
	server  *http3.Server
	closed  chan struct{}
	access  sync.Mutex
	conns   int
	tunnels int
}

func (s *countingTunnelTransportServer) counts() (int, int) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.conns, s.tunnels
}

// startTunnelTransportServer starts a real HTTP/3 server that accepts extended CONNECT.
func startTunnelTransportServer(t *testing.T) *countingTunnelTransportServer {
	t.Helper()
	server := &countingTunnelTransportServer{closed: make(chan struct{})}

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
			// A tunnel is answered 200 and then held open, so the stream stays usable.
			writer.WriteHeader(http.StatusOK)
			if flusher, isFlusher := writer.(http.Flusher); isFlusher {
				flusher.Flush()
			}
			<-request.Context().Done()
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

// newTunnelTransportClient builds a transport/http client pointed at a loopback server.
//
// It is assembled here rather than through NewClientWithTLS because the constructor resolves a
// full outbound dialer from the service registry, which is a configuration-layer concern. What
// this test needs is the TUNNEL path -- which branch openTunnel takes -- and that is reachable
// with the client's own fields set, exactly as the hook tests in this package do it.
func newTunnelTransportClient(t *testing.T, address string) *Client {
	t.Helper()
	tlsConfig, err := tls.NewSTDClient(t.Context(), logger.NOP(), "example.test",
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.test",
			Insecure:   true,
			ALPN:       []string{"h3"},
		})
	require.NoError(t, err)

	// CONNECT-IP requires QUIC datagrams, and the client must negotiate them or the server
	// refuses the request with "missing QUIC Datagram support".
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		EnableDatagrams:      true,
	}

	// The HTTP/3 client is what openTunnel consults, so it is built with the same helper the
	// other HTTP/3 tests in this package use.
	impl := &http3ClientImpl{
		dialer:     &loopbackDialer{},
		server:     M.ParseSocksaddr(address),
		authority:  address,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		transport:  &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}
	impl.connectCandidate = impl.connectCandidateAt

	return &Client{
		dialer: &loopbackDialer{},
		// The tunnel path falls back through HTTP/2 and HTTP/1, so a client that may fail must
		// have the dialers those branches use. They are the same loopback dialer: the fallback
		// will fail to connect, which is what this test asserts about the REPORT rather than
		// about the connection.
		http1Dialer:       &loopbackDialer{},
		tlsDialer:         nil,
		authorityOverride: address,
		version:           3,
		server:            M.ParseSocksaddr(address),
		http3:             impl,
	}
}

// loopbackDialer dials a CONNECTED UDP socket, which QUIC requires: an unconnected socket has no
// remote address, and the handshake would fail for a reason unrelated to what is being tested.
type loopbackDialer struct{}

func (d *loopbackDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(destination.Addr, destination.Port)))
}

func (d *loopbackDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

// TestTunnelTransportReportsHTTP3 proves a tunnel established over HTTP/3 is reported as such.
func TestTunnelTransportReportsHTTP3(t *testing.T) {
	t.Parallel()

	server := startTunnelTransportServer(t)
	client := newTunnelTransportClient(t, server.address)

	stream, tunnelTransport, err := client.OpenTunnelWithInfo(context.Background(), "connect-ip", "/")
	require.NoError(t, err)
	require.Equal(t, TunnelTransportHTTP3, tunnelTransport,
		"a tunnel established over HTTP/3 must be reported as HTTP/3, which is the fact a same-connection DoH decision depends on")
	require.NotNil(t, stream)
	_ = stream.Close()

	connections, tunnels := server.counts()
	require.Equal(t, 1, connections, "exactly one QUIC connection")
	require.Equal(t, 1, tunnels)
}

// TestTunnelTransportIsNotReportedWhenTheTunnelFails is the negative half.
//
// A tunnel that could not be established must NOT be reported as HTTP/3. A caller that treated a
// failed open as HTTP/3 would consider a same-connection DNS transport available and send queries
// onto a connection that does not exist -- the failure being reported at the wrong layer and far
// from its cause.
//
// The positive HTTP/2 case needs a real HTTP/2 CONNECT-IP server, which the MASQUE package covers
// end to end; what this asserts is the invariant that matters here: HTTP/3 is never reported
// unless HTTP/3 is what succeeded.
func TestTunnelTransportIsNotReportedWhenTheTunnelFails(t *testing.T) {
	t.Parallel()

	// A port nothing listens on, so every attempt fails.
	client := newTunnelTransportClient(t, "127.0.0.1:1")

	stream, tunnelTransport, openErr := client.OpenTunnelWithInfo(context.Background(), "connect-ip", "/")
	require.Error(t, openErr, "there is nothing listening, so no tunnel can be established")
	require.Nil(t, stream)
	require.NotEqual(t, TunnelTransportHTTP3, tunnelTransport,
		"a failed open must never report HTTP/3, or a caller would treat an unusable transport as available")
}

// TestTunnelTransportUnknownWhenNoTunnelExists proves the zero value is the honest one.
//
// A caller that has not opened a tunnel must not be told it has an HTTP/3 one, and
// TunnelTransportUnknown is what the constants start at so that a zero-valued field cannot
// accidentally mean HTTP/3.
func TestTunnelTransportUnknownIsTheZeroValue(t *testing.T) {
	t.Parallel()

	var tunnelTransport TunnelTransport
	require.Equal(t, TunnelTransportUnknown, tunnelTransport)
	require.NotEqual(t, TunnelTransportHTTP3, tunnelTransport,
		"the zero value must not mean HTTP/3, or an unset field would claim a transport")
	require.Equal(t, "unknown", tunnelTransport.String())
	require.Equal(t, "h3", TunnelTransportHTTP3.String())
}

// TestTunnelTransportConstantsAreDistinct guards against a copy-paste collision in the enum.
func TestTunnelTransportConstantsAreDistinct(t *testing.T) {
	t.Parallel()

	values := []TunnelTransport{
		TunnelTransportUnknown,
		TunnelTransportHTTP1,
		TunnelTransportHTTP2,
		TunnelTransportHTTP3,
	}
	seen := make(map[TunnelTransport]bool, len(values))
	for _, value := range values {
		require.False(t, seen[value], "transport values must be distinct, or one would be reported as another")
		seen[value] = true
	}
}
