package http

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// blackholeDialer accepts UDP "connections" and then silently discards every
// packet, never replying. This models the mobile-network failure that matters
// most: the socket is fine, the packets leave, and nothing ever comes back.
//
// A closed port is NOT this case. A closed port produces an ICMP rejection and
// fails fast; a blackhole produces a handshake TIMEOUT, which is a different
// code path and the one that used to surface to the user as a bare timeout
// instead of a fallback.
type blackholeDialer struct{}

func (blackholeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	// Discard everything written, and never deliver a reply.
	return &blackholeConn{closed: make(chan struct{})}, nil
}

// ListenPacket satisfies network.Dialer. The client only dials, so this is never
// expected to be reached.
func (blackholeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("blackhole dialer does not listen")
}

type blackholeConn struct{ closed chan struct{} }

func (c *blackholeConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blackholeConn) Write(p []byte) (int, error) {
	// Report success: the packet is "sent" and simply never answered.
	return len(p), nil
}

func (c *blackholeConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *blackholeConn) LocalAddr() net.Addr  { return dummyAddr{} }
func (c *blackholeConn) RemoteAddr() net.Addr { return dummyAddr{} }
func (c *blackholeConn) SetDeadline(t time.Time) error {
	// Honour cancellation so the handshake attempt cannot hang forever.
	go func() {
		if !t.IsZero() {
			timer := time.NewTimer(time.Until(t))
			defer timer.Stop()
			<-timer.C
		}
		_ = c.Close()
	}()
	return nil
}
func (c *blackholeConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *blackholeConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "udp" }
func (dummyAddr) String() string  { return "blackhole" }

// TestBlackholeUDPIsReportedAsH3Unavailable is the P0/P1 regression for the
// silent-blackhole case.
//
// When every pool slot fails to establish transport -- the signature of a UDP
// blackhole -- the failure must be reported as ErrHTTP3Unavailable so the caller
// falls back to HTTP/2, rather than surfacing a bare timeout to the user.
func TestBlackholeUDPIsReportedAsH3Unavailable(t *testing.T) {
	if testing.Short() {
		t.Skip("exercises a real handshake timeout")
	}
	client := newBlackholeClient(t, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := client.DialContext(ctx, M.ParseSocksaddr("127.0.0.1:9"))
	require.Error(t, err, "a blackholed UDP endpoint cannot establish a tunnel")
	require.True(t, errors.Is(err, ErrHTTP3Unavailable),
		"an exhausted pool of transport-establishment failures must be reported "+
			"as HTTP/3 unavailable so the caller can fall back to HTTP/2; got %v", err)
}

// newBlackholeClient builds a MASQUE client whose UDP dialer blackholes traffic.
func newBlackholeClient(t *testing.T, poolSize int) *http3ClientImpl {
	t.Helper()
	tlsConfig, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context: context.Background(),
		Options: option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.test",
			Insecure:   true,
			// A short handshake timeout so the blackhole attempt fails on its OWN
			// timeout rather than being cut off by the test context. That
			// distinction matters: a context cancellation is a caller-side
			// cancellation, whereas the handshake timeout is the
			// transport-establishment failure this test is about.
			HandshakeTimeout: badoption.Duration(3 * time.Second),
		},
	})
	require.NoError(t, err)
	tlsConfig.SetNextProtos([]string{http3.NextProtoH3})

	client, err := newHTTP3Client(ClientOptions{
		Server:    M.ParseSocksaddr("127.0.0.1:443"),
		RawDialer: blackholeDialer{},
		TLSConfig: tlsConfig,
		Authority: "example.test",
		HTTP3Options: option.QUICOptions{
			HTTP3ConnectionPool: &option.HTTP3ConnectionPoolOptions{
				Size: poolSize, Strategy: option.HTTP3PoolStrategyRoundRobin,
			},
		},
	}, "")
	require.NoError(t, err)
	impl, isImpl := client.(*http3ClientImpl)
	require.True(t, isImpl)
	t.Cleanup(func() { _ = impl.Close() })
	return impl
}
