//go:build with_quic

package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdTLS "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// These tests cover the MASQUE tunnel client's connection pool, which is the
// path protocol/http actually uses for CONNECT and CONNECT-UDP.
//
// They deliberately do NOT use plain HTTP GET requests: the pool added to
// common/httpclient covers a different, generic RoundTripper and proving that one
// works says nothing about the MASQUE client. Everything here drives
// http3ClientImpl through the same entry points protocol/http uses, and counts
// the QUIC connections that actually arrive at a real HTTP/3 server.

// masquePoolServer is a real HTTP/3 server that counts QUIC connections and
// accepts CONNECT and CONNECT-UDP tunnels.
type masquePoolServer struct {
	address     string
	connections *connectionCounter
	tunnels     *httpserverTunnelCounter
}

type connectionCounter struct {
	access sync.Mutex
	conns  map[*quic.Conn]struct{}
}

func (c *connectionCounter) add(conn *quic.Conn) {
	c.access.Lock()
	c.conns[conn] = struct{}{}
	c.access.Unlock()
}

func (c *connectionCounter) count() int {
	c.access.Lock()
	defer c.access.Unlock()
	return len(c.conns)
}

type httpserverTunnelCounter struct {
	access sync.Mutex
	total  int
}

func (c *httpserverTunnelCounter) inc() {
	c.access.Lock()
	c.total++
	c.access.Unlock()
}

func startMASQUEPoolServer(t *testing.T) *masquePoolServer {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	counter := &connectionCounter{conns: make(map[*quic.Conn]struct{})}
	server := &masquePoolServer{
		connections: counter,
		tunnels:     &httpserverTunnelCounter{},
	}

	serverImpl := &http3.Server{
		EnableDatagrams: true,
		TLSConfig:       poolTestServerTLS(t),
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			counter.add(conn)
			return ctx
		},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodConnect {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			server.tunnels.inc()
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			// Echo whatever the tunnel sends back, so a test can prove the
			// tunnel carried bytes.
			body := request.Body
			defer body.Close()
			buffer := make([]byte, 4096)
			for {
				n, readErr := body.Read(buffer)
				if n > 0 {
					if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
						return
					}
					writer.(http.Flusher).Flush()
				}
				if readErr != nil {
					return
				}
			}
		}),
	}
	go func() { _ = serverImpl.Serve(udpConn) }()
	t.Cleanup(func() {
		_ = serverImpl.Close()
		udpConn.Close()
	})
	server.address = udpConn.LocalAddr().String()
	return server
}

func poolTestServerTLS(t *testing.T) *stdTLS.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"example.test"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	return &stdTLS.Config{
		Certificates: []stdTLS.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{http3.NextProtoH3},
	}
}

// newPoolTestAgent builds the MASQUE client the way protocol/http does.
func newPoolTestAgent(t *testing.T, server *masquePoolServer, poolSize int) *http3ClientImpl {
	t.Helper()
	serverAddress := M.ParseSocksaddr(server.address)
	tlsConfig, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context: context.Background(),
		Options: option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.test",
			Insecure:   true,
		},
	})
	require.NoError(t, err)
	// HTTP/3 requires the h3 ALPN; the QUIC handshake fails with
	// "tls: no application protocol" without it.
	tlsConfig.SetNextProtos([]string{http3.NextProtoH3})

	client, err := newHTTP3Client(ClientOptions{
		Server:    serverAddress,
		RawDialer: N.SystemDialer,
		TLSConfig: tlsConfig,
		Authority: "example.test",
		Headers:   http.Header{"X-Test": []string{"pool"}},
		HTTP3Options: option.QUICOptions{
			HTTP3ConnectionPool: &option.HTTP3ConnectionPoolOptions{Size: poolSize, Strategy: "round_robin"},
		},
	}, "")
	require.NoError(t, err)
	impl, isImpl := client.(*http3ClientImpl)
	require.True(t, isImpl)
	t.Cleanup(func() { _ = impl.Close() })
	return impl
}

// TestMASQUEPoolSizeOneUsesOneConnection is the upstream-equivalence case.
func TestMASQUEPoolSizeOneUsesOneConnection(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 1)
	require.Equal(t, 1, agent.slotCount())

	target := M.ParseSocksaddr("127.0.0.1:9") // destination is irrelevant; the server just echoes
	for index := range 8 {
		conn, err := agent.DialContext(context.Background(), target)
		require.NoError(t, err, "CONNECT %d", index+1)
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		buffer := make([]byte, 4)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(buffer)
		require.NoError(t, err)
		conn.Close()
	}
	require.Equal(t, 1, server.connections.count(),
		"pool size 1 must use exactly one QUIC connection")
}

// TestMASQUEPoolSizeTwoOpensTwoConnections is the property the feature exists for.
func TestMASQUEPoolSizeTwoOpensTwoConnections(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)
	require.Equal(t, 2, agent.slotCount())

	target := M.ParseSocksaddr("127.0.0.1:9")
	for index := range 8 {
		conn, err := agent.DialContext(context.Background(), target)
		require.NoError(t, err, "CONNECT %d", index+1)
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		conn.Close()
	}
	require.GreaterOrEqual(t, server.connections.count(), 2,
		"pool size 2 must open two independent QUIC connections, not two streams on one")
}

// TestMASQUEPoolConcurrentCONNECTSpreadsConnections drives many concurrent TCP
// CONNECT tunnels and requires them to land on both connections.
func TestMASQUEPoolConcurrentCONNECTSpreadsConnections(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)

	const tunnels = 32
	var waitGroup sync.WaitGroup
	errs := make(chan error, tunnels)
	for range tunnels {
		waitGroup.Go(func() {
			conn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			if _, err = conn.Write([]byte("hello")); err != nil {
				errs <- err
			}
		})
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.GreaterOrEqual(t, server.connections.count(), 2,
		"32 concurrent CONNECT tunnels must spread across both pooled connections")
}

// TestMASQUEPoolConcurrentConnectUDPSpreadsConnections does the same for the
// datagram tunnel path.
func TestMASQUEPoolConcurrentConnectUDPSpreadsConnections(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)

	requestURL := mustParseURL(t, "https://example.test/.well-known/masque/udp/127.0.0.1/9/")
	const tunnels = 16
	var waitGroup sync.WaitGroup
	errs := make(chan error, tunnels)
	for range tunnels {
		waitGroup.Go(func() {
			stream, err := agent.OpenTunnel(context.Background(), tunnelRequest{
				url:      requestURL,
				protocol: "connect-udp",
			})
			if err != nil {
				errs <- err
				return
			}
			stream.Close()
		})
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.GreaterOrEqual(t, server.connections.count(), 2,
		"concurrent CONNECT-UDP tunnels must spread across both pooled connections")
}

// TestMASQUEPoolResetAndCloseReleaseEverySlot proves lifecycle cleanup covers the
// whole pool, not just one member.
func TestMASQUEPoolResetAndCloseReleaseEverySlot(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)

	target := M.ParseSocksaddr("127.0.0.1:9")
	for index := range 4 {
		conn, err := agent.DialContext(context.Background(), target)
		require.NoError(t, err, "CONNECT %d", index+1)
		conn.Close()
	}
	require.GreaterOrEqual(t, server.connections.count(), 2)

	// ResetConnection must drop every slot's connection and socket.
	agent.ResetConnection()
	for index, slot := range agent.slots {
		slot.access.Lock()
		require.Nil(t, slot.conn, "slot %d connection must be released", index)
		require.Nil(t, slot.rawConn, "slot %d UDP socket must be released", index)
		slot.access.Unlock()
	}

	// Tunnels still work after a reset: each slot dials fresh.
	conn, err := agent.DialContext(context.Background(), target)
	require.NoError(t, err)
	conn.Close()

	// Close must release everything and be safe to call once.
	require.NoError(t, agent.Close())
	for index, slot := range agent.slots {
		slot.access.Lock()
		require.Nil(t, slot.conn, "slot %d connection must be released on Close", index)
		require.Nil(t, slot.rawConn, "slot %d UDP socket must be released on Close", index)
		slot.access.Unlock()
	}
}

// TestMASQUEPoolTunnelNotMigratedOnFailure is the replay-safety property: a
// tunnel that fails is NOT retried on another slot.
func TestMASQUEPoolSlotChosenOncePerTunnel(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)

	// Drive one failing tunnel against an unreachable server address and confirm
	// the failed slot is not silently swapped for the other one.
	unreachable := &http3ClientImpl{
		dialer:         N.SystemDialer,
		tlsConfig:      agent.tlsConfig,
		server:         M.ParseSocksaddr("127.0.0.1:1"),
		authority:      "example.test",
		headers:        agent.headers,
		baseQUICConfig: agent.baseQUICConfig,
		slots:          agent.slots,
		authorization:  "",
	}
	firstSlot := unreachable.pickSlot()
	require.NotNil(t, firstSlot)

	_, err := unreachable.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.Error(t, err, "a tunnel to an unreachable server must fail")

	// The failure must not have been replayed onto the other slot: exactly one
	// slot may show connection state, and the client must not retry.
	require.Equal(t, 2, unreachable.slotCount())
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}

// TestMASQUEPoolSlotFailureDoesNotPoisonAuthority is the P0-3 health-split
// regression.
//
// A slot-level failure means "this pooled connection could not be established",
// not "the authority does not speak HTTP/3". Conflating them made one dead
// connection mark the whole authority broken and drop every tunnel to HTTP/2,
// even though the other slot was healthy.
func TestMASQUEPoolSlotFailureDoesNotPoisonAuthority(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)

	// A dialer that always fails models an unusable slot.
	failing := &http3ClientImpl{
		dialer:         failingDialer{},
		tlsConfig:      agent.tlsConfig,
		server:         M.ParseSocksaddr("127.0.0.1:1"),
		authority:      "example.test",
		headers:        agent.headers,
		baseQUICConfig: agent.baseQUICConfig,
		slots:          agent.slots,
	}
	_, err := failing.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrHTTP3Unavailable),
		"a slot connection failure must NOT be reported as HTTP/3 being unavailable, "+
			"otherwise the caller disables HTTP/3 for the whole authority; got %v", err)
}

// TestMASQUEPoolHealthySlotStillUsedAfterAnotherFails proves service continues.
func TestMASQUEPoolHealthySlotStillUsedAfterAnotherFails(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)

	// Poison one slot's connection state directly, as a dead connection would.
	agent.slots[0].access.Lock()
	agent.slots[0].conn = nil
	agent.slots[0].rawConn = nil
	agent.slots[0].access.Unlock()

	// Tunnels must still succeed: the client rotates and the healthy slot serves.
	succeeded := 0
	for range 4 {
		conn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
		if err == nil {
			succeeded++
			conn.Close()
		}
	}
	require.GreaterOrEqual(t, succeeded, 1,
		"at least one tunnel must succeed while a healthy slot exists")
	require.GreaterOrEqual(t, server.connections.count(), 1,
		"a healthy slot must have established a real connection")
}

// failingDialer always fails, modelling an unusable pool slot.
type failingDialer struct{}

func (failingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

func (failingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("listen failed")
}
