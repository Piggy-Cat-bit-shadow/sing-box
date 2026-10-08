package quic

import (
	"context"
	stdTLS "crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// # What these tests pin
//
// DoQ and DoH3 used to implement only Reset, so the memory-trim pass (adapter.IdleConnectionKeeper
// -> CloseIdleConnections) could not reach them at all: the QUIC connection and the HTTP/3 session
// had no idle path, and a trim was a no-op that left the sockets and their buffers resident.
//
// The shape that matters is the one common/httpclient/managed_transport.go documents: a trim must
// drop IDLE state and keep the generation. It must not dial, it must not replace the transport/pool
// (which would make the next query rebuild more than the trim released), and it must not disturb a
// query that is in flight. These run against real quic-go listeners on loopback, because the
// property under test is what the pool's and http3.Transport's own idle bookkeeping does, and a
// double would only assert that the call was made.
//
// Every dial goes through countingDialer, so "the trim itself causes zero dials" is a measurement
// rather than an inspection of the code path.

// countingDialer is the only way a transport under test can reach the network. It records the UDP
// dials so a test can prove that a trim added none and that a post-trim query either reused the
// surviving connection or (when nothing reusable remained) dialed exactly once more.
type countingDialer struct {
	dials atomic.Int64
}

func (d *countingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *countingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var listener net.ListenConfig
	return listener.ListenPacket(ctx, "udp", "")
}

var (
	testCertificateOnce sync.Once
	testCertificate     stdTLS.Certificate
	testCertificateErr  error
)

// testCertificates returns one self-signed pair for the whole package. RSA key generation is the
// slowest part of a QUIC handshake test, and the certificate is immutable, so generating it once
// keeps -count=20 affordable.
func testCertificates(t *testing.T) stdTLS.Certificate {
	t.Helper()
	testCertificateOnce.Do(func() {
		keyPEM, certPEM, err := tls.GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(24*time.Hour))
		if err != nil {
			testCertificateErr = err
			return
		}
		testCertificate, testCertificateErr = stdTLS.X509KeyPair(certPEM, keyPEM)
	})
	require.NoError(t, testCertificateErr)
	return testCertificate
}

func newTestQuery() *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	message.RecursionDesired = true
	return message
}

func testLogger() log.ContextLogger {
	return log.NewNOPFactory().NewLogger("dns-quic-trim-test")
}

// ---------------------------------------------------------------------------
// DoQ
// ---------------------------------------------------------------------------

// doqTestServer speaks just enough DNS-over-QUIC for the transport under test: accept the QUIC
// connection, read one length-prefixed query, answer it, repeat. When gated is set the response is
// withheld until release is closed, which is what lets a test hold an exchange open while it trims.
type doqTestServer struct {
	listener *quic.Listener
	addr     M.Socksaddr
	queryCh  chan struct{}
	release  chan struct{}
	gated    bool

	connGone chan struct{}
	goneOnce sync.Once
	conns    atomic.Int64
}

func startDoQTestServer(t *testing.T, gated bool) *doqTestServer {
	t.Helper()
	certificate := testCertificates(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &stdTLS.Config{
		Certificates: []stdTLS.Certificate{certificate},
		NextProtos:   []string{"doq"},
	}, &quic.Config{})
	require.NoError(t, err)
	server := &doqTestServer{
		listener: listener,
		addr:     M.SocksaddrFromNet(listener.Addr()),
		queryCh:  make(chan struct{}, 8),
		release:  make(chan struct{}),
		gated:    gated,
		connGone: make(chan struct{}),
	}
	go server.accept()
	t.Cleanup(func() { listener.Close() })
	return server
}

func (s *doqTestServer) accept() {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return
		}
		s.conns.Add(1)
		go func() {
			<-conn.Context().Done()
			s.goneOnce.Do(func() { close(s.connGone) })
		}()
		go s.serveConn(conn)
	}
}

func (s *doqTestServer) serveConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			message, readErr := transport.ReadMessage(stream)
			if readErr != nil {
				stream.CancelRead(0)
				stream.Close()
				return
			}
			select {
			case s.queryCh <- struct{}{}:
			default:
			}
			if s.gated {
				select {
				case <-s.release:
				case <-conn.Context().Done():
					stream.CancelRead(0)
					stream.Close()
					return
				}
			}
			response := new(mDNS.Msg)
			response.SetReply(message)
			_ = transport.WriteMessage(stream, 0, response)
			stream.Close()
		}()
	}
}

// newDoQTestTransport builds the production pool shape with a dialer the test can count. It goes
// through the same ConnPoolSingle options NewQUIC uses, so the idle-only behaviour under test is
// the real one rather than a relaxed test double.
func newDoQTestTransport(t *testing.T, dialer N.Dialer, serverAddr M.Socksaddr) *Transport {
	t.Helper()
	tlsConfig, err := tls.NewSTDClient(context.Background(), testLogger(), "localhost", option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
		ALPN:     []string{"doq"},
	})
	require.NoError(t, err)
	return &Transport{
		dialer:     dialer,
		serverAddr: serverAddr,
		tlsConfig:  tlsConfig,
		connection: transport.NewConnPool(transport.ConnPoolOptions[*quic.Conn]{
			Mode: transport.ConnPoolSingle,
			IsAlive: func(conn *quic.Conn) bool {
				return conn != nil && !common.Done(conn.Context())
			},
			Close: func(conn *quic.Conn, _ error) {
				conn.CloseWithError(0, "")
			},
		}),
	}
}

// TestQUICTransportTrimReleasesIdleConnectionWithoutDialing is the base case: with no query in
// flight, the trim must release the pooled QUIC connection (observable as the server's connection
// ending) and must not dial. Because nothing reusable is left, the query after the trim is allowed
// to dial again - and that is asserted too, so a trim that released nothing cannot pass by leaving
// the connection for the next query.
func TestQUICTransportTrimReleasesIdleConnectionWithoutDialing(t *testing.T) {
	t.Parallel()
	server := startDoQTestServer(t, false)
	dialer := &countingDialer{}
	clientTransport := newDoQTestTransport(t, dialer, server.addr)
	t.Cleanup(func() { clientTransport.connection.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := clientTransport.Exchange(ctx, newTestQuery())
	require.NoError(t, err)
	require.NotNil(t, response)
	require.EqualValues(t, 1, dialer.dials.Load(), "one exchange dials one QUIC connection")

	// The exchange has returned, so no query holds the connection: it is idle in the pool.
	clientTransport.CloseIdleConnections()
	require.EqualValues(t, 1, dialer.dials.Load(), "the trim itself must not dial")

	select {
	case <-server.connGone:
	case <-time.After(5 * time.Second):
		t.Fatal("the trim did not release the idle QUIC connection")
	}

	// Nothing reusable remains, so this query dials - once, and successfully.
	response, err = clientTransport.Exchange(ctx, newTestQuery())
	require.NoError(t, err)
	require.NotNil(t, response)
	require.EqualValues(t, 2, dialer.dials.Load())
	require.EqualValues(t, 2, server.conns.Load())
}

// TestQUICTransportTrimKeepsAnActiveExchange is the concurrency half: a trim that lands while a
// query has the pooled connection checked out must not close it. It must also leave the pool's
// generation intact, so the query after the overlap reuses the same connection rather than
// rebuilding - which is exactly the failure common/httpclient/managed_transport.go documents for a
// trim that swaps a generation.
func TestQUICTransportTrimKeepsAnActiveExchange(t *testing.T) {
	t.Parallel()
	server := startDoQTestServer(t, true)
	dialer := &countingDialer{}
	clientTransport := newDoQTestTransport(t, dialer, server.addr)
	t.Cleanup(func() { clientTransport.connection.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type exchangeResult struct {
		response *mDNS.Msg
		err      error
	}
	done := make(chan exchangeResult, 1)
	go func() {
		response, err := clientTransport.Exchange(ctx, newTestQuery())
		done <- exchangeResult{response: response, err: err}
	}()

	// The query has reached the server, so the pool has the connection checked out right now.
	select {
	case <-server.queryCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the query never reached the server")
	}

	clientTransport.CloseIdleConnections()
	require.EqualValues(t, 1, dialer.dials.Load(), "the trim itself must not dial")

	select {
	case <-server.connGone:
		t.Fatal("the trim closed the connection out from under an active exchange")
	default:
	}

	close(server.release)
	result := <-done
	require.NoError(t, result.err)
	require.NotNil(t, result.response)

	response, err := clientTransport.Exchange(ctx, newTestQuery())
	require.NoError(t, err)
	require.NotNil(t, response)
	require.EqualValues(t, 1, dialer.dials.Load(), "the post-trim query must reuse the surviving connection, not rebuild")
	require.EqualValues(t, 1, server.conns.Load())
}

// ---------------------------------------------------------------------------
// DoH3
// ---------------------------------------------------------------------------

type h3TestServer struct {
	listener  *quic.Listener
	addr      M.Socksaddr
	requestCh chan struct{}
	release   chan struct{}
	gated     bool

	connGone chan struct{}
	goneOnce sync.Once
	conns    atomic.Int64
}

// trackingListener records the QUIC connections http3.Server accepts, so a test can observe the
// server side of an idle-connection release without reaching into the client's internals.
type trackingListener struct {
	*quic.Listener
	onConn func(*quic.Conn)
}

func (l *trackingListener) Accept(ctx context.Context) (*quic.Conn, error) {
	conn, err := l.Listener.Accept(ctx)
	if err == nil {
		l.onConn(conn)
	}
	return conn, err
}

func startH3TestServer(t *testing.T, gated bool) *h3TestServer {
	t.Helper()
	server := &h3TestServer{
		requestCh: make(chan struct{}, 8),
		release:   make(chan struct{}),
		gated:     gated,
		connGone:  make(chan struct{}),
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case server.requestCh <- struct{}{}:
		default:
		}
		if server.gated {
			// Withheld BEFORE the response headers, which is the window http3.Transport's own
			// useCount covers. Waiting here keeps RoundTrip in flight for the whole overlap.
			select {
			case <-server.release:
			case <-request.Context().Done():
				return
			}
		}
		rawQuery, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var query mDNS.Msg
		if err = query.Unpack(rawQuery); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var response mDNS.Msg
		response.SetReply(&query)
		rawResponse, err := response.Pack()
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", transport.MimeType)
		_, _ = writer.Write(rawResponse)
	})

	certificate := testCertificates(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &stdTLS.Config{
		Certificates: []stdTLS.Certificate{certificate},
		NextProtos:   []string{http3.NextProtoH3},
	}, &quic.Config{})
	require.NoError(t, err)
	server.listener = listener
	server.addr = M.SocksaddrFromNet(listener.Addr())
	tracked := &trackingListener{Listener: listener, onConn: func(conn *quic.Conn) {
		server.conns.Add(1)
		go func() {
			<-conn.Context().Done()
			server.goneOnce.Do(func() { close(server.connGone) })
		}()
	}}
	h3Server := &http3.Server{Handler: handler}
	go h3Server.ServeListener(tracked)
	t.Cleanup(func() {
		h3Server.Close()
		listener.Close()
	})
	return server
}

func newDoH3TestTransport(t *testing.T, dialer N.Dialer, serverAddr M.Socksaddr) *HTTP3Transport {
	t.Helper()
	clientConfig, err := tls.NewSTDClient(context.Background(), testLogger(), "localhost", option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
		ALPN:     []string{http3.NextProtoH3},
	})
	require.NoError(t, err)
	stdConfig, err := clientConfig.STDConfig()
	require.NoError(t, err)
	clientTransport := &HTTP3Transport{
		logger:      testLogger(),
		dialer:      dialer,
		destination: &url.URL{Scheme: "https", Host: "localhost", Path: "/dns-query"},
		headers:     make(http.Header),
		serverAddr:  serverAddr,
		tlsConfig:   stdConfig,
	}
	clientTransport.transport = clientTransport.newTransport()
	clientTransport.keepIdle.Store(true)
	t.Cleanup(func() { clientTransport.transport.Close() })
	return clientTransport
}

// TestHTTP3TransportTrimReleasesIdleSessionWithoutDialing is DoH3's base case. http3.Transport's
// own CloseIdleConnections is the mechanism: it closes only clients whose useCount is zero, which
// is the server-visible connection ending asserted here.
func TestHTTP3TransportTrimReleasesIdleSessionWithoutDialing(t *testing.T) {
	t.Parallel()
	server := startH3TestServer(t, false)
	dialer := &countingDialer{}
	clientTransport := newDoH3TestTransport(t, dialer, server.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := clientTransport.Exchange(ctx, newTestQuery())
	require.NoError(t, err)
	require.NotNil(t, response)
	require.EqualValues(t, 1, dialer.dials.Load(), "one exchange dials one QUIC connection")

	clientTransport.CloseIdleConnections()
	require.EqualValues(t, 1, dialer.dials.Load(), "the trim itself must not dial")

	select {
	case <-server.connGone:
	case <-time.After(5 * time.Second):
		t.Fatal("the trim did not release the idle HTTP/3 session")
	}

	// The transport itself was kept, so this is a fresh QUIC connection on the SAME transport -
	// not a rebuilt transport. Nothing reusable remained, so the dial is expected.
	response, err = clientTransport.Exchange(ctx, newTestQuery())
	require.NoError(t, err)
	require.NotNil(t, response)
	require.EqualValues(t, 2, dialer.dials.Load())
	require.EqualValues(t, 2, server.conns.Load())
}

// TestHTTP3TransportTrimKeepsAnActiveExchange is DoH3's concurrency half, and it also pins the
// difference from Reset: the request after the overlap reuses the surviving session (one dial in
// total), which a transport swap could not do.
func TestHTTP3TransportTrimKeepsAnActiveExchange(t *testing.T) {
	t.Parallel()
	server := startH3TestServer(t, true)
	dialer := &countingDialer{}
	clientTransport := newDoH3TestTransport(t, dialer, server.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type exchangeResult struct {
		response *mDNS.Msg
		err      error
	}
	done := make(chan exchangeResult, 1)
	go func() {
		response, err := clientTransport.Exchange(ctx, newTestQuery())
		done <- exchangeResult{response: response, err: err}
	}()

	select {
	case <-server.requestCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the HTTP/3 server")
	}

	clientTransport.CloseIdleConnections()
	require.EqualValues(t, 1, dialer.dials.Load(), "the trim itself must not dial")

	select {
	case <-server.connGone:
		t.Fatal("the trim closed the HTTP/3 session out from under an active exchange")
	default:
	}

	close(server.release)
	result := <-done
	require.NoError(t, result.err)
	require.NotNil(t, result.response)

	response, err := clientTransport.Exchange(ctx, newTestQuery())
	require.NoError(t, err)
	require.NotNil(t, response)
	require.EqualValues(t, 1, dialer.dials.Load(), "the post-trim query must reuse the surviving session, not rebuild")
	require.EqualValues(t, 1, server.conns.Load())
}
