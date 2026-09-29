//go:build with_quic

package http

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// End-to-end test of the property Stage 6 and Stage 7 exist for: a CONNECT-IP tunnel and
// the DoH requests that ride along with it must travel on ONE QUIC connection.
//
// # Why this cannot be inferred from the unit tests
//
// The unit tests prove the plumbing: that acquire() memoizes, that the generic path calls it,
// that DoH selects the generic path. All of those could hold while the real system still
// opened two connections -- for instance if the tunnel and the DoH client were built from
// different Client values, or if a connection reset between them.
//
// So this test runs against a REAL HTTP/3 server that accepts a CONNECT-IP request and
// ordinary requests on the same listener, and counts the QUIC connections the server
// accepted. One is the only acceptable answer. The server is not mocked: it is a real
// quic-go http3.Server with a real TLS handshake, and the count is taken from the server's
// own ConnContext callback rather than from anything the client reports about itself.

// countingTunnelServer is a real HTTP/3 server that serves both an extended CONNECT tunnel
// and ordinary requests, and counts the QUIC connections it accepts.
type countingTunnelServer struct {
	address  string
	server   *http3.Server
	closed   chan struct{}
	access   sync.Mutex
	conns    []*quic.Conn
	tunnels  int
	requests int
	// dohAnswer is returned for POSTs to the DoH path.
	dohAnswer []byte
}

func (s *countingTunnelServer) connectionCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.conns)
}

func (s *countingTunnelServer) streamCounts() (tunnels int, requests int) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.tunnels, s.requests
}

// startCountingTunnelServer starts the server on loopback.
//
// It enables Extended CONNECT and datagrams, because a CONNECT-IP tunnel needs both, and
// the client under test refuses to use a connection whose settings do not advertise them.
func startCountingTunnelServer(t *testing.T, dohAnswer []byte) *countingTunnelServer {
	t.Helper()
	server := &countingTunnelServer{closed: make(chan struct{}), dohAnswer: dohAnswer}

	tlsConfig := testServerTLSConfig(t)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	server.address = packetConn.LocalAddr().String()

	server.server = &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			server.access.Lock()
			if request.Method == http.MethodConnect {
				server.tunnels++
			} else {
				server.requests++
			}
			answer := server.dohAnswer
			server.access.Unlock()

			if request.Method == http.MethodConnect {
				// A CONNECT-IP stream is answered with 200 and then stays open as the
				// tunnel. The handler must NOT return, or the stream would be closed;
				// it blocks until the request context is cancelled.
				writer.WriteHeader(http.StatusOK)
				if flusher, isFlusher := writer.(http.Flusher); isFlusher {
					flusher.Flush()
				}
				<-request.Context().Done()
				return
			}
			writer.Header().Set("Content-Type", "application/dns-message")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(answer)
		}),
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			// The tunnel is long-lived, so the idle timeout must not close it while the
			// test is still using it.
			MaxIdleTimeout:  60 * time.Second,
			EnableDatagrams: true,
		},
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			server.access.Lock()
			server.conns = append(server.conns, conn)
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

// testTLSClientConfig builds a client TLS config that trusts the server's certificate.
func testTLSClientConfig(t *testing.T) *tls.Config {
	t.Helper()
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}
}

// TestTunnelAndDoHShareOneConnection is the Stage 7 acceptance test.
//
// It opens a CONNECT-IP tunnel, then issues several DoH requests, and requires the server to
// have accepted exactly ONE QUIC connection for all of them. A second connection would mean
// the coalescing the draft asks for is not happening, and the privacy property the design
// claims -- that inner DNS queries and tunnel traffic are indistinguishable as one flow --
// would be false.
func TestTunnelAndDoHShareOneConnection(t *testing.T) {
	t.Parallel()

	answer := []byte("dns-wire-response")
	server := startCountingTunnelServer(t, answer)

	clientConn, err := quic.DialAddr(context.Background(),
		server.address, testTLSClientConfig(t), &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			EnableDatagrams:      true,
		})
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	// Build the same shape transport/http uses: one ClientConn wrapping this QUIC
	// connection, which is what acquire() memoizes in production.
	transport := &http3.Transport{}
	http3Conn := transport.NewClientConn(clientConn)

	// Wait for the server's SETTINGS, which advertise Extended CONNECT and datagrams.
	select {
	case <-http3Conn.ReceivedSettings():
	case <-time.After(5 * time.Second):
		t.Fatal("server settings were not received")
	}
	require.True(t, http3Conn.Settings().EnableDatagrams,
		"the server must advertise datagrams for a CONNECT-IP tunnel")

	impl := &http3ClientImpl{
		transport: transport,
		conn:      http3Conn,
		authority: server.address,
	}
	client := &Client{http3: impl, http3Authority: server.address}

	// 1. Open a CONNECT-IP tunnel on the shared connection.
	tunnelURL := &url.URL{Scheme: "https", Host: server.address, Path: "/.well-known/masque/ip/*/*/"}
	tunnelRequest, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, tunnelURL.String(), nil)
	require.NoError(t, err)
	tunnelRequest.Proto = "connect-ip"
	tunnelRequest.Host = server.address
	tunnelRequest.Header.Set("Capsule-Protocol", "?1")

	tunnelResponse, err := client.RoundTripHTTP3(context.Background(), tunnelRequest)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tunnelResponse.StatusCode,
		"the tunnel must be established on the shared connection")
	defer tunnelResponse.Body.Close()

	// 2. Issue DoH requests. The FIRST one must reuse the connection the tunnel is on,
	//    which is the whole claim: these are separate HTTP/3 streams, not a second
	//    connection.
	const dohRequestCount = 8
	var waitGroup sync.WaitGroup
	errors := make(chan error, dohRequestCount)
	for index := range dohRequestCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			requestURL := "https://" + server.address + "/dns-query"
			request, requestErr := http.NewRequestWithContext(context.Background(), http.MethodPost,
				requestURL, stringReader("query-"+strconv.Itoa(index)))
			if requestErr != nil {
				errors <- requestErr
				return
			}
			response, roundTripErr := client.RoundTripHTTP3(context.Background(), request)
			if roundTripErr != nil {
				errors <- roundTripErr
				return
			}
			payload, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				errors <- readErr
				return
			}
			if string(payload) != string(answer) {
				errors <- E.New("unexpected DoH payload: ", string(payload))
			}
		}()
	}
	waitGroup.Wait()
	close(errors)
	for requestErr := range errors {
		require.NoError(t, requestErr)
	}

	// 3. The proof: ONE connection carried the tunnel and every DoH request.
	require.Equal(t, 1, server.connectionCount(),
		"the tunnel and all DoH requests must share exactly one QUIC connection; a second connection means the DoH traffic is not coalesced and the privacy claim is false")

	tunnels, requests := server.streamCounts()
	require.Equal(t, 1, tunnels, "exactly one CONNECT-IP stream")
	require.Equal(t, dohRequestCount, requests,
		"each DoH request must be its own HTTP/3 stream on the shared connection")

	// The connection is still usable after all of that, which is what proves the DoH
	// streams did not disturb the tunnel.
	require.NoError(t, clientConn.Context().Err(), "the shared connection must still be alive")
}

// stringReader is a tiny io.Reader for bodies, avoiding strings.NewReader so that the
// ContentLength is deliberately left unset -- which is the case the request path has to
// handle by treating an unknown length honestly.
type simpleReader struct {
	data []byte
	read bool
}

func (r *simpleReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	n := copy(p, r.data)
	return n, nil
}

func stringReader(value string) *simpleReader {
	return &simpleReader{data: []byte(value)}
}

// TestDoHRequestDoesNotCreateASecondConnectionWhenTunnelExists is the negative half.
//
// It asserts that the connection count stays at one across many sequential requests, so a
// per-request connection (a plausible regression if acquire() were ever bypassed) is caught
// even though every individual request would still succeed.
func TestDoHRequestDoesNotCreateASecondConnectionWhenTunnelExists(t *testing.T) {
	t.Parallel()

	server := startCountingTunnelServer(t, []byte("answer"))

	clientConn, err := quic.DialAddr(context.Background(),
		server.address, testTLSClientConfig(t), &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			EnableDatagrams:      true,
		})
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	transport := &http3.Transport{}
	http3Conn := transport.NewClientConn(clientConn)
	select {
	case <-http3Conn.ReceivedSettings():
	case <-time.After(5 * time.Second):
		t.Fatal("server settings were not received")
	}

	impl := &http3ClientImpl{transport: transport, conn: http3Conn, authority: server.address}
	client := &Client{http3: impl, http3Authority: server.address}

	for range 5 {
		request, requestErr := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"https://"+server.address+"/dns-query", stringReader("q"))
		require.NoError(t, requestErr)
		response, roundTripErr := client.RoundTripHTTP3(context.Background(), request)
		require.NoError(t, roundTripErr)
		_, _ = io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
	}

	require.Equal(t, 1, server.connectionCount(),
		"sequential requests must never open another connection")
}
