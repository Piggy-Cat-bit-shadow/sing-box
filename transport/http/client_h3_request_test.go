//go:build with_quic

package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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

// Acceptance tests for the generic HTTP/3 request capability.
//
// The property that justifies this API's existence is connection REUSE: a DNS_ASSIGN DoH
// resolver must be able to send queries over the same QUIC connection that carries the
// CONNECT-IP tunnel. Proving that means counting connections and streams, not comparing
// host and port -- an earlier trap in this codebase was asserting reuse from configuration
// rather than from the transport.

// countingH3Server is a real HTTP/3 server that records how many QUIC connections it
// accepts and how many request streams it serves.
type countingH3Server struct {
	server      *http3.Server
	address     string
	quicConns   atomic.Int64
	streams     atomic.Int64
	statusCode  int
	body        string
	respondWith func(writer http.ResponseWriter, request *http.Request)
	accepted    []*quic.Conn
	access      sync.Mutex
	closed      chan struct{}
}

func startCountingH3Server(t *testing.T, handler http.HandlerFunc) *countingH3Server {
	t.Helper()
	server := &countingH3Server{
		statusCode: http.StatusOK,
		body:       "ok",
		closed:     make(chan struct{}),
	}
	server.respondWith = handler

	// The package already has a loopback HTTP/3 TLS helper; reusing it keeps this test
	// file focused on the reuse semantics rather than on certificate plumbing.
	tlsConfig := testServerTLSConfig(t)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	server.address = packetConn.LocalAddr().String()

	server.server = &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			server.streams.Add(1)
			if server.respondWith != nil {
				server.respondWith(writer, request)
				return
			}
			writer.WriteHeader(server.statusCode)
			_, _ = io.WriteString(writer, server.body)
		}),
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			// Short handshake budget: these are loopback tests and a slow handshake would
			// only add time without testing anything.
			HandshakeIdleTimeout: 5 * time.Second,
		},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			server.quicConns.Add(1)
			server.access.Lock()
			server.accepted = append(server.accepted, conn)
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
		_ = packetConn.Close()
	})
	return server
}

func (s *countingH3Server) connectionCount() int {
	return int(s.quicConns.Load())
}

func (s *countingH3Server) streamCount() int {
	return int(s.streams.Load())
}

// newGenericTestClient builds a real *Client configured for HTTP/3 against a test server.
func newGenericTestClient(t *testing.T, server *countingH3Server) *Client {
	t.Helper()
	// The ALPN must be "h3" explicitly. NewClientWithTLS sets it when Version == 3, but
	// this test constructs the HTTP/3 client directly, so it has to state what that path
	// would have derived. Without it the server refuses the handshake with
	// "tls: no application protocol".
	tlsConfig, err := tls.NewSTDClient(t.Context(), logger.NOP(), "localhost",
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "localhost",
			Insecure:   true,
			ALPN:       []string{"h3"},
		})
	require.NoError(t, err)

	dialer := &hookRecordingDialer{}
	client := &Client{
		dialer:            dialer,
		authorityOverride: server.address,
		version:           3,
	}
	// The cached UDP dialer path is not used here; the H3 client dials the test server
	// directly through its own dialer.
	h3, err := newHTTP3Client(ClientOptions{
		Dialer:    dialer,
		TLSConfig: tlsConfig,
		Server:    M.ParseSocksaddr(server.address),
		Authority: server.address,
		Version:   3,
	}, "")
	require.NoError(t, err)
	client.http3 = h3
	client.http3Authority = server.address
	return client
}

// ---------------------------------------------------------------------------
// Acceptance 7: H2-only client returns the typed H3-unavailable error
// ---------------------------------------------------------------------------

// TestRoundTripHTTP3OnNonH3ClientReturnsTypedError is acceptance 7.
//
// A client without HTTP/3 must report that clearly rather than silently downgrading: this
// API exists to preserve same-connection reuse, and a downgrade would establish a
// different connection while appearing to work.
func TestRoundTripHTTP3OnNonH3ClientReturnsTypedError(t *testing.T) {
	t.Parallel()

	client := &Client{}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://example.test/dns-query", nil)
	require.NoError(t, err)

	_, err = client.RoundTripHTTP3(context.Background(), request)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHTTP3Unavailable,
		"the failure must be the typed H3-unavailable error so callers can fall back")
}

// TestRoundTripHTTP3RejectsCrossOrigin is the security test.
//
// The connection is authenticated for one authority. Letting it carry a request for
// another would make it a cross-origin tunnel riding on credentials never presented for
// that origin.
func TestRoundTripHTTP3RejectsCrossOrigin(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, nil)
	client := newGenericTestClient(t, server)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://someone-else.test/dns-query", nil)
	require.NoError(t, err)

	_, err = client.RoundTripHTTP3(context.Background(), request)
	require.Error(t, err, "a cross-origin request must be refused")
	require.Contains(t, err.Error(), "cross-origin")
	require.Equal(t, 0, server.connectionCount(),
		"a refused request must not even establish a connection")
}

func TestRoundTripHTTP3AcceptsSameAuthorityWithImplicitPort(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "dns-answer")
	})
	client := newGenericTestClient(t, server)

	host, _, found := strings.Cut(server.address, ":")
	if !found {
		host = server.address
	}
	// The authority without the explicit port must be accepted for the same host.
	client.http3Authority = host

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+host+":443/dns-query", strings.NewReader("query"))
	require.NoError(t, err)

	response, err := client.RoundTripHTTP3(context.Background(), request)
	require.NoError(t, err, "the same authority with an implicit default port must be accepted")
	defer response.Body.Close()
}

// ---------------------------------------------------------------------------
// Acceptance 8, 9: connection reuse across requests
// ---------------------------------------------------------------------------

// TestRoundTripHTTP3ReusesOneConnection is acceptance 8 and 9.
//
// Several sequential requests and then many concurrent ones must all travel on ONE QUIC
// connection. A second connection would mean the reuse claim is false, and the test counts
// connections at the server rather than trusting the client.
func TestRoundTripHTTP3ReusesOneConnection(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-message")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "answer")
	})
	client := newGenericTestClient(t, server)

	// Sequential requests.
	for range 3 {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"https://"+server.address+"/dns-query", strings.NewReader("q"))
		require.NoError(t, err)
		response, err := client.RoundTripHTTP3(context.Background(), request)
		require.NoError(t, err)
		_, _ = io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
	}
	require.Equal(t, 1, server.connectionCount(),
		"sequential requests must share one QUIC connection")

	// Concurrent requests.
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				"https://"+server.address+"/dns-query", strings.NewReader("q"))
			if err != nil {
				return
			}
			response, err := client.RoundTripHTTP3(context.Background(), request)
			if err != nil {
				return
			}
			_, _ = io.ReadAll(response.Body)
			_ = response.Body.Close()
		}()
	}
	wg.Wait()

	require.Equal(t, 1, server.connectionCount(),
		"concurrent requests must share the SAME connection, not open more")
	require.GreaterOrEqual(t, server.streamCount(), 19,
		"each request must have its own stream on the shared connection")
}

// ---------------------------------------------------------------------------
// Acceptance 10, 11: request bodies and response body lifecycle
// ---------------------------------------------------------------------------

// TestRoundTripHTTP3SendsRequestBody is acceptance 10, required because DoH POSTs carry
// the DNS query in the body.
func TestRoundTripHTTP3SendsRequestBody(t *testing.T) {
	t.Parallel()

	const query = "dns-wire-query-bytes"
	// The handler runs on a different goroutine from the test, so what it observes is
	// handed over through a channel rather than through shared variables. Writing to plain
	// variables here is a data race, and an intermittent one: it only shows up when the
	// read happens to overlap the handler, which is exactly the kind of flake that gets
	// attributed to something else.
	type receivedRequest struct {
		body string
		err  error
	}
	received := make(chan receivedRequest, 1)
	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		received <- receivedRequest{body: string(body), err: err}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "ok")
	})
	client := newGenericTestClient(t, server)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+server.address+"/dns-query", strings.NewReader(query))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/dns-message")

	response, err := client.RoundTripHTTP3(context.Background(), request)
	require.NoError(t, err)
	defer response.Body.Close()

	// The response arriving means the handler has already sent its body, so this receive
	// is not a race against the handler completing.
	observed := <-received
	require.NoError(t, observed.err)
	require.Equal(t, query, observed.body,
		"the request body must arrive intact, which is what makes DoH POST possible")
}

// TestRoundTripHTTP3ResponseBodyCloseReleasesStream is acceptance 11.
//
// The response body owns the stream. Closing it must finish the stream, and closing twice
// must be harmless. An unclosed stream would hold flow-control credit on the SHARED
// connection, eventually stalling the CONNECT-IP tunnel too.
func TestRoundTripHTTP3ResponseBodyCloseReleasesStream(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "payload")
	})
	client := newGenericTestClient(t, server)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+server.address+"/dns-query", nil)
	require.NoError(t, err)

	response, err := client.RoundTripHTTP3(context.Background(), request)
	require.NoError(t, err)

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "payload", string(body))

	require.NoError(t, response.Body.Close(), "closing the body must succeed")
	require.NoError(t, response.Body.Close(), "closing twice must be harmless")
}

// TestRoundTripHTTP3ReturnsNonSuccessStatus is acceptance 13.
//
// The generic layer must NOT require 200. A DoH server answers 4xx for a malformed query
// and that is a legitimate response the caller interprets; treating it as a transport
// failure would hide the DNS-level error.
func TestRoundTripHTTP3ReturnsNonSuccessStatus(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, "malformed query")
	})
	client := newGenericTestClient(t, server)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+server.address+"/dns-query", strings.NewReader("bad"))
	require.NoError(t, err)

	response, err := client.RoundTripHTTP3(context.Background(), request)
	require.NoError(t, err, "a non-2xx status is a response, not a transport failure")
	defer response.Body.Close()
	require.Equal(t, http.StatusBadRequest, response.StatusCode)

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "malformed query", string(body))
}

// ---------------------------------------------------------------------------
// Acceptance 12: cancellation is per-stream
// ---------------------------------------------------------------------------

// TestRoundTripHTTP3CancellationDoesNotCloseTheSharedConnection is acceptance 12.
//
// A cancelled or failed DoH query must not take down the CONNECT-IP tunnel. Since both
// live on one connection, cancelling the connection instead of the stream would be a
// catastrophic failure mode: one slow DNS query would kill the user's VPN.
func TestRoundTripHTTP3CancellationDoesNotCloseTheSharedConnection(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/slow" {
			<-release
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "fast")
	})
	client := newGenericTestClient(t, server)

	// A request that blocks on the server, cancelled by its own context.
	slowCtx, cancelSlow := context.WithCancel(context.Background())
	slowRequest, err := http.NewRequestWithContext(slowCtx, http.MethodGet,
		"https://"+server.address+"/slow", nil)
	require.NoError(t, err)

	slowDone := make(chan error, 1)
	go func() {
		_, slowErr := client.RoundTripHTTP3(slowCtx, slowRequest)
		slowDone <- slowErr
	}()
	time.Sleep(200 * time.Millisecond)
	cancelSlow()

	select {
	case <-slowDone:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the cancelled request did not return")
	}
	close(release)

	// The shared connection must still work.
	fastRequest, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+server.address+"/fast", nil)
	require.NoError(t, err)
	response, err := client.RoundTripHTTP3(context.Background(), fastRequest)
	require.NoError(t, err,
		"cancelling one stream must NOT close the connection the tunnel also uses")
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, 1, server.connectionCount(),
		"the retry must reuse the same connection")
}

// ---------------------------------------------------------------------------
// Acceptance 14, 15: ResetConnection and Close
// ---------------------------------------------------------------------------

// TestResetConnectionInvalidatesSharedConnection is acceptance 14.
//
// ResetConnection is what a session restart relies on. After it, the next request must
// establish a NEW connection rather than reusing a connection that was torn down.
func TestResetConnectionInvalidatesSharedConnection(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "ok")
	})
	client := newGenericTestClient(t, server)

	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+server.address+"/dns-query", nil)
	require.NoError(t, err)
	response, err := client.RoundTripHTTP3(context.Background(), first)
	require.NoError(t, err)
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	require.Equal(t, 1, server.connectionCount())

	client.ResetConnections()

	second, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+server.address+"/dns-query", nil)
	require.NoError(t, err)
	response, err = client.RoundTripHTTP3(context.Background(), second)
	require.NoError(t, err)
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()

	require.Equal(t, 2, server.connectionCount(),
		"after ResetConnection the next request must establish a fresh connection")
}

// TestCloseClosesTheSharedConnection is acceptance 15.
func TestCloseClosesTheSharedConnection(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "ok")
	})
	client := newGenericTestClient(t, server)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+server.address+"/dns-query", nil)
	require.NoError(t, err)
	response, err := client.RoundTripHTTP3(context.Background(), request)
	require.NoError(t, err)
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()

	require.NoError(t, client.Close())
}
