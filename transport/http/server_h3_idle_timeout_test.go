//go:build with_quic

package http

import (
	"context"
	stdTLS "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// These tests cover the HTTP/3 APPLICATION-layer idle timeout
// (http3.Server.IdleTimeout), which is a different knob from
// quic.Config.MaxIdleTimeout.
//
// The distinction is the whole point of the fix: quic.Config.MaxIdleTimeout is
// the QUIC transport idle timeout and is refreshed by ANY packet on the
// connection -- including a bare PING -- so it can never reclaim a connection
// that completes the handshake and then does nothing but ping. The
// application-layer timer is armed at connection creation, stopped as soon as a
// request stream arrives, and reset only when the last stream goes away.
//
// Every behavioural test below drives the REAL listener factory
// (ConfigureHTTP3ListenerFunc) rather than constructing an http3.Server by
// hand. That matters: an earlier draft built the server directly and passed
// even with the wiring in server_h3.go removed, which would have made these
// tests worthless as regression guards.
//
// None of these tests sleep for the production 60s. They all use a test-only
// short timeout, which is what makes them usable as regression tests.

// TestH3ApplicationIdleTimeoutReachesServer proves an explicitly configured
// idle_timeout is carried into the QUIC option set the listener factory receives.
// Before the fix IdleTimeout was never set on the http3.Server at all, so it
// applied only to quic.Config.MaxIdleTimeout and the application layer had no
// timeout. That gap is what this asserts is closed, now through the explicit
// option rather than through a named profile.
func TestH3ApplicationIdleTimeoutReachesServer(t *testing.T) {
	// Decoded from JSON with an explicit version, because the resource fields live
	// on HTTP3Options, which carries `json:"-"` and is filled by
	// unmarshalHTTPVersionsOptions. Without a version the decoder takes its default
	// branch and leaves the option set zero, silently discarding idle_timeout.
	var options option.HTTPInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"version": 3,
		"idle_timeout": "60s"
	}`), &options)
	require.NoError(t, err)

	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)
	require.Equal(t, 60*time.Second, time.Duration(resolved.HTTP3Options.IdleTimeout),
		"an explicit idle_timeout must reach the resolved QUIC options")
}

// TestH3IdleTimeoutIsPerInboundNotInherited proves two inbounds can carry
// different idle timeouts, which the removed profile could not express: it
// applied one value to every H3 listener that selected it.
func TestH3IdleTimeoutIsPerInboundNotInherited(t *testing.T) {
	decode := func(literal string) time.Duration {
		t.Helper()
		var options option.HTTPInboundOptions
		require.NoError(t, json.UnmarshalContext(context.Background(), []byte(literal), &options))
		resolved, err := options.ResolveServerResources()
		require.NoError(t, err)
		return time.Duration(resolved.HTTP3Options.IdleTimeout)
	}

	require.Equal(t, 7*time.Second, decode(`{"version": 3, "idle_timeout": "7s"}`))
	require.Equal(t, 90*time.Second, decode(`{"version": 3, "idle_timeout": "90s"}`))

	// And an inbound that sets nothing keeps quic-go's "no application timeout".
	require.Zero(t, decode(`{"version": 3}`))
}

// TestH3IdleTimeoutUnsetKeepsUpstreamDefault proves that with no profile and no
// explicit value the application idle timeout stays zero, which is the upstream
// "no timeout" behaviour. The fix must not impose a timeout nobody asked for.
func TestH3IdleTimeoutUnsetKeepsUpstreamDefault(t *testing.T) {
	options := option.HTTPInboundOptions{}
	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)
	require.Zero(t, time.Duration(resolved.HTTP3Options.IdleTimeout),
		"an unselected profile must not invent an idle timeout")

	// A zero value means quic-go never arms the timer, so a connection that
	// only pings stays up well past the short timeouts used elsewhere here.
	_, address := startRealH3Listener(t, http.HandlerFunc(defaultH3Handler), 0)
	quicConn := dialRealH3(t, address, 50*time.Millisecond)
	select {
	case <-quicConn.Context().Done():
		t.Fatal("idle_timeout unset must leave the application idle timer disabled")
	case <-time.After(1 * time.Second):
	}
}

// TestH3ConnectionWithNoRequestStreamIsReclaimed is the core resource-gap test.
//
// It completes the QUIC handshake, keeps the connection alive with QUIC PINGs,
// and never opens an HTTP/3 request stream. Only the application-layer idle
// timeout can reclaim such a connection, so its closure proves the timer is
// armed and enforced end to end through the real listener factory.
func TestH3ConnectionWithNoRequestStreamIsReclaimed(t *testing.T) {
	const idleTimeout = 400 * time.Millisecond

	_, address := startRealH3Listener(t, http.HandlerFunc(defaultH3Handler), idleTimeout)

	// KeepAlivePeriod makes the client send PINGs, which is exactly the traffic
	// that must NOT keep the connection alive at the application layer.
	quicConn := dialRealH3(t, address, 50*time.Millisecond)

	select {
	case <-quicConn.Context().Done():
		// Reclaimed. Good.
	case <-time.After(10 * time.Second):
		t.Fatal("an HTTP/3 connection that sends only PINGs and never opens a request " +
			"stream must be closed by the application-layer idle timeout")
	}
}

// TestH3ActiveStreamIsNotKilledByApplicationIdleTimeout proves the fix does not
// break the data path: once a request stream exists the timer is stopped, so a
// slow request that outlives the idle timeout still completes.
//
// This is the regression guard for long-lived CONNECT tunnels, which are the
// only reason this inbound exists.
func TestH3ActiveStreamIsNotKilledByApplicationIdleTimeout(t *testing.T) {
	// A short idle window keeps the test quick; the handler then blocks for many
	// times that window, so the test is not sensitive to scheduling jitter under
	// a loaded parallel test run.
	const idleTimeout = 200 * time.Millisecond
	const handlerDelay = 2 * time.Second

	// The handler deliberately blocks for well over the idle timeout before
	// responding, standing in for a long-lived tunnel.
	handlerDone := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-time.After(handlerDelay):
		case <-request.Context().Done():
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("completed"))
		close(handlerDone)
	})

	_, address := startRealH3Listener(t, handler, idleTimeout)

	// The client keeps its own QUIC transport alive well past the application
	// timeout, so a failure here can only come from the application-layer timer
	// rather than from the client's own transport idle timeout.
	clientTransport := &http3.Transport{
		TLSClientConfig: testClientTLSConfig(),
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  30 * time.Second,
			KeepAlivePeriod: 100 * time.Millisecond,
		},
	}
	defer clientTransport.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	quicConn, err := quic.DialAddrEarly(dialCtx, address, testClientTLSConfig(), &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 100 * time.Millisecond,
	})
	require.NoError(t, err)
	defer quicConn.CloseWithError(0, "")
	clientConn := clientTransport.NewClientConn(quicConn)
	defer clientConn.CloseWithError(0, "")

	status, err := h3RoundTrip(t, clientConn, http.Header{})
	require.NoError(t, err, "an active request must not be killed by the application idle timeout")
	require.Equal(t, http.StatusOK, status)

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never completed")
	}
}

// TestH3IdleTimeoutRestartsAfterLastStreamCloses proves the timer is not simply
// disabled for the lifetime of a connection that has served a request: once the
// last stream closes the countdown restarts, so a connection cannot be parked
// open forever by making one request and then going silent.
func TestH3IdleTimeoutRestartsAfterLastStreamCloses(t *testing.T) {
	const idleTimeout = 400 * time.Millisecond

	_, address := startRealH3Listener(t, http.HandlerFunc(defaultH3Handler), idleTimeout)

	clientTransport := &http3.Transport{
		TLSClientConfig: testClientTLSConfig(),
		QUICConfig:      &quic.Config{},
	}
	defer clientTransport.Close()

	quicConn := dialRealH3(t, address, 50*time.Millisecond)
	clientConn := clientTransport.NewClientConn(quicConn)
	defer clientConn.CloseWithError(0, "")

	// Serve one request. While it is open the timer is stopped.
	status, err := h3RoundTrip(t, clientConn, http.Header{})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// The stream is now closed. PINGs continue but must not hold it open.
	select {
	case <-quicConn.Context().Done():
		// Reclaimed after the last stream closed. Good.
	case <-time.After(10 * time.Second):
		t.Fatal("after the last request stream closes, the application idle timeout must " +
			"reclaim the connection even while the client keeps PINGing")
	}
}

// TestH3IdleTimeoutDoesNotBreakOpenRequestStream guards the tunnel path: a
// connection whose request stream stays open must not be torn down by the idle
// timer, however long it lives.
func TestH3IdleTimeoutDoesNotBreakOpenRequestStream(t *testing.T) {
	const idleTimeout = 300 * time.Millisecond

	// The handler holds the request open until the client goes away, exactly
	// like a live tunnel.
	_, address := startRealH3Listener(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}), idleTimeout)

	clientTransport := &http3.Transport{
		TLSClientConfig: testClientTLSConfig(),
		QUICConfig:      &quic.Config{},
		EnableDatagrams: true,
	}
	defer clientTransport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddr(ctx, address, testClientTLSConfig(), &quic.Config{
		EnableDatagrams: true,
	})
	require.NoError(t, err)
	defer quicConn.CloseWithError(0, "")

	clientConn := clientTransport.NewClientConn(quicConn)
	defer clientConn.CloseWithError(0, "")

	stream, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
		Host:   "example.test",
	})
	require.NoError(t, err)

	// Outlive the idle timeout several times over while the stream stays open.
	select {
	case <-quicConn.Context().Done():
		t.Fatal("a connection with an open request stream must not be reclaimed by the " +
			"application idle timeout")
	case <-time.After(3 * idleTimeout):
	}
}

// ---------------------------------------------------------------------------
// helpers driving the real listener factory
// ---------------------------------------------------------------------------

// defaultH3Handler is the trivial 200 handler most of these tests use.
func defaultH3Handler(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

// startRealH3Listener builds an HTTP/3 listener through the PRODUCTION
// ConfigureHTTP3ListenerFunc with the given application idle timeout, so a
// regression in server_h3.go's IdleTimeout wiring fails these tests.
func startRealH3Listener(t *testing.T, handler http.Handler, idleTimeout time.Duration) (io.Closer, string) {
	t.Helper()
	require.NotNil(t, ConfigureHTTP3ListenerFunc, "the HTTP/3 listener factory must be registered")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Reserve a free UDP port, then release it for the listener to bind.
	probeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	listenPort := probeConn.LocalAddr().(*net.UDPAddr).Port
	probeConn.Close()

	listenAddr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	bindListener := listener.New(listener.Options{
		Context: ctx,
		Logger:  testLogger(),
		Network: []string{"udp"},
		Listen: option.ListenOptions{
			Listen:     &listenAddr,
			ListenPort: uint16(listenPort),
		},
	})

	tlsConfig := testRealServerTLSConfig(t, ctx)
	closer, err := ConfigureHTTP3ListenerFunc(
		ctx,
		testLogger(),
		bindListener,
		handler,
		tlsConfig,
		option.QUICOptions{HTTP2Options: option.HTTP2Options{IdleTimeout: badoption.Duration(idleTimeout)}},
		1<<20,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		if closer != nil {
			_ = closer.Close()
		}
	})

	return closer, net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort))
}

// dialRealH3 completes a QUIC handshake and keeps it alive with PINGs at
// keepAlive, without ever opening a request stream.
func dialRealH3(t *testing.T, address string, keepAlive time.Duration) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddr(ctx, address, testClientTLSConfig(), &quic.Config{
		KeepAlivePeriod: keepAlive,
	})
	require.NoError(t, err)
	t.Cleanup(func() { quicConn.CloseWithError(0, "") })
	return quicConn
}

// testClientTLSConfig trusts the throwaway loopback certificate.
func testClientTLSConfig() *stdTLS.Config {
	return &stdTLS.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}
}

// testRealServerTLSConfig builds the sing-box TLS server config the listener
// factory expects, reusing the throwaway certificate from testServerTLSConfig.
//
// common/tls takes both Certificate and Key as INLINE PEM strings and joins each
// list into one blob (std_server.go). CertificatePath/KeyPath are the file-based
// variants and are deliberately left empty here.
func testRealServerTLSConfig(t *testing.T, ctx context.Context) tls.ServerConfig {
	t.Helper()
	stdConfig := testServerTLSConfig(t)
	certificate := stdConfig.Certificates[0]

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))

	keyBytes, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	require.NoError(t, err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))

	tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
		Context: ctx,
		Logger:  logger.NOP(),
		Options: option.InboundTLSOptions{
			Enabled:     true,
			ServerName:  "example.test",
			Certificate: []string{certPEM},
			Key:         badoption.Listable[string]{keyPEM},
			ALPN:        []string{http3.NextProtoH3},
		},
	})
	require.NoError(t, err)
	return tlsConfig
}
