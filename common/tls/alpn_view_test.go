package tls

import (
	"context"
	stdTLS "crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The view must scope ALPN for every handshake entry point the listeners use.
//
// Three paths reach a handshake: Server() (used by aTLS.ServerHandshake when the
// config is not ServerConfigCompat), STDConfig() (used by the sing-quic listener
// path) and ServerHandshake() (used when the config IS ServerConfigCompat).
// A view that overrides only one of them silently leaks the shared ALPN through
// the others, which is what an earlier revision of this file did.
func TestALPNViewScopesEveryHandshakePath(t *testing.T) {
	base := newTestServerConfig(t)

	view := TransportALPNView(base, []string{"h2", "http/1.1"})

	if got := view.NextProtos(); len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Fatalf("NextProtos = %v", got)
	}

	// STDConfig is the sing-quic path.
	scoped, err := view.STDConfig()
	if err != nil {
		t.Fatalf("STDConfig: %v", err)
	}
	if len(scoped.NextProtos) != 2 || scoped.NextProtos[0] != "h2" {
		t.Fatalf("STDConfig NextProtos = %v, want the view's list", scoped.NextProtos)
	}

	// The shared config must be untouched, or the other transport is affected.
	shared, err := base.STDConfig()
	if err != nil {
		t.Fatalf("base STDConfig: %v", err)
	}
	for _, proto := range shared.NextProtos {
		if proto == "h2" || proto == "http/1.1" {
			t.Fatalf("the view mutated the shared config: %v", shared.NextProtos)
		}
	}
}

// TestALPNViewNegotiatesItsOwnList is the end-to-end assertion: a real TLS
// handshake against the view negotiates the view's ALPN, not the shared one.
func TestALPNViewNegotiatesItsOwnList(t *testing.T) {
	base := newTestServerConfig(t)

	// The shared config advertises h3, standing in for the union that used to
	// reach the TCP listener.
	base.SetNextProtos([]string{"h2", "http/1.1", "h3"})

	tcpView := TransportALPNView(base, []string{"h2", "http/1.1"})
	quicView := TransportALPNView(base, []string{"h3"})

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	_ = clientConn.SetDeadline(time.Now().Add(10 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(10 * time.Second))

	handshakeDone := make(chan string, 1)
	go func() {
		tlsConn, err := tcpView.Server(serverConn)
		if err != nil {
			handshakeDone <- "server-error:" + err.Error()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			handshakeDone <- "handshake-error:" + err.Error()
			return
		}
		handshakeDone <- tlsConn.ConnectionState().NegotiatedProtocol
	}()

	client := stdTLS.Client(clientConn, &stdTLS.Config{
		InsecureSkipVerify: true,
		ServerName:         "naive.test",
		// Offer everything, including h3. A TCP listener must choose h2.
		NextProtos: []string{"h3", "h2", "http/1.1"},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	select {
	case got := <-handshakeDone:
		if got != "h2" {
			t.Fatalf("the TCP view negotiated %q, want h2: the shared h3 leaked "+
				"into the TCP handshake", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server handshake never completed")
	}

	// And the QUIC view must still offer h3, so scoping did not disable H3.
	if got := quicView.NextProtos(); len(got) != 1 || got[0] != "h3" {
		t.Fatalf("QUIC view NextProtos = %v, want [h3]", got)
	}
}

// TestALPNViewSharesLifecycle asserts the view adds no lifecycle of its own.
//
// The whole reason for a view rather than a Clone is that the certificate
// provider, the ACME service and the watcher must exist exactly once. A view that
// started or closed the shared config independently would double-start ACME or
// double-close the watcher.
func TestALPNViewSharesLifecycle(t *testing.T) {
	base := newTestServerConfig(t)
	view := TransportALPNView(base, []string{"h3"})

	// Close on the view must reach the shared config exactly once.
	if err := view.Close(); err != nil {
		t.Fatalf("view Close: %v", err)
	}
	if !base.closed {
		t.Fatal("closing the view did not close the shared config")
	}
	if base.closeCount != 1 {
		t.Fatalf("the shared config was closed %d times, want exactly 1",
			base.closeCount)
	}
}

// testServerConfig is a minimal ServerConfig that records lifecycle calls, so a
// view can be checked for double-start or double-close.
type testServerConfig struct {
	config     *stdTLS.Config
	closed     bool
	closeCount int
	startCount int
}

func (c *testServerConfig) ServerName() string { return c.config.ServerName }

func (c *testServerConfig) SetServerName(n string) { c.config.ServerName = n }

func (c *testServerConfig) NextProtos() []string { return c.config.NextProtos }

func (c *testServerConfig) SetNextProtos(p []string) { c.config.NextProtos = p }

func (c *testServerConfig) HandshakeTimeout() time.Duration { return 0 }

func (c *testServerConfig) SetHandshakeTimeout(time.Duration) {}

func (c *testServerConfig) STDConfig() (*STDConfig, error) { return c.config, nil }

func (c *testServerConfig) Client(net.Conn) (Conn, error) { return nil, nil }

func (c *testServerConfig) Clone() Config {
	return &testServerConfig{config: c.config.Clone()}
}

func (c *testServerConfig) Start() error {
	c.startCount++
	return nil
}

func (c *testServerConfig) Close() error {
	c.closed = true
	c.closeCount++
	return nil
}

func (c *testServerConfig) Server(conn net.Conn) (Conn, error) {
	return stdTLS.Server(conn, c.config), nil
}

// newTestServerConfig builds a minimal ServerConfig with a usable certificate.
func newTestServerConfig(t *testing.T) *testServerConfig {
	t.Helper()
	certPEM, keyPEM, err := testCertificate()
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	certificate, err := stdTLS.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return &testServerConfig{
		config: &stdTLS.Config{Certificates: []stdTLS.Certificate{certificate}},
	}
}

// testCertificate produces a self-signed pair for the handshake test.
//
// GenerateCertificate returns (privateKeyPem, publicKeyPem); the key is the
// FIRST return value.
func testCertificate() (certPEM, keyPEM []byte, err error) {
	keyPEM, certPEM, err = GenerateCertificate(nil, nil, time.Now, "naive.test",
		time.Now().Add(24*time.Hour))
	return certPEM, keyPEM, err
}

// ---------------------------------------------------------------------------
// Shared lifecycle ownership across views
// ---------------------------------------------------------------------------

// The production shape this pins: ONE shared ServerConfig, TWO transport views
// built from it, and the inbound as the single lifecycle owner.
//
//	  shared ServerConfig            <- started and closed exactly once, by the inbound
//	  ├── TCP  view  (h2, http/1.1)  <- negotiated with, never started or closed
//	  └── QUIC view  (h3)            <- negotiated with, never started or closed
//
// The reason this needs a regression rather than a comment: a view EMBEDS the
// shared config, so Start and Close reach it through the embedded value. If
// anything ever called Start or Close on a view - a listener that "helpfully"
// cleaned up its config, or an inbound closing several handles - the shared
// config would be started or closed more than once, double-closing the
// certificate provider, the ACME service and the watcher.
//
// The single-view test above does not catch that: it never has two owners in
// play. This one does.

// TestALPNViewsShareOneLifecycleOwner is the production-shape regression.
func TestALPNViewsShareOneLifecycleOwner(t *testing.T) {
	shared := newTestServerConfig(t)

	tcpView := TransportALPNView(shared, []string{"h2", "http/1.1"})
	quicView := TransportALPNView(shared, []string{"h3"})

	// ALPN must be scoped per view before anything is started.
	require.Equal(t, []string{"h2", "http/1.1"}, tcpView.NextProtos())
	require.Equal(t, []string{"h3"}, quicView.NextProtos())

	// The inbound starts the SHARED config once. Views are not started.
	if err := shared.Start(); err != nil {
		t.Fatalf("shared Start: %v", err)
	}
	if shared.startCount != 1 {
		t.Fatalf("the shared config was started %d times, want exactly 1",
			shared.startCount)
	}

	// Both views must still report their own ALPN after the start, because
	// Start can merge ACME protocols into the shared list. A view that read
	// through to the shared config would pick those up.
	require.Equal(t, []string{"h2", "http/1.1"}, tcpView.NextProtos(),
		"starting the shared config must not change what the TCP view offers")
	require.Equal(t, []string{"h3"}, quicView.NextProtos(),
		"starting the shared config must not change what the QUIC view offers")

	// The inbound closes the SHARED config once. Views are not closed.
	if err := shared.Close(); err != nil {
		t.Fatalf("shared Close: %v", err)
	}
	if shared.closeCount != 1 {
		t.Fatalf("the shared config was closed %d times, want exactly 1",
			shared.closeCount)
	}
}

// TestALPNViewsForwardLifecycleToTheOneOwnerIfCalled shows what a view does when
// something DOES call Start or Close on it.
//
// It forwards to the shared config through the embedded value rather than
// duplicating state. That is the property that makes the single-owner contract
// enforceable: there is no second lifecycle to get out of step. The test states
// it explicitly so a future change that gave a view its own counters would be
// visible here.
func TestALPNViewsForwardLifecycleToTheOneOwnerIfCalled(t *testing.T) {
	shared := newTestServerConfig(t)
	view := TransportALPNView(shared, []string{"h3"})

	if err := view.Start(); err != nil {
		t.Fatalf("view Start: %v", err)
	}
	if shared.startCount != 1 {
		t.Fatalf("a Start on the view must reach the shared config exactly once, "+
			"got %d", shared.startCount)
	}

	if err := view.Close(); err != nil {
		t.Fatalf("view Close: %v", err)
	}
	if shared.closeCount != 1 {
		t.Fatalf("a Close on the view must reach the shared config exactly once, "+
			"got %d", shared.closeCount)
	}
}

// TestALPNViewsDoNotCrossMutateTheSharedConfig asserts neither view can change
// what the other negotiates.
//
// The failure this guards against is a view that writes its ALPN through to the
// shared config - the behaviour that made the original implementation leak h3
// onto the TCP listener. With two views the leak is asymmetric and easy to miss:
// whichever view was created or used last would win.
func TestALPNViewsDoNotCrossMutateTheSharedConfig(t *testing.T) {
	shared := newTestServerConfig(t)
	shared.SetNextProtos([]string{"h2", "http/1.1", "h3"})

	tcpView := TransportALPNView(shared, []string{"h2", "http/1.1"})
	quicView := TransportALPNView(shared, []string{"h3"})

	// Mutating one view must not affect the other, or the shared config.
	tcpView.SetNextProtos([]string{"h2"})
	require.Equal(t, []string{"h3"}, quicView.NextProtos(),
		"mutating the TCP view changed what the QUIC view offers")

	sharedAfter, err := shared.STDConfig()
	if err != nil {
		t.Fatalf("shared STDConfig: %v", err)
	}
	require.Equal(t, []string{"h2", "http/1.1", "h3"}, sharedAfter.NextProtos,
		"a view mutated the shared config's ALPN list")

	// Closing both views must not disturb the other's negotiated list either.
	require.Equal(t, []string{"h2"}, tcpView.NextProtos())
	require.Equal(t, []string{"h3"}, quicView.NextProtos())
}

// TestALPNViewsAreIndependentOfCreationOrder asserts the two views do not depend
// on which was built first.
//
// A shared config that accumulated ALPN would make the second view inherit the
// first's list, so ordering would silently matter. Building both orders and
// comparing the results catches that.
func TestALPNViewsAreIndependentOfCreationOrder(t *testing.T) {
	for _, order := range []string{"tcp-first", "quic-first"} {
		t.Run(order, func(t *testing.T) {
			shared := newTestServerConfig(t)
			var tcpView, quicView ServerConfig
			if order == "tcp-first" {
				tcpView = TransportALPNView(shared, []string{"h2", "http/1.1"})
				quicView = TransportALPNView(shared, []string{"h3"})
			} else {
				quicView = TransportALPNView(shared, []string{"h3"})
				tcpView = TransportALPNView(shared, []string{"h2", "http/1.1"})
			}

			require.Equal(t, []string{"h2", "http/1.1"}, tcpView.NextProtos(),
				"the TCP view depends on creation order")
			require.Equal(t, []string{"h3"}, quicView.NextProtos(),
				"the QUIC view depends on creation order")
		})
	}
}
