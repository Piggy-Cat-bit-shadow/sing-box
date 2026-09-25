package tls

import (
	"context"
	stdTLS "crypto/tls"
	"net"
	"testing"
	"time"
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
