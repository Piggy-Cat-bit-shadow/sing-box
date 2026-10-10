package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Tests for the HTTP/3 acquisition window of ServerEndpoint.StartStateStart.
//
// # The window these pin
//
// close_boundary_test.go pins the window for the listening socket: StartStateStart binds it after
// Scope.Close has already drained, and `acquiredStillOwned` makes Start release what it bound itself.
// That check sits AFTER the bind and BEFORE the HTTP/3 listener is acquired:
//
//	err = s.listener.Start()
//	if err != nil { return err }
//	if err = s.acquiredStillOwned(); err != nil { return E.Errors(err, s.listener.Close()) }
//	if s.http3 {
//	    s.http3Server, err = s.httpServer.ListenHTTP3(...)   // <- acquired AFTER the check
//	    if err != nil { return err }
//	}
//	s.started.Store(true)
//
// Close has already run and returned by the time ListenHTTP3 executes - that is the premise the
// close_boundary tests establish - and closeOnce has already consumed `s.http3Server`. So the QUIC
// listener this call creates is published into a field nobody reads again: the release list Close
// computed is final, the Scope's queue was drained before the acquisition, and Box.Close() still only
// closes the Scope. The bound UDP socket survives all three.
//
// # What is NOT claimed here
//
// The acquisition itself is the PRODUCTION factory (transport/http.ConfigureHTTP3ListenerFunc): a real
// UDP socket is bound through the endpoint's real listener, and a real QUIC listener is created. The
// gate below is a seam on WHEN that factory returns, not a model of it. Nothing here asserts anything
// about the QUIC data path.
//
// The endpoint under test is built by the PRODUCTION constructor, NewServerEndpoint, from the same
// option shape a configuration produces - not by assembling the struct by hand.

// http3Gate wraps the production HTTP/3 listener factory so a test can hold Start inside the
// acquisition, between "the resource exists" and "the resource is published".
type http3Gate struct {
	entered chan struct{}
	release chan struct{}
}

// installHTTP3Gate replaces the package-level factory for the duration of the test and restores it on
// cleanup. The gate signals `entered` once the real listener has been built and then waits for
// `release` before handing it back, which is exactly the interval under test.
//
// The gate is installed at most once per process: a test that runs it repeatedly (or a second test in
// the same binary) reinstalls it, and the restore is what keeps a chain of wrappers from building up
// and calling close twice on one gate.
func installHTTP3Gate(t *testing.T) *http3Gate {
	t.Helper()
	original := transportHTTP.ConfigureHTTP3ListenerFunc
	if installedFactory != nil {
		original = installedFactory.original
	}
	require.NotNil(t, original,
		"this build has no HTTP/3 listener factory, so the H3 acquisition window cannot be exercised; "+
			"run with the QUIC build tag (release/DEFAULT_BUILD_TAGS)")
	factory := &gatedHTTP3Factory{
		original: original,
		gate: &http3Gate{
			entered: make(chan struct{}),
			release: make(chan struct{}),
		},
	}
	transportHTTP.ConfigureHTTP3ListenerFunc = factory.listen
	installedFactory = factory
	t.Cleanup(func() { transportHTTP.ConfigureHTTP3ListenerFunc = factory.original })
	return factory.gate
}

// installedFactory is the wrapper currently in the package-level factory slot, so a repeat install can
// unwrap the previous one instead of nesting inside it. Tests in one package share the slot and run
// serially, which is what makes a single package-level variable sufficient.
var installedFactory *gatedHTTP3Factory

// gatedHTTP3Factory is installHTTP3Gate's wrapper. It is held by pointer so a repeat install can
// unwrap the previous one instead of nesting inside it.
type gatedHTTP3Factory struct {
	original func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.QUICOptions, maxHeaderBytes int) (io.Closer, error)
	gate     *http3Gate
}

func (f *gatedHTTP3Factory) listen(ctx context.Context, factoryLogger logger.Logger, bindListener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.QUICOptions, maxHeaderBytes int) (io.Closer, error) {
	closer, err := f.original(ctx, factoryLogger, bindListener, handler, tlsConfig, options, maxHeaderBytes)
	if err != nil {
		return nil, err
	}
	close(f.gate.entered)
	<-f.gate.release
	return closer, nil
}

// newConfiguredHTTP3Endpoint builds the endpoint the way a configuration does: NewServerEndpoint with
// HTTP/3 enabled, TLS configured, and loopback listening addresses. Everything the endpoint then does
// - the device, the listener, the MASQUE server, the HTTP server, the TLS config - is the production
// object.
func newConfiguredHTTP3Endpoint(t *testing.T) *ServerEndpoint {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	// The constructor resolves the interface finder through the service registry, exactly as it does
	// under the daemon; the stub is the one the constructor-level tests already use.
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &stubNetworkManager{})
	certPEM, keyPEM := newLoopbackCertificate(t)
	endpoint, err := NewServerEndpoint(
		ctx,
		nil,
		log.NewNOPFactory().Logger(),
		"masque-h3-window",
		option.MASQUEServerEndpointOptions{
			MASQUEEndpointOptions: option.MASQUEEndpointOptions{
				MTU: 1500,
			},
			ListenOptions: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.AddrFrom4([4]byte{127, 0, 0, 1}))),
				ListenPort: 0,
			},
			Version: badoption.Listable[int]{3},
			Address: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.0.0.0/24")},
			Path:    "/",
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &option.InboundTLSOptions{
					Enabled:     true,
					ServerName:  "example.test",
					Certificate: []string{certPEM},
					Key:         badoption.Listable[string]{keyPEM},
				},
			},
		},
	)
	require.NoError(t, err)
	serverEndpoint, isServerEndpoint := endpoint.(*ServerEndpoint)
	require.True(t, isServerEndpoint, "the production constructor must return the server endpoint")
	require.True(t, serverEndpoint.http3, "the fixture must have HTTP/3 enabled, or the window is not exercised")
	t.Cleanup(func() { _ = serverEndpoint.Close() })
	return serverEndpoint
}

// TestServerEndpointReleasesAnH3ListenerAcquiredWhileClosing is the window, forced deterministically.
//
// The Start goroutine cannot return from ListenHTTP3 until the test lets it, and the test only lets it
// after Close has returned. There is no timing assumption in either direction.
func TestServerEndpointReleasesAnH3ListenerAcquiredWhileClosing(t *testing.T) {
	gate := installHTTP3Gate(t)
	endpoint := newConfiguredHTTP3Endpoint(t)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"

	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))

	startDone := make(chan error, 1)
	go func() { startDone <- scope.Start(name, endpoint, adapter.StartStateStart) }()

	// Start is now inside ListenHTTP3: the QUIC listener exists and its UDP socket is bound.
	<-gate.entered
	acquiredAddress := boundAddressOf(t, endpoint)

	// The drain runs the teardown that StartStateInitialize registered, and returns. The release list
	// was computed here, and the H3 listener did not exist yet.
	require.NoError(t, scope.Close())

	close(gate.release)
	startErr := <-startDone
	require.Error(t, startErr,
		"Start must not report success for an endpoint that was closed while it was starting")

	// The endpoint's own Close must agree, and cannot release the H3 listener either: closeOnce is
	// spent.
	require.NoError(t, endpoint.Close())

	// The rollback releases the listener before publishing it, which is the contract: nothing acquired
	// after Close has an owner, so nothing may be registered for a release that already ran, and the
	// endpoint must not carry a reference to it either.
	require.Nil(t, endpoint.http3Server,
		"Start published the HTTP/3 listener it acquired while Close was draining: that field is read "+
			"exactly once, by the closeOnce body that had already run")

	requirePortFree(t, acquiredAddress,
		"the HTTP/3 listener acquired while Close was draining is still bound: its UDP socket outlives "+
			"the endpoint, the Scope and Box.Close()")

	require.False(t, endpoint.started.Load(),
		"a closed endpoint must never advertise itself as started")
}

// TestServerEndpointH3WindowOnRepeatedInterleavings runs the same decision boundary many times inside
// one process. The gate fixes the order; the repetition is there to catch a release that is correct
// once and wrong on a later race.
func TestServerEndpointH3WindowOnRepeatedInterleavings(t *testing.T) {
	if testing.Short() {
		t.Skip("repeated interleaving")
	}
	for range 20 {
		gate := installHTTP3Gate(t)
		endpoint := newConfiguredHTTP3Endpoint(t)
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"

		require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))
		startDone := make(chan error, 1)
		go func() { startDone <- scope.Start(name, endpoint, adapter.StartStateStart) }()

		<-gate.entered
		acquiredAddress := boundAddressOf(t, endpoint)
		require.NoError(t, scope.Close())
		close(gate.release)
		require.Error(t, <-startDone)
		require.NoError(t, endpoint.Close())

		require.Nil(t, endpoint.http3Server, "iteration left the HTTP/3 listener published")
		requirePortFree(t, acquiredAddress, "iteration left the HTTP/3 listener bound")
		require.False(t, endpoint.started.Load(),
			"a closed endpoint must never advertise itself as started")
	}
}

// boundAddressOf reports the address the endpoint's HTTP/3 listener is bound to, so the release can be
// proven by rebinding it. It is only valid while the gate holds the acquisition open.
func boundAddressOf(t *testing.T, endpoint *ServerEndpoint) string {
	t.Helper()
	require.NotNil(t, endpoint.listener.UDPConn(),
		"the premise of this test: acquiring the HTTP/3 listener bound the endpoint's UDP socket")
	return endpoint.listener.UDPConn().LocalAddr().String()
}

// requirePortFree proves the resource is genuinely released rather than merely dereferenced: the
// listening port must be bindable again.
func requirePortFree(t *testing.T, address string, message string) {
	t.Helper()
	udpAddress, err := net.ResolveUDPAddr("udp", address)
	require.NoError(t, err)
	// The release is asynchronous: the QUIC accept loop closes the socket when it unwinds. Binding in
	// a bounded loop waits for that without assuming how long it takes.
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, listenErr := net.ListenUDP("udp", udpAddress)
		if listenErr == nil {
			require.NoError(t, conn.Close())
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (rebinding %s: %v)", message, address, listenErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// newLoopbackCertificate returns a throwaway loopback certificate and key as inline PEM, which is the
// form option.InboundTLSOptions takes.
func newLoopbackCertificate(t *testing.T) (string, string) {
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
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
}
