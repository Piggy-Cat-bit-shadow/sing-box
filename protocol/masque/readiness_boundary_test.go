package masque

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"testing"

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

// Tests for the readiness publication itself: `started` must be decided in the same critical section
// that decides whether the endpoint still has an owner.
//
// # The window these pin
//
// close_boundary_h3_test.go pins the HTTP/3 acquisition window, and it left a narrower one open. The
// sequence after that fix was:
//
//	if err = s.publishAcquiredHTTP3(http3Server); err != nil { ... }   // takes startAccess, RELEASES it
//	s.started.Store(true)                                             // OUTSIDE the critical section
//
// and Close published `closed` under that lock and then stored `started = false` outside it. So this
// interleaving was reachable, and it is the one the round asked to be *held open deterministically*
// rather than hunted with -count:
//
//	Start:  publishAcquiredHTTP3 succeeds, lock released
//	Close:  takes the lock, publishes closed = true, releases it
//	Close:  started = false, then releases the listener, the H3 server, the device, the TLS config
//	Start:  started.Store(true)          <- the endpoint is now closed AND advertised as ready
//
// `started` is exactly what WritePackets, DialContext and ListenPacketWithDestination gate the data
// path on, so the endpoint answered those calls as if it were live while the device behind it had been
// released. This file holds that window open with a seam at the boundary, so the outcome is a fact
// rather than a race that may or may not be observed.
//
// # What is NOT claimed here
//
// These tests do not model the QUIC lifecycle: the HTTP/3 listener is the real one, created by the
// production factory. The seam below only decides WHEN the production call that publishes it runs.

// readinessGate wraps the production HTTP/3 listener factory and, on demand, stops the Start side at
// the boundary between "the resource is acquired" and "the endpoint decides its readiness".
//
// The boundary is entered by the caller of Start, not by the factory: the factory is wrapped only so
// that the test knows the acquisition has happened, which is the precondition for the boundary to be
// the interesting one.
type readinessGate struct {
	acquired chan struct{}
	hold     chan struct{}
	release  chan struct{}
}

// installReadinessGate returns a gate that signals `acquired` once the production HTTP/3 listener
// exists. `hold` is read by the test to decide whether to stop the Start side at the boundary, and
// `release` lets it continue.
func installReadinessGate(t *testing.T) *readinessGate {
	t.Helper()
	original := transportHTTP.ConfigureHTTP3ListenerFunc
	require.NotNil(t, original, "this build has no HTTP/3 listener factory; run with the QUIC tags")
	gate := &readinessGate{
		acquired: make(chan struct{}),
		hold:     make(chan struct{}),
		release:  make(chan struct{}),
	}
	transportHTTP.ConfigureHTTP3ListenerFunc = func(ctx context.Context, factoryLogger logger.Logger, bindListener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.QUICOptions, maxHeaderBytes int) (io.Closer, error) {
		closer, err := original(ctx, factoryLogger, bindListener, handler, tlsConfig, options, maxHeaderBytes)
		if err != nil {
			return nil, err
		}
		close(gate.acquired)
		<-gate.hold
		return closer, nil
	}
	t.Cleanup(func() { transportHTTP.ConfigureHTTP3ListenerFunc = original })
	return gate
}

// newReadinessEndpoint builds the endpoint through the production constructor, so the device, the
// listener, the HTTP server, the TLS config and the HTTP/3 server are all production objects.
func newReadinessEndpoint(t *testing.T) *ServerEndpoint {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &stubNetworkManager{})
	certPEM, keyPEM := newLoopbackCertificate(t)
	endpoint, err := NewServerEndpoint(
		ctx,
		nil,
		log.NewNOPFactory().Logger(),
		"masque-readiness-window",
		option.MASQUEServerEndpointOptions{
			MASQUEEndpointOptions: option.MASQUEEndpointOptions{MTU: 1500},
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
	require.True(t, isServerEndpoint)
	t.Cleanup(func() { _ = serverEndpoint.Close() })
	return serverEndpoint
}

// TestStartDoesNotAdvertiseReadinessAfterCloseCompleted holds the exact window open, at the boundary
// the window lives on: the readiness decision has been committed and startAccess has been released,
// and the statement that used to store `started` a second time - outside the lock - would run next.
//
// The seam is testPublishStartedHook, which fires at precisely that point. The test stops the Start
// side there, runs Close from beginning to end, and only then lets Start continue. Nothing here is a
// sleep and nothing is a repetition: the ordering is enforced by the test.
func TestStartDoesNotAdvertiseReadinessAfterCloseCompleted(t *testing.T) {
	gate := installReadinessGate(t)
	endpoint := newReadinessEndpoint(t)

	// The seam: stop the Start side after the readiness decision, before anything else can run.
	boundaryReached := make(chan struct{})
	boundaryRelease := make(chan struct{})
	endpoint.testPublishStartedHook = func() {
		close(boundaryReached)
		<-boundaryRelease
	}

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))

	startDone := make(chan error, 1)
	go func() { startDone <- scope.Start(name, endpoint, adapter.StartStateStart) }()

	// Let the production HTTP/3 listener be created, then stop the Start side at the readiness
	// boundary. Both channels are consumed, so a passing test cannot be passing because the gate or
	// the seam never fired.
	<-gate.acquired
	close(gate.hold)
	<-boundaryReached
	acquiredPort := endpoint.listener.UDPConn().LocalAddr().String()
	require.True(t, endpoint.started.Load(),
		"the premise: the readiness decision has been committed by the time the seam runs")

	// Close runs from beginning to end while the Start side is stopped at the boundary.
	require.NoError(t, scope.Close())
	require.False(t, endpoint.started.Load(), "Close must clear readiness")

	// Now let Start continue past the boundary. Any remaining work on this path runs against a fully
	// released endpoint.
	close(boundaryRelease)
	startErr := <-startDone

	require.False(t, endpoint.started.Load(),
		"the endpoint advertises itself as ready after Close returned: work that runs after the "+
			"readiness decision can resurrect the flag, so a released endpoint answers WritePackets, "+
			"DialContext and ListenPacketWithDestination as if it were live while the device behind it "+
			"has been released")
	require.Error(t, startErr,
		"Start must not report success for an endpoint that was closed while it was starting")

	// And the released resources must really be released. The assertion is on the SOCKET rather than on
	// the field: Close releases what the field points at and does not erase the reference, and after
	// the release the listener reports no TCP socket, so neither nil-check would be the right
	// observable.
	requirePortFree(t, acquiredPort, "the HTTP/3 listener's UDP port is still held")
}

// TestH1H2StartDoesNotAdvertiseReadinessAfterCloseCompleted is the same window for the non-HTTP/3
// path, which takes the other branch of the readiness decision and must reach the same conclusion.
//
// It matters because the H1/H2 endpoint acquires nothing between the ownership re-check and the
// readiness store, so a fix that only covered the HTTP/3 branch would leave this one advertising
// readiness after the endpoint was released.
func TestH1H2StartDoesNotAdvertiseReadinessAfterCloseCompleted(t *testing.T) {
	endpoint := newReadinessEndpoint(t)
	// Version 1 only: no HTTP/3, so `s.http3` is false and Start takes the readiness-only branch.
	endpoint.http3 = false
	endpoint.http3Server = nil
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"

	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))
	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateStart))
	require.True(t, endpoint.started.Load(), "the premise: a normally started H1/H2 endpoint is ready")

	require.NoError(t, scope.Close())
	require.False(t, endpoint.started.Load(), "closing the Scope must clear readiness")

	// The readiness decision refuses a second Start for the same reason it refuses a closed endpoint:
	// the endpoint owns resources whose only release is the spent closeOnce body, so a second start
	// would orphan the first listener.
	secondErr := endpoint.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger()))
	require.Error(t, secondErr, "a second Start must be refused rather than overwrite the first")
	require.False(t, endpoint.started.Load(),
		"a refused second Start must not leave the endpoint advertising itself as ready")
}

// TestConcurrentClosesAgreeAndLeaveTheEndpointNotReady pins the idempotence contract under two
// concurrent Close calls, and that neither of them can leave readiness set.
func TestConcurrentClosesAgreeAndLeaveTheEndpointNotReady(t *testing.T) {
	endpoint := newReadinessEndpoint(t)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"

	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))
	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateStart))
	require.True(t, endpoint.started.Load())

	results := make(chan error, 2)
	for range 2 {
		go func() { results <- endpoint.Close() }()
	}
	first, second := <-results, <-results
	// Both calls must agree: a closer that returned early would report SUCCESS for a teardown that had
	// not finished.
	require.Equal(t, first, second, "two concurrent Close calls must return the same result")
	require.False(t, endpoint.started.Load(), "a closed endpoint must never be ready")
}

// TestRepeatedStartStopLeavesTheEndpointNotReady pins the API contract across a whole start/stop
// cycle: after a successful stop the endpoint is not ready, and a start that is refused does not
// change that.
func TestRepeatedStartStopLeavesTheEndpointNotReady(t *testing.T) {
	endpoint := newReadinessEndpoint(t)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"

	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))
	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateStart))
	require.True(t, endpoint.started.Load())
	releasedPort := endpoint.listener.UDPConn().LocalAddr().String()

	// A second StartStateStart on a live endpoint is refused, and refusing it must not disturb the
	// live state.
	require.Error(t, endpoint.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())))
	require.True(t, endpoint.started.Load(), "a refused restart must not clear a live endpoint's readiness")

	require.NoError(t, scope.Close())
	require.False(t, endpoint.started.Load())
	// The field keeps its pointer: Close releases the listener it holds rather than erasing the
	// reference, so the observable is the socket, not the pointer. Asserting nil here was wrong and
	// was corrected after the diagnostic that showed a released endpoint still holding its (closed)
	// QUIC listener.
	requirePortFree(t, releasedPort, "Close must have released the HTTP/3 listener's UDP socket")

	// After the stop, nothing may resurrect readiness.
	require.Error(t, endpoint.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())))
	require.False(t, endpoint.started.Load())
}
