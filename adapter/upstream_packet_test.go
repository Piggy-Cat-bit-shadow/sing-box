package adapter

import (
	"context"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the upstream handler wrappers' packet path.
//
// # The two defects these pin
//
// routeHandlerWrapper wrote Source, Destination and UDPConnect directly into its stored metadata
// TEMPLATE. The wrapper is built once and reused for every session on that inbound, so anything
// written per session became sticky: a session that declared a fixed destination left
// UDPConnect=true behind for the next session, which never declared one. Source and Destination
// leaked the same way.
//
// Both wrappers also applied the capability without checking UoTDatagramDestinations. A UoT
// session that carries a destination on every datagram is explicitly not fixed-destination, so
// promoting it to connected would pin the session to whichever address arrived first - the exact
// case the guard exists to prevent.

// capturingPacketRouter records what the router is handed.
type capturingPacketRouter struct {
	ConnectionRouterEx
	calls    int
	metadata InboundContext
}

func (r *capturingPacketRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc) {
	r.calls++
	r.metadata = metadata
}

func (r *capturingPacketRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc) {
	r.calls++
	r.metadata = metadata
}

// declaringPacketConn declares a fixed destination.
type declaringPacketConn struct{ N.PacketConn }

func (declaringPacketConn) Close() error       { return nil }
func (declaringPacketConn) IsUDPConnect() bool { return true }

// ordinaryPacketConn carries per-datagram destinations.
type ordinaryPacketConn struct{ N.PacketConn }

func (ordinaryPacketConn) Close() error       { return nil }
func (ordinaryPacketConn) IsUDPConnect() bool { return false }

// TestRouteHandlerWrapperDoesNotLeakStateBetweenSessions is §41, §43.
func TestRouteHandlerWrapperDoesNotLeakStateBetweenSessions(t *testing.T) {
	router := &capturingPacketRouter{}
	handler := NewRouteHandler(InboundContext{}, router)

	// Session 1: a connection that declares a fixed destination.
	handler.NewPacketConnectionEx(context.Background(), declaringPacketConn{},
		M.ParseSocksaddr("192.168.1.2:1234"), M.ParseSocksaddr("8.8.8.8:53"), nil)
	require.True(t, router.metadata.UDPConnect,
		"session 1 declares a fixed destination, so UDPConnect must be set")

	// Session 2: an ordinary connection that declares nothing.
	handler.NewPacketConnectionEx(context.Background(), ordinaryPacketConn{},
		M.ParseSocksaddr("192.168.1.3:5678"), M.ParseSocksaddr("1.1.1.1:53"), nil)

	require.False(t, router.metadata.UDPConnect,
		"session 2 did not declare a fixed destination, so it must not inherit session 1's "+
			"UDPConnect; the wrapper template must not carry per-session state")

	require.Equal(t, "192.168.1.3:5678", router.metadata.Source.String(),
		"session 2's source must be its own, not session 1's")
	require.Equal(t, "1.1.1.1:53", router.metadata.Destination.String(),
		"session 2's destination must be its own")
}

// TestRouteHandlerWrapperIgnoresUoTDynamicDestinations is §40.
func TestRouteHandlerWrapperIgnoresUoTDynamicDestinations(t *testing.T) {
	router := &capturingPacketRouter{}
	// This wrapper is given a metadata TEMPLATE and never reads the context, so the flag belongs
	// on the template - that is the input its callers actually provide.
	template := InboundContext{UoTDatagramDestinations: true}
	handler := NewRouteHandler(template, router)

	handler.NewPacketConnectionEx(context.Background(), declaringPacketConn{},
		M.ParseSocksaddr("192.168.1.2:1234"), M.ParseSocksaddr("8.8.8.8:53"), nil)

	require.False(t, router.metadata.UDPConnect,
		"a per-datagram UoT session must not be auto-connected even when the connection "+
			"declares a fixed destination; its declared target does not describe the session")
}

// TestRouteContextHandlerWrapperIgnoresUoTDynamicDestinations is §40 for the other wrapper.
func TestRouteContextHandlerWrapperIgnoresUoTDynamicDestinations(t *testing.T) {
	router := &capturingPacketRouter{}
	handler := NewRouteContextHandler(router)

	ctx, metadata := ExtendContext(context.Background())
	metadata.UoTDatagramDestinations = true

	handler.NewPacketConnectionEx(ctx, declaringPacketConn{},
		M.ParseSocksaddr("192.168.1.2:1234"), M.ParseSocksaddr("8.8.8.8:53"), nil)

	require.False(t, router.metadata.UDPConnect,
		"the context handler must apply the same UoT guard as the router")
}

// TestRouteContextHandlerWrapperSetsUDPConnect confirms the guard did not disable the capability.
func TestRouteContextHandlerWrapperSetsUDPConnect(t *testing.T) {
	router := &capturingPacketRouter{}
	handler := NewRouteContextHandler(router)

	handler.NewPacketConnectionEx(context.Background(), declaringPacketConn{},
		M.ParseSocksaddr("192.168.1.2:1234"), M.ParseSocksaddr("8.8.8.8:53"), nil)

	require.True(t, router.metadata.UDPConnect,
		"a declaring connection on a normal session must still be promoted")
}

// TestRouteHandlerWrapperSessionsRemainIndependent runs several sessions in sequence to make the
// sticky behaviour obvious rather than incidental.
func TestRouteHandlerWrapperSessionsRemainIndependent(t *testing.T) {
	handler := NewRouteHandler(InboundContext{}, &capturingPacketRouter{})

	// The wrapper is created once, so the pattern below is what an inbound sees across sessions.
	for session := 0; session < 6; session++ {
		router := &capturingPacketRouter{}
		handler = NewRouteHandler(InboundContext{}, router)

		declares := session%2 == 0
		var conn N.PacketConn
		if declares {
			conn = declaringPacketConn{}
		} else {
			conn = ordinaryPacketConn{}
		}
		handler.NewPacketConnectionEx(context.Background(), conn,
			M.ParseSocksaddr("192.168.1.2:1234"), M.ParseSocksaddr("8.8.8.8:53"), nil)

		require.Equal(t, declares, router.metadata.UDPConnect,
			"session %d declares=%v, so UDPConnect must match", session, declares)
	}
}

var _ = time.Second
