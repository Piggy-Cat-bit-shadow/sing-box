package http

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A CONNECT-UDP tunnel must automatically take the connected-UDP path.
//
// # Why this is a data-path change, not a flag
//
// RFC 9298 binds one tunnel to one target host:port, so every datagram on the
// connection goes to the same peer. sing-box already had a connected-UDP fast path in
// route/conn.go behind metadata.UDPConnect, which:
//
//	DialContext("udp", fixed target)          instead of  ListenPacket(...)
//	bufio.NewUnbindPacketConn(connected)      instead of  the unconnected wrapper
//
// but reaching it required the operator to write an explicit route rule with
// `udp_connect: true`. A CONNECT-UDP tunnel therefore ran the SLOW path by default:
// an unconnected socket, a per-packet destination on the write, and no connected-
// socket batch capability downstream.
//
// # What is asserted
//
// The protocol layer declares the fixed destination and the router opts in on that
// declaration alone. The declaration is a marker INTERFACE rather than an inference,
// because the connection's shape cannot express it: a SOCKS/mixed UDP association is
// also an N.PacketConn and carries a destination per packet, so inferring "fixed"
// from anything observable about the socket would capture associations that
// legitimately retarget.
//
// So these tests assert three separate things:
//
//	a CONNECT-UDP conn sets metadata.UDPConnect
//	a non-marking packet conn does NOT, so ordinary UDP is untouched
//	the marker only reports true when the destination really is fixed

// markingPacketConn is a packet connection that declares a fixed destination.
type markingPacketConn struct {
	N.PacketConn
	marker bool
}

func (c *markingPacketConn) IsUDPConnect() bool { return c.marker }

// plainPacketConn is a packet connection that carries a per-packet destination, like
// a SOCKS/mixed UDP association. It deliberately does NOT implement the marker.
type plainPacketConn struct {
	N.PacketConn
}

// metadataCapturingRouter records the metadata the router is handed.
type metadataCapturingRouter struct {
	metadata adapter.InboundContext
	called   bool
}

func (r *metadataCapturingRouter) RouteConnection(context.Context, net.Conn, adapter.InboundContext) error {
	return nil
}

func (r *metadataCapturingRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	return nil
}

func (r *metadataCapturingRouter) RouteConnectionEx(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) {
}

func (r *metadataCapturingRouter) RoutePacketConnectionEx(_ context.Context, _ N.PacketConn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.metadata = metadata
	r.called = true
}

// TestConnectUDPDeclaresItselfForTheConnectedPath is the primary assertion.
//
// The capsuleConn built for an RFC 9298 CONNECT-UDP request must take the connected
// path without any route rule.
func TestConnectUDPDeclaresItselfForTheConnectedPath(t *testing.T) {
	conn := newCapsuleConn(nil, &discardConn{}, M.ParseSocksaddr("192.0.2.1:443"))

	require.Implements(t, (*adapter.UDPConnectPacketConn)(nil), conn,
		"the CONNECT-UDP capsule connection must declare a fixed destination, or the "+
			"connected-UDP fast path is unreachable without an operator opt-in")

	var marker adapter.UDPConnectPacketConn = conn
	require.True(t, marker.IsUDPConnect(),
		"a CONNECT-UDP tunnel always has a fixed destination")

	// And the router must turn that declaration into metadata.UDPConnect.
	metadata := adapter.InboundContext{}
	require.False(t, metadata.UDPConnect, "precondition: the flag starts unset")
	capturePacketMetadata(t, conn, &metadata)
	require.True(t, metadata.UDPConnect,
		"the router must set UDPConnect for a declaring connection; without this the "+
			"fast path stays unreachable even though the protocol layer declared it")
}

// TestHTTP3ConnectUDPDeclaresItselfForTheConnectedPath is the H3 half.
//
// http3PacketConn is a DIFFERENT type on a different code path from capsuleConn, and
// it is the one that serves the production VPS, so it needs its own assertion.
func TestHTTP3ConnectUDPDeclaresItselfForTheConnectedPath(t *testing.T) {
	conn := &http3PacketConn{destination: M.ParseSocksaddr("192.0.2.1:443")}

	require.Implements(t, (*adapter.UDPConnectPacketConn)(nil), conn,
		"the H3 CONNECT-UDP packet connection must declare a fixed destination")

	var marker adapter.UDPConnectPacketConn = conn
	require.True(t, marker.IsUDPConnect())

	metadata := adapter.InboundContext{}
	capturePacketMetadata(t, conn, &metadata)
	require.True(t, metadata.UDPConnect,
		"the H3 CONNECT-UDP path must reach the connected-UDP fast path")
}

// TestPlainPacketConnDoesNotSelectUDPConnect is the negative control, and it is the
// assertion that keeps the change narrow.
//
// A connection that does NOT declare a fixed destination must be untouched: it keeps
// the unconnected socket and the per-packet destination. If this ever passed, the
// change would have widened to every UDP proxy path, which breaks associations that
// legitimately send to several destinations over one socket.
func TestPlainPacketConnDoesNotSelectUDPConnect(t *testing.T) {
	conn := &plainPacketConn{}

	_, isMarker := any(conn).(adapter.UDPConnectPacketConn)
	require.False(t, isMarker,
		"precondition: this fixture must not implement the marker, or it cannot show "+
			"that a non-declaring connection is left alone")

	metadata := adapter.InboundContext{}
	capturePacketMetadata(t, conn, &metadata)
	require.False(t, metadata.UDPConnect,
		"a packet connection that does not declare a fixed destination must NOT take "+
			"the connected path: it carries a destination per packet")
}

// TestMarkerReportsFalseWhenTheDestinationIsNotFixed proves the marker is a real
// report rather than a type assertion that always answers true.
//
// A connection can implement the interface and still answer false, which is the shape
// a future multi-destination tunnel would use. That path must not select connected
// UDP either.
func TestMarkerReportsFalseWhenTheDestinationIsNotFixed(t *testing.T) {
	conn := &markingPacketConn{marker: false}

	var marker adapter.UDPConnectPacketConn = conn
	require.False(t, marker.IsUDPConnect())

	metadata := adapter.InboundContext{}
	capturePacketMetadata(t, conn, &metadata)
	require.False(t, metadata.UDPConnect,
		"a marking connection that reports false must not take the connected path; the "+
			"flag must follow the REPORT, not the interface")
}

// TestUDPConnectFlagSurvivesAnExistingMetadataValue is the composition check.
//
// The router wrapper fills the flag on metadata that may already carry a value from
// the inbound context. A tunnel declaration must win, because it is a property of the
// connection rather than of the listener.
func TestUDPConnectFlagSurvivesAnExistingMetadataValue(t *testing.T) {
	conn := newCapsuleConn(nil, &discardConn{}, M.ParseSocksaddr("192.0.2.1:443"))

	metadata := adapter.InboundContext{UDPConnect: false}
	capturePacketMetadata(t, conn, &metadata)
	require.True(t, metadata.UDPConnect,
		"the connection's own declaration must set the flag")
}

// capturePacketMetadata runs conn through the real route handler wrapper and records
// the metadata the router receives.
//
// It uses the production wrapper rather than copying its logic, so a change to how the
// wrapper builds metadata is caught here instead of being mirrored by the test.
func capturePacketMetadata(t *testing.T, conn N.PacketConn, metadata *adapter.InboundContext) {
	t.Helper()

	router := &metadataCapturingRouter{}
	handler := adapter.NewRouteContextHandler(router)

	ctx := adapter.WithContext(context.Background(), metadata)
	handler.NewPacketConnectionEx(ctx, conn, M.ParseSocksaddr("203.0.113.9:1234"),
		M.ParseSocksaddr("192.0.2.1:443"), nil)

	require.True(t, router.called,
		"the wrapper must reach the router; otherwise this helper proves nothing")
	*metadata = router.metadata
}

// discardConn is a net.Conn whose writes are discarded, so a capsuleConn can be built
// without a real socket.
type discardConn struct{}

func (c *discardConn) Read([]byte) (int, error)         { return 0, nil }
func (c *discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *discardConn) Close() error                     { return nil }
func (c *discardConn) LocalAddr() net.Addr              { return nil }
func (c *discardConn) RemoteAddr() net.Addr             { return nil }
func (c *discardConn) SetDeadline(time.Time) error      { return nil }
func (c *discardConn) SetReadDeadline(time.Time) error  { return nil }
func (c *discardConn) SetWriteDeadline(time.Time) error { return nil }
