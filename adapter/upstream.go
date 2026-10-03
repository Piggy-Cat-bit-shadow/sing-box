package adapter

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type (
	ConnectionHandlerFunc       = func(ctx context.Context, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
	PacketConnectionHandlerFunc = func(ctx context.Context, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
)

func NewUpstreamHandler(
	metadata InboundContext,
	connectionHandler ConnectionHandlerFunc,
	packetHandler PacketConnectionHandlerFunc,
) UpstreamHandlerAdapter {
	return &myUpstreamHandlerWrapper{
		metadata:          metadata,
		connectionHandler: connectionHandler,
		packetHandler:     packetHandler,
	}
}

// ApplyUDPConnect records a connection's fixed-destination declaration on the metadata.
//
// # Why it is exported
//
// The declaration is made by the INBOUND tunnel, and it has to be read at the point where the
// original packet connection is still visible - before the router wraps it for caching,
// destination guarding, connection tracking or FakeIP NAT. Those wrappers do not forward the
// type assertion, so a reader placed after them silently stops working. The router performs
// the read, so it needs this helper.
//
// It sets the flag ONLY from an explicit declaration. It deliberately does not infer a fixed
// destination from anything else: an ordinary SOCKS UDP session has a destination on its first
// datagram too, and treating that as "fixed" would pin the session to one address.
func ApplyUDPConnect(metadata *InboundContext, conn N.PacketConn) {
	if conn == nil || metadata == nil {
		return
	}
	marker, isMarker := conn.(UDPConnectPacketConn)
	if !isMarker || !marker.IsUDPConnect() {
		return
	}
	// Only ever set, never clear: an explicit udp_connect rule action may already have set it,
	// and a capability must not be able to turn a user's configuration off.
	metadata.UDPConnect = true
}

var _ UpstreamHandlerAdapter = (*myUpstreamHandlerWrapper)(nil)

type myUpstreamHandlerWrapper struct {
	metadata          InboundContext
	connectionHandler ConnectionHandlerFunc
	packetHandler     PacketConnectionHandlerFunc
}

func (w *myUpstreamHandlerWrapper) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	myMetadata := w.metadata
	if source.IsValid() {
		myMetadata.Source = source
	}
	if destination.IsValid() {
		myMetadata.Destination = destination
	}
	w.connectionHandler(ctx, conn, myMetadata, onClose)
}

func (w *myUpstreamHandlerWrapper) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	myMetadata := w.metadata
	if source.IsValid() {
		myMetadata.Source = source
	}
	if destination.IsValid() {
		myMetadata.Destination = destination
	}
	w.packetHandler(ctx, conn, myMetadata, onClose)
}

var _ UpstreamHandlerAdapter = (*myUpstreamContextHandlerWrapper)(nil)

type myUpstreamContextHandlerWrapper struct {
	connectionHandler ConnectionHandlerFunc
	packetHandler     PacketConnectionHandlerFunc
}

func NewUpstreamContextHandler(
	connectionHandler ConnectionHandlerFunc,
	packetHandler PacketConnectionHandlerFunc,
) UpstreamHandlerAdapter {
	return &myUpstreamContextHandlerWrapper{
		connectionHandler: connectionHandler,
		packetHandler:     packetHandler,
	}
}

func (w *myUpstreamContextHandlerWrapper) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, myMetadata := ExtendContext(ctx)
	if source.IsValid() {
		myMetadata.Source = source
	}
	if destination.IsValid() {
		myMetadata.Destination = destination
	}
	w.connectionHandler(ctx, conn, *myMetadata, onClose)
}

func (w *myUpstreamContextHandlerWrapper) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, myMetadata := ExtendContext(ctx)
	if source.IsValid() {
		myMetadata.Source = source
	}
	if destination.IsValid() {
		myMetadata.Destination = destination
	}
	w.packetHandler(ctx, conn, *myMetadata, onClose)
}

func NewRouteHandler(
	metadata InboundContext,
	router ConnectionRouterEx,
) UpstreamHandlerAdapter {
	return &routeHandlerWrapper{
		metadata: metadata,
		router:   router,
	}
}

var _ UpstreamHandlerAdapter = (*routeHandlerWrapper)(nil)

type routeHandlerWrapper struct {
	metadata InboundContext
	router   ConnectionRouterEx
}

func (r *routeHandlerWrapper) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if source.IsValid() {
		r.metadata.Source = source
	}
	if destination.IsValid() {
		r.metadata.Destination = destination
	}
	r.router.RouteConnectionEx(ctx, conn, r.metadata, onClose)
}

func (r *routeHandlerWrapper) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if source.IsValid() {
		r.metadata.Source = source
	}
	if destination.IsValid() {
		r.metadata.Destination = destination
	}
	ApplyUDPConnect(&r.metadata, conn)
	r.router.RoutePacketConnectionEx(ctx, conn, r.metadata, onClose)
}

func NewRouteContextHandler(
	router ConnectionRouterEx,
) UpstreamHandlerAdapter {
	return &routeContextHandlerWrapper{
		router: router,
	}
}

var _ UpstreamHandlerAdapter = (*routeContextHandlerWrapper)(nil)

type routeContextHandlerWrapper struct {
	router ConnectionRouterEx
}

func (r *routeContextHandlerWrapper) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	r.router.RouteConnectionEx(ctx, conn, *metadata, onClose)
}

func (r *routeContextHandlerWrapper) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	ApplyUDPConnect(metadata, conn)
	r.router.RoutePacketConnectionEx(ctx, conn, *metadata, onClose)
}
