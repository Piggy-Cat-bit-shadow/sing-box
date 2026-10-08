package socks

import (
	std_bufio "bufio"
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SocksInboundOptions](registry, C.TypeSOCKS, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router        adapter.ConnectionRouterEx
	logger        logger.ContextLogger
	listener      *listener.Listener
	authenticator *auth.Authenticator
	udpTimeout    time.Duration
	// hasUsers is `authenticator != nil`, resolved once at construction.
	//
	// It is what keeps a SOCKS4 USERID from becoming an identity. sing's SOCKS4
	// handshake puts the request's IDENT claim into the context unconditionally
	// (protocol/socks/handshake.go) and only verifies it when an authenticator was
	// configured, so the context alone cannot distinguish "verified user" from
	// "whatever the client typed". With no users configured there is nothing to
	// verify against, and the claim must stay protocol input: it must not reach
	// metadata.User, route rules that match on `user`, or the connection log.
	hasUsers bool
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SocksInboundOptions) (adapter.Inbound, error) {
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	authenticator := auth.NewAuthenticator(options.Users)
	inbound := &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeSOCKS, tag),
		router:        uot.NewRouter(router, logger),
		logger:        logger,
		authenticator: authenticator,
		hasUsers:      authenticator != nil,
		udpTimeout:    udpTimeout,
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := h.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	// A zero-length SOCKS5 domain would shift the stream by two bytes instead of
	// failing cleanly; see GuardSOCKS5Address. It is installed BEFORE the reader:
	// the parser reads through a buffered reader, so a guard placed after it
	// would only see bytes the buffer did not already hold, which is usually
	// none of them.
	// The guard goes before the reader; see GuardSOCKS5Address for why the
	// placement is the whole reason it works.
	conn = GuardSOCKS5Address(conn)
	// One reader for the whole connection, shared with the wrapper: the handshake
	// parses through it, and the bytes it holds beyond the handshake belong to
	// the tunnel. Handing the bare connection to socks strands those bytes and
	// silently truncates the tunnel -- which is what this inbound used to do, and
	// what mixed already fixed. See FirstPayloadConn.
	reader := std_bufio.NewReader(conn)
	handshakeConn := NewFirstPayloadConn(conn, reader)
	err := socks.HandleConnectionEx(ctx, handshakeConn, reader, h.authenticator, adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.streamUserPacketConnection), h.listener, h.udpTimeout, metadata.Source, onClose)
	if err != nil {
		// Only a FAILED handshake is reported through onClose here.
		// N.CloseOnHandshakeFailure invokes the handler even for a nil error, so
		// calling it unconditionally reports a live session as closed the moment
		// the handshake succeeds: the caller's handler is the flow's close
		// notification (a TUN flow, or the outer flow of an inbound_detour
		// chain), and its owner releases the flow on the first call. A
		// successful handshake transfers ownership of the connection to the
		// handler and ends with no notification at all.
		N.CloseOnHandshakeFailure(handshakeConn, onClose, err)
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := h.lookupUser(ctx)
	if !loaded {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) streamUserPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	user, loaded := h.lookupUser(ctx)
	if !loaded {
		if !metadata.Destination.IsValid() {
			h.logger.InfoContext(ctx, "inbound packet connection")
		} else {
			h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
		}
		h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	if !metadata.Destination.IsValid() {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection")
	} else {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// lookupUser resolves the authenticated user for a session.
//
// The no-users case is answered from immutable construction-time state, so a
// SOCKS4 IDENT claim cannot become an identity by arriving when no credential
// table exists to check it against. The users-configured case keeps the exact
// previous semantics: the handshake verified the SOCKS4 user id (or the SOCKS5
// username/password pair) before it recorded the user in the context, and a
// session that reached here without one came through a path that did not
// authenticate.
func (h *Inbound) lookupUser(ctx context.Context) (string, bool) {
	if !h.hasUsers {
		return "", false
	}
	return auth.UserFromContext[string](ctx)
}
