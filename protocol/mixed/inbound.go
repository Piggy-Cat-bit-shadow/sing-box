package mixed

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	socksinbound "github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.HTTPMixedInboundOptions](registry, C.TypeMixed, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router     adapter.ConnectionRouterEx
	logger     log.ContextLogger
	listener   *listener.Listener
	server     *http.Server
	tlsConfig  tls.ServerConfig
	udpTimeout time.Duration
	// authenticator is the SOCKS4/SOCKS5 credential table, or nil when no users
	// are configured.
	//
	// The nil is deliberate and load-bearing: sing's socks handshake treats a nil
	// authenticator as "no authentication configured" and replies
	// AuthTypeNotRequired. Passing a non-nil-but-empty authenticator instead makes
	// the SOCKS5 server demand the username/password sub-negotiation and reject
	// every client that does not offer it -- which is what an earlier revision of
	// this file did, so a mixed inbound with no `users` could not be used over
	// SOCKS5 at all.
	authenticator *auth.Authenticator
	// hasUsers is the same fact as `authenticator != nil`, resolved once at
	// construction so the per-connection logging path does not have to call
	// auth.UserFromContext at all when there is nothing to look up.
	hasUsers bool
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPMixedInboundOptions) (adapter.Inbound, error) {
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	authenticator := auth.NewAuthenticator(options.Users)
	inbound := &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeMixed, tag),
		router:        uot.NewRouter(router, logger),
		logger:        logger,
		authenticator: authenticator,
		hasUsers:      authenticator != nil,
		udpTimeout:    udpTimeout,
	}
	inbound.server = http.NewServer(http.ServerOptions{
		Authenticator: authenticator,
		Logger:        logger,
		HTTP1:         true,
		HTTP2:         true,
		UDP:           true,
	})
	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context:        ctx,
			Logger:         logger,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: true,
		})
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
		SetSystemProxy:    options.SetSystemProxy,
		SystemProxySOCKS:  true,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(h.tlsConfig.Close)
	}
	err := h.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	// A zero-length SOCKS5 domain would shift the stream by two bytes instead of
	// failing cleanly; see GuardSOCKS5Address.
	//
	// The guard is installed BEFORE the reader, and that placement is the whole
	// reason it works. The parser reads through a buffered reader of its own, and
	// SOCKS5 negotiation is a round trip, so a guard placed on the connection
	// after that reader only ever sees the bytes the buffer did not already hold
	// -- which for the request is usually all of them. On the connection, before
	// anything buffers, it sees every byte as it comes off the socket.
	//
	// It disables itself on the first byte of anything that is not SOCKS5, so an
	// HTTP connection pays one comparison and the guard object.
	conn = socksinbound.GuardSOCKS5Address(conn)
	// One reader for the whole connection. Every parser below reads through it.
	reader := http.NewReader(conn)
	headerBytes, err := reader.Peek(1)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": peek first byte"))
		}
		return
	}
	handler := adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.streamUserPacketConnection)
	switch headerBytes[0] {
	case socks4.Version, socks5.Version:
		// The SOCKS handshake reads through `reader`, so tunnel payload that
		// arrived in the same segment as the handshake is sitting in the reader's
		// buffer, not in `conn`. Handing the bare `conn` to socks strands those
		// bytes and truncates the tunnel, which is what the earlier revision of
		// this file did.
		//
		// The buffered bytes can only be moved AFTER the handshake has consumed
		// what it owns: Peek does not consume, so moving the buffer beforehand
		// would move the handshake itself and the parser would then read EOF.
		// earlyDataConn is therefore a transparent pass-through until the routing
		// layer first reads from it, which is after the handshake has returned.
		//
		// It is ALWAYS built, never conditionally. `reader.Buffered() > 1` is not
		// evidence of early data: with a one-byte boundary the buffer holds only
		// the version byte while the payload is still in the socket, so a
		// conditional wrapper would lose exactly the case it was meant to skip.
		handshakeConn := net.Conn(newEarlyDataConn(conn, reader))
		// HandleConnectionEx owns `conn` and `onClose` once the hand-off succeeds,
		// which it reports by returning nil. A nil return is NOT a handshake
		// failure: treating it as one would close a live tunnel and invoke
		// onClose a second time, which the callers wrap in sync.Once and which the
		// connection manager reads as "this flow ended" while it is still running.
		err = socks.HandleConnectionEx(ctx, handshakeConn, reader.Reader, h.authenticator, handler, h.listener, h.udpTimeout, metadata.Source, onClose)
		if err != nil {
			N.CloseOnHandshakeFailure(handshakeConn, onClose, err)
			if E.IsClosedOrCanceled(err) {
				h.logger.DebugContext(ctx, "connection closed: ", err)
			} else {
				h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
			}
		}
	default:
		h.server.ServeConnection(ctx, conn, reader, handler, metadata.Source, onClose)
	}
}

// earlyDataConn carries tunnel payload that the protocol discriminator and the
// handshake pre-read into the parser's buffer.
//
// # The problem it solves
//
// A proxy client may write its first payload byte in the same segment as the
// handshake -- a SOCKS client that forwards optimistically does exactly that, and
// so does a browser, whose CONNECT request and TLS ClientHello arrive together.
// The handshake reads through a bufio.Reader, so one Read from the socket can
// pull in bytes that belong to the TUNNEL. Those bytes live in the reader, and
// the socks handshake wraps whatever connection it was given. Passing the bare
// connection therefore hands the routing layer a stream that is missing its
// first bytes.
//
// # Why the move is deferred to first use
//
// The bytes cannot be moved before the handshake runs: the version byte and the
// rest of the handshake are in that same buffer, and moving it early makes the
// parser read EOF. They cannot be moved after it either, because by then socks
// has already wrapped the connection it will forward.
//
// So this wrapper is what the handshake is given, and it forwards to the raw
// connection until the routing layer first uses it. That first use is after the
// handshake has consumed everything it owns, so the buffer at that moment holds
// payload and nothing else. The handshake itself never reads through this
// wrapper -- it reads through the parser's reader -- so deferring costs no
// correctness.
//
// # Cost when there is no early data
//
// Every method forwards straight to the embedded connection, so the routing
// layer receives a connection that still reports every real capability it has:
// syscall.Conn, io.ReaderFrom, io.WriterTo and CloseRead/CloseWrite all answer
// for the true underlying socket. The only addition is one branch per call on a
// wrapper that socks already wraps anyway.
type earlyDataConn struct {
	net.Conn
	// reader is the parser's reader, captured at construction. It is only
	// consulted on first use -- which is after the handshake -- so by then its
	// buffer holds tunnel payload and nothing else.
	reader *http.Reader
	// delegate is non-nil once buffered payload has been installed.
	delegate net.Conn
	// resolved records that the reader has been consulted once.
	resolved bool
}

func newEarlyDataConn(conn net.Conn, reader *http.Reader) *earlyDataConn {
	return &earlyDataConn{Conn: conn, reader: reader}
}

// use resolves the delegate once. It must be called before delegating any call,
// so that capability probes and data reads agree on what is serving them.
//
// It is first called after the handshake has consumed its own bytes, which is
// why nothing has to be moved earlier: Peek does not consume, so moving the
// buffer before the handshake would move the handshake itself.
func (c *earlyDataConn) use() net.Conn {
	if !c.resolved {
		c.resolved = true
		if c.reader != nil {
			c.delegate = c.reader.BufferedConn(c.Conn)
		}
	}
	if c.delegate != nil {
		return c.delegate
	}
	return c.Conn
}

func (c *earlyDataConn) Read(p []byte) (int, error) {
	return c.use().Read(p)
}

// Write deliberately does NOT resolve the delegate.
//
// The handshake writes its reply before it has read the request, so at that
// moment the parser's buffer still holds handshake bytes that the parser has not
// consumed yet. Resolving there would move those bytes onto the connection and
// the parser would then read them twice. Writes do not need the buffered payload
// -- it is inbound data -- so the resolution is confined to the read side, which
// the handshake never touches.
func (c *earlyDataConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p)
}

func (c *earlyDataConn) ReadFrom(r io.Reader) (int64, error) {
	if readerFrom, isReaderFrom := c.use().(io.ReaderFrom); isReaderFrom {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{c.use()}, r)
}

func (c *earlyDataConn) WriteTo(w io.Writer) (int64, error) {
	if writerTo, isWriterTo := c.use().(io.WriterTo); isWriterTo {
		return writerTo.WriteTo(w)
	}
	return io.Copy(w, struct{ io.Reader }{c.use()})
}

func (c *earlyDataConn) CloseRead() error {
	if closer, isCloser := c.use().(interface{ CloseRead() error }); isCloser {
		return closer.CloseRead()
	}
	return nil
}

func (c *earlyDataConn) CloseWrite() error {
	if closer, isCloser := c.use().(interface{ CloseWrite() error }); isCloser {
		return closer.CloseWrite()
	}
	return nil
}

// ReaderReplaceable, WriterReplaceable and Upstream forward to whatever is
// actually serving the connection.
//
// The forwarding is load-bearing rather than cosmetic. Once use() has resolved a
// delegate, that delegate is a cached connection and reports ReaderReplaceable
// false while its buffer is non-empty, which is exactly the signal the shared
// core reads before it decides it may splice the raw socket. Resolving here
// before answering is what makes that signal visible instead of hidden behind
// this wrapper.
func (c *earlyDataConn) ReaderReplaceable() bool {
	resolved := c.use()
	replaceable, isReplaceable := resolved.(N.ReaderWithUpstream)
	if !isReplaceable {
		return false
	}
	return replaceable.ReaderReplaceable()
}

func (c *earlyDataConn) WriterReplaceable() bool {
	resolved := c.use()
	replaceable, isReplaceable := resolved.(N.WriterWithUpstream)
	if !isReplaceable {
		return false
	}
	return replaceable.WriterReplaceable()
}

func (c *earlyDataConn) Upstream() any {
	return c.use()
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	// No configured users means there is nothing in the context to find. Skip the
	// lookup entirely rather than paying for it and then branching on the miss.
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
// The no-users case is answered from immutable construction-time state, without
// touching the context. The users-configured case keeps the exact previous
// semantics: the handshake authenticated the client and recorded the username in
// the context, and a session that has no user in its context is one that came
// through a path which did not authenticate.
func (h *Inbound) lookupUser(ctx context.Context) (string, bool) {
	if !h.hasUsers {
		return "", false
	}
	return auth.UserFromContext[string](ctx)
}
