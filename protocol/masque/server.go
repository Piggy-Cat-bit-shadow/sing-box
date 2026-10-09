package masque

import (
	"context"
	"io"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/transport/device"
	"github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var (
	_ adapter.OutboundWithPreferredRoutes = (*ServerEndpoint)(nil)
	_ adapter.FlowOutbound                = (*ServerEndpoint)(nil)
	_ adapter.ConnectionHandler           = (*serverConnectionHandler)(nil)
	_ dialer.PacketDialerWithDestination  = (*ServerEndpoint)(nil)
	_ masque.ServerHandler                = (*ServerEndpoint)(nil)
)

type ServerEndpoint struct {
	endpointBase
	ctx            context.Context
	dnsRouter      adapter.DNSRouter
	listener       *listener.Listener
	httpServer     *http.Server
	tlsConfig      tls.ServerConfig
	http3          bool
	quicOptions    option.QUICOptions
	http3Server    io.Closer
	server         *masque.Server
	deviceOptions  *device.Options
	device         device.Device
	localAddresses []netip.Prefix
	started        atomic.Bool
	// startAccess orders the externally visible acquisitions in StartStateStart against the
	// closeOnce teardown. Close publishes `closed` under it before it releases anything, and Start
	// reads it under the same lock after it has bound the listener, so a socket that was bound while
	// Close was running cannot be left without an owner.
	startAccess sync.Mutex
	closed      bool
	closeOnce   sync.Once
	closeErr    error
	// testPublishStartedHook, when set, runs inside publishStarted after the readiness decision has
	// been committed and startAccess has been released.
	//
	// It exists so a test can hold the Start side at the exact boundary the readiness window lives on
	// and run Close to completion from the other side, which turns "the store used to happen outside
	// the lock" from an argument into an observation. It is nil in production.
	testPublishStartedHook func()
}

func NewServerEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEServerEndpointOptions) (adapter.Endpoint, error) {
	if options.MTU == 0 {
		options.MTU = masque.DefaultMTU
	}
	versions := options.Versions()
	if len(options.Version) == 0 && http.ConfigureHTTP3ListenerFunc == nil {
		logger.Warn("QUIC is not included in this build, HTTP/3 is disabled")
		versions = []int{1, 2}
	}
	serveHTTP1 := slices.Contains(versions, 1)
	serveHTTP2 := slices.Contains(versions, 2)
	serveHTTP3 := slices.Contains(versions, 3)
	if serveHTTP3 && (options.TLS == nil || !options.TLS.Enabled) {
		return nil, E.New("TLS is required for HTTP/3")
	}
	if options.HTTP3Options.InitialPacketSize == 0 {
		options.HTTP3Options.InitialPacketSize = min(int(options.MTU)+masque.QUICPacketOverhead, math.MaxUint16)
	}
	serverEndpoint := &ServerEndpoint{
		endpointBase: endpointBase{
			Adapter: endpoint.NewAdapter(C.TypeMASQUEServer, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, nil),
			router:  router,
			logger:  logger,
		},
		ctx:            ctx,
		dnsRouter:      service.FromContext[adapter.DNSRouter](ctx),
		http3:          serveHTTP3,
		quicOptions:    options.HTTP3Options,
		localAddresses: options.Address,
	}
	server, err := masque.NewServer(masque.ServerOptions{
		Context:         ctx,
		Logger:          logger,
		Path:            options.Path,
		Address:         options.Address,
		AdvertiseRoutes: options.AdvertiseRoutes,
		Resolve:         serverEndpoint.resolve,
		Handler:         serverEndpoint,
	})
	if err != nil {
		return nil, err
	}
	serverEndpoint.server = server
	serverEndpoint.httpServer = http.NewServer(http.ServerOptions{
		Authenticator: auth.NewAuthenticator(options.Users),
		Logger:        logger,
		HTTP1:         serveHTTP1,
		HTTP2:         serveHTTP2,
		HTTP2Options:  options.HTTP2Options,
		Tunnels:       map[string]http.TunnelHandler{"connect-ip": server},
	})
	if options.TLS != nil {
		tlsConfig, tlsErr := tls.NewServerWithOptions(tls.ServerOptions{
			Context:        ctx,
			Logger:         logger,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: true,
		})
		if tlsErr != nil {
			return nil, tlsErr
		}
		if tlsConfig != nil {
			serverEndpoint.httpServer.ConfigureTLS(tlsConfig)
		}
		serverEndpoint.tlsConfig = tlsConfig
	}
	var network []string
	if serveHTTP1 || serveHTTP2 {
		network = []string{N.NetworkTCP}
	}
	serverEndpoint.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           network,
		Listen:            options.ListenOptions,
		ConnectionHandler: (*serverConnectionHandler)(serverEndpoint),
	})
	serverEndpoint.deviceOptions = newDeviceOptions(ctx, logger, serverEndpoint, options.MASQUEEndpointOptions, time.Duration(options.UDPTimeout), options.Address)
	serverEndpoint.deviceOptions.Route = server.RouteOutbound
	return serverEndpoint, nil
}

func (s *ServerEndpoint) resolve(ctx context.Context, domain string) ([]netip.Addr, error) {
	return s.dnsRouter.Lookup(ctx, domain, adapter.DNSQueryOptions{})
}

func (s *ServerEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		s.deviceOptions.MemoryPressure = oomkiller.MemoryPressure(s.ctx)
		tunnelDevice, err := device.New(*s.deviceOptions)
		if err != nil {
			return err
		}
		tunnelDevice.SetPacketWriter(s.writePacketBuffers)
		s.device = tunnelDevice
		s.deviceOptions = nil
		// Hand the teardown to the Scope in the same breath as the acquisition.
		//
		// The product closes a Box by closing its Scope, and Scope.Close() runs the entries handed
		// to it through scope.Add - it never calls a component's Close() method. Close released the
		// device, the listener, the TLS config, the server and the HTTP/3 server, but nothing had
		// given it to the Scope, so on a real Box.Close() the listening socket and the device stayed
		// open. Registering here also covers a failure in StartStateStart, which runs after this and
		// can fail at any of its four steps: the Box rolls a failed start back by closing the Scope.
		scope.Add(s.Close)
	case adapter.StartStateStart:
		if s.tlsConfig != nil {
			err := s.tlsConfig.Start()
			if err != nil {
				return E.Cause(err, "create TLS config")
			}
		}
		err := s.device.Start()
		if err != nil {
			return E.Cause(err, "start device")
		}
		err = s.listener.Start()
		if err != nil {
			return err
		}
		// Binds happen after the Scope's teardown is already registered, and Scope.Close does not
		// wait for a Start that is already running: it runs the cleanup queue and returns, while this
		// goroutine is still between device.Start and the bind above. The cleanup registered in
		// StartStateInitialize has therefore already run by the time the listener binds, and the
		// listener it released was the not-yet-started one, so nothing would ever close this socket.
		// The device is guarded by its own Start-after-Close contract; common/listener has none.
		if err = s.acquiredStillOwned(); err != nil {
			return E.Errors(err, s.listener.Close())
		}
		if s.http3 {
			// The HTTP/3 listener is acquired, but NOT published yet.
			//
			// `s.http3Server` is released by exactly one thing: the closeOnce body in Close, which is
			// already spent by the time this line runs (that is what the check above detects). A
			// listener published here would therefore have no owner at all - not Close, which has
			// returned, and not the Scope, whose queue was drained before the bind - and the UDP
			// socket it bound would outlive the endpoint, the Scope and Box.Close().
			//
			// So the acquisition is handed to the ownership decision first: either nothing is closed,
			// or this is not published, and it is rolled back here on the spot. The lock is held for
			// the decision only - never across ListenHTTP3, which binds a socket and starts the QUIC
			// accept loop - because Close must not be made to wait behind an acquisition.
			var http3Server io.Closer
			http3Server, err = s.httpServer.ListenHTTP3(s.ctx, s.logger, s.listener, nil, s.tlsConfig, s.quicOptions)
			if err != nil {
				return err
			}
			if err = s.publishStarted(http3Server); err != nil {
				return E.Errors(err, http3Server.Close())
			}
		} else if err = s.publishStarted(nil); err != nil {
			return err
		}
	}
	return nil
}

// acquiredStillOwned reports whether what a running Start has just acquired still has an owner.
//
// `closed` is published under startAccess before Close releases anything, and read under the same
// lock after the acquisition, so exactly one side owns the resource: either this returns nil, and
// the release that follows Close's critical section is ordered after the acquisition and therefore
// sees it, or it returns an error and Start releases what it just acquired on the spot. Neither
// branch can leave a bound socket behind, and neither waits for anything but the lock.
//
// It is the cheap pre-acquisition check: it lets Start avoid acquiring at all when Close has already
// finished. The authoritative decision is publishStarted, which makes the same comparison together
// with the state it protects.
func (s *ServerEndpoint) acquiredStillOwned() error {
	s.startAccess.Lock()
	closed := s.closed
	s.startAccess.Unlock()
	if !closed {
		return nil
	}
	return E.Cause(net.ErrClosed, "endpoint closed while starting")
}

// publishStarted is the endpoint's single readiness decision, and the last step of StartStateStart.
//
// # What it decides, in one critical section
//
//   - the ownership check: `closed` was published by Close before it released anything, and it is
//     read here under the same lock;
//   - the publication of what Start acquired, if anything (the HTTP/3 listener, or nil for the
//     H1/H2-only endpoint, which acquires nothing at this point);
//   - the readiness flag the data path gates on: `s.started`.
//
// # Why `started` may not be stored by the caller afterwards
//
// It could, briefly, and that was a real defect. The previous shape was:
//
//	if err = s.publishAcquiredHTTP3(http3Server); err != nil { ... }   // releases the lock
//	s.started.Store(true)                                             // OUTSIDE it
//
// Close takes the same lock to publish `closed` and then runs `s.started.Store(false)` outside it, so
// the interleaving "publish, release, Close runs to completion, store true" was reachable: the
// endpoint closed, its HTTP/3 listener released, its port free - and `started` true again afterwards.
// `WritePackets`, `DialContext` and `ListenPacketWithDestination` gate on exactly that flag, so a
// released endpoint answered them as if it were ready and the data path ran into a released device.
//
// With the store inside the critical section the two outcomes are the only ones:
//
//   - Close first. `closed` is visible, nothing is published, `started` stays false, the caller
//     releases what it acquired on the spot, and it never advertises itself as ready.
//   - This first. The publication and `started = true` are both visible before Close reads anything,
//     and Close's own `started.Store(false)` is ordered after them, so the endpoint ends up closed.
//
// Restarting an already-started endpoint is refused for the same reason: the endpoint owns resources
// whose only release is the spent closeOnce body, so a second Start that overwrote `s.http3Server`
// would orphan the first listener. The product never does this - a component's StartStateStart runs
// once per Scope - and a refusal makes that contract observable instead of silently destructive.
func (s *ServerEndpoint) publishStarted(http3Server io.Closer) error {
	s.startAccess.Lock()
	if s.closed {
		s.startAccess.Unlock()
		return E.Cause(net.ErrClosed, "endpoint closed while starting")
	}
	if s.started.Load() {
		s.startAccess.Unlock()
		return E.New("endpoint is already started")
	}
	if http3Server != nil {
		s.http3Server = http3Server
	}
	s.started.Store(true)
	s.startAccess.Unlock()
	// The seam sits AFTER the decision has been committed and the lock has been released, which is the
	// only place a test can hold this side open while Close runs: everything the readiness publication
	// excludes - publishing `closed`, releasing the listener and the HTTP/3 server - takes
	// startAccess, so a seam inside the critical section would deadlock the invalidation rather than
	// interleave with it.
	//
	// It is what makes the readiness window a fact instead of a race. The window it exposes is exactly
	// the one the baseline had: the decision is committed and the lock is free, and the statement that
	// used to follow here - `s.started.Store(true)`, outside the lock - has not run yet. A test that
	// stops here, runs Close to completion, and then continues observes whether the remaining work can
	// resurrect the readiness of an endpoint that is already closed. Nil in production, where it costs
	// one comparison per endpoint start.
	if hook := s.testPublishStartedHook; hook != nil {
		hook()
	}
	return nil
}

// Close releases the endpoint's running resources.
//
// It is idempotent because two paths can reach it: the Scope owns it, and adapter/endpoint/manager.go
// closes an endpoint that lost a duplicate-tag race. Releasing the same listener and device twice is
// not something the underlying objects have to tolerate, so the release is guarded here rather than
// assumed safe. A concurrent second Close waits for the first and returns its result.
//
// Close also has to survive a Scope.Close() that runs while StartStateStart is in flight: the parts
// of the teardown that Start acquires AFTER that drain - the listener in particular - are released
// by Start itself, which is why `closed` is published first and re-checked after the bind.
func (s *ServerEndpoint) Close() error {
	s.closeOnce.Do(func() {
		// Publish the decision before releasing anything, under the lock Start re-checks after an
		// acquisition. A Start that is already running cannot be waited for - nothing bounds it - so
		// this is what lets it discover that its acquisition has no owner left.
		s.startAccess.Lock()
		s.closed = true
		s.startAccess.Unlock()
		s.started.Store(false)
		s.closeErr = common.Close(
			s.listener,
			s.http3Server,
			s.server,
			s.device,
			s.tlsConfig,
		)
	})
	return s.closeErr
}

type serverConnectionHandler ServerEndpoint

func (h *serverConnectionHandler) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	h.httpServer.ServeConnection(ctx, conn, http.NewReader(conn), nil, metadata.Source, onClose)
}

func (s *ServerEndpoint) WriteInboundBuffers(packetBuffers []*buf.Buffer) error {
	err := s.device.WriteInboundBuffers(packetBuffers)
	buf.ReleaseMulti(packetBuffers)
	return err
}

func (s *ServerEndpoint) FrontHeadroom() int {
	return s.device.FrontHeadroom()
}

func (s *ServerEndpoint) NewOutboundQueue(handler func(packetBuffers []*buf.Buffer)) *tun.OutboundQueue {
	return s.device.NewOutboundQueue(handler)
}

func (s *ServerEndpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (s *ServerEndpoint) PortAddresses() (netip.Addr, netip.Addr) {
	return s.device.PortAddresses()
}

func (s *ServerEndpoint) PortMTU() uint32 {
	return s.device.PortMTU()
}

func (s *ServerEndpoint) UpstreamPort() any {
	return s.device
}

func (s *ServerEndpoint) AttachReturn(returnPath tun.Return) error {
	return s.device.AttachReturn(returnPath)
}

func (s *ServerEndpoint) DetachReturn(returnPath tun.Return) error {
	return s.device.DetachReturn(returnPath)
}

func (s *ServerEndpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return s.judgeFlow(s, s.localAddresses, network, source, destination, firstPacket)
}

func (s *ServerEndpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	s.newDNSPacket(log.ContextWithNewID(s.ctx), s, payload, source, destination, writer)
}

func (s *ServerEndpoint) WritePackets(packets [][]byte) error {
	if !s.started.Load() {
		return E.New("endpoint is not ready yet")
	}
	return s.server.WritePacketBuffers(common.Map(packets, func(packet []byte) *buf.Buffer {
		packetBuffer := buf.NewSize(masque.PacketHeadroom + len(packet))
		packetBuffer.Resize(masque.PacketHeadroom, 0)
		common.Must1(packetBuffer.Write(packet))
		return packetBuffer
	}), true)
}

func (s *ServerEndpoint) writePacketBuffers(packetBuffers []*buf.Buffer) error {
	return s.server.WritePacketBuffers(packetBuffers, false)
}

func (s *ServerEndpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	s.newConnection(ctx, s, s.localAddresses, conn, source, destination, onClose)
}

func (s *ServerEndpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	s.newPacketConnection(ctx, s, s.localAddresses, conn, source, destination, onClose)
}

func (s *ServerEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		s.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		s.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if !s.started.Load() {
		return nil, E.New("endpoint is not ready yet")
	}
	if destination.IsDomain() {
		destinationAddresses, err := s.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, s.device, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return s.device.DialContext(ctx, network, destination)
}

func (s *ServerEndpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	s.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if !s.started.Load() {
		return nil, netip.Addr{}, E.New("endpoint is not ready yet")
	}
	if destination.IsDomain() {
		destinationAddresses, err := s.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, s.device, destination, destinationAddresses)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return iponly.NewPacketConn(s.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := s.device.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(s.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(s.logger, packetConn), netip.Addr{}, nil
}

func (s *ServerEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := s.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (s *ServerEndpoint) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	return false
}

func (s *ServerEndpoint) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	return s.started.Load() && s.server.Contains(address)
}
