package masque

import (
	"context"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/transport/device"
	"github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const defaultKeepAlivePeriod = 10 * time.Second

var (
	_ adapter.OutboundWithPreferredRoutes = (*ClientEndpoint)(nil)
	_ adapter.FlowOutbound                = (*ClientEndpoint)(nil)
	_ adapter.InterfaceUpdateListener     = (*ClientEndpoint)(nil)
	_ adapter.OnDemandEndpoint            = (*ClientEndpoint)(nil)
	_ dialer.PacketDialerWithDestination  = (*ClientEndpoint)(nil)
	_ masque.ClientHandler                = (*ClientEndpoint)(nil)
)

type ClientEndpoint struct {
	endpointBase
	ctx       context.Context
	dnsRouter adapter.DNSRouter
	// innerQueryOptions resolves domains reached THROUGH the tunnel. It is
	// resolved ONCE at construction, not per connection, so an inner lookup takes
	// the DNS router's transport fast path instead of re-walking the rule set for
	// every target domain.
	//
	// The zero value is meaningful and is the default: it tells the router to apply
	// the configured DNS rules, which is exactly the behaviour that existed before
	// this option.
	innerQueryOptions adapter.DNSQueryOptions
	// assignedDNS is the endpoint-local transport that resolves through a nameserver the
	// server assigned. It is nil when no DNS_ASSIGN has been accepted, which is what
	// makes the resolver precedence fall through to the ordinary DNS rules.
	assignedDNS   *assignedDNSTransport
	client        *masque.Client
	deviceOptions *device.Options
	device        device.Device
	mtu           uint32
	onDemand      bool
	stateAccess   sync.Mutex
	deviceStarted bool
	state         atomic.Pointer[clientState]
}

type clientState struct {
	configured     bool
	localAddresses []netip.Prefix
	routes         []masque.AddressRange
}

func NewClientEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEClientEndpointOptions) (adapter.Endpoint, error) {
	if options.MTU == 0 {
		options.MTU = masque.DefaultMTU
	}
	version := options.ResolvedVersion()
	http2Options := options.HTTP2Options
	if version == 3 {
		http2Options = options.HTTP3Options.HTTP2Options
		if options.Version == 0 && http.NewHTTP3Client == nil {
			version = 2
		}
	}
	if http2Options.KeepAlivePeriod == 0 {
		http2Options.KeepAlivePeriod = badoption.Duration(defaultKeepAlivePeriod)
	}
	options.HTTP3Options.HTTP2Options = http2Options
	if options.HTTP3Options.InitialPacketSize == 0 {
		options.HTTP3Options.InitialPacketSize = min(int(options.MTU)+masque.QUICPacketOverhead, math.MaxUint16)
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   options.ServerIsDomain(),
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}
	// The inner resolver is a DIFFERENT question from the bootstrap one above, and
	// the two must not be conflated:
	//
	//	DialerOptions.DomainResolver -> the MASQUE server hostname, needed before any
	//	                                tunnel exists
	//	InnerDomainResolver          -> domains carried INSIDE the tunnel, which may
	//	                                depend on state that only exists once the
	//	                                tunnel is up
	//
	// Resolving it here means a missing or unknown resolver tag fails at
	// configuration time rather than on the first inner lookup.
	var innerQueryOptions adapter.DNSQueryOptions
	if options.InnerDomainResolver != nil && options.InnerDomainResolver.Server != "" {
		innerQueryOptions, err = dialer.NewDNSQueryOptions(ctx, options.InnerDomainResolver, false)
		if err != nil {
			return nil, E.Cause(err, "initialize inner domain resolver")
		}
	}
	headers := options.Headers.Build()
	authority := headers.Get("Host")
	headers.Del("Host")
	if authority == "" {
		server := options.ServerOptions.Build()
		authority = server.String()
		if server.Port == 443 {
			authority = server.AddrString()
			if server.IsIPv6() {
				authority = "[" + authority + "]"
			}
		}
	}
	httpClient, err := http.NewClientWithTLS(ctx, logger, outboundDialer, options.ServerOptions, common.PtrValueOrDefault(options.TLS), http.ClientOptions{
		Authority:              authority,
		Username:               options.Username,
		Password:               options.Password,
		Headers:                headers,
		Version:                version,
		DisableVersionFallback: options.DisableVersionFallback,
		HTTP2Options:           http2Options,
		HTTP3Options:           options.HTTP3Options,
	})
	if err != nil {
		return nil, err
	}
	clientEndpoint := &ClientEndpoint{
		endpointBase: endpointBase{
			Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeMASQUEClient, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
			router:  router,
			logger:  logger,
		},
		ctx:               ctx,
		dnsRouter:         service.FromContext[adapter.DNSRouter](ctx),
		innerQueryOptions: innerQueryOptions,
		// Built unconditionally but installed only when an assignment arrives. It holds
		// the DEVICE as its dialer, which is what makes every assigned query go through
		// the tunnel rather than the host stack.
		assignedDNS: newAssignedDNSTransport(logger, nil, tag),
		mtu:         options.MTU,
		onDemand:    options.OnDemand,
	}
	clientEndpoint.state.Store(&clientState{})
	clientEndpoint.deviceOptions = newDeviceOptions(ctx, logger, clientEndpoint, options.MASQUEEndpointOptions, time.Duration(options.UDPTimeout), nil)
	clientEndpoint.client, err = masque.NewClient(masque.ClientOptions{
		Context:         ctx,
		Logger:          logger,
		HTTPClient:      httpClient,
		Path:            options.Path,
		AdvertiseRoutes: options.AdvertiseRoutes,
		Handler:         clientEndpoint,
	})
	if err != nil {
		httpClient.Close()
		return nil, err
	}
	return clientEndpoint, nil
}

func (c *ClientEndpoint) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		c.deviceOptions.MemoryPressure = oomkiller.MemoryPressure(c.ctx)
		tunnelDevice, err := device.New(*c.deviceOptions)
		if err != nil {
			return err
		}
		tunnelDevice.SetPacketWriter(c.writePacketBuffers)
		c.device = tunnelDevice
		c.deviceOptions = nil
		// The assigned-DNS transport dials through the device, so it can only be given
		// its dialer once the device exists. Until an assignment arrives it stays
		// inactive, and its fail-closed behaviour covers the window before this point.
		c.assignedDNS.dialer = tunnelDevice
	case adapter.StartStatePostStart:
		c.client.Start()
	}
	return nil
}

func (c *ClientEndpoint) Close() error {
	return common.Close(c.client, c.device)
}

func (c *ClientEndpoint) UpdateConfiguration(configuration masque.Configuration) error {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	err := c.device.UpdateConfiguration(device.Configuration{
		MTU:     c.mtu,
		Address: configuration.Address,
	})
	if err != nil {
		return E.Cause(err, "update device configuration")
	}
	if !c.deviceStarted {
		err = c.device.Start()
		if err != nil {
			return E.Cause(err, "start device")
		}
		c.deviceStarted = true
	}
	if !slices.Equal(c.state.Load().localAddresses, configuration.Address) {
		c.logger.Info("assigned ", strings.Join(common.Map(configuration.Address, netip.Prefix.String), " "))
	}
	c.state.Store(&clientState{
		configured:     true,
		localAddresses: configuration.Address,
		routes:         configuration.Routes,
	})
	// Resolver precedence, applied here because this is where a new configuration and
	// its routes arrive together:
	//
	//	explicit inner_domain_resolver   (highest)
	//	server-pushed DNS_ASSIGN
	//	normal DNS Router rules          (default)
	//
	// A configured inner resolver always wins, and the server's assignment is still
	// parsed and VALIDATED but not installed. That is a security property rather than a
	// convenience: the operator's explicit choice is the trusted one, and a server must
	// not be able to override where the client's DNS goes.
	c.installAssignedDNS(configuration)
	return nil
}

// installAssignedDNS decides whether the server's assignment becomes the resolver.
//
// The reachability check is the important part. A nameserver outside the advertised
// routes would be reached by the ordinary routing table rather than through the tunnel,
// so installing it would produce exactly the cleartext DNS leak that accepting a
// server-assigned resolver is meant to avoid. An unreachable assignment is refused and
// the resolver falls through to the ordinary rules.
func (c *ClientEndpoint) installAssignedDNS(configuration masque.Configuration) {
	if c.innerQueryOptions.Transport != nil {
		// An explicit resolver is configured. Record that the assignment was seen and
		// ignored, at debug level so a server that pushes one does not produce noise.
		if configuration.DNS != nil && !configuration.DNS.Empty() {
			c.logger.Debug("server DNS assignment received but an explicit inner resolver is configured; ignoring it")
		}
		return
	}
	if configuration.DNS == nil || configuration.DNS.Empty() {
		// Withdrawn, or nothing usable. Clearing is correct rather than leaving the
		// previous resolver installed.
		c.assignedDNS.clear()
		return
	}

	selected := configuration.DNS.SelectNameservers()
	// Every nameserver in the selected configuration must be routable through the
	// tunnel. A configuration with none reachable is refused as a whole rather than
	// partially installed: a partial resolver would answer some queries through the
	// tunnel and send the rest somewhere else.
	var reachable masque.DNSConfiguration
	for _, nameserver := range selected {
		if !nameserverReachable(nameserver, configuration.Routes) {
			c.logger.Warn("ignoring server DNS assignment: nameserver ",
				nameserverAddressString(nameserver),
				" is not reachable through the advertised routes")
			c.assignedDNS.clear()
			return
		}
		reachable.Nameservers = append(reachable.Nameservers, nameserver)
	}
	reachable.InternalDomains = dnsInternalDomains(configuration.DNS)
	reachable.SearchDomains = dnsSearchDomains(configuration.DNS)
	c.assignedDNS.apply(reachable, configuration.PREF64)
	c.logger.Debug("using server-assigned DNS resolver (", len(reachable.Nameservers),
		" nameservers, generation ", configuration.DNS.Generation, ")")
}

// nameserverReachable reports whether every address of a nameserver lies inside the
// advertised routes. An address-less nameserver (reachable only by name) is NOT treated
// as reachable, because resolving that name would itself need a resolver.
func nameserverReachable(nameserver masque.DNSNameserver, routes []masque.AddressRange) bool {
	addresses := append(append([]netip.Addr(nil), nameserver.IPv4Addresses...), nameserver.IPv6Addresses...)
	if len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		if !isReachableThroughRoutes(address, routes) {
			return false
		}
	}
	return true
}

func nameserverAddressString(nameserver masque.DNSNameserver) string {
	if len(nameserver.IPv4Addresses) > 0 {
		return nameserver.IPv4Addresses[0].String()
	}
	if len(nameserver.IPv6Addresses) > 0 {
		return nameserver.IPv6Addresses[0].String()
	}
	if nameserver.AuthenticationDomainName != "" {
		return nameserver.AuthenticationDomainName
	}
	return "<none>"
}

func dnsInternalDomains(assignment *masque.DNSAssignment) []string {
	var domains []string
	for _, configuration := range assignment.Configurations {
		domains = append(domains, configuration.InternalDomains...)
	}
	return domains
}

func dnsSearchDomains(assignment *masque.DNSAssignment) []string {
	var domains []string
	for _, configuration := range assignment.Configurations {
		domains = append(domains, configuration.SearchDomains...)
	}
	return domains
}

func (c *ClientEndpoint) WriteInboundBuffers(packetBuffers []*buf.Buffer) error {
	if !c.state.Load().configured {
		buf.ReleaseMulti(packetBuffers)
		return nil
	}
	err := c.device.WriteInboundBuffers(packetBuffers)
	buf.ReleaseMulti(packetBuffers)
	return err
}

func (c *ClientEndpoint) FrontHeadroom() int {
	return c.device.FrontHeadroom()
}

func (c *ClientEndpoint) InterfaceUpdated(ctx context.Context) {
	c.client.RestartSession()
}

func (c *ClientEndpoint) OnDemand() bool {
	return c.onDemand
}

func (c *ClientEndpoint) SetKeepIdleConnections(keep bool) {
	if keep {
		c.client.Resume()
	} else {
		c.client.Suspend()
	}
}

func (c *ClientEndpoint) waitReady(ctx context.Context) error {
	if !c.onDemand {
		if !c.client.Ready() {
			return E.New("endpoint is not ready yet")
		}
		return nil
	}
	c.client.Resume()
	waitCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	return c.client.WaitReady(waitCtx)
}

func (c *ClientEndpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (c *ClientEndpoint) PortAddresses() (netip.Addr, netip.Addr) {
	return c.device.PortAddresses()
}

func (c *ClientEndpoint) PortMTU() uint32 {
	return c.device.PortMTU()
}

func (c *ClientEndpoint) AttachReturn(returnPath tun.Return) error {
	return c.device.AttachReturn(returnPath)
}

func (c *ClientEndpoint) DetachReturn(returnPath tun.Return) error {
	return c.device.DetachReturn(returnPath)
}

func (c *ClientEndpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return c.judgeFlow(c, c.state.Load().localAddresses, network, source, destination, firstPacket)
}

func (c *ClientEndpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	c.newDNSPacket(log.ContextWithNewID(c.ctx), c, payload, source, destination, writer)
}

func (c *ClientEndpoint) WritePackets(packets [][]byte) error {
	if c.onDemand {
		c.client.Resume()
	}
	if !c.client.Ready() {
		return E.New("endpoint is not ready yet")
	}
	return c.client.WritePacketBuffers(common.Map(packets, func(packet []byte) *buf.Buffer {
		packetBuffer := buf.NewSize(masque.PacketHeadroom + len(packet))
		packetBuffer.Resize(masque.PacketHeadroom, 0)
		common.Must1(packetBuffer.Write(packet))
		return packetBuffer
	}), true)
}

func (c *ClientEndpoint) writePacketBuffers(packetBuffers []*buf.Buffer) error {
	if c.onDemand {
		c.client.Resume()
	}
	return c.client.WritePacketBuffers(packetBuffers, false)
}

func (c *ClientEndpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	c.newConnection(ctx, c, c.state.Load().localAddresses, conn, source, destination, onClose)
}

func (c *ClientEndpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	c.newPacketConnection(ctx, c, c.state.Load().localAddresses, conn, source, destination, onClose)
}

func (c *ClientEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		c.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		c.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	err := c.waitReady(ctx)
	if err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		destinationAddresses, lookupErr := c.lookupInner(ctx, destination.Fqdn)
		if lookupErr != nil {
			return nil, lookupErr
		}
		return c.dialResolved(ctx, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return c.device.DialContext(ctx, network, destination)
}

// lookupInner resolves a domain reached through the tunnel, applying the resolver
// precedence in one place so the TCP and UDP paths cannot disagree about it.
//
//	explicit inner_domain_resolver   (highest)
//	server-pushed DNS_ASSIGN
//	normal DNS Router rules          (default)
//
// The assigned resolver is installed into the query options as a TRANSPORT rather than
// replacing the router, so the DNS client's cache, TTL handling, negative cache,
// singleflight and optimistic cache all still apply. Only the wire changes: instead of
// the configured upstream, the query goes to the server-assigned nameserver through the
// tunnel.
//
// Fail-closed is inherited rather than re-implemented: if the assigned transport cannot
// reach its nameserver, its Exchange returns an error and the lookup FAILS. There is no
// path here that would retry the query against a host resolver, which is the leak the
// assigned transport exists to prevent.
func (c *ClientEndpoint) lookupInner(ctx context.Context, domain string) ([]netip.Addr, error) {
	queryOptions := c.innerQueryOptions
	if queryOptions.Transport == nil && c.assignedDNS.active() {
		queryOptions.Transport = c.assignedDNS
	}
	return c.dnsRouter.Lookup(ctx, domain, queryOptions)
}

// dialResolved connects to one of the addresses the resolver returned.
//
// # TCP races the address families; UDP does not
//
// For TCP the families are raced with a fallback delay, so a dual-stack target
// whose IPv6 path is blackholed connects over IPv4 in about one fallback delay
// instead of waiting for the IPv6 attempt to time out. That is what N.DialParallel
// provides, and it already degrades to a serial attempt when the answer contains
// only one family, so a single-stack target pays nothing for this.
//
// UDP deliberately keeps the serial path, and the reason is worth stating because
// the asymmetry looks like an oversight otherwise: a UDP "connection" is
// connectionless, so a successful socket creation or connect() proves only that
// the local kernel accepted the address. It says nothing about whether the peer is
// reachable. Racing on that signal would pick a winner that has not been shown to
// work, which is worse than no race at all. TCP has a handshake to win; UDP does
// not, and this code will not pretend otherwise.
func (c *ClientEndpoint) dialResolved(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return N.DialSerial(ctx, c.device, network, destination, destinationAddresses)
	}
	return N.DialParallel(ctx, c.device, network, destination, destinationAddresses,
		preferIPv6(c.innerQueryOptions.Strategy, destinationAddresses), DefaultInnerFallbackDelay)
}

// preferIPv6 decides which address family the TCP race attempts first.
//
// The configured strategy wins, because the operator has already expressed a
// preference and overriding it here would make the strategy option quietly
// ineffective for tunnelled traffic.
//
// With no preference (AsIS) the decision is taken from the answer itself: the
// family of the resolver's FIRST address goes first. That respects the ordering the
// DNS layer already chose under its own rules instead of hardcoding one, and it is
// the reading "as is" asks for. An answer with only one family yields no race at
// all, because N.DialParallel short-circuits to serial in that case.
func preferIPv6(strategy C.DomainStrategy, addresses []netip.Addr) bool {
	switch strategy {
	case C.DomainStrategyPreferIPv6:
		return true
	case C.DomainStrategyPreferIPv4:
		return false
	}
	for _, address := range addresses {
		if address.Is4() || address.Is4In6() {
			return false
		}
		if address.Is6() {
			return true
		}
	}
	return false
}

// DefaultInnerFallbackDelay is how long the TCP race waits before starting the
// other address family.
//
// It matches the standard Happy Eyeballs default rather than introducing a new
// tunable: the task is to make dual-stack targets connect promptly, not to add
// another knob whose correct value nobody knows.
const DefaultInnerFallbackDelay = N.DefaultFallbackDelay

func (c *ClientEndpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	c.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	err := c.waitReady(ctx)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsDomain() {
		// Same precedence as the TCP path: both go through lookupInner so they cannot
		// disagree about which server resolves tunnelled names.
		destinationAddresses, lookupErr := c.lookupInner(ctx, destination.Fqdn)
		if lookupErr != nil {
			return nil, netip.Addr{}, lookupErr
		}
		// Serial, deliberately: see dialResolved for why UDP does not race.
		packetConn, destinationAddress, listenErr := N.ListenSerial(ctx, c.device, destination, destinationAddresses)
		if listenErr != nil {
			return nil, netip.Addr{}, listenErr
		}
		return iponly.NewPacketConn(c.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := c.device.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(c.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(c.logger, packetConn), netip.Addr{}, nil
}

func (c *ClientEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := c.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (c *ClientEndpoint) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	return false
}

func (c *ClientEndpoint) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	state := c.state.Load()
	if !state.configured || !c.client.Ready() {
		return false
	}
	var protocol uint8
	switch metadata.Network {
	case N.NetworkTCP:
		protocol = uint8(header.TCPProtocolNumber)
	case N.NetworkUDP:
		protocol = uint8(header.UDPProtocolNumber)
	case N.NetworkICMP:
		protocol = uint8(header.ICMPv4ProtocolNumber)
	}
	return masque.RoutesContain(state.routes, address, protocol)
}
