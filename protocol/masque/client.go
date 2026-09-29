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

	"github.com/sagernet/quic-go"
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
	// httpClient is the HTTP client the tunnel is established with.
	httpClient *http.Client
	// httpDialer is the dialer that client actually uses. It is the bootstrap wrapper when
	// a bootstrap resolver is available, and the raw outbound dialer otherwise. It is kept
	// on the endpoint so the wiring can be inspected and asserted rather than inferred.
	httpDialer N.Dialer
	// http3ConnDialer is the handshake-racing hook installed on the HTTP client, or nil
	// when there is no bootstrap candidate list to race. nil is the meaningful default:
	// it is what preserves the plain dial path for every endpoint without a resolver.
	http3ConnDialer http.HTTP3ConnDialer
	mtu             uint32
	onDemand        bool
	stateAccess     sync.Mutex
	deviceStarted   bool
	state           atomic.Pointer[clientState]
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
	// The bootstrap path for the MASQUE server hostname.
	//
	// This must never consult the tunnel, the server's DNS assignment, or the
	// same-connection DoH, because it runs BEFORE any tunnel exists: connecting needs the
	// server's address, and the address cannot need the connection. The resolver used here
	// is the one common/dialer already built from `domain_resolver`, so this adds recovery
	// state without introducing a second resolver or a new configuration surface.
	//
	// What it adds over the plain dialer is memory: the DNS layer knows TTLs, but it does
	// not know which address the server actually ANSWERED on. During a resolver outage --
	// exactly when a reconnect storm happens -- that memory is the difference between
	// reconnecting immediately and waiting for the resolver to come back.
	bootstrapCache := newBootstrapCache()
	bootstrapResolver, hasBootstrapResolve := buildBootstrapResolution(outboundDialer, service.FromContext[adapter.DNSRouter](ctx))
	var bootstrapDialer *bootstrapDialer
	if hasBootstrapResolve {
		bootstrapDialer = newBootstrapDialer(outboundDialer, bootstrapCache, bootstrapResolver)
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
	// The dialer the HTTP client uses, and the handshake hook.
	//
	// Both are derived from the bootstrap state above and are only substituted when a
	// bootstrap resolver actually exists. When it does not -- a bare IP server, or a
	// resolver that is not a dialer.ResolveDialer -- the ORIGINAL dialer is passed
	// through untouched and the hook stays nil, so this endpoint behaves exactly as it did
	// before the recovery path existed rather than acquiring a degraded one.
	httpDialer := outboundDialer
	var (
		http3ConnDialer http.HTTP3ConnDialer
		candidateHolder *candidateDialerHolder
	)
	if bootstrapDialer != nil {
		httpDialer = bootstrapDialer
		// The candidate primitive lives on the HTTP client, which does not exist yet: the
		// client needs this hook in order to be constructed. A small holder breaks the cycle
		// without weakening either side -- by the time the hook runs, the client is built, and
		// a nil candidate dialer only means the racer falls back to its own DialEarly.
		candidateHolder = &candidateDialerHolder{}
		http3ConnDialer = masqueConnDialer(
			newHandshakeRacer(N.DefaultFallbackDelay),
			bootstrapDialer,
			bootstrapResolver.strategy(),
			candidateHolder,
		)
	}

	httpClient, err := http.NewClientWithTLS(ctx, logger, httpDialer, options.ServerOptions, common.PtrValueOrDefault(options.TLS), http.ClientOptions{
		Authority:              authority,
		Username:               options.Username,
		Password:               options.Password,
		Headers:                headers,
		Version:                version,
		DisableVersionFallback: options.DisableVersionFallback,
		HTTP2Options:           http2Options,
		HTTP3Options:           options.HTTP3Options,
		// The handshake racer, when there is a bootstrap resolver to drive it.
		//
		// nil means "dial directly", which is the behaviour for every other user of
		// transport/http and for this endpoint when no bootstrap resolver is available.
		// Only the HTTP/3 path consults the hook, and only when it is non-nil, so
		// Naive, protocol/http and common/httpclient keep the default path exactly.
		HTTP3ConnDialer: http3ConnDialer,
	})
	if err != nil {
		return nil, err
	}
	// The holder was needed before the client existed; now it can be filled.
	if candidateHolder != nil {
		candidateHolder.set(http3CandidateDialer(httpClient))
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
		assignedDNS:     newAssignedDNSTransport(logger, nil, tag),
		httpClient:      httpClient,
		httpDialer:      httpDialer,
		http3ConnDialer: http3ConnDialer,
		mtu:             options.MTU,
		onDemand:        options.OnDemand,
	}
	// The assigned resolver sends DoH queries on the SAME connection as the tunnel, which
	// is what draft-ietf-masque-connect-ip-dns-06 §3.5 asks for when the proxy is
	// authoritative for the DoH origin. Passing the client here is what makes that
	// possible; the transport still holds the device as its dialer, so the UDP path stays
	// inside the tunnel.
	clientEndpoint.assignedDNS.setDoHClient(httpClient)
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

	// # Claims are installed even when their resolvers are not usable
	//
	// Every configuration is published, INCLUDING one whose resolvers cannot currently be
	// used. That is deliberate and it is a privacy property rather than tidiness.
	//
	// A configuration's internal domains are a CLAIM: the server is saying "names under here
	// are mine, and must be resolved by my nameserver". Whether we can reach that nameserver
	// right now is a separate question, answered once the routes and the client's transport
	// capability are known. If unreachability deleted the claim, the name would become
	// unclaimed, and an unclaimed name is resolved by the ordinary DNS rules -- so a
	// temporary inability to reach an internal resolver would silently send `internal.corp`
	// to a public resolver. That is the split-DNS leak this design exists to prevent.
	//
	// So the configuration is published with its claim intact and its resolvers marked
	// unusable. A query for a claimed name then finds the claim, finds no usable resolver, and
	// FAILS -- which is the correct outcome.
	//
	// The wire types are passed through unchanged; usability is computed by the runtime model,
	// where the routes and the client's capability are both available.
	capability := c.resolverCapability(configuration.Routes)
	c.assignedDNS.apply(configuration.DNS.Configurations, configuration.PREF64, capability)
	c.logger.Debug("using server-assigned DNS resolver (", len(configuration.DNS.Configurations),
		" configurations, generation ", configuration.DNS.Generation, ")")
}

// candidateDialerHolder breaks the construction cycle between the HTTP client and the
// handshake hook that client needs.
//
// The hook is a field of the client, and the client's single-candidate primitive is what the
// hook wants to delegate to, so one of them has to be supplied late. This holder is that
// indirection: the hook is given the holder immediately, and the holder is filled in once the
// client exists. The hook is not invoked until a connection is dialed, which is long after
// construction, so the fill always happens first.
type candidateDialerHolder struct {
	dialer candidateDialer
}

func (h *candidateDialerHolder) set(dialer candidateDialer) {
	h.dialer = dialer
}

// DialHTTP3Candidate implements candidateDialer.
func (h *candidateDialerHolder) DialHTTP3Candidate(ctx context.Context, server M.Socksaddr, address netip.Addr) (net.Conn, *quic.Conn, error) {
	if h.dialer == nil {
		// No candidate primitive: report it so the racer falls back to its own DialEarly
		// rather than failing the connection.
		return nil, nil, errNoCandidateDialer
	}
	return h.dialer.DialHTTP3Candidate(ctx, server, address)
}

// errNoCandidateDialer signals that no transport-supplied candidate primitive exists, so the
// racer should build the candidate itself.
var errNoCandidateDialer = E.New("no HTTP/3 candidate dialer available")

// http3CandidateDialer extracts the transport's single-candidate primitive, or nil when the
// client has no HTTP/3 support.
func http3CandidateDialer(client *http.Client) candidateDialer {
	if client == nil {
		return nil
	}
	provided := client.HTTP3CandidateDialer()
	if provided == nil {
		return nil
	}
	dialer, isDialer := provided.(candidateDialer)
	if !isDialer {
		return nil
	}
	return dialer
}

// resolverCapability describes what this client can currently do, which decides whether an
// advertised transport is usable.
//
// # The tunnel's transport, not the CONFIGURED version
//
// draft-06 §3.5 asks that DoH be coalesced over the same HTTPS connection as the tunnel. That
// is only honest if the tunnel really is that connection, and the configured protocol version
// is not the same fact: transport/http falls back from H3 to H2, so an endpoint configured for
// version 3 can end up on an H2 tunnel while the H3 code path still exists.
//
// Reporting "the tunnel is H3" from the configuration would therefore be a guess, and the
// consequence of guessing wrong is that a DNS query DIALS A SECOND H3 CONNECTION. So the fact
// is asked of the HTTP client, which owns the connection, and it is false until proven
// otherwise.
func (c *ClientEndpoint) resolverCapability(routes []masque.AddressRange) resolverCapability {
	capability := resolverCapability{routes: append([]masque.AddressRange(nil), routes...)}
	if c.httpClient == nil {
		return capability
	}
	authority, tunnelIsHTTP3 := c.httpClient.HTTP3ConnectionState()
	if !tunnelIsHTTP3 || authority == "" {
		return capability
	}
	capability.tunnelIsHTTP3 = true
	capability.sameH3Authorities = []string{authority}
	return capability
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

// lookupInner resolves a domain reached through the tunnel, applying the resolver precedence
// in one place so the TCP and UDP paths cannot disagree about it.
//
// # The precedence, and the distinction that makes it safe
//
//	explicit inner_domain_resolver        (highest: the operator's choice is the trusted one)
//	        >
//	DNS_ASSIGN, when it CLAIMS this name
//	        >
//	normal DNS Router rules               (default)
//
// The middle line is the one that matters, and it is why the decision is made on the CLAIM
// rather than on the assignment's mere presence.
//
//	draft-06 §3.5: "Sending an empty string as an internal domain indicates the DNS root"
//	draft-06 §3.6.2: a split-tunnel configuration claims "internal.corp.example" and nothing
//	                 else, so public names must resolve normally
//
// An earlier version asked only "is an assignment active". That made every name assigned-DNS
// traffic, so in a split tunnel a public name was sent to the internal resolver -- which then
// refused it, because no configuration claimed it. Public resolution broke, and the failure
// looked like a server fault rather than a routing mistake.
//
// # Claimed and unclaimed are different, and a claimed failure must NOT fall back
//
//	UNCLAIMED name -> the ordinary rules. The server never said this was its business.
//	CLAIMED name   -> the assigned resolver, or FAILURE. Never the ordinary rules.
//
// The second rule is the privacy invariant of split DNS. A claimed name belongs to a resolver
// the server nominated; if that resolver is unreachable, unsupported, or erroring, sending the
// query to a public resolver would leak an internal name -- and would do so precisely when the
// internal path is broken, which is when it is least expected. So a claimed name never falls
// through. `assignedDNS.claimsName` answers the ownership question WITHOUT reference to
// usability, which is what stops a temporarily unreachable resolver from quietly converting an
// internal name into a public one.
func (c *ClientEndpoint) lookupInner(ctx context.Context, domain string) ([]netip.Addr, error) {
	// 1. An explicit resolver wins outright: the operator has already said where queries go,
	//    and a server must not be able to override that.
	if c.innerQueryOptions.Transport != nil {
		return c.dnsRouter.Lookup(ctx, domain, c.innerQueryOptions)
	}

	// 2. The server's assignment, but ONLY for names it claims.
	if c.assignedDNS.claimsName(domain) {
		queryOptions := c.innerQueryOptions
		queryOptions.Transport = c.assignedDNS
		// No fallback here by construction: the router will use this transport, and if it
		// fails the lookup fails.
		return c.dnsRouter.Lookup(ctx, domain, queryOptions)
	}

	// 3. Unclaimed. The ordinary rules, which is the entire point of a split tunnel.
	return c.dnsRouter.Lookup(ctx, domain, c.innerQueryOptions)
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
