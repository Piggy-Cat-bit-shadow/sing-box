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
	transportHTTP "github.com/sagernet/sing-box/transport/http"
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
	// dnsAssignment is the compiled DNS_ASSIGN currently in force, or nil when none has been
	// received. It is an IMMUTABLE snapshot replaced wholesale: a lookup captures it once and
	// uses that value for its whole lifetime, so a capsule arriving mid-lookup cannot produce
	// a mixed answer.
	dnsAssignment atomic.Pointer[dnsAssignmentSnapshot]
	// pref64 holds the NAT64 prefixes in force. It is deliberately separate from the DNS
	// assignment: PREF64 does not affect any answer or any transport, so it must not be able
	// to invalidate the DNS cache.
	pref64 pref64Store
	// dnsTag is the transport tag assigned lookups are reported under.
	dnsTag string
	// sessionTransport is the protocol the CURRENT tunnel session was established over,
	// recorded from the session itself. Its zero value (TunnelTransportUnknown) is the correct
	// starting state: nothing has been established yet.
	//
	// It is a uint32 because the session goroutine writes it while lookups read it, and the
	// value is a small enum, so an atomic store avoids a lock on the lookup path.
	sessionTransport atomic.Uint32
	// assignmentAccess guards currentAssignment and currentRoutes: the last server
	// configuration received, kept so the capability can be RECOMPILED when the tunnel
	// changes. The server does not resend DNS_ASSIGN when the tunnel's transport changes --
	// the assignment did not change, our ability to use it did.
	assignmentAccess  sync.Mutex
	currentAssignment *masque.DNSAssignment
	currentRoutes     []masque.AddressRange
	client            *masque.Client
	deviceOptions     *device.Options
	device            device.Device
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
	var http3ConnDialer http.HTTP3ConnDialer
	if bootstrapDialer != nil {
		httpDialer = bootstrapDialer
		// The transport supplies the candidate connector per call, through the hook's own
		// parameter, so nothing is stored here and there is no construction cycle to break.
		http3ConnDialer = masqueConnDialer(
			newHandshakeRacer(N.DefaultFallbackDelay),
			bootstrapDialer,
			bootstrapResolver.strategy(),
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
	clientEndpoint := &ClientEndpoint{
		endpointBase: endpointBase{
			Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeMASQUEClient, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
			router:  router,
			logger:  logger,
		},
		ctx:               ctx,
		dnsRouter:         service.FromContext[adapter.DNSRouter](ctx),
		innerQueryOptions: innerQueryOptions,
		dnsTag:            tag,
		httpClient:        httpClient,
		httpDialer:        httpDialer,
		http3ConnDialer:   http3ConnDialer,
		mtu:               options.MTU,
		onDemand:          options.OnDemand,
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

// installAssignedDNS publishes the server's DNS assignment as a new immutable snapshot.
//
// # Claims are published even when their resolvers are unusable
//
// Every configuration is compiled and published, INCLUDING one whose resolvers cannot currently
// be used. That is a privacy property, not tidiness.
//
// A configuration's internal domains are a CLAIM: the server is saying "names under here are
// mine, and must be resolved by my nameserver". Whether that nameserver is reachable right now
// is a separate question, answered by compileResolver once the routes and the client's
// transport capability are known. If unreachability deleted the claim, the name would become
// unclaimed -- and an unclaimed name goes to the ordinary DNS rules -- so a temporarily
// unreachable internal resolver would silently send `internal.corp` to a public resolver. That
// is the split-DNS leak this design exists to prevent.
//
// So the configuration keeps its claim, its resolvers are marked unusable, and a query for a
// claimed name fails closed instead. `decide` is what makes that distinction, and it is
// deliberately answered without reference to usability.
func (c *ClientEndpoint) installAssignedDNS(configuration masque.Configuration) {
	// # PREF64 is published FIRST, and unconditionally
	//
	// PREF64 and DNS resolver precedence are independent states. PREF64 records NAT64 prefixes;
	// this client performs no synthesis, so it neither affects nor is affected by which resolver
	// answers. An earlier version returned early when an explicit inner resolver was configured,
	// which meant those prefixes were silently never stored -- a state update lost to an
	// unrelated preference.
	c.pref64.publish(configuration.PREF64)

	// Remember the assignment so the capability can be recomputed later, when the tunnel's
	// transport or its routes change. That recomputation is what stops an availability decision
	// from being frozen at the moment the capsule happened to arrive.
	c.assignmentAccess.Lock()
	if configuration.DNS == nil || configuration.DNS.Empty() {
		c.currentAssignment = nil
	} else {
		c.currentAssignment = configuration.DNS
	}
	c.currentRoutes = append([]masque.AddressRange(nil), configuration.Routes...)
	c.assignmentAccess.Unlock()

	if c.innerQueryOptions.Transport != nil {
		// An explicit resolver is configured. The operator has said where inner queries go, and
		// a server must not override that. The assignment is still parsed and validated, and
		// PREF64 above is still applied -- only the DNS RESOLUTION policy is left alone.
		if configuration.DNS != nil && !configuration.DNS.Empty() {
			c.logger.Debug("server DNS assignment received but an explicit inner resolver is configured; not used for resolution")
		}
		c.dnsAssignment.Store(nil)
		return
	}

	if configuration.DNS == nil || configuration.DNS.Empty() {
		// Withdrawn. Storing nil is what makes every name unclaimed again, and an in-flight
		// lookup keeps using the snapshot it captured.
		c.dnsAssignment.Store(nil)
		return
	}

	snapshot := compileDNSAssignment(configuration.DNS.Configurations, c.resolverCapability(configuration.Routes))
	// A single pointer store: readers see either the old snapshot or the new one, never a
	// mixture, and an in-flight lookup is unaffected by the replacement.
	c.dnsAssignment.Store(snapshot)
	c.logger.Debug("using server-assigned DNS resolver (", len(snapshot.configurations), " configurations)")
}

// Pref64Prefixes reports the NAT64 prefixes currently in force.
//
// This is state EXPOSURE only: this client performs no DNS64 synthesis, so the prefixes do not
// affect resolution. They are reported so the configuration surface is honest about what the
// server sent rather than silently discarding it.
func (c *ClientEndpoint) Pref64Prefixes() []netip.Prefix {
	return c.pref64.snapshot()
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

	// Three facts, and same-connection DoH needs the third:
	//
	//	1. this HTTP client CAN speak HTTP/3            (configuration)
	//	2. it currently HOLDS a live HTTP/3 connection  (resource)
	//	3. THIS tunnel session WAS ESTABLISHED over it  (session truth)
	//
	// The first two are not sufficient and the session truth is not derivable from them: the
	// tunnel path falls back, so a live HTTP/3 connection can coexist with a session running
	// over HTTP/2. Sending a DNS query on that connection would put it on a connection the
	// tunnel traffic does not share, which is precisely what draft-06 §3.5's coalescing
	// requirement forbids.
	//
	// So the session transport is taken from the session, which recorded it at the branch that
	// actually opened the tunnel.
	if c.sessionTransport.Load() != uint32(transportHTTP.TunnelTransportHTTP3) {
		return capability
	}
	if c.httpClient == nil {
		return capability
	}
	// And the connection must still be live: the session being H3 says how it started, not
	// that the connection is up now.
	authority, live := c.httpClient.HTTP3ConnectionState()
	if !live || authority == "" {
		return capability
	}
	capability.tunnelIsHTTP3 = true
	capability.sameH3Authorities = []string{authority}
	return capability
}

// UpdateTunnelTransport implements transportHTTP's optional tunnel-transport reporting.
//
// # Why a change here must recompile the DNS capability
//
// Whether a resolver can use same-connection DoH is a JOINT property of what the server
// advertised and how the tunnel is currently carried. A snapshot compiled while the tunnel was
// HTTP/2 marks an addressless DoH resolver unusable; if the tunnel later comes back over
// HTTP/3, that decision is stale and the resolver stays unusable forever -- unless it is
// recomputed here. The reverse matters too: a snapshot compiled on HTTP/3 would keep offering
// DoH after a fallback to HTTP/2.
//
// The server does not resend DNS_ASSIGN when the tunnel changes, and it should not have to:
// the assignment did not change, our ability to use it did.
func (c *ClientEndpoint) UpdateTunnelTransport(ctx context.Context, tunnelTransport transportHTTP.TunnelTransport) {
	c.sessionTransport.Store(uint32(tunnelTransport))
	c.recompileAssignedDNS()
}

// recompileAssignedDNS re-evaluates the current assignment against the CURRENT capability.
//
// The server configuration is unchanged; only availability is recomputed. A new immutable
// snapshot is published, so an in-flight lookup keeps the one it captured.
func (c *ClientEndpoint) recompileAssignedDNS() {
	c.assignmentAccess.Lock()
	assignment, routes := c.currentAssignment, c.currentRoutes
	c.assignmentAccess.Unlock()
	if assignment == nil {
		return
	}
	snapshot := compileDNSAssignment(assignment.Configurations, c.resolverCapability(routes))
	c.dnsAssignment.Store(snapshot)
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

// lookupInner resolves a domain the endpoint is about to carry through the tunnel.
//
// # The precedence
//
//	explicit inner_domain_resolver   (highest: the operator's choice is the trusted one)
//	        >
//	DNS_ASSIGN, when it CLAIMS this name
//	        >
//	normal DNS Router rules          (default)
//
// # One lookup, one snapshot
//
// The snapshot is captured ONCE, at the top, and everything below uses that captured value.
//
// This matters because a single lookup issues an A and an AAAA query CONCURRENTLY. Reading the
// assignment again inside the transport would let a capsule arriving mid-lookup send the A query
// through one assignment and the AAAA query through the next, producing mixed-family answers
// that came from two different configurations. Capturing once makes that impossible rather than
// unlikely.
//
// # Claimed and unclaimed are different, and a claimed failure must NOT fall back
//
//	UNCLAIMED  -> the server never said this name was its business, so the ordinary rules apply
//	CLAIMED    -> the assigned configuration answers it, or the lookup FAILS
//
// The second rule is the privacy invariant of split DNS: a name the server claimed belongs to a
// resolver it nominated, and handing it to a public resolver when that resolver is unreachable
// would leak an internal name at exactly the moment the internal path is broken.
//
// # What precedes the first DNS_ASSIGN is unknowable
//
// draft-06 has no capsule announcing that an assignment is coming, so before the first
// DNS_ASSIGN arrives the client cannot know which names WILL be claimed. Until then every name
// is unclaimed and resolves normally. That is a protocol limitation, not a gap this code can
// close, and no timer or readiness gate is invented here to pretend otherwise.
func (c *ClientEndpoint) lookupInner(ctx context.Context, domain string) ([]netip.Addr, error) {
	// 1. An explicit resolver wins outright. The server's assignment is still parsed and
	//    validated, but it must not be able to override the operator's own choice.
	if c.innerQueryOptions.Transport != nil {
		return c.dnsRouter.Lookup(ctx, domain, c.innerQueryOptions)
	}

	// 2. Capture the assignment ONCE for this whole lookup.
	snapshot := c.dnsAssignment.Load()
	decision := snapshot.decide(domain)

	switch {
	case !decision.claimed:
		// Nobody claimed it, so the ordinary rules decide -- this is what makes a split tunnel
		// resolve public names.
		return c.dnsRouter.Lookup(ctx, domain, c.innerQueryOptions)

	case !decision.usable:
		// Claimed, but nothing can serve it. Fail closed and do NOT consult the ordinary rules.
		c.logger.Debug("assigned DNS configuration claims ", domain, " but has no usable resolver")
		return nil, E.New("the server-assigned DNS configuration for ", domain,
			" has no usable resolver, and the name is not resolved by any other means")

	default:
		// Claimed and serveable. The transport is bound to THIS configuration, so the choice
		// made here cannot drift if a new assignment is published while the query is in flight.
		queryOptions := c.innerQueryOptions
		queryOptions.Transport = newConfigurationDNSTransport(
			c.logger,
			c.device,
			c.dnsTag,
			decision.configuration,
			c.dohExecutor(),
		)
		return c.dnsRouter.Lookup(ctx, domain, queryOptions)
	}
}

// dohExecutor returns the same-connection DoH executor, or nil when it cannot be used.
//
// draft-06 §3.5 asks for DoH to be coalesced over the connection the tunnel already uses, which
// presupposes that the tunnel IS that connection. The configured protocol version is not the
// same fact: transport/http falls back to HTTP/2, so an endpoint configured for version 3 can
// have an HTTP/2 tunnel while the HTTP/3 code path still exists. Reporting the capability from
// the client that owns the connection is what keeps a DNS query from creating a second one.
func (c *ClientEndpoint) dohExecutor() dohExecutor {
	if c.httpClient == nil {
		return nil
	}
	if _, live := c.httpClient.HTTP3ConnectionState(); !live {
		return nil
	}
	return c.httpClient
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
