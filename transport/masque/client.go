package masque

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	reconnectBackoffInitial = time.Second
	reconnectBackoffMax     = time.Minute
)

type Configuration struct {
	Address          []netip.Prefix
	Routes           []AddressRange
	RoutesAdvertised bool
	// DNS is the DNS configuration the server last assigned, or nil when none has
	// been received or the last one was empty.
	//
	// draft-ietf-masque-connect-ip-dns-06 §3.4: "If multiple DNS_ASSIGN capsules are
	// sent in one direction, each DNS_ASSIGN capsule supersedes prior ones." So this
	// is REPLACED on every capsule and never appended to. The value is owned by the
	// published snapshot, exactly like Address and Routes.
	DNS *DNSAssignment
	// PREF64 holds the NAT64 prefixes the server last advertised, or nil when the last
	// capsule was empty.
	//
	// §4.2: "The newly received PREF64 capsule overrides any previously received
	// PREF64 capsules", and "An empty PREF64 capsule invalidates any previously
	// received NAT64 Prefixes." Both are replacements, including the empty case, which
	// is why an empty capsule clears rather than being ignored.
	PREF64 []netip.Prefix
}

type ClientHandler interface {
	UpdateConfiguration(configuration Configuration) error
	WriteInboundBuffers(packetBuffers []*buf.Buffer) error
	FrontHeadroom() int
}

// ClientHandlerWithTunnelTransport is an OPTIONAL extra capability of a ClientHandler.
//
// # Why the session reports this rather than the handler guessing
//
// "This HTTP client can speak HTTP/3", "this HTTP client currently holds a live HTTP/3
// connection", and "THIS tunnel session was established over HTTP/3" are three different facts.
// A handler that inferred the third from either of the first two would be wrong whenever the
// tunnel path fell back: the fallback leaves an H3 connection object in place from an earlier
// success while the session itself runs over HTTP/2.
//
// That distinction has a concrete consequence for MASQUE DNS, so the session -- which is the
// only component that knows which branch actually succeeded -- reports it. A handler that does
// not implement this interface is unaffected; it simply never learns the transport.
type ClientHandlerWithTunnelTransport interface {
	// UpdateTunnelTransport reports the protocol the current session was established over.
	// It is called once per established session, and with TunnelTransportUnknown when the
	// session ends, so a stale value cannot outlive the session it described.
	UpdateTunnelTransport(ctx context.Context, transport transportHTTP.TunnelTransport)
}

type ClientOptions struct {
	Context         context.Context
	Logger          logger.ContextLogger
	HTTPClient      *transportHTTP.Client
	Path            string
	AdvertiseRoutes []netip.Prefix
	Handler         ClientHandler
}

type Client struct {
	ctx             context.Context
	cancel          context.CancelFunc
	logger          logger.ContextLogger
	httpClient      *transportHTTP.Client
	template        *Template
	advertiseRoutes []AddressRange
	handler         ClientHandler
	access          sync.Mutex
	current         *clientSession
	suspended       bool
	restarting      bool
	lastError       error
	stateUpdated    chan struct{}
	loopDone        chan struct{}
}

// clientSession is one established MASQUE tunnel.
//
// # Why there are two views of the same state
//
// configuration and ready are written RARELY - only when an ADDRESS_ASSIGN or
// ROUTE_ADVERTISEMENT capsule arrives - and read on EVERY packet, from both the
// transmit path (WritePacketBuffers) and the receive path (handlePacket). That is
// the textbook "read very often, write rarely" shape.
//
// access still guards the WRITE side and the invariants that span several fields
// (it is what makes "compare, then update, then publish" atomic with respect to
// other writers). state is the READ side: an immutable snapshot published with a
// single atomic store, so the hot path never takes a lock.
//
// Measured on darwin/arm64 M1 before making this change (benchstat, n=6):
//
//	TestSessionConfigRead   mutex read   86-101 ns/op
//	TestSessionConfigRead   snapshot read 2.6-8.9 ns/op
//
// The mutex figure is the same whether or not a writer is running (~108 ns/op
// contended), so this is fast-path cost rather than futex contention - which is
// why the change is worth making even though a single tunnel has little lock
// contention.
//
// # The immutability rule
//
// A published snapshot is NEVER mutated in place, and neither are the slices it
// points at. Every update builds a NEW snapshot and swaps it in. That is what
// makes the lock-free read safe: a reader that loaded the pointer holds a fully
// formed value for as long as it keeps the reference, regardless of how many
// writers publish afterwards.
//
// The specific hazard this avoids is aliasing a backing array that a later write
// extends: `snapshot.Address = append(snapshot.Address, ...)` could write into an
// array a concurrent reader is still reading. The writers below therefore always
// assign freshly built slices, never append into a published one.
type clientSession struct {
	*session
	client *Client
	// access guards writes to configuration/ready and the compare-then-publish
	// sequences below. It is NOT taken on the packet read path.
	access        sync.Mutex
	configuration Configuration
	ready         bool
	// tunnelTransport is the protocol THIS session was established over, recorded where it
	// was decided. It is per-session state rather than client state, so a replaced session
	// cannot inherit the previous one's transport.
	tunnelTransport transportHTTP.TunnelTransport
	// state is the lock-free read view. It is written only under access and
	// always with a complete, immutable snapshot.
	state atomic.Pointer[sessionState]
}

// sessionState is the immutable snapshot the packet hot path reads.
//
// Every field is read-only after publication. The slices are owned by the
// snapshot: no other goroutine may append to them, and a writer that needs a
// different set builds a new slice.
type sessionState struct {
	configuration Configuration
	ready         bool
	// routes is the precompiled form of configuration.Routes, built when the snapshot is
	// PUBLISHED and read without a lock on the packet path. Compiling here rather than per packet
	// is what turns a linear scan into a binary search for free: a capsule arrives rarely, a
	// packet arrives constantly.
	//
	// It is derived state, so it must be built from the SAME routes value the snapshot carries.
	// publishStateLocked is the only place that pairs them.
	routes routeMatcher
}

// publishStateLocked rebuilds and publishes the snapshot. The caller MUST hold
// s.access, which is what serialises snapshot construction against other writers.
//
// configuration is copied by value and its slices are carried over as-is rather
// than cloned, because Configuration values are only ever ASSIGNED wholesale by
// the capsule handlers - they never append into the slices a previous snapshot
// published. That is the invariant that makes the shallow copy sufficient, and it
// is asserted by TestSessionSnapshotDoesNotAliasPublishedSlices.
func (s *clientSession) publishStateLocked() {
	configuration := s.configuration
	s.state.Store(&sessionState{
		configuration: configuration,
		ready:         s.ready,
		// Derived from the same value the snapshot carries, so the two cannot disagree.
		routes: compileRouteMatcher(configuration.Routes),
	})
}

// loadState returns the current snapshot. It is safe to call from any goroutine
// and never blocks.
//
// A nil result means no snapshot has been published yet, which cannot happen for
// a session built by newClientSession - it publishes before the session is visible
// to any reader. The nil check is kept anyway so a future construction path that
// forgets to publish returns zero values rather than panicking on the packet path.
func (s *clientSession) loadState() sessionState {
	current := s.state.Load()
	if current == nil {
		return sessionState{}
	}
	return *current
}

func NewClient(options ClientOptions) (*Client, error) {
	template, err := ParseTemplate(options.Path)
	if err != nil {
		return nil, err
	}
	advertiseRoutes, err := RangesFromPrefixes(options.AdvertiseRoutes, 0)
	if err != nil {
		return nil, E.Cause(err, "build advertised routes")
	}
	ctx, cancel := context.WithCancel(options.Context)
	return &Client{
		ctx:             ctx,
		cancel:          cancel,
		logger:          options.Logger,
		httpClient:      options.HTTPClient,
		template:        template,
		advertiseRoutes: advertiseRoutes,
		handler:         options.Handler,
		stateUpdated:    make(chan struct{}),
	}, nil
}

func (c *Client) Start() {
	c.loopDone = make(chan struct{})
	go c.loop()
}

func (c *Client) Close() error {
	c.cancel()
	if c.loopDone != nil {
		<-c.loopDone
	}
	return c.httpClient.Close()
}

// notifyTunnelTransport reports the session transport to a handler that asked for it.
//
// The optional interface keeps every existing handler working: one that does not implement it
// simply never learns the transport, which is the same as before this existed.
func (c *Client) notifyTunnelTransport(tunnelTransport transportHTTP.TunnelTransport) {
	handler, wantsTransport := c.handler.(ClientHandlerWithTunnelTransport)
	if !wantsTransport {
		return
	}
	handler.UpdateTunnelTransport(c.ctx, tunnelTransport)
}

func (c *Client) notifyStateLocked() {
	close(c.stateUpdated)
	c.stateUpdated = make(chan struct{})
}

func (c *Client) loop() {
	defer close(c.loopDone)
	backoff := reconnectBackoffInitial
	for {
		c.access.Lock()
		suspended := c.suspended
		stateUpdated := c.stateUpdated
		c.restarting = false
		if !suspended {
			c.lastError = nil
		}
		c.access.Unlock()
		if suspended {
			select {
			case <-stateUpdated:
				continue
			case <-c.ctx.Done():
				return
			}
		}
		established, err := c.connect()
		if c.ctx.Err() != nil {
			return
		}
		c.access.Lock()
		interrupted := c.suspended || c.restarting
		if !interrupted {
			c.lastError = err
		}
		c.notifyStateLocked()
		stateUpdated = c.stateUpdated
		c.access.Unlock()
		if interrupted {
			backoff = reconnectBackoffInitial
			continue
		}
		if err != nil {
			c.logger.Error(E.Cause(err, "connection closed"))
		}
		if established {
			backoff = reconnectBackoffInitial
		}
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-stateUpdated:
			timer.Stop()
		case <-c.ctx.Done():
			timer.Stop()
			return
		}
		backoff = min(backoff*2, reconnectBackoffMax)
	}
}

func (c *Client) connect() (bool, error) {
	dialCtx, cancelDial := context.WithTimeout(c.ctx, C.TCPTimeout)
	stream, tunnelTransport, err := c.httpClient.OpenTunnelWithInfo(dialCtx, upgradeToken, c.template.Expand())
	cancelDial()
	if err != nil {
		return false, err
	}
	current := &clientSession{client: c}
	// Publish the initial (not-ready) snapshot BEFORE the session can be observed
	// through c.current. The hot path reads the snapshot without a lock, so a
	// session that reached a reader without one would take the nil branch of
	// loadState on every packet until the first capsule arrived. Doing it here
	// rather than in a constructor keeps the ordering explicit: publish, then
	// become visible.
	current.publishStateLocked()
	c.access.Lock()
	if c.suspended || c.restarting {
		suspended := c.suspended
		c.access.Unlock()
		stream.Close()
		if suspended {
			c.httpClient.ResetConnections()
		}
		return false, nil
	}
	current.session = newSession(c.ctx, stream, current, c.handler.FrontHeadroom)
	current.tunnelTransport = tunnelTransport
	c.current = current
	c.access.Unlock()
	// Report the transport the session was actually established over, now that it is the
	// current one. The handler may use it to decide whether a same-connection transport is
	// available; it must never have to infer that from which connection objects exist.
	c.notifyTunnelTransport(tunnelTransport)
	err = current.writeCapsule(newAddressCapsule(capsuleTypeAddressRequest, []AssignedAddress{
		{RequestID: 1, Prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 32)},
		{RequestID: 2, Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 128)},
	}))
	if err == nil && len(c.advertiseRoutes) > 0 {
		err = current.writeCapsule(newRouteCapsule(c.advertiseRoutes))
	}
	if err != nil {
		current.cancel(err)
	}
	err = current.run()
	c.access.Lock()
	c.current = nil
	c.access.Unlock()
	// The session is over, so the transport fact it carried is no longer true. Reporting
	// Unknown rather than leaving the last value in place is what stops a handler from
	// treating a finished H3 session as a live one.
	c.notifyTunnelTransport(transportHTTP.TunnelTransportUnknown)
	// The session is finished: clear ready so a reader that still holds the
	// pointer observes the tunnel as not-ready rather than as the state it had
	// while it was up.
	current.access.Lock()
	established := current.ready
	current.ready = false
	current.publishStateLocked()
	current.access.Unlock()
	return established, err
}

func (c *Client) activeSession() *clientSession {
	c.access.Lock()
	defer c.access.Unlock()
	return c.current
}

func (c *Client) Ready() bool {
	current := c.activeSession()
	if current == nil {
		return false
	}
	return current.loadState().ready
}

func (c *Client) WaitReady(ctx context.Context) error {
	for {
		c.access.Lock()
		current := c.current
		lastError := c.lastError
		stateUpdated := c.stateUpdated
		c.access.Unlock()
		if current != nil {
			if current.loadState().ready {
				return nil
			}
		} else if lastError != nil {
			return lastError
		}
		select {
		case <-stateUpdated:
		case <-ctx.Done():
			return ctx.Err()
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}
}

func (c *Client) Suspend() {
	c.access.Lock()
	if c.suspended {
		c.access.Unlock()
		return
	}
	c.suspended = true
	if c.current != nil {
		c.current.cancel(E.New("suspended"))
	}
	c.notifyStateLocked()
	c.access.Unlock()
	c.httpClient.ResetConnections()
}

func (c *Client) Resume() {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.suspended {
		return
	}
	c.suspended = false
	c.lastError = nil
	c.notifyStateLocked()
}

func (c *Client) RestartSession() {
	c.access.Lock()
	c.restarting = true
	if c.current != nil {
		c.current.cancel(E.New("network changed"))
	}
	c.lastError = nil
	c.notifyStateLocked()
	c.access.Unlock()
	c.httpClient.ResetConnections()
}

func (c *Client) WritePacketBuffers(packetBuffers []*buf.Buffer, forwarded bool) error {
	current := c.activeSession()
	if current == nil {
		buf.ReleaseMulti(packetBuffers)
		return nil
	}
	// One lock-free snapshot read for both fields, instead of a mutex acquisition
	// on every packet batch. See clientSession's doc comment for the measurement.
	state := current.loadState()
	if !state.ready {
		buf.ReleaseMulti(packetBuffers)
		return nil
	}
	configuration := state.configuration
	inet4Address, inet6Address := firstAddresses(configuration.Address)
	var replies []*buf.Buffer
	routedBuffers := packetBuffers[:0]
	for _, packetBuffer := range packetBuffers {
		_, destination, protocol, valid := packetAddresses(packetBuffer.Bytes())
		if !valid {
			packetBuffer.Release()
			continue
		}
		errorType := tun.ICMPErrorNoRoute
		// The precompiled matcher from the SAME snapshot the configuration came from, so the
		// routing decision stays lock-free and consistent with the routes it was built for.
		routed := !configuration.RoutesAdvertised || state.routes.contains(destination, protocol)
		if routed && forwarded && !decrementHopLimit(packetBuffer.Bytes()) {
			routed = false
			errorType = tun.ICMPErrorHopLimitExceeded
		}
		if !routed {
			reply, built := buildICMPError(packetBuffer.Bytes(), errorType, inet4Address, inet6Address, 0, c.handler.FrontHeadroom())
			if built {
				replies = append(replies, reply)
			}
			packetBuffer.Release()
			continue
		}
		routedBuffers = append(routedBuffers, packetBuffer)
	}
	err := current.writePackets(routedBuffers)
	if err != nil {
		current.cancel(err)
	}
	if len(replies) > 0 {
		return c.handler.WriteInboundBuffers(replies)
	}
	return nil
}

func (s *clientSession) handleAddressAssign(addresses []AssignedAddress) error {
	var assigned []netip.Prefix
	for _, address := range addresses {
		if address.RequestID != 0 && address.Prefix.Addr().IsUnspecified() && address.Prefix.IsSingleIP() {
			continue
		}
		localAddress := address.Prefix.Addr()
		if !address.Prefix.IsSingleIP() {
			localAddress = localAddress.Next()
		}
		assigned = append(assigned, netip.PrefixFrom(localAddress, address.Prefix.Bits()))
	}
	s.access.Lock()
	if slices.Equal(s.configuration.Address, assigned) {
		s.access.Unlock()
		return nil
	}
	s.configuration.Address = assigned
	configuration := s.configuration
	s.publishStateLocked()
	s.access.Unlock()
	return s.updateConfiguration(configuration)
}

// handleDNSAssign replaces the session's DNS configuration.
//
// Replacement is unconditional, including by an EMPTY assignment: the draft makes each
// capsule supersede the last, and a configuration carrying no usable nameserver is a
// genuine withdrawal. Treating empty as "nothing to do" would leave a resolver the
// server has stopped advertising.
//
// The locking follows handleRouteAdvertisement exactly, and the shape matters: the
// lock is held only while building and publishing the snapshot, released BEFORE
// calling out to the handler, and never held across it. Calling out under the lock
// would let a slow handler block the packet path, and using `defer Unlock` together
// with an explicit Unlock is a double-unlock.
func (s *clientSession) handleDNSAssign(configurations []DNSConfiguration) error {
	s.access.Lock()
	if len(configurations) == 0 {
		if s.configuration.DNS == nil {
			s.access.Unlock()
			return nil
		}
		s.configuration.DNS = nil
	} else {
		// A fresh value rather than a mutation, so nothing a reader already holds can
		// observe the change: a reader takes the pointer and the value it gets stays
		// valid and unchanged for as long as it holds it.
		s.configuration.DNS = &DNSAssignment{
			Configurations: configurations,
		}
	}
	configuration := s.configuration
	s.publishStateLocked()
	s.access.Unlock()
	if len(configuration.Address) == 0 {
		// The session is not ready yet, so there is nothing to notify. The state is
		// published and will be observed when ready is set.
		return nil
	}
	return s.updateConfiguration(configuration)
}

// handlePREF64 replaces the session's NAT64 prefixes.
//
// An empty slice clears them, which §4.2 states explicitly rather than leaving to
// inference. Same locking discipline as handleDNSAssign.
func (s *clientSession) handlePREF64(prefixes []netip.Prefix) error {
	s.access.Lock()
	if len(prefixes) == 0 {
		if s.configuration.PREF64 == nil {
			s.access.Unlock()
			return nil
		}
		s.configuration.PREF64 = nil
	} else {
		// Copied, because the parser's slice must not become state a later caller
		// could mutate through its own reference.
		s.configuration.PREF64 = append([]netip.Prefix(nil), prefixes...)
	}
	configuration := s.configuration
	s.publishStateLocked()
	s.access.Unlock()
	if len(configuration.Address) == 0 {
		return nil
	}
	return s.updateConfiguration(configuration)
}

func (s *clientSession) handleRouteAdvertisement(routes []AddressRange) error {
	s.access.Lock()
	if s.configuration.RoutesAdvertised && slices.Equal(s.configuration.Routes, routes) {
		s.access.Unlock()
		return nil
	}
	s.configuration.Routes = routes
	s.configuration.RoutesAdvertised = true
	configuration := s.configuration
	s.publishStateLocked()
	s.access.Unlock()
	if len(configuration.Address) == 0 {
		return nil
	}
	return s.updateConfiguration(configuration)
}

func (s *clientSession) updateConfiguration(configuration Configuration) error {
	if len(configuration.Address) == 0 {
		s.access.Lock()
		s.ready = false
		s.publishStateLocked()
		s.access.Unlock()
		s.client.access.Lock()
		s.client.notifyStateLocked()
		s.client.access.Unlock()
		return nil
	}
	err := s.client.handler.UpdateConfiguration(configuration)
	if err != nil {
		return E.Cause(err, "update configuration")
	}
	s.access.Lock()
	s.ready = true
	s.publishStateLocked()
	s.access.Unlock()
	s.client.access.Lock()
	s.client.lastError = nil
	s.client.notifyStateLocked()
	s.client.access.Unlock()
	return nil
}

func (s *clientSession) handleAddressRequest(addresses []AssignedAddress) error {
	rejections := make([]AssignedAddress, 0, len(addresses))
	for _, address := range addresses {
		unspecified := netip.IPv4Unspecified()
		if address.Prefix.Addr().Is6() {
			unspecified = netip.IPv6Unspecified()
		}
		rejections = append(rejections, AssignedAddress{RequestID: address.RequestID, Prefix: netip.PrefixFrom(unspecified, unspecified.BitLen())})
	}
	return s.writeCapsule(newAddressCapsule(capsuleTypeAddressAssign, rejections))
}

func (s *clientSession) handlePacket(buffer *buf.Buffer) {
	_, destination, _, valid := packetAddresses(buffer.Bytes())
	if !valid {
		buffer.Release()
		return
	}
	// One lock-free snapshot read per received packet. This is the hottest read in
	// the tunnel: it runs for every datagram the peer sends.
	configuration := s.loadState().configuration
	if !prefixesContain(configuration.Address, destination) && !rangesContain(s.client.advertiseRoutes, destination) {
		inet4Address, inet6Address := firstAddresses(configuration.Address)
		reply, built := buildICMPError(buffer.Bytes(), tun.ICMPErrorNoRoute, inet4Address, inet6Address, 0, transportHTTP.CapsuleHeadroom)
		buffer.Release()
		if built {
			_ = s.writePackets([]*buf.Buffer{reply})
		}
		return
	}
	err := s.client.handler.WriteInboundBuffers([]*buf.Buffer{buffer})
	if err != nil {
		s.client.logger.Debug(E.Cause(err, "write packet to device"))
	}
}

func (s *clientSession) handlePacketTooBig(buffer *buf.Buffer, mtu int) {
	inet4Address, inet6Address := firstAddresses(s.loadState().configuration.Address)
	reply, built := buildICMPError(buffer.Bytes(), tun.ICMPErrorPacketTooBig, inet4Address, inet6Address, mtu, s.client.handler.FrontHeadroom())
	buffer.Release()
	if !built {
		return
	}
	err := s.client.handler.WriteInboundBuffers([]*buf.Buffer{reply})
	if err != nil {
		s.client.logger.Debug(E.Cause(err, "write packet to device"))
	}
}

func firstAddresses(addresses []netip.Prefix) (netip.Addr, netip.Addr) {
	var inet4Address netip.Addr
	var inet6Address netip.Addr
	for _, prefix := range addresses {
		if prefix.Addr().Is4() && !inet4Address.IsValid() {
			inet4Address = prefix.Addr()
		} else if prefix.Addr().Is6() && !inet6Address.IsValid() {
			inet6Address = prefix.Addr()
		}
	}
	return inet4Address, inet6Address
}

func prefixesContain(prefixes []netip.Prefix, address netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
		return prefix.Contains(address)
	})
}

func RoutesContain(routes []AddressRange, address netip.Addr, protocol uint8) bool {
	return slices.ContainsFunc(routes, func(route AddressRange) bool {
		return route.Contains(address) && (route.Protocol == 0 || route.Protocol == protocol || isControlProtocol(protocol))
	})
}

func rangesContain(routes []AddressRange, address netip.Addr) bool {
	return slices.ContainsFunc(routes, func(route AddressRange) bool {
		return route.Contains(address)
	})
}
