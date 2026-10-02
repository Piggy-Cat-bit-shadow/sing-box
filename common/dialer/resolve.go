package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var (
	_ N.Dialer                = (*resolveDialer)(nil)
	_ ParallelInterfaceDialer = (*resolveParallelNetworkDialer)(nil)
)

type ResolveDialer interface {
	N.Dialer
	QueryOptions() adapter.DNSQueryOptions
}

type ParallelInterfaceResolveDialer interface {
	ParallelInterfaceDialer
	QueryOptions() adapter.DNSQueryOptions
}

type resolveDialer struct {
	transport     adapter.DNSTransportManager
	router        adapter.DNSRouter
	dialer        N.Dialer
	parallel      bool
	server        string
	initOnce      sync.Once
	initErr       error
	queryOptions  adapter.DNSQueryOptions
	fallbackDelay time.Duration
}

func NewResolveDialer(ctx context.Context, dialer N.Dialer, parallel bool, server string, queryOptions adapter.DNSQueryOptions, fallbackDelay time.Duration) ResolveDialer {
	if parallelDialer, isParallel := dialer.(ParallelInterfaceDialer); isParallel {
		return &resolveParallelNetworkDialer{
			resolveDialer{
				transport:     service.FromContext[adapter.DNSTransportManager](ctx),
				router:        service.FromContext[adapter.DNSRouter](ctx),
				dialer:        dialer,
				parallel:      parallel,
				server:        server,
				queryOptions:  queryOptions,
				fallbackDelay: fallbackDelay,
			},
			parallelDialer,
		}
	}
	return &resolveDialer{
		transport:     service.FromContext[adapter.DNSTransportManager](ctx),
		router:        service.FromContext[adapter.DNSRouter](ctx),
		dialer:        dialer,
		parallel:      parallel,
		server:        server,
		queryOptions:  queryOptions,
		fallbackDelay: fallbackDelay,
	}
}

type resolveParallelNetworkDialer struct {
	resolveDialer
	dialer ParallelInterfaceDialer
}

func (d *resolveDialer) initialize() error {
	d.initOnce.Do(d.initServer)
	return d.initErr
}

func (d *resolveDialer) initServer() {
	if d.server == "" {
		return
	}
	transport, loaded := d.transport.Transport(d.server)
	if !loaded {
		d.initErr = E.New("domain resolver not found: " + d.server)
		return
	}
	d.queryOptions.Transport = transport
}

func (d *resolveDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		// A literal destination. It may still be worth recovering the other address family:
		// the application has usually already resolved the name, so a connection to one
		// address has nothing to fall back to if that address's family is broken. Sniffing
		// recovered the domain; this turns it back into candidates.
		//
		// Recovery is refused when it does not apply, so an unusual situation degrades to the
		// previous single-candidate dial rather than to a surprising one.
		recovered := d.recoverCandidates(ctx, destination)
		if len(recovered) == 0 {
			return d.dialer.DialContext(ctx, network, destination)
		}
		// The original destination stays a candidate, ordered by the shared planner so the
		// configured family preference survives the recovery.
		strategy := d.queryOptions.Strategy
		candidates := MergeOriginalDestination(destination.Addr, recovered, strategy)
		return d.raceCandidates(ctx, network, destination, candidates, strategy)
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
	if err != nil {
		return nil, err
	}
	if !d.parallel {
		// parallel=false is an explicit request for serial behaviour, used by callers that
		// dial one bootstrap address at a time. It is NOT "the old implementation", so it
		// keeps its meaning: no racing, no fallback delay, resolver order preserved.
		return N.DialSerial(ctx, d.dialer, network, destination, addresses)
	}
	// A hostname now takes the SAME candidate planner and scheduler as a recovered literal.
	// Previously this branch called N.DialParallel, which split candidates into family groups
	// and iterated serially inside each - so a hostname did not get interleaving, same-family
	// stagger, the unified error aggregation or family health. Two implementations of one
	// policy is how a fix lands on one path and not the other.
	return d.raceCandidates(ctx, network, destination, addresses, d.queryOptions.Strategy)
}

// raceCandidates dials the planned candidates through the shared scheduler.
//
// Every racing path in this file goes through here, so candidate ordering, scheduling, family
// health and loser cleanup cannot differ between a hostname and a recovered literal.
func (d *resolveDialer) raceCandidates(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr, strategy C.DomainStrategy) (net.Conn, error) {
	plan := planCandidates(addresses, destination.Addr, strategy)
	if len(plan.candidates) == 0 {
		return nil, E.New("no dial candidates for ", destination)
	}
	scheduler := d.newScheduler()
	conn, _, err := scheduler.dial(ctx, plan, func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
		return d.dialer.DialContext(attemptCtx, network, M.SocksaddrFrom(address, destination.Port))
	})
	return conn, err
}

// newScheduler builds a scheduler bound to this dialer's family health.
//
// When the underlying dialer owns health - the production case - the verdict survives across
// connections instead of being relearned every time. The fallback keeps the previously
// health-less behaviour for dialers that have no state to share, rather than inventing a
// per-connection one that would never accumulate history.
func (d *resolveDialer) newScheduler() *candidateScheduler {
	if owner, isOwner := d.dialer.(familyHealthOwner); isOwner {
		return owner.newDualStackScheduler(d.fallbackDelay)
	}
	return &candidateScheduler{fallbackDelay: d.fallbackDelay}
}

// familyHealthOwner is implemented by dialers that own long-lived family health.
type familyHealthOwner interface {
	newDualStackScheduler(fallbackDelay time.Duration) *candidateScheduler
}

func (d *resolveDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return d.dialer.ListenPacket(ctx, destination)
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
	if err != nil {
		return nil, err
	}
	conn, destinationAddress, err := N.ListenSerial(ctx, d.dialer, destination, addresses)
	if err != nil {
		return nil, err
	}
	return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
}

func (d *resolveDialer) QueryOptions() adapter.DNSQueryOptions {
	return d.queryOptions
}

func (d *resolveDialer) Upstream() any {
	return d.dialer
}

func (d *resolveParallelNetworkDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return d.dialer.DialContext(ctx, network, destination)
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
	if err != nil {
		return nil, err
	}
	if fallbackDelay == 0 {
		fallbackDelay = d.fallbackDelay
	}
	if d.parallel {
		return DialParallelNetwork(ctx, d.dialer, network, destination, addresses, d.queryOptions.Strategy == C.DomainStrategyPreferIPv6, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	} else {
		return DialSerialNetwork(ctx, d.dialer, network, destination, addresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
}

func (d *resolveParallelNetworkDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return d.dialer.ListenPacket(ctx, destination)
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
	if err != nil {
		return nil, err
	}
	if fallbackDelay == 0 {
		fallbackDelay = d.fallbackDelay
	}
	conn, destinationAddress, err := ListenSerialNetworkPacket(ctx, d.dialer, destination, addresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
}

func (d *resolveParallelNetworkDialer) QueryOptions() adapter.DNSQueryOptions {
	return d.queryOptions
}

func (d *resolveParallelNetworkDialer) Upstream() any {
	return d.dialer
}
