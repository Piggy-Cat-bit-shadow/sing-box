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
	if !d.parallel {
		// parallel=false is an explicit request for serial behaviour, used by callers that
		// dial one bootstrap address at a time. It is NOT "the old implementation", so it
		// keeps its meaning: no racing, no fallback delay, resolver order preserved.
		ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
		addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, d.dialer, network, destination, addresses)
	}
	// A hostname takes the SAME candidate planner and scheduler as a recovered literal.
	// Previously this branch called N.DialParallel, which split candidates into family groups
	// and iterated serially inside each - so a hostname did not get interleaving, same-family
	// stagger, the unified error aggregation or family health. Two implementations of one
	// policy is how a fix lands on one path and not the other.
	return d.raceResolvedName(ctx, network, destination)
}

// raceResolvedName resolves a hostname and races the candidates, letting a late family join.
//
// # Why the family stream matters here
//
// A and AAAA answer independently and one is often much slower. Waiting for both before racing
// means the connection waits for the slow family; racing a list captured after a partial answer
// means the family that finally arrives cannot participate. Streaming lets the first family
// start the connection while the second joins the race when it lands.
//
// # Fallback
//
// A router that does not implement the optional capability is resolved with the ordinary
// complete lookup, which is the previous behaviour. That keeps third-party and test routers
// working rather than requiring them to implement a new interface.
func (d *resolveDialer) raceResolvedName(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	lookupCtx := log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	strategy := d.queryOptions.Strategy

	dualStackRouter, supportsStreaming := d.router.(adapter.DNSDualStackRouter)
	if !supportsStreaming {
		addresses, err := d.router.Lookup(lookupCtx, destination.Fqdn, d.queryOptions)
		if err != nil {
			return nil, err
		}
		return d.raceCandidates(ctx, network, destination, addresses, strategy)
	}

	// The channel is unbuffered and owned here: the publisher blocks until the scheduler takes
	// a candidate, so no goroutine outlives the race holding a result nobody will read.
	candidates := make(chan dualStackCandidate)

	// The preferred family leads. A family is only fed to the scheduler as it arrives, so
	// without this the first family to ANSWER would take the first launch slot and "prefer
	// IPv6" would silently mean "prefer whichever replied first".
	//
	// Exactly one grace owner lives here. The non-preferred family is held for at most
	// preferredFamilyGrace before being fed through anyway, so a hung preferred family cannot
	// withhold an answer already in hand. The preferred family is never held, so when it
	// answers first the connection starts with no added delay at all.
	preferIPv6 := strategy == C.DomainStrategyPreferIPv6
	firstReady := make(chan struct{})
	var readyOnce sync.Once

	// Arrivals are handed to one feeding goroutine over a channel, so the held buffer has a
	// single owner and needs no lock. The callback only deposits.
	type arrival struct {
		result adapter.DNSFamilyResult
	}
	arrivals := make(chan adapter.DNSFamilyResult, 4)

	go func() {
		defer close(candidates)

		// graceTimer releases a held non-preferred family if the preferred one is slow. It is
		// the ONLY timer for this grace period; the resolution path no longer holds results on
		// its own, so the maximum delay from this mechanism is exactly preferredFamilyGrace.
		graceTimer := time.NewTimer(preferredFamilyGrace)
		defer graceTimer.Stop()

		var (
			held        []dualStackCandidate
			graceActive bool
			closed      bool
		)

		feed := func(candidate dualStackCandidate) bool {
			select {
			case candidates <- candidate:
				return true
			case <-ctx.Done():
				return false
			}
		}
		release := func() {
			for _, candidate := range held {
				if !feed(candidate) {
					return
				}
			}
			held = nil
			graceActive = false
		}

		for {
			var (
				arrivalValue adapter.DNSFamilyResult
				haveArrival  bool
				graceSignal  <-chan time.Time
			)
			if graceActive {
				graceSignal = graceTimer.C
			}
			select {
			case <-ctx.Done():
				return
			case arrivalValue, haveArrival = <-arrivals:
				if !haveArrival {
					// Resolution finished. Publish anything held, so a family that answered
					// just before completion is not discarded.
					release()
					return
				}
			case <-graceSignal:
				release()
				continue
			}

			result := arrivalValue
			if len(result.Addresses) == 0 {
				continue
			}

			batch := make([]dualStackCandidate, 0, len(result.Addresses))
			for _, address := range result.Addresses {
				batch = append(batch, dualStackCandidate{
					address: unmapAddress(address),
					family:  classifyAddress(address),
				})
			}

			if result.IPv6 == preferIPv6 {
				// The preferred family is the reason to wait, so once it arrives nothing is
				// held back: this is what keeps a preferred-first answer at zero added delay.
				release()
				for _, candidate := range batch {
					if !feed(candidate) {
						return
					}
				}
				continue
			}

			if !graceActive {
				// No grace running: either it already expired, or this is the first arrival
				// and it becomes the thing the grace protects against a slow preferred family.
				graceActive = true
				graceTimer.Reset(preferredFamilyGrace)
			}
			held = append(held, batch...)
			_ = closed
		}
	}()

	go func() {
		defer close(arrivals)
		_ = dualStackRouter.LookupFamilies(lookupCtx, destination.Fqdn, d.queryOptions, func(result adapter.DNSFamilyResult) {
			readyOnce.Do(func() { close(firstReady) })
			select {
			case arrivals <- result:
			case <-ctx.Done():
			}
		})
	}()

	// Wait for the first result so a completely failing lookup is reported as a lookup error
	// rather than as an empty dial. A context ending first is also honoured.
	select {
	case <-firstReady:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	plan := planCandidates(nil, netip.Addr{}, strategy)
	scheduler := d.newScheduler()
	conn, _, err := scheduler.dialWithLateCandidates(ctx, plan, candidates,
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return d.dialer.DialContext(attemptCtx, network, M.SocksaddrFrom(address, destination.Port))
		})
	if err != nil {
		return nil, err
	}
	return conn, nil
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

// preferredFamilyGrace bounds how long a non-preferred family's addresses wait for the
// preferred family to answer.
//
// It is deliberately short and deliberately NOT the connection fallback delay. That delay
// staggers connection attempts; this one bounds how long an answer already in hand is withheld
// in the hope that the preferred family is about to arrive. The maximum delay this mechanism
// can add is exactly this value, because it has a single owner.
const preferredFamilyGrace = 50 * time.Millisecond
