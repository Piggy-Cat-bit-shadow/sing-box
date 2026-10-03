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

	// effectiveStrategy is the family policy that actually applies, resolved ONCE from the router.
	//
	// queryOptions.Strategy is what the CALLER said, and AsIS means "use the resolver's default" -
	// which only the router knows. Every decision in this package that depends on family policy
	// must use this value, not the raw one, or a strict policy can be walked around by whichever
	// layer happens to read the caller's literal AsIS.
	//
	// It is resolved lazily by effectiveFamilyStrategy so a nil or non-reporting router degrades to
	// the caller's value rather than to an arbitrary one.
	effectiveStrategy     C.DomainStrategy
	effectiveStrategyOnce sync.Once
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
		// A literal destination is the PRIMARY endpoint and dials immediately.
		//
		// Recovery may add candidates from the sniffed domain, but it must never be a
		// prerequisite for reaching the address the application already chose. An earlier
		// version looked the domain up synchronously first, so a literal IP - which used to
		// connect at once - waited on a full DNS resolution, and a slow or hanging resolver
		// delayed or broke a connection that needed no DNS at all.
		//
		// The application's address wins for a concrete reason: it may come from the
		// application's own DNS cache, a hosts file, split-horizon or enterprise DNS, a CDN
		// selection, or an earlier legitimate answer. Re-resolving the sniffed name can return
		// a DIFFERENT address for the same name, and that must never displace the endpoint the
		// application actually selected.
		return d.dialLiteralWithRecovery(ctx, network, destination)
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
	// The EFFECTIVE strategy: AsIS means "the resolver's default", and planning with the raw
	// value would discard the preference the resolver applied.
	strategy := d.effectiveFamilyStrategy()

	dualStackRouter, supportsStreaming := d.router.(adapter.DNSDualStackRouter)
	if !supportsStreaming {
		addresses, err := d.router.Lookup(lookupCtx, destination.Fqdn, d.queryOptions)
		if err != nil {
			return nil, err
		}
		return d.raceCandidates(ctx, network, destination, addresses, strategy)
	}

	// resolutionCtx owns everything that exists only to feed THIS connection's race.
	//
	// The caller's ctx is the connection's lifetime, which can outlive the race by a long way -
	// the connection is returned and used for minutes. Without a narrower context, a late DNS
	// answer would still be trying to hand a candidate to a scheduler that has already returned:
	// the send blocks, and the feeder and lookup goroutines stay parked on it until the
	// connection eventually closes.
	//
	// Cancelling on the way out means the whole producer set stops the moment the winner is
	// known, whether the sender is blocked on a channel, holding a grace timer, or still inside
	// the resolver.
	resolutionCtx, cancelResolution := context.WithCancel(ctx)
	defer cancelResolution()

	// The channel is unbuffered and owned here: the publisher blocks until the scheduler takes
	// a candidate, so no goroutine outlives the race holding a result nobody will read.
	candidates := make(chan dualStackCandidate)

	// lookupDone carries the resolver's own error exactly once, so a DNS failure can be
	// surfaced instead of being replaced by a generic "no candidates".
	//
	// Buffered, and never closed: the resolver always sends exactly one value, and closing it
	// would make the failure-path read indistinguishable from a nil error.
	lookupDone := make(chan error, 1)

	// lookupFinished closes when the resolver goroutine has returned, whether or not it published
	// anything. It distinguishes "still resolving" from "finished with nothing to say", which the
	// published-result signal alone cannot express.
	lookupFinished := make(chan struct{})

	// producers tracks the two producer goroutines so the winner path can prove they have
	// exited rather than merely assuming it. A test can then assert termination deterministically
	// instead of counting goroutines and hoping.
	var producers sync.WaitGroup

	// The preferred family leads. A family is only fed to the scheduler as it arrives, so
	// without this the first family to ANSWER would take the first launch slot and "prefer
	// IPv6" would silently mean "prefer whichever replied first".
	//
	// Exactly one grace owner lives here. The non-preferred family is held for at most
	// preferredFamilyGrace before being fed through anyway, so a hung preferred family cannot
	// withhold an answer already in hand. The preferred family is never held, so when it
	// answers first the connection starts with no added delay at all.
	// The preference is decided by the EFFECTIVE strategy reported by the resolver, not by
	// d.queryOptions.Strategy.
	//
	// Strategy is frequently AsIS, which does not mean "no preference" - it means "use the DNS
	// router's default", and that default may be prefer_ipv6. Reading the raw option would treat
	// AsIS as "not PreferIPv6" and rank IPv4 first, so a resolver configured to prefer IPv6
	// would get the opposite of its configuration on every connection.
	//
	// The value arrives with the first family result, so the decision is made inside the feeder
	// rather than here. Until it is known, nothing is held back and nothing is preferred: the
	// feeder falls back to the raw option, which is correct for every non-AsIS strategy.
	preferIPv6 := strategy == C.DomainStrategyPreferIPv6
	effectiveKnown := false
	firstReady := make(chan struct{})
	var readyOnce sync.Once

	arrivals := make(chan adapter.DNSFamilyResult, 4)

	// --- producer 1: the resolver ---
	producers.Add(1)
	go func() {
		defer producers.Done()
		defer close(arrivals)

		err := dualStackRouter.LookupFamilies(resolutionCtx, destination.Fqdn, d.queryOptions,
			func(result adapter.DNSFamilyResult) {
				readyOnce.Do(func() { close(firstReady) })
				select {
				case arrivals <- result:
				case <-resolutionCtx.Done():
				}
			})
		// The error is published, not discarded. Without it a resolution failure would be
		// reported as "no dial candidates", which describes a symptom and hides the cause.
		lookupDone <- err
		close(lookupFinished)
	}()

	// --- producer 2: the feeder ---
	producers.Add(1)
	go func() {
		defer producers.Done()
		defer close(candidates)

		// graceTimer releases a held non-preferred family if the preferred one is slow. It is
		// the ONLY timer for this grace period. It is stopped on every exit path so no callback
		// outlives the feeder.
		graceTimer := time.NewTimer(preferredFamilyGrace)
		defer graceTimer.Stop()

		var (
			held        []dualStackCandidate
			graceActive bool
		)

		feed := func(candidate dualStackCandidate) bool {
			select {
			case candidates <- candidate:
				return true
			case <-resolutionCtx.Done():
				// The only exit condition is the resolution context, NOT the connection
				// context: once the race is decided this feeder must stop immediately rather
				// than waiting for a connection that may live for minutes.
				return false
			}
		}
		release := func() {
			for _, candidate := range held {
				if !feed(candidate) {
					held = nil
					graceActive = false
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
			case <-resolutionCtx.Done():
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

			// Adopt the resolver's effective preference, when the resolver reports one.
			//
			// A result that carries no effective strategy - an AsIS default, or a third-party
			// router that predates this field - must NOT silently become "prefer IPv4". AsIS
			// here means "no opinion was expressed", so the option the caller already supplied
			// is kept. That is what makes this addition backward compatible instead of a
			// behaviour change for every existing implementation.
			if !effectiveKnown {
				effectiveKnown = true
				if result.EffectiveStrategy != C.DomainStrategyAsIS {
					preferIPv6 = result.EffectiveStrategy == C.DomainStrategyPreferIPv6
				}
			}

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
		}
	}()

	// Wait for the first result so a completely failing lookup is reported as a lookup error
	// rather than as an empty dial.
	//
	// # Why the producer's own completion is also watched
	//
	// DNSDualStackRouter is an OPTIONAL interface, and an implementation may report a failure by
	// RETURNING AN ERROR without ever calling publish - which is an ordinary way to say "this
	// lookup failed". Waiting only for a published result meant such a router blocked the dial
	// until the caller's entire context expired, turning an immediate DNS failure into a connect
	// timeout.
	//
	// lookupFinished closes when the resolver goroutine is done, so an error with no results is
	// acted on at once rather than waited out. A context ending first is still honoured.
	select {
	case <-firstReady:
	case <-lookupFinished:
		// The resolver returned without publishing anything. Let the terminal handling below
		// report its error, which is more informative than a timeout.
	case <-ctx.Done():
		cancelResolution()
		producers.Wait()
		return nil, ctx.Err()
	}

	plan := planCandidates(nil, netip.Addr{}, strategy)
	scheduler := d.newScheduler()
	conn, _, err := scheduler.dialWithLateCandidates(ctx, plan, candidates,
		func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
			return d.dialer.DialContext(attemptCtx, network, M.SocksaddrFrom(address, destination.Port))
		})

	// Stop the producers before returning, whatever the outcome. A winner must not leave a
	// lookup running, and the wait makes that a guarantee rather than an expectation.
	cancelResolution()
	producers.Wait()

	if err != nil {
		// Now that both producers have exited, lookupDone holds the resolver's verdict (or is
		// empty if it had not finished sending). A resolution failure is the more informative
		// error: "no dial candidates" describes the symptom and hides that DNS itself failed.
		//
		// It is consulted ONLY on the failure path. If a candidate won, a late DNS error must
		// not turn a working connection into a failed one.
		select {
		case lookupErr := <-lookupDone:
			if lookupErr != nil {
				return nil, E.Cause(lookupErr, "resolve ", destination.Fqdn)
			}
		default:
		}
		return nil, err
	}
	return conn, nil
}

// raceCandidates dials the planned candidates through the shared scheduler.
//
// Every racing path in this file goes through here, so candidate ordering, scheduling, family
// health and loser cleanup cannot differ between a hostname and a recovered literal.
// dialLiteralWithRecovery dials a literal destination immediately, with domain recovery as a
// parallel fallback rather than a precondition.
//
// # The shape
//
//	original address ──── dial immediately ────────────────────┐
//	                                                           ├── first success wins
//	sniffed-domain lookup ──── recovered candidates ───────────┘
//
// The original attempt is not deferred by even one syscall of DNS work. Recovery runs
// concurrently and its candidates are dialled only if it produces them in time.
//
// # Failure handling, deliberately simple
//
// If the original address fails and recovery has produced candidates, those are tried. If
// recovery produced nothing, the original error is returned. There is no dynamic racing of the
// two streams: an earlier design attempt in this area grew a second scheduler, and the
// complexity was not worth it. Correctness and "the original dial is never blocked" come first.
//
// # Bounded
//
// One goroutine for the lookup, cancelled when the original succeeds. The recovered dial uses
// the same bounded scheduler as every other racing path, so its losers are closed and its
// winner is unique.
// effectiveFamilyStrategy reports the family policy that actually applies to this dialer.
//
// AsIS means "the resolver's default". A router that can report it is asked once; anything else
// keeps the caller's value, which is the safe degradation - a caller that said ipv4_only still
// gets ipv4_only, and a caller that said AsIS with a router that cannot answer is treated as
// having no family restriction rather than an invented one.
func (d *resolveDialer) effectiveFamilyStrategy() C.DomainStrategy {
	d.effectiveStrategyOnce.Do(func() {
		strategy := d.queryOptions.Strategy
		if strategy != C.DomainStrategyAsIS {
			d.effectiveStrategy = strategy
			return
		}
		if resolver, isResolver := d.router.(adapter.DNSStrategyResolver); isResolver && d.router != nil {
			strategy = resolver.ResolveStrategy(d.queryOptions)
		}
		d.effectiveStrategy = strategy
	})
	return d.effectiveStrategy
}

func (d *resolveDialer) dialLiteralWithRecovery(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	originalCtx, cancelOriginal := context.WithCancel(ctx)
	defer cancelOriginal()

	original := make(chan literalDialResult, 1)

	// A hard single-family strategy applies to the ORIGINAL address too.
	//
	// planCandidates enforces "only means only" by dropping the other family, but the original
	// attempt is dialled directly rather than through the planner - so without this check a
	// literal IPv6 address would be dialled under ipv4_only, silently turning a strict policy
	// into a suggestion. The original is preferred, not exempt.
	// The EFFECTIVE strategy, not the caller's raw value. See effectiveFamilyStrategy.
	originalAllowed := addressAllowedByStrategy(destination.Addr, d.effectiveFamilyStrategy())
	if originalAllowed {
		go func() {
			conn, err := d.dialer.DialContext(originalCtx, network, destination)
			original <- literalDialResult{conn: conn, err: err}
		}()
	} else {
		// Nothing to dial for the original. Report the exclusion rather than hanging on a
		// channel that will never receive.
		original <- literalDialResult{err: E.New("destination ", destination.Addr, " excluded by strategy ", strategyName(d.effectiveFamilyStrategy()))}
	}

	// Recovery runs concurrently. Its result channel is buffered and it always sends exactly
	// once, so the goroutine cannot outlive this function blocked on an unread channel.
	recovered := make(chan []netip.Addr, 1)
	go func() {
		addresses := d.recoverCandidates(ctx, destination)
		recovered <- addresses
	}()

	select {
	case result := <-original:
		if result.err == nil {
			return result.conn, nil
		}
		// The original failed. Recovery still gets its chance.
		//
		// This used to read the recovery channel NON-BLOCKINGLY and, finding it empty, return the
		// original's error immediately. A lookup that had not finished yet was therefore treated
		// as "recovery found nothing", and a healthy recovered candidate was never tried - which
		// discards the entire purpose of recovery, because a fast failure is exactly when a
		// fallback is most useful.
		//
		// The wait is bounded by the caller's context and by the recovery lookup's own
		// cancellation, so this cannot hang: recoverCandidates honours both.
		select {
		case addresses := <-recovered:
			return d.dialRecoveredOrReport(ctx, network, destination, addresses, result.err)
		case <-ctx.Done():
			return nil, result.err
		}

	case addresses := <-recovered:
		if len(addresses) == 0 {
			// Recovery found nothing; the original attempt is the only candidate, so wait for
			// it rather than returning early.
			result := <-original
			if result.err != nil {
				return nil, result.err
			}
			return result.conn, nil
		}

		// Recovery produced candidates while the original is STILL in flight. The original
		// remains preferred, so give it a bounded head start rather than waiting for it
		// indefinitely.
		//
		// Waiting unconditionally was a starvation bug: against a blackholed original the wait
		// consumed the whole context, so by the time the fallback was reached there was no
		// budget left to dial with. The recovered candidates - the entire point of doing
		// recovery - could never actually be used.
		//
		// The head start is the connection fallback delay, the same interval that staggers
		// candidates elsewhere in this package, so a healthy original still wins outright and a
		// hanging one does not hold the fallback hostage.
		fallbackTimer := time.NewTimer(d.fallbackDelayOrDefault())
		defer fallbackTimer.Stop()

		select {
		case result := <-original:
			if result.err == nil {
				return result.conn, nil
			}
			return d.dialRecoveredOrReport(ctx, network, destination, addresses, result.err)

		case <-fallbackTimer.C:
			// The original has had its head start and is still pending. Dial the recovered
			// candidates in parallel with it; the first success wins and the other attempt is
			// cancelled by the deferred cancelOriginal.
			return d.raceWithPendingOriginal(ctx, network, destination, addresses, original, cancelOriginal)
		}
	}
}

// dialRecoveredOrReport dials recovered candidates, or reports the original error when there
// are none.
func (d *resolveDialer) dialRecoveredOrReport(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr, originalErr error) (net.Conn, error) {
	if len(addresses) == 0 {
		return nil, originalErr
	}
	// The EFFECTIVE strategy, and the original is merged only if that strategy admits it.
	//
	// Merging unconditionally re-introduced an address the policy had just excluded: with
	// ipv4_only and an IPv6 original, MergeOriginalDestination put the IPv6 address back into the
	// plan because it has its own rule for AsIS ("keep the caller's family first") and cannot tell
	// that the effective policy already answered the question.
	strategy := d.effectiveFamilyStrategy()
	original := destination.Addr
	if !addressAllowedByStrategy(original, strategy) {
		original = netip.Addr{}
	}
	candidates := MergeOriginalDestination(original, addresses, strategy)
	conn, err := d.raceCandidatesExcluding(ctx, network, destination, candidates, original, strategy)
	if err != nil {
		// Both the original endpoint and every recovered candidate failed. The original error
		// is the more useful one to surface: it is the endpoint the application asked for.
		return nil, originalErr
	}
	return conn, nil
}

func (d *resolveDialer) raceCandidates(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr, strategy C.DomainStrategy) (net.Conn, error) {
	return d.raceCandidatesExcluding(ctx, network, destination, addresses, destination.Addr, strategy)
}

// raceCandidatesExcluding races candidates without treating the given address as the original.
//
// planCandidates normally puts the original first, which is right when this is the only attempt.
// When the original is already running as its own owned attempt, passing it here would dial it a
// second time; passing an invalid address excludes it while keeping the planner's ordering for
// everything else.
func (d *resolveDialer) raceCandidatesExcluding(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr, original netip.Addr, strategy C.DomainStrategy) (net.Conn, error) {
	plan := planCandidates(addresses, original, strategy)
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
		// preferIPv6 comes from the EFFECTIVE strategy. Deriving it from the raw value made a
		// router default of prefer_ipv6 invisible here, so the parallel dialler started with the
		// IPv4 interface.
		preferIPv6 := d.effectiveFamilyStrategy() == C.DomainStrategyPreferIPv6
		return DialParallelNetwork(ctx, d.dialer, network, destination, addresses, preferIPv6, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
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

// addressAllowedByStrategy reports whether a hard single-family strategy admits this address.
//
// Only the strict strategies exclude. AsIS, PreferIPv4 and PreferIPv6 all admit both families,
// so the original address is always dialled under them.
func addressAllowedByStrategy(address netip.Addr, strategy C.DomainStrategy) bool {
	if !address.IsValid() {
		return true
	}
	is4 := address.Is4() || address.Is4In6()
	switch strategy {
	case C.DomainStrategyIPv4Only:
		return is4
	case C.DomainStrategyIPv6Only:
		return !is4
	default:
		return true
	}
}

func strategyName(strategy C.DomainStrategy) string {
	switch strategy {
	case C.DomainStrategyIPv4Only:
		return "ipv4_only"
	case C.DomainStrategyIPv6Only:
		return "ipv6_only"
	case C.DomainStrategyPreferIPv4:
		return "prefer_ipv4"
	case C.DomainStrategyPreferIPv6:
		return "prefer_ipv6"
	default:
		return "as_is"
	}
}

// raceWithPendingOriginal dials recovered candidates while the original attempt is still in
// flight, and returns whichever succeeds first.
//
// # Why both run at once
//
// The original has already had a full fallback delay and has not answered. Continuing to wait
// for it - the previous behaviour - meant a blackholed original consumed the caller's entire
// context and the fallback could never connect. Racing them gives the preferred endpoint every
// chance to win while guaranteeing the recovered candidates get to try.
//
// # Ownership
//
// Exactly one connection is returned. This is enforced, not asserted:
//
//	both attempts run under raceCtx
//	the loser is cancelled
//	the loser's worker is WAITED for before returning
//	a loser that succeeded anyway is closed
//
// # Why a child context and a wait, rather than cancelling and hoping
//
// The earlier version ran the recovered race on the CALLER's context and kept no handle on its
// worker. When the original won, the recovered attempt therefore kept dialling for as long as
// the connection lived - and if it eventually succeeded, that connection was written to a
// buffered channel nobody would ever read and was leaked, open, with no owner.
//
// Cancelling is not sufficient on its own either: a dial can have already established a
// connection before the cancellation is observed, so the worker must be waited for and its
// result inspected. That is what makes "the loser is closed" true rather than likely.
//
// The wait is bounded by the loser's own attempt, which is itself bounded by raceCtx and the
// attempt timeout - so this cannot block on a dial that ignores cancellation forever.
func (d *resolveDialer) raceWithPendingOriginal(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr, original <-chan literalDialResult, cancelOriginal context.CancelFunc) (net.Conn, error) {
	// raceCtx governs BOTH attempts. Cancelling it stops the loser's dial; waiting on the
	// WaitGroup afterwards proves the loser is no longer running.
	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	recoveredResult := make(chan literalDialResult, 1)

	var workers sync.WaitGroup

	// --- attempt 1: the recovered candidates ---
	//
	// The original is deliberately NOT merged into this list. It is already running as its own
	// attempt, owned by the caller, so including it here dialled the same address twice: once as
	// the caller's attempt and once as this plan's first candidate. That wasted an attempt and,
	// because the plan is staggered, pushed the healthy recovered family behind a duplicate of the
	// address that was already failing - roughly doubling how long recovery took.
	//
	// planCandidates still puts the original first when one is supplied, and the literal path
	// relies on that order for the single-attempt case; this race is the one place where the
	// original must be excluded, because here it has its own owner.
	workers.Add(1)
	go func() {
		defer workers.Done()
		strategy := d.effectiveFamilyStrategy()
		conn, err := d.raceCandidatesExcluding(raceCtx, network, destination, addresses, netip.Addr{}, strategy)
		recoveredResult <- literalDialResult{conn: conn, err: err}
	}()

	var (
		winner   net.Conn
		firstErr error
		haveErr  bool
	)

	// The original is not owned by this function; its worker belongs to the caller and is
	// cancelled through cancelOriginal. It reports on the `original` channel, which is buffered,
	// so a late result cannot block it and cannot be lost.
	for winner == nil {
		select {
		case result := <-original:
			if result.err == nil {
				winner = result.conn
			} else if !haveErr {
				firstErr = result.err
				haveErr = true
			}
		case result := <-recoveredResult:
			if result.err == nil {
				winner = result.conn
			} else if !haveErr {
				firstErr = result.err
				haveErr = true
			}
			// The recovered attempt has reported. Whether it won or lost, it is finished.
		case <-raceCtx.Done():
			cancelOriginal()
			cancelRace()
			workers.Wait()
			d.closeLateRecovered(recoveredResult)
			return nil, raceCtx.Err()
		}

		if winner != nil {
			break
		}
	}

	// A winner exists. Stop the other side and make sure nothing survives this function.
	cancelOriginal()
	cancelRace()

	// Wait for the recovered worker to finish, then take ownership of anything it produced.
	// Without this wait, "the loser is closed" would be a claim about a goroutine that may not
	// have run yet.
	workers.Wait()
	d.closeLateRecovered(recoveredResult)

	if winner != nil {
		return winner, nil
	}
	if haveErr {
		return nil, firstErr
	}
	// Neither attempt produced a connection and neither reported an error, which can only
	// happen when the race context ended underneath them.
	return nil, raceCtx.Err()
}

// closeLateRecovered closes a recovered connection that arrived after the race was decided.
//
// The channel is buffered with capacity one and the worker sends exactly once, so this is a
// non-blocking read: either the result is already there, or the worker exited without producing
// one. There is no third case, and no detached cleanup goroutine is needed.
func (d *resolveDialer) closeLateRecovered(recoveredResult <-chan literalDialResult) {
	select {
	case result := <-recoveredResult:
		if result.conn != nil {
			result.conn.Close()
		}
	default:
	}
}

// literalDialResult is one attempt's outcome on the literal-recovery path.
type literalDialResult struct {
	conn net.Conn
	err  error
}

// fallbackDelayOrDefault returns the delay that staggers connection candidates.
//
// # Why the default is the connection fallback delay, not the DNS grace
//
// This used to return preferredFamilyGrace - the 50ms window that governs how long the DNS layer
// holds a non-preferred address family waiting for the preferred one. That is a RESOLUTION
// timescale: it decides which family's answer is fed to the dialer first.
//
// The value returned here is a CONNECTION timescale: how long the original literal attempt gets
// before the recovered candidates start. Borrowing the resolution constant conflated two
// different decisions and made literal recovery start roughly six times sooner than the rest of
// the dialer staggers candidates, so a healthy-but-slow original could be raced before it had a
// realistic chance - losing the preference the application asked for.
//
// The connection timescale already has a definition in this project: N.DefaultFallbackDelay,
// the same interval the candidate scheduler uses. Reusing it keeps one meaning for "stagger a
// connection attempt" and avoids inventing a third constant that would drift from both.
func (d *resolveDialer) fallbackDelayOrDefault() time.Duration {
	if d.fallbackDelay > 0 {
		return d.fallbackDelay
	}
	return N.DefaultFallbackDelay
}
