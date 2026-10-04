package group

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterLoadBalance(registry *outbound.Registry) {
	outbound.Register[option.LoadBalanceOutboundOptions](registry, C.TypeLoadBalance, NewLoadBalance)
}

var (
	_ adapter.OutboundGroup          = (*LoadBalance)(nil)
	_ adapter.FlowAwareOutboundGroup = (*LoadBalance)(nil)
	_ adapter.Referrer               = (*LoadBalance)(nil)
)

// LoadBalance distributes new flows over its members and keeps each flow on the member it
// was given.
//
// # What it is
//
// A control-plane object. It chooses a member and then hands the flow to that member's own
// data plane; it never wraps a connection, never sees a byte and never touches the copy,
// splice or batch paths. The group is gone by the time the connection exists, which is why
// a flow through it keeps every property the leaf outbound has.
//
// # What it is not
//
// Not bonding, not striping, not packet-level switching, not a session pool. One flow is
// one member for the flow's whole life. Two flows to the same destination may take
// different members, and one flow never takes two.
//
// # Selection ownership
//
// A balancing choice is a side effect: the round-robin cursor moves, an affinity pin is
// written. The route path asks for a choice twice for some flows - once speculatively
// during the pre-match preview, whose result is discarded when the connection is created,
// and once for the connection that is actually established. Only the second may consume
// state, which is what the commit parameter on SelectForFlow carries. A speculative choice
// answers with the member the next committed choice would use, without moving anything.
type LoadBalance struct {
	outbound.Adapter
	ctx      context.Context
	outbound adapter.OutboundManager
	logger   log.ContextLogger
	router   adapter.Router

	tags           []string
	strategy       string
	url            string
	expectedStatus string
	interval       time.Duration
	tolerance      uint16
	idleTimeout    time.Duration

	history *urltest.HistoryStorage

	// cursor is the round-robin position, counted in committed selections.
	//
	// It is a counter rather than an index into a member list: the candidate set is a
	// function of health and of the network, so an index would have to be re-derived
	// against a set that may have changed between two selections. Counting committed
	// choices and reducing modulo the CURRENT candidate count is what makes the
	// distribution even without a lock, and it wraps harmlessly at the uint64 bound.
	cursor atomic.Uint64

	affinity *loadBalanceAffinity

	// members is the configured member list in configuration order, resolved once at
	// start. It is published atomically and never mutated afterwards, so a selection
	// reads it without a lock. It is read in configuration order for round-robin and as
	// the bucket space for hashing, which must not depend on health: a hash whose bucket
	// count moved with liveness would re-map every flow whenever any member failed.
	members atomic.Pointer[[]adapter.Outbound]

	// health measures the members when a URL is configured. It is the urltest engine,
	// used only as a measurement source: its own Select is never called, because
	// "the group's best node" is a different question from "this flow's member", and
	// answering the second with the first is how a balancing group degenerates into a
	// single node.
	health      atomic.Pointer[URLTestGroup]
	healthScope urltest.MeasurementScope

	// networks is the union of the member networks, computed at start. A parent group
	// filters candidates by Network(), so advertising the union is what lets a
	// loadbalance group holding both a TCP-only and a TCP+UDP member be considered for
	// a UDP flow at all; the per-flow check inside selection is what then refuses to
	// hand that flow to the TCP-only member.
	networks []string

	interruptGroup *interrupt.Group
	lifecycle      sync.Mutex
	closed         bool
}

func NewLoadBalance(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.LoadBalanceOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds) == 0 {
		return nil, E.New("missing tags")
	}
	strategy := options.Strategy
	if strategy == "" {
		// Round-robin is the default, and the divergence from the reference
		// implementation is deliberate: hashing on the destination sends every flow to
		// one site to one member, which for a client whose traffic concentrates on a
		// few sites is the opposite of what the group is for. A configuration that
		// wants the hashing behaviour states it.
		strategy = loadBalanceStrategyRoundRobin
	}
	switch strategy {
	case loadBalanceStrategyRoundRobin, loadBalanceStrategyConsistentHash, loadBalanceStrategyStickySessions:
	default:
		return nil, E.New("unknown strategy: ", strategy)
	}
	interval := time.Duration(options.Interval)
	if interval < 0 {
		return nil, E.New("interval must not be negative")
	}
	idleTimeout := time.Duration(options.IdleTimeout)
	if idleTimeout < 0 {
		return nil, E.New("idle_timeout must not be negative")
	}
	if options.URL == "" && options.ExpectedStatus != "" {
		// An expectation without a target describes nothing: nothing measures the members,
		// so there is no health to constrain. Refusing is better than accepting a
		// configuration whose only effect is to look like it checks something.
		return nil, E.New("expected_status requires url")
	}
	if options.URL != "" {
		if _, err := urltest.ParseExpectedStatus(options.ExpectedStatus); err != nil {
			return nil, E.Cause(err, "invalid expected_status")
		}
		if _, err := urltest.ParseMeasurementTarget(options.URL); err != nil {
			return nil, E.Cause(err, "invalid URL test target")
		}
	}
	loadBalance := &LoadBalance{
		Adapter:        outbound.NewAdapter(C.TypeLoadBalance, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:            ctx,
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		logger:         logger,
		router:         router,
		tags:           options.Outbounds,
		strategy:       strategy,
		url:            options.URL,
		expectedStatus: options.ExpectedStatus,
		interval:       interval,
		tolerance:      options.Tolerance,
		idleTimeout:    idleTimeout,
		history:        service.PtrFromContext[urltest.HistoryStorage](ctx),
		interruptGroup: interrupt.NewGroup(),
	}
	if strategy == loadBalanceStrategyStickySessions {
		loadBalance.affinity = newLoadBalanceAffinity(loadBalanceDefaultAffinityTTL, loadBalanceDefaultAffinityLimit)
	}
	return loadBalance, nil
}

// Network reports the union of the member networks.
func (g *LoadBalance) Network() []string {
	members := g.snapshot()
	if len(members) == 0 {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	networks := make([]string, 0, 2)
	for _, member := range members {
		for _, network := range member.Network() {
			if !common.Contains(networks, network) {
				networks = append(networks, network)
			}
		}
	}
	return networks
}

func (g *LoadBalance) All() []string {
	return g.tags
}

// References reports every member as a dependency.
//
// A selector depends on the one member it has chosen; a balancing group depends on all of
// them, because the next flow may take any. Reporting only one would let a configuration
// validate a cycle that a later flow walks straight into.
func (g *LoadBalance) References() []string {
	return g.tags
}

// Selected is the capability-free answer, and it is a pure preview.
//
// It exists because the group must satisfy adapter.OutboundGroup: callers that only know
// that interface - a control-plane listing, a parent group without flow metadata - ask
// through it. It never consumes state, because it has no flow to attribute the choice to
// and a caller that cannot say whether it owns the connection must not be able to move the
// cursor.
func (g *LoadBalance) Selected(network string) adapter.Outbound {
	return g.SelectForFlow(nil, network, false)
}

// SelectForFlow implements adapter.FlowAwareOutboundGroup.
func (g *LoadBalance) SelectForFlow(metadata *adapter.InboundContext, network string, commit bool) adapter.Outbound {
	members := g.snapshot()
	if len(members) == 0 {
		return nil
	}
	switch g.strategy {
	case loadBalanceStrategyConsistentHash:
		return g.selectByHash(members, loadBalanceDestinationKey(metadata), network, commit)
	case loadBalanceStrategyStickySessions:
		return g.selectByAffinity(members, metadata, network, commit)
	default:
		return g.selectRoundRobin(members, network, commit)
	}
}

// selectRoundRobin returns the next member in rotation.
//
// # Why the cursor is not simply an index
//
// The candidate set is not the member list: members that cannot carry this network, and -
// when a URL is configured - members with no current health evidence, are not candidates.
// An index into a set that changes between two calls would skip or repeat members. The
// cursor therefore counts committed choices and is reduced modulo the candidate count of
// THIS call, and the walk that follows visits only candidates, which is also what keeps a
// dead member from consuming a rotation slot.
func (g *LoadBalance) selectRoundRobin(members []adapter.Outbound, network string, commit bool) adapter.Outbound {
	ignoreHealth := g.noHealthyCandidate(members, network)
	candidates := g.candidateCount(members, network, ignoreHealth)
	if candidates == 0 {
		// No member can carry this network at all. The route path reports that as an
		// error; answering with a member that cannot carry the flow would be a false hit.
		return nil
	}
	var slot uint64
	if commit {
		slot = g.cursor.Add(1) - 1
	} else {
		slot = g.cursor.Load()
	}
	target := slot % uint64(candidates)
	for _, member := range members {
		if !g.isCandidate(member, network, ignoreHealth) {
			continue
		}
		if target == 0 {
			return member
		}
		target--
	}
	return g.firstCompatible(members, network)
}

// noHealthyCandidate reports whether this selection has no measured-healthy member to choose
// from, which is when health filtering is suspended.
//
// # Unknown is not dead
//
// A member with no health entry is one that has not been measured, or whose last measurement
// failed: the store cannot tell those apart, and neither can this group. Filtering both out
// is correct only while SOME member is known-good. With none, the group has nothing to go on
// and must fall back to the members that can at least carry the network, or a group whose
// probe target is unreachable - or whose first check has not finished - would answer every
// flow with its first member, which is the degeneration this feature exists to avoid.
//
// The decision is recomputed for every selection, so a member recovering becomes a candidate
// on the next flow rather than at the end of some window.
func (g *LoadBalance) noHealthyCandidate(members []adapter.Outbound, network string) bool {
	if g.url == "" {
		return false
	}
	for _, member := range members {
		if !common.Contains(member.Network(), network) {
			continue
		}
		if g.healthy(member, network) {
			return false
		}
	}
	return true
}

// selectByHash pins a destination identity to a member.
//
// The bucket space is the member list, NOT the candidate set, so that a member becoming
// unhealthy does not re-map the flows that were not pointing at it. When the hashed member
// is not currently a candidate the key is stepped - the same key plus one, up to a few
// times - and only then does the search become a scan.
func (g *LoadBalance) selectByHash(members []adapter.Outbound, key string, network string, commit bool) adapter.Outbound {
	if key == "" {
		// No destination identity to hash. Hashing nothing would put every such flow on
		// one member, which is the failure this guard exists to prevent; round-robin is
		// the honest answer.
		//
		// The caller's commit flag travels with the fallback: this is now a stateful
		// choice, and a preview that took it must not advance the rotation.
		return g.selectRoundRobin(members, network, commit)
	}
	hash := loadBalanceHash(key)
	buckets := int32(len(members))
	ignoreHealth := g.noHealthyCandidate(members, network)
	for i := 0; i < loadBalanceHashRetries; i++ {
		member := members[jumpHash(hash+uint64(i), buckets)]
		if g.isCandidate(member, network, ignoreHealth) {
			return member
		}
	}
	return g.firstCandidateOrCompatible(members, network, ignoreHealth)
}

// selectByAffinity pins a source and destination pair to a member for a bounded time.
//
// Health outranks affinity: a pin that points at a member which is no longer a candidate is
// not honoured, it is replaced. Otherwise a member that died would keep receiving the flows
// its pin covers until the entry expired.
func (g *LoadBalance) selectByAffinity(members []adapter.Outbound, metadata *adapter.InboundContext, network string, commit bool) adapter.Outbound {
	key := loadBalanceSessionKey(metadata)
	if key == "" {
		return g.selectRoundRobin(members, network, commit)
	}
	ignoreHealth := g.noHealthyCandidate(members, network)
	if tag, pinned := g.affinity.member(key); pinned {
		for _, member := range members {
			if member.Tag() == tag && g.isCandidate(member, network, ignoreHealth) {
				return member
			}
		}
	}
	// A cold key, or a pin whose member is gone or unhealthy. The replacement is the
	// round-robin choice, so a group whose keys are all cold still distributes evenly
	// instead of leaning on whichever member the hash happened to name.
	member := g.selectRoundRobin(members, network, commit)
	if commit && member != nil {
		g.affinity.pin(key, member.Tag())
	}
	return member
}

// isCandidate reports whether a member may serve a flow on this network right now.
func (g *LoadBalance) isCandidate(member adapter.Outbound, network string, ignoreHealth bool) bool {
	if !common.Contains(member.Network(), network) {
		return false
	}
	if g.url == "" || ignoreHealth {
		// Nothing measures the members, or nothing measured is known-good: in both cases
		// the absence of a health entry cannot mean "dead" and must not be read as one.
		return true
	}
	return g.healthy(member, network)
}

// healthy reports whether the shared health store currently holds a successful measurement
// of this member, for this group's target, on this network.
//
// The store is the one the urltest group maintains, keyed by the member's real leaf tag and
// the measurement scope. That is what makes health shared rather than duplicated: a
// loadbalance group and a urltest group over the same members and the same URL read the
// same evidence, and a member that a failed check removed from the store is not a candidate
// for either.
func (g *LoadBalance) healthy(member adapter.Outbound, network string) bool {
	if g.history == nil || g.healthScope.IsZero() {
		// No history store means no evidence can exist; treating that as unhealthy would
		// let the group refuse every flow in a build without the storage service.
		return true
	}
	return g.history.LoadURLTestHistoryFor(RealTag(member, network), g.healthScope) != nil
}

// candidateCount counts the members that may serve this network right now, in one pass and
// without allocating a candidate slice: the selection path runs once per flow and this
// group must not add an allocation to every connection.
func (g *LoadBalance) candidateCount(members []adapter.Outbound, network string, ignoreHealth bool) int {
	count := 0
	for _, member := range members {
		if g.isCandidate(member, network, ignoreHealth) {
			count++
		}
	}
	return count
}

// firstCandidateOrCompatible prefers any candidate, then any member that can carry the
// network at all, then nothing.
func (g *LoadBalance) firstCandidateOrCompatible(members []adapter.Outbound, network string, ignoreHealth bool) adapter.Outbound {
	for _, member := range members {
		if g.isCandidate(member, network, ignoreHealth) {
			return member
		}
	}
	return g.firstCompatible(members, network)
}

// firstCompatible returns the first member that can carry this network, health aside.
func (g *LoadBalance) firstCompatible(members []adapter.Outbound, network string) adapter.Outbound {
	for _, member := range members {
		if common.Contains(member.Network(), network) {
			return member
		}
	}
	return nil
}

// CommittedSelections reports how many committed decisions this group has made.
//
// It exists so a test can assert that a flow consumed exactly one decision - the property
// the whole design turns on - rather than inferring it from a distribution that a bug could
// also produce.
func (g *LoadBalance) CommittedSelections() uint64 {
	return g.cursor.Load()
}

func (g *LoadBalance) snapshot() []adapter.Outbound {
	members := g.members.Load()
	if members == nil {
		return nil
	}
	return *members
}

// Touch marks the group as in use, which is what keeps a lazy health checker checking.
func (g *LoadBalance) Touch() {
	if health := g.health.Load(); health != nil {
		health.Touch()
	}
}

func (g *LoadBalance) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		members := make([]adapter.Outbound, 0, len(g.tags))
		for i, tag := range g.tags {
			member, loaded := g.outbound.Outbound(tag)
			if !loaded {
				return E.New("outbound ", i, " not found: ", tag)
			}
			members = append(members, member)
		}
		if duplicate := loadBalanceDuplicateTag(members); duplicate != "" {
			// A repeated member is accepted and carries twice the share, which is a
			// deliberate weight. It is reported once, because a user who wrote the same
			// tag twice most likely meant to write a different one.
			g.logger.Warn("loadbalance group ", g.Tag(), " lists ", duplicate, " more than once; it receives a proportional share of new flows")
		}

		networks := make([]string, 0, 2)
		for _, member := range members {
			for _, network := range member.Network() {
				if !common.Contains(networks, network) {
					networks = append(networks, network)
				}
			}
		}
		if len(networks) == 0 {
			return E.New("no member of loadbalance group ", g.Tag(), " supports any network")
		}

		var health *URLTestGroup
		if g.url != "" {
			if g.history == nil {
				return E.New("missing URL test history storage")
			}
			expected, err := urltest.ParseExpectedStatus(g.expectedStatus)
			if err != nil {
				return E.Cause(err, "invalid expected_status")
			}
			target, err := urltest.ParseMeasurementTarget(g.url)
			if err != nil {
				return E.Cause(err, "invalid URL test target")
			}
			health, err = NewURLTestGroupWithExpected(
				g.ctx,
				g.outbound,
				g.logger,
				members,
				g.url,
				g.expectedStatus,
				g.interval,
				g.tolerance,
				g.idleTimeout,
				false,
			)
			if err != nil {
				return E.Cause(err, "create health checker")
			}
			g.healthScope = urltest.MeasurementScope{
				URL:      target.ScopeURL,
				Expected: expected.Canonical(),
			}
		}

		// Publish under the lifecycle lock and re-check closed, so a Close that completed
		// while this was being built cannot be undone by the store: a group that closed
		// successfully must not own a live checker afterwards.
		g.lifecycle.Lock()
		if g.closed {
			g.lifecycle.Unlock()
			if health != nil {
				_ = health.Close()
			}
			return os.ErrClosed
		}
		g.members.Store(&members)
		g.networks = networks
		if health != nil {
			g.health.Store(health)
			// The scope owns the teardown, registered against the group this Start
			// installed, so a teardown racing Start cannot leave it running.
			scope.Add(health.Close)
		}
		g.lifecycle.Unlock()
	case adapter.StartStateStarted:
		if health := g.health.Load(); health != nil {
			health.PostStart()
		}
	}
	return nil
}

func (g *LoadBalance) Close() error {
	g.lifecycle.Lock()
	if g.closed {
		g.lifecycle.Unlock()
		return nil
	}
	g.closed = true
	health := g.health.Swap(nil)
	g.members.Store(nil)
	g.lifecycle.Unlock()
	// Close outside the lock: it stops a ticker and cancels background work, and holding
	// the lifecycle lock across other components' teardown is how a deadlock starts.
	if health != nil {
		return health.Close()
	}
	return nil
}

// AttachConnection registers a connection with the group's interrupt group.
//
// The flag is false because a balancing group has no "selection changed" event to
// propagate: a connection is attached to the member it was given, and nothing about the
// group can move it afterwards.
func (g *LoadBalance) AttachConnection(closer io.Closer) func() {
	return g.interruptGroup.Add(closer, false)
}

// DialContext dials the member this flow is given.
//
// The route path resolves the chain and dials the leaf itself, so this is reached when the
// group is used as a detour - a DNS transport, a nested member of another group - where the
// flow metadata travels in the context. The choice made here is committed: the connection
// is what the choice is for.
func (g *LoadBalance) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	member := g.SelectForFlow(adapter.ContextFrom(ctx), network, true)
	if member == nil {
		return nil, E.New(strings.ToUpper(network), " is not supported by outbound: ", g.Tag())
	}
	g.Touch()
	conn, err := member.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return g.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

// ListenPacket opens the packet connection of the member this flow is given.
//
// One call, one member: the returned packet connection is the member's own, so every
// datagram of this session leaves through it. Selecting per datagram would change the
// source address underneath a session that NAT, QUIC and DNS are all tracking.
func (g *LoadBalance) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	member := g.SelectForFlow(adapter.ContextFrom(ctx), N.NetworkUDP, true)
	if member == nil {
		return nil, E.New(N.NetworkUDP, " is not supported by outbound: ", g.Tag())
	}
	g.Touch()
	conn, err := member.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return g.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

// loadBalanceDuplicateTag reports the first tag listed more than once, or empty.
func loadBalanceDuplicateTag(members []adapter.Outbound) string {
	seen := make(map[string]struct{}, len(members))
	for _, member := range members {
		tag := member.Tag()
		if _, loaded := seen[tag]; loaded {
			return tag
		}
		seen[tag] = struct{}{}
	}
	return ""
}
