package group

import (
	"context"
	"io"
	"net"
	"os"
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
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterURLTest(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.OutboundGroup           = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
	_ adapter.Referrer                = (*URLTest)(nil)
)

type URLTest struct {
	outbound.Adapter
	ctx      context.Context
	outbound adapter.OutboundManager
	logger   log.ContextLogger
	tags     []string
	link     string
	// expectedStatus is the configured expression, kept for diagnostics.
	expectedStatus string
	// scope identifies the target this group measures against. Selection, skipping and health
	// checks must only read measurements for THIS target.
	scope                        urltest.MeasurementScope
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	checkAccess                  sync.Mutex
	interruptExternalConnections bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		expectedStatus:               options.ExpectedStatus,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *URLTest) Start() error {
	// Dispose of any group from an earlier Start before replacing it.
	//
	// Assigning a new group over the old one stranded everything the old group owned: its ticker,
	// its pause callback and its background context, none of which anything referenced afterwards.
	// A health check already running kept running, for a group nothing could reach.
	//
	// Start is called once in the normal lifecycle, so this is about not leaking when it is not.
	s.checkAccess.Lock()
	if s.group != nil {
		_ = s.group.Close()
		s.group = nil
	}
	s.checkAccess.Unlock()

	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroupWithExpected(s.ctx, s.outbound, s.logger, outbounds, s.link, s.expectedStatus, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
	if err != nil {
		return err
	}
	s.group = group
	return nil
}

func (s *URLTest) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *URLTest) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *URLTest) All() []string {
	return s.tags
}

func (s *URLTest) Selected(network string) adapter.Outbound {
	var outbound adapter.Outbound
	if state := s.group.selected.Load(); state != nil {
		if network == N.NetworkUDP {
			outbound = state.udp
		} else {
			outbound = state.tcp
		}
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	return outbound
}

func (s *URLTest) AttachConnection(closer io.Closer) func() {
	s.group.Touch()
	return s.group.interruptGroup.Add(closer, true)
}

func (s *URLTest) References() []string {
	group := s.group
	if group == nil {
		return nil
	}
	state := group.selected.Load()
	if state == nil {
		return nil
	}
	var references []string
	if state.tcp != nil {
		references = append(references, state.tcp.Tag())
	}
	if state.udp != nil && state.udp != state.tcp {
		references = append(references, state.udp.Tag())
	}
	return references
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	s.group.CheckOutbounds(s.ctx, true)
}

func (s *URLTest) PerformUpdateCheck() {
	s.group.performUpdateCheck()
}

func (s *URLTest) InterfaceUpdated(ctx context.Context) {
	group := s.group
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go func() {
		s.checkAccess.Lock()
		defer s.checkAccess.Unlock()
		if ctx.Err() != nil {
			return
		}
		group.CheckOutbounds(ctx, true)
	}()
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	if state := s.group.selected.Load(); state != nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			outbound = state.tcp
		case N.NetworkUDP:
			outbound = state.udp
		default:
			return nil, E.Extend(N.ErrUnknownNetwork, network)
		}
	} else if N.NetworkName(network) != N.NetworkTCP && N.NetworkName(network) != N.NetworkUDP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	// A real connection failed, so the node is not usable now regardless of what an earlier
	// measurement said. Only this target's result is invalidated, and only if this outbound is
	// still the selected one - a concurrent update may already have moved on.
	s.group.clearSelectionFor(network, outbound)
	return nil, err
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	if state := s.group.selected.Load(); state != nil {
		outbound = state.udp
	}
	if outbound == nil {
		outbound, _ = s.group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.clearSelectionFor(N.NetworkUDP, outbound)
	return nil, err
}

// selectedState is one immutable generation of the group's selection.
//
// It is replaced wholesale, never mutated, so a reader that has loaded a pointer can use both
// fields without them changing underneath it.
type selectedState struct {
	tcp adapter.Outbound
	udp adapter.Outbound
}

type URLTestGroup struct {
	ctx context.Context
	// cancelBackground cancels ctx, which is a child of the caller's context created by
	// NewURLTestGroup. Every background check runs on it, so Close stops work that is already
	// running rather than only preventing new work from starting.
	cancelBackground context.CancelFunc
	outbound         adapter.OutboundManager
	pause            pause.Manager
	pauseCallback    *list.Element[pause.Callback]
	logger           log.Logger
	outbounds        []adapter.Outbound
	// link is target.RequestURL: the spelling the operator configured, which is what is fetched.
	//
	// It is deliberately NOT the canonical identity. Storing the canonical form here is what let a
	// scope canonicalisation rewrite the request on the automatic group path.
	link string
	// target carries the three separate uses of the configured URL.
	target urltest.MeasurementTarget
	// expected is the parsed status set its health checks accept, and is part of the scope.
	expected urltest.ExpectedStatus
	// scope identifies the target this group measures against, so selection and skipping only
	// ever read measurements made against that same target.
	scope       urltest.MeasurementScope
	interval    time.Duration
	tolerance   uint16
	idleTimeout time.Duration
	history     *urltest.HistoryStorage
	// checking serialises health ROUNDS. It is what stops a periodic check and a forced recheck
	// from measuring the same members at the same time.
	checking atomic.Bool
	// recheckAccess guards the two fields below.
	//
	// This is not a traffic hot path - it is touched at most once per failing connection - so a
	// mutex is the right tool. Two independent atomics could each be correct alone while the pair
	// still lost a request, which is exactly the bug being fixed here.
	recheckAccess sync.Mutex
	// recheckRequested counts recheck requests; recheckServed counts those a completed round has
	// accounted for. Debt exists while requested > served.
	//
	// # Why a sequence and not a flag
	//
	// A flag says only "something is owed". That is not enough to recover from a panic, because the
	// recovery has to tell apart two debts that look identical to a boolean:
	//
	//	the debt the PANICKING round was already serving  -> must NOT be retried
	//	debt created WHILE it ran, by a genuine failure    -> must NOT be lost
	//
	// Retrying the first turns a reproducible panic into an unbounded retry loop. Dropping the
	// second leaves debt with no worker to serve it. A sequence distinguishes them by value: a
	// round records the sequence it is serving, so anything above that number arrived during the
	// round and needs a replacement worker.
	recheckRequested uint64
	recheckServed    uint64
	// recheckWorker records that a worker exists to serve the outstanding sequence, so a burst does
	// not start a goroutine per failure.
	recheckWorker bool
	// recheckRuns counts forced rounds actually executed. It exists so a test can assert the
	// guarantee as a fact rather than inferring it from timing.
	recheckRuns atomic.Int32
	// forcedRoundOverride replaces the body of one forced round in tests.
	//
	// It exists because the worker's panic recovery guards work that runs on the worker's OWN
	// goroutine, and nothing in the production code path can be made to panic on demand from a
	// test. Nil in production, where runForcedRound is used directly.
	forcedRoundOverride func()
	// selected holds the TCP and UDP choices as ONE immutable generation.
	//
	// They were two bare interface fields, written by the background health check and read by
	// real traffic. That is a data race, and reading them separately could yield two different
	// generations within one operation. Publishing them together means a reader loads once and
	// sees a consistent pair.
	selected                     atomic.Pointer[selectedState]
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	updateAccess                 sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	// closed is the terminal state. It is set by Close under access and checked by Touch, so a
	// Touch can never start background work on a closed group.
	closed     bool
	lastActive common.TypedValue[time.Time]
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, interruptExternalConnections bool) (*URLTestGroup, error) {
	return NewURLTestGroupWithExpected(ctx, outboundManager, logger, outbounds, link, "", interval, tolerance, idleTimeout, interruptExternalConnections)
}

// NewURLTestGroupWithExpected builds a group whose health checks accept only the given HTTP
// statuses.
//
// An empty expectedStatus means no constraint, which is the historical behaviour and keeps every
// existing configuration working unchanged. A configuration that needs a strict 204 says so.
func NewURLTestGroupWithExpected(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, expectedStatus string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, interruptExternalConnections bool) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	// Durations are validated rather than assumed.
	//
	// A negative value used to reach time.NewTicker, which panics at runtime - long after the
	// configuration was accepted, and with a stack trace instead of a diagnostic.
	if interval < 0 {
		return nil, E.New("interval must not be negative")
	}
	if idleTimeout < 0 {
		return nil, E.New("idle_timeout must not be negative")
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	// Resolve the target once, here, and refuse an unusable one now.
	//
	// Deferring this would let a group start, look healthy, and only discover after the first
	// interval that every measurement fails - by which time the operator has been told nothing.
	// The request target and health identity are kept separate: RequestURL controls what is
	// fetched, ScopeURL controls which health evidence the result belongs to.
	//
	// The expected status is parsed HERE, with the target, so an unusable expression fails
	// configuration rather than only surfacing when the first background check runs.
	expected, err := urltest.ParseExpectedStatus(expectedStatus)
	if err != nil {
		return nil, E.Cause(err, "invalid expected_status")
	}
	// The request target and the health identity are intentionally kept SEPARATE:
	// RequestURL controls what is fetched, and ScopeURL controls which health evidence the result
	// belongs to. Collapsing them into one string means a canonicalisation chosen for identity
	// silently rewrites what is requested - which is what this group used to do, by storing the
	// canonical form as its link and measuring with it.
	target, err := urltest.ParseMeasurementTarget(link)
	if err != nil {
		return nil, E.Cause(err, "invalid URL test target")
	}
	scope := urltest.MeasurementScope{
		URL:      target.ScopeURL,
		Expected: expected.Canonical(),
	}
	// The group owns its background lifetime. Storing the caller's context alone meant Close could
	// not stop a check that was already running: it could only stop the loop that schedules them,
	// and a recheck requested by a failing connection started a goroutine nothing could cancel.
	groupCtx, cancelBackground := context.WithCancel(ctx)

	return &URLTestGroup{
		ctx:                          groupCtx,
		cancelBackground:             cancelBackground,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         target.RequestURL,
		target:                       target,
		expected:                     expected,
		scope:                        scope,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
	}, nil
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	// A closed group is terminal. Setting started here would leave the group reporting itself
	// started while it is closed, and would queue background work for a group whose services are
	// gone - the exact contradiction `closed` exists to prevent.
	if g.closed {
		return
	}
	g.started = true
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(g.ctx, false)
}

// MeasurementScope reports the target and status set this group measures against.
//
// It is read-only and exists so a display layer can read the group's OWN health evidence rather
// than the process-wide display history. Selecting a member from one measurement and showing
// another's delay is how a UI ends up contradicting the selection it is describing.
func (s *URLTest) MeasurementScope() urltest.MeasurementScope {
	return s.group.scope
}

// backgroundContext reports the context this group's background work runs on.
//
// It exists so a test can assert that Close cancels in-flight work, rather than inferring it from
// the absence of some other effect.
func (g *URLTestGroup) backgroundContext() context.Context {
	return g.ctx
}

func (g *URLTestGroup) Touch() {
	g.access.Lock()
	defer g.access.Unlock()

	// Both flags are read UNDER THE LOCK. The started check used to happen before it, which was a
	// data race against PostStart and Close, and let a Touch interleave with a Close: it could
	// observe started == true, then register a ticker and a pause callback on a group that was
	// being torn down, leaving a background task running after close.
	if !g.started || g.closed {
		return
	}
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	go g.loopCheck(ticker, g.close)
}

func (g *URLTestGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()

	// Idempotent: a second Close must not stop a ticker twice, unregister a nil element, or close
	// an already-closed channel.
	if g.closed {
		return nil
	}

	// Terminal BEFORE anything else. A group that only cleared its ticker would still report
	// itself started, so a concurrent or later Touch could start fresh background work on it -
	// which is exactly what "closed" has to prevent.
	g.closed = true
	g.started = false

	// The ticker may never have been created: a group can be started and closed without being
	// touched. The previous early return in that case skipped the terminal transition entirely,
	// leaving the group startable.
	if g.ticker != nil {
		g.ticker.Stop()
		g.ticker = nil
	}
	if g.pauseCallback != nil {
		g.pause.UnregisterCallback(g.pauseCallback)
		g.pauseCallback = nil
	}
	close(g.close)

	// Stop work that is already running. Stopping the ticker only stops future scheduling.
	if g.cancelBackground != nil {
		g.cancelBackground()
		g.cancelBackground = nil
	}
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	var minDelay uint16
	var minOutbound adapter.Outbound
	switch network {
	case N.NetworkTCP:
		if state := g.selected.Load(); state != nil && state.tcp != nil {
			if history := g.history.LoadURLTestHistoryFor(RealTag(state.tcp, N.NetworkTCP), g.scope); history != nil {
				minOutbound = state.tcp
				minDelay = history.Delay
			}
		}
	case N.NetworkUDP:
		if state := g.selected.Load(); state != nil && state.udp != nil {
			if history := g.history.LoadURLTestHistoryFor(RealTag(state.udp, N.NetworkUDP), g.scope); history != nil {
				minOutbound = state.udp
				minDelay = history.Delay
			}
		}
	}
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.history.LoadURLTestHistoryFor(RealTag(detour, network), g.scope)
		if history == nil {
			continue
		}
		// Widened to uint32 before adding.
		//
		// Both operands are uint16, so `history.Delay + g.tolerance` wraps: with a delay of 30000
		// and a tolerance of 50000 the sum is 14464, and the comparison then prefers a node that
		// is actually FAR slower. The tolerance is a ceiling on acceptable difference, and a
		// ceiling that inverts the ordering is worse than no tolerance at all.
		if minDelay == 0 || uint32(minDelay) > uint32(history.Delay)+uint32(g.tolerance) {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range g.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(g.ctx, false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		g.CheckOutbounds(g.ctx, false)
	}
}

func (g *URLTestGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTest(ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true)
}

// operationContext anchors a health operation to the group's own Box context.
//
// # Why the caller's context cannot be the base
//
// The group owns g.ctx, which carries the Box's services - the URL-test Coordinator, the certificate
// roots, the time service - and the group's lifetime. The public entries used to pass the CALLER's
// context straight through to Measure, and the production callers are the Clash API (the HTTP
// request's context) and the native command client (a gRPC context). Neither carries Box services,
// so supplying one replaced the Box context entirely and three invariants broke together:
//
//   - the per-Box concurrency limit did not apply, because the Coordinator could not be reached
//   - a private-root endpoint failed here while the identical native measurement succeeded, because
//     the roots could not be reached
//   - Close did not cancel the measurement, because Close cancels g.ctx and the measurement was not
//     using it
//
// The caller's context therefore contributes only what a caller legitimately owns: a deadline and
// cancellation. Everything else comes from the group.
//
// It returns an error when the group is terminal, so no network work starts for a group whose
// services are gone.
func (g *URLTestGroup) operationContext(caller context.Context) (context.Context, context.CancelFunc, error) {
	if g.ctx.Err() != nil {
		return nil, nil, os.ErrClosed
	}

	// Values and lifetime come from g.ctx.
	operationCtx, cancelOperation := context.WithCancel(g.ctx)

	if caller == nil {
		return operationCtx, cancelOperation, nil
	}

	// The caller's deadline is layered ON TOP, so it still bounds the operation while the group's
	// own cancellation stays in force.
	if deadline, hasDeadline := caller.Deadline(); hasDeadline {
		var cancelDeadline context.CancelFunc
		operationCtx, cancelDeadline = context.WithDeadline(operationCtx, deadline)
		cancelBase := cancelOperation
		cancelOperation = func() {
			cancelDeadline()
			cancelBase()
		}
	}

	// The caller's cancellation is wired in WITHOUT becoming the base. A caller that gives up stops
	// the operation, and a caller that never cancels cannot keep it alive past Close - which is
	// what the group's own context still governs.
	stopCallerWatch := context.AfterFunc(caller, cancelOperation)
	cancelBase := cancelOperation
	cancelOperation = func() {
		stopCallerWatch()
		cancelBase()
	}

	return operationCtx, cancelOperation, nil
}

func (g *URLTestGroup) urlTest(caller context.Context, force bool) (map[string]uint16, error) {
	// Anchor to the group's own Box context before anything else.
	//
	// A terminal group returns here, so a closed group cannot start a health round at all - its
	// services are gone and any result would be written for a group that no longer exists.
	ctx, cancelOperation, contextErr := g.operationContext(caller)
	if contextErr != nil {
		return make(map[string]uint16), nil
	}
	defer cancelOperation()

	if g.checking.Swap(true) {
		// A round is already running, so this one cannot proceed.
		//
		// # Why a FORCED round must not simply return here
		//
		// Returning silently is correct for a periodic check - the running round measures the same
		// members against the same target, so the work is genuinely redundant. It is NOT correct
		// for a forced round: the caller asked because a traffic failure contradicted the current
		// measurement, and the running round is a periodic one that will SKIP members whose history
		// is still fresh. Dropping it means the contradiction is never re-examined, which is the
		// defect this handoff exists to remove.
		//
		// The request is therefore queued. The worker that owns this round will run it afterwards.
		if force {
			g.queueForcedRecheck()
		}
		return make(map[string]uint16), nil
	}
	defer g.checking.Store(false)
	result := URLTestOutboundsWithTarget(ctx, g.outbound, g.history, g.logger, g.outbounds, g.link, g.expected, g.interval, force, TestHistoryHealth)
	g.performUpdateCheck()
	return result, nil
}

// queueForcedRecheck records that a forced round is owed and ensures a worker will run it.
//
// It is used when a round is already in flight, so the request cannot be served now.
func (g *URLTestGroup) queueForcedRecheck() {
	g.recheckAccess.Lock()
	g.recheckRequested++
	startWorker := !g.recheckWorker
	if startWorker {
		g.recheckWorker = true
	}
	g.recheckAccess.Unlock()

	if startWorker {
		go g.drainHealthRechecks()
	}
}

type urlTestBatch struct {
	ctx      context.Context
	outbound adapter.OutboundManager
	history  *urltest.HistoryStorage
	logger   log.Logger
	// scope is the target every measurement in this batch shares, so results are stored and
	// freshness is judged against the right key.
	scope   urltest.MeasurementScope
	batch   *batch.Batch[any]
	checked map[string]bool
	groups  []adapter.OutboundGroup
	// mode decides which evidence layer this round may write.
	mode TestHistoryMode
	// expected is the status set this round accepts, and is part of the scope it stores under.
	expected urltest.ExpectedStatus
	access   sync.Mutex
	result   map[string]uint16
}

// TestHistoryMode says which evidence a measurement round is allowed to write.
//
// The distinction is not cosmetic. Selection reads the health layer, so a manual diagnostic that
// wrote there could move live traffic on the strength of a measurement taken against an unrelated
// URL - and would let a user grow that layer without bound by testing arbitrary URLs.
type TestHistoryMode int

const (
	// TestHistoryDisplayOnly records what was measured, for display, and nothing else.
	//
	// Used by every manual entry point: a Clash delay probe, a native single-node test, and a
	// native test of a generic group. None of them measured against a group's own target.
	TestHistoryDisplayOnly TestHistoryMode = iota

	// TestHistoryHealth records automatic health evidence, which selection reads.
	//
	// Used only by a URLTest group checking its own configured target.
	TestHistoryHealth
)

// TestHistoryModeFromForce maps the historical force flag onto the explicit mode.
//
// Deprecated naming kept so existing internal callers stay readable: a forced round is an automatic
// health check, an unforced one is the periodic check, and both are health.
func TestHistoryModeFromForce(force bool) TestHistoryMode {
	_ = force
	return TestHistoryHealth
}

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	return URLTestOutboundsWithMode(ctx, outboundManager, history, logger, outbounds, link, interval, force, TestHistoryHealth)
}

// URLTestOutboundsWithMode runs one measurement round and records it according to mode.
func URLTestOutboundsWithMode(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool, mode TestHistoryMode) map[string]uint16 {
	return URLTestOutboundsWithTarget(ctx, outboundManager, history, logger, outbounds, link, nil, interval, force, mode)
}

// URLTestOutboundsWithTarget runs one measurement round against an explicit status set.
//
// The target is resolved once for the whole batch. An unusable one means there is nothing to
// measure, so the batch reports no results rather than failing every node individually.
func URLTestOutboundsWithTarget(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, expected urltest.ExpectedStatus, interval time.Duration, force bool, mode TestHistoryMode) map[string]uint16 {
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))

	// Parse the target ONCE and keep all three uses distinct.
	//
	// This used to do `link = scope.URL`, which replaced the request target with the canonical
	// identity - so everything measured through this batch fetched a rewritten URL. The batch now
	// carries the request spelling for the measurement and the scope for storage.
	target, targetErr := urltest.ParseMeasurementTarget(link)
	if targetErr != nil {
		logger.Error("invalid URL test target: ", targetErr)
		return map[string]uint16{}
	}
	scope := urltest.MeasurementScope{
		URL:      target.ScopeURL,
		Expected: expected.Canonical(),
	}
	testBatch := &urlTestBatch{
		ctx:      ctx,
		outbound: outboundManager,
		history:  history,
		logger:   logger,
		scope:    scope,
		batch:    b,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
		mode:     mode,
		expected: expected,
	}
	testBatch.test(outbounds, target.RequestURL, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		groupHistory := history.LoadURLTestHistoryFor(RealTag(outboundGroup, N.NetworkTCP), scope)
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
}

// measure runs one member's probe, converting a panic into an error.
//
// # Why a member panic must not escape
//
// batch.Go runs each member on its own goroutine and does NOT recover. A panic there therefore
// reaches the runtime, which terminates the whole process - a single misbehaving outbound would
// take down sing-box rather than being reported as one unusable node.
//
// Converting it to an error also keeps the round's own bookkeeping correct: the member is treated
// as unavailable, exactly like a failed dial, so the batch still completes and the other members are
// still measured.
func (b *urlTestBatch) measure(ctx context.Context, link string, detour adapter.Outbound) (measurement urltest.Measurement, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = E.New("measurement panicked: ", recovered)
		}
	}()
	return urltest.Measure(ctx, urltest.MeasureOptions{
		Link:           link,
		ExpectedStatus: b.expected,
	}, detour)
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] {
			continue
		}
		switch nested := detour.(type) {
		case adapter.OutboundGroup:
			// EVERY group member - including a nested URLTest group - is expanded down to its
			// leaves and measured against THIS batch's target.
			//
			// A nested *URLTest used to be special-cased: it ran the child's own urlTest(), which
			// measured the child's leaves against the CHILD's configured URL and rewrote the
			// child's selection. The parent then folded those delays into its own ranking.
			//
			// Two things were wrong with that. The parent ranked a member by a delay measured
			// against a target the parent never chose, so a member could win or lose on an
			// unrelated measurement. And a parent's health check silently re-ran and mutated the
			// child's policy, which is the child's own business.
			//
			// Recursing to leaves means the parent evaluates "what delay would this member give
			// me, on my target, right now", which is what it actually needs to rank. The child's
			// own selection is untouched; the child's own health check remains the only thing that
			// changes it.
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			// The freshness check is scoped: a result against a DIFFERENT target says nothing
			// about this one, so it must not cause this test to be skipped.
			history := b.history.LoadURLTestHistoryFor(tag, b.scope)
			if !force && history != nil && time.Since(history.Time) < interval {
				continue
			}
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				testCtx, cancel := context.WithTimeout(b.ctx, C.TCPTimeout)
				defer cancel()

				// Called directly. batch.Go is already running this on its own goroutine, and
				// Measure honours the context, so the previous goroutine-plus-channel-plus-select
				// added nothing but a second race: when the context expired while the result was
				// also ready, Go picked between the two cases at random and the measurement's
				// outcome became non-deterministic.
				measurement, testErr := b.measure(testCtx, link, detour)
				if testErr != nil {
					if b.ctx.Err() != nil {
						return nil, nil
					}
					b.logger.Debug("outbound ", tag, " unavailable: ", testErr)
					if b.mode == TestHistoryHealth {
						// Only this target's health result is removed. The display entry is left
						// alone: a failed check against this group's target does not invalidate a
						// previous success against another one.
						b.history.DeleteHealthHistory(tag, b.scope)
					}
				} else {
					b.logger.Debug("outbound ", tag, " available: ", measurement.Delay, "ms")
					// The scope comes from the measurement itself, so the key cannot disagree
					// with what was actually requested.
					health := &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: measurement.Delay,
					}
					if b.mode == TestHistoryHealth {
						b.history.StoreHealthHistory(tag, measurement.Scope, health)
					} else {
						b.history.StoreDisplayHistory(tag, measurement.Scope, health)
					}
					b.access.Lock()
					b.result[tag] = measurement.Delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}

// clearSelectionFor drops the failed outbound from the live selection WITHOUT touching its health
// evidence, and requests a bounded health recheck.
//
// # Why a traffic failure is not evidence about the node
//
// This used to delete the node's measurement, on the reasoning that a real connection failing says
// something about the node regardless of what a test showed. It does not. DialContext reports
// whatever went wrong on the path, and the overwhelming majority of causes have nothing to do with
// the proxy: the target refused the connection, the target's port is closed, the remote reset, the
// destination does not exist. A node that carried the connection perfectly produces every one of
// them.
//
// Deleting a correct measurement because a website was down is not merely wasteful - the recheck it
// triggers re-selects from the reduced set, so the group can move to a WORSE node on the strength
// of a third party refusing a connection.
//
// So a traffic failure clears the SELECTION (the caller needs a working path now) and requests a
// recheck. The recheck is what decides whether the node is actually unhealthy, and only its failure
// removes the measurement.
//
// # Why the selection is still cleared
//
// The node just failed to carry traffic, so keeping it selected would make the next connection fail
// the same way. Clearing it lets the immediate re-selection pick another node; if the recheck
// confirms the node is healthy, the measurement is still there and it can be chosen again.
//
// # Why the comparison
//
// The current selection is re-read under the lock and compared: a concurrent update may already have
// replaced this outbound, and clearing the newer choice would undo that work.
//
// # Why only TCP clears the measurement's meaning
//
// A delay measurement dials over TCP and speaks HTTP over it, so the stored value describes the TCP
// path and remains true after a UDP failure. TCP and UDP selection read the same entry, so a UDP
// failure must not move the TCP selection as a side effect.
func (g *URLTestGroup) clearSelectionFor(network string, failed adapter.Outbound) {
	if failed == nil {
		return
	}

	g.updateAccess.Lock()
	previous := g.selected.Load()
	next := &selectedState{}
	if previous != nil {
		next.tcp = previous.tcp
		next.udp = previous.udp
	}

	cleared := false
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if next.tcp == failed {
			next.tcp = nil
			cleared = true
		}
	case N.NetworkUDP:
		if next.udp == failed {
			next.udp = nil
			cleared = true
		}
	}
	if cleared {
		g.selected.Store(next)
	}
	g.updateAccess.Unlock()

	if cleared {
		// Request a health recheck rather than deleting the measurement. The recheck is
		// single-flight, so a burst of failing connections produces one round of probes rather
		// than one per failure.
		g.requestHealthRecheck()
	}
}

// requestHealthRecheck asks for one background health check, collapsing concurrent requests.
//
// A burst of failing connections must not start a burst of probes: each would dial every member,
// which on a mobile device is exactly the traffic storm a health check exists to avoid. The group
// already has a single-flight guard for its checks, so this defers to it and does not add a second
// mechanism.
func (g *URLTestGroup) requestHealthRecheck() {
	// A closed group must not start work. A check against a torn-down group would measure nothing
	// and write history for a group that no longer exists.
	g.access.Lock()
	closed := g.closed
	g.access.Unlock()
	if closed {
		return
	}

	g.recheckAccess.Lock()
	// Re-check terminal INSIDE the lock that records the debt.
	//
	// The check above runs before this lock, so a Close can land in between. Without this second
	// check the request would record debt on a group that can never serve it, and - because the
	// group is terminal - that debt is exactly what the exit path has to retire, so nothing is
	// gained by admitting it. Refusing here keeps "requested > served" meaning "work that is still
	// possible".
	if g.ctx.Err() != nil {
		g.recheckAccess.Unlock()
		return
	}
	// Record the debt. This is the whole point of the redesign: whether or not a round is running,
	// the request is remembered, because a forced probe that never happens leaves the node that
	// just failed to carry traffic eligible for selection on the strength of the measurement the
	// failure already contradicted.
	g.recheckRequested++
	if g.recheckWorker {
		// A worker already exists and will observe the new sequence. Starting another would make a
		// burst of failing connections a burst of goroutines.
		g.recheckAccess.Unlock()
		return
	}
	g.recheckWorker = true
	g.recheckAccess.Unlock()

	go g.drainHealthRechecks()
}

// drainHealthRechecks runs forced rounds until no request is owed.
//
// # The handoff this exists to guarantee
//
// A request arriving while a round is running is recorded, not dropped:
//
//	request   -> recheckRequested++
//	worker    -> records the sequence it is serving, runs a forced round
//	             (a request arriving during it raises recheckRequested further)
//	worker    -> marks that sequence served, and if more was requested runs ONE more round
//	worker    -> only then gives up the worker slot
//
// Ordering the last two steps under the lock is what makes it race-free: a request either raises the
// sequence in time for the final comparison, or finds no worker and starts one.
//
// Many failures therefore coalesce into at most one extra round, and none are lost. The same
// sequence is what lets the panic path tell apart debt this round already owned - which must not be
// retried - from debt that arrived while it ran, which must not be dropped.
func (g *URLTestGroup) drainHealthRechecks() {
	// The worker gives up its slot on EVERY exit, including a panic, and decides there whether a
	// replacement is owed.
	//
	// # What a panic must and must not do
	//
	// MUST NOT retry the round that panicked. A reproducible panic would then become an unbounded
	// retry loop that pins a CPU and floods the log.
	//
	// MUST NOT drop debt created WHILE that round ran. A genuine traffic failure arriving during
	// the round is a real request nobody else will serve: the previous design released `checking`
	// and the worker while leaving the queued flag set, which is debt with no worker to serve it.
	//
	// `retired` is the sequence this worker has accounted for, either by completing a round or by
	// ABANDONING the one that panicked.
	//
	// It starts at the sequence the worker was created to serve, NOT at recheckServed. The
	// difference is the whole point: a round that panics abandons the debt it was serving, so that
	// debt must be marked retired rather than left outstanding - leaving it outstanding is what
	// would make the replacement worker retry the panicking round forever.
	//
	// Anything ABOVE the round's own serving mark arrived while it ran, so it is genuinely new debt
	// and the tail starts a replacement worker to serve exactly that.
	g.recheckAccess.Lock()
	retired := g.recheckRequested
	g.recheckAccess.Unlock()

	// servingMark is the sequence the CURRENT round is serving. A panic retires exactly this, so the
	// panicking round's own debt is abandoned while anything newer survives.
	var servingMark uint64

	defer func() {
		if recovered := recover(); recovered != nil {
			if g.logger != nil {
				g.logger.Error("health recheck panicked: ", recovered)
			}
		}
		g.checking.Store(false)

		g.recheckAccess.Lock()
		g.recheckWorker = false
		if servingMark > g.recheckServed {
			// The round was abandoned rather than completed, so its debt is retired rather than
			// served. Writing it back to recheckServed is what keeps the counter pair meaningful:
			// "requested > served" must mean "somebody still owes a round", and an abandoned round
			// is nobody's debt any more. Leaving it outstanding would also make a replacement
			// worker replay the same panicking round without bound.
			g.recheckServed = servingMark
		}

		// A TERMINAL group owes nothing.
		//
		// Its remaining debt can never be served, so it must be retired rather than carried. The
		// comparison below is otherwise permanently true on a canceled group - every exiting worker
		// would spawn a replacement, which would start, find the context canceled, exit, and spawn
		// another. Close did not stop the group's health work; it converted it into goroutine churn
		// that outlives the group.
		if g.ctx.Err() != nil {
			g.recheckServed = g.recheckRequested
		}

		retired = g.recheckServed
		replacement := g.ctx.Err() == nil && g.recheckRequested > retired
		if replacement {
			// Claim the worker slot while still holding the lock, so a request arriving now either
			// observes a worker or starts one itself. There is no window in which it waits for a
			// worker that has already decided to exit.
			g.recheckWorker = true
		}
		g.recheckAccess.Unlock()

		if replacement {
			go g.drainHealthRechecks()
		}
	}()

	for {
		g.recheckAccess.Lock()
		// This round serves every request made up to now. Many failures therefore still coalesce
		// into ONE round: the sequence is not one-round-per-request.
		serving := g.recheckRequested
		g.recheckAccess.Unlock()

		if g.ctx.Err() != nil {
			break
		}

		// Run the round DIRECTLY, through the same path a periodic check uses.
		//
		// The worker must not call CheckOutbounds here. CheckOutbounds routes through the
		// re-queuing guard, and this worker is itself the drain of that queue: if the guard were
		// still held - by the round this worker was queued behind, whose deferred release has not
		// run yet - the call would re-queue the very request being served, and the loop would
		// re-trigger itself without bound. Running the round directly removes that coupling.
		if !g.checking.CompareAndSwap(false, true) {
			// Another round is still finishing. Wait for it rather than spin, then serve the debt.
			//
			// This is a bounded wait on a mutex-guarded handoff, not a traffic path.
			time.Sleep(time.Millisecond)
			continue
		}

		g.recheckRuns.Add(1)
		// Record the mark BEFORE running, so the panic path can retire exactly this round's debt
		// rather than re-deriving it from state the panic may have left inconsistent.
		g.recheckAccess.Lock()
		servingMark = serving
		g.recheckAccess.Unlock()

		g.runForcedRound()
		g.checking.Store(false)

		// The round completed, so everything up to `serving` is now accounted for.
		g.recheckAccess.Lock()
		if serving > g.recheckServed {
			g.recheckServed = serving
		}
		retired = g.recheckServed
		more := g.recheckRequested > g.recheckServed && g.ctx.Err() == nil
		if !more {
			g.recheckWorker = false
		}
		g.recheckAccess.Unlock()
		if !more {
			return
		}
	}
}

// runForcedRound performs one forced health measurement and re-evaluates the selection.
//
// force = true. A recheck must actually PROBE: with force = false the batch skips any member whose
// measurement is younger than the interval, which is exactly the state a traffic failure leaves
// behind - nothing would be re-measured, and the selection that follows would re-read the very
// measurement the failure just contradicted.
//
// It is a separate function so the worker's ownership of the `checking` guard is visible at the
// call site.
func (g *URLTestGroup) runForcedRound() {
	if g.forcedRoundOverride != nil {
		g.forcedRoundOverride()
		return
	}
	URLTestOutboundsWithTarget(g.ctx, g.outbound, g.history, g.logger, g.outbounds, g.link, g.expected, g.interval, true, TestHistoryHealth)
	g.performUpdateCheck()
}

// clearSelected is invalidateSelected without the re-selection, so the cleared generation can be
// observed on its own. It exists because the two effects are separate concerns: which fields the
// invalidation clears is a rule, and which node selection then settles on is a policy.
func (g *URLTestGroup) clearSelected(network string, failed adapter.Outbound) {
	if failed == nil {
		return
	}
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()

	previous := g.selected.Load()
	if previous == nil {
		return
	}
	next := &selectedState{tcp: previous.tcp, udp: previous.udp}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if next.tcp == failed {
			next.tcp = nil
		}
	case N.NetworkUDP:
		if next.udp == failed {
			next.udp = nil
		}
	}
	g.selected.Store(next)
}

func (g *URLTestGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	var (
		updated  bool
		selected bool
	)

	// The previous generation is read once and the next is built from it, so TCP and UDP are
	// published together. Assigning each field separately would let a reader observe one updated
	// network and one stale one.
	previous := g.selected.Load()
	next := &selectedState{}
	if previous != nil {
		next.tcp = previous.tcp
		next.udp = previous.udp
	}

	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil && (next.tcp == nil || (exists && outbound != next.tcp)) {
		if next.tcp != nil {
			updated = true
		}
		next.tcp = outbound
		selected = true
	}
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil && (next.udp == nil || (exists && outbound != next.udp)) {
		if next.udp != nil {
			updated = true
		}
		next.udp = outbound
		selected = true
	}

	g.selected.Store(next)
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	if selected {
		g.history.NotifyUpdated()
	}
}
