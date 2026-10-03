package group

import (
	"context"
	"io"
	"net"
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
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
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
	link             string
	// scope identifies the target this group measures against, so selection and skipping only
	// ever read measurements made against that same target.
	scope       urltest.MeasurementScope
	interval    time.Duration
	tolerance   uint16
	idleTimeout time.Duration
	history     *urltest.HistoryStorage
	checking    atomic.Bool
	// recheckPending collapses a burst of failing connections into ONE recheck worker.
	//
	// checking alone is not enough: it makes the redundant work inside the health function return
	// early, but every failure still starts its own goroutine. A burst of failing connections on a
	// phone would create a burst of short-lived goroutines.
	recheckPending atomic.Bool
	// recheckRuns counts how many recheck workers actually started. It exists so a test can assert
	// the single-flight guarantee as a fact rather than inferring it from timing.
	recheckRuns atomic.Int32
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
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
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
	// The canonical URL is kept so the scope and what is actually requested are the same string.
	scope, err := urltest.NewMeasurementScope(link, nil)
	if err != nil {
		return nil, E.Cause(err, "invalid URL test target")
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
		link:                         scope.URL,
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
	g.started = true
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(g.ctx, false)
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
		if minDelay == 0 || minDelay > history.Delay+g.tolerance {
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

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	if g.checking.Swap(true) {
		return make(map[string]uint16), nil
	}
	defer g.checking.Store(false)
	result := URLTestOutbounds(ctx, g.outbound, g.history, g.logger, g.outbounds, g.link, g.interval, force)
	g.performUpdateCheck()
	return result, nil
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
	access  sync.Mutex
	result  map[string]uint16
}

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	// The target is resolved once for the whole batch. An unusable one means there is nothing to
	// measure, so the batch reports no results rather than failing every node individually.
	scope, scopeErr := urltest.NewMeasurementScope(link, nil)
	if scopeErr != nil {
		logger.Error("invalid URL test target: ", scopeErr)
		return map[string]uint16{}
	}
	link = scope.URL
	testBatch := &urlTestBatch{
		ctx:      ctx,
		outbound: outboundManager,
		history:  history,
		logger:   logger,
		scope:    scope,
		batch:    b,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		groupHistory := history.LoadURLTestHistoryFor(RealTag(outboundGroup, N.NetworkTCP), scope)
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
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
				measurement, testErr := urltest.Measure(testCtx, urltest.MeasureOptions{Link: link}, detour)
				if testErr != nil {
					if b.ctx.Err() != nil {
						return nil, nil
					}
					b.logger.Debug("outbound ", tag, " unavailable: ", testErr)
					// Only this target's result is removed.
					b.history.DeleteURLTestHistoryFor(tag, b.scope)
				} else {
					b.logger.Debug("outbound ", tag, " available: ", measurement.Delay, "ms")
					// The scope comes from the measurement itself, so the key cannot disagree
					// with what was actually requested.
					b.history.StoreURLTestHistoryFor(tag, measurement.Scope, &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: measurement.Delay,
					})
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
	// A closed group must not start work. The worker below would otherwise run a full health check
	// against a torn-down group and write history for one that no longer exists.
	g.access.Lock()
	closed := g.closed
	g.access.Unlock()
	if closed {
		return
	}

	// ONE worker per burst. CompareAndSwap is what makes that a guarantee rather than a hope: a
	// failing connection arriving while a recheck is already pending is dropped, not queued.
	if !g.recheckPending.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer g.recheckPending.Store(false)
		defer func() {
			if recovered := recover(); recovered != nil && g.logger != nil {
				g.logger.Error("health recheck panicked: ", recovered)
			}
		}()

		if g.ctx.Err() != nil {
			return
		}
		g.recheckRuns.Add(1)

		// force = true. A recheck must actually PROBE.
		//
		// With force = false the batch skips any member whose measurement is younger than the
		// interval - which is exactly the state a traffic failure leaves behind. Nothing would be
		// re-measured, and the selection that follows would re-read the very measurement the
		// failure just contradicted, so the node that could not carry traffic stayed eligible.
		g.CheckOutbounds(g.ctx, true)
	}()
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
