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
	s.group.invalidateSelected(network, outbound)
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
	s.group.invalidateSelected(N.NetworkUDP, outbound)
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
	ctx           context.Context
	outbound      adapter.OutboundManager
	pause         pause.Manager
	pauseCallback *list.Element[pause.Callback]
	logger        log.Logger
	outbounds     []adapter.Outbound
	link          string
	// scope identifies the target this group measures against, so selection and skipping only
	// ever read measurements made against that same target.
	scope       urltest.MeasurementScope
	interval    time.Duration
	tolerance   uint16
	idleTimeout time.Duration
	history     *urltest.HistoryStorage
	checking    atomic.Bool
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
	lastActive                   common.TypedValue[time.Time]
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
	return &URLTestGroup{
		ctx:                          ctx,
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

func (g *URLTestGroup) Touch() {
	if !g.started {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
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
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.ticker = nil
	g.pause.UnregisterCallback(g.pauseCallback)
	g.pauseCallback = nil
	close(g.close)
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

// invalidateSelected drops a node that just failed a real connection.
//
// # Why a measurement is not enough on its own
//
// History records how a node behaved when tested. A node can pass every test and still fail to
// carry traffic - the endpoint moved, the credentials were revoked, a middlebox started dropping
// the flow - and a selection that keeps pointing at it makes every subsequent connection fail
// until the next interval.
//
// # Why the comparison
//
// The current selection is re-read under the lock and compared: a concurrent update may already
// have replaced this outbound, and clearing the newer choice would undo that work.
//
// # Why only a TCP failure discards the measurement
//
// A delay measurement dials over TCP - URLTest establishes a TCP path through the outbound and
// speaks HTTP over it. The stored value is therefore a statement about the TCP path, and it
// remains true after a UDP failure. Discarding it because UDP failed would throw away correct
// information and, because TCP and UDP selection read the same entry, would move the TCP
// selection as a side effect of a UDP problem.
//
// So a UDP failure clears only the UDP selection: the group picks another node for UDP traffic
// immediately, while the TCP-path measurement stays available for the next selection round. A TCP
// failure is evidence about the path the measurement describes, so it discards the measurement.
//
// The result is published as one generation and the normal update check runs, which re-selects
// from whatever scoped history remains.
func (g *URLTestGroup) invalidateSelected(network string, failed adapter.Outbound) {
	if failed == nil {
		return
	}
	realTag := RealTag(failed, network)

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

	// Only this target's result is invalidated, and only when the failure is evidence about the
	// path the measurement describes. Another target's measurement of the same node is a
	// different observation and remains valid either way.
	if N.NetworkName(network) == N.NetworkTCP {
		g.history.DeleteURLTestHistoryFor(realTag, g.scope)
	}

	if cleared {
		// Try to pick a replacement immediately rather than leaving the group without a selection
		// until the next interval.
		g.performUpdateCheck()
	}
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
