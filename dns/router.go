package dns

import (
	"context"
	"errors"
	"hash/fnv"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/task"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

var (
	_ adapter.DNSRouter                 = (*Router)(nil)
	_ adapter.DNSRuleSetUpdateValidator = (*Router)(nil)
)

type Router struct {
	ctx          context.Context
	logger       logger.ContextLogger
	transport    adapter.DNSTransportManager
	outbound     adapter.OutboundManager
	powerManager *powerreport.Manager
	client       adapter.DNSClient
	// concreteClient is the same client, typed.
	//
	// The network reset needs one internal operation on it - re-pinning each transport's environment
	// - and widening adapter.DNSClient for a single caller inside this package would put a
	// fork-specific method on a shared interface. Holding the concrete type keeps that seam local.
	concreteClient        *Client
	rawRules              []option.DNSRule
	rules                 []adapter.DNSRule
	defaultDomainStrategy C.DomainStrategy
	dnsReverseMapping     *freelru.Cache[netip.Addr, string]
	// networkGeneration advances on every ResetNetwork so a DNS response can be attributed to the
	// network its request was issued on.
	networkGeneration atomic.Uint64
	// dnsEnvironmentAccess guards the DNS environment observation pair
	// (dnsEnvironmentObserved, dnsEnvironmentFingerprint) together with the advance of
	// dnsEnvironmentGeneration, so "the fingerprint I compared" and "the epoch I produced" are one
	// atomic mutation rather than two.
	//
	// It is a leaf lock: it is held only across the transports' own Environment() reads, which do
	// not call back into the router.
	dnsEnvironmentAccess sync.Mutex
	// dnsEnvironmentObserved reports whether the DNS environment has been observed at least once.
	// The first observation PINS the fingerprint without advancing - see observeDNSEnvironment.
	dnsEnvironmentObserved bool
	// dnsEnvironmentFingerprint is the last observed aggregate of every transport's published DNS
	// environment: the resolver addresses and the search domains the platform is currently handing
	// this box. It is the "environment fingerprint" the DNS generation is tied to.
	dnsEnvironmentFingerprint uint64
	// dnsEnvironmentDescription is the human-readable form of the last observed fingerprint, kept
	// only for the log line a change emits.
	dnsEnvironmentDescription string
	// dnsEnvironmentGeneration advances when - and only when - dnsEnvironmentFingerprint changes.
	//
	// It is INDEPENDENT of networkGeneration on purpose. A DNS server change on an unchanged
	// interface is not a network transition, and the two must be able to move separately: the network
	// epoch moving tears down connections, while this one only retires the DNS verdicts that were
	// learned from the previous resolver set.
	dnsEnvironmentGeneration atomic.Uint64
	platformInterface        adapter.PlatformInterface
	legacyDNSMode            bool
	rulesAccess              sync.RWMutex
	started                  bool
	closing                  bool
	// testReverseMappingRecordHook, when set, runs inside commitReverseMappingAnswers at the start of
	// the commit protocol - after every step that runs outside the critical section, and before the
	// epoch comparison and the writes it guards.
	//
	// It exists so a test can prove that comparison is atomic with the invalidation rather than assume
	// it: the test stops the recording there and completes a real invalidation from the other side. It
	// is nil in production, where it costs one nil comparison per recorded response.
	//
	// It is a decision seam, not a model of the cache: it passes the answers and the captured epoch, so
	// a test drives the invalidation through the router's own entry points rather than through a
	// reimplementation of them.
	testReverseMappingRecordHook func(answers []reverseMappingAnswer, generation uint64)
}

func NewRouter(ctx context.Context, logFactory log.Factory, options option.DNSOptions) (*Router, error) {
	router := &Router{
		ctx:                   ctx,
		logger:                logFactory.NewLogger("dns"),
		transport:             service.FromContext[adapter.DNSTransportManager](ctx),
		outbound:              service.FromContext[adapter.OutboundManager](ctx),
		powerManager:          service.FromContext[*powerreport.Manager](ctx),
		rawRules:              make([]option.DNSRule, 0, len(options.Rules)),
		rules:                 make([]adapter.DNSRule, 0, len(options.Rules)),
		defaultDomainStrategy: C.DomainStrategy(options.Strategy),
	}
	if options.DNSClientOptions.IndependentCache {
		deprecated.Report(ctx, deprecated.OptionIndependentDNSCache)
	}
	var optimisticTimeout time.Duration
	optimisticOptions := common.PtrValueOrDefault(options.DNSClientOptions.Optimistic)
	if optimisticOptions.Enabled {
		if options.DNSClientOptions.DisableCache {
			return nil, E.New("`optimistic` is conflict with `disable_cache`")
		}
		if options.DNSClientOptions.DisableExpire {
			return nil, E.New("`optimistic` is conflict with `disable_expire`")
		}
		optimisticTimeout = time.Duration(optimisticOptions.Timeout)
		if optimisticTimeout == 0 {
			optimisticTimeout = 3 * 24 * time.Hour
		}
	}
	router.concreteClient = NewClient(ClientOptions{
		Context:           ctx,
		Timeout:           time.Duration(options.DNSClientOptions.Timeout),
		DisableCache:      options.DNSClientOptions.DisableCache,
		DisableExpire:     options.DNSClientOptions.DisableExpire,
		OptimisticTimeout: optimisticTimeout,
		CacheCapacity:     options.DNSClientOptions.CacheCapacity,
		ClientSubnet:      options.DNSClientOptions.ClientSubnet.Build(netip.Prefix{}),
		RDRC: func() adapter.RDRCStore {
			cacheFile := service.FromContext[adapter.CacheFile](ctx)
			if cacheFile == nil {
				return nil
			}
			if !cacheFile.StoreRDRC() {
				return nil
			}
			return cacheFile
		},
		// The SAME generation the reverse mapping uses. One network reset advances one counter, so
		// the two caches cannot disagree about which epoch an answer belongs to.
		NetworkGeneration: router.dnsGeneration,
		DNSCache: func() adapter.DNSCacheStore {
			cacheFile := service.FromContext[adapter.CacheFile](ctx)
			if cacheFile == nil {
				return nil
			}
			if !cacheFile.StoreDNS() {
				return nil
			}
			cacheFile.SetDisableExpire(options.DNSClientOptions.DisableExpire)
			cacheFile.SetOptimisticTimeout(optimisticTimeout)
			return cacheFile
		},
		Logger: router.logger,
	})
	router.client = router.concreteClient
	if options.ReverseMapping {
		router.dnsReverseMapping = common.Must1(freelru.New[netip.Addr, string](1024, maphash.NewHasher[netip.Addr]().Hash32, true))
	}
	return router, nil
}

func (r *Router) Initialize(rules []option.DNSRule) error {
	r.rawRules = append(r.rawRules[:0], rules...)
	newRules, _, _, err := r.buildRules(false)
	if err != nil {
		return err
	}
	closeRules(newRules)
	return nil
}

func (r *Router) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	monitor := taskmonitor.New(r.logger, C.StartTimeout)
	switch stage {
	case adapter.StartStateStart:
		scope.Add(func() error {
			r.rulesAccess.Lock()
			r.closing = true
			runtimeRules := r.rules
			r.rules = nil
			r.rulesAccess.Unlock()
			closeRules(runtimeRules)
			return nil
		})
		monitor.Start("initialize DNS client")
		r.client.Start()
		monitor.Finish()

		monitor.Start("initialize DNS rules")
		newRules, legacyDNSMode, modeFlags, err := r.buildRules(true)
		monitor.Finish()
		if err != nil {
			return err
		}
		r.rulesAccess.Lock()
		if r.closing {
			r.rulesAccess.Unlock()
			closeRules(newRules)
			return nil
		}
		r.rules = newRules
		r.legacyDNSMode = legacyDNSMode
		r.started = true
		r.rulesAccess.Unlock()
		if legacyDNSMode && common.Any(newRules, func(rule adapter.DNSRule) bool { return rule.WithAddressLimit() }) {
			deprecated.Report(r.ctx, deprecated.OptionLegacyDNSAddressFilter)
		}
		if legacyDNSMode && modeFlags.neededFromStrategy {
			deprecated.Report(r.ctx, deprecated.OptionLegacyDNSRuleStrategy)
		}
	}
	return nil
}

func (r *Router) buildRules(startRules bool) ([]adapter.DNSRule, bool, dnsRuleModeFlags, error) {
	for i, ruleOptions := range r.rawRules {
		err := R.ValidateNoNestedDNSRuleActions(ruleOptions)
		if err != nil {
			return nil, false, dnsRuleModeFlags{}, E.Cause(err, "parse dns rule[", i, "]")
		}
	}
	router := service.FromContext[adapter.Router](r.ctx)
	legacyDNSMode, modeFlags, err := resolveLegacyDNSMode(router, r.rawRules, nil)
	if err != nil {
		return nil, false, dnsRuleModeFlags{}, err
	}
	if !legacyDNSMode {
		var validationWarnings []string
		validationWarnings, err = validateLegacyDNSModeDisabledRules(router, r.rawRules, nil)
		if err != nil {
			return nil, false, dnsRuleModeFlags{}, err
		}
		for _, warning := range validationWarnings {
			r.logger.Warn(warning)
		}
	}
	err = validateEvaluateFakeIPRules(r.rawRules, r.transport)
	if err != nil {
		return nil, false, dnsRuleModeFlags{}, err
	}
	newRules := make([]adapter.DNSRule, 0, len(r.rawRules))
	for i, ruleOptions := range r.rawRules {
		var dnsRule adapter.DNSRule
		dnsRule, err = R.NewDNSRule(r.ctx, r.logger, ruleOptions, true, legacyDNSMode)
		if err != nil {
			closeRules(newRules)
			return nil, false, dnsRuleModeFlags{}, E.Cause(err, "parse dns rule[", i, "]")
		}
		newRules = append(newRules, dnsRule)
	}
	if startRules {
		for i, rule := range newRules {
			err = rule.Start()
			if err != nil {
				closeRules(newRules)
				return nil, false, dnsRuleModeFlags{}, E.Cause(err, "initialize DNS rule[", i, "]")
			}
		}
	}
	return newRules, legacyDNSMode, modeFlags, nil
}

func closeRules(rules []adapter.DNSRule) {
	for _, rule := range rules {
		_ = rule.Close()
	}
}

func (r *Router) ValidateRuleSetMetadataUpdate(tag string, metadata adapter.RuleSetMetadata) error {
	if len(r.rawRules) == 0 {
		return nil
	}
	router := service.FromContext[adapter.Router](r.ctx)
	if router == nil {
		return E.New("router service not found")
	}
	overrides := map[string]adapter.RuleSetMetadata{
		tag: metadata,
	}
	r.rulesAccess.RLock()
	started := r.started
	legacyDNSMode := r.legacyDNSMode
	closing := r.closing
	r.rulesAccess.RUnlock()
	if closing {
		return nil
	}
	if !started {
		candidateLegacyDNSMode, _, err := resolveLegacyDNSMode(router, r.rawRules, overrides)
		if err != nil {
			return err
		}
		if !candidateLegacyDNSMode {
			_, err = validateLegacyDNSModeDisabledRules(router, r.rawRules, overrides)
			return err
		}
		return nil
	}
	candidateLegacyDNSMode, flags, err := resolveLegacyDNSMode(router, r.rawRules, overrides)
	if err != nil {
		return err
	}
	if legacyDNSMode {
		if !candidateLegacyDNSMode && flags.disabled {
			_, err = validateLegacyDNSModeDisabledRules(router, r.rawRules, overrides)
			if err != nil {
				return err
			}
			return E.New(deprecated.OptionLegacyDNSAddressFilter.MessageWithLink())
		}
		return nil
	}
	if candidateLegacyDNSMode {
		return E.New(deprecated.OptionLegacyDNSAddressFilter.MessageWithLink())
	}
	_, err = validateLegacyDNSModeDisabledRules(router, r.rawRules, overrides)
	return err
}

func (r *Router) matchDNS(ctx context.Context, rules []adapter.DNSRule, allowFakeIP bool, ruleIndex int, isAddressQuery bool, options *adapter.DNSQueryOptions) (adapter.DNSTransport, adapter.DNSRule, int) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	var currentRuleIndex int
	if ruleIndex != -1 {
		currentRuleIndex = ruleIndex + 1
	}
	for ; currentRuleIndex < len(rules); currentRuleIndex++ {
		currentRule := rules[currentRuleIndex]
		if currentRule.WithAddressLimit() && !isAddressQuery {
			continue
		}
		metadata.ResetRuleCache()
		metadata.DestinationAddressMatchFromResponse = false
		if currentRule.LegacyPreMatch(metadata) {
			if ruleDescription := currentRule.String(); ruleDescription != "" {
				r.logger.DebugContext(ctx, "match[", currentRuleIndex, "] ", currentRule, " => ", currentRule.Action())
			} else {
				r.logger.DebugContext(ctx, "match[", currentRuleIndex, "] => ", currentRule.Action())
			}
			switch action := currentRule.Action().(type) {
			case *R.RuleActionDNSRoute:
				transport, loaded := r.transport.Transport(action.Server)
				if !loaded {
					r.logger.ErrorContext(ctx, "transport not found: ", action.Server)
					continue
				}
				isFakeIP := transport.Type() == C.DNSTypeFakeIP
				if isFakeIP && !allowFakeIP {
					continue
				}
				if action.Strategy != C.DomainStrategyAsIS {
					options.Strategy = action.Strategy
				}
				if isFakeIP || action.DisableCache {
					options.DisableCache = true
				}
				if action.RewriteTTL != nil {
					options.RewriteTTL = action.RewriteTTL
				}
				if action.Timeout > 0 {
					options.Timeout = action.Timeout
				}
				if action.ClientSubnet.IsValid() {
					options.ClientSubnet = action.ClientSubnet
					options.RemoveClientSubnet = false
				}
				if action.RemoveClientSubnet {
					options.ClientSubnet = netip.Prefix{}
					options.RemoveClientSubnet = true
				}
				return transport, currentRule, currentRuleIndex
			case *R.RuleActionDNSRouteOptions:
				if action.Strategy != C.DomainStrategyAsIS {
					options.Strategy = action.Strategy
				}
				if action.DisableCache {
					options.DisableCache = true
				}
				if action.RewriteTTL != nil {
					options.RewriteTTL = action.RewriteTTL
				}
				if action.Timeout > 0 {
					options.Timeout = action.Timeout
				}
				if action.ClientSubnet.IsValid() {
					options.ClientSubnet = action.ClientSubnet
					options.RemoveClientSubnet = false
				}
				if action.RemoveClientSubnet {
					options.ClientSubnet = netip.Prefix{}
					options.RemoveClientSubnet = true
				}
			case *R.RuleActionReject:
				return nil, currentRule, currentRuleIndex
			case *R.RuleActionPredefined:
				return nil, currentRule, currentRuleIndex
			}
		}
	}
	transport := r.transport.Default()
	return transport, nil, -1
}

func (r *Router) applyDNSRouteOptions(options *adapter.DNSQueryOptions, routeOptions R.RuleActionDNSRouteOptions) {
	// Strategy is intentionally skipped here. A non-default DNS rule action strategy
	// forces legacy mode via resolveLegacyDNSMode, so this path is only reachable
	// when strategy remains at its default value.
	if routeOptions.DisableCache {
		options.DisableCache = true
	}
	if routeOptions.DisableOptimisticCache {
		options.DisableOptimisticCache = true
	}
	if routeOptions.RewriteTTL != nil {
		options.RewriteTTL = routeOptions.RewriteTTL
	}
	if routeOptions.Timeout > 0 {
		options.Timeout = routeOptions.Timeout
	}
	if routeOptions.ClientSubnet.IsValid() {
		options.ClientSubnet = routeOptions.ClientSubnet
		options.RemoveClientSubnet = false
	}
	if routeOptions.RemoveClientSubnet {
		options.ClientSubnet = netip.Prefix{}
		options.RemoveClientSubnet = true
	}
}

type dnsRouteStatus uint8

const (
	dnsRouteStatusMissing dnsRouteStatus = iota
	dnsRouteStatusSkipped
	dnsRouteStatusResolved
)

func (r *Router) resolveDNSRoute(server string, routeOptions R.RuleActionDNSRouteOptions, allowFakeIP bool, options *adapter.DNSQueryOptions) (adapter.DNSTransport, dnsRouteStatus) {
	transport, loaded := r.transport.Transport(server)
	if !loaded {
		return nil, dnsRouteStatusMissing
	}
	isFakeIP := transport.Type() == C.DNSTypeFakeIP
	if isFakeIP && !allowFakeIP {
		return transport, dnsRouteStatusSkipped
	}
	r.applyDNSRouteOptions(options, routeOptions)
	if isFakeIP {
		options.DisableCache = true
	}
	return transport, dnsRouteStatusResolved
}

func (r *Router) logRuleMatch(ctx context.Context, ruleIndex int, currentRule adapter.DNSRule) {
	if ruleDescription := currentRule.String(); ruleDescription != "" {
		r.logger.DebugContext(ctx, "match[", ruleIndex, "] ", currentRule, " => ", currentRule.Action())
	} else {
		r.logger.DebugContext(ctx, "match[", ruleIndex, "] => ", currentRule.Action())
	}
}

type exchangeWithRulesResult struct {
	response     *mDNS.Msg
	transport    adapter.DNSTransport
	rejectAction *R.RuleActionReject
	err          error
}

const dnsRespondMissingResponseMessage = "respond action requires an evaluated response from a preceding evaluate action"

type dnsRuleWalkState struct {
	ruleIndex        int
	lastLoggedIndex  int
	effectiveOptions adapter.DNSQueryOptions
	anonymousFuture  *dnsEvaluatedFuture
	namedFutures     map[string]*dnsEvaluatedFuture
	namedResponses   map[string]*mDNS.Msg
	namedTransports  map[string]adapter.DNSTransport
	futures          []*dnsEvaluatedFuture
	armedRules       []*dnsArmedRule
	terminalFuture   *dnsEvaluatedFuture
	terminalIndex    int
	wake             chan struct{}
}

func (s *dnsRuleWalkState) anonymousResponse() *mDNS.Msg {
	if s.anonymousFuture == nil {
		return nil
	}
	return s.anonymousFuture.view()
}

type dnsEvaluatedFuture struct {
	tag       string
	terminal  bool
	transport adapter.DNSTransport
	cancel    context.CancelFunc
	done      chan struct{}
	response  *mDNS.Msg
	err       error
	settled   bool
}

func (f *dnsEvaluatedFuture) resolved() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

func (f *dnsEvaluatedFuture) view() *mDNS.Msg {
	if !f.resolved() || f.err != nil {
		return nil
	}
	return f.response
}

type dnsArmedRule struct {
	ruleIndex       int
	rule            adapter.DNSRule
	futures         []*dnsEvaluatedFuture
	anonymousFuture *dnsEvaluatedFuture
	bindsAnonymous  bool
	options         adapter.DNSQueryOptions
}

type dnsPendingExchange struct {
	transport adapter.DNSTransport
	options   adapter.DNSQueryOptions
	future    *dnsEvaluatedFuture
}

type dnsWalkSuspension struct {
	await   *dnsEvaluatedFuture
	drain   bool
	pending *dnsPendingExchange
}

func (r *Router) launchDNSEvaluate(ctx context.Context, state *dnsRuleWalkState, tag string, transport adapter.DNSTransport, message *mDNS.Msg, options adapter.DNSQueryOptions) *dnsEvaluatedFuture {
	if state.wake == nil {
		state.wake = make(chan struct{}, 1)
	}
	wake := state.wake
	exchangeCtx, cancel := context.WithCancel(adapter.OverrideContext(ctx))
	future := &dnsEvaluatedFuture{
		tag:       tag,
		transport: transport,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	state.futures = append(state.futures, future)
	r.client.ExchangeAsync(exchangeCtx, transport, message, r.finalizeExchangeOptions(options), nil, func(response *mDNS.Msg, err error) {
		future.response = response
		future.err = err
		close(future.done)
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	return future
}

func (r *Router) settleDNSFutures(ctx context.Context, message *mDNS.Msg, state *dnsRuleWalkState) {
	for _, future := range state.futures {
		if future.settled || !future.resolved() {
			continue
		}
		future.settled = true
		if future.err != nil && !future.terminal {
			r.logger.ErrorContext(ctx, E.Cause(future.err, "exchange failed for ", FormatQuestion(message.Question[0].String())))
		}
		if future.tag == "" {
			continue
		}
		newResponses := make(map[string]*mDNS.Msg, len(state.namedResponses)+1)
		maps.Copy(newResponses, state.namedResponses)
		newResponses[future.tag] = future.view()
		state.namedResponses = newResponses
		newTransports := make(map[string]adapter.DNSTransport, len(state.namedTransports)+1)
		maps.Copy(newTransports, state.namedTransports)
		newTransports[future.tag] = future.transport
		state.namedTransports = newTransports
	}
}

func cancelDNSFutures(state *dnsRuleWalkState) {
	for _, future := range state.futures {
		future.cancel()
	}
}

func dnsRefusedResponse(message *mDNS.Msg) *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Id:       message.Id,
			Rcode:    mDNS.RcodeRefused,
			Response: true,
		},
		Question: []mDNS.Question{message.Question[0]},
	}
}

func (r *Router) finalizeExchangeOptions(options adapter.DNSQueryOptions) adapter.DNSQueryOptions {
	if options.Strategy == C.DomainStrategyAsIS {
		options.Strategy = r.defaultDomainStrategy
	}
	return options
}

func (r *Router) walkDNSRules(ctx context.Context, rules []adapter.DNSRule, message *mDNS.Msg, state *dnsRuleWalkState, allowFakeIP bool) (exchangeWithRulesResult, *dnsWalkSuspension) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	for ; state.ruleIndex < len(rules); state.ruleIndex++ {
		currentRule := rules[state.ruleIndex]
		hasBindings := len(currentRule.MatchResponseTags()) > 0 || currentRule.MatchResponseAnonymous()
		if hasBindings {
			r.settleDNSFutures(ctx, message, state)
			if currentRule.Race() {
				var (
					pendingFutures  []*dnsEvaluatedFuture
					anonymousFuture *dnsEvaluatedFuture
				)
				for _, responseTag := range currentRule.MatchResponseTags() {
					future := state.namedFutures[responseTag]
					if future != nil && !future.resolved() {
						pendingFutures = append(pendingFutures, future)
					}
				}
				bindsAnonymous := currentRule.MatchResponseAnonymous()
				if bindsAnonymous {
					anonymousFuture = state.anonymousFuture
					if anonymousFuture != nil && !anonymousFuture.resolved() {
						pendingFutures = append(pendingFutures, anonymousFuture)
					}
				}
				if len(pendingFutures) > 0 {
					r.logger.DebugContext(ctx, "armed[", state.ruleIndex, "] ", currentRule, " => ", currentRule.Action())
				}
				state.armedRules = append(state.armedRules, &dnsArmedRule{
					ruleIndex:       state.ruleIndex,
					rule:            currentRule,
					futures:         pendingFutures,
					anonymousFuture: anonymousFuture,
					bindsAnonymous:  bindsAnonymous,
					options:         state.effectiveOptions,
				})
				if len(pendingFutures) == 0 {
					sweepResult, sweepPending, committed := r.sweepArmedDNSRules(ctx, message, state, allowFakeIP)
					if committed {
						if sweepPending != nil {
							state.armedRules = nil
							return exchangeWithRulesResult{}, &dnsWalkSuspension{pending: sweepPending}
						}
						return sweepResult, nil
					}
				}
				continue
			}
			var awaitFuture *dnsEvaluatedFuture
			for _, responseTag := range currentRule.MatchResponseTags() {
				future := state.namedFutures[responseTag]
				if future != nil && !future.resolved() {
					awaitFuture = future
					break
				}
			}
			if awaitFuture == nil && currentRule.MatchResponseAnonymous() {
				if future := state.anonymousFuture; future != nil && !future.resolved() {
					awaitFuture = future
				}
			}
			if awaitFuture != nil {
				return exchangeWithRulesResult{}, &dnsWalkSuspension{await: awaitFuture}
			}
		}
		metadata.ResetRuleCache()
		metadata.DNSResponse = state.anonymousResponse()
		metadata.NamedDNSResponses = state.namedResponses
		metadata.DestinationAddressMatchFromResponse = false
		if !currentRule.Match(metadata) {
			continue
		}
		if state.lastLoggedIndex != state.ruleIndex {
			state.lastLoggedIndex = state.ruleIndex
			r.logRuleMatch(ctx, state.ruleIndex, currentRule)
		}
		switch action := currentRule.Action().(type) {
		case *R.RuleActionDNSRouteOptions:
			r.applyDNSRouteOptions(&state.effectiveOptions, *action)
		case *R.RuleActionEvaluate:
			transport, loaded := r.transport.Transport(action.Server)
			if !loaded {
				r.logger.ErrorContext(ctx, "transport not found: ", action.Server)
				if action.Tag == "" {
					state.anonymousFuture = nil
				}
				continue
			}
			if !action.Speculative && len(state.armedRules) > 0 {
				return exchangeWithRulesResult{}, &dnsWalkSuspension{drain: true}
			}
			queryOptions := state.effectiveOptions
			r.applyDNSRouteOptions(&queryOptions, action.RuleActionDNSRouteOptions)
			future := r.launchDNSEvaluate(ctx, state, action.Tag, transport, message, queryOptions)
			if action.Tag == "" {
				state.anonymousFuture = future
			} else {
				if state.namedFutures == nil {
					state.namedFutures = make(map[string]*dnsEvaluatedFuture)
				}
				state.namedFutures[action.Tag] = future
			}
		case *R.RuleActionRespond:
			if len(state.armedRules) > 0 {
				return exchangeWithRulesResult{}, &dnsWalkSuspension{drain: true}
			}
			if responseTag := currentRule.MatchResponseTag(); responseTag != "" {
				namedResponse := state.namedResponses[responseTag]
				if namedResponse == nil {
					return exchangeWithRulesResult{
						err: E.New(dnsRespondMissingResponseMessage),
					}, nil
				}
				return exchangeWithRulesResult{
					response:  namedResponse,
					transport: state.namedTransports[responseTag],
				}, nil
			}
			if !hasBindings {
				if future := state.anonymousFuture; future != nil && !future.resolved() {
					return exchangeWithRulesResult{}, &dnsWalkSuspension{await: future}
				}
			}
			response := state.anonymousResponse()
			if response == nil {
				return exchangeWithRulesResult{
					err: E.New(dnsRespondMissingResponseMessage),
				}, nil
			}
			return exchangeWithRulesResult{
				response:  response,
				transport: state.anonymousFuture.transport,
			}, nil
		case *R.RuleActionDNSRoute:
			queryOptions := state.effectiveOptions
			transport, status := r.resolveDNSRoute(action.Server, action.RuleActionDNSRouteOptions, allowFakeIP, &queryOptions)
			switch status {
			case dnsRouteStatusMissing:
				r.logger.ErrorContext(ctx, "transport not found: ", action.Server)
				continue
			case dnsRouteStatusSkipped:
				continue
			}
			if len(state.armedRules) > 0 {
				if action.Speculative && state.terminalFuture == nil {
					future := r.launchDNSEvaluate(ctx, state, "", transport, message, queryOptions)
					future.terminal = true
					state.terminalFuture = future
					state.terminalIndex = state.ruleIndex
				}
				return exchangeWithRulesResult{}, &dnsWalkSuspension{drain: true}
			}
			if state.terminalFuture != nil && state.terminalIndex == state.ruleIndex {
				return exchangeWithRulesResult{}, &dnsWalkSuspension{pending: &dnsPendingExchange{transport: state.terminalFuture.transport, future: state.terminalFuture}}
			}
			return exchangeWithRulesResult{}, &dnsWalkSuspension{pending: &dnsPendingExchange{transport: transport, options: queryOptions}}
		case *R.RuleActionReject:
			if len(state.armedRules) > 0 {
				return exchangeWithRulesResult{}, &dnsWalkSuspension{drain: true}
			}
			switch action.Method {
			case C.RuleActionRejectMethodDefault:
				return exchangeWithRulesResult{
					response:     dnsRefusedResponse(message),
					rejectAction: action,
				}, nil
			case C.RuleActionRejectMethodDrop:
				return exchangeWithRulesResult{
					rejectAction: action,
					err:          R.ErrDrop,
				}, nil
			}
		case *R.RuleActionPredefined:
			if len(state.armedRules) > 0 {
				return exchangeWithRulesResult{}, &dnsWalkSuspension{drain: true}
			}
			return exchangeWithRulesResult{
				response: action.Response(message),
			}, nil
		}
	}
	if len(state.armedRules) > 0 {
		return exchangeWithRulesResult{}, &dnsWalkSuspension{drain: true}
	}
	return exchangeWithRulesResult{}, &dnsWalkSuspension{pending: &dnsPendingExchange{transport: r.transport.Default(), options: state.effectiveOptions}}
}

func (r *Router) exchangeWithRules(ctx context.Context, rules []adapter.DNSRule, message *mDNS.Msg, options adapter.DNSQueryOptions, allowFakeIP bool) exchangeWithRulesResult {
	state := dnsRuleWalkState{effectiveOptions: options, lastLoggedIndex: -1}
	result, suspension := r.walkDNSRules(ctx, rules, message, &state, allowFakeIP)
	if suspension == nil {
		cancelDNSFutures(&state)
		return result
	}
	return r.resumeExchangeWithRules(ctx, rules, message, &state, allowFakeIP, suspension)
}

func (r *Router) resumeExchangeWithRules(ctx context.Context, rules []adapter.DNSRule, message *mDNS.Msg, state *dnsRuleWalkState, allowFakeIP bool, suspension *dnsWalkSuspension) exchangeWithRulesResult {
	defer cancelDNSFutures(state)
	for {
		r.settleDNSFutures(ctx, message, state)
		sweepResult, sweepPending, committed := r.sweepArmedDNSRules(ctx, message, state, allowFakeIP)
		if committed {
			if sweepPending != nil {
				return r.finishPendingExchange(ctx, message, state, sweepPending)
			}
			return sweepResult
		}
		if suspension != nil {
			if suspension.pending != nil {
				return r.finishPendingExchange(ctx, message, state, suspension.pending)
			}
			if (suspension.await != nil && !suspension.await.resolved()) || (suspension.drain && len(state.armedRules) > 0) {
				select {
				case <-state.wake:
				case <-ctx.Done():
					return exchangeWithRulesResult{err: ctx.Err()}
				}
				continue
			}
		}
		var result exchangeWithRulesResult
		result, suspension = r.walkDNSRules(ctx, rules, message, state, allowFakeIP)
		if suspension == nil {
			return result
		}
	}
}

func (r *Router) sweepArmedDNSRules(ctx context.Context, message *mDNS.Msg, state *dnsRuleWalkState, allowFakeIP bool) (exchangeWithRulesResult, *dnsPendingExchange, bool) {
	metadata := adapter.ContextFrom(ctx)
	for index := 0; index < len(state.armedRules); {
		armed := state.armedRules[index]
		ready := true
		for _, future := range armed.futures {
			if !future.resolved() {
				ready = false
				break
			}
		}
		if !ready {
			index++
			continue
		}
		state.armedRules = append(state.armedRules[:index], state.armedRules[index+1:]...)
		metadata.ResetRuleCache()
		if armed.bindsAnonymous {
			if armed.anonymousFuture != nil {
				metadata.DNSResponse = armed.anonymousFuture.view()
			} else {
				metadata.DNSResponse = nil
			}
		} else {
			metadata.DNSResponse = state.anonymousResponse()
		}
		metadata.NamedDNSResponses = state.namedResponses
		metadata.DestinationAddressMatchFromResponse = false
		if !armed.rule.Match(metadata) {
			continue
		}
		r.logRuleMatch(ctx, armed.ruleIndex, armed.rule)
		switch action := armed.rule.Action().(type) {
		case *R.RuleActionRespond:
			var (
				response  *mDNS.Msg
				transport adapter.DNSTransport
			)
			if responseTag := armed.rule.MatchResponseTag(); responseTag != "" {
				response = state.namedResponses[responseTag]
				transport = state.namedTransports[responseTag]
			} else if armed.anonymousFuture != nil {
				response = armed.anonymousFuture.view()
				transport = armed.anonymousFuture.transport
			} else if state.anonymousFuture != nil {
				response = state.anonymousResponse()
				transport = state.anonymousFuture.transport
			}
			if response == nil {
				return exchangeWithRulesResult{
					err: E.New(dnsRespondMissingResponseMessage),
				}, nil, true
			}
			return exchangeWithRulesResult{
				response:  response,
				transport: transport,
			}, nil, true
		case *R.RuleActionDNSRoute:
			queryOptions := armed.options
			transport, status := r.resolveDNSRoute(action.Server, action.RuleActionDNSRouteOptions, allowFakeIP, &queryOptions)
			switch status {
			case dnsRouteStatusMissing:
				r.logger.ErrorContext(ctx, "transport not found: ", action.Server)
				continue
			case dnsRouteStatusSkipped:
				continue
			}
			return exchangeWithRulesResult{}, &dnsPendingExchange{transport: transport, options: queryOptions}, true
		case *R.RuleActionReject:
			switch action.Method {
			case C.RuleActionRejectMethodDefault:
				return exchangeWithRulesResult{
					response:     dnsRefusedResponse(message),
					rejectAction: action,
				}, nil, true
			case C.RuleActionRejectMethodDrop:
				return exchangeWithRulesResult{
					rejectAction: action,
					err:          R.ErrDrop,
				}, nil, true
			}
		case *R.RuleActionPredefined:
			return exchangeWithRulesResult{
				response: action.Response(message),
			}, nil, true
		}
	}
	return exchangeWithRulesResult{}, nil, false
}

func (r *Router) finishPendingExchange(ctx context.Context, message *mDNS.Msg, state *dnsRuleWalkState, pending *dnsPendingExchange) exchangeWithRulesResult {
	for _, future := range state.futures {
		if future != pending.future {
			future.cancel()
		}
	}
	if pending.future != nil {
		select {
		case <-pending.future.done:
		case <-ctx.Done():
			return exchangeWithRulesResult{err: ctx.Err()}
		}
		return exchangeWithRulesResult{
			response:  pending.future.view(),
			transport: pending.future.transport,
			err:       pending.future.err,
		}
	}
	response, err := r.client.Exchange(adapter.OverrideContext(ctx), pending.transport, message, r.finalizeExchangeOptions(pending.options), nil)
	return exchangeWithRulesResult{
		response:  response,
		transport: pending.transport,
		err:       err,
	}
}

func (r *Router) exchangeWithRulesAsync(ctx context.Context, rules []adapter.DNSRule, message *mDNS.Msg, options adapter.DNSQueryOptions, allowFakeIP bool, callback func(result exchangeWithRulesResult)) {
	state := &dnsRuleWalkState{effectiveOptions: options, lastLoggedIndex: -1}
	result, suspension := r.walkDNSRules(ctx, rules, message, state, allowFakeIP)
	if suspension == nil {
		cancelDNSFutures(state)
		callback(result)
		return
	}
	if suspension.pending != nil && suspension.pending.future == nil {
		cancelDNSFutures(state)
		pending := suspension.pending
		r.client.ExchangeAsync(adapter.OverrideContext(ctx), pending.transport, message, r.finalizeExchangeOptions(pending.options), nil, func(response *mDNS.Msg, err error) {
			callback(exchangeWithRulesResult{
				response:  response,
				transport: pending.transport,
				err:       err,
			})
		})
		return
	}
	go func() {
		callback(r.resumeExchangeWithRules(ctx, rules, message, state, allowFakeIP, suspension))
	}()
}

// ResolveStrategy reports the strategy that will actually be applied for the given options.
//
// AsIS means "use this router's default", and only the router knows what that is. A caller that
// must plan or order work with the SAME policy the lookup will use - rather than re-deriving it
// from the raw options - reads it here. Without this, a caller passing AsIS sees only the literal
// value and cannot tell "no preference expressed" from "the default is about to be applied".
func (r *Router) ResolveStrategy(options adapter.DNSQueryOptions) C.DomainStrategy {
	return r.resolveLookupStrategy(options)
}

func (r *Router) resolveLookupStrategy(options adapter.DNSQueryOptions) C.DomainStrategy {
	if options.LookupStrategy != C.DomainStrategyAsIS {
		return options.LookupStrategy
	}
	if options.Strategy != C.DomainStrategyAsIS {
		return options.Strategy
	}
	return r.defaultDomainStrategy
}

func withLookupQueryMetadata(ctx context.Context, qType uint16) context.Context {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.QueryType = qType
	metadata.QueryClientSubnet = netip.Prefix{}
	metadata.QueryDNSSEC = false
	metadata.IPVersion = 0
	switch qType {
	case mDNS.TypeA:
		metadata.IPVersion = 4
	case mDNS.TypeAAAA:
		metadata.IPVersion = 6
	}
	return ctx
}

func filterAddressesByQueryType(addresses []netip.Addr, qType uint16) []netip.Addr {
	switch qType {
	case mDNS.TypeA:
		return common.Filter(addresses, func(address netip.Addr) bool {
			return address.Is4()
		})
	case mDNS.TypeAAAA:
		return common.Filter(addresses, func(address netip.Addr) bool {
			return address.Is6()
		})
	default:
		return addresses
	}
}

func (r *Router) lookupWithRules(ctx context.Context, rules []adapter.DNSRule, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	strategy := r.resolveLookupStrategy(options)
	lookupOptions := options
	if strategy != C.DomainStrategyAsIS {
		lookupOptions.Strategy = strategy
	}
	if strategy == C.DomainStrategyIPv4Only {
		return r.lookupWithRulesType(ctx, rules, domain, mDNS.TypeA, lookupOptions)
	}
	if strategy == C.DomainStrategyIPv6Only {
		return r.lookupWithRulesType(ctx, rules, domain, mDNS.TypeAAAA, lookupOptions)
	}
	var (
		response4 []netip.Addr
		response6 []netip.Addr
	)
	// The epoch this complete lookup belongs to, captured BEFORE either family is dispatched.
	//
	// A and AAAA are two independent resolutions, and each captures the network generation when its
	// own request is issued. A reset landing between them splits them: A is answered on the network
	// that has been left and AAAA on the one that is current. Both halves are individually
	// well-formed, and the caller receives ONE address set that was never simultaneously true on any
	// network - with nothing in the result distinguishing them.
	//
	// A complete lookup is a single claim about a name, so its halves must share an epoch. The
	// streaming entry point is deliberately different: each family is published as its own
	// observation, so a superseded one simply loses a connection race there.
	lookupEpoch := r.dnsGeneration()

	var group task.Group
	group.Append("exchange4", func(ctx context.Context) error {
		result, err := r.lookupWithRulesType(ctx, rules, domain, mDNS.TypeA, lookupOptions)
		response4 = result
		return err
	})
	group.Append("exchange6", func(ctx context.Context) error {
		result, err := r.lookupWithRulesType(ctx, rules, domain, mDNS.TypeAAAA, lookupOptions)
		response6 = result
		return err
	})
	err := group.Run(ctx)
	if len(response4) == 0 && len(response6) == 0 {
		return nil, err
	}

	// Refuse a set assembled across an epoch change, before it can be observed as a complete answer.
	//
	// Refusing is the minimal behaviour change: the answer was never valid, so it becomes an error
	// rather than a silently half-stale success. The per-exchange generation guard keeps doing its
	// own job - nothing from a superseded family is cached either way.
	if r.dnsGeneration() != lookupEpoch {
		return nil, E.New("network changed while resolving ", domain,
			"; the address families belong to different networks")
	}

	return sortAddresses(response4, response6, strategy), nil
}

func (r *Router) lookupWithRulesType(ctx context.Context, rules []adapter.DNSRule, domain string, qType uint16, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	request := &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			RecursionDesired: true,
		},
		Question: []mDNS.Question{{
			Name:   mDNS.Fqdn(domain),
			Qtype:  qType,
			Qclass: mDNS.ClassINET,
		}},
	}
	exchangeResult := r.exchangeWithRules(withLookupQueryMetadata(ctx, qType), rules, request, options, false)
	if exchangeResult.rejectAction != nil {
		return nil, exchangeResult.rejectAction.Error(ctx)
	}
	if exchangeResult.err != nil {
		return nil, exchangeResult.err
	}
	if exchangeResult.response.Rcode != mDNS.RcodeSuccess {
		return nil, RcodeError(exchangeResult.response.Rcode)
	}
	return filterAddressesByQueryType(MessageToAddresses(exchangeResult.response), qType), nil
}

type dnsExchangeContext struct {
	ctx           context.Context
	rules         []adapter.DNSRule
	legacyDNSMode bool
	metadata      *adapter.InboundContext
	// generation is the network generation this request was issued on.
	generation uint64
}

func (r *Router) prepareExchange(ctx context.Context, message *mDNS.Msg) (*dnsExchangeContext, *mDNS.Msg, error) {
	if r.powerManager != nil {
		recorder := r.powerManager.Recorder()
		if recorder != nil {
			var domain string
			if len(message.Question) == 1 {
				domain = message.Question[0].Name
			}
			recorder.CountDNSQuery(domain)
		}
	}
	if len(message.Question) != 1 {
		r.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		return nil, &mDNS.Msg{
			MsgHdr: mDNS.MsgHdr{
				Id:       message.Id,
				Response: true,
				Rcode:    mDNS.RcodeFormatError,
			},
			Question: message.Question,
		}, nil
	}
	if isResolverDiscoveryQuery(message.Question[0]) {
		r.logger.DebugContext(ctx, "rejected resolver discovery query ", FormatQuestion(message.Question[0].String()))
		return nil, &mDNS.Msg{
			MsgHdr: mDNS.MsgHdr{
				Id:                 message.Id,
				Response:           true,
				RecursionDesired:   message.RecursionDesired,
				RecursionAvailable: true,
				Rcode:              mDNS.RcodeSuccess,
			},
			Question: message.Question,
		}, nil
	}
	r.rulesAccess.RLock()
	if r.closing {
		r.rulesAccess.RUnlock()
		return nil, nil, E.New("dns router closed")
	}
	rules := r.rules
	legacyDNSMode := r.legacyDNSMode
	r.rulesAccess.RUnlock()
	r.logger.DebugContext(ctx, "exchange ", FormatQuestion(message.Question[0].String()))
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Destination = M.Socksaddr{}
	metadata.QueryType = message.Question[0].Qtype
	metadata.DNSResponse = nil
	metadata.NamedDNSResponses = nil
	metadata.DestinationAddressMatchFromResponse = false
	switch metadata.QueryType {
	case mDNS.TypeA:
		metadata.IPVersion = 4
	case mDNS.TypeAAAA:
		metadata.IPVersion = 6
	}
	metadata.Domain = FqdnToDomain(message.Question[0].Name)
	metadata.QueryClientSubnet = clientSubnetFromMessage(message)
	edns0Option := message.IsEdns0()
	metadata.QueryDNSSEC = edns0Option != nil && edns0Option.Do()
	return &dnsExchangeContext{
		ctx:           ctx,
		rules:         rules,
		legacyDNSMode: legacyDNSMode,
		metadata:      metadata,
		// The generation is captured HERE, when the request is issued.
		//
		// Reading it when the response arrives is not a guard at all: a request in flight across a
		// network change would capture the post-change value, compare it against itself, match, and
		// write into the cache the change had just purged. The comparison has to be against the
		// network the question was asked on.
		generation: r.dnsGeneration(),
	}, nil, nil
}

// dnsGeneration returns the current DNS generation: the network epoch plus the DNS environment
// epoch.
//
// # Why there are two components
//
// The network epoch answers "has a NETWORK transition begun since I captured this". It advances in
// Router.ResetNetwork, and it is the right counter for a changed interface, gateway or SSID.
//
// It is the wrong counter for a change to only the DNS servers or search domains on an UNCHANGED
// interface. Such a change moves nothing the network epoch watches: route/network_environment.go
// hashes the default interface's gateways, the Wi-Fi SSID and the gateway hardware addresses, and
// nothing else; the Darwin monitor that drives it reads an AF_ROUTE socket and emits on a route
// message, which a dnsinfo change is not. So the network epoch does not move, and neither does
// Router.ResetNetwork run.
//
// Every DNS cache except one is nevertheless safe, because Client.environmentHash mixes each
// transport's LIVE environment list into its cache namespace - the exact entry, the NXDOMAIN
// verdict, the RDRC namespace and the persistent key all carry it, so a resolver change separates
// them on its own. The REVERSE MAPPING is the exception: its only namespace is this generation. Its
// purge in Router.ResetNetwork is justified by exactly the case a resolver change IS - "with
// split-horizon or captive-portal DNS the same address can mean a different name on the new
// network" - and a resolver change on the same interface reaches that case without reaching the
// reset.
//
// # What the DNS environment epoch deliberately does NOT do
//
// It does not run the network reset body, does not advance NetworkManager's reset epoch, and does
// not publish anything to runtimecoord. A resolver change is not a network transition: the sockets
// still lead to the right network, and tearing them down for it would kill every active QUIC, H2,
// MASQUE and voice session on a device whose network never changed. Only the DNS layer's own
// ownership epoch moves, plus the one cache that has no other namespace.
//
// # Why the observation happens here rather than at a notification
//
// There is no push to hook. dns/transport/local/systemconfig/source_darwin.go registers a
// notify_register_check token and POLLS it with notify_check; notify_check is not a blocking wait,
// so nothing is woken when the DNS configuration changes and the change becomes visible only when
// something reads it. Reading it here makes every consumer of the generation - the request capture,
// the response ownership check and the reverse mapping guard - observe the environment before it
// acts on the epoch, so no reader can act on a generation that a resolver change has already
// invalidated. It is the same "no debounce, the recompute decides" shape as
// NetworkManager.postUpdateNetworkEnvironment, and it needs no goroutine, timer or extra lock
// ordering.
//
// # Cost
//
// One aggregate observation per generation read, where the DNS path previously observed the issuing
// transport's environment once or twice per query. The transports cache their own reads, so an
// unchanged environment costs one notify_check per transport.
func (r *Router) dnsGeneration() uint64 {
	return r.networkGeneration.Load() + r.observeDNSEnvironment()
}

// dnsGenerationLocked is dnsGeneration for a caller that already holds dnsEnvironmentAccess.
//
// The lock is NOT reentrant, so the two-phase commit in commitReverseMappingAnswers - the one place
// that has to read the epoch and publish under the same acquisition - cannot call dnsGeneration. This
// is the same expression with that one acquisition removed, and it exists so the commit path has no
// second lock to order: the epoch it compares against is read from the counter the invalidation
// advances, while the invalidation cannot run.
func (r *Router) dnsGenerationLocked() uint64 {
	return r.networkGeneration.Load() + r.observeDNSEnvironmentLocked()
}

// observeDNSEnvironment refreshes the aggregate DNS environment fingerprint and returns the DNS
// environment epoch that is current as a result.
//
// The compare, the advance and the read happen under one lock, so the fingerprint and the epoch are
// a single observation: a reader that sees the new epoch has also seen the fingerprint that
// produced it, and no reader can advance the epoch twice for one change.
func (r *Router) observeDNSEnvironment() uint64 {
	if r.transport == nil {
		// A Router built without a transport manager has no DNS environment to observe, and
		// nothing to attribute an answer to either. Degrade to the network epoch alone.
		return r.dnsEnvironmentGeneration.Load()
	}
	// The snapshot is taken INSIDE the lock, and that is load-bearing rather than tidy.
	//
	// Reading the snapshot first and locking only to compare is a lost-update race. Two observers
	// see states A and B; the one that saw B locks first, advances the epoch and stores B; the one
	// still holding A then locks, finds A != B, and stores A on top of it. The next observation of
	// B is a "change" again. The epoch advances twice for one change, and while two observers keep
	// interleaving the stored fingerprint oscillates between A and B and the epoch advances without
	// bound - the reset storm the de-bounce exists to prevent, produced by the de-bounce itself.
	//
	// Held across the transports' Environment() reads, this is a leaf lock: an Environment()
	// implementation reads platform state and does not call back into the router. The cost is that
	// one observation runs at a time; the transports cache their own reads, so an unchanged
	// environment is one notify_check per transport.
	r.dnsEnvironmentAccess.Lock()
	defer r.dnsEnvironmentAccess.Unlock()
	return r.observeDNSEnvironmentLocked()
}

// observeDNSEnvironmentLocked is the body of observeDNSEnvironment, for callers that already hold
// dnsEnvironmentAccess.
//
// Holding the lock is what makes "the fingerprint I compared" and "the epoch I produced" one atomic
// mutation, and it is also what makes the two-phase commit in commitReverseMappingAnswers a single
// decision: while the commit holds this lock, an invalidation cannot advance the epoch or purge
// between its check and its writes.
func (r *Router) observeDNSEnvironmentLocked() uint64 {
	if r.transport == nil {
		// A Router built without a transport manager has no DNS environment to observe, and
		// nothing to attribute an answer to either. Degrade to the network epoch alone.
		return r.dnsEnvironmentGeneration.Load()
	}
	fingerprint, description, pinned := r.dnsEnvironmentFingerprintNow()
	if !r.dnsEnvironmentObserved {
		// The FIRST observation pins without advancing.
		//
		// It is not a change: there is no previous environment for anything to be stale against.
		// Advancing here would also make the initial epoch depend on whether a query happened to
		// be issued before the first one - a value that must be a property of the network, not of
		// the order in which the box's callers happened to ask. It matches how
		// Client.transportEnvironment pins its own first observation.
		r.dnsEnvironmentObserved = true
		r.dnsEnvironmentFingerprint = fingerprint
		r.dnsEnvironmentDescription = description
		if pinned {
			r.logger.Debug("pinned DNS environment: ", description)
		}
		return r.dnsEnvironmentGeneration.Load()
	}
	if fingerprint == r.dnsEnvironmentFingerprint {
		// A duplicate or reordered notification carrying the same information. This is the
		// de-bounce: notify_check documents false positives, and the platform repeats itself, but
		// a repeated notification is not a state change and must not cost an epoch.
		return r.dnsEnvironmentGeneration.Load()
	}
	r.dnsEnvironmentFingerprint = fingerprint
	r.dnsEnvironmentDescription = description
	r.dnsEnvironmentGeneration.Add(1)
	epoch := r.dnsEnvironmentGeneration.Load()
	// The reverse mapping is the one DNS cache with no environment component in its key, so it is
	// the one that has to be purged here. With split-horizon or captive-portal DNS the same address
	// can mean a different name on the new resolver set, which is the reason Router.ResetNetwork
	// purges it for a network change; a resolver change reaches the same case without a network
	// change.
	//
	// The other caches - the exact entry, the NXDOMAIN verdict, the RDC namespace and the
	// persistent key - are namespaced by Client.environmentHash, which already mixes the
	// transport's environment list in. Purging them here would additionally discard entries that
	// are still correct for the old resolver set and are simply no longer reachable, and would make
	// a resolver change far more expensive than it needs to be.
	if r.dnsReverseMapping != nil {
		r.dnsReverseMapping.Purge()
	}
	r.logger.Info("DNS environment changed, advancing DNS generation to ", epoch, ": ", description)
	return epoch
}

// dnsEnvironmentFingerprintNow builds the aggregate fingerprint of every transport's published DNS
// environment, and reports whether any transport published one at all.
//
// A transport that publishes an EMPTY list contributes nothing, which is the same rule
// Client.environmentHash applies when it decides that a transport with no list of its own is
// namespaced by the network alone. Keeping the two consistent by construction is what lets this
// fingerprint stand in for "the DNS namespace the caches are about to use".
//
// The transports are sorted by TAG, because Transports() is backed by a map and map iteration order
// is not a property of the environment. Within one transport the published order is SIGNIFICANT, for
// two reasons that agree:
//
//   - Client.environmentHash hashes the list in order, so a reordered list is already a different
//     cache namespace. A fingerprint that ignored the order would leave the reverse mapping and the
//     in-flight generation guards on the old epoch while the caches had already moved to the new
//     namespace - the epoch would be WEAKER than the namespace it is supposed to bound;
//   - the order is resolution semantics, not bookkeeping. Config.NameList walks the search list in
//     order and newNameExchanger walks the server list in order, so the same addresses in a
//     different order can produce a different answer.
//
// The cost of being order-sensitive is that a platform returning its resolver list in a
// nondeterministically shuffled order would advance an epoch on every read. That risk is real and is
// stated rather than hidden; the measured behaviour of both readers this tree has - dnsinfo's
// nameserver array and resolv.conf's lines - is index-stable for an unchanged configuration, and
// TestDuplicateDNSEnvironmentNotificationDoesNotAdvanceWithoutBound asserts that a stably re-read
// environment does not advance.
func (r *Router) dnsEnvironmentFingerprintNow() (uint64, string, bool) {
	type publishedEnvironment struct {
		tag     string
		entries []string
	}
	var published []publishedEnvironment
	for _, transport := range r.transport.Transports() {
		environmentTransport, withEnvironment := transport.(adapter.DNSTransportWithEnvironment)
		if !withEnvironment {
			continue
		}
		environment := environmentTransport.Environment()
		if len(environment) == 0 {
			continue
		}
		published = append(published, publishedEnvironment{tag: transport.Tag(), entries: environment})
	}
	if len(published) == 0 {
		return 0, "", false
	}
	slices.SortFunc(published, func(a publishedEnvironment, b publishedEnvironment) int {
		return strings.Compare(a.tag, b.tag)
	})
	// The hash is taken over NUL-separated parts, because a tag is user-configured text and "="
	// alone would let two different (tag, entry) splits collide. The description is built separately
	// and is log-safe: a NUL byte in a log line truncates it in every consumer.
	digest := fnv.New64a()
	descriptions := make([]string, 0, len(published))
	for _, environment := range published {
		for _, entry := range environment.entries {
			digest.Write([]byte(environment.tag))
			digest.Write([]byte{0})
			digest.Write([]byte(entry))
			digest.Write([]byte{0})
			descriptions = append(descriptions, environment.tag+"="+entry)
		}
	}
	return digest.Sum64(), strings.Join(descriptions, ", "), true
}

// reverseMappingGenerationCurrent reports whether a captured generation still describes the live
// network.
//
// # Why this is one function rather than a condition written twice
//
// The guard appeared twice: inline in recordReverseMappingFrom, and again in a test-facing helper
// that recorded a mapping. Two copies of one rule can drift, and the drift is invisible in the worst
// direction - production could be corrected while the test-facing copy kept the old behaviour, so the
// tests would keep passing against a rule the product no longer follows.
//
// The condition lives here, and both callers use it.
//
// It reads dnsGeneration rather than networkGeneration so that a DNS-only environment change counts
// as an epoch change for the one cache that has no other namespace. The reverse mapping is a
// statement about what a name means on a resolver set, so it belongs to that resolver set, not to
// the route the query happened to travel.
func (r *Router) reverseMappingGenerationCurrent(generation uint64) bool {
	if r.dnsReverseMapping == nil {
		return false
	}
	return generation == r.dnsGeneration()
}

// reverseMappingAnswer is one address-to-name mapping learned from a DNS answer.
type reverseMappingAnswer struct {
	address  netip.Addr
	domain   string
	lifetime time.Duration
}

// reverseMappingAnswersFrom extracts the address-to-name pairs a response carries.
//
// Fake-IP answers are excluded HERE rather than at the write: a fake address is a local stand-in for
// a name, not something a resolver said the name means, so it must never enter the one cache route
// policy reads as "what this address really is".
func reverseMappingAnswersFrom(response *mDNS.Msg, transport adapter.DNSTransport) []reverseMappingAnswer {
	if response == nil || len(response.Answer) == 0 {
		return nil
	}
	if transport != nil && transport.Type() == C.DNSTypeFakeIP {
		return nil
	}
	var answers []reverseMappingAnswer
	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *mDNS.A:
			answers = append(answers, reverseMappingAnswer{
				address:  M.AddrFromIP(record.A),
				domain:   FqdnToDomain(record.Hdr.Name),
				lifetime: time.Duration(record.Hdr.Ttl) * time.Second,
			})
		case *mDNS.AAAA:
			answers = append(answers, reverseMappingAnswer{
				address:  M.AddrFromIP(record.AAAA),
				domain:   FqdnToDomain(record.Hdr.Name),
				lifetime: time.Duration(record.Hdr.Ttl) * time.Second,
			})
		}
	}
	return answers
}

// recordReverseMappingFrom records a mapping only if the response still belongs to the resolver set it
// was asked on.
//
// The generation is captured when the REQUEST is issued and re-checked here, but the check alone is
// not the guard: it is the check TOGETHER WITH the write, under one lock, that makes this atomic
// against the invalidation protocol.
//
// # Why the check and the write cannot be two steps
//
// Everything that retires this cache - observeDNSEnvironment for a resolver/search-domain change,
// ResetNetwork for a network transition - advances an epoch and then purges, and both do it under
// dnsEnvironmentAccess. Read-then-write with nothing in between is not a guard against them: the
// purge lands in the gap, clears a cache the write has not filled yet, and the write then adds the
// answer it was supposed to retire. What route-rule matching reads afterwards is a name learned from
// resolvers the device is no longer using, which is the exact outcome ResetNetwork's purge exists to
// prevent.
//
// # What the locked section establishes
//
// The epoch is re-read from the same counter the invalidation advances, inside the lock that
// invalidation holds while it advances it and purges. So either the invalidation happened first - the
// epoch moved, the answers are refused, nothing is written - or the write happened first, and the
// purge that follows removes exactly what it wrote. There is no third ordering.
//
// # Cost
//
// One acquisition of the lock this path already takes for its observation. The answers are extracted
// before the lock, so only the comparison and the writes are inside it, and the writes are bounded by
// the number of A/AAAA records in one response.
func (r *Router) recordReverseMappingFrom(message *mDNS.Msg, response *mDNS.Msg, transport adapter.DNSTransport, generation uint64) {
	if r.dnsReverseMapping == nil {
		return
	}
	if len(message.Question) == 0 {
		return
	}
	answers := reverseMappingAnswersFrom(response, transport)
	if len(answers) == 0 {
		return
	}
	r.commitReverseMappingAnswers(answers, generation)
}

// commitReverseMappingAnswers publishes a response's answers if, and only if, the captured epoch is
// still current at the moment of publication.
//
// The comparison and the writes are one decision because they are made while holding
// dnsEnvironmentAccess: that is the lock the invalidation protocol - observeDNSEnvironment's advance
// and Purge, and ResetNetwork's - is performed under, so no invalidation can be interleaved between
// this check and these writes. See recordReverseMappingFrom for why that matters.
//
// The lock covers the two things it may cover here and nothing else: reading the counter and
// publishing already-extracted answers into the cache. Nothing inside the critical section calls out,
// waits, or takes another lock.
func (r *Router) commitReverseMappingAnswers(answers []reverseMappingAnswer, generation uint64) {
	// The seam sits at the START of the commit protocol, and that is the only place it can sit.
	//
	// Everything this protocol excludes - purging the cache, advancing an epoch - has to happen while
	// this side is stopped, and every one of those operations takes dnsEnvironmentAccess itself. A
	// seam held INSIDE the critical section would deadlock the invalidation instead of interleaving
	// with it, and would prove nothing about the ordering. Held here, a test establishes the exact
	// ordering the protocol is a claim about: the recording side has passed every pre-lock step, and
	// the invalidation runs to completion before the guarded comparison is made.
	if hook := r.testReverseMappingRecordHook; hook != nil {
		hook(answers, generation)
	}
	r.dnsEnvironmentAccess.Lock()
	defer r.dnsEnvironmentAccess.Unlock()
	if generation != r.dnsGenerationLocked() {
		return
	}
	for _, answer := range answers {
		r.dnsReverseMapping.AddWithLifetime(answer.address, answer.domain, answer.lifetime)
	}
}

func (r *Router) exchangeLegacy(ctx context.Context, exchangeCtx *dnsExchangeContext, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, adapter.DNSTransport, error) {
	var (
		transport adapter.DNSTransport
		rule      adapter.DNSRule
		ruleIndex int
	)
	ruleIndex = -1
	for {
		dnsCtx := adapter.OverrideContext(ctx)
		dnsOptions := options
		transport, rule, ruleIndex = r.matchDNS(ctx, exchangeCtx.rules, true, ruleIndex, isAddressQuery(message), &dnsOptions)
		if rule != nil {
			switch action := rule.Action().(type) {
			case *R.RuleActionReject:
				switch action.Method {
				case C.RuleActionRejectMethodDefault:
					return &mDNS.Msg{
						MsgHdr: mDNS.MsgHdr{
							Id:       message.Id,
							Rcode:    mDNS.RcodeRefused,
							Response: true,
						},
						Question: []mDNS.Question{message.Question[0]},
					}, nil, nil
				case C.RuleActionRejectMethodDrop:
					return nil, nil, R.ErrDrop
				}
			case *R.RuleActionPredefined:
				return action.Response(message), nil, nil
			}
		}
		responseCheck := addressLimitResponseCheck(rule, exchangeCtx.metadata)
		response, err := r.client.Exchange(dnsCtx, transport, message, r.finalizeExchangeOptions(dnsOptions), responseCheck)
		var rejected bool
		if err != nil {
			if errors.Is(err, ErrResponseRejectedCached) {
				rejected = true
				r.logger.DebugContext(ctx, E.Cause(err, "response rejected for ", FormatQuestion(message.Question[0].String())), " (cached)")
			} else if errors.Is(err, ErrResponseRejected) {
				rejected = true
				r.logger.DebugContext(ctx, E.Cause(err, "response rejected for ", FormatQuestion(message.Question[0].String())))
			} else if len(message.Question) > 0 {
				r.logger.ErrorContext(ctx, E.Cause(err, "exchange failed for ", FormatQuestion(message.Question[0].String())))
			} else {
				r.logger.ErrorContext(ctx, E.Cause(err, "exchange failed for <empty query>"))
			}
		}
		if responseCheck != nil && rejected {
			continue
		}
		return response, transport, err
	}
}

func (r *Router) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	exchangeCtx, earlyResponse, err := r.prepareExchange(ctx, message)
	if exchangeCtx == nil {
		return earlyResponse, err
	}
	ctx = exchangeCtx.ctx
	var (
		response  *mDNS.Msg
		transport adapter.DNSTransport
	)
	if options.Transport != nil {
		transport = options.Transport
		response, err = r.client.Exchange(ctx, transport, message, r.finalizeExchangeOptions(options), nil)
	} else if !exchangeCtx.legacyDNSMode {
		exchangeResult := r.exchangeWithRules(ctx, exchangeCtx.rules, message, options, true)
		response, transport, err = exchangeResult.response, exchangeResult.transport, exchangeResult.err
	} else {
		response, transport, err = r.exchangeLegacy(ctx, exchangeCtx, message, options)
	}
	if err != nil {
		return nil, err
	}
	r.recordReverseMappingFrom(message, response, transport, exchangeCtx.generation)
	return response, nil
}

func (r *Router) ExchangeAsync(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, callback func(response *mDNS.Msg, err error)) {
	exchangeCtx, earlyResponse, err := r.prepareExchange(ctx, message)
	if exchangeCtx == nil {
		callback(earlyResponse, err)
		return
	}
	ctx = exchangeCtx.ctx
	if options.Transport != nil {
		transport := options.Transport
		r.client.ExchangeAsync(ctx, transport, message, r.finalizeExchangeOptions(options), nil, func(response *mDNS.Msg, exchangeErr error) {
			r.finishExchangeAsync(message, transport, response, exchangeErr, exchangeCtx.generation, callback)
		})
	} else if !exchangeCtx.legacyDNSMode {
		r.exchangeWithRulesAsync(ctx, exchangeCtx.rules, message, options, true, func(result exchangeWithRulesResult) {
			r.finishExchangeAsync(message, result.transport, result.response, result.err, exchangeCtx.generation, callback)
		})
	} else {
		go func() {
			response, transport, exchangeErr := r.exchangeLegacy(ctx, exchangeCtx, message, options)
			r.finishExchangeAsync(message, transport, response, exchangeErr, exchangeCtx.generation, callback)
		}()
	}
}

func (r *Router) finishExchangeAsync(message *mDNS.Msg, transport adapter.DNSTransport, response *mDNS.Msg, err error, generation uint64, callback func(response *mDNS.Msg, err error)) {
	if err != nil {
		callback(nil, err)
		return
	}
	r.recordReverseMappingFrom(message, response, transport, generation)
	callback(response, nil)
}

func (r *Router) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.rulesAccess.RLock()
	if r.closing {
		r.rulesAccess.RUnlock()
		return nil, E.New("dns router closed")
	}
	rules := r.rules
	legacyDNSMode := r.legacyDNSMode
	r.rulesAccess.RUnlock()
	var (
		responseAddrs []netip.Addr
		err           error
	)
	printResult := func() {
		if err == nil && len(responseAddrs) == 0 {
			err = E.New("empty result")
		}
		if err != nil {
			if errors.Is(err, ErrResponseRejectedCached) {
				r.logger.DebugContext(ctx, "response rejected for ", domain, " (cached)")
			} else if errors.Is(err, ErrResponseRejected) {
				r.logger.DebugContext(ctx, "response rejected for ", domain)
			} else if R.IsRejected(err) {
				r.logger.DebugContext(ctx, "lookup rejected for ", domain)
			} else if errors.Is(err, ErrNotCached) {
				r.logger.DebugContext(ctx, "cache-only lookup missed for ", domain)
			} else {
				r.logger.ErrorContext(ctx, E.Cause(err, "lookup failed for ", domain))
			}
		}
		if err != nil {
			err = E.Cause(err, "lookup ", domain)
		}
	}
	r.logger.DebugContext(ctx, "lookup domain ", domain)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Destination = M.Socksaddr{}
	metadata.Domain = FqdnToDomain(domain)
	metadata.DNSResponse = nil
	metadata.NamedDNSResponses = nil
	metadata.DestinationAddressMatchFromResponse = false
	if options.Transport != nil {
		transport := options.Transport
		if options.Strategy == C.DomainStrategyAsIS {
			options.Strategy = r.defaultDomainStrategy
		}
		responseAddrs, err = r.client.Lookup(ctx, transport, domain, options, nil)
	} else if !legacyDNSMode {
		responseAddrs, err = r.lookupWithRules(ctx, rules, domain, options)
	} else {
		var (
			transport adapter.DNSTransport
			rule      adapter.DNSRule
			ruleIndex int
		)
		ruleIndex = -1
		for {
			dnsCtx := adapter.OverrideContext(ctx)
			dnsOptions := options
			transport, rule, ruleIndex = r.matchDNS(ctx, rules, false, ruleIndex, true, &dnsOptions)
			if rule != nil {
				switch action := rule.Action().(type) {
				case *R.RuleActionReject:
					return nil, &R.RejectedError{Cause: action.Error(ctx)}
				case *R.RuleActionPredefined:
					responseAddrs = nil
					if action.Rcode != mDNS.RcodeSuccess {
						err = RcodeError(action.Rcode)
					} else {
						err = nil
						for _, answer := range action.Answer {
							switch record := answer.(type) {
							case *mDNS.A:
								responseAddrs = append(responseAddrs, M.AddrFromIP(record.A))
							case *mDNS.AAAA:
								responseAddrs = append(responseAddrs, M.AddrFromIP(record.AAAA))
							}
						}
					}
					goto response
				}
			}
			responseCheck := addressLimitResponseCheck(rule, metadata)
			if dnsOptions.Strategy == C.DomainStrategyAsIS {
				dnsOptions.Strategy = r.defaultDomainStrategy
			}
			responseAddrs, err = r.client.Lookup(dnsCtx, transport, domain, dnsOptions, responseCheck)
			if responseCheck == nil || err == nil {
				break
			}
			printResult()
		}
	}
response:
	printResult()
	if len(responseAddrs) > 0 {
		r.logger.InfoContext(ctx, "lookup succeed for ", domain, ": ", strings.Join(F.MapToString(responseAddrs), " "))
	}
	return responseAddrs, err
}

func isResolverDiscoveryQuery(question mDNS.Question) bool {
	return question.Qtype == mDNS.TypeSVCB && len(question.Name) > 5 && strings.EqualFold(question.Name[:5], "_dns.")
}

func isAddressQuery(message *mDNS.Msg) bool {
	for _, question := range message.Question {
		if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA || question.Qtype == mDNS.TypeHTTPS {
			return true
		}
	}
	return false
}

func addressLimitResponseCheck(rule adapter.DNSRule, metadata *adapter.InboundContext) func(response *mDNS.Msg) bool {
	if rule == nil || !rule.WithAddressLimit() {
		return nil
	}
	responseMetadata := *metadata
	return func(response *mDNS.Msg) bool {
		checkMetadata := responseMetadata
		return rule.MatchAddressLimit(&checkMetadata, response)
	}
}

func (r *Router) ClearCache() {
	r.client.ClearCache()
	if r.platformInterface != nil {
		r.platformInterface.ClearDNSCache()
	}
	if r.dnsReverseMapping != nil {
		r.dnsReverseMapping.Purge()
	}
}

// LookupReverseMapping answers "what name does this address mean".
//
// # Why it observes the DNS environment before it reads
//
// This is the only reader of a DNS cache that is not namespaced by the live environment: the exact
// entry, the NXDOMAIN verdict, the RDRC namespace and the persistent key all mix
// Client.environmentHash in, so a resolver change separates them by construction. This cache is
// guarded by the generation alone, and the generation only moves when SOMETHING observes the
// environment.
//
// observeDNSEnvironment is called from the query path - prepareExchange, the response ownership check
// and the reverse mapping commit - so a resolver change is noticed at the next DNS request. That is
// not good enough for this caller: route/route.go reads this mapping while matching a connection that
// needs no DNS request at all (a literal destination address, or a name already known), so between
// the change and the first new query a route rule could match on a name learned from the previous
// resolver set. Reading without observing is a read of the retired epoch.
//
// # Cost
//
// One observation, which is a mutex, a loop over the transports and an FNV hash over the entries they
// publish. The transports cache their own platform reads, so an unchanged environment is a cached
// value per transport; a change advances the epoch and purges here rather than at the next query.
// This is the same observation dnsGeneration already performs several times per DNS exchange, moved
// onto the connection path, and it is what makes the epoch a property of the environment rather than
// of who happened to ask.
func (r *Router) LookupReverseMapping(ip netip.Addr) (string, bool) {
	if r.dnsReverseMapping == nil {
		return "", false
	}
	r.observeDNSEnvironment()
	domain, loaded := r.dnsReverseMapping.Get(ip)
	return domain, loaded
}

func (r *Router) ResetNetwork() {
	// The generation advances FIRST, making this a barrier from its very first instruction.
	//
	// It used to advance last, after the transports were reset and the reverse mapping purged. That
	// left the window this ordering exists to close: a request issued before the reset still carried
	// the pre-reset generation, still compared equal to the still-current pre-reset value, and was
	// therefore accepted - refilling the cache the purge had just cleared with a name learned on the
	// network being left.
	//
	// Advancing first means every capture taken before the reset is stale the moment it begins, and
	// the purge below then removes whatever those captures had already written. The two steps are one
	// barrier rather than two independent operations.
	r.networkGeneration.Add(1)

	for _, transport := range r.transport.Transports() {
		transport.Reset()
	}

	// Re-pin every transport's network environment.
	//
	// NetworkManager publishes the new environment BEFORE it calls this, so a query issued in
	// between would otherwise be stamped with the new fingerprint while travelling over a connection
	// belonging to the previous network - and because the stamp matched, the answer would be served
	// to every later query on the new network for the rest of its TTL.
	//
	// The transports have just been reset, which is what makes this the correct moment: a transport
	// now serves the new network, so stamping it with the new environment is accurate rather than
	// premature.
	if r.concreteClient != nil {
		r.concreteClient.refreshTransportEnvironments()
	}

	// The reverse mapping is a cache of what previous answers said an address meant, and a network
	// change is exactly when that may no longer hold: with split-horizon or captive-portal DNS the
	// same address can mean a different name on the new network. Leaving entries behind lets a
	// stale name participate in route rule matching until its DNS TTL expires.
	//
	// Nothing depends on the mapping surviving a network change - it is a cache, and every entry
	// is re-learned from the next answer - so purging it here is strictly a reduction in stale
	// state rather than a behaviour change for any correct configuration.
	if r.dnsReverseMapping != nil {
		r.dnsReverseMapping.Purge()
	}
}

func defaultRuleNeedsLegacyDNSModeFromAddressFilter(rule option.DefaultDNSRule) bool {
	if rule.RuleSetIPCIDRAcceptEmpty { //nolint:staticcheck
		return true
	}
	return !rule.MatchResponse.IsEnabled() && (rule.IPAcceptAny || len(rule.IPCIDR) > 0 || rule.IPIsPrivate)
}

func hasResponseMatchFields(rule option.DefaultDNSRule) bool {
	return rule.ResponseRcode != nil ||
		len(rule.ResponseAnswer) > 0 ||
		len(rule.ResponseNs) > 0 ||
		len(rule.ResponseExtra) > 0
}

func defaultRuleDisablesLegacyDNSMode(rule option.DefaultDNSRule) bool {
	return rule.MatchResponse.IsEnabled() ||
		hasResponseMatchFields(rule) ||
		rule.Action == C.RuleActionTypeEvaluate ||
		rule.Action == C.RuleActionTypeRespond ||
		rule.IPVersion > 0 ||
		len(rule.QueryType) > 0
}

type dnsRuleModeFlags struct {
	disabled           bool
	needed             bool
	neededFromStrategy bool
}

func (f *dnsRuleModeFlags) merge(other dnsRuleModeFlags) {
	f.disabled = f.disabled || other.disabled
	f.needed = f.needed || other.needed
	f.neededFromStrategy = f.neededFromStrategy || other.neededFromStrategy
}

func resolveLegacyDNSMode(router adapter.Router, rules []option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (bool, dnsRuleModeFlags, error) {
	flags, err := dnsRuleModeRequirements(router, rules, metadataOverrides)
	if err != nil {
		return false, flags, err
	}
	if flags.disabled && flags.neededFromStrategy {
		return false, flags, E.New(deprecated.OptionLegacyDNSRuleStrategy.MessageWithLink())
	}
	if flags.disabled {
		return false, flags, nil
	}
	return flags.needed, flags, nil
}

func dnsRuleModeRequirements(router adapter.Router, rules []option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleModeFlags, error) {
	var flags dnsRuleModeFlags
	for i, rule := range rules {
		ruleFlags, err := dnsRuleModeRequirementsInRule(router, rule, metadataOverrides)
		if err != nil {
			return dnsRuleModeFlags{}, E.Cause(err, "dns rule[", i, "]")
		}
		flags.merge(ruleFlags)
	}
	return flags, nil
}

func dnsRuleModeRequirementsInRule(router adapter.Router, rule option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleModeFlags, error) {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return dnsRuleModeRequirementsInDefaultRule(router, rule.DefaultOptions, metadataOverrides)
	case C.RuleTypeLogical:
		flags := dnsRuleModeFlags{
			disabled: dnsRuleActionType(rule) == C.RuleActionTypeEvaluate ||
				dnsRuleActionType(rule) == C.RuleActionTypeRespond ||
				dnsRuleActionDisablesLegacyDNSMode(rule.LogicalOptions.DNSRuleAction),
			neededFromStrategy: dnsRuleActionHasStrategy(rule.LogicalOptions.DNSRuleAction),
		}
		flags.needed = flags.neededFromStrategy
		for i, subRule := range rule.LogicalOptions.Rules {
			subFlags, err := dnsRuleModeRequirementsInRule(router, subRule, metadataOverrides)
			if err != nil {
				return dnsRuleModeFlags{}, E.Cause(err, "sub rule[", i, "]")
			}
			flags.merge(subFlags)
		}
		return flags, nil
	default:
		return dnsRuleModeFlags{}, nil
	}
}

func dnsRuleModeRequirementsInDefaultRule(router adapter.Router, rule option.DefaultDNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleModeFlags, error) {
	flags := dnsRuleModeFlags{
		disabled:           defaultRuleDisablesLegacyDNSMode(rule) || dnsRuleActionDisablesLegacyDNSMode(rule.DNSRuleAction),
		neededFromStrategy: dnsRuleActionHasStrategy(rule.DNSRuleAction),
	}
	flags.needed = defaultRuleNeedsLegacyDNSModeFromAddressFilter(rule) || flags.neededFromStrategy
	if len(rule.RuleSet) == 0 {
		return flags, nil
	}
	if router == nil {
		return dnsRuleModeFlags{}, E.New("router service not found")
	}
	for _, tag := range rule.RuleSet {
		metadata, err := lookupDNSRuleSetMetadata(router, tag, metadataOverrides)
		if err != nil {
			return dnsRuleModeFlags{}, err
		}
		// ip_version is not a headless-rule item, so ContainsIPVersionRule is intentionally absent.
		flags.disabled = flags.disabled || metadata.ContainsDNSQueryTypeRule
		if !rule.RuleSetIPCIDRMatchSource && metadata.ContainsIPCIDRRule {
			flags.needed = true
		}
	}
	return flags, nil
}

func lookupDNSRuleSetMetadata(router adapter.Router, tag string, metadataOverrides map[string]adapter.RuleSetMetadata) (adapter.RuleSetMetadata, error) {
	if metadataOverrides != nil {
		if metadata, loaded := metadataOverrides[tag]; loaded {
			return metadata, nil
		}
	}
	ruleSet, loaded := router.RuleSet(tag)
	if !loaded {
		return adapter.RuleSetMetadata{}, E.New("rule-set not found: ", tag)
	}
	return ruleSet.Metadata(), nil
}

type dnsRuleResponseUse struct {
	needsAnonymous bool
	referencedTags []string
}

func validateLegacyDNSModeDisabledRules(router adapter.Router, rules []option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) ([]string, error) {
	var (
		warnings               []string
		seenAnonymousEvaluate  bool
		seenRace               bool
		definedTags            = make(map[string]bool)
		definedTagOrder        []string
		referencedTags         = make(map[string]bool)
		lastAnonymousEvaluate  = -1
		anonymousReadSinceLast bool
	)
	for i, rule := range rules {
		use, err := validateLegacyDNSModeDisabledRuleTree(router, rule, metadataOverrides)
		if err != nil {
			return nil, E.Cause(err, "validate dns rule[", i, "]")
		}
		if dnsRuleActionSpeculative(rule) && !seenRace {
			warnings = append(warnings, F.ToString("dns rule[", i, "]: `speculative` has no effect without a preceding `race` rule"))
		}
		if dnsRuleRace(rule) {
			seenRace = true
		}
		if use.needsAnonymous {
			if !seenAnonymousEvaluate {
				if len(definedTagOrder) > 0 {
					return nil, E.New("dns rule[", i, "]: response-based matching requires a preceding evaluate action without `tag`; use `match_response` with an evaluate tag to reference a tagged result")
				}
				return nil, E.New("dns rule[", i, "]: response-based matching requires a preceding evaluate action")
			}
			anonymousReadSinceLast = true
		}
		for _, tag := range use.referencedTags {
			if !definedTags[tag] {
				return nil, E.New("dns rule[", i, "]: undefined evaluate tag: ", tag)
			}
			referencedTags[tag] = true
		}
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			tag := dnsRuleActionEvaluateTag(rule)
			if tag == "" {
				if lastAnonymousEvaluate >= 0 && !anonymousReadSinceLast {
					warnings = append(warnings, F.ToString("dns rule[", lastAnonymousEvaluate, "]: evaluated response is overwritten by dns rule[", i, "] before any use"))
				}
				seenAnonymousEvaluate = true
				lastAnonymousEvaluate = i
				anonymousReadSinceLast = false
			} else {
				if definedTags[tag] {
					return nil, E.New("dns rule[", i, "]: duplicate evaluate tag: ", tag)
				}
				definedTags[tag] = true
				definedTagOrder = append(definedTagOrder, tag)
			}
		}
	}
	for _, tag := range definedTagOrder {
		if !referencedTags[tag] {
			warnings = append(warnings, F.ToString("evaluate tag is never referenced: ", tag))
		}
	}
	return warnings, nil
}

func validateEvaluateFakeIPRules(rules []option.DNSRule, transportManager adapter.DNSTransportManager) error {
	if transportManager == nil {
		return nil
	}
	for i, rule := range rules {
		if dnsRuleActionType(rule) != C.RuleActionTypeEvaluate {
			continue
		}
		server := dnsRuleActionServer(rule)
		if server == "" {
			continue
		}
		transport, loaded := transportManager.Transport(server)
		if !loaded || transport.Type() != C.DNSTypeFakeIP {
			continue
		}
		return E.New("dns rule[", i, "]: evaluate action cannot use fakeip server: ", server)
	}
	return nil
}

func validateLegacyDNSModeDisabledRuleTree(router adapter.Router, rule option.DNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleResponseUse, error) {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return validateLegacyDNSModeDisabledDefaultRule(router, rule.DefaultOptions, metadataOverrides)
	case C.RuleTypeLogical:
		var use dnsRuleResponseUse
		for i, subRule := range rule.LogicalOptions.Rules {
			subUse, err := validateLegacyDNSModeDisabledRuleTree(router, subRule, metadataOverrides)
			if err != nil {
				return dnsRuleResponseUse{}, E.Cause(err, "sub rule[", i, "]")
			}
			use.needsAnonymous = use.needsAnonymous || subUse.needsAnonymous
			use.referencedTags = append(use.referencedTags, subUse.referencedTags...)
		}
		if rule.LogicalOptions.Action == C.RuleActionTypeRespond {
			if len(use.referencedTags) > 0 {
				return dnsRuleResponseUse{}, E.New("respond on a logical rule cannot bind a `match_response` tag from its sub rules; use a non-logical rule")
			}
			use.needsAnonymous = true
		}
		return use, nil
	default:
		return dnsRuleResponseUse{}, nil
	}
}

func validateLegacyDNSModeDisabledDefaultRule(router adapter.Router, rule option.DefaultDNSRule, metadataOverrides map[string]adapter.RuleSetMetadata) (dnsRuleResponseUse, error) {
	hasResponseRecords := hasResponseMatchFields(rule)
	if (hasResponseRecords || len(rule.IPCIDR) > 0 || rule.IPIsPrivate || rule.IPAcceptAny) && !rule.MatchResponse.IsEnabled() {
		return dnsRuleResponseUse{}, E.New("Response Match Fields (ip_cidr, ip_is_private, ip_accept_any, response_rcode, response_answer, response_ns, response_extra) require match_response to be enabled")
	}
	// rule_set entries are only rejected when every referenced set is pure-IP;
	// mixed sets still fall through because their non-IP branches remain matchable
	// before a DNS response is available.
	if !rule.MatchResponse.IsEnabled() && len(rule.RuleSet) > 0 {
		for _, tag := range rule.RuleSet {
			metadata, err := lookupDNSRuleSetMetadata(router, tag, metadataOverrides)
			if err != nil {
				return dnsRuleResponseUse{}, err
			}
			if metadata.ContainsIPCIDRRule && !metadata.ContainsNonIPCIDRRule {
				return dnsRuleResponseUse{}, E.New(deprecated.OptionLegacyDNSAddressFilter.MessageWithLink())
			}
		}
	}
	if rule.RuleSetIPCIDRAcceptEmpty { //nolint:staticcheck
		return dnsRuleResponseUse{}, E.New(deprecated.OptionRuleSetIPCIDRAcceptEmpty.MessageWithLink())
	}
	var use dnsRuleResponseUse
	if rule.MatchResponse.IsEnabled() {
		if responseTag := rule.MatchResponse.ResponseTag(); responseTag != "" {
			use.referencedTags = append(use.referencedTags, responseTag)
		} else {
			use.needsAnonymous = true
		}
	}
	if rule.Action == C.RuleActionTypeRespond && rule.MatchResponse.ResponseTag() == "" {
		use.needsAnonymous = true
	}
	return use, nil
}

func dnsRuleActionDisablesLegacyDNSMode(action option.DNSRuleAction) bool {
	if action.Race {
		return true
	}
	switch action.Action {
	case "", C.RuleActionTypeRoute:
		return action.RouteOptions.DisableOptimisticCache || action.RouteOptions.Speculative
	case C.RuleActionTypeEvaluate:
		return action.EvaluateOptions.DisableOptimisticCache || action.EvaluateOptions.Speculative
	case C.RuleActionTypeRouteOptions:
		return action.RouteOptionsOptions.DisableOptimisticCache
	default:
		return false
	}
}

func dnsRuleActionHasStrategy(action option.DNSRuleAction) bool {
	switch action.Action {
	case "", C.RuleActionTypeRoute:
		return C.DomainStrategy(action.RouteOptions.Strategy) != C.DomainStrategyAsIS
	case C.RuleActionTypeEvaluate:
		return C.DomainStrategy(action.EvaluateOptions.Strategy) != C.DomainStrategyAsIS
	case C.RuleActionTypeRouteOptions:
		return C.DomainStrategy(action.RouteOptionsOptions.Strategy) != C.DomainStrategyAsIS
	default:
		return false
	}
}

func dnsRuleActionType(rule option.DNSRule) string {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		if rule.DefaultOptions.Action == "" {
			return C.RuleActionTypeRoute
		}
		return rule.DefaultOptions.Action
	case C.RuleTypeLogical:
		if rule.LogicalOptions.Action == "" {
			return C.RuleActionTypeRoute
		}
		return rule.LogicalOptions.Action
	default:
		return ""
	}
}

func dnsRuleActionServer(rule option.DNSRule) string {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			return rule.DefaultOptions.EvaluateOptions.Server
		}
		return rule.DefaultOptions.RouteOptions.Server
	case C.RuleTypeLogical:
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			return rule.LogicalOptions.EvaluateOptions.Server
		}
		return rule.LogicalOptions.RouteOptions.Server
	default:
		return ""
	}
}

func dnsRuleActionEvaluateTag(rule option.DNSRule) string {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return rule.DefaultOptions.EvaluateOptions.Tag
	case C.RuleTypeLogical:
		return rule.LogicalOptions.EvaluateOptions.Tag
	default:
		return ""
	}
}

func dnsRuleActionSpeculative(rule option.DNSRule) bool {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			return rule.DefaultOptions.EvaluateOptions.Speculative
		}
		return rule.DefaultOptions.RouteOptions.Speculative
	case C.RuleTypeLogical:
		if dnsRuleActionType(rule) == C.RuleActionTypeEvaluate {
			return rule.LogicalOptions.EvaluateOptions.Speculative
		}
		return rule.LogicalOptions.RouteOptions.Speculative
	default:
		return false
	}
}

func dnsRuleRace(rule option.DNSRule) bool {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return rule.DefaultOptions.Race
	case C.RuleTypeLogical:
		return rule.LogicalOptions.Race
	default:
		return false
	}
}
