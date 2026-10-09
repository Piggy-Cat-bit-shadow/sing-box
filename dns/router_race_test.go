package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeDNSTransport struct {
	tag         string
	delay       time.Duration
	immediate   bool
	rcode       int
	address     netip.Addr
	exchangeErr error

	// release, when non-nil, holds Exchange open after its delay until the test closes it.
	//
	// A nil channel blocks forever, so leaving it unset disables the gate and every caller that
	// does not set it behaves exactly as before. It exists so a test can say "this transport must
	// NOT be waited for" as an event - the exchange returned while this one was still unanswered -
	// instead of answering after a sleep the test then has to beat with a wall-clock bound.
	release <-chan struct{}

	// queried is closed the first time Exchange is entered, so a test can wait for a LAUNCH
	// rather than assume one happened within some number of milliseconds.
	queried     chan struct{}
	queriedOnce sync.Once

	access       sync.Mutex
	queryCount   atomic.Int32
	firstQueried time.Time
}

func (t *fakeDNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (t *fakeDNSTransport) Type() string {
	return "fake"
}

func (t *fakeDNSTransport) Tag() string {
	return t.tag
}

func (t *fakeDNSTransport) Dependencies() []string {
	return nil
}

func (t *fakeDNSTransport) Reset() {
}

func (t *fakeDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.access.Lock()
	if t.firstQueried.IsZero() {
		t.firstQueried = time.Now()
	}
	t.access.Unlock()
	t.queryCount.Add(1)
	if t.queried != nil {
		t.queriedOnce.Do(func() { close(t.queried) })
	}
	select {
	case <-time.After(t.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if t.release != nil {
		select {
		case <-t.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if t.exchangeErr != nil {
		return nil, t.exchangeErr
	}
	if t.rcode != mDNS.RcodeSuccess {
		return FixedResponseStatus(message, t.rcode), nil
	}
	return FixedResponse(message.Id, message.Question[0], []netip.Addr{t.address}, 300), nil
}

func (t *fakeDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if t.immediate {
		callback(t.Exchange(ctx, message))
		return
	}
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

type fakeDNSTransportManager struct {
	transports       map[string]adapter.DNSTransport
	defaultTransport adapter.DNSTransport
}

func (m *fakeDNSTransportManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (m *fakeDNSTransportManager) Transports() []adapter.DNSTransport {
	return nil
}

func (m *fakeDNSTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

func (m *fakeDNSTransportManager) Default() adapter.DNSTransport {
	return m.defaultTransport
}

func (m *fakeDNSTransportManager) FakeIP() adapter.FakeIPTransport {
	return nil
}

func (m *fakeDNSTransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

func raceTestRouter(t *testing.T, transports ...*fakeDNSTransport) *Router {
	transportMap := make(map[string]adapter.DNSTransport)
	for _, transport := range transports {
		transportMap[transport.tag] = transport
	}
	return &Router{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{
			transports:       transportMap,
			defaultTransport: transportMap["final"],
		},
		client: NewClient(ClientOptions{
			Context:      context.Background(),
			DisableCache: true,
			Logger:       log.NewNOPFactory().Logger(),
		}),
	}
}

func raceTestRules(t *testing.T, rawRules []option.DNSRule) []adapter.DNSRule {
	rules := make([]adapter.DNSRule, 0, len(rawRules))
	for _, rawRule := range rawRules {
		rule, err := R.NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), rawRule, true, false)
		require.NoError(t, err)
		rules = append(rules, rule)
	}
	return rules
}

func raceTestExchange(router *Router, rules []adapter.DNSRule) exchangeWithRulesResult {
	return raceTestExchangeContext(context.Background(), router, rules)
}

// raceTestExchangeContext is raceTestExchange with the caller's context.
//
// It exists for the tests that deliberately hold a transport open: a router that wrongly waits for
// that transport must fail with the context error rather than block the package until `go test`'s
// own timeout. That guard is a liveness bound on a BLOCKED operation - only a regression can reach
// it, and a correct exchange in these tests finishes in milliseconds - which is a different thing
// from the wall-clock bounds these tests used to put on a correct one.
func raceTestExchangeContext(ctx context.Context, router *Router, rules []adapter.DNSRule) exchangeWithRulesResult {
	message := &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Id:               1,
			RecursionDesired: true,
		},
		Question: []mDNS.Question{{
			Name:   "race.example.org.",
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		}},
	}
	metadata := &adapter.InboundContext{
		Domain:    "race.example.org",
		QueryType: mDNS.TypeA,
	}
	requestCtx := adapter.WithContext(ctx, metadata)
	return router.exchangeWithRules(requestCtx, rules, message, adapter.DNSQueryOptions{}, false)
}

// awaitQueryLaunch waits until a transport has been asked its first question.
//
// This is the barrier that replaces the wall-clock bounds on a LAUNCH. "The query was in flight
// while the other transport was still unanswered" is an event, and an event can be waited for; the
// timeout below is a liveness guard on a router that never launches it at all, not a budget the
// machine can spend.
func awaitQueryLaunch(t *testing.T, transport *fakeDNSTransport, what string) {
	t.Helper()
	select {
	case <-transport.queried:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s was never queried: the exchange did not launch it while the other transport "+
			"was deliberately left unanswered", what)
	}
}

// startRaceTestExchange runs the exchange off the test goroutine so the test can observe the
// launches it makes while a transport is held open.
func startRaceTestExchange(ctx context.Context, router *Router, rules []adapter.DNSRule) <-chan exchangeWithRulesResult {
	result := make(chan exchangeWithRulesResult, 1)
	go func() {
		result <- raceTestExchangeContext(ctx, router, rules)
	}()
	return result
}

// heldExchangeDeadline bounds an exchange whose transports are deliberately held open. It is far
// longer than the guard in awaitRaceTestExchangeWhileHeld on purpose: a regression must fail on
// that guard, not be rescued by the deadline cancelling the held transport's future, which would
// resolve it and let the walk commit as if nothing were wrong.
const heldExchangeDeadline = 60 * time.Second

// awaitRaceTestExchangeWhileHeld waits for an exchange to finish while the transport behind a
// held-open gate is still unanswered, and fails if it does not.
//
// This is the barrier form of "the exchange must not wait for that transport", and it is what makes
// holding a transport open equivalent to - and stronger than - the wall-clock bound it replaced.
// The guard below bounds an operation that is BLOCKED: a correct router returns in milliseconds and
// can only reach the guard by waiting for a transport the test never released, so the guard is a
// liveness check on a regression rather than a budget the machine can spend. (An earlier version of
// this fix awaited the exchange synchronously; the same injected regression then blocked until the
// context deadline, the deadline resolved the held future with an error, and the walk committed the
// RIGHT answer ten seconds late - a wrong-but-passing result. The distinction only exists if the
// guard fires before the deadline does, which is why the deadline is heldExchangeDeadline.)
func awaitRaceTestExchangeWhileHeld(t *testing.T, result <-chan exchangeWithRulesResult, what string) exchangeWithRulesResult {
	t.Helper()
	select {
	case exchangeResult := <-result:
		return exchangeResult
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: the exchange never returned while the slower transport was deliberately left "+
			"unanswered, so it waited for a rule it exists to out-race", what)
		return exchangeWithRulesResult{}
	}
}

// awaitRaceTestExchange completes a started exchange, failing rather than hanging if the router is
// still blocked on a transport the test never released.
func awaitRaceTestExchange(t *testing.T, result <-chan exchangeWithRulesResult, what string) exchangeWithRulesResult {
	t.Helper()
	select {
	case exchangeResult := <-result:
		return exchangeResult
	case <-time.After(10 * time.Second):
		t.Fatalf("%s never returned; the router is still waiting for a transport the test is "+
			"holding open, which is the regression these tests exist for", what)
		return exchangeWithRulesResult{}
	}
}

func evaluateRule(server string, tag string, speculative bool) option.DNSRule {
	return option.DNSRule{
		Type: "",
		DefaultOptions: option.DefaultDNSRule{
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeEvaluate,
				EvaluateOptions: option.DNSEvaluateActionOptions{
					Server:      server,
					Tag:         tag,
					Speculative: speculative,
				},
			},
		},
	}
}

func respondRule(responseTag string, race bool, requireSuccess bool) option.DNSRule {
	rule := option.DNSRule{
		Type: "",
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				MatchResponse: &option.DNSRuleMatchResponse{Enabled: true, Tag: responseTag},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRespond,
				Race:   race,
			},
		},
	}
	if requireSuccess {
		successRcode := option.DNSRCode(mDNS.RcodeSuccess)
		rule.DefaultOptions.ResponseRcode = &successRcode
	}
	return rule
}

func routeRule(server string, speculative bool) option.DNSRule {
	return option.DNSRule{
		Type: "",
		DefaultOptions: option.DefaultDNSRule{
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:      server,
					Speculative: speculative,
				},
			},
		},
	}
}

func responseAddress(t *testing.T, response *mDNS.Msg) netip.Addr {
	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)
	record, isA := response.Answer[0].(*mDNS.A)
	require.True(t, isA)
	address, _ := netip.AddrFromSlice(record.A)
	return address.Unmap()
}

// Both evaluate queries must launch in parallel, and a failed primary must
// fall through to the secondary instead of failing the request.
func TestDNSEvaluateParallelFallback(t *testing.T) {
	t.Parallel()
	// Both transports are held until BOTH have been queried, which is the parallelism claim as an
	// event: if the walk asked x and waited for its answer before asking y, y's query would never
	// arrive while x is left unanswered and awaitQueryLaunch would fail. The old form asserted the
	// same thing as a 100ms bound on the gap between two launch timestamps, which a loaded host can
	// close, plus a 350ms bound on the whole exchange, which a loaded host can also cross.
	release := make(chan struct{})
	transportX := &fakeDNSTransport{tag: "x", delay: 200 * time.Millisecond,
		exchangeErr: context.DeadlineExceeded, release: release, queried: make(chan struct{})}
	transportY := &fakeDNSTransport{tag: "y", rcode: mDNS.RcodeSuccess,
		address: netip.MustParseAddr("192.0.2.2"), release: release, queried: make(chan struct{})}
	router := raceTestRouter(t, transportX, transportY)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", false, true),
		respondRule("y", false, true),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := startRaceTestExchange(ctx, router, rules)

	awaitQueryLaunch(t, transportX, "the failing primary")
	awaitQueryLaunch(t, transportY, "the secondary")
	close(release)

	exchangeResult := awaitRaceTestExchange(t, result, "the parallel evaluate exchange")
	require.NoError(t, exchangeResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, exchangeResult.response),
		"a failed primary must fall through to the secondary instead of failing the request")
	require.Equal(t, int32(1), transportX.queryCount.Load())
	require.Equal(t, int32(1), transportY.queryCount.Load())
}

// The first race rule whose response arrives and matches must commit
// immediately, without waiting for the slower rule written before it.
func TestDNSRaceFastestWins(t *testing.T) {
	t.Parallel()
	// x is held unanswered for as long as the test needs. The claim is "the fastest response
	// commits without waiting for the slower rule written before it", and holding x states it
	// exactly: the exchange returns at all only because it did not wait for x. The old form gave x
	// a 500ms answer and bounded the exchange at 400ms, which a loaded host crosses.
	release := make(chan struct{})
	defer close(release)
	transportX := &fakeDNSTransport{tag: "x", rcode: mDNS.RcodeSuccess,
		address: netip.MustParseAddr("192.0.2.1"), release: release, queried: make(chan struct{})}
	transportY := &fakeDNSTransport{tag: "y", delay: 20 * time.Millisecond, rcode: mDNS.RcodeSuccess,
		address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transportX, transportY)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", true, true),
		respondRule("y", true, true),
	})

	ctx, cancel := context.WithTimeout(context.Background(), heldExchangeDeadline)
	defer cancel()
	startTime := time.Now()
	result := startRaceTestExchange(ctx, router, rules)

	exchangeResult := awaitRaceTestExchangeWhileHeld(t, result, "the fastest race response")
	require.NoError(t, exchangeResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, exchangeResult.response))
	// The winner's own cost is still paid, so this is a measurement and not a shortcut.
	require.GreaterOrEqual(t, time.Since(startTime), transportY.delay)
	// And the loser really was in flight: the exchange ignored an armed rule, it did not skip one.
	// The launch is waited for rather than sampled, because the transport answers on its own
	// goroutine and reading the counter immediately would be a race with the scheduler.
	awaitQueryLaunch(t, transportX, "the slower race rule's transport")
}

// A race rule whose response completed synchronously (cache hit) before its
// rule is scanned must commit immediately instead of being blocked by an
// earlier armed race rule.
func TestDNSRaceImmediateLaterResponseWins(t *testing.T) {
	t.Parallel()
	// The earlier armed rule is held unanswered, so committing at all is the proof that the
	// synchronous later response was not blocked behind it. The old form let x answer at 200ms and
	// bounded the exchange at 100ms, which is a statement about the machine.
	release := make(chan struct{})
	defer close(release)
	transportX := &fakeDNSTransport{tag: "x", rcode: mDNS.RcodeSuccess,
		address: netip.MustParseAddr("192.0.2.1"), release: release, queried: make(chan struct{})}
	transportY := &fakeDNSTransport{tag: "y", immediate: true, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transportX, transportY)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", true, true),
		respondRule("y", true, true),
	})

	ctx, cancel := context.WithTimeout(context.Background(), heldExchangeDeadline)
	defer cancel()
	result := startRaceTestExchange(ctx, router, rules)

	exchangeResult := awaitRaceTestExchangeWhileHeld(t, result, "the synchronous later race response")
	require.NoError(t, exchangeResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, exchangeResult.response))
}

// A synchronously completed race rule that misses disarms in place and rule
// scanning continues; the remaining race rule wins once its response arrives.
func TestDNSRaceImmediateMissContinues(t *testing.T) {
	t.Parallel()
	transportX := &fakeDNSTransport{tag: "x", delay: 100 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	transportY := &fakeDNSTransport{tag: "y", immediate: true, rcode: mDNS.RcodeNameError}
	router := raceTestRouter(t, transportX, transportY)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("y", true, true),
		respondRule("x", true, true),
	})
	startTime := time.Now()
	result := raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), responseAddress(t, result.response))
	require.GreaterOrEqual(t, time.Since(startTime), 90*time.Millisecond)
}

// A race route rule whose binding completed synchronously must commit its
// route immediately instead of being blocked by an earlier armed race rule.
func TestDNSRaceImmediateRouteCommits(t *testing.T) {
	t.Parallel()
	// As above: the earlier armed rule never answers, so the exchange completing is the proof.
	release := make(chan struct{})
	defer close(release)
	transportX := &fakeDNSTransport{tag: "x", rcode: mDNS.RcodeSuccess,
		address: netip.MustParseAddr("192.0.2.1"), release: release, queried: make(chan struct{})}
	transportY := &fakeDNSTransport{tag: "y", immediate: true, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	transportFinal := &fakeDNSTransport{tag: "final", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.9")}
	router := raceTestRouter(t, transportX, transportY, transportFinal)
	successRcode := option.DNSRCode(mDNS.RcodeSuccess)
	raceRouteRule := option.DNSRule{
		Type: "",
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				MatchResponse: &option.DNSRuleMatchResponse{Enabled: true, Tag: "y"},
				ResponseRcode: &successRcode,
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: "final",
				},
				Race: true,
			},
		},
	}
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", true, true),
		raceRouteRule,
	})

	ctx, cancel := context.WithTimeout(context.Background(), heldExchangeDeadline)
	defer cancel()
	result := startRaceTestExchange(ctx, router, rules)

	exchangeResult := awaitRaceTestExchangeWhileHeld(t, result, "the synchronous race route")
	require.NoError(t, exchangeResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.9"), responseAddress(t, exchangeResult.response))
	require.Equal(t, int32(1), transportFinal.queryCount.Load())
	awaitQueryLaunch(t, transportX, "the earlier armed rule's transport")
}

// Without race, rule order decides even when a later response arrives first.
func TestDNSOrderedReadsPreferEarlierRule(t *testing.T) {
	t.Parallel()
	transportX := &fakeDNSTransport{tag: "x", delay: 200 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	transportY := &fakeDNSTransport{tag: "y", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transportX, transportY)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", false, true),
		respondRule("y", false, true),
	})
	result := raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), responseAddress(t, result.response))
}

// A pending race rule must hold back the default route: the default server
// is never queried when the race rule hits, and is queried only after the
// race decision resolved when it misses.
func TestDNSRaceBarrierProtectsDefaultRoute(t *testing.T) {
	t.Parallel()
	transportHit := &fakeDNSTransport{tag: "x", delay: 100 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	transportFinal := &fakeDNSTransport{tag: "final", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.9")}
	router := raceTestRouter(t, transportHit, transportFinal)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		respondRule("x", true, true),
	})
	result := raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), responseAddress(t, result.response))
	require.Equal(t, int32(0), transportFinal.queryCount.Load())

	transportMiss := &fakeDNSTransport{tag: "x", delay: 100 * time.Millisecond, rcode: mDNS.RcodeNameError}
	transportFinal = &fakeDNSTransport{tag: "final", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.9")}
	router = raceTestRouter(t, transportMiss, transportFinal)
	rules = raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		respondRule("x", true, true),
	})
	startTime := time.Now()
	result = raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.9"), responseAddress(t, result.response))
	require.Equal(t, int32(1), transportFinal.queryCount.Load())
	require.GreaterOrEqual(t, transportFinal.firstQueried.Sub(startTime), 90*time.Millisecond)
}

// A speculative route launches while the race decision is pending, but its
// response is only used after the race rule missed.
func TestDNSSpeculativeRoute(t *testing.T) {
	t.Parallel()
	// The race transport is held unanswered, so "the speculative route was launched while the race
	// decision was pending" is asserted by waiting for the launch while that transport is still
	// open - an event, not a 90ms bound on how quickly the host schedules the launch goroutine.
	release := make(chan struct{})
	transportMiss := &fakeDNSTransport{tag: "x", delay: 100 * time.Millisecond, rcode: mDNS.RcodeNameError,
		release: release, queried: make(chan struct{})}
	transportFinal := &fakeDNSTransport{tag: "final", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess,
		address: netip.MustParseAddr("192.0.2.9"), queried: make(chan struct{})}
	router := raceTestRouter(t, transportMiss, transportFinal)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		respondRule("x", true, true),
		routeRule("final", true),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	startTime := time.Now()
	result := startRaceTestExchange(ctx, router, rules)

	awaitQueryLaunch(t, transportMiss, "the race rule's transport")
	awaitQueryLaunch(t, transportFinal, "the speculative route's transport")
	close(release)

	exchangeResult := awaitRaceTestExchange(t, result, "the speculative route exchange")
	require.NoError(t, exchangeResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.9"), responseAddress(t, exchangeResult.response))
	require.Equal(t, int32(1), transportFinal.queryCount.Load())
	require.GreaterOrEqual(t, time.Since(startTime), transportMiss.delay,
		"the speculative response must only be used after the race rule missed")

	// The other half: when the race rule hits, the speculative result is discarded.
	transportHit := &fakeDNSTransport{tag: "x", delay: 100 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	transportFinal = &fakeDNSTransport{tag: "final", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.9")}
	router = raceTestRouter(t, transportHit, transportFinal)
	rules = raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		respondRule("x", true, true),
		routeRule("final", true),
	})
	result = startRaceTestExchange(ctx, router, rules)
	exchangeResult = awaitRaceTestExchange(t, result, "the speculative route exchange on a hit")
	require.NoError(t, exchangeResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), responseAddress(t, exchangeResult.response))
	require.Equal(t, int32(1), transportFinal.queryCount.Load())
}

// A matched rule without race must not take effect while a race rule is
// still pending: a race hit wins even when the other rule matched earlier,
// and on a race miss the other rule takes effect only after that decision.
func TestDNSNonRaceCommitWaitsForPendingRace(t *testing.T) {
	t.Parallel()
	transportHit := &fakeDNSTransport{tag: "x", delay: 150 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	transportY := &fakeDNSTransport{tag: "y", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transportHit, transportY)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", true, true),
		respondRule("y", false, true),
	})
	startTime := time.Now()
	result := raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), responseAddress(t, result.response))
	require.GreaterOrEqual(t, time.Since(startTime), 140*time.Millisecond)

	transportMiss := &fakeDNSTransport{tag: "x", delay: 150 * time.Millisecond, rcode: mDNS.RcodeNameError}
	transportY = &fakeDNSTransport{tag: "y", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router = raceTestRouter(t, transportMiss, transportY)
	rules = raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", true, true),
		respondRule("y", false, true),
	})
	startTime = time.Now()
	result = raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, result.response))
	require.GreaterOrEqual(t, time.Since(startTime), 140*time.Millisecond)
}

// speculative on a route rule with match_response launches the route query as
// soon as the rule matched, while its response is only used after the pending
// race rule missed.
func TestDNSSpeculativeRouteOnBindingRule(t *testing.T) {
	t.Parallel()
	transportMiss := &fakeDNSTransport{tag: "x", delay: 100 * time.Millisecond, rcode: mDNS.RcodeNameError}
	transportY := &fakeDNSTransport{tag: "y", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	transportFinal := &fakeDNSTransport{tag: "final", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.9")}
	router := raceTestRouter(t, transportMiss, transportY, transportFinal)
	successRcode := option.DNSRCode(mDNS.RcodeSuccess)
	boundRouteRule := option.DNSRule{
		Type: "",
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				MatchResponse: &option.DNSRuleMatchResponse{Enabled: true, Tag: "y"},
				ResponseRcode: &successRcode,
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:      "final",
					Speculative: true,
				},
			},
		},
	}
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", true, true),
		boundRouteRule,
	})

	// Same barrier as TestDNSSpeculativeRoute: the binding rule's route must be launched while the
	// race rule's transport is still unanswered.
	release := make(chan struct{})
	transportMiss.release = release
	transportMiss.queried = make(chan struct{})
	transportFinal.queried = make(chan struct{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	startTime := time.Now()
	result := startRaceTestExchange(ctx, router, rules)

	awaitQueryLaunch(t, transportMiss, "the race rule's transport")
	awaitQueryLaunch(t, transportFinal, "the bound route rule's transport")
	close(release)

	exchangeResult := awaitRaceTestExchange(t, result, "the bound speculative route exchange")
	require.NoError(t, exchangeResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.9"), responseAddress(t, exchangeResult.response))
	require.Equal(t, int32(1), transportFinal.queryCount.Load())
	require.GreaterOrEqual(t, time.Since(startTime), transportMiss.delay,
		"the speculative route's response must only be used after the race rule missed")
}

// A race rule that rejects its response (NXDOMAIN vs required success)
// disarms and lets the other race rule win.
func TestDNSRaceSkipsRejectedResponse(t *testing.T) {
	t.Parallel()
	transportX := &fakeDNSTransport{tag: "x", delay: 10 * time.Millisecond, rcode: mDNS.RcodeNameError}
	transportY := &fakeDNSTransport{tag: "y", delay: 100 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transportX, transportY)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "x", false),
		evaluateRule("y", "y", false),
		respondRule("x", true, true),
		respondRule("y", true, true),
	})
	result := raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, result.response))
}

// A logical race rule is judged once all of its referenced responses arrived:
// it wins over a slower race rule when its sub-rules match, and on a miss the
// slower race rule takes over.
func TestDNSLogicalRace(t *testing.T) {
	t.Parallel()
	successRcode := option.DNSRCode(mDNS.RcodeSuccess)
	logicalRule := func() option.DNSRule {
		return option.DNSRule{
			Type: C.RuleTypeLogical,
			LogicalOptions: option.LogicalDNSRule{
				RawLogicalDNSRule: option.RawLogicalDNSRule{
					Mode: C.LogicalTypeAnd,
					Rules: []option.DNSRule{
						{
							Type: C.RuleTypeDefault,
							DefaultOptions: option.DefaultDNSRule{
								RawDefaultDNSRule: option.RawDefaultDNSRule{
									MatchResponse: &option.DNSRuleMatchResponse{Enabled: true},
									ResponseRcode: &successRcode,
								},
							},
						},
						{
							Type: C.RuleTypeDefault,
							DefaultOptions: option.DefaultDNSRule{
								RawDefaultDNSRule: option.RawDefaultDNSRule{
									MatchResponse: &option.DNSRuleMatchResponse{Enabled: true, Tag: "y"},
									ResponseRcode: &successRcode,
								},
							},
						},
					},
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRespond,
					Race:   true,
				},
			},
		}
	}

	// The loser z never answers until the test lets it. That is the ordering claim stated as an
	// event rather than as a number: if the router waited for z's 250ms response, the exchange
	// below could not return at all, and the context guard turns that into a failure instead of a
	// hang. The old form let z answer at 250ms and required the exchange to finish inside 240ms,
	// leaving 138ms of measured slack (102ms nominal) for the host to spend - and under a parallel
	// full-suite run it spent 156ms and the test failed at 258.4ms.
	releaseLoser := make(chan struct{})
	defer close(releaseLoser)

	transportX := &fakeDNSTransport{tag: "x", delay: 100 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.1")}
	transportY := &fakeDNSTransport{tag: "y", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	transportZ := &fakeDNSTransport{tag: "z", release: releaseLoser, rcode: mDNS.RcodeSuccess,
		address: netip.MustParseAddr("192.0.2.3"), queried: make(chan struct{})}
	router := raceTestRouter(t, transportX, transportY, transportZ)
	rules := raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "", false),
		evaluateRule("y", "y", false),
		evaluateRule("z", "z", false),
		logicalRule(),
		respondRule("z", true, true),
	})
	ctx, cancel := context.WithTimeout(context.Background(), heldExchangeDeadline)
	defer cancel()
	startTime := time.Now()
	result := startRaceTestExchange(ctx, router, rules)
	exchangeResult := awaitRaceTestExchangeWhileHeld(t, result, "the logical race rule")
	require.NoError(t, exchangeResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), responseAddress(t, exchangeResult.response))
	require.Equal(t, int32(1), transportZ.queryCount.Load(),
		"the slower race rule must still have been launched, or there was nothing to win against")
	require.GreaterOrEqual(t, time.Since(startTime), transportX.delay,
		"the logical rule is judged on x's response, so x's own cost must have been paid")

	// The miss case: x rejects, so the logical rule cannot match and the router must fall through
	// to z. z's answer cannot exist before its own delay has been paid in full, so requiring z's
	// address and deriving the floor from z.delay states "the fall-through waits for the slower
	// race rule" without a constant. This half was already a LOWER bound and a lower bound is safe
	// under load - the host can only make it larger - so it is derived rather than restructured.
	transportX = &fakeDNSTransport{tag: "x", delay: 100 * time.Millisecond, rcode: mDNS.RcodeNameError}
	transportY = &fakeDNSTransport{tag: "y", delay: 10 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.2")}
	transportZ = &fakeDNSTransport{tag: "z", delay: 250 * time.Millisecond, rcode: mDNS.RcodeSuccess, address: netip.MustParseAddr("192.0.2.3")}
	router = raceTestRouter(t, transportX, transportY, transportZ)
	rules = raceTestRules(t, []option.DNSRule{
		evaluateRule("x", "", false),
		evaluateRule("y", "y", false),
		evaluateRule("z", "z", false),
		logicalRule(),
		respondRule("z", true, true),
	})
	startTime = time.Now()
	missResult := raceTestExchange(router, rules)
	require.NoError(t, missResult.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.3"), responseAddress(t, missResult.response))
	require.GreaterOrEqual(t, time.Since(startTime), transportZ.delay,
		"the fall-through must wait for the slower race rule's own response")
}
