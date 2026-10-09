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
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The question this file answers
// ---------------------------------------------------------------------------
//
// `clashmode.Manager.SetMode` changes the active mode and then calls `dnsRouter.ClearCache()`, and the
// reason it does is that a `clash_mode` DNS rule (option/rule_dns.go:164, wired at
// route/rule/rule_dns.go:320) routes queries to a DIFFERENT DNS server per mode. The cache clear is
// what is supposed to make the new mode's server take effect.
//
// `dnsCacheKey` (dns/client.go:133) is {Question, transportTag, clientSubnet, environment}. It has no
// mode and no policy generation, and `environmentHash` (dns/client.go:447) is a fingerprint of the
// network and the transports' own DNS environment - neither of which a mode switch changes.
//
// So the claim "a mode switch necessarily moves the answer into a different cache namespace" - which
// the previous round reported - is NOT true when both modes route to the same transport, and it is NOT
// true for any answer whose query was already in flight when the switch happened. This file measures
// which of those is reachable, deterministically, instead of reasoning about the hash.

// modeAwareTransport answers with an address that depends on the mode the test sets.
//
// The gate is how "in flight across the switch" is expressed as an event: Exchange signals `entered`
// and then waits for `release`, so the test knows the query has been sent and can perform the mode
// switch before the answer exists. Nothing here is timed.
type modeAwareTransport struct {
	tag string

	// addressFor reads the address this transport should answer with right now.
	addressFor func() netip.Addr

	entered chan struct{}
	release chan struct{}
	once    sync.Once

	queryCount atomic.Int32
}

func (t *modeAwareTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (t *modeAwareTransport) Close() error                                               { return nil }
func (t *modeAwareTransport) Type() string                                               { return "mode-aware" }
func (t *modeAwareTransport) Tag() string                                                { return t.tag }
func (t *modeAwareTransport) Dependencies() []string                                     { return nil }
func (t *modeAwareTransport) Reset()                                                     {}
func (t *modeAwareTransport) Environment() []string                                      { return []string{"mode-aware", t.tag} }

func (t *modeAwareTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queryCount.Add(1)
	if t.entered != nil {
		t.once.Do(func() { close(t.entered) })
	}
	if t.release != nil {
		select {
		case <-t.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return FixedResponse(message.Id, message.Question[0], []netip.Addr{t.addressFor()}, 300), nil
}

func (t *modeAwareTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

// modeSwitchHarness is the object graph the product runs: a real clashmode.Manager holding the mode, a
// real ClashModeItem answering `clash_mode` rules through the context, a real dns.Router with its CACHE
// ENABLED, and one transport both modes can route to.
type modeSwitchHarness struct {
	manager   *clashmode.Manager
	router    *Router
	transport *modeAwareTransport
	address   atomic.Value // netip.Addr
}

func (h *modeSwitchHarness) setAddress(address netip.Addr) { h.address.Store(address) }

func newModeSwitchHarness(t *testing.T, tag string, withGate bool) *modeSwitchHarness {
	t.Helper()
	harness := &modeSwitchHarness{}
	harness.setAddress(netip.MustParseAddr("192.0.2.10"))

	harness.transport = &modeAwareTransport{
		tag: tag,
		addressFor: func() netip.Addr {
			address, _ := harness.address.Load().(netip.Addr)
			return address
		},
	}
	if withGate {
		harness.transport.entered = make(chan struct{})
		harness.transport.release = make(chan struct{})
	}

	// The router comes first, because the manager must be handed the REAL router: SetMode's entire
	// effect on DNS is the ClearCache call it makes on the router it was given. A no-op router here
	// would make this test measure nothing - the clear would never reach the cache under inspection.
	transportMap := map[string]adapter.DNSTransport{tag: harness.transport}
	harness.router = &Router{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{
			transports:       transportMap,
			defaultTransport: harness.transport,
		},
	}

	// The manager must be reachable from the context the DNS rules are built and STARTED with, because
	// ClashModeItem.Start resolves it with service.PtrFromContext - the same wiring box.go:412 uses. The
	// DNSRouter slot holds a forwarder to the router built above, so SetMode's ClearCache lands on the
	// cache this test inspects.
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), &forwardingDNSRouter{router: harness.router})
	harness.router.ctx = ctx
	harness.router.client = NewClient(ClientOptions{
		Context: ctx,
		// The CACHE IS ON. The whole question is what the cache does across a mode switch, so a router
		// with DisableCache would measure nothing.
		Logger: log.NewNOPFactory().Logger(),
		// Wired exactly as the production constructor does it (dns/router.go, PolicyGeneration). Without
		// it the client has no policy concept and the guard under test is inert - which is how the first
		// run of this test reported a "failure to fix" that was really a harness gap.
		PolicyGeneration: harness.router.policyEpoch,
	})
	harness.manager = clashmode.NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Global", "Direct"})
	service.MustRegisterPtr(ctx, harness.manager)

	harness.router.client.Start()
	// The rules are installed on the router, which is where `prepareExchange` reads them from
	// (`rules := r.rules`, dns/router.go:1719). They must be built and STARTED with the same context
	// the transport manager carries, because ClashModeItem.Start resolves the manager from it.
	harness.router.rules = modeTestRules(t, ctx, tag, tag)
	harness.router.rulesAccess.Lock()
	harness.router.started = true
	harness.router.rulesAccess.Unlock()
	return harness
}

// forwardingDNSRouter puts the router built by the harness into the context slot a DNSRouter occupies,
// so the clashmode manager's ClearCache reaches the cache under test.
//
// It forwards only the invalidation paths the manager uses; everything else is unreachable from it.
type forwardingDNSRouter struct {
	router *Router
}

func (r *forwardingDNSRouter) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (r *forwardingDNSRouter) Close() error                                               { return nil }

func (r *forwardingDNSRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return r.router.Exchange(ctx, message, options)
}

func (r *forwardingDNSRouter) ExchangeAsync(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, callback func(*mDNS.Msg, error)) {
	r.router.ExchangeAsync(ctx, message, options, callback)
}

func (r *forwardingDNSRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.router.Lookup(ctx, domain, options)
}

func (r *forwardingDNSRouter) ClearCache() { r.router.ClearCache() }

func (r *forwardingDNSRouter) LookupReverseMapping(address netip.Addr) (string, bool) {
	return r.router.LookupReverseMapping(address)
}

func (r *forwardingDNSRouter) ResetNetwork() { r.router.ResetNetwork() }

// modeTestRules builds two `clash_mode` DNS rules, one per mode, each routing to the given server.
//
// The shape is the one configuration produces: a default DNS rule whose condition is `clash_mode` and
// whose action routes to a server. `ClashMode` lives on RawDefaultDNSRule (option/rule_dns.go:164),
// which DefaultDNSRule embeds.
func modeTestRules(t *testing.T, ctx context.Context, ruleServer, globalServer string) []adapter.DNSRule {
	t.Helper()
	build := func(clashMode, server string) option.DNSRule {
		return option.DNSRule{
			Type: "",
			DefaultOptions: option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{ClashMode: clashMode},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server: server,
					},
				},
			},
		}
	}
	raw := []option.DNSRule{build("Rule", ruleServer), build("Global", globalServer)}

	rules := make([]adapter.DNSRule, 0, len(raw))
	for _, rawRule := range raw {
		rule, err := R.NewDNSRule(ctx, log.NewNOPFactory().Logger(), rawRule, true, false)
		require.NoError(t, err)
		// Start is what resolves the manager out of the context, exactly as the router starts its rules.
		require.NoError(t, rule.Start())
		rules = append(rules, rule)
	}
	return rules
}

// modeTestMessage is one A query for a fixed name.
func modeTestMessage(name string) (*mDNS.Msg, *adapter.InboundContext) {
	message := &mDNS.Msg{
		MsgHdr:   mDNS.MsgHdr{Id: 1, RecursionDesired: true},
		Question: []mDNS.Question{{Name: name, Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}},
	}
	metadata := &adapter.InboundContext{Domain: name, QueryType: mDNS.TypeA}
	return message, metadata
}

func modeTestAddress(t *testing.T, response *mDNS.Msg, err error) netip.Addr {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotEmpty(t, response.Answer)
	address, isA := response.Answer[0].(*mDNS.A)
	require.True(t, isA, "the answer must be an A record, got %T", response.Answer[0])
	return netip.MustParseAddr(address.A.String())
}

// ---------------------------------------------------------------------------
// The measurement
// ---------------------------------------------------------------------------

// TestAnInFlightAnswerFromTheOldModeIsNotServedUnderTheNewMode is the reproduction.
//
// The sequence is the product's, with the timing made into events:
//
//  1. a query is sent while the mode is Rule, and its transport is held BEFORE answering - so the
//     query is genuinely in flight;
//  2. the controller switches to Global, which is what calls ClearCache, and the clear is allowed to
//     complete;
//  3. the old answer is released, so it arrives after the clear;
//  4. Global issues the SAME question.
//
// If step 4 is answered from step 3's response, then SetMode did not do what it exists to do: the
// answer was produced by the server the mode switch moved away from, and the new mode serves it
// anyway. The transport tag, the client subnet and the environment fingerprint are all identical
// across the switch, and this test does not assume otherwise - it holds them byte for byte.
func TestAnInFlightAnswerFromTheOldModeIsNotServedUnderTheNewMode(t *testing.T) {
	harness := newModeSwitchHarness(t, "shared", true)

	const name = "mode-switch.example.org."
	message, metadata := modeTestMessage(name)

	// --- 1. send under mode Rule, hold the transport before it answers -----------------------------
	require.Equal(t, "Rule", harness.manager.Mode(),
		"the harness must start in the mode whose rule is first")
	firstCtx := adapter.WithContext(context.Background(), metadata)
	firstResult := make(chan netip.Addr, 1)
	firstError := make(chan error, 1)
	go func() {
		response, err := harness.router.Exchange(firstCtx, message, adapter.DNSQueryOptions{})
		if err != nil {
			firstError <- err
			return
		}
		firstResult <- modeTestAddress(t, response, nil)
	}()

	select {
	case <-harness.transport.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first query never reached its transport, so nothing was ever in flight")
	}

	// --- 2. switch mode; the clear must COMPLETE before the answer is released ---------------------
	harness.manager.SetMode("Global")
	require.Equal(t, "Global", harness.manager.Mode())

	// --- 3. release the old answer, still answering with the OLD mode's address --------------------
	//
	// The order here matters and is the whole point: the answer is produced while the transport is
	// still configured as the old mode had it, and the address only changes AFTER the in-flight answer
	// has been cached. Swapping the address first would make the "in flight" answer carry the new
	// mode's value, and the test would then be measuring nothing.
	close(harness.transport.release)
	select {
	case address := <-firstResult:
		require.Equal(t, netip.MustParseAddr("192.0.2.10"), address,
			"the in-flight answer must be the OLD mode's answer, or there is nothing stale to serve")
	case err := <-firstError:
		t.Fatalf("the in-flight query failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight query never completed after its release")
	}

	// The new mode's server answers differently, so which one is served is observable.
	harness.setAddress(netip.MustParseAddr("192.0.2.20"))

	// --- 4. ask the same question under the new mode ------------------------------------------------
	secondCtx := adapter.WithContext(context.Background(), metadata)
	secondResponse, secondErr := harness.router.Exchange(secondCtx, message, adapter.DNSQueryOptions{})
	served := modeTestAddress(t, secondResponse, secondErr)

	require.Equal(t, netip.MustParseAddr("192.0.2.20"), served,
		"the new mode served the OLD mode's answer. SetMode's ClearCache had completed, yet an answer "+
			"produced by the server the switch moved away from was stored afterwards and answered "+
			"normally, because dnsCacheKey has no policy generation and the mode switch changes neither "+
			"the transport tag nor the environment fingerprint")
}

// TestAPureFlushKeepsTheSnapshotContract is the guard on the other side: the manual `POST /dns/flush`
// path must keep its best-effort meaning, and must not be turned into a request barrier.
//
// It is the positive control that stops a fix for the test above from being "make every clear a
// barrier": a flush with no mode change must still leave the cache usable and must not invalidate an
// answer that belongs to the current policy.
func TestAPureFlushKeepsTheSnapshotContract(t *testing.T) {
	harness := newModeSwitchHarness(t, "shared", false)

	const name = "flush-contract.example.org."
	message, metadata := modeTestMessage(name)
	requestCtx := adapter.WithContext(context.Background(), metadata)

	first, err := harness.router.Exchange(requestCtx, message, adapter.DNSQueryOptions{})
	require.Equal(t, netip.MustParseAddr("192.0.2.10"), modeTestAddress(t, first, err))

	// A manual flush with no mode change.
	harness.router.ClearCache()

	// The next query must be answered, and it must be answered by the transport - a flush drops cached
	// entries, so the query goes out again rather than failing or being served a retired entry.
	before := harness.transport.queryCount.Load()
	second, err := harness.router.Exchange(requestCtx, message, adapter.DNSQueryOptions{})
	require.Equal(t, netip.MustParseAddr("192.0.2.10"), modeTestAddress(t, second, err))
	require.Greater(t, harness.transport.queryCount.Load(), before,
		"after a flush the question must be asked again rather than answered from a retired entry")
}
