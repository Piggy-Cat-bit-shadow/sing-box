package tun

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

// L0 versus the DNS reverse mapping: two pieces of the user's configuration describe the same flow,
// and only one of them can decide it.
//
// # The configuration this file is about
//
//	DNS reverse mapping    203.0.113.10 -> blocked.example.com
//	                       (the DNS layer answered a query for that domain and remembers the address)
//	Router domain rule     blocked.example.com -> reject
//	                       (the user's policy for the domain)
//	L0 route set           the address is outside route_address_set, or inside
//	                       route_exclude_address_set
//	                       (the user's policy for the address)
//
// Neither rule is wrong and neither is a misconfiguration: an address rule and a domain rule are
// independent ways to write policy, and DNS state is exactly what makes an address and a domain the
// same flow. JudgeFlow's order decides which one is authoritative for it.
//
// # Why this needed its own tests
//
// direct_offload_l0_report_test.go pins that L0 answers without asking the router at all, and
// TestL0CannotExpressAnythingButAddresses pins that L0 cannot express a domain rule - but both hand
// that router a flow with no domain attached and no DNS layer that could attach one. The conflict is
// what makes the boundary dangerous rather than academic: on the L0 branch the bypass is taken for a
// destination the router WOULD have rejected, so the ordering has to be a deliberate product
// decision rather than an accident of the two features having been written at different times.
//
// # The contract these tests pin
//
//	JudgeFlow returns ActionBypass
//	the Router is consulted 0 times
//	LookupReverseMapping is called 0 times
//	the domain, process and protocol policy in the router intentionally does not participate
//
// # Why that is the right contract
//
// The route sets ARE the TUN's own routing configuration: when route_exclude_address_set contains
// 203.0.113.10, that address is in the platform's routing table and the flow is carried by the
// platform whether or not sing-box has an opinion about its domain. A verdict produced by consulting
// the router first is one the TUN layer cannot then carry out - the packet already left through the
// platform path - and the reverse mapping is DNS state, which is authoritative for the DNS layer and
// not for an address the platform routes. The L0 answer is therefore the only one that can be
// honoured, and consulting the router anyway would buy a counter or a log line at the price of a
// second, contradictory source of truth.
//
// # The harness is the production decision, not a stand-in for it
//
// The router in these tests is the REAL route.Router, built through its production constructor, with
// rules parsed by the production rule parser and its reverse-mapping lookup wired to a DNS layer
// that counts and records what it is asked. That distinction is the whole value of these tests: a
// router double returning a canned verdict would prove only that a double was called, when the
// question is whether the production chain
//
//	route.Router.PreMatch -> prepareMatchMetadata -> dns.LookupReverseMapping -> metadata.Domain
//	-> DomainItem.Match -> PreMatchReject
//
// is reached at all for this flow.
//
// The DNS layer itself is the one stand-in: reverseLookupRecorder supplies the mapping, because a
// reverse mapping IS DNS state that a test has to provide. What is not a stand-in is the router's
// use of it - the metadata pass, the domain matcher and the fast-path refusal that consumes the
// recovered domain are the production implementations.
//
// # What is proven, and what is not
//
// Proven: the L0 verdict, both counters, and - on the non-L0 branch - that a reverse-mapped domain
// changes the real router's verdict (a matched domain rule rejects a flow that is bypassed when the
// same DNS layer knows nothing about the address), that a network condition and a source-address
// condition change it too, and that the process-rule half of the policy is present in the router the
// flow reaches.
//
// Not proven, and deliberately not claimed: that a PROCESS rule would have MATCHED a flow on this
// branch. A process condition is evaluated against adapter.InboundContext.ProcessInfo, which is
// filled in by the router's OS process searcher during a real deployment; the TUN inbound never sets
// it, and no searcher exists on a test host, so a process rule can only ever be observed as present
// and evaluated, never as matching. TestL0DoesNotDiscardProcessOrProtocolRulesOnTheNonL0Branch says
// so at the assertion.
//
// # Determinism
//
// Every test here is synchronous: JudgeFlow and PreMatch are ordinary calls on the calling
// goroutine, there is no channel, no goroutine and no sleep, and the counters are read after the
// call that would have moved them has returned. There is nothing to wait for and therefore no
// timeout to add.

const (
	// reverseMappedAddress is the destination whose policy the two layers disagree about.
	reverseMappedAddress = "203.0.113.10"
	// reverseMappedDomain is the domain the DNS layer knows that address by.
	reverseMappedDomain = "blocked.example.com"
	// unrelatedDomain is a second domain, for the case where the reverse mapping exists but no rule
	// describes it.
	unrelatedDomain = "unrelated.example.com"
)

// --- the configured box, with the real router -------------------------------------------------

// reverseLookupRecorder is the DNS layer's reverse mapping.
//
// It records every question the router asks it, which is what makes "the domain policy did not
// participate" checkable independently of the verdict: if a later edit moved the route sets below
// the router, the count would move even for a flow that happened to reach the same verdict.
type reverseLookupRecorder struct {
	adapter.DNSRouter
	mapping map[netip.Addr]string

	lookupCalls  atomic.Int32
	askedAddress atomic.Pointer[netip.Addr]
}

func (r *reverseLookupRecorder) LookupReverseMapping(address netip.Addr) (string, bool) {
	r.lookupCalls.Add(1)
	asked := address
	r.askedAddress.Store(&asked)
	domain, loaded := r.mapping[address]
	return domain, loaded
}

// noFakeIPTransport is the transport manager of a configuration with no FakeIP transport.
//
// FakeIP() must answer nil rather than a store: that is what sends the router's metadata pass down
// the reverse-mapping branch. With a FakeIP store configured the router would try to unmap the
// address through it first, and this file would be testing the FakeIP boundary instead of the
// reverse-mapping one - a different contract, pinned by direct_fast_path_dns_test.go.
type noFakeIPTransport struct{ adapter.DNSTransportManager }

func (m *noFakeIPTransport) FakeIP() adapter.FakeIPTransport { return nil }

// plainBypassableDirect is an outbound whose behaviour for a literal destination is a plain connect,
// so the router's fast-bypass allow-list can accept it.
//
// It counts the questions the router asks it, which is a second, independent record that the
// router's own decision really ran: a flow that never reaches the router never reaches this.
type plainBypassableDirect struct {
	adapter.Outbound
	bypassCalls atomic.Int32
}

func (o *plainBypassableDirect) Type() string      { return C.TypeDirect }
func (o *plainBypassableDirect) Tag() string       { return "direct" }
func (o *plainBypassableDirect) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *plainBypassableDirect) CanBypass(string, netip.Addr) bool {
	o.bypassCalls.Add(1)
	return true
}

// singleOutboundManager serves one outbound by tag and as the default.
type singleOutboundManager struct {
	adapter.OutboundManager
	defaultOutbound adapter.Outbound
}

func (m *singleOutboundManager) Default() adapter.Outbound { return m.defaultOutbound }

func (m *singleOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	if tag == m.defaultOutbound.Tag() {
		return m.defaultOutbound, true
	}
	return nil, false
}

// preMatchCounter is the adapter.Router the TUN inbound holds: the real router, with every decision
// the TUN layer delegates to it counted.
type preMatchCounter struct {
	adapter.Router
	calls atomic.Int32
}

func (r *preMatchCounter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	r.calls.Add(1)
	return r.Router.PreMatch(metadata, firstPacket)
}

// l0ConflictFixture is one configured box: a real router carrying the given rules, a DNS layer with
// the given reverse mapping, and a TUN inbound whose route sets the caller configures.
type l0ConflictFixture struct {
	inbound *Inbound
	// router is what the inbound holds, and is what the counters below are read from.
	router *preMatchCounter
	// realRouter is the production router behind the counter, for the configuration questions that
	// only it can answer.
	realRouter adapter.Router
	dns        *reverseLookupRecorder
	direct     *plainBypassableDirect
}

// newL0ConflictFixture builds the box.
//
// The rules reach the router twice on purpose, because that is how the product wires them:
// route.NewRouter reads them to decide which flow metadata it must be able to obtain (NeedFindProcess,
// for the process rule), and Initialize parses them into the rules the pre-match loop walks.
func newL0ConflictFixture(t *testing.T, rules []option.Rule, reverseMapping map[netip.Addr]string) *l0ConflictFixture {
	t.Helper()
	dnsRouter := &reverseLookupRecorder{mapping: reverseMapping}
	directOutbound := &plainBypassableDirect{}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, &noFakeIPTransport{})
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &singleOutboundManager{defaultOutbound: directOutbound})
	realRouter := route.NewRouter(ctx, log.NewNOPFactory(), option.RouteOptions{Rules: rules}, option.DNSOptions{})
	require.NoError(t, realRouter.Initialize(rules, nil),
		"the rules must come from the production parser, or the domain rule under test is not the "+
			"one a real configuration would install")
	router := &preMatchCounter{Router: realRouter}

	return &l0ConflictFixture{
		inbound: &Inbound{
			tag:    "tun-l0",
			ctx:    context.Background(),
			router: router,
			logger: log.NewNOPFactory().Logger(),
		},
		router:     router,
		realRouter: realRouter,
		dns:        dnsRouter,
		direct:     directOutbound,
	}
}

// --- the rules ---------------------------------------------------------------------------------

// blockedDomainRejectRule is the policy the user wrote for the reverse-mapped domain.
//
// A reject rather than a route to a proxy, because the verdict then names its cause unambiguously:
// in this fixture route.PreMatch has exactly two ways to answer PreMatchReject - a matched reject
// rule, and a failed resolve action - and there is no resolve action in it. So ActionReject is
// evidence that the rule matched. A route to a proxy could not give that evidence: a matched proxy
// rule and a fast path refused for a recovered domain both arrive as ActionAccept.
func blockedDomainRejectRule() option.Rule {
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				DomainSuffix: []string{reverseMappedDomain},
			},
			RuleAction: rejectAction(),
		},
	}
}

// rejectAction is an "action": "reject" with no method, as a configuration writes it.
//
// The method is spelled out because a rule built in Go does not go through
// RejectActionOptions.UnmarshalJSON, which is what normalises an absent method to "default" for a
// JSON configuration. An empty method reaches RuleActionReject.Error, which panics on it - a
// sharp edge of the Go API that no configuration can reach (every configured rule is unmarshalled)
// and that this file therefore has to work around rather than report as a product defect.
func rejectAction() option.RuleAction {
	return option.RuleAction{
		Action:        C.RuleActionTypeReject,
		RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
	}
}

// reverseMapping is the DNS state: the address is known by this domain.
func reverseMapping(domain string) map[netip.Addr]string {
	return map[netip.Addr]string{netip.MustParseAddr(reverseMappedAddress): domain}
}

// sourceCIDR is one source_ip_cidr entry, in the form the option type takes.
func sourceCIDR(cidr string) *badoption.Prefixable {
	prefix := badoption.Prefixable(netip.MustParsePrefix(cidr))
	return &prefix
}

// --- 1. L0 wins --------------------------------------------------------------------------------

// TestL0AuthoritativeIPPolicyWinsBeforeReverseMapping is the core contract of this file.
//
// Both legal L0 trigger shapes are covered, because they are different lines of JudgeFlow: a miss
// against a non-empty route_address_set, and a hit against route_exclude_address_set. A fix or a
// reordering that covered only one of them would look correct from the other.
func TestL0AuthoritativeIPPolicyWinsBeforeReverseMapping(t *testing.T) {
	destination := netip.MustParseAddrPort(reverseMappedAddress + ":443")
	source := netip.MustParseAddrPort("192.168.1.2:40000")

	shapes := []struct {
		name       string
		routeSet   []*netipx.IPSet
		excludeSet []*netipx.IPSet
		why        string
	}{
		{
			name:     "route_address_set miss",
			routeSet: []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")},
			why: "the include set is non-empty and does not contain the destination: every address " +
				"outside it is the platform's business, which is the ordinary 'this set is my VPN " +
				"range' configuration",
		},
		{
			name:       "route_exclude_address_set hit",
			excludeSet: []*netipx.IPSet{ipSetFrom(t, reverseMappedAddress)},
			why: "the exclude set names the destination explicitly, so the platform carries this one " +
				"address and nothing else",
		},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			// Both wire forms of the same destination. A v4-mapped address is an IPv4 address in
			// sixteen bytes, and an L0 rule that stopped applying to it would hand the flow to the
			// platform for reasons the configuration never stated - the same failure the mapped
			// address tests pin for the guards, here for the guard that competes with a domain rule.
			forms := []struct {
				name        string
				destination netip.AddrPort
			}{
				{"four-byte", destination},
				{"v4-mapped", mappedAddrPort(destination)},
			}

			for _, form := range forms {
				t.Run(form.name, func(t *testing.T) {
					fixture := newL0ConflictFixture(t, []option.Rule{blockedDomainRejectRule()},
						reverseMapping(reverseMappedDomain))
					fixture.inbound.routeAddressSet = shape.routeSet
					fixture.inbound.routeExcludeAddressSet = shape.excludeSet

					verdict := fixture.inbound.JudgeFlow(uint8(headerTCP), source, form.destination, nil)

					require.Equal(t, tun.ActionBypass, verdict.Action,
						"%s: the flow must be handed to the platform. %s", shape.name, shape.why)

					require.EqualValues(t, 0, fixture.router.calls.Load(),
						"the router was consulted for a flow L0 had already answered. The route sets "+
							"ARE the TUN's routing configuration, so a router verdict here could not "+
							"be carried out - the address is in the platform's routing table either "+
							"way - and the domain rule would silently win over an address rule the "+
							"user wrote for the same destination")

					require.EqualValues(t, 0, fixture.dns.lookupCalls.Load(),
						"the reverse mapping was looked up for a flow L0 had already answered. The "+
							"lookup is the first step of the domain policy, so a non-zero count here "+
							"means the two layers are both deciding this flow")

					// The same statement from the other side: the outbound's own bypass question is
					// what the router asks when it runs its fast-path decision.
					require.EqualValues(t, 0, fixture.direct.bypassCalls.Load(),
						"the router's fast-path decision ran for a flow L0 had already answered")
				})
			}
		})
	}

	// The precondition that keeps every assertion above from being vacuous: with the L0 condition
	// removed and nothing else changed, this fixture's domain rule really does reject the flow. If a
	// future edit broke the rule parsing or the reverse-mapping wiring, this fails rather than the
	// L0 assertions quietly passing for the wrong reason.
	t.Run("precondition: without the L0 rule the same flow is rejected by the domain rule", func(t *testing.T) {
		fixture := newL0ConflictFixture(t, []option.Rule{blockedDomainRejectRule()},
			reverseMapping(reverseMappedDomain))

		verdict := fixture.inbound.JudgeFlow(uint8(headerTCP), source, destination, nil)

		require.Equal(t, tun.ActionReject, verdict.Action,
			"the fixture must be able to reject this flow through the reverse-mapped domain, or "+
				"the tests above prove nothing about which layer decided it")
		require.EqualValues(t, 1, fixture.dns.lookupCalls.Load(),
			"and it must be the reverse mapping that supplied the domain the rule matched")
	})
}

// --- 2. the positive control -------------------------------------------------------------------

// TestNonL0FlowReachesTheRouterAndCanUseDNSDerivedPolicy is the control that makes the test above
// meaningful: the same destination, the same inbound and the same router, with the L0 condition NOT
// satisfied, so the flow falls through to the full policy - and there the reverse-mapped domain
// decides the verdict.
//
// # What makes this more than a call count
//
// The three runs below differ in ONE input: what the DNS layer knows about the destination address.
// Everything else - rules, outbounds, route sets, request - is identical, and the verdicts differ.
// That is the claim "the domain participates", and it is made against the real router: the chain
//
//	PreMatch -> prepareMatchMetadata -> LookupReverseMapping -> metadata.Domain -> DomainItem.Match
//
// is production code from end to end, and the discard is production code too (canFastBypass refuses
// a fast bypass once a domain has been recovered).
//
// # What it still does not prove
//
// It does not prove anything about a deployment whose DNS layer has no reverse mapping for the
// address: run (b) IS that case, and it bypasses. The L0 contract in test 1 is what keeps that from
// mattering for the flows L0 answers.
func TestNonL0FlowReachesTheRouterAndCanUseDNSDerivedPolicy(t *testing.T) {
	destination := netip.MustParseAddrPort(reverseMappedAddress + ":443")
	source := netip.MustParseAddrPort("192.168.1.2:40000")

	// (a) The domain is known and a rule describes it: the real router rejects the flow.
	t.Run("reverse-mapped domain matches a rule", func(t *testing.T) {
		fixture := newL0ConflictFixture(t, []option.Rule{blockedDomainRejectRule()},
			reverseMapping(reverseMappedDomain))

		verdict := fixture.inbound.JudgeFlow(uint8(headerTCP), source, destination, nil)

		require.Equal(t, tun.ActionReject, verdict.Action,
			"with no L0 condition holding, the flow must reach the router, and the router must be "+
				"able to act on the domain the DNS layer knows for the destination. In this fixture "+
				"route.PreMatch can answer PreMatchReject only from a matched reject rule (the "+
				"other source, a failed resolve action, is not configured), so this verdict is the "+
				"domain rule's doing and not a fall-through")
		require.EqualValues(t, 1, fixture.router.calls.Load(),
			"the router is consulted exactly once for the flow")
		require.EqualValues(t, 1, fixture.dns.lookupCalls.Load(),
			"and the lookup that supplies the domain is the router's own metadata pass, not a "+
				"stand-in placed in front of it")

		asked := fixture.dns.askedAddress.Load()
		require.NotNil(t, asked)
		require.Equal(t, netip.MustParseAddr(reverseMappedAddress), *asked,
			"the router must ask about the flow's destination address")
	})

	// (b) Nothing knows a domain for that address. Same everything else.
	t.Run("no reverse mapping", func(t *testing.T) {
		fixture := newL0ConflictFixture(t, []option.Rule{blockedDomainRejectRule()}, nil)

		verdict := fixture.inbound.JudgeFlow(uint8(headerTCP), source, destination, nil)

		require.Equal(t, tun.ActionBypass, verdict.Action,
			"with no domain recovered, the flow settles on the plain direct outbound and the "+
				"router's own fast path bypasses it. This is the control that attributes (a) to the "+
				"domain: the only input that changed is what the DNS layer knew")
		require.EqualValues(t, 1, fixture.router.calls.Load(),
			"the router is still consulted, so the bypass is its verdict and not L0's")
		require.EqualValues(t, 1, fixture.dns.lookupCalls.Load(),
			"the lookup was still made; it simply answered nothing")
		require.NotZero(t, fixture.direct.bypassCalls.Load(),
			"the router's fast-path decision ran and asked the outbound, which is the decision the "+
				"recovered domain is capable of refusing")
	})

	// (c) A domain is recovered but no rule describes it. It still participates: the router refuses
	// its own fast bypass for any flow whose domain it had to recover, because the userspace path is
	// where dual-stack recovery and unmapping live.
	t.Run("reverse-mapped domain matches no rule", func(t *testing.T) {
		fixture := newL0ConflictFixture(t, []option.Rule{blockedDomainRejectRule()},
			reverseMapping(unrelatedDomain))

		verdict := fixture.inbound.JudgeFlow(uint8(headerTCP), source, destination, nil)

		require.Equal(t, tun.ActionAccept, verdict.Action,
			"a recovered domain keeps the flow on the userspace path even when no rule matches it")
		require.NotEqual(t, tun.ActionBypass, verdict.Action,
			"the domain the DNS layer supplied is part of the decision, so this flow must not take "+
				"the bypass that (b) - identical except for that domain - does take")
		require.EqualValues(t, 1, fixture.dns.lookupCalls.Load())
		require.Zero(t, fixture.direct.bypassCalls.Load(),
			"the router never asked the outbound, because it refused the fast path before that "+
				"question: the refusal is the recovered domain's doing")
	})
}

// --- 3. the non-L0 branch keeps the full policy -------------------------------------------------

// TestL0DoesNotDiscardProcessOrProtocolRulesOnTheNonL0Branch pins the other half of the boundary.
//
// Test 1 says the L0 branch does not consult the router, which is correct because L0 carries an
// address-only decision. This says what happens to the flows L0 does NOT answer: they reach a router
// that still holds every condition the user wrote - including the ones L0 has no representation for
// at all, which is why a DIRECT rule must never be compiled into a route set.
//
// # What each sub-test proves, and what it cannot
//
//	protocol (network)   a network condition decides the same destination two different ways
//	source address       a condition L0 never sees - L0 reads the destination address alone -
//	                     decides the flow
//	process              the process half of the policy is present and live in the router the flow
//	                     reaches (NeedFindProcess, which is what makes the router obtain process
//	                     metadata in a real deployment). It is NOT proof that a process rule would
//	                     MATCH: a process condition is evaluated against
//	                     adapter.InboundContext.ProcessInfo, which only the router's OS process
//	                     searcher fills in, and a TUN flow as this test can build it carries none.
//	                     The rule is walked and evaluated; it is simply not matchable here.
func TestL0DoesNotDiscardProcessOrProtocolRulesOnTheNonL0Branch(t *testing.T) {
	source := netip.MustParseAddrPort("192.168.1.2:40000")
	otherSource := netip.MustParseAddrPort("192.168.1.9:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	t.Run("a protocol rule still decides the flow", func(t *testing.T) {
		// No L0 route set at all: nothing can bypass, so the router's rules are the whole policy.
		fixture := newL0ConflictFixture(t, []option.Rule{{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{Network: []string{N.NetworkUDP}},
				RuleAction:     rejectAction(),
			},
		}}, nil)

		udpVerdict := fixture.inbound.JudgeFlow(uint8(headerUDP), source, destination, nil)
		require.Equal(t, tun.ActionReject, udpVerdict.Action,
			"a protocol condition must still be able to decide a flow that reaches the router")

		tcpVerdict := fixture.inbound.JudgeFlow(uint8(headerTCP), source, destination, nil)
		require.Equal(t, tun.ActionBypass, tcpVerdict.Action,
			"and the same destination on the other protocol must not be rejected: the reject above "+
				"is the protocol condition's doing, not a blanket verdict")
		require.EqualValues(t, 2, fixture.router.calls.Load(),
			"both flows reached the router")
		require.NotZero(t, fixture.direct.bypassCalls.Load())
	})

	t.Run("a source condition still decides the flow", func(t *testing.T) {
		fixture := newL0ConflictFixture(t, []option.Rule{{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					SourceIPCIDR: []*badoption.Prefixable{sourceCIDR("192.168.1.2/32")},
				},
				RuleAction: rejectAction(),
			},
		}}, nil)

		verdict := fixture.inbound.JudgeFlow(uint8(headerTCP), source, destination, nil)
		require.Equal(t, tun.ActionReject, verdict.Action,
			"a source-address condition is one of the things L0 cannot express - it reads the "+
				"destination address alone - so it must be evaluated here")

		verdict = fixture.inbound.JudgeFlow(uint8(headerTCP), otherSource, destination, nil)
		require.Equal(t, tun.ActionBypass, verdict.Action,
			"and a different source must not match it")
	})

	t.Run("the process half of the policy is present, not skipped", func(t *testing.T) {
		fixture := newL0ConflictFixture(t, []option.Rule{{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{ProcessName: []string{"l0-test-never-running"}},
				RuleAction:     rejectAction(),
			},
		}}, nil)

		require.True(t, fixture.realRouter.NeedFindProcess(),
			"a process rule must put the router into process-finding mode. This is the process "+
				"policy L0 has no representation for, and it survives on the branch the flow takes")

		verdict := fixture.inbound.JudgeFlow(uint8(headerTCP), source, destination, nil)
		require.EqualValues(t, 1, fixture.router.calls.Load(),
			"the flow reached the rule set that holds the process rule; the rule was walked and "+
				"evaluated against its metadata")
		require.Equal(t, tun.ActionBypass, verdict.Action,
			"the process rule cannot match without ProcessInfo, which no TUN flow carries here. "+
				"That is a limit of the harness and is why this sub-test claims presence and "+
				"evaluation rather than a process match - see the file header")
	})
}

// --- 4. the missing direction of the DNS-by-port negative control --------------------------------

// TestDNSByPortDisabledUDP53FollowsRouteAddressSetPolicy is the include-set direction of the
// negative control that direct_fast_path_dns_test.go pins for the exclude set
// (TestDNSHijackByPortDisabledDoesNotHijack).
//
// The claim is that with the by-port rule OFF and no configured hijack address, port 53 is ordinary
// traffic and the route sets decide it. The exclude direction shows that such a query is not
// forcibly hijacked on a destination the user excluded; the include direction shows the sharper
// case, where the address is a miss against route_address_set - the configuration under which the
// platform carries most of the internet, and therefore the one where "port 53 is special" would
// quietly capture every query on the machine.
func TestDNSByPortDisabledUDP53FollowsRouteAddressSetPolicy(t *testing.T) {
	source := netip.MustParseAddrPort("192.168.1.2:40000")
	query := netip.MustParseAddrPort("8.8.8.8:53")

	// The rule is off: the query is a plain UDP packet and the route set answers it.
	inbound, _ := hijackTestInbound(t, nil, false)
	inbound.routeAddressSet = []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")}

	verdict := inbound.JudgeFlow(uint8(headerUDP), source, query, nil)
	require.Equal(t, tun.ActionBypass, verdict.Action,
		"UDP/53 outside route_address_set must follow the route set. It is not hijacked, because "+
			"the by-port rule is off and no hijack address is configured")
	require.NotEqual(t, tun.ActionHijackDNS, verdict.Action,
		"port 53 must not be special-cased on its own: with the rule off, nothing in the "+
			"configuration asks for this query to be hijacked")

	// The control: the same packet with the rule on IS hijacked, so the assertion above is about
	// the switch and not about a fixture that cannot hijack anything.
	enabled, _ := hijackTestInbound(t, nil, true)
	enabled.routeAddressSet = []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")}

	verdict = enabled.JudgeFlow(uint8(headerUDP), source, query, nil)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action,
		"with dns_hijack enabled by port the same query is hijacked even though the route set "+
			"misses it, which is what makes the disabled case a decision rather than an accident")

	// And the route set is not merely ignored for port 53 when the rule is off: a non-DNS port in
	// the same position behaves identically, so the two cases cannot drift apart.
	verdict = inbound.JudgeFlow(uint8(headerUDP), source,
		netip.MustParseAddrPort("8.8.8.8:443"), nil)
	require.Equal(t, tun.ActionBypass, verdict.Action,
		"a non-DNS port outside the same set behaves exactly as port 53 does")
}
