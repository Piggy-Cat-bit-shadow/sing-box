package group

import (
	"context"
	"math"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// The loadbalance group's strategy semantics, asserted through the group rather than
// through the strategy functions.
//
// Every test here builds a real group with real members and asks it for a member, because
// the failure this feature is most likely to have is not a wrong algorithm - it is a
// strategy that never reaches the decision the data plane makes. A test that called the
// strategy function directly would pass with the group wired to nothing.

// recordingOutbound is a member that remembers what was done to it.
type recordingOutbound struct {
	adapter.Outbound
	tag      string
	networks []string

	access    sync.Mutex
	conns     int
	packets   int
	datagrams int
}

func newRecordingOutbound(tag string, networks ...string) *recordingOutbound {
	if len(networks) == 0 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	}
	return &recordingOutbound{tag: tag, networks: networks}
}

func (o *recordingOutbound) Type() string      { return "recording" }
func (o *recordingOutbound) Tag() string       { return o.tag }
func (o *recordingOutbound) Network() []string { return o.networks }

func (o *recordingOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	o.access.Lock()
	o.conns++
	o.access.Unlock()
	return &stubConn{}, nil
}

func (o *recordingOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	o.access.Lock()
	o.packets++
	o.access.Unlock()
	return &recordingPacketConn{owner: o}, nil
}

func (o *recordingOutbound) counts() (conns int, packets int, datagrams int) {
	o.access.Lock()
	defer o.access.Unlock()
	return o.conns, o.packets, o.datagrams
}

// recordingPacketConn counts datagrams written through it, which is where a per-datagram
// selection would show up.
type recordingPacketConn struct {
	net.PacketConn
	owner *recordingOutbound
}

func (c *recordingPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	c.owner.access.Lock()
	c.owner.datagrams++
	c.owner.access.Unlock()
	return len(payload), nil
}

func (c *recordingPacketConn) Close() error { return nil }

// healthNow is a measurement that succeeded a moment ago.
func healthNow() *adapter.URLTestHistory {
	return &adapter.URLTestHistory{Time: time.Now(), Delay: 20}
}

// keyOf reports the hash key the group derives for a domain, so a test can assert the key
// itself rather than a member index that happens to differ.
func keyOf(t *testing.T, domain string) string {
	t.Helper()
	return loadBalanceDestinationKey(&adapter.InboundContext{Network: N.NetworkTCP, Domain: domain})
}

// loadBalanceManager resolves the members a group lists.
type loadBalanceManager struct {
	adapter.OutboundManager
	members map[string]adapter.Outbound
}

func (m *loadBalanceManager) Outbounds() []adapter.Outbound {
	outbounds := make([]adapter.Outbound, 0, len(m.members))
	for _, member := range m.members {
		outbounds = append(outbounds, member)
	}
	return outbounds
}

func (m *loadBalanceManager) Outbound(tag string) (adapter.Outbound, bool) {
	member, loaded := m.members[tag]
	return member, loaded
}

type loadBalanceFixture struct {
	group       *LoadBalance
	manager     *loadBalanceManager
	storage     *urltest.HistoryStorage
	members     []*recordingOutbound
	coordinator *runtimecoord.Coordinator
	ctx         context.Context
}

// newLoadBalanceFixture builds a started group over the given members.
func newLoadBalanceFixture(t *testing.T, options option.LoadBalanceOutboundOptions, members ...*recordingOutbound) *loadBalanceFixture {
	t.Helper()
	return newLoadBalanceFixtureLogger(t, nil, options, members...)
}

// newLoadBalanceFixtureLogger is the same fixture with a caller-supplied logger, and is how a
// test observes what the group reported rather than only what it did.
//
// The context always carries a real network-generation coordinator. It starts at generation
// zero and stays there unless a test advances it, so a test that does not care about
// generations sees exactly the behaviour a core with no reset would produce.
func newLoadBalanceFixtureLogger(t *testing.T, groupLogger log.ContextLogger, options option.LoadBalanceOutboundOptions, members ...*recordingOutbound) *loadBalanceFixture {
	t.Helper()
	coordinator := runtimecoord.New()
	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	ctx = service.ContextWith[*runtimecoord.Coordinator](ctx, coordinator)
	manager := &loadBalanceManager{members: make(map[string]adapter.Outbound, len(members))}
	tags := make([]string, 0, len(members))
	for _, member := range members {
		manager.members[member.Tag()] = member
		tags = append(tags, member.Tag())
	}
	if len(options.Outbounds) == 0 {
		options.Outbounds = tags
	}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	if groupLogger == nil {
		groupLogger = log.NewNOPFactory().NewLogger("loadbalance")
	}
	created, err := NewLoadBalance(ctx, nil, groupLogger, "lb", options)
	require.NoError(t, err)
	group, isGroup := created.(*LoadBalance)
	require.True(t, isGroup)

	scope := &adapter.Scope{}
	require.NoError(t, group.Start(adapter.StartStateStart, scope))
	t.Cleanup(func() {
		require.NoError(t, group.Close())
	})
	return &loadBalanceFixture{
		group:       group,
		manager:     manager,
		storage:     service.PtrFromContext[urltest.HistoryStorage](ctx),
		members:     members,
		coordinator: coordinator,
		ctx:         ctx,
	}
}

// selectFor builds metadata pointing at a domain and selects once.
func (f *loadBalanceFixture) selectFor(t *testing.T, network string, domain string, source string, commit bool) string {
	t.Helper()
	metadata := &adapter.InboundContext{Network: network}
	if domain != "" {
		metadata.Domain = domain
	}
	if source != "" {
		metadata.Source = M.ParseSocksaddrHostPort(source, 40000)
	}
	selected := f.group.SelectForFlow(metadata, network, commit)
	require.NotNil(t, selected, "the group must answer for a flow it can carry")
	return selected.Tag()
}

// tagsFrom collects the member each of n committed selections chose.
func (f *loadBalanceFixture) tagsFrom(t *testing.T, n int, network string, domain string) []string {
	t.Helper()
	tags := make([]string, 0, n)
	for i := 0; i < n; i++ {
		tags = append(tags, f.selectFor(t, network, domain, "192.168.1.9", true))
	}
	return tags
}

func indexOfTag(order []string, tag string) int {
	for i, candidate := range order {
		if candidate == tag {
			return i
		}
	}
	return -1
}

func fourMembers() []*recordingOutbound {
	return []*recordingOutbound{
		newRecordingOutbound("A"),
		newRecordingOutbound("B"),
		newRecordingOutbound("C"),
		newRecordingOutbound("D"),
	}
}

// --- round robin ------------------------------------------------------------------------

// TestLoadBalanceRoundRobinRotatesOverMembers is the primary behaviour: successive committed
// selections visit successive members and wrap.
func TestLoadBalanceRoundRobinRotatesOverMembers(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, fourMembers()...)

	require.Equal(t,
		[]string{"A", "B", "C", "D", "A", "B", "C", "D"},
		fixture.tagsFrom(t, 8, N.NetworkTCP, "example.com"))
}

// TestLoadBalanceRoundRobinIsTheDefault pins the documented default, which is a deliberate
// divergence from the reference implementation's consistent-hashing default.
func TestLoadBalanceRoundRobinIsTheDefault(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{}, fourMembers()...)

	require.Equal(t, loadBalanceStrategyRoundRobin, fixture.group.strategy)
	require.Equal(t,
		[]string{"A", "B", "C", "D"},
		fixture.tagsFrom(t, 4, N.NetworkTCP, "example.com"))
}

// TestLoadBalanceSpeculativeSelectionConsumesNothing is the pre-match rule.
//
// The route path asks for a member twice for some flows: once for the pre-match preview,
// whose verdict may be discarded, and once for the connection that is established. A
// preview that advanced the rotation would spend a member on a connection that never
// existed and make the two walks disagree about the flow.
func TestLoadBalanceSpeculativeSelectionConsumesNothing(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, fourMembers()...)

	// Many previews, as the pre-match path would issue, all answering with the member the
	// next committed selection will use.
	for i := 0; i < 7; i++ {
		require.Equal(t, "A", fixture.selectFor(t, N.NetworkTCP, "example.com", "", false),
			"a preview must report the next committed member")
	}

	// The committed selections then run from the beginning, unimpeded.
	require.Equal(t,
		[]string{"A", "B", "C", "D"},
		fixture.tagsFrom(t, 4, N.NetworkTCP, "example.com"))
}

// TestLoadBalancePreviewAndCommitAgreeWithinOneFlow is the invariant the split exists for:
// the member the preview reported is the member the committed selection returns, so the
// verdict the preview computed describes the connection that is made.
func TestLoadBalancePreviewAndCommitAgreeWithinOneFlow(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, fourMembers()...)

	for i := 0; i < 8; i++ {
		preview := fixture.selectFor(t, N.NetworkTCP, "example.com", "", false)
		committed := fixture.selectFor(t, N.NetworkTCP, "example.com", "", true)
		require.Equal(t, preview, committed,
			"flow %d: the preview and the connection it announced must take the same member", i+1)
	}
}

// TestLoadBalanceCursorWrapsWithoutPanicking covers the overflow edge: a uint64 counter
// reduced modulo a small member count is valid at every value, including the ones around
// the wrap.
func TestLoadBalanceCursorWrapsWithoutPanicking(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, fourMembers()...)

	order := []string{"A", "B", "C", "D"}
	for _, start := range []uint64{0, math.MaxUint64 - 1, math.MaxUint64, math.MaxUint64/2 + 1} {
		fixture.group.cursor.Store(start)
		tags := fixture.tagsFrom(t, 12, N.NetworkTCP, "example.com")
		// Whatever the starting value, the sequence is a rotation of the members in
		// configuration order: each tag is the successor of the previous one. That is the
		// invariant; the particular member the wrapped counter lands on is arithmetic.
		for i := 1; i < len(tags); i++ {
			previous := indexOfTag(order, tags[i-1])
			require.Equal(t, order[(previous+1)%len(order)], tags[i],
				"at cursor %d the sequence left the rotation at step %d: %v", start, i, tags)
		}
	}
}

// TestLoadBalanceSingleMemberIsAlwaysThatMember covers the degenerate member list.
func TestLoadBalanceSingleMemberIsAlwaysThatMember(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, newRecordingOutbound("only"))

	require.Equal(t, []string{"only", "only", "only"}, fixture.tagsFrom(t, 3, N.NetworkTCP, "example.com"))
}

// TestLoadBalanceDuplicateMemberTakesAProportionalShare documents what a repeated tag means:
// an accepted configuration whose member receives a share in proportion to how often it is
// listed.
func TestLoadBalanceDuplicateMemberTakesAProportionalShare(t *testing.T) {
	fixture := newLoadBalanceFixture(t,
		option.LoadBalanceOutboundOptions{Strategy: "round_robin", Outbounds: []string{"A", "A", "B"}},
		newRecordingOutbound("A"), newRecordingOutbound("B"))

	tags := fixture.tagsFrom(t, 6, N.NetworkTCP, "example.com")
	counts := map[string]int{}
	for _, tag := range tags {
		counts[tag]++
	}
	require.Equal(t, 4, counts["A"], "a member listed twice takes two of every three flows")
	require.Equal(t, 2, counts["B"])
}

// TestLoadBalanceEmptyMemberListFailsConfiguration is the fail-closed start: a group with
// nothing to balance must not start at all.
func TestLoadBalanceEmptyMemberListFailsConfiguration(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &loadBalanceManager{members: map[string]adapter.Outbound{}})

	_, err := NewLoadBalance(ctx, nil, log.NewNOPFactory().NewLogger("lb"), "lb", option.LoadBalanceOutboundOptions{})
	require.Error(t, err, "a group with no members must refuse to be constructed")
}

// TestLoadBalanceUnknownStrategyFailsConfiguration covers the config error path.
func TestLoadBalanceUnknownStrategyFailsConfiguration(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &loadBalanceManager{members: map[string]adapter.Outbound{}})

	for _, strategy := range []string{"round-robin", "ROUND_ROBIN", "random", "sticky"} {
		_, err := NewLoadBalance(ctx, nil, log.NewNOPFactory().NewLogger("lb"), "lb", option.LoadBalanceOutboundOptions{
			Outbounds: []string{"A"},
			Strategy:  strategy,
		})
		require.Error(t, err, "strategy %q must be rejected, not silently mapped to a default", strategy)
	}
}

// TestLoadBalanceMissingMemberFailsStart covers a tag that resolves to nothing.
func TestLoadBalanceMissingMemberFailsStart(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &loadBalanceManager{members: map[string]adapter.Outbound{}}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	created, err := NewLoadBalance(ctx, nil, log.NewNOPFactory().NewLogger("lb"), "lb", option.LoadBalanceOutboundOptions{
		Outbounds: []string{"absent"},
	})
	require.NoError(t, err)
	require.Error(t, created.(*LoadBalance).Start(adapter.StartStateStart, &adapter.Scope{}))
}

// --- network compatibility --------------------------------------------------------------

// TestLoadBalanceSkipsMembersThatCannotCarryTheNetwork is the false-hit guard: a member that
// cannot carry UDP must never receive a UDP flow, not even when it is the rotation's turn.
func TestLoadBalanceSkipsMembersThatCannotCarryTheNetwork(t *testing.T) {
	udpFixture := newLoadBalanceFixture(t,
		option.LoadBalanceOutboundOptions{Strategy: "round_robin"},
		newRecordingOutbound("tcp-only", N.NetworkTCP), newRecordingOutbound("both"))
	require.Equal(t, []string{"both", "both", "both"}, udpFixture.tagsFrom(t, 3, N.NetworkUDP, "example.com"),
		"a member that cannot carry UDP must never be selected for one")

	// The same member list over TCP rotates through both, so the filter above is about the
	// network rather than about the rotation being stuck.
	tcpFixture := newLoadBalanceFixture(t,
		option.LoadBalanceOutboundOptions{Strategy: "round_robin"},
		newRecordingOutbound("tcp-only", N.NetworkTCP), newRecordingOutbound("both"))
	require.Equal(t, []string{"tcp-only", "both", "tcp-only"}, tcpFixture.tagsFrom(t, 3, N.NetworkTCP, "example.com"))
}

// TestLoadBalanceRefusesANetworkNoMemberSupports is the fail-closed answer: nil, which the
// route path turns into an error, rather than a member that cannot carry the flow.
func TestLoadBalanceRefusesANetworkNoMemberSupports(t *testing.T) {
	fixture := newLoadBalanceFixture(t,
		option.LoadBalanceOutboundOptions{Strategy: "round_robin"},
		newRecordingOutbound("tcp-only", N.NetworkTCP))

	require.Nil(t, fixture.group.SelectForFlow(&adapter.InboundContext{}, N.NetworkUDP, true))
}

// TestLoadBalanceNetworkIsTheUnionOfItsMembers matters for parent groups, which filter a
// member by Network() before asking it for anything.
func TestLoadBalanceNetworkIsTheUnionOfItsMembers(t *testing.T) {
	fixture := newLoadBalanceFixture(t,
		option.LoadBalanceOutboundOptions{Strategy: "round_robin"},
		newRecordingOutbound("tcp-only", N.NetworkTCP),
		newRecordingOutbound("both"))

	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, fixture.group.Network())
}

// --- health -----------------------------------------------------------------------------

// TestLoadBalanceHealthFiltersCandidates is the point of the URL option: a member whose
// measurement failed is not a candidate, so the rotation passes over it.
func TestLoadBalanceHealthFiltersCandidates(t *testing.T) {
	members := fourMembers()
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "http://127.0.0.1:1/generate_204",
	}, members...)

	// Two members measured successfully, two with no evidence at all.
	fixture.storage.StoreHealthHistory("A", fixture.group.healthScope, healthNow())
	fixture.storage.StoreHealthHistory("C", fixture.group.healthScope, healthNow())

	require.Equal(t,
		[]string{"A", "C", "A", "C"},
		fixture.tagsFrom(t, 4, N.NetworkTCP, "example.com"),
		"members with no current health evidence must not be handed a flow")
}

// TestLoadBalanceHealthWithoutEvidenceKeepsEveryMember is the false-miss guard.
//
// A configured URL whose first round has not finished yet, or whose group is simply idle,
// leaves every member without evidence. Reading that as "dead" would refuse the whole group
// for as long as the checker had not run - and for a group whose URL is unreachable, for
// ever.
func TestLoadBalanceHealthWithoutEvidenceKeepsEveryMember(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "https://probe.example/generate_204",
	}, fourMembers()...)

	require.Equal(t,
		[]string{"A", "B", "C", "D"},
		fixture.tagsFrom(t, 4, N.NetworkTCP, "example.com"))
}

// TestLoadBalanceHealthRecoveryReturnsAMemberToRotation covers the other false miss: a
// failure must not exclude a member for ever.
func TestLoadBalanceHealthRecoveryReturnsAMemberToRotation(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "https://probe.example/generate_204",
	}, fourMembers()...)

	fixture.storage.StoreHealthHistory("A", fixture.group.healthScope, healthNow())
	require.Equal(t, []string{"A", "A"}, fixture.tagsFrom(t, 2, N.NetworkTCP, "example.com"))

	// A and B are measured now; both take their turn.
	fixture.storage.StoreHealthHistory("B", fixture.group.healthScope, healthNow())
	require.Equal(t, []string{"A", "B", "A", "B"}, fixture.tagsFrom(t, 4, N.NetworkTCP, "example.com"))
}

// TestLoadBalanceHealthScopeIsTheURLTestScope proves the reuse the design claims: the group
// reads the same evidence a urltest group with the same url and expected_status maintains,
// because it is the same key.
func TestLoadBalanceHealthScopeIsTheURLTestScope(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{
		Strategy:       "round_robin",
		URL:            "https://probe.example/generate_204",
		ExpectedStatus: "204",
	}, fourMembers()...)

	expectedStatus, err := urltest.ParseExpectedStatus("204")
	require.NoError(t, err)
	expected, err := urltest.NewMeasurementScope("https://probe.example/generate_204", expectedStatus)
	require.NoError(t, err)
	require.Equal(t, expected, fixture.group.healthScope,
		"health is shared with a urltest group measuring the same target with the same expectation")
}

// TestLoadBalanceHealthIsNotConsultedWithoutAURL keeps the no-URL configuration inert: with
// nothing measuring the members, evidence left over from another group's checks must not
// silently start filtering this one.
func TestLoadBalanceHealthIsNotConsultedWithoutAURL(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, fourMembers()...)

	require.Equal(t,
		[]string{"A", "B", "C", "D"},
		fixture.tagsFrom(t, 4, N.NetworkTCP, "example.com"))
}

// TestLoadBalanceAllMembersUnhealthyStillAnswers is the all-down policy.
//
// The reference implementation answers with a member rather than failing, and so does this:
// a group whose probe target is merely unreachable, or wrong, must not become an outage.
// What it must never do is answer with something that is not a member, or with nothing.
func TestLoadBalanceAllMembersUnhealthyStillAnswers(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "https://probe.example/generate_204",
	}, fourMembers()...)

	selected := fixture.group.SelectForFlow(&adapter.InboundContext{}, N.NetworkTCP, true)
	require.NotNil(t, selected, "a group with no healthy member still has to answer for a flow")
	require.Contains(t, []string{"A", "B", "C", "D"}, selected.Tag())
}

// --- consistent hashing -----------------------------------------------------------------

// TestLoadBalanceConsistentHashingIsStableForOneDestination is the strategy's contract.
func TestLoadBalanceConsistentHashingIsStableForOneDestination(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "consistent_hashing"}, fourMembers()...)

	first := fixture.selectFor(t, N.NetworkTCP, "shop.example.com", "192.168.1.9", true)
	for i := 0; i < 99; i++ {
		require.Equal(t, first, fixture.selectFor(t, N.NetworkTCP, "shop.example.com", "192.168.1.9", true),
			"the same destination must keep the same member")
	}
	// And it is not simply always the first member.
	seen := map[string]bool{first: true}
	for i := 0; i < 64; i++ {
		seen[fixture.selectFor(t, N.NetworkTCP, "host"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example.net", "192.168.1.9", true)] = true
	}
	require.Greater(t, len(seen), 1, "different destinations must spread over more than one member")
}

// TestLoadBalanceHashKeyCanonicalisation pins what the key is and is not sensitive to.
func TestLoadBalanceHashKeyCanonicalisation(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		first    string
		second   string
		together bool
	}{
		{"case is not identity", "Shop.Example.COM", "shop.example.com", true},
		{"a trailing dot is the same name", "shop.example.com.", "shop.example.com", true},
		{"subdomains of one site are one identity", "a.shop.example.com", "b.shop.example.com", true},
		{"different sites are different identities", "shop.example.com", "other.example.org", false},
		{"an IPv4 literal is the same address in any spelling", "10.0.0.1", "10.0.0.1", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "consistent_hashing"}, fourMembers()...)
			first := fixture.selectFor(t, N.NetworkTCP, testCase.first, "192.168.1.9", true)
			second := fixture.selectFor(t, N.NetworkTCP, testCase.second, "192.168.1.9", true)
			if testCase.together {
				require.Equal(t, first, second)
			} else {
				// Not required to differ for every pair - only that the key differs, which is
				// asserted directly below.
				require.NotEqual(t, keyOf(t, testCase.first), keyOf(t, testCase.second))
			}
		})
	}
}

// TestLoadBalanceHashKeyIsTheRegistrableDomain pins the eTLD+1 rule against the reference
// implementation, which is the behaviour a migrated configuration expects.
func TestLoadBalanceHashKeyIsTheRegistrableDomain(t *testing.T) {
	require.Equal(t, "example.com", keyOf(t, "a.b.example.com"))
	require.Equal(t, "example.com", keyOf(t, "shop.example.com"))
	require.Equal(t, "example.co.uk", keyOf(t, "shop.example.co.uk"))
	require.Equal(t, "10.0.0.1", keyOf(t, "10.0.0.1"))
	// A single-label host has no registrable domain; it is still a logical target, and it
	// must not collapse into an empty key.
	require.Equal(t, "localhost", keyOf(t, "localhost"))
}

// TestLoadBalanceHashKeyIsStableAcrossResolverAnswers is the dual-stack rule: the same
// domain is the same identity whichever family DNS answered with.
func TestLoadBalanceHashKeyIsStableAcrossResolverAnswers(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "consistent_hashing"}, fourMembers()...)

	metadataV6 := &adapter.InboundContext{
		Network:              N.NetworkTCP,
		Domain:               "shop.example.com",
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("2606:4700::1")},
	}
	metadataV4 := &adapter.InboundContext{
		Network:              N.NetworkTCP,
		Domain:               "shop.example.com",
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
	}
	require.Equal(t,
		fixture.group.SelectForFlow(metadataV6, N.NetworkTCP, true).Tag(),
		fixture.group.SelectForFlow(metadataV4, N.NetworkTCP, true).Tag(),
		"a fallback from AAAA to A must not move an affinity that is defined on the name")
}

// TestLoadBalanceMappedAddressIsOneDestination covers the sixteen-byte spelling of a
// four-byte address, which is the same destination.
func TestLoadBalanceMappedAddressIsOneDestination(t *testing.T) {
	four := netip.MustParseAddr("93.184.216.34")
	mapped := netip.AddrFrom16(four.As16())

	require.Equal(t, loadBalanceCanonicalAddr(four), loadBalanceCanonicalAddr(mapped))
	require.Equal(t,
		loadBalanceDestinationKey(&adapter.InboundContext{Destination: M.SocksaddrFromNetIP(netip.AddrPortFrom(four, 443))}),
		loadBalanceDestinationKey(&adapter.InboundContext{Destination: M.SocksaddrFromNetIP(netip.AddrPortFrom(mapped, 443))}))
}

// TestLoadBalanceEmptyKeyFallsBackToRoundRobin is the empty-semantics guard.
//
// Hashing nothing would send every flow with no destination identity to one member, which
// is the failure a hash key that is silently always empty produces.
func TestLoadBalanceEmptyKeyFallsBackToRoundRobin(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "consistent_hashing"}, fourMembers()...)

	require.Equal(t, "", loadBalanceDestinationKey(&adapter.InboundContext{Network: N.NetworkTCP}))
	require.Equal(t,
		[]string{"A", "B", "C", "D"},
		fixture.tagsFrom(t, 4, N.NetworkTCP, ""),
		"a flow with no destination identity must still spread")
}

// TestLoadBalanceHashBucketSpaceDoesNotFollowHealth is why the hash is taken over the member
// list and not over the candidate set: a member becoming unhealthy must not re-map the flows
// that were not pointing at it.
func TestLoadBalanceHashBucketSpaceDoesNotFollowHealth(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{
		Strategy: "consistent_hashing",
		URL:      "https://probe.example/generate_204",
	}, fourMembers()...)

	// Everything is measured, so every member is a candidate and no key is displaced.
	for _, tag := range []string{"A", "B", "C", "D"} {
		fixture.storage.StoreHealthHistory(tag, fixture.group.healthScope, healthNow())
	}
	keys := make([]string, 0, 32)
	hosts := make([]string, 0, 32)
	for i := 0; i < 32; i++ {
		host := "host" + strings.Repeat("x", 1+i%5) + string(rune('a'+i)) + ".example.com"
		hosts = append(hosts, host)
		keys = append(keys, fixture.selectFor(t, N.NetworkTCP, host, "192.168.1.9", true))
	}

	// A member goes away. The destinations that were not on it keep their member.
	fixture.storage.DeleteHealthHistory("B", fixture.group.healthScope)
	moved := 0
	for i, host := range hosts {
		if fixture.selectFor(t, N.NetworkTCP, host, "192.168.1.9", true) != keys[i] {
			moved++
		}
	}
	require.Less(t, moved, len(hosts), "a health change must not remap every key")
	require.Greater(t, len(hosts)-moved, 0)
}

// --- sticky sessions --------------------------------------------------------------------

// TestLoadBalanceStickyPinsSourceAndDestination is the strategy's contract.
func TestLoadBalanceStickyPinsSourceAndDestination(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "sticky_sessions"}, fourMembers()...)

	first := fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true)
	for i := 0; i < 9; i++ {
		require.Equal(t, first, fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true))
	}
	// The same source to a different destination is a different pin.
	require.NotEqual(t, "", fixture.selectFor(t, N.NetworkTCP, "other.example.org", "192.168.1.9", true))
	// And the destinations do not all have to be the same member; what matters is that the
	// pins are per key, which the spread of many keys shows.
	// Distinct registrable domains, because one site is one pin by design: every subdomain
	// of example.net is the same session identity.
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		seen[fixture.selectFor(t, N.NetworkTCP, "shop.example"+string(rune('a'+i))+".net", "192.168.1.9", true)] = true
	}
	require.Greater(t, len(seen), 1, "distinct destinations must be able to reach distinct members")
}

// TestLoadBalanceStickyDoesNotConsumeSpeculation is the pre-match rule again, for the
// strategy whose cache a preview would otherwise seed with a pin no flow ever used.
func TestLoadBalanceStickyDoesNotConsumeSpeculation(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "sticky_sessions"}, fourMembers()...)

	for i := 0; i < 5; i++ {
		fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", false)
	}
	require.Equal(t, 0, fixture.group.affinity.size(),
		"a preview must not write an affinity pin")

	// The first committed selection is the one that pins, and it pins the member it used.
	pinned := fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true)
	require.Equal(t, 1, fixture.group.affinity.size())
	require.Equal(t, pinned, fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true))
}

// TestLoadBalanceStickyExpiresAPin covers the TTL: affinity is bounded in time, so a
// destination may be rebalanced once the pin has expired.
func TestLoadBalanceStickyExpiresAPin(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "sticky_sessions"}, fourMembers()...)

	now := time.Now()
	fixture.group.affinity.now = func() time.Time { return now }

	pinned := fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true)
	require.Equal(t, pinned, fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true))

	now = now.Add(loadBalanceDefaultAffinityTTL + time.Second)
	_, loaded := fixture.group.affinity.member("192.168.1.9\x00example.com")
	require.False(t, loaded, "an expired pin must not be honoured")
}

// TestLoadBalanceStickyIsBounded is the memory guard: the cache is keyed by something the
// peer controls, so it must not grow with the number of keys.
func TestLoadBalanceStickyIsBounded(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "sticky_sessions"}, fourMembers()...)

	for i := 0; i < loadBalanceDefaultAffinityLimit*3; i++ {
		fixture.selectFor(t, N.NetworkTCP,
			"host"+strconv.Itoa(i)+".example.com",
			"192.168."+strconv.Itoa(i/256%256)+"."+strconv.Itoa(i%256),
			true)
	}
	require.LessOrEqual(t, fixture.group.affinity.size(), loadBalanceDefaultAffinityLimit,
		"the affinity cache must stay within its bound")
}

// TestLoadBalanceStickyHealthOverridesAStalePin is the interaction the two features have to
// get right: affinity is a preference, not a promise, and it loses to liveness.
func TestLoadBalanceStickyHealthOverridesAStalePin(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{
		Strategy: "sticky_sessions",
		URL:      "https://probe.example/generate_204",
	}, fourMembers()...)

	// Everything is healthy to begin with, so the pin is the only thing deciding.
	for _, tag := range []string{"A", "B", "C", "D"} {
		fixture.storage.StoreHealthHistory(tag, fixture.group.healthScope, healthNow())
	}
	pinned := fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true)
	require.Equal(t, "A", pinned)

	// The pinned member dies while the others are healthy. The pin is a preference, so the
	// next flow for the same key must go to a member that can actually carry it.
	fixture.storage.DeleteHealthHistory("A", fixture.group.healthScope)
	next := fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true)
	require.NotEqual(t, "A", next, "a pin must not survive the death of the member it points at")

	// The replacement is pinned in its place, so the affinity survives the member.
	require.Equal(t, next, fixture.selectFor(t, N.NetworkTCP, "login.example.com", "192.168.1.9", true))

	// A recovered member is a candidate again on the next flow, without waiting for a window.
	fixture.storage.StoreHealthHistory("A", fixture.group.healthScope, healthNow())
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		seen[fixture.selectFor(t, N.NetworkTCP, "other.example"+string(rune('a'+i))+".net", "192.168.1.9", true)] = true
	}
	require.Contains(t, seen, "A", "a recovered member must return to the rotation")
}

// --- lifecycle --------------------------------------------------------------------------

// TestLoadBalanceCloseIsIdempotentAndStopsTheChecker covers the lifecycle debt: start, close,
// close again, and confirm the group no longer answers with a member list or a checker.
func TestLoadBalanceCloseIsIdempotentAndStopsTheChecker(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "https://probe.example/generate_204",
	}, fourMembers()...)

	require.NotNil(t, fixture.group.health.Load())
	require.NoError(t, fixture.group.Close())
	require.NoError(t, fixture.group.Close(), "closing twice must not fail or panic")
	require.Nil(t, fixture.group.health.Load(), "the checker must not outlive the group")
	require.Empty(t, fixture.group.snapshot(), "the member list must be released")
}

// TestLoadBalanceStartAfterCloseRefuses covers the racing teardown: a group that has closed
// must not be brought back to life by a late start.
func TestLoadBalanceStartAfterCloseRefuses(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, fourMembers()...)

	require.NoError(t, fixture.group.Close())
	require.Error(t, fixture.group.Start(adapter.StartStateStart, &adapter.Scope{}))
}

// TestLoadBalanceRepeatedLifecycleDoesNotLeakGoroutines guards the one resource this group
// owns: the health checker it composes.
//
// # Two oracles, because one of them is the real contract
//
// The contract is that the group closes the checker it owns, and that is asserted directly on
// the engine: after Close, the engine must report itself closed. A group that dropped the
// engine instead of closing it would leave a ticker and a context behind for every reload, and
// the direct assertion notices that without depending on how quickly a goroutine is scheduled.
//
// The goroutine count is kept as the second oracle because it measures the consequence rather
// than the call - and it is deliberately tolerant, because a measurement round in flight is a
// goroutine too.
//
// The groups here are started through the STARTED stage AND touched, because the checker's
// background work has two halves that start at different times: the first round starts with the
// group, and the periodic ticker starts when the group is first used. A leak test that only
// started the group would pass on an implementation that never stops the ticker.
func TestLoadBalanceRepeatedLifecycleDoesNotLeakGoroutines(t *testing.T) {
	members := fourMembers()
	options := option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "http://127.0.0.1:1/generate_204",
	}

	// Warm up so one-off runtime goroutines are already running.
	warm := newLoadBalanceFixture(t, options, members...)
	require.NoError(t, warm.group.Start(adapter.StartStateStarted, &adapter.Scope{}))
	warm.group.Touch()
	require.NoError(t, warm.group.Close())

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 25; i++ {
		options.Outbounds = []string{"A", "B", "C", "D"}
		created, err := NewLoadBalance(warm.ctx, nil, log.NewNOPFactory().NewLogger("loadbalance"), "lb", options)
		require.NoError(t, err)
		group := created.(*LoadBalance)
		require.NoError(t, group.Start(adapter.StartStateStart, &adapter.Scope{}))
		engine := group.health.Load()
		require.NotNil(t, engine, "a group with a URL must own a health checker")
		require.NoError(t, group.Start(adapter.StartStateStarted, &adapter.Scope{}))
		// Touch, so the periodic ticker exists before the close has to stop it.
		group.Touch()
		require.NotNil(t, group.SelectForFlow(&adapter.InboundContext{Domain: "example.com"}, N.NetworkTCP, true))

		require.NoError(t, group.Close())
		require.True(t, engine.closed,
			"cycle %d: the group must close the health checker it owns, not merely drop it", i+1)
	}

	time.Sleep(150 * time.Millisecond)
	after := runtime.NumGoroutine()
	require.LessOrEqual(t, after, before+5,
		"25 start/close cycles must not accumulate goroutines; before=%d after=%d", before, after)
}
