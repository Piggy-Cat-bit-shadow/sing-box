package dns

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// A DNS-only environment change gets its own generation.
//
// # The defect these pin
//
// Every DNS cache the fork keeps is namespaced by the transport's environment hash - the exact
// entry, the NXDOMAIN verdict, the RDRC namespace and the persistent key all carry it - and that
// hash mixes in the transport's LIVE environment list, so a resolver change separates them without
// any help. The REVERSE MAPPING is the exception: it is guarded only by the network generation
// (`Router.reverseMappingGenerationCurrent`), and that counter advances only in
// `Router.ResetNetwork`.
//
// A DNS server or search domain change on an UNCHANGED interface advances neither the network
// environment fingerprint (`route/network_environment.go` hashes gateways, SSID and gateway
// hardware addresses and nothing else), nor the reset epoch, nor `Router.networkGeneration`. So:
//
//   - a mapping learned through the OLD resolvers stays visible for route-rule matching while the
//     NEW resolvers answer - and with split-horizon or captive-portal DNS the same address can mean
//     a different name, which is the reasoning `Router.ResetNetwork` already gives for purging
//     exactly this cache;
//   - a mapping produced by a request issued under the OLD resolvers is RECORDED, because the
//     captured generation compares equal to the still-current generation.
//
// The fix is an INDEPENDENT DNS environment generation, advanced when - and only when - the
// aggregate DNS environment fingerprint changes. It deliberately does NOT run the network reset
// body: a resolver change is not a network transition, and tearing the transports down for it would
// kill QUIC, H2, MASQUE and voice sessions that are still on the right network.
//
// # What these tests deliberately do NOT assert
//
// They do not assert that a resolver change is a lock/unlock, that it emits a device event, or that
// it pauses anything. It is none of those, and the fix touches none of that machinery.

// mutableEnvironmentTransport is a DNS transport whose published environment - the resolver addresses and
// search domains the platform hands it - can be replaced while queries are in flight.
//
// It is the injectable DNS server / search domain snapshot these tests need. The production local
// transport reads the same thing from the platform (dnsinfo on Darwin, resolv.conf elsewhere); the
// router's job is to notice that the value changed, not to care where it came from.
type mutableEnvironmentTransport struct {
	adapter.DNSTransport
	tag string

	environmentAccess sync.Mutex
	environment       []string

	// resetCount counts Reset() calls, so a test can prove the fix does NOT reset the transports.
	resetCount atomic.Uint64

	address netip.Addr

	// entered and release let a test hold a request inside the transport, so the request is provably
	// in flight across the environment change. blocking selects that behaviour.
	blocking bool
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func newMutableEnvironmentTransport(tag string, environment ...string) *mutableEnvironmentTransport {
	return &mutableEnvironmentTransport{
		tag:         tag,
		environment: environment,
		address:     netip.MustParseAddr("203.0.113.53"),
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (t *mutableEnvironmentTransport) Type() string           { return "environment" }
func (t *mutableEnvironmentTransport) Tag() string            { return t.tag }
func (t *mutableEnvironmentTransport) Dependencies() []string { return nil }
func (t *mutableEnvironmentTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *mutableEnvironmentTransport) Close() error { return nil }
func (t *mutableEnvironmentTransport) Reset()       { t.resetCount.Add(1) }

// Environment reports the resolver addresses and search domains this transport currently serves.
//
// This is the seam the platform reader sits behind: replacing it is what "the DNS servers changed on
// the same interface" means to everything above.
func (t *mutableEnvironmentTransport) Environment() []string {
	t.environmentAccess.Lock()
	defer t.environmentAccess.Unlock()
	return append([]string(nil), t.environment...)
}

// setEnvironment publishes a new resolver list, exactly as the platform reader would after a
// notification.
func (t *mutableEnvironmentTransport) setEnvironment(environment ...string) {
	t.environmentAccess.Lock()
	defer t.environmentAccess.Unlock()
	t.environment = environment
}

func (t *mutableEnvironmentTransport) answer(message *mDNS.Msg) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(message)
	if len(message.Question) > 0 {
		question := message.Question[0]
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
			A:   t.address.AsSlice(),
		})
	}
	return response
}

func (t *mutableEnvironmentTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.blocking {
		t.once.Do(func() { close(t.entered) })
		select {
		case <-t.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return t.answer(message), nil
}

func (t *mutableEnvironmentTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// environmentTransportManager is a transport manager that actually LISTS its transports.
//
// The shared fakeDNSTransportManager returns nil from Transports(), which is fine for a reset (it
// has nothing to reset in those tests) but hides the environment from an aggregate that has to be
// computed over every transport the router knows. This one answers the real question, as
// TransportManager does.
type environmentTransportManager struct {
	transports []adapter.DNSTransport
}

func (m *environmentTransportManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (m *environmentTransportManager) Transports() []adapter.DNSTransport { return m.transports }

func (m *environmentTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	for _, transport := range m.transports {
		if transport.Tag() == tag {
			return transport, true
		}
	}
	return nil, false
}

func (m *environmentTransportManager) Default() adapter.DNSTransport { return nil }
func (m *environmentTransportManager) FakeIP() adapter.FakeIPTransport {
	return nil
}
func (m *environmentTransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

// newRouterForEnvironmentTest builds a Router over the given transports, with the reverse mapping
// enabled, which is the store under test.
func newRouterForEnvironmentTest(t *testing.T, transports ...adapter.DNSTransport) *Router {
	t.Helper()
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()
	router := &Router{
		ctx:       context.Background(),
		logger:    log.NewNOPFactory().Logger(),
		transport: &environmentTransportManager{transports: transports},
		client:    client,
	}
	// The client reads the ROUTER's generation, which is what a reset - or, after the fix, a DNS
	// environment change - advances. Wiring the client to a private counter would let the test
	// advance one and the router read the other, so the guard under test would never see it.
	client.networkGeneration = router.dnsGeneration
	router.dnsReverseMapping = common.Must1(freelru.New[netip.Addr, string](
		1024, maphash.NewHasher[netip.Addr]().Hash32, true))
	return router
}

// exchangeForEnvironmentTest issues one real exchange through the router, which is the observation
// point a resolver change has to be noticed at.
func exchangeForEnvironmentTest(t *testing.T, router *Router, transport adapter.DNSTransport, domain string) {
	t.Helper()
	message := new(mDNS.Msg)
	message.SetQuestion(mDNS.Fqdn(domain), mDNS.TypeA)
	response, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: transport})
	require.NoError(t, err)
	require.NotNil(t, response)
}

// TestDNSOnlyChangeAdvancesTheGeneration is (B): the same interface, only the DNS server list
// genuinely changes.
//
// Old behaviour: `router.dnsGeneration()` does not move, because the only thing that advances it is
// ResetNetwork, and a resolver change on an unchanged interface runs no reset.
func TestDNSOnlyChangeAdvancesTheGeneration(t *testing.T) {
	transport := newMutableEnvironmentTransport("dns-only-servers", "1.1.1.1:53", "1.0.0.1:53")
	router := newRouterForEnvironmentTest(t, transport)

	// The first observation pins the environment without advancing: there is no previous
	// environment for anything to be stale against, and the initial epoch must not depend on
	// whether a query happened to be issued before the first one.
	exchangeForEnvironmentTest(t, router, transport, "first.example")
	require.EqualValues(t, 0, router.dnsGeneration(),
		"the first observation of the DNS environment must PIN it, not advance the epoch: "+
			"otherwise the initial epoch depends on whether a query was issued first")

	// (B) same interface, only the resolver list changes.
	transport.setEnvironment("9.9.9.9:53")
	exchangeForEnvironmentTest(t, router, transport, "second.example")

	require.EqualValues(t, 1, router.dnsGeneration(),
		"a DNS server change on an UNCHANGED interface advanced nothing. Every DNS cache except the "+
			"reverse mapping is namespaced by the transport environment hash and separates itself, "+
			"but the reverse mapping is guarded only by this generation - so a mapping learned "+
			"through the old resolvers stays visible to route rule matching while the new resolvers "+
			"answer, and with split-horizon DNS the same address can mean a different name")
}

// TestDNSOnlySearchDomainChangeAdvancesTheGeneration is (C).
func TestDNSOnlySearchDomainChangeAdvancesTheGeneration(t *testing.T) {
	transport := newMutableEnvironmentTransport("dns-only-search", "1.1.1.1:53", "corp.example.")
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "first.example")
	require.EqualValues(t, 0, router.dnsGeneration())

	transport.setEnvironment("1.1.1.1:53", "other.example.")
	exchangeForEnvironmentTest(t, router, transport, "second.example")

	require.EqualValues(t, 1, router.dnsGeneration(),
		"a search domain change on an unchanged interface advances nothing, so a name resolved "+
			"through the old search list is indistinguishable from one resolved through the new one")
}

// TestReverseMappingFromThePreviousDNSEnvironmentIsNotReused is the user-visible consequence: a
// mapping produced by a request issued under the OLD resolvers must not be recorded once the
// resolvers have changed.
func TestReverseMappingFromThePreviousDNSEnvironmentIsNotReused(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.201")
	pinned := newMutableEnvironmentTransport("dns-only-stale-pin", "1.1.1.1:53")
	pinned.address = address
	transport := newMutableEnvironmentTransport("dns-only-stale", "1.1.1.1:53")
	transport.blocking = true
	transport.address = address
	router := newRouterForEnvironmentTest(t, pinned, transport)

	// Establish the environment first, so the change below is a genuine change and not the pin.
	exchangeForEnvironmentTest(t, router, pinned, "pin.example")
	require.EqualValues(t, 0, router.dnsGeneration())

	message := new(mDNS.Msg)
	message.SetQuestion("stale-dns.example.", mDNS.TypeA)
	done := make(chan error, 1)
	go func() {
		_, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: transport})
		done <- err
	}()

	// Barrier: the request is genuinely inside the transport, issued under the OLD resolver list.
	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the transport")
	}

	// The resolvers change on the SAME interface while the request is in flight.
	transport.setEnvironment("9.9.9.9:53")

	close(transport.release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the exchange never returned")
	}

	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded,
		"a mapping produced by a request issued under the previous resolver list was recorded "+
			"after the resolvers changed. The captured generation still compared equal, because "+
			"nothing advances it for a DNS-only change - so the mapping describes a name learned "+
			"from resolvers the device is no longer using")
}

// TestDuplicateDNSEnvironmentNotificationDoesNotAdvanceWithoutBound is (D).
//
// A platform notification is not a state change: the same information can be delivered repeatedly,
// and notify_check documents false positives for notify_register_check tokens. Re-observing an
// unchanged environment must cost nothing.
func TestDuplicateDNSEnvironmentNotificationDoesNotAdvanceWithoutBound(t *testing.T) {
	transport := newMutableEnvironmentTransport("dns-only-duplicate", "1.1.1.1:53")
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "pin.example")
	require.EqualValues(t, 0, router.dnsGeneration())

	// One genuine change.
	transport.setEnvironment("9.9.9.9:53")
	exchangeForEnvironmentTest(t, router, transport, "change.example")
	require.EqualValues(t, 1, router.dnsGeneration())

	// Then a burst of duplicate notifications carrying the same information.
	for i := range 64 {
		exchangeForEnvironmentTest(t, router, transport, fmt.Sprintf("duplicate-%d.example", i))
	}
	require.EqualValues(t, 1, router.dnsGeneration(),
		"64 duplicate notifications advanced the epoch again. Each advancement is a full barrier "+
			"that discards what is in flight, so an un-debounced notification path is a reset storm "+
			"driven by the platform's own repetition")
}

// TestReorderedSearchDomainsAdvanceOnce is the (C) edge case the order names: search domains equal
// but reordered.
//
// Reordering is NOT a duplicate. The search list is tried in order by Config.NameList, so a
// reordered list is a different resolution order and can produce a different answer. It must
// advance - once, and then de-bounce.
func TestReorderedSearchDomainsAdvanceOnce(t *testing.T) {
	transport := newMutableEnvironmentTransport("dns-only-reorder", "1.1.1.1:53", "a.example.", "b.example.")
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "pin.example")
	require.EqualValues(t, 0, router.dnsGeneration())

	transport.setEnvironment("1.1.1.1:53", "b.example.", "a.example.")
	exchangeForEnvironmentTest(t, router, transport, "reorder.example")
	require.EqualValues(t, 1, router.dnsGeneration(),
		"a reordered search list changes which suffix is tried first, so it is a real environment "+
			"change rather than a duplicate notification")

	for i := range 16 {
		exchangeForEnvironmentTest(t, router, transport, fmt.Sprintf("reorder-repeat-%d.example", i))
	}
	require.EqualValues(t, 1, router.dnsGeneration())
}

// TestEmptyThenRecoveredDNSEnvironmentIsBounded is (E): a temporary empty list, then recovery.
//
// The generation is an epoch, not a state, so it cannot go back. What must hold is that the
// transition is BOUNDED - one advancement each way, not one per observation.
func TestEmptyThenRecoveredDNSEnvironmentIsBounded(t *testing.T) {
	transport := newMutableEnvironmentTransport("dns-only-empty", "1.1.1.1:53")
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "pin.example")
	require.EqualValues(t, 0, router.dnsGeneration())

	// The platform momentarily reports no resolver at all (DHCP renewal, VPN re-negotiating DNS).
	transport.setEnvironment()
	for i := range 8 {
		exchangeForEnvironmentTest(t, router, transport, fmt.Sprintf("empty-%d.example", i))
	}
	require.EqualValues(t, 1, router.dnsGeneration(), "the empty list is one transition, not eight")

	// Recovery to the original list is a second, equally bounded transition.
	transport.setEnvironment("1.1.1.1:53")
	for i := range 8 {
		exchangeForEnvironmentTest(t, router, transport, fmt.Sprintf("recovered-%d.example", i))
	}
	require.EqualValues(t, 2, router.dnsGeneration(), "and recovery is the second, not the ninth")
}

// TestDNSOnlyChangeDoesNotResetTransports is the constraint that makes this fix usable at all.
//
// A resolver change is not a network transition. Running the network reset body - or even the
// transports' own Reset - for it would tear down sessions that are still on the right network.
func TestDNSOnlyChangeDoesNotResetTransports(t *testing.T) {
	transport := newMutableEnvironmentTransport("dns-only-noreset", "1.1.1.1:53")
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "pin.example")
	require.EqualValues(t, 0, transport.resetCount.Load())

	for i := range 4 {
		transport.setEnvironment(fmt.Sprintf("9.9.9.%d:53", i+1))
		exchangeForEnvironmentTest(t, router, transport, fmt.Sprintf("change-%d.example", i))
	}

	require.EqualValues(t, 0, transport.resetCount.Load(),
		"a DNS-only environment change reset the DNS transports. There is nothing wrong with the "+
			"sockets: the resolvers changed, the network did not")
}

// TestDNSEnvironmentChangeIsRaceFree drives the change concurrently with many in-flight queries.
//
// The epoch and the fingerprint are two words that must move together, and every observation of the
// generation has to see both. Run under -race, this is where a torn update shows up.
//
// Each flip is observed by the sequential driver as well as by the concurrent queries, so the
// advanced count is deterministic: a value that has been observed once cannot advance the epoch a
// second time, whoever observed it.
func TestDNSEnvironmentChangeIsRaceFree(t *testing.T) {
	pinned := newMutableEnvironmentTransport("dns-only-race-pin", "1.1.1.1:53")
	flapping := newMutableEnvironmentTransport("dns-only-race", "1.1.1.1:53")
	router := newRouterForEnvironmentTest(t, pinned, flapping)

	exchangeForEnvironmentTest(t, router, pinned, "pin.example")
	require.EqualValues(t, 0, router.dnsGeneration())

	const flips = 24
	const concurrentQueries = 8

	var waitGroup sync.WaitGroup
	stop := make(chan struct{})
	for range concurrentQueries {
		waitGroup.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				message := new(mDNS.Msg)
				message.SetQuestion("concurrent.example.", mDNS.TypeA)
				_, _ = router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: pinned})
			}
		})
	}

	for i := range flips {
		flapping.setEnvironment(fmt.Sprintf("198.51.100.%d:53", i+1))
		require.EqualValues(t, i+1, router.dnsGeneration(),
			"each genuine DNS environment change must advance the epoch exactly once, no matter how "+
				"many queries are observing it concurrently")
	}
	close(stop)
	waitGroup.Wait()

	require.EqualValues(t, flips, router.dnsGeneration())
}
