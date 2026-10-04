package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A query issued WHILE a network transition is pending must not be cached under the environment it
// was stamped with.
//
// # The three counters that matter, and the fact that there are three
//
//	NetworkManager.networkResetGeneration   the route/dialer epoch, advanced by beginTransition
//	dns.Router.networkGeneration            the DNS epoch, advanced by Router.ResetNetwork
//	Client.environmentPins                  the per-transport environment pin, refreshed by the reset
//
// They are NOT one counter. beginTransition advances only the first. So during a transition that has
// claimed its epoch but has not yet run its reset body, the DNS client sees exactly what it saw
// before: the same DNS generation and the same pin.
//
// # Why the existing guards do not cover this
//
// generationStillCurrent compares the DNS generation, which has not moved.
// finishCacheKey compares environmentHash(transport) - the PIN - against the key, and the pin is
// still A while the key was built from the same pin, so they match.
//
// Both guards therefore agree that the answer belongs to A, even though the transport has re-dialled
// on B and the answer was produced there. The result is an entry that claims to describe network A
// and is served to every later query on A for the rest of its TTL.
//
// # What distinguishes this from the in-flight case
//
// The in-flight case - a query issued BEFORE the transition - is covered by the route epoch, because
// the dial it performs is still owned by the old epoch. This case is different: the query is issued
// AFTER the transition began, so its dial captures the NEW route epoch and is legitimately current by
// the dialer's reckoning. Nothing rejects it, and that is the defect.

// transitionStateManager is a NetworkEnvironment plus the route epoch, so the test can express
// "published B but the transition is still pending" rather than only "B".
type transitionStateManager struct {
	adapter.NetworkManager
	environment atomic.Uint64
	routeEpoch  atomic.Uint64
	// stable mirrors NetworkManager.transitionStable: false while a transition is pending.
	stable atomic.Bool
}

func (m *transitionStateManager) NetworkEnvironment() uint64 { return m.environment.Load() }
func (m *transitionStateManager) NetworkResetGeneration() uint64 {
	return m.routeEpoch.Load()
}
func (m *transitionStateManager) NetworkTransitionStable() bool { return m.stable.Load() }

// rebindingWindowTransport is a transport whose connection can be broken and re-established against
// whichever backend is current, with the same object and the same Tag throughout.
type rebindingWindowTransport struct {
	adapter.DNSTransport
	tag         string
	environment []string

	current func() netip.Addr
	queries int
}

func (t *rebindingWindowTransport) Type() string           { return "rebinding-window" }
func (t *rebindingWindowTransport) Tag() string            { return t.tag }
func (t *rebindingWindowTransport) Dependencies() []string { return nil }
func (t *rebindingWindowTransport) Environment() []string  { return t.environment }
func (t *rebindingWindowTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *rebindingWindowTransport) Close() error { return nil }

// Reset models the pooled connection being invalidated. The object and Tag are untouched, which is
// what makes the next Exchange re-dial.
func (t *rebindingWindowTransport) Reset() {}

func (t *rebindingWindowTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries++
	// The dial happens at query time against whatever backend is current, exactly as production
	// resolves it.
	address := t.current()
	response := new(mDNS.Msg)
	response.SetReply(message)
	if len(message.Question) > 0 {
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA,
				Class: mDNS.ClassINET, Ttl: 300},
			A: address.AsSlice(),
		})
	}
	return response, nil
}

func (t *rebindingWindowTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// newPendingTransitionFixture builds a Router whose DNS generation is wired to the router itself (as
// production does) and whose transport dials whatever backend is current.
func newPendingTransitionFixture(t *testing.T, manager adapter.NetworkManager, transport adapter.DNSTransport) (*Router, *Client) {
	t.Helper()
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
	router, err := NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{})
	require.NoError(t, err)
	concrete, isConcrete := router.client.(*Client)
	require.True(t, isConcrete)
	router.concreteClient = concrete
	concrete.Start()
	concrete.networkManager = manager
	router.transport = &listingTransportManager{
		fakeDNSTransportManager: &fakeDNSTransportManager{
			transports:       map[string]adapter.DNSTransport{transport.Tag(): transport},
			defaultTransport: transport,
		},
		transports: []adapter.DNSTransport{transport},
	}
	return router, concrete
}

// TestDNSQueryStartedDuringPendingTransitionCannotCacheUnderOldEnvironment is the PART B
// reproduction.
//
// The transition has published B and claimed its route epoch, but its reset body has not run: the DNS
// generation is unchanged and the transport is still pinned to A. A query issued now dials B and must
// not be cached as an A answer.
func TestDNSQueryStartedDuringPendingTransitionCannotCacheUnderOldEnvironment(t *testing.T) {
	const (
		envA = 0xA
		envB = 0xB
	)
	backendA := netip.MustParseAddr("10.1.0.1")
	backendB := netip.MustParseAddr("10.2.0.1")
	current := backendA

	manager := &transitionStateManager{}
	manager.environment.Store(envA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "wifi-roaming",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	router, client := newPendingTransitionFixture(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("roam.example.", mDNS.TypeA)
	question := message.Question[0]

	// --- stable A -------------------------------------------------------------
	pinnedA := client.environmentHash(transport)
	require.EqualValues(t, envA, client.transportEnvironment(transport),
		"the transport must start pinned to A, or this test proves nothing")

	// --- the transition begins: publish B, claim the route epoch, DO NOT reset ---
	//
	// This is exactly the state beginTransition leaves behind while it waits for resetRunAccess:
	// NetworkEnvironment() reports B, the route epoch has moved, and nothing in the DNS layer has
	// been touched yet.
	// beginTransition clears stability BEFORE the epoch moves, then the epoch moves. The reset body
	// has not run, so the DNS generation is untouched and the pin still names A.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	dnsGenerationDuring := router.dnsGeneration()

	// --- a NEW query, issued DURING the transition ---------------------------------
	//
	// Its dial runs now, so it reaches B. This is not the in-flight case: the query did not exist
	// before the transition, and its dial is legitimately current by the route epoch.
	current = backendB

	key := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.EqualValues(t, pinnedA, key.environment,
		"the key is stamped from the transport pin, which the reset has not yet refreshed")

	// The query is issued WHILE the transition is pending, so it must not be delivered as a stable
	// result at all - not merely refused a cache write.
	response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.Error(t, err,
		"a query issued during a pending transition was returned as a normal success. The answer "+
			"may well have come from the new network while the key still names the old one, and "+
			"nothing downstream can tell: the pin has not been refreshed and the DNS generation has "+
			"not advanced")
	require.Nil(t, response)

	// The generation the query captured and the generation that is current are the same, because
	// nothing advanced the DNS counter.
	require.EqualValues(t, dnsGenerationDuring, router.dnsGeneration(),
		"the DNS generation has not moved: Router.ResetNetwork has not run")
	require.EqualValues(t, 2, manager.routeEpoch.Load(),
		"the route epoch HAS moved: beginTransition ran")

	// --- the guard ------------------------------------------------------------------
	cached, _, _ := client.loadResponse(key)
	require.Nil(t, cached,
		"an answer produced on network B was cached under network A's namespace. The query was "+
			"issued while the transition was pending, its dial legitimately reached B, and both "+
			"guards agreed it belonged to A - the DNS generation had not advanced (the reset body "+
			"has not run) and the pin still named A. Every later query on A is now served a B answer "+
			"for the rest of its TTL")
}

// TestDNSQueryStartedDuringPendingTransitionIsNotServedToLaterQueries is the consequence, stated
// separately so the impact is not only inferred from the cache key.
func TestDNSQueryStartedDuringPendingTransitionIsNotServedToLaterQueries(t *testing.T) {
	backendA := netip.MustParseAddr("10.1.0.1")
	backendB := netip.MustParseAddr("10.2.0.1")
	current := backendA

	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "served",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("served.example.", mDNS.TypeA)

	manager.stable.Store(false)
	manager.environment.Store(0xB)
	manager.routeEpoch.Add(1)
	current = backendB

	_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.Error(t, err,
		"the query issued during the transition was delivered as a stable result")

	// Nothing was written, so A's namespace cannot hold a B answer.
	key := client.newCacheKey(transport, message.Question[0], message, adapter.DNSQueryOptions{})
	cached, _, _ := client.loadResponse(key)
	require.Nil(t, cached,
		"the B answer was left reachable from A's namespace, so a later query on A is served an "+
			"answer learned on B")
}

// After the transition commits, queries are cached normally again, under the new namespace.
//
// # Why this matters as much as the refusal
//
// A guard that refuses every cache write once a transition has ever happened would "fix" the
// mislabelling by disabling the cache - a silent performance and behaviour change rather than a
// correctness fix. The state must return to settled, and a query issued then must be cached under the
// network it actually used.
func TestDNSQueryAfterTransitionCommitIsCachedUnderTheNewEnvironment(t *testing.T) {
	const (
		envA = 0xA
		envB = 0xB
	)
	current := netip.MustParseAddr("10.1.0.1")

	manager := &transitionStateManager{}
	manager.environment.Store(envA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "committed",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	router, client := newPendingTransitionFixture(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("committed.example.", mDNS.TypeA)
	question := message.Question[0]

	// Settle on A, then transition fully: publish, mark unstable, run the reset body, commit.
	_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	manager.stable.Store(false)
	manager.environment.Store(envB)
	manager.routeEpoch.Add(1)
	current = netip.MustParseAddr("10.2.0.1")
	router.ResetNetwork() // the reset body: advances the DNS generation and re-pins
	manager.stable.Store(true)

	// A query issued now must be cached, under B.
	key := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.EqualValues(t, client.environmentHash(transport), key.environment,
		"the key carries the environment the transport is pinned to")
	require.EqualValues(t, envB, client.transportEnvironment(transport),
		"after the commit the transport is re-pinned to the new network")

	_, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	cached, _, _ := client.loadResponse(key)
	require.NotNil(t, cached,
		"a query issued in a settled state must be cached normally; refusing it would turn this "+
			"fix into a cache outage")
}

// A query issued while a transition is pending must not be served the OLD network's cached answer.
//
// # Why the pin does not protect this
//
// The cache key is built from the transport pin, and the pin is refreshed by the reset body - which
// has not run. So during the transition the pin still names A, the cache key still names A, and the
// entry written while the network was settled on A is an exact hit. The query is answered from a
// network that is being left, and the answer is presented as a normal success.
//
// Refusing only the cache WRITE, which is what the previous round did, does not cover this: the read
// happens first and never consults the transition state at all.
func TestDNSQueryDuringTransitionCannotReadExactCache(t *testing.T) {
	const envA = 0xA
	current := netip.MustParseAddr("10.1.0.1")

	manager := &transitionStateManager{}
	manager.environment.Store(envA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "exact-cache",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)
	require.True(t, client != nil)

	message := new(mDNS.Msg)
	message.SetQuestion("cached.example.", mDNS.TypeA)

	// Settle on A and populate the cache with A's answer.
	first, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Len(t, first.Answer, 1)
	require.Equal(t, "10.1.0.1", first.Answer[0].(*mDNS.A).A.String())
	queriesAfterPopulate := transport.queries
	require.Equal(t, 1, queriesAfterPopulate, "the first query must have gone upstream")

	// The transition begins. The reset body has NOT run, so the pin still names A and the cache entry
	// is still reachable under A's key.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	current = netip.MustParseAddr("10.2.0.1")

	// The same query, DURING the transition.
	_, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)

	require.Error(t, err,
		"the query was answered from the OLD network's cache while a transition was pending. The "+
			"cache key still names A because the pin is refreshed only by the reset body, so the "+
			"stale entry is an exact hit and the answer is delivered as a normal success even though "+
			"the network it describes is being left")
	require.Equal(t, queriesAfterPopulate, transport.queries,
		"and it must not have silently gone upstream instead: the refusal is the point")
}

// The same for the NXDOMAIN cache, which is consulted separately from the exact cache.
func TestDNSQueryDuringTransitionCannotReadNXDOMAIN(t *testing.T) {
	const envA = 0xA

	manager := &transitionStateManager{}
	manager.environment.Store(envA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &nxdomainWindowTransport{
		tag:         "nxdomain-cache",
		environment: []string{"wifi"},
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("absent.example.", mDNS.TypeA)

	// Populate the NXDOMAIN cache while settled.
	first, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, first.Rcode)
	require.Greater(t, transport.queries, 0)

	// Transition pending; the pin and therefore the key still name A.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)

	_, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.Error(t, err,
		"a negative answer learned on the old network was served during a pending transition. "+
			"NXDOMAIN is a statement about a NAME on a specific network, and the network it was "+
			"learned on is being left")
}

// nxdomainWindowTransport answers NXDOMAIN and counts queries.
type nxdomainWindowTransport struct {
	adapter.DNSTransport
	tag         string
	environment []string
	queries     int
}

func (t *nxdomainWindowTransport) Type() string                                   { return "nxdomain-window" }
func (t *nxdomainWindowTransport) Tag() string                                    { return t.tag }
func (t *nxdomainWindowTransport) Dependencies() []string                         { return nil }
func (t *nxdomainWindowTransport) Environment() []string                          { return t.environment }
func (t *nxdomainWindowTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (t *nxdomainWindowTransport) Close() error                                   { return nil }
func (t *nxdomainWindowTransport) Reset()                                         {}

func (t *nxdomainWindowTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries++
	response := new(mDNS.Msg)
	response.SetRcode(message, mDNS.RcodeNameError)
	return response, nil
}

func (t *nxdomainWindowTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// A query that STARTED during a transition must not become valid because the transition committed
// before its response arrived.
//
// # Why the finish-time check is not enough
//
// A commit settles the state without advancing the DNS generation or refreshing the pin. So a query
// issued while the network was unsettled, checked only when its answer arrives, sees a settled
// network, an unchanged generation and its own pin - and is accepted. The answer it carries was
// produced while ownership was unresolved, and its key still names the network being left.
func TestDNSQueryStartedDuringTransitionCannotBecomeValidAfterCommit(t *testing.T) {
	const envA = 0xA
	current := netip.MustParseAddr("10.1.0.1")

	manager := &transitionStateManager{}
	manager.environment.Store(envA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "started-during",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("started.example.", mDNS.TypeA)
	question := message.Question[0]

	// Settle on A so the pin and the cache key name a real network.
	_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	// The settled query wrote an entry under this key; that entry is legitimate and would satisfy the
	// assertion below without proving anything. The DURING query therefore uses a DIFFERENT name, so
	// any entry found under its key can only have come from the query issued during the transition.
	message.SetQuestion("during-only.example.", mDNS.TypeA)
	question = message.Question[0]
	key := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	cachedBefore, _, _ := client.loadResponse(key)
	require.Nil(t, cachedBefore, "the second name must start with no cache entry")

	// The transition begins and the query is issued inside it.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	current = netip.MustParseAddr("10.2.0.1")

	_, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.Error(t, err, "a query issued during the transition was answered")

	// The transition commits BEFORE anything else happens: the generation does not move and the pin
	// is not refreshed by a commit, so a finish-time check alone would now accept the query.
	manager.stable.Store(true)

	cached, _, _ := client.loadResponse(key)
	require.Nil(t, cached,
		"a result from a query issued during the transition became reachable once the transition "+
			"committed. The commit settles the state but does not change the generation or the pin, "+
			"so only the recorded START state can reject it")
}

// DisableCache must not bypass the ownership guard.
//
// Whether a response may be cached and whether it may be trusted are different questions. A caller
// that asks for a fresh answer is still asking for an answer about the CURRENT network, so the
// transition contract applies with or without a cache.
func TestDNSDisableCacheStillRejectsTransitionResult(t *testing.T) {
	const envA = 0xA
	current := netip.MustParseAddr("10.1.0.1")

	manager := &transitionStateManager{}
	manager.environment.Store(envA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "disable-cache",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("nocache.example.", mDNS.TypeA)

	// The transition is pending when the query is issued.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	current = netip.MustParseAddr("10.2.0.1")

	response, err := client.Exchange(context.Background(), transport, message,
		adapter.DNSQueryOptions{DisableCache: true}, nil)
	require.Error(t, err,
		"DisableCache bypassed the transition ownership guard: the query was issued while the "+
			"network was unsettled and was still delivered as a normal success")
	require.Nil(t, response)

	// And once the network settles, the same query succeeds normally.
	manager.stable.Store(true)
	response, err = client.Exchange(context.Background(), transport, message,
		adapter.DNSQueryOptions{DisableCache: true}, nil)
	require.NoError(t, err, "a query in a settled state must succeed")
	require.Len(t, response.Answer, 1)
}
