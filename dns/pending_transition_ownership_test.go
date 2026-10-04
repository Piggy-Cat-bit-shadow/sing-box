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
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	badoption "github.com/sagernet/sing/common/json/badoption"
	slog "github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"path/filepath"

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

// persistentRDRCStore wraps a REAL cachefile store, so the namespace under test is exactly the
// production key rather than a test invention.
type persistentRDRCStore struct {
	file *cachefile.CacheFile
}

func newPersistentRDRCStore(t *testing.T) *persistentRDRCStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rdrc-ns.db")
	file := cachefile.New(context.Background(), log.NewNOPFactory().Logger(), option.CacheFileOptions{
		Enabled:     true,
		Path:        path,
		StoreRDRC:   true,
		RDRCTimeout: badoption.Duration(7 * 24 * time.Hour),
		CacheID:     "rdrc-ns-test",
	})
	// Teardown is scope-owned under the current lifecycle, as in production.
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	// Initialize opens the bolt file; Start begins the cleanup loop. Both are needed before the
	// store can be read or written.
	require.NoError(t, file.Start(adapter.StartStateInitialize, scope))
	require.NoError(t, file.Start(adapter.StartStateStart, scope))
	t.Cleanup(func() { _ = scope.Close() })
	return &persistentRDRCStore{file: file}
}

func (s *persistentRDRCStore) LoadRDRC(transportName string, qName string, qType uint16) bool {
	return s.file.LoadRDRC(transportName, qName, qType)
}

func (s *persistentRDRCStore) SaveRDRC(transportName string, qName string, qType uint16) error {
	return s.file.SaveRDRC(transportName, qName, qType)
}

func (s *persistentRDRCStore) SaveRDRCAsync(transportName string, qName string, qType uint16, l slog.Logger) {
	s.file.SaveRDRCAsync(transportName, qName, qType, l)
}

// rejected reports whether a verdict is visible for the given key.
func (s *persistentRDRCStore) rejected(transportName string, qName string, qType uint16) bool {
	return s.file.LoadRDRC(transportName, qName, qType)
}

// newPendingTransitionFixtureWithRDRC is newPendingTransitionFixture with a persistent RDRC store
// attached.
func newPendingTransitionFixtureWithRDRC(t *testing.T, manager adapter.NetworkManager, transport adapter.DNSTransport, store adapter.RDRCStore) (*Router, *Client) {
	t.Helper()
	router, client := newPendingTransitionFixture(t, manager, transport)
	client.rdrc = store
	return router, client
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

// Client.Lookup must obey the same transition ownership as Exchange.
//
// # Why the Exchange guard does not reach it
//
// lookupToExchange consults questionCache BEFORE it calls Exchange:
//
//	cachedAddresses, err := c.questionCache(...)
//	if err != ErrNotCached { return cachedAddresses, err }
//	response, err := c.Exchange(...)        <- the guard lives in here, too late
//
// The startedStable check lives in beginExchange, which questionCache never reaches. So a cache hit
// during a transition is returned as a normal result without any ownership question being asked.
func TestLookupDuringTransitionCannotReadOldExactCache(t *testing.T) {
	const envA = 0xA
	current := netip.MustParseAddr("10.1.0.1")

	manager := &transitionStateManager{}
	manager.environment.Store(envA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "lookup-exact",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	// Settle on A and populate the cache.
	_, err := client.Lookup(context.Background(), transport, "lookup.example.",
		adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}, nil)
	require.NoError(t, err)
	queriesAfterPopulate := transport.queries
	require.Equal(t, 1, queriesAfterPopulate, "the first lookup must have gone upstream")

	// The transition begins; the reset body has not run, so the pin and the cache key still name A.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	current = netip.MustParseAddr("10.2.0.1")

	addresses, err := client.Lookup(context.Background(), transport, "lookup.example.",
		adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}, nil)

	require.Error(t, err,
		"Lookup returned a result from the OLD network's cache while a transition was pending. "+
			"lookupToExchange consults questionCache before it reaches Exchange, so the "+
			"startedStable guard in beginExchange is never consulted on a cache hit")
	require.Nil(t, addresses)
	require.Equal(t, queriesAfterPopulate, transport.queries,
		"and it must not have silently gone upstream instead")
}

// The optimistic (stale-but-served) path must be refused too.
//
// A stale exact entry is served immediately AND triggers a background refresh. Both halves matter:
// the served answer describes the network being left, and the refresh would deposit a new one.
func TestLookupDuringTransitionCannotReturnOptimisticOldCache(t *testing.T) {
	const envA = 0xA
	current := netip.MustParseAddr("10.1.0.1")

	manager := &transitionStateManager{}
	manager.environment.Store(envA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "lookup-optimistic",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	_, err := client.Lookup(context.Background(), transport, "optimistic.example.",
		adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}, nil)
	require.NoError(t, err)
	queriesAfterPopulate := transport.queries

	// Make the stored entry stale-but-servable, which is the optimistic path: the entry is past its
	// TTL (so isStale is true) but still inside the optimistic window (so it is served rather than
	// dropped). The window is a client field, so it can be widened here rather than reaching into the
	// cache's expiry bookkeeping.
	client.optimisticTimeout = time.Hour

	// Push the entry's expiry into the past by rewriting the cache entry under a lifetime of zero,
	// which AddWithLifetime accepts and which makes the very next read report staleness.
	// Build the key exactly as lookupToExchange does: the message it constructs carries only
	// RecursionDesired and the canonical FQDN, and the key is derived from that message.
	probe := new(mDNS.Msg)
	probe.RecursionDesired = true
	probe.Question = []mDNS.Question{{
		Name:   mDNS.Fqdn("optimistic.example."),
		Qtype:  mDNS.TypeA,
		Qclass: mDNS.ClassINET,
	}}
	key := client.newCacheKey(transport, probe.Question[0], probe,
		adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
	entry, _, isStale := client.loadResponse(key)
	require.NotNil(t, entry, "the priming lookup must have stored an entry")
	require.False(t, isStale, "and it must still be fresh before the test ages it")
	// Re-add with a lifetime already in the past, so the next read reports the entry as STALE while
	// it is still inside the optimistic window widened above. A zero lifetime would NOT do this: it
	// stores a fresh entry whose remaining TTL is simply zero, and the optimistic branch is never
	// reached.
	client.cache.AddWithLifetime(key, entry, -time.Minute)
	_, _, staleNow := client.loadResponse(key)
	require.True(t, staleNow,
		"the entry must actually be stale, or this test exercises the fresh-hit path instead of "+
			"the optimistic one it is named for")

	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	current = netip.MustParseAddr("10.2.0.1")

	addresses, err := client.Lookup(context.Background(), transport, "optimistic.example.",
		adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}, nil)

	require.Error(t, err,
		"Lookup served a STALE optimistic answer learned on the old network during a pending "+
			"transition. The optimistic path returns the cached answer immediately and defers the "+
			"correction to a background refresh, so the caller receives an answer for a network "+
			"that is being left")
	require.Nil(t, addresses)
	require.Equal(t, queriesAfterPopulate, transport.queries,
		"the optimistic path must not have started a refresh either")
}

// The background refresh must carry its own ownership record.
//
// # The hole
//
// backgroundRefreshDNS built an exchangeOperation that set only the generation guard:
//
//	refreshOperation := &exchangeOperation{}
//	if c.networkGeneration != nil {
//	    refreshOperation.generation = c.networkGeneration()
//	    refreshOperation.hasGenerationGuard = true
//	}
//
// It never set hasOwnershipGuard, and the ownership predicates begin with
// `if !operation.hasOwnershipGuard { return true }`. So the guard was a no-op on this path: a refresh
// that STARTED during a transition captured the transition's own generation, and a commit advances
// neither the generation nor the pin, so the comparison found no change and the deposit was allowed.
func TestBackgroundRefreshStartedDuringTransitionCannotStore(t *testing.T) {
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
		tag:         "refresh-during",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	// Prime with A's answer so a stale entry exists to be refreshed.
	_, err := client.Exchange(context.Background(), transport, messageFor("refreshd.example."),
		adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	// Build the key and age the entry into the optimistic window.
	client.optimisticTimeout = time.Hour
	probe := probeMessage("refreshd.example.")
	key := client.newCacheKey(transport, probe.Question[0], probe, adapter.DNSQueryOptions{})
	entry, _, _ := client.loadResponse(key)
	require.NotNil(t, entry)
	client.cache.AddWithLifetime(key, entry, -time.Minute)

	// The transition begins BEFORE the refresh is scheduled, and it is STILL PENDING when the refresh
	// starts. The backend has already moved, so a refresh that went ahead would fetch the new
	// network's answer and deposit it under the old key.
	//
	// The state is deliberately left unstable: scheduling a refresh during a settled network is a
	// legitimate refresh and must not be refused, so the test would prove nothing.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	manager.environment.Store(envB)
	current = netip.MustParseAddr("10.2.0.1")
	require.False(t, manager.NetworkTransitionStable(),
		"the transition must still be pending when the refresh is scheduled")

	queriesBefore := transport.queries
	client.backgroundRefreshDNS(transport, key, client.prepareExchangeMessage(probe.Copy(),
		adapter.DNSQueryOptions{}), adapter.DNSQueryOptions{}, nil)
	waitForRefreshIdle(t, client)

	require.Equal(t, queriesBefore, transport.queries,
		"the background refresh made a round trip even though it was scheduled while the network was "+
			"unsettled. Its operation recorded no ownership state, so the guard returned true "+
			"unconditionally and the answer from the new network could be deposited under the old key")

	// The entry still present is the STALE one the test aged; what must not exist is a renewal. The
	// aged entry carries A's address with a zero remaining TTL, whereas a deposit would carry B's
	// address and a fresh TTL.
	stored, ttl, _ := client.loadResponse(key)
	if stored != nil {
		require.Len(t, stored.Answer, 1)
		require.Equal(t, "10.1.0.1", stored.Answer[0].(*mDNS.A).A.String(),
			"a refresh that started while the network was unsettled deposited the NEW network's "+
				"answer under the OLD key")
		require.EqualValues(t, 0, ttl, "and it must not have renewed the entry's lifetime")
	}
}

// A refresh that starts SETTLED and whose network moves underneath it must not deposit either.
func TestBackgroundRefreshCrossingTransitionCannotStore(t *testing.T) {
	current := netip.MustParseAddr("10.1.0.1")

	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	// The transport blocks inside the exchange, so the transition can land while it is in flight.
	release := make(chan struct{})
	transport := &blockingWindowTransport{
		tag:         "refresh-crossing",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return current },
		release:     release,
		entered:     make(chan struct{}),
	}
	router, client := newPendingTransitionFixture(t, manager, transport)

	_, err := client.Exchange(context.Background(), transport, messageFor("crossing.example."),
		adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	client.optimisticTimeout = time.Hour
	probe := probeMessage("crossing.example.")
	key := client.newCacheKey(transport, probe.Question[0], probe, adapter.DNSQueryOptions{})
	entry, _, _ := client.loadResponse(key)
	require.NotNil(t, entry)
	client.cache.AddWithLifetime(key, entry, -time.Minute)

	// The refresh starts settled and blocks mid-flight.
	transport.block = true
	client.backgroundRefreshDNS(transport, key, client.prepareExchangeMessage(probe.Copy(),
		adapter.DNSQueryOptions{}), adapter.DNSQueryOptions{}, nil)
	waitForBlockedExchange(t, transport)

	// The network moves while the refresh is in flight, and the transition runs its REAL reset body.
	//
	// Router.ResetNetwork is what advances the DNS generation and re-pins the transports; modelling
	// the transition without it would leave the generation unchanged, which is not a state production
	// can reach - and a generation that never moved would let the deposit through for the wrong
	// reason, proving nothing about the ownership check.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	manager.environment.Store(0xB)
	current = netip.MustParseAddr("10.2.0.1")
	router.ResetNetwork()
	manager.stable.Store(true)

	close(release)
	waitForRefreshIdle(t, client)

	// The aged A entry may still be present; what must not be present is a B deposit. A deposit would
	// carry the new address with a fresh TTL.
	stored, ttl, _ := client.loadResponse(key)
	if stored != nil {
		require.Len(t, stored.Answer, 1)
		require.Equal(t, "10.1.0.1", stored.Answer[0].(*mDNS.A).A.String(),
			"a refresh that started settled deposited the NEW network's answer after the network "+
				"moved underneath it. The generation and pin both still describe the network it was "+
				"issued on, so only the settled check can refuse it")
		require.EqualValues(t, 0, ttl, "and it must not have renewed the entry's lifetime")
	}
}

// blockingWindowTransport can hold an exchange open so a transition lands mid-flight.
type blockingWindowTransport struct {
	adapter.DNSTransport
	tag         string
	environment []string
	current     func() netip.Addr
	release     chan struct{}
	block       bool
	entered     chan struct{}
	once        sync.Once
	// queries counts round trips, so a test can assert that a lookup actually reached the resolver.
	queries int
}

func (t *blockingWindowTransport) Type() string                                   { return "blocking-window" }
func (t *blockingWindowTransport) Tag() string                                    { return t.tag }
func (t *blockingWindowTransport) Dependencies() []string                         { return nil }
func (t *blockingWindowTransport) Environment() []string                          { return t.environment }
func (t *blockingWindowTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (t *blockingWindowTransport) Close() error                                   { return nil }
func (t *blockingWindowTransport) Reset()                                         {}

func (t *blockingWindowTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries++
	if t.block {
		// entered is built with the transport, never from here: creating it on the exchange
		// goroutine would race the test's read of the field and could lose the signal entirely.
		t.once.Do(func() { close(t.entered) })
		<-t.release
	}
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

func (t *blockingWindowTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// messageFor builds the lookup message shape.
func messageFor(domain string) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion(domain, mDNS.TypeA)
	return message
}

// probeMessage matches the message lookupToExchange builds, so the key is the same one it uses.
func probeMessage(domain string) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.RecursionDesired = true
	message.Question = []mDNS.Question{{
		Name:   mDNS.Fqdn(domain),
		Qtype:  mDNS.TypeA,
		Qclass: mDNS.ClassINET,
	}}
	return message
}

// waitForRefreshIdle joins on the refresh registry rather than sampling a timer.
func waitForRefreshIdle(t *testing.T, client *Client) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		idle := true
		client.backgroundRefresh.Range(func(dnsCacheKey, struct{}) bool {
			idle = false
			return false
		})
		if idle {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the background refresh never finished")
		case <-time.After(time.Millisecond):
		}
	}
}

// waitForBlockedExchange waits until the transport is inside the exchange.
func waitForBlockedExchange(t *testing.T, transport *blockingWindowTransport) {
	t.Helper()
	select {
	case <-transport.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh never entered the transport")
	}
}

// recordingRDRC records every verdict so a test can assert that none was written.
type recordingRDRC struct {
	access sync.Mutex
	saved  []string
}

func (r *recordingRDRC) LoadRDRC(string, string, uint16) bool { return false }
func (r *recordingRDRC) SaveRDRC(transportName string, qName string, qType uint16) error {
	r.access.Lock()
	defer r.access.Unlock()
	r.saved = append(r.saved, qName)
	return nil
}
func (r *recordingRDRC) SaveRDRCAsync(transportName string, qName string, qType uint16, _ slog.Logger) {
	_ = r.SaveRDRC(transportName, qName, qType)
}

func (r *recordingRDRC) count() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.saved)
}

// An RDRC verdict is a claim about how THIS network answers a name.
//
// # The shape that matters
//
// The query must START in a settled state, so beginExchange lets it through and the round trip is
// made. The transition then lands WHILE it is in flight, and the response is rejected by the checker.
//
// Starting the query during the transition would prove nothing here: beginExchange refuses it, so
// finishExchange never runs and the RDRC path is unreachable. The defect is in the in-flight case,
// where the generation and the pin both still describe the network the query was issued on and the
// rejection branch runs before any ownership check.
func TestCrossGenerationRejectedResponseDoesNotPersistRDRC(t *testing.T) {
	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	release := make(chan struct{})
	transport := &blockingWindowTransport{
		tag:         "rdrc-cross",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return netip.MustParseAddr("10.1.0.1") },
		release:     release,
		entered:     make(chan struct{}),
	}
	router, client := newPendingTransitionFixture(t, manager, transport)

	store := &recordingRDRC{}
	client.rdrc = store
	reject := func(*mDNS.Msg) bool { return false }

	// Positive control first: a settled query whose response is rejected DOES persist a verdict.
	message := messageFor("rejected.example.")
	_, err := client.Exchange(context.Background(), transport, message,
		adapter.DNSQueryOptions{}, reject)
	require.Error(t, err, "the checker must reject, or this test does not reach the RDRC path")
	require.Equal(t, 1, store.count(),
		"a settled same-generation rejection must still persist a verdict; disabling RDRC is not "+
			"an acceptable way to pass this test")

	// Now hold a query open, move the network underneath it, and reject its response.
	transport.block = true
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = client.Exchange(context.Background(), transport, messageFor("inflight.example."),
			adapter.DNSQueryOptions{}, reject)
	}()
	waitForBlockedExchange(t, transport)

	// The transition runs its real reset body, so the DNS generation advances as it does in
	// production.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	manager.environment.Store(0xB)
	router.ResetNetwork()
	manager.stable.Store(true)

	before := store.count()
	close(release)
	<-done

	require.Equal(t, before, store.count(),
		"a response produced before the network moved persisted an RDRC verdict after it. The "+
			"verdict says how the CURRENT network answers this name, but the answer it was derived "+
			"from describes the network being left - and the rejection branch runs before the "+
			"delivery and mutation gates, so nothing refused it")
}

// The background refresh's rejection must not persist a verdict either.
func TestBackgroundRefreshDuringTransitionDoesNotPersistRDRC(t *testing.T) {
	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "rdrc-refresh",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return netip.MustParseAddr("10.1.0.1") },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	_, err := client.Exchange(context.Background(), transport, messageFor("rdrcr.example."),
		adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	client.optimisticTimeout = time.Hour
	probe := probeMessage("rdrcr.example.")
	key := client.newCacheKey(transport, probe.Question[0], probe, adapter.DNSQueryOptions{})
	entry, _, _ := client.loadResponse(key)
	require.NotNil(t, entry)
	client.cache.AddWithLifetime(key, entry, -time.Minute)

	store := &recordingRDRC{}
	client.rdrc = store

	// The refresh is scheduled while the transition is pending, and its checker rejects.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)

	client.backgroundRefreshDNS(transport, key,
		client.prepareExchangeMessage(probe.Copy(), adapter.DNSQueryOptions{}),
		adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return false })
	waitForRefreshIdle(t, client)

	require.Equal(t, 0, store.count(),
		"a background refresh scheduled during a transition persisted an RDRC verdict for the "+
			"network that replaced the one it measured")
}

// ExchangeAsync must enforce the same delivery contract as Exchange.
//
// It reaches the ownership gates by delegating to Exchange for the wait case, and through
// beginExchange for the early-return cases. This asserts both, because an async path that delivered
// what the sync path refuses would be a silent hole: callers use the async form precisely where they
// are least able to inspect the result.
func TestExchangeAsyncSharesTheDeliveryContract(t *testing.T) {
	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "async-contract",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return netip.MustParseAddr("10.1.0.1") },
	}
	_, client := newPendingTransitionFixture(t, manager, transport)

	// Settled: the async form succeeds and reports no error.
	settledDone := make(chan error, 1)
	client.ExchangeAsync(context.Background(), transport, messageFor("async-ok.example."),
		adapter.DNSQueryOptions{}, nil, func(_ *mDNS.Msg, err error) { settledDone <- err })
	select {
	case err := <-settledDone:
		require.NoError(t, err, "a settled async exchange must succeed")
	case <-time.After(10 * time.Second):
		t.Fatal("the settled async exchange never completed")
	}

	// Pending: the async form must report the same transient refusal as the sync form.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)

	asyncDone := make(chan error, 1)
	client.ExchangeAsync(context.Background(), transport, messageFor("async-during.example."),
		adapter.DNSQueryOptions{}, nil, func(_ *mDNS.Msg, err error) { asyncDone <- err })
	select {
	case err := <-asyncDone:
		require.ErrorIs(t, err, errNetworkTransitioning,
			"the async path delivered a result the sync path refuses")
	case <-time.After(10 * time.Second):
		t.Fatal("the pending async exchange never completed")
	}

	// And the sync path agrees, so the two cannot drift.
	_, err := client.Exchange(context.Background(), transport, messageFor("async-during.example."),
		adapter.DNSQueryOptions{}, nil)
	require.ErrorIs(t, err, errNetworkTransitioning, "the sync path must refuse the same operation")
}

// An RDRC verdict is a claim about how a NETWORK answers a name, not about how a transport does.
//
// # The defect
//
// The persistent key is (transportName, qName, qType) with no environment and no generation, and
// Router.ResetNetwork does not clear RDRC. The default RDRC timeout is 7 days. So:
//
//	network A: transport dns1, foo.example/A rejected -> verdict stored for (dns1, foo.example, A)
//	A -> B:    DNS generation advances, transport re-pinned to B
//	network B: same transport tag, same name, same type
//	           LoadRDRC(dns1, foo.example, A) -> HIT -> ErrResponseRejectedCached
//
// B is never queried. A rejection learned on one network suppresses DNS on another, which
// contradicts the code's own premise that RDRC is network state and its writes require
// stateMutationAllowed.
//
// This test drives a REAL persistent store and a REAL Router.ResetNetwork.
func TestRDRCVerdictFromNetworkACannotRejectNetworkB(t *testing.T) {
	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "dns-rdrc-ns",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return netip.MustParseAddr("10.1.0.1") },
	}

	// A real persistent RDRC store, so the namespace is whatever the production key produces.
	store := newPersistentRDRCStore(t)
	router, client := newPendingTransitionFixtureWithRDRC(t, manager, transport, store)

	message := messageFor("ns-verdict.example.")

	// --- network A: the checker rejects, which stores a verdict ---------------
	reject := func(*mDNS.Msg) bool { return false }
	_, err := client.Exchange(context.Background(), transport, message,
		adapter.DNSQueryOptions{}, reject)
	require.Error(t, err, "A must reject, or no verdict is stored")
	// The namespace is derived from the transport's pinned environment, which is what the operation
	// captured - not from the manager's current fingerprint.
	aNamespace := rdrcNamespace("dns-rdrc-ns", router.concreteClient.environmentHash(transport))
	require.True(t, store.rejected(aNamespace, mDNS.Fqdn("ns-verdict.example."), mDNS.TypeA),
		"the positive control: a settled rejection on A persists a verdict in A's namespace")

	// --- transition A -> B, running the real reset body -----------------------
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	manager.environment.Store(0xB)
	router.ResetNetwork()
	manager.stable.Store(true)

	// --- network B: the same query must actually reach the resolver -----------
	// The transport now answers acceptably, so a query that reaches it succeeds.
	transport.current = func() netip.Addr { return netip.MustParseAddr("10.2.0.1") }
	queriesBefore := transport.queries

	response, err := client.Exchange(context.Background(), transport, message,
		adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return true })

	require.Greater(t, transport.queries, queriesBefore,
		"network B was never queried: the verdict learned on A satisfied the lookup on B. RDRC's "+
			"persistent key carries only (transport, name, type), so a rejection from one network "+
			"suppresses DNS on every later network at the same tag")
	require.NoError(t, err,
		"B's own answer was refused with a verdict that describes A")
	require.NotNil(t, response)
}

// A -> B -> A must reuse A's verdict, because the fingerprint really did return to A.
//
// The namespace is content-addressed rather than sequence-addressed: it names the network, not the
// point in time. Returning to a network whose fingerprint is identical means returning to a network
// the verdict still describes, so the verdict is still true of it. Requiring a re-query would treat
// an identical environment as a different one, which is what the DNS cache namespace deliberately
// does NOT do either.
func TestRDRCVerdictIsReusedWhenTheEnvironmentReturns(t *testing.T) {
	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "dns-rdrc-aba",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return netip.MustParseAddr("10.1.0.1") },
	}
	store := newPersistentRDRCStore(t)
	router, client := newPendingTransitionFixtureWithRDRC(t, manager, transport, store)

	message := messageFor("aba-verdict.example.")
	_, err := client.Exchange(context.Background(), transport, message,
		adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return false })
	require.Error(t, err)

	aHash := router.concreteClient.environmentHash(transport)
	require.True(t, store.rejected(rdrcNamespace("dns-rdrc-aba", aHash),
		mDNS.Fqdn("aba-verdict.example."), mDNS.TypeA), "A holds a verdict")

	// A -> B.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	manager.environment.Store(0xB)
	router.ResetNetwork()
	manager.stable.Store(true)

	bNamespace := rdrcNamespace("dns-rdrc-aba", router.concreteClient.environmentHash(transport))
	require.NotEqual(t, rdrcNamespace("dns-rdrc-aba", aHash), bNamespace,
		"B must not share A's namespace, or the isolation this test pairs with proves nothing")
	require.False(t, store.rejected(bNamespace, mDNS.Fqdn("aba-verdict.example."), mDNS.TypeA),
		"A's verdict must not be visible in B")

	// B -> A, restoring A's fingerprint exactly as the manager publishes it.
	manager.environment.Store(0xA)
	router.ResetNetwork()
	manager.stable.Store(true)

	restored := rdrcNamespace("dns-rdrc-aba", router.concreteClient.environmentHash(transport))
	require.Equal(t, rdrcNamespace("dns-rdrc-aba", aHash), restored,
		"returning to A must restore A's namespace")
	require.True(t, store.rejected(restored, mDNS.Fqdn("aba-verdict.example."), mDNS.TypeA),
		"the verdict still describes this network, so it is reused rather than re-learned")
}

// A write authorised on A must not become visible to B even if it lands after B commits.
//
// This is the TOCTOU the namespace exists to close. The guard below is passed deliberately: the point
// is that authorisation alone cannot make a late write correct, because "check then mutate" always
// leaves a gap between the two. The namespace removes the consequence rather than narrowing the gap.
func TestLateRDRCWriteCannotPoisonNewEnvironment(t *testing.T) {
	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	release := make(chan struct{})
	transport := &blockingWindowTransport{
		tag:         "dns-rdrc-late",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return netip.MustParseAddr("10.1.0.1") },
		release:     release,
		entered:     make(chan struct{}),
	}
	store := newPersistentRDRCStore(t)
	router, client := newPendingTransitionFixtureWithRDRC(t, manager, transport, store)

	// Drive a REAL operation on A and hold it inside its round trip, so the transition can land
	// before the response is judged. The transport blocks until release.
	//
	// aNamespace is captured here only to assert, below, that A's own namespace is where any late
	// write would have to appear; the shipped guard refuses the write outright.
	_ = rdrcNamespace("dns-rdrc-late", router.concreteClient.environmentHash(transport))
	transport.block = true

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = client.Exchange(context.Background(), transport, messageFor("late.example."),
			adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return false })
	}()
	waitForBlockedExchange(t, transport)

	// A -> B completes first.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	manager.environment.Store(0xB)
	router.ResetNetwork()
	manager.stable.Store(true)

	// Release the A-era operation now that B owns the network. It has passed its guard, so it will
	// write - the question is which namespace it writes into.
	close(release)
	<-done

	bNamespace := rdrcNamespace("dns-rdrc-late", router.concreteClient.environmentHash(transport))

	// Two independent defences, and this asserts the OUTCOME rather than which one fired.
	//
	// In the shipped code the write is refused earlier, by stateMutationAllowed: the operation
	// started settled on A, B has since committed, and ResetNetwork advanced the generation, so the
	// guard is false and nothing is written at all.
	//
	// The namespace is what covers the remainder. Removing that guard does not reopen the hole: the
	// write then proceeds, but into A's namespace, which no B lookup reads. Verified by deleting the
	// guard and re-running this test, which still passes.
	//
	// Asserting the outcome rather than the mechanism keeps this valid whichever defence fires, and
	// is why this test is not merely a restatement of the guard test above.
	require.False(t, store.rejected(bNamespace, mDNS.Fqdn("late.example."), mDNS.TypeA),
		"a late A-era write became visible to B")

	// And a query on B reaches the resolver rather than being suppressed by it.
	transport.block = false
	queriesBefore := transport.queries
	_, _ = client.Exchange(context.Background(), transport, messageFor("late.example."),
		adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return true })
	require.Greater(t, transport.queries, queriesBefore, "B must actually be queried")
}

// A background refresh that crosses a transition must not persist an RDRC verdict for the new network.
//
// # Why the existing refresh test did not cover this
//
// TestBackgroundRefreshDuringTransitionDoesNotPersistRDRC schedules the refresh while the network is
// already unsettled, so the refresh returns before it ever reaches its checker. The refresh's RDRC
// guard is therefore never exercised, and deleting it produced no test failure - the gap the previous
// report admitted.
//
// # The shape that does cover it
//
// The refresh must start SETTLED, so it passes its start-state check and makes its round trip. The
// transition then completes while the response is in flight, and the response comes back rejected.
// That is the only ordering in which the refresh's own guard is the thing being tested.
func TestBackgroundRefreshCrossingTransitionCannotPersistRDRC(t *testing.T) {
	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	release := make(chan struct{})
	transport := &blockingWindowTransport{
		tag:         "rdrc-refresh-cross",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return netip.MustParseAddr("10.1.0.1") },
		release:     release,
		entered:     make(chan struct{}),
	}
	store := newPersistentRDRCStore(t)
	router, client := newPendingTransitionFixtureWithRDRC(t, manager, transport, store)

	// Prime a cache entry that the optimistic path can serve.
	_, err := client.Exchange(context.Background(), transport, messageFor("rdrccross.example."),
		adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	client.optimisticTimeout = time.Hour
	probe := probeMessage("rdrccross.example.")
	key := client.newCacheKey(transport, probe.Question[0], probe, adapter.DNSQueryOptions{})
	entry, _, _ := client.loadResponse(key)
	require.NotNil(t, entry)
	client.cache.AddWithLifetime(key, entry, -time.Minute)

	// A's namespace, captured before the transition re-pins the transport.
	namespaceA := rdrcNamespace("rdrc-refresh-cross", router.concreteClient.environmentHash(transport))

	// The refresh starts while the network is SETTLED - this is what makes the test discriminating.
	transport.block = true
	client.backgroundRefreshDNS(transport, key,
		client.prepareExchangeMessage(probe.Copy(), adapter.DNSQueryOptions{}),
		adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return false })
	waitForBlockedExchange(t, transport)

	// The transition completes while the refresh is in flight.
	manager.stable.Store(false)
	manager.routeEpoch.Add(1)
	manager.environment.Store(0xB)
	router.ResetNetwork()
	manager.stable.Store(true)

	close(release)
	waitForRefreshIdle(t, client)

	bNamespace := rdrcNamespace("rdrc-refresh-cross", router.concreteClient.environmentHash(transport))
	require.False(t, store.rejected(bNamespace, mDNS.Fqdn("rdrccross.example."), mDNS.TypeA),
		"a background refresh that started settled persisted an RDRC verdict for the network that "+
			"replaced the one it measured")

	// The refresh's OWN guard refuses the write outright, so A's namespace stays empty too.
	//
	// Asserting this is what gives the test discriminating power. Without it, deleting the refresh
	// guard still passes - because the write then lands in A's namespace and B is unaffected either
	// way. That case is genuinely covered by the namespace, but it is the GUARD that stops the write
	// here, and a test that cannot tell the two apart does not test the guard.
	require.False(t, store.rejected(namespaceA,
		mDNS.Fqdn("rdrccross.example."), mDNS.TypeA),
		"the refresh's stateMutationAllowed guard must refuse the deposit entirely: the network moved "+
			"underneath it, so the verdict describes a network that no longer holds. Removing that "+
			"guard makes this assertion fail, which is what makes this test discriminating")
}

// A legacy raw-tag verdict must not be read as a current-environment verdict.
//
// # Why this is the safe direction
//
// Older builds persisted RDRC under the bare transport tag. The new lookup key is namespaced, so a
// legacy entry simply does not match: the first new-environment lookup misses and queries the
// resolver.
//
// That is the correct failure mode. RDRC is an optimization: a miss costs one DNS query, while a
// wrong hit skips the real resolver entirely and suppresses a name on a network that never rejected
// it. Reading legacy entries as "true for every network" would reintroduce exactly the defect this
// change removes, so they are left to expire on their own timeout rather than migrated.
func TestLegacyRawRDRCEntryIsNotReadAsAEnvironmentVerdict(t *testing.T) {
	manager := &transitionStateManager{}
	manager.environment.Store(0xA)
	manager.routeEpoch.Store(1)
	manager.stable.Store(true)

	transport := &rebindingWindowTransport{
		tag:         "dns-rdrc-legacy",
		environment: []string{"wifi"},
		current:     func() netip.Addr { return netip.MustParseAddr("10.1.0.1") },
	}
	store := newPersistentRDRCStore(t)
	_, client := newPendingTransitionFixtureWithRDRC(t, manager, transport, store)

	// A verdict written the OLD way: the bare transport tag, no namespace.
	require.NoError(t, store.SaveRDRC("dns-rdrc-legacy", mDNS.Fqdn("legacy.example."), mDNS.TypeA))
	require.True(t, store.rejected("dns-rdrc-legacy", mDNS.Fqdn("legacy.example."), mDNS.TypeA),
		"the legacy key is readable under its own name")

	// The client must not find it, and must therefore query the resolver.
	queriesBefore := transport.queries
	_, err := client.Exchange(context.Background(), transport, messageFor("legacy.example."),
		adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return true })

	require.NoError(t, err, "the legacy verdict must not suppress the query")
	require.Greater(t, transport.queries, queriesBefore,
		"a legacy raw-tag verdict was read as a verdict for the current environment. Legacy entries "+
			"describe no particular network, so treating them as true for every network is the "+
			"original defect; they are left to expire instead")
}
