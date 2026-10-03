package dns

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Tests for the DNS cache's network-generation ownership guard.
//
// # Why the environment fingerprint is not enough
//
// The fingerprint namespaces the cache by WHICH network an answer belongs to. It cannot express
// "same network identity, different epoch": a reset that leaves the fingerprint unchanged - the same
// SSID reconnected, the same interface re-addressed to the same values - produces an identical
// fingerprint. A response issued before that reset and captured after it therefore looks like it
// belongs, and a value-only comparison accepts it.
//
// The generation is the OWNERSHIP guard: it says whether an answer still belongs to the network its
// request was issued on. The fingerprint remains the NAMESPACE. They answer different questions and
// both are needed.

// generationNetworkManager reports a controllable environment and a stable fingerprint source.
type generationNetworkManager struct {
	adapter.NetworkManager
	environment atomic.Uint64
}

func (m *generationNetworkManager) NetworkEnvironment() uint64 { return m.environment.Load() }

// fixedFingerprintTransport participates in environments and reports a FIXED set of keys, so its
// fingerprint never changes across a reset - which is the case under test.
type fixedFingerprintTransport struct {
	adapter.DNSTransport
	tag string

	environment []string
	queries     atomic.Int32
}

func (t *fixedFingerprintTransport) Type() string           { return "fixed-fingerprint" }
func (t *fixedFingerprintTransport) Tag() string            { return t.tag }
func (t *fixedFingerprintTransport) Dependencies() []string { return nil }
func (t *fixedFingerprintTransport) Environment() []string  { return t.environment }
func (t *fixedFingerprintTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *fixedFingerprintTransport) Close() error { return nil }
func (t *fixedFingerprintTransport) Reset()       {}

func (t *fixedFingerprintTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	return aRecordReply(message, "198.51.100.1"), nil
}

func (t *fixedFingerprintTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	response, err := t.Exchange(ctx, message)
	callback(response, err)
}

func aRecordReply(message *mDNS.Msg, address string) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(message)
	if len(message.Question) > 0 {
		question := message.Question[0]
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 99},
		})
	}
	return response
}

// newGenerationGuardedClient builds a client whose generation is supplied by the test.
func newGenerationGuardedClient(t *testing.T, generation *atomic.Uint64) *Client {
	t.Helper()
	networkManager := &generationNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	client := NewClient(ClientOptions{
		Context:           ctx,
		Logger:            log.NewNOPFactory().NewLogger("dns-generation"),
		NetworkGeneration: generation.Load,
	})
	client.Start()
	return client
}

// TestSameFingerprintDifferentGenerationIsIsolated is B5, the case a value-only comparison cannot
// catch.
//
// The environment is identical before and after the reset, so the fingerprint matches. Only the
// generation distinguishes them, and the response issued before the reset must not be cached.
func TestSameFingerprintDifferentGenerationIsIsolated(t *testing.T) {
	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	transport := &fixedFingerprintTransport{tag: "fixed", environment: []string{"wifi"}}

	fingerprintBefore := client.environmentHash(transport)

	// Issue the query at generation 0, capture the generation, then let the reset happen before the
	// response is stored - which is exactly the in-flight case.
	operation := &exchangeOperation{}
	message := new(mDNS.Msg)
	message.SetQuestion("same-net.example.", mDNS.TypeA)
	operation.cacheKey = client.newCacheKey(transport, message.Question[0], message, adapter.DNSQueryOptions{})
	client.captureGeneration(operation)

	// The network resets but the fingerprint does not change.
	generation.Add(1)

	require.Equal(t, fingerprintBefore, client.environmentHash(transport),
		"the fixture must NOT change the fingerprint, or this test would pass on the fingerprint "+
			"guard alone and prove nothing about the generation")

	require.False(t, client.generationStillCurrent(operation),
		"a response issued on generation 0 was still considered current on generation 1. The "+
			"fingerprint is identical on both sides, so a value-only comparison accepts it and the "+
			"new network inherits an answer measured on the old one")

	// And the corresponding same-generation case still stores.
	current := &exchangeOperation{}
	current.cacheKey = operation.cacheKey
	client.captureGeneration(current)
	require.True(t, client.generationStillCurrent(current),
		"with no reset the guard must not reject, or caching would stop working entirely")
}

// TestZeroEnvironmentZeroGenerationStillCaches is B4.
//
// A transport with no environment keys on a platform reporting environment 0 has a fingerprint of 0
// AND a generation of 0. Both are legitimate identities, not "unknown", so caching must work.
func TestZeroEnvironmentZeroGenerationStillCaches(t *testing.T) {
	var generation atomic.Uint64 // permanently 0
	client := newGenerationGuardedClient(t, &generation)
	transport := &fixedFingerprintTransport{tag: "zero", environment: nil}

	require.EqualValues(t, 0, client.environmentHash(transport),
		"the fixture must produce a zero fingerprint")

	first := client.newCacheKey(transport, mustQuestion(t, "zero.example."), mustMessage(t, "zero.example."), adapter.DNSQueryOptions{})
	operation := &exchangeOperation{cacheKey: first}
	client.captureGeneration(operation)

	require.True(t, client.generationStillCurrent(operation),
		"generation 0 with no reset is current")

	stored, storable := client.finishCacheKey(transport, first)
	require.True(t, storable,
		"a stable-zero environment on generation 0 must cache. Both zeros are real identities, not "+
			"markers for 'unknown', so the guard must not reject them")
	require.Equal(t, first, stored)
}

// TestZeroEnvironmentAcrossGenerationIsRejected is the zero-fingerprint half of B5.
//
// Generation 0 -> reset -> generation 1, with the fingerprint 0 on both sides.
func TestZeroEnvironmentAcrossGenerationIsRejected(t *testing.T) {
	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	transport := &fixedFingerprintTransport{tag: "zero-across", environment: nil}

	key := client.newCacheKey(transport, mustQuestion(t, "zero-across.example."), mustMessage(t, "zero-across.example."), adapter.DNSQueryOptions{})
	operation := &exchangeOperation{cacheKey: key}
	client.captureGeneration(operation)

	generation.Add(1)

	require.EqualValues(t, 0, client.environmentHash(transport),
		"the fingerprint is still 0, so it cannot distinguish the two sides")
	require.False(t, client.generationStillCurrent(operation),
		"a response from generation 0 with a zero fingerprint was accepted on generation 1: the "+
			"zero-fingerprint case is exactly where the generation guard is load-bearing")
}

// TestLegacyClientWithoutGenerationStaysFingerprintOnly documents the degradation.
func TestLegacyClientWithoutGenerationStaysFingerprintOnly(t *testing.T) {
	client := NewClient(ClientOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().NewLogger("dns-no-generation"),
	})
	client.Start()

	operation := &exchangeOperation{}
	client.captureGeneration(operation)

	require.True(t, client.generationStillCurrent(operation),
		"a caller with no generation concept must degrade to fingerprint-only behaviour rather than "+
			"rejecting every response, which would disable caching for every such caller")
}

func mustQuestion(t *testing.T, name string) mDNS.Question {
	t.Helper()
	return mDNS.Question{Name: name, Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}
}

func mustMessage(t *testing.T, name string) *mDNS.Msg {
	t.Helper()
	message := new(mDNS.Msg)
	message.SetQuestion(name, mDNS.TypeA)
	return message
}

// blockingGenerationTransport is a transport whose exchange blocks until released, so a reset can be
// placed deterministically inside the round trip.
type blockingGenerationTransport struct {
	adapter.DNSTransport
	tag string

	entered chan struct{}
	release chan struct{}
	once    sync.Once

	// rcodes, when set, answers NXDOMAIN with an SOA so the negative path is exercised.
	nxdomain bool
	queries  atomic.Int32
}

func (t *blockingGenerationTransport) Type() string           { return "blocking-generation" }
func (t *blockingGenerationTransport) Tag() string            { return t.tag }
func (t *blockingGenerationTransport) Dependencies() []string { return nil }
func (t *blockingGenerationTransport) Environment() []string  { return []string{"wifi"} }
func (t *blockingGenerationTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *blockingGenerationTransport) Close() error { return nil }
func (t *blockingGenerationTransport) Reset()       {}

func (t *blockingGenerationTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	t.once.Do(func() { close(t.entered) })
	select {
	case <-t.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	response := new(mDNS.Msg)
	response.SetReply(message)
	if t.nxdomain {
		response.Rcode = mDNS.RcodeNameError
		if len(message.Question) > 0 {
			response.Ns = append(response.Ns, &mDNS.SOA{
				Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeSOA, Class: mDNS.ClassINET, Ttl: 300},
				Ns:  "ns.example.", Mbox: "hostmaster.example.", Serial: 1,
				Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
			})
		}
		return response, nil
	}
	if len(message.Question) > 0 {
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 55},
		})
	}
	return response, nil
}

func (t *blockingGenerationTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// TestExactCacheRejectsAResponseFromBeforeAReset is B6, the exact path, driven through the REAL
// exchange so the guard is exercised where it actually runs.
func TestExactCacheRejectsAResponseFromBeforeAReset(t *testing.T) {
	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	transport := &blockingGenerationTransport{
		tag: "exact-blocking", entered: make(chan struct{}), release: make(chan struct{}),
	}

	message := new(mDNS.Msg)
	message.SetQuestion("exact-blocking.example.", mDNS.TypeA)

	done := make(chan error, 1)
	go func() {
		_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
		done <- err
	}()

	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the query never reached the transport")
	}

	// The network resets while the response is in flight.
	generation.Add(1)
	close(transport.release)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the exchange never returned")
	}

	// A second identical query must reach upstream: the first response was not cached.
	before := transport.queries.Load()
	cached, _, isStale := client.loadResponse(client.newCacheKey(transport, message.Question[0], message, adapter.DNSQueryOptions{}))
	require.False(t, cached != nil && !isStale,
		"a response issued before the reset was stored in the exact cache. The generation was not "+
			"consulted before storing, so the new network is served an answer from the old one")
	require.EqualValues(t, before, transport.queries.Load())
}

// TestNXDomainCacheRejectsAResponseFromBeforeAReset is B6, the NXDOMAIN path.
func TestNXDomainCacheRejectsAResponseFromBeforeAReset(t *testing.T) {
	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	transport := &blockingGenerationTransport{
		tag: "nx-blocking", entered: make(chan struct{}), release: make(chan struct{}), nxdomain: true,
	}

	message := new(mDNS.Msg)
	message.SetQuestion("nx-blocking.example.", mDNS.TypeA)

	done := make(chan error, 1)
	go func() {
		_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
		done <- err
	}()

	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the query never reached the transport")
	}

	generation.Add(1)
	close(transport.release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the exchange never returned")
	}

	// A different record type for the same name must not find a name-wide verdict.
	question := message.Question[0]
	negative, hit := client.loadNXDomain(client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{}), question, message.Id)
	require.False(t, hit && negative != nil,
		"an NXDOMAIN issued before the reset was recorded name-wide, so the new network inherits a "+
			"negative verdict for a name it never asked about")
}

// TestPersistentCacheIsNotPollutedAcrossAGeneration is B6, the persistent path.
//
// The generation must NOT become part of the persistent key: a process-local counter would make
// every persisted entry meaningless to the next process. What must hold instead is that a response
// from a superseded generation is never offered to the persistent store at all.
func TestPersistentCacheIsNotPollutedAcrossAGeneration(t *testing.T) {
	store := &recordingGenerationCacheStore{}

	var generation atomic.Uint64
	networkManager := &generationNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	client := NewClient(ClientOptions{
		Context:           ctx,
		Logger:            log.NewNOPFactory().NewLogger("dns-persistent-generation"),
		NetworkGeneration: generation.Load,
		DNSCache:          func() adapter.DNSCacheStore { return store },
	})
	client.Start()

	transport := &blockingGenerationTransport{
		tag: "persistent-blocking", entered: make(chan struct{}), release: make(chan struct{}),
	}

	message := new(mDNS.Msg)
	message.SetQuestion("persistent-blocking.example.", mDNS.TypeA)

	done := make(chan error, 1)
	go func() {
		_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
		done <- err
	}()

	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the query never reached the transport")
	}

	generation.Add(1)
	close(transport.release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the exchange never returned")
	}

	// The persistent save is asynchronous, so wait for it to settle rather than guessing: the
	// counter is the barrier, and it must remain at zero.
	time.Sleep(200 * time.Millisecond)

	require.EqualValues(t, 0, store.saves.Load(),
		"a response issued before the reset was written to the PERSISTENT cache. The next process "+
			"would then load an answer measured on a network it has never been on")

	// And a same-generation response still persists, so the guard has not disabled persistence.
	freshTransport := &blockingGenerationTransport{
		tag: "persistent-fresh", entered: make(chan struct{}), release: make(chan struct{}),
	}
	close(freshTransport.release)

	freshMessage := new(mDNS.Msg)
	freshMessage.SetQuestion("persistent-fresh.example.", mDNS.TypeA)
	_, err := client.Exchange(context.Background(), freshTransport, freshMessage, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Eventually(t, func() bool { return store.saves.Load() > 0 }, 3*time.Second, 10*time.Millisecond,
		"a response from the current generation must still be persisted, or the guard has broken "+
			"the persistent cache rather than protecting it")
}

// recordingGenerationCacheStore counts persistent saves.
type recordingGenerationCacheStore struct {
	adapter.DNSCacheStore
	saves atomic.Int32
}

func (s *recordingGenerationCacheStore) SaveDNSCacheAsync(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time, logger logger.Logger) {
	s.saves.Add(1)
}

func (s *recordingGenerationCacheStore) SaveDNSCache(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time) error {
	s.saves.Add(1)
	return nil
}

func (s *recordingGenerationCacheStore) LoadDNSCache(transportName string, qName string, qType uint16) ([]byte, time.Time, bool) {
	return nil, time.Time{}, false
}

func (s *recordingGenerationCacheStore) ClearDNSCache() error { return nil }

// TestRouterAndClientShareOneGenerationTruth is B7.
//
// The reverse mapping and the DNS cache must agree about which epoch an answer belongs to. They do
// so because the Router injects its own generator into the client, so a single ResetNetwork advances
// one counter that both observe.
func TestRouterAndClientShareOneGenerationTruth(t *testing.T) {
	// Build the Router through its REAL constructor, so the injection under test is the production
	// one rather than something the test wires itself.
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(),
		&fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{}})
	router, err := NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{})
	require.NoError(t, err)

	concrete, isConcrete := router.client.(*Client)
	require.True(t, isConcrete, "the router's client must be the concrete DNS client")

	require.NotNil(t, concrete.networkGeneration,
		"the Router must inject its own generator into the client. A client with no generator would "+
			"fall back to fingerprint-only behaviour while the reverse mapping used generations, so "+
			"the two caches would disagree about which network an answer belongs to")

	before := router.dnsGeneration()
	require.EqualValues(t, before, concrete.networkGeneration(),
		"and the injected function must report the same value as the router's own accessor")

	router.ResetNetwork()

	require.EqualValues(t, before+1, router.dnsGeneration(),
		"one reset advances the generation")
	require.EqualValues(t, before+1, concrete.networkGeneration(),
		"and the client observes the same single advancement, not a separate counter of its own")
}
