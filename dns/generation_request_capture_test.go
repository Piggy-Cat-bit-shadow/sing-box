package dns

import (
	"context"
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

// Tests that a response is attributed to the network its REQUEST was issued on.
//
// # The defect these pin
//
// The generation guard existed, but the generation was read when the RESPONSE arrived:
//
//	func (r *Router) recordReverseMapping(...) {
//	    r.recordReverseMappingFrom(..., r.dnsGeneration())
//	}
//
// A request issued on generation G1 that completes after a reset therefore captured G2, compared G2
// against the current G2, matched, and wrote its mapping into the cache the reset had just purged -
// the exact stale entry the guard was written to prevent. The comparison was self-satisfying: it
// always agreed with itself.
//
// These tests drive the REAL Router.Exchange and Router.ExchangeAsync with a transport that blocks
// until released, so the request is provably in flight across the reset.

// blockingReverseTransport is a transport whose exchange blocks until released.
//
// It answers with an A record so a reverse mapping would be recorded on success.
type blockingReverseTransport struct {
	adapter.DNSTransport
	tag string

	// entered is signalled once the request has genuinely reached the transport.
	entered chan struct{}
	// release unblocks the response.
	release chan struct{}
	once    sync.Once

	address netip.Addr
}

func (t *blockingReverseTransport) Type() string           { return "blocking" }
func (t *blockingReverseTransport) Tag() string            { return t.tag }
func (t *blockingReverseTransport) Dependencies() []string { return nil }
func (t *blockingReverseTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *blockingReverseTransport) Close() error { return nil }
func (t *blockingReverseTransport) Reset()       {}

func (t *blockingReverseTransport) answer(message *mDNS.Msg) *mDNS.Msg {
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

func (t *blockingReverseTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.once.Do(func() { close(t.entered) })
	select {
	case <-t.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return t.answer(message), nil
}

func (t *blockingReverseTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// newRouterForGenerationTest builds a Router whose client uses the given transport.
func newRouterForGenerationTest(t *testing.T, transport adapter.DNSTransport) *Router {
	t.Helper()
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()
	router := &Router{
		logger:    log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{transport.Tag(): transport}},
		client:    client,
	}
	router.dnsReverseMapping = common.Must1(freelru.New[netip.Addr, string](
		1024, maphash.NewHasher[netip.Addr]().Hash32, true))
	return router
}

// TestExchangeCapturesGenerationAtRequestTime is B2.
//
// A request issued on G1 that completes after ResetNetwork advances to G2 must not write its mapping:
// the answer describes the network it was asked on, not the one that is current when it arrives.
func TestExchangeCapturesGenerationAtRequestTime(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.9")
	transport := &blockingReverseTransport{
		tag:     "blocking",
		entered: make(chan struct{}),
		release: make(chan struct{}),
		address: address,
	}
	router := newRouterForGenerationTest(t, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("stale.example.", mDNS.TypeA)

	type exchangeOutcome struct {
		response *mDNS.Msg
		err      error
	}
	done := make(chan exchangeOutcome, 1)
	go func() {
		response, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: transport})
		done <- exchangeOutcome{response, err}
	}()

	// Barrier: the request is genuinely inside the transport, at generation G1.
	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the transport")
	}

	require.EqualValues(t, 0, router.dnsGeneration(), "and it was issued on the initial generation")

	// The network changes while the request is in flight.
	router.ResetNetwork()
	require.EqualValues(t, 1, router.dnsGeneration(), "ResetNetwork advances the generation")

	// Now let the OLD response come back.
	close(transport.release)

	select {
	case outcome := <-done:
		require.NoError(t, outcome.err)
	case <-time.After(5 * time.Second):
		t.Fatal("the exchange never returned")
	}

	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded,
		"a response from generation 0 was recorded after ResetNetwork advanced to generation 1. "+
			"The generation was read when the RESPONSE arrived, so it captured the post-reset value, "+
			"compared it against itself, matched, and refilled the cache the reset had just purged - "+
			"the new network inherited a name learned on the old one")
}

// TestExchangeAsyncCapturesGenerationAtRequestTime is B2 for the asynchronous entry point.
func TestExchangeAsyncCapturesGenerationAtRequestTime(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.10")
	transport := &blockingReverseTransport{
		tag:     "blocking-async",
		entered: make(chan struct{}),
		release: make(chan struct{}),
		address: address,
	}
	router := newRouterForGenerationTest(t, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("stale-async.example.", mDNS.TypeA)

	callbackDone := make(chan error, 1)
	router.ExchangeAsync(context.Background(), message, adapter.DNSQueryOptions{Transport: transport},
		func(response *mDNS.Msg, err error) {
			callbackDone <- err
		})

	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the async request never reached the transport")
	}

	require.EqualValues(t, 0, router.dnsGeneration())
	router.ResetNetwork()
	require.EqualValues(t, 1, router.dnsGeneration())

	close(transport.release)

	select {
	case err := <-callbackDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the async callback never ran")
	}

	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded,
		"the asynchronous path recorded a mapping for a request issued before the reset")
}

// TestResponseOnSameGenerationIsRecorded keeps the positive case: nothing reset, so the mapping is
// recorded normally.
func TestResponseOnSameGenerationIsRecorded(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.11")
	transport := &blockingReverseTransport{
		tag:     "same-generation",
		entered: make(chan struct{}),
		release: make(chan struct{}),
		address: address,
	}
	router := newRouterForGenerationTest(t, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("fresh.example.", mDNS.TypeA)

	go func() {
		<-transport.entered
		close(transport.release)
	}()

	_, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: transport})
	require.NoError(t, err)

	domain, loaded := router.LookupReverseMapping(address)
	require.True(t, loaded,
		"with no reset the mapping must be recorded; otherwise the guard rejects everything and the "+
			"reverse mapping stops working")
	require.Equal(t, "fresh.example", domain)
}

// TestResetNetworkClosesTheWindowBeforePurging is B1.
//
// ResetNetwork purged the reverse mapping and then advanced the generation. Between those two steps a
// request issued BEFORE the reset still carried the pre-reset generation, still compared equal to the
// still-current pre-reset value, and was therefore accepted - writing into the cache the purge had
// just cleared.
//
// The consequence is that the reset is not a barrier until it has finished, so a response arriving
// during the reset is treated as belonging to the network that has already been left. Advancing the
// generation FIRST closes the window: every capture from before the reset is stale the moment the
// reset begins, and the purge then removes whatever those captures had already written.
func TestResetNetworkClosesTheWindowBeforePurging(t *testing.T) {
	router := newRouterForGenerationTest(t, &blockingReverseTransport{
		tag: "unused", entered: make(chan struct{}), release: make(chan struct{}),
	})

	address := netip.MustParseAddr("203.0.113.12")
	message := new(mDNS.Msg)
	message.SetQuestion("window.example.", mDNS.TypeA)
	response := new(mDNS.Msg)
	response.SetReply(message)
	response.Answer = append(response.Answer, &mDNS.A{
		Hdr: mDNS.RR_Header{Name: "window.example.", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
		A:   address.AsSlice(),
	})

	// A request issued before the reset, whose response arrives during it.
	capturedGeneration := router.dnsGeneration()

	// Something the pre-reset generation had already recorded.
	router.dnsReverseMapping.Add(address, "pre-reset.example")

	// During ResetNetwork, after the purge and BEFORE the generation advance, the old capture is
	// still considered current. This is the window.
	purgeThenCheck := func() bool {
		router.dnsReverseMapping.Purge()
		router.recordReverseMappingFrom(message, response, nil, capturedGeneration)
		_, loaded := router.LookupReverseMapping(address)
		return loaded
	}
	require.True(t, purgeThenCheck(),
		"this documents the old ordering's window: a capture from before the reset is accepted after "+
			"the purge, because the generation has not advanced yet")

	// Now perform ResetNetwork for real and confirm the window is closed afterwards.
	router.ResetNetwork()
	router.recordReverseMappingFrom(message, response, nil, capturedGeneration)
	_, afterReset := router.LookupReverseMapping(address)
	require.False(t, afterReset,
		"after ResetNetwork a capture from before it must be refused")
	require.EqualValues(t, capturedGeneration+1, router.dnsGeneration(),
		"and the reset advances the generation exactly once")

	// And the freshly purged cache holds nothing.
	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded)
}

// TestResetNetworkOrderIsBarrierFirst asserts the production ordering directly.
//
// The generation must be advanced before the purge, so the reset is a barrier: everything issued
// before it is stale the moment it starts, rather than only once it finishes.
func TestResetNetworkOrderIsBarrierFirst(t *testing.T) {
	router := newRouterForGenerationTest(t, &blockingReverseTransport{tag: "unused-3", entered: make(chan struct{}), release: make(chan struct{})})

	address := netip.MustParseAddr("203.0.113.13")
	message := new(mDNS.Msg)
	message.SetQuestion("late.example.", mDNS.TypeA)
	response := new(mDNS.Msg)
	response.SetReply(message)
	response.Answer = append(response.Answer, &mDNS.A{
		Hdr: mDNS.RR_Header{Name: "late.example.", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
		A:   address.AsSlice(),
	})
	router.dnsReverseMapping.Add(address, "before-reset.example")

	// A request issued before the reset.
	capturedGeneration := router.dnsGeneration()

	router.ResetNetwork()

	// The purge must have happened...
	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded, "the reset purges the mapping")

	// ...AND the generation must already be advanced, so the pre-reset capture is stale.
	require.NotEqual(t, capturedGeneration, router.dnsGeneration(),
		"the generation must advance as part of the same reset")
	router.recordReverseMappingFrom(message, response, nil, capturedGeneration)
	_, lateLoaded := router.LookupReverseMapping(address)
	require.False(t, lateLoaded, "a capture from before the reset must not be recordable after it")
}

// TestResetNetworkIsABarrierFromItsFirstInstruction is the discriminating form of B1.
//
// The window can be observed rather than described: a reverse mapping recorded from a pre-reset
// capture must not survive a reset, and the reset must not be able to end with a pre-reset capture
// still considered current.
//
// With the generation advanced last, `dnsGeneration()` observed during the reset is still the
// pre-reset value, so a capture taken before it compares equal and is accepted. With the generation
// advanced first, it is already stale. The test drives a transport whose Reset() callback inspects
// the generation at that exact moment, which is the window itself.
func TestResetNetworkIsABarrierFromItsFirstInstruction(t *testing.T) {
	probe := &generationProbeTransport{tag: "probe"}
	router := newRouterForGenerationTest(t, probe)
	// The probe reads the router's generation from inside Reset, which runs mid-ResetNetwork.
	probe.probe = router.dnsGeneration
	router.transport = &probeTransportManager{
		fakeDNSTransportManager: router.transport.(*fakeDNSTransportManager),
		transports:              []adapter.DNSTransport{probe},
	}

	before := router.dnsGeneration()

	// The transport's Reset runs in the MIDDLE of ResetNetwork. Whatever the generation is at that
	// point is the generation during the window.
	router.ResetNetwork()

	require.NotEqual(t, before, probe.generationSeenDuringReset.Load(),
		"the generation observed while the transports were being reset was still the pre-reset "+
			"value. That means the generation advanced LAST, so a response issued before the reset "+
			"compares equal to the still-current value and is accepted into the cache the purge just "+
			"cleared - the reset is not a barrier until it has finished, which is too late")

	require.EqualValues(t, before+1, probe.generationSeenDuringReset.Load(),
		"the generation must already be advanced by the time the transports are reset")
}

// probeTransportManager reports the probe as the only transport, so ResetNetwork reaches it.
type probeTransportManager struct {
	*fakeDNSTransportManager
	transports []adapter.DNSTransport
}

func (m *probeTransportManager) Transports() []adapter.DNSTransport { return m.transports }

// generationProbeTransport records the generation as observed from inside Reset.
type generationProbeTransport struct {
	adapter.DNSTransport
	tag string

	generationSeenDuringReset atomic.Uint64
	probe                     func() uint64
}

func (t *generationProbeTransport) Type() string           { return "generation-probe" }
func (t *generationProbeTransport) Tag() string            { return t.tag }
func (t *generationProbeTransport) Dependencies() []string { return nil }
func (t *generationProbeTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *generationProbeTransport) Close() error { return nil }

func (t *generationProbeTransport) Reset() {
	if t.probe != nil {
		t.generationSeenDuringReset.Store(t.probe())
	}
}

func (t *generationProbeTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, nil
}

func (t *generationProbeTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(nil, nil)
}
