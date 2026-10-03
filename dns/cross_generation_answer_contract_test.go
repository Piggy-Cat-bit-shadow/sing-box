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

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Item 4: what a caller may receive when its query spans a network change.
//
// # The contract, established from the code rather than assumed
//
// ResetNetwork closes every managed connection, tells the endpoints, inbounds and outbounds that the
// interface changed, and resets the DNS router. It does NOT cancel DNS queries that are already in
// flight, and nothing in the exchange path aborts a response because the network moved.
//
// So the existing contract is: an in-flight query completes, and the answer it receives is the one
// the network it asked on produced. That is a deliberate property rather than an oversight - a DNS
// answer is a dated observation about a name, the caller learns which network it came from, and
// cancelling every in-flight resolution on a transient interface event would turn a wifi blip into a
// failed lookup for every application.
//
// Returning a cancellation instead would be a BEHAVIOUR CHANGE, so it is not made here. What this
// test does is make the current contract explicit and mechanical, so the change cannot happen by
// accident: if someone later makes a superseded answer an error, this fails and the decision has to
// be taken deliberately.
//
// The companion guarantee is that nothing from the superseded answer is stored. Both halves are
// asserted together, because "returned but not cached" is the actual contract and neither half alone
// describes it.

// stepwiseTransport answers with a per-generation address and blocks until released.
type stepwiseTransport struct {
	adapter.DNSTransport
	tag string

	entered chan struct{}
	release chan struct{}
	once    sync.Once

	address    netip.Addr
	generation *atomic.Uint64
	// queries counts how many exchanges reached this transport.
	queries atomic.Int32
}

func (t *stepwiseTransport) Type() string                                               { return "stepwise" }
func (t *stepwiseTransport) Tag() string                                                { return t.tag }
func (t *stepwiseTransport) Dependencies() []string                                     { return nil }
func (t *stepwiseTransport) Environment() []string                                      { return []string{"wifi"} }
func (t *stepwiseTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (t *stepwiseTransport) Close() error                                               { return nil }
func (t *stepwiseTransport) Reset()                                                     {}

func (t *stepwiseTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	t.once.Do(func() { close(t.entered) })
	select {
	case <-t.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	response := new(mDNS.Msg)
	response.SetReply(message)
	if len(message.Question) > 0 {
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA,
				Class: mDNS.ClassINET, Ttl: 300},
			A: t.address.AsSlice(),
		})
	}
	return response, nil
}

func (t *stepwiseTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// TestInFlightAnswerIsDeliveredAndNotStored is item 4.
func TestInFlightAnswerIsDeliveredAndNotStored(t *testing.T) {
	oldNetworkAddress := netip.MustParseAddr("10.0.0.1")

	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	client.networkManager = &generationNetworkManager{}

	transport := &stepwiseTransport{
		tag:        "stepwise",
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
		address:    oldNetworkAddress,
		generation: &generation,
	}
	router := &Router{
		logger: log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{
			transports:       map[string]adapter.DNSTransport{transport.Tag(): transport},
			defaultTransport: transport,
		},
		client: client,
	}
	client.networkGeneration = router.dnsGeneration

	message := new(mDNS.Msg)
	message.SetQuestion("contract.internal.", mDNS.TypeA)

	type outcome struct {
		response *mDNS.Msg
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		response, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: transport})
		done <- outcome{response, err}
	}()

	// Barrier: the query is genuinely in flight on the old network.
	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the query never reached the transport")
	}

	// The network changes, as NetworkManager.ResetNetwork performs it.
	router.ResetNetwork()
	close(transport.release)

	var received outcome
	select {
	case received = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the exchange never returned")
	}

	// Half one: the answer is delivered, not turned into an error.
	require.NoError(t, received.err,
		"the in-flight answer was converted into an error by the network change. The current "+
			"contract delivers it: a DNS answer is a dated observation, and cancelling every "+
			"resolution on an interface event would turn a transient blip into a failed lookup")
	require.NotNil(t, received.response)

	addresses := answersOf(received.response)
	require.Equal(t, []netip.Addr{oldNetworkAddress}, addresses,
		"the delivered answer is the one the network the question was asked on produced")

	// Half two: nothing from it is stored.
	//
	// The check is the NXDOMAIN and persistent layers plus a re-query, in that order: a probe issued
	// now runs at the CURRENT generation and would legitimately record its own entries, so any
	// assertion made after it could not distinguish the two.
	question := message.Question[0]
	cacheKey := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	cached, _, isStale := client.loadResponse(cacheKey)
	require.False(t, cached != nil && !isStale,
		"the superseded answer was stored, so the new network is served an address measured on the "+
			"old one")

	negative, hit := client.loadNXDomain(cacheKey, question, message.Id)
	require.False(t, hit && negative != nil,
		"the superseded answer recorded a name-wide negative verdict")

	// A re-query must reach the transport again, which is the observable form of "it was not
	// cached". The probe uses its own transport, so a cache hit would be served without this one
	// being touched.
	released := make(chan struct{})
	close(released)
	refresh := &stepwiseTransport{
		tag:     "stepwise-probe",
		entered: make(chan struct{}),
		release: released,
		address: netip.MustParseAddr("10.0.0.2"),
	}
	client.networkManager = &generationNetworkManager{}
	router.transport = &fakeDNSTransportManager{
		transports:       map[string]adapter.DNSTransport{refresh.Tag(): refresh},
		defaultTransport: refresh,
	}

	_, probeErr := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: refresh})
	require.NoError(t, probeErr)
	require.EqualValues(t, 1, refresh.queries.Load(),
		"the re-query did not reach the transport, so the superseded answer was served from cache")

}
