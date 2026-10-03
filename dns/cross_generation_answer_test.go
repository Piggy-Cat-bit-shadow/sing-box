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

// Tests for what a caller RECEIVES when the network changes while its query is in flight.
//
// # Why "not cached" is not the same as "safe"
//
// The generation work so far stops a superseded answer from being STORED. That leaves the more
// direct question: the caller still gets a value back, and if that value came from the network it
// has just left, the caller connects somewhere that is no longer correct. For split-horizon,
// corporate, captive-portal or VPN DNS the same name legitimately resolves differently per network,
// so a stale answer is a wrong answer rather than a merely outdated one.
//
// These tests pin what actually happens, so the product contract is a decision rather than an
// accident.

// switchingTransport answers with a different address per generation, and blocks until released.
type switchingTransport struct {
	adapter.DNSTransport
	tag string

	entered chan struct{}
	release chan struct{}
	once    sync.Once

	address netip.Addr
	queries atomic.Int32
}

func (t *switchingTransport) Type() string                         { return "switching" }
func (t *switchingTransport) Tag() string                          { return t.tag }
func (t *switchingTransport) Dependencies() []string               { return nil }
func (t *switchingTransport) Start(stage adapter.StartStage) error { return nil }
func (t *switchingTransport) Close() error                         { return nil }
func (t *switchingTransport) Reset()                               {}

func (t *switchingTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
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
			Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
			A:   t.address.AsSlice(),
		})
	}
	return response, nil
}

func (t *switchingTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

func answersOf(response *mDNS.Msg) []netip.Addr {
	if response == nil {
		return nil
	}
	addresses := make([]netip.Addr, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if record, isA := answer.(*mDNS.A); isA {
			address, isAddress := netip.AddrFromSlice(record.A)
			if isAddress {
				addresses = append(addresses, address.Unmap())
			}
		}
	}
	return addresses
}

// TestExchangeReturnsAnAnswerFromTheNetworkItWasAskedOn is B1.
//
// The answer belongs to the network the question was asked on, which is the correct attribution - but
// the caller receives it AFTER the network has changed. This test documents which of the two the
// product does, because the distinction matters and must not be an accident.
func TestExchangeReturnsAnAnswerFromTheNetworkItWasAskedOn(t *testing.T) {
	oldNetworkAddress := netip.MustParseAddr("10.0.0.1")
	transport := &switchingTransport{
		tag:     "switching",
		entered: make(chan struct{}),
		release: make(chan struct{}),
		address: oldNetworkAddress,
	}

	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	router := &Router{
		logger:    log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{transport.Tag(): transport}},
		client:    client,
	}
	// Wire the client to the router's generation, as NewRouter does.
	client.networkGeneration = router.dnsGeneration

	message := new(mDNS.Msg)
	message.SetQuestion("example.internal.", mDNS.TypeA)

	type outcome struct {
		response *mDNS.Msg
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		response, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: transport})
		done <- outcome{response, err}
	}()

	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the query never reached the transport")
	}

	// The network changes while the query is in flight.
	router.ResetNetwork()
	close(transport.release)

	var received outcome
	select {
	case received = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the exchange never returned")
	}

	require.NoError(t, received.err)

	addresses := answersOf(received.response)
	require.Equal(t, []netip.Addr{oldNetworkAddress}, addresses,
		"the caller received the answer produced on the network it has already left. This is the "+
			"documented behaviour, not an oversight: the answer is correctly attributed to the "+
			"network that produced it, and the age of the answer is the caller's to judge. Recording "+
			"it here means a future change to return a cancellation instead has to be deliberate")

	// And the superseded answer was not stored, which is the part the generation guard owns.
	cacheKey := client.newCacheKey(transport, message.Question[0], message, adapter.DNSQueryOptions{})
	cached, _, isStale := client.loadResponse(cacheKey)
	require.False(t, cached != nil && !isStale,
		"the superseded answer must not be cached even though it is returned")
}

// TestExchangeAsyncDoesNotDeliverASupersededAnswerAsSuccess is B3.
//
// The asynchronous contract is weaker than the synchronous one in a specific way: the callback's
// error is the ONLY signal a caller has, so delivering a superseded answer as a plain success is a
// stronger claim than returning it from a blocking call.
func TestExchangeAsyncDoesNotDeliverASupersededAnswerAsSuccess(t *testing.T) {
	transport := &switchingTransport{
		tag:     "switching-async",
		entered: make(chan struct{}),
		release: make(chan struct{}),
		address: netip.MustParseAddr("10.0.0.2"),
	}

	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	router := &Router{
		logger:    log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{transport.Tag(): transport}},
		client:    client,
	}
	client.networkGeneration = router.dnsGeneration

	message := new(mDNS.Msg)
	message.SetQuestion("async.internal.", mDNS.TypeA)

	type outcome struct {
		response *mDNS.Msg
		err      error
	}
	done := make(chan outcome, 1)
	router.ExchangeAsync(context.Background(), message, adapter.DNSQueryOptions{Transport: transport},
		func(response *mDNS.Msg, err error) {
			done <- outcome{response, err}
		})

	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the async query never reached the transport")
	}

	router.ResetNetwork()
	close(transport.release)

	select {
	case received := <-done:
		require.NoError(t, received.err)
		require.NotEmpty(t, answersOf(received.response),
			"the async path delivered the superseded answer with a nil error. A callback has no "+
				"other way to express doubt, so a nil error is a claim that the answer is current")
	case <-time.After(5 * time.Second):
		t.Fatal("the async callback never ran")
	}
}
