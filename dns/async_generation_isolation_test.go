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
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// The asynchronous exchange must not write any cache layer across a network change.
//
// # Why the synchronous result is not sufficient
//
// Exchange and ExchangeAsync reach the store through different code: the synchronous one runs in the
// caller's goroutine, the asynchronous one finishes from the transport's callback. A guard that only
// holds on one of them is a half-guard, and the asynchronous path is the one a control plane or a
// background refresh actually uses.
//
// All three stores are exercised, because they are separate writes with separate conditions:
// the exact entry, the name-wide NXDOMAIN verdict, and the persistent mirror.

// asyncGatedTransport blocks every exchange until released, and answers with a configurable record.
type asyncGatedTransport struct {
	adapter.DNSTransport
	tag string

	entered chan struct{}
	release chan struct{}
	once    sync.Once

	// nxdomain makes the answer a name-wide negative one.
	nxdomain bool
	address  netip.Addr
	queries  atomic.Int32
}

func (t *asyncGatedTransport) Type() string                                               { return "async-gated" }
func (t *asyncGatedTransport) Tag() string                                                { return t.tag }
func (t *asyncGatedTransport) Dependencies() []string                                     { return nil }
func (t *asyncGatedTransport) Environment() []string                                      { return []string{"wifi"} }
func (t *asyncGatedTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (t *asyncGatedTransport) Close() error                                               { return nil }
func (t *asyncGatedTransport) Reset()                                                     {}

func (t *asyncGatedTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	t.once.Do(func() { close(t.entered) })
	select {
	case <-t.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	response := new(mDNS.Msg)
	response.SetReply(message)
	if len(message.Question) == 0 {
		return response, nil
	}
	question := message.Question[0]
	if t.nxdomain {
		response.Rcode = mDNS.RcodeNameError
		response.Ns = append(response.Ns, &mDNS.SOA{
			Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeSOA,
				Class: mDNS.ClassINET, Ttl: 300},
			Ns: "ns.example.", Mbox: "hostmaster.example.", Serial: 1,
			Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
		})
		return response, nil
	}
	response.Answer = append(response.Answer, &mDNS.A{
		Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA,
			Class: mDNS.ClassINET, Ttl: 300},
		A: t.address.AsSlice(),
	})
	return response, nil
}

func (t *asyncGatedTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// asyncCountingStore counts persistent saves.
type asyncCountingStore struct {
	adapter.DNSCacheStore
	saves atomic.Int32
}

func (s *asyncCountingStore) SaveDNSCacheAsync(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time, logger logger.Logger) {
	s.saves.Add(1)
}

func (s *asyncCountingStore) SaveDNSCache(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time) error {
	s.saves.Add(1)
	return nil
}

func (s *asyncCountingStore) LoadDNSCache(transportName string, qName string, qType uint16) ([]byte, time.Time, bool) {
	return nil, time.Time{}, false
}

func (s *asyncCountingStore) ClearDNSCache() error { return nil }

// TestClientExchangeAsyncWritesNoCacheLayerAcrossAGeneration is item 1.
//
// The callback is held until the response is genuinely in flight, the generation advances, and only
// then is the response released. Nothing from it may reach the exact cache, the NXDOMAIN cache, or
// the persistent store.
func TestClientExchangeAsyncWritesNoCacheLayerAcrossAGeneration(t *testing.T) {
	store := &asyncCountingStore{}
	var generation atomic.Uint64

	networkManager := &generationNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	client := NewClient(ClientOptions{
		Context:           ctx,
		Logger:            log.NewNOPFactory().NewLogger("dns-async-generation"),
		NetworkGeneration: generation.Load,
		DNSCache:          func() adapter.DNSCacheStore { return store },
	})
	client.Start()

	transport := &asyncGatedTransport{
		tag:      "async-blocking",
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		address:  netip.MustParseAddr("10.0.0.1"),
		nxdomain: true,
	}

	message := new(mDNS.Msg)
	message.SetQuestion("async-cross.example.", mDNS.TypeA)

	callbackDone := make(chan error, 1)
	client.ExchangeAsync(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil,
		func(response *mDNS.Msg, err error) { callbackDone <- err })

	// Barrier: the query is inside the transport, at generation 0.
	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the async query never reached the transport")
	}

	// The network changes while the query is in flight.
	generation.Add(1)

	close(transport.release)
	select {
	case <-callbackDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the async callback never ran")
	}

	// Let any asynchronous persistent write settle, then assert it did not happen.
	time.Sleep(200 * time.Millisecond)

	require.EqualValues(t, 0, store.saves.Load(),
		"the asynchronous path mirrored a superseded answer into the persistent cache")

	// The name-wide NXDOMAIN verdict, checked FIRST.
	//
	// It must be checked before any probe exchange: a probe issued now runs at the CURRENT
	// generation, so it would legitimately record its own verdict and the assertion could not tell
	// the two apart.
	question := message.Question[0]
	nxdomainKey := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	negative, hit := client.loadNXDomain(nxdomainKey, question, message.Id)
	require.False(t, hit && negative != nil,
		"the asynchronous path recorded a name-wide NXDOMAIN verdict from a superseded answer, so "+
			"every other record type for that name now inherits it")

	// The exact cache: probe through a fresh exchange, counting upstream queries. The probe runs at
	// the current generation, so if it reaches upstream then nothing was stored by the async path.
	queriesBefore := transport.queries.Load()
	_, probeErr := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, probeErr)
	require.Greater(t, transport.queries.Load(), queriesBefore,
		"the asynchronous path stored the superseded answer in the exact cache, so the next query "+
			"was answered from it instead of upstream")
}
