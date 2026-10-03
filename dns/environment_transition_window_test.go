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

// The window between the environment fingerprint changing and the DNS routers resetting.
//
// # The ordering, from NetworkManager.updateInterface
//
//	UpdateWIFIState
//	updateNetworkEnvironment()   <- the fingerprint becomes B here
//	ResetNetwork()               <- the generation advances and transports reset here
//	    CloseAll, InterfaceUpdated..., router.ResetNetwork()
//
// resetRunAccess is held for the whole of updateInterface, so the two steps cannot interleave with
// each other. Nothing, however, stops an ordinary DNS query from another goroutine running in
// between: updateInterface is not a stop-the-world barrier, and the DNS client it exposes is live.
//
// # What makes that dangerous
//
// The environment fingerprint is read when the CACHE KEY IS BUILT, which is at request issue:
//
//	environment: c.environmentHash(transport)
//
// In the window, NetworkEnvironment() already reports B while the generation is still G1 and the
// transport pool still holds the previous network's sockets. A query issued there is therefore
//
//	stamped with environment B,
//	carried over a connection belonging to network A,
//	and stored under generation G1.
//
// The result is a cache entry that claims to describe network B while the answer was produced on
// network A - and because it is stamped B, it is served to every later query on the new network for
// the remainder of its TTL. Neither guard catches it: the generation matches (nothing advanced yet)
// and the fingerprint matches (the answer was stamped with the current value).

// windowNetworkManager is a NetworkEnvironment whose value the test moves.
type windowNetworkManager struct {
	adapter.NetworkManager
	environment atomic.Uint64
}

func (m *windowNetworkManager) NetworkEnvironment() uint64 { return m.environment.Load() }

// windowTransport participates in environments and answers immediately, recording each query.
type windowTransport struct {
	adapter.DNSTransport
	tag string

	environment []string
	address     netip.Addr
	queries     atomic.Int32
}

func (t *windowTransport) Type() string                                               { return "window" }
func (t *windowTransport) Tag() string                                                { return t.tag }
func (t *windowTransport) Dependencies() []string                                     { return nil }
func (t *windowTransport) Environment() []string                                      { return t.environment }
func (t *windowTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (t *windowTransport) Close() error                                               { return nil }
func (t *windowTransport) Reset()                                                     {}

func (t *windowTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
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

func (t *windowTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// TestQueryCannotBeStampedWithTheNewEnvironmentBeforeTheReset is A1.
//
// The fingerprint is moved to B while the generation is still G1 and the transport is still the one
// serving network A. A query issued in that window must not produce a cache entry claiming to
// describe network B, because the answer was produced on network A.
func TestQueryCannotBeStampedWithTheNewEnvironmentBeforeTheReset(t *testing.T) {
	manager := &windowNetworkManager{}

	transport := &windowTransport{
		tag:         "window",
		environment: []string{"wifi"},
		address:     netip.MustParseAddr("10.0.0.1"),
	}

	// Network A.
	manager.environment.Store(0xA)

	router, client := newRouterWithWindowTransport(t, manager, transport)

	// The transport's first observation pins it to network A.
	fingerprintA := client.environmentHash(transport)
	require.EqualValues(t, 0xA, client.transportEnvironment(transport),
		"the pin must record the network the transport was established on")

	// The environment changes, exactly as updateNetworkEnvironment performs it: the fingerprint is
	// published first, and the DNS router has not been told yet.
	manager.environment.Store(0xB)

	// A query issued NOW, in the window, goes out over network A's transport. Its cache key must
	// still say A, because A is the network the answer comes from.
	message := new(mDNS.Msg)
	message.SetQuestion("window.example.", mDNS.TypeA)
	question := message.Question[0]
	key := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})

	require.EqualValues(t, fingerprintA, key.environment,
		"the key was stamped with the NEW environment while the query travels over the OLD network's "+
			"transport. The answer describes network A, but every later query on network B would be "+
			"served it for the rest of its TTL because the stamp matched")

	_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	// The answer is stored under A, so it cannot be reached from B.
	cached, _, isStale := client.loadResponse(key)
	require.NotNil(t, cached, "the answer was stored under the network it actually came from")
	require.False(t, isStale)

	// After the reset the transport serves the new network, so the pin moves with it.
	router.ResetNetwork()
	require.EqualValues(t, 0xB, client.transportEnvironment(transport),
		"the reset must re-pin the transport to the network it now serves")

	// And the entry stored under A is not served to a query on B.
	keyB := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.NotEqual(t, key.environment, keyB.environment)
	afterReset, _, _ := client.loadResponse(keyB)
	require.Nil(t, afterReset,
		"an answer produced on network A was served to a query on network B")
}

// listingTransportManager lists the transports ResetNetwork must reset.
type listingTransportManager struct {
	*fakeDNSTransportManager
	transports []adapter.DNSTransport
}

func (m *listingTransportManager) Transports() []adapter.DNSTransport { return m.transports }

// newRouterWithWindowTransport builds a Router and its concrete client around one transport.
func newRouterWithWindowTransport(t *testing.T, manager adapter.NetworkManager, transport adapter.DNSTransport) (*Router, *Client) {
	t.Helper()
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
	options := option.DNSOptions{}
	router, err := NewRouter(ctx, log.NewNOPFactory(), options)
	require.NoError(t, err)

	concrete, isConcrete := router.client.(*Client)
	require.True(t, isConcrete)
	router.concreteClient = concrete
	// NewRouter does not start the client, and Start is what builds the caches AND re-reads the
	// network manager from the context. Starting first, then injecting the manager, means the
	// injected one is not immediately overwritten.
	concrete.Start()
	concrete.networkManager = manager
	// The transport manager is replaced with one that yields the test transport as the default AND
	// lists it, which is what Router.ResetNetwork iterates to reset the transports.
	router.transport = &listingTransportManager{
		fakeDNSTransportManager: &fakeDNSTransportManager{
			transports:       map[string]adapter.DNSTransport{transport.Tag(): transport},
			defaultTransport: transport,
		},
		transports: []adapter.DNSTransport{transport},
	}
	return router, concrete
}

// TestOldEnvironmentNamespaceIsNotReadUnderTheNewFingerprint is Part F.
//
// The complement of the misattribution: an entry written under one environment must not be served
// after the transport has been re-pinned to another. This is the half the fingerprint already
// provides, asserted so the pin cannot quietly turn the cache into one namespace.
func TestOldEnvironmentNamespaceIsNotReadUnderTheNewFingerprint(t *testing.T) {
	manager := &windowNetworkManager{}
	manager.environment.Store(0xA)

	transport := &windowTransport{
		tag:         "namespace",
		environment: []string{"wifi"},
		address:     netip.MustParseAddr("10.0.0.2"),
	}

	router, client := newRouterWithWindowTransport(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("namespace.example.", mDNS.TypeA)
	question := message.Question[0]

	// An answer learned while the transport serves network A.
	keyA := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	cachedA, _, _ := client.loadResponse(keyA)
	require.NotNil(t, cachedA, "the answer is stored against network A")

	// The network changes and the reset re-pins the transport.
	manager.environment.Store(0xB)
	router.ResetNetwork()

	keyB := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.NotEqual(t, keyA.environment, keyB.environment,
		"the two networks must map to different cache namespaces")

	cached, _, _ := client.loadResponse(keyB)
	require.Nil(t, cached,
		"an answer from network A was served under network B's namespace, which would mean the "+
			"environment is not namespacing the cache at all")
}
