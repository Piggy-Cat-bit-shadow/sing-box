package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TD-008/013: the DNS cache must not cross networks for REMOTE transports.
//
// # The defect this pins
//
// The environment fingerprint was applied only to transports that implement
// adapter.DNSTransportWithEnvironment - local, mDNS and DHCP - and returned 0 for
// every other one. Zero is not a namespace: the exact cache key, the NXDOMAIN
// verdict key, the RDRC key and the persistent cache name were then identical on
// every network, so an answer, a negative verdict or a rejection learned on one
// network was served on the next one. Every transport a user actually resolves
// through - UDP, TCP, TLS, HTTPS, QUIC, H3, the platform transports - is in that
// set.
//
// The pinning machinery already covered all of them: Router.ResetNetwork re-pins
// every known transport, and the manager publishes a new fingerprint on every real
// transition. The fingerprint was simply not consulted for them.
//
// # What these tests assert
//
// Counts of upstream queries and the identity of the answer, never elapsed time.
// ---------------------------------------------------------------------------

// remoteTransport is a transport of the kind every upstream transport is: it has no
// Environment() method, so it is NOT an adapter.DNSTransportWithEnvironment.
type remoteTransport struct {
	adapter.DNSTransport
	tag string

	mu      sync.Mutex
	address netip.Addr
	rcode   int

	queries atomic.Int32

	// hold, when non-nil, is waited on before a response is produced.
	hold chan struct{}
}

func newRemoteTransport(tag string, address string) *remoteTransport {
	transport := &remoteTransport{tag: tag}
	if address != "" {
		transport.address = netip.MustParseAddr(address)
	}
	return transport
}

func (t *remoteTransport) Type() string                                               { return "remote" }
func (t *remoteTransport) Tag() string                                                { return t.tag }
func (t *remoteTransport) Dependencies() []string                                     { return nil }
func (t *remoteTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (t *remoteTransport) Close() error                                               { return nil }
func (t *remoteTransport) Reset()                                                     {}

func (t *remoteTransport) setAnswer(address string, rcode int) {
	t.mu.Lock()
	if address == "" {
		t.address = netip.Addr{}
	} else {
		t.address = netip.MustParseAddr(address)
	}
	t.rcode = rcode
	t.mu.Unlock()
}

func (t *remoteTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	// The answer this query will produce is decided when the query ARRIVES, not when it
	// returns: a held query must describe the network it was measured on even if the test
	// moves that network underneath it.
	t.mu.Lock()
	address, rcode := t.address, t.rcode
	t.mu.Unlock()
	if t.hold != nil {
		select {
		case <-t.hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	response := new(mDNS.Msg)
	response.SetReply(message)
	response.Rcode = rcode
	if len(message.Question) > 0 {
		question := message.Question[0]
		switch rcode {
		case mDNS.RcodeSuccess:
			if address.IsValid() {
				response.Answer = append(response.Answer, &mDNS.A{
					Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA,
						Class: mDNS.ClassINET, Ttl: 300},
					A: address.AsSlice(),
				})
			}
		case mDNS.RcodeNameError:
			// A name-wide verdict is only usable when the answer carries the zone's
			// negative TTL, so a resolvable fixture must send the SOA with it.
			response.Ns = append(response.Ns, &mDNS.SOA{
				Hdr: mDNS.RR_Header{Name: "example.", Rrtype: mDNS.TypeSOA,
					Class: mDNS.ClassINET, Ttl: 300},
				Ns: "ns.example.", Mbox: "hostmaster.example.", Serial: 1,
				Refresh: 60, Retry: 60, Expire: 60, Minttl: 300,
			})
		}
	}
	return response, nil
}

func (t *remoteTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// responseAddress returns the A record an answer carries, or an invalid address.
func remoteResponseAddress(response *mDNS.Msg) netip.Addr {
	if response == nil {
		return netip.Addr{}
	}
	for _, answer := range response.Answer {
		if record, isA := answer.(*mDNS.A); isA {
			address, _ := netip.AddrFromSlice(record.A)
			return address
		}
	}
	return netip.Addr{}
}

func remoteQueryFor(t *testing.T, name string) *mDNS.Msg {
	t.Helper()
	message := new(mDNS.Msg)
	message.SetQuestion(name, mDNS.TypeA)
	return message
}

// TestRemoteTransportCacheDoesNotCrossNetworks is the primary gate: an answer cached
// on one network must not be served on the next one, and repeated queries on the
// SAME network must still hit the cache.
func TestRemoteTransportCacheDoesNotCrossNetworks(t *testing.T) {
	manager := &windowNetworkManager{}
	manager.environment.Store(0xA)
	transport := newRemoteTransport("remote-doh", "10.1.0.1")
	router, client := newRouterWithWindowTransport(t, manager, transport)

	message := remoteQueryFor(t, "split-horizon.example.")

	response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.1.0.1"), remoteResponseAddress(response))
	require.EqualValues(t, 1, transport.queries.Load())

	// Same network: the second query is answered from the cache, which is the behaviour
	// that must not regress.
	response, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.1.0.1"), remoteResponseAddress(response))
	require.EqualValues(t, 1, transport.queries.Load(), "a repeat query on the same network must be a cache hit")

	// The network changes. Production does exactly this: the manager publishes the new
	// fingerprint and the reset re-pins every transport.
	manager.environment.Store(0xB)
	transport.setAnswer("10.2.0.1", mDNS.RcodeSuccess)
	router.ResetNetwork()

	response, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, transport.queries.Load(),
		"the answer cached on the previous network was served on the new one")
	require.Equal(t, netip.MustParseAddr("10.2.0.1"), remoteResponseAddress(response),
		"the answer on the new network must come from the new network")
}

// TestRemoteTransportNegativeVerdictDoesNotCrossNetworks is the NXDOMAIN half: a name
// that does not exist on one network may exist on the next, and the name-wide negative
// verdict must not answer for it.
func TestRemoteTransportNegativeVerdictDoesNotCrossNetworks(t *testing.T) {
	manager := &windowNetworkManager{}
	manager.environment.Store(0xA)
	transport := newRemoteTransport("remote-doh", "")
	transport.setAnswer("", mDNS.RcodeNameError)
	router, client := newRouterWithWindowTransport(t, manager, transport)

	message := remoteQueryFor(t, "hotspot-only.example.")

	response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
	require.EqualValues(t, 1, transport.queries.Load())

	// Same network: the verdict is reused, one query per name rather than per record type.
	response, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
	require.EqualValues(t, 1, transport.queries.Load(), "the negative verdict must be reused on the same network")

	// The name resolves on the next network.
	manager.environment.Store(0xB)
	transport.setAnswer("10.3.0.1", mDNS.RcodeSuccess)
	router.ResetNetwork()

	response, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, transport.queries.Load(),
		"the NXDOMAIN verdict from the previous network suppressed the query on the new one")
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode, "the name exists on this network")
	require.Equal(t, netip.MustParseAddr("10.3.0.1"), remoteResponseAddress(response))
}

// TestRemoteTransportPersistentAndRDRCNamespacesFollowTheNetwork pins the two keys
// that outlive the process: the persistent cache name and the RDRC namespace.
func TestRemoteTransportPersistentAndRDRCNamespacesFollowTheNetwork(t *testing.T) {
	manager := &windowNetworkManager{}
	manager.environment.Store(0xA)
	transport := newRemoteTransport("remote-doh", "10.1.0.1")
	router, client := newRouterWithWindowTransport(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("namespaced.example.", mDNS.TypeA)
	question := message.Question[0]

	before := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.NotZero(t, before.environment,
		"a remote transport must carry the network it serves, or its cache has no namespace")
	require.Contains(t, before.persistentName(), "\x01",
		"the persistent cache name must carry the environment")

	manager.environment.Store(0xB)
	router.ResetNetwork()

	after := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.NotEqual(t, before.environment, after.environment)
	require.NotEqual(t, before.persistentName(), after.persistentName())
	require.NotEqual(t, rdrcNamespace(transport.Tag(), before.environment),
		rdrcNamespace(transport.Tag(), after.environment),
		"an RDRC verdict measured on one network must not be readable on another")
	require.NotEqual(t, transport.Tag(), rdrcNamespace(transport.Tag(), after.environment),
		"an empty namespace is the defect: the verdict would be shared by every network")
}

// TestRemoteTransportInFlightAnswerIsNotStoredOnTheNewNetwork is the write side: a
// query issued on network A whose answer arrives after the transition must not be
// filed under network B.
func TestRemoteTransportInFlightAnswerIsNotStoredOnTheNewNetwork(t *testing.T) {
	manager := &windowNetworkManager{}
	manager.environment.Store(0xA)
	transport := newRemoteTransport("remote-doh", "10.1.0.1")
	hold := make(chan struct{})
	transport.hold = hold
	router, client := newRouterWithWindowTransport(t, manager, transport)

	message := remoteQueryFor(t, "in-flight.example.")
	done := make(chan *mDNS.Msg, 1)
	go func() {
		response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
		if err != nil {
			done <- nil
			return
		}
		done <- response
	}()

	// Wait until the query is inside the transport, then move the network under it.
	require.Eventually(t, func() bool { return transport.queries.Load() > 0 }, time.Second, time.Millisecond)
	manager.environment.Store(0xB)
	transport.setAnswer("10.2.0.1", mDNS.RcodeSuccess)
	router.ResetNetwork()
	close(hold)

	response := <-done
	require.NotNil(t, response, "the in-flight answer is still delivered to the caller that asked")
	require.Equal(t, netip.MustParseAddr("10.1.0.1"), remoteResponseAddress(response),
		"the answer describes the network it was measured on")

	// The next query must go upstream: nothing about network A may be readable on B.
	before := transport.queries.Load()
	response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Greater(t, transport.queries.Load(), before,
		"an answer produced on the previous network was stored under the new one")
	require.Equal(t, netip.MustParseAddr("10.2.0.1"), remoteResponseAddress(response))
}
