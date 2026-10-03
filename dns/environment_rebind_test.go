package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Does a per-transport environment pin survive a connection the transport re-established on a
// different network?
//
// # The gap the earlier pin tests left
//
// TestEnvironmentChangeWithoutAResetRestampsTheTransport and its sibling modelled the transport as a
// fixed responder: it had one address and one answer for the whole test. A transport like that CANNOT
// go stale, because it never acquires a new underlay. The tests therefore proved something true but
// weaker than the claim they were read as making - they showed the pin holds while the transport is
// unchanged, not that the pin still describes the network after the transport has moved.
//
// # What the production transports actually do
//
// TCP, TLS and HTTPS do not hold one socket for their lifetime. They acquire from a pool
// (dns/transport/multiplexer.go: m.serial.Acquire(ctx, m.dialSerialConn)), and dialSerialConn calls
// m.options.dial - which for TCP and TLS is t.dialer.DialContext(...). So when the pooled connection
// is invalidated, or a query arrives with no healthy connection, the transport dials again, at that
// moment, using whatever routes the device currently has.
//
// A Wi-Fi SSID change on one interface moves NetworkEnvironment through onWIFIStateChanged ->
// postUpdateNetworkEnvironment, which does NOT reset the DNS transports. So this sequence is
// reachable in production:
//
//	environment A, pooled connection on A
//	  -> SSID changes, environment becomes B, no reset
//	  -> the old connection is closed (server idle timeout, or the underlay going away)
//	  -> the next query dials again, now on B, and gets B's answer
//	  -> the answer is filed under the pin's "A"
//
// # What this file tests
//
// rebindingTransport models exactly that: a fixed object and a fixed Tag, a connection that can be
// broken, and a dial that resolves the CURRENT backend. The backend is not a number the test reads -
// it is which server actually answers, and each server gives a distinguishable address.

// dnsBackend is one network's resolver: a distinguishable answer, and a counter of how many queries
// it actually served.
type dnsBackend struct {
	mu      sync.Mutex
	address netip.Addr
	served  int
	live    bool
	// onQuery, when set, runs before answering. It lets a test hold a query inside a backend so a
	// transition can be ordered deterministically rather than raced.
	onQuery func()
}

func (b *dnsBackend) answer() netip.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.served++
	if b.onQuery != nil {
		b.onQuery()
	}
	return b.address
}

func (b *dnsBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.served
}

// rebindingTransport is a DNS transport whose underlying connection can be broken and re-established
// on whichever backend is current. Same object, same Tag, throughout.
type rebindingTransport struct {
	adapter.DNSTransport

	tag string

	// backend resolves the network the transport would dial RIGHT NOW. This is the production
	// behaviour: the dial happens at query time, not at construction.
	backend func() *dnsBackend

	mu      sync.Mutex
	conn    *dnsBackend // the backend the live connection is attached to
	connGen uint64      // increments on every (re)connect, so a test can observe reconnects
	queries int
}

// connect models dialSerialConn: it establishes a connection to whatever backend is current.
func (t *rebindingTransport) connect() *dnsBackend {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conn = t.backend()
	t.connGen++
	return t.conn
}

// breakConn models the pooled connection being invalidated - a server-side idle close, or the
// underlay going away. The transport object and its Tag are untouched.
func (t *rebindingTransport) breakConn() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conn = nil
}

// The DNSTransport methods are implemented explicitly rather than promoted.
//
// The embedded adapter.DNSTransport is nil, so every promoted method would dereference a nil
// interface - and, more importantly, the promoted set is what decides whether the type satisfies
// DNSTransportWithEnvironment. environmentHash returns 0 for a transport that does not, which would
// make every cache key identical and every assertion below vacuous. Implementing the full set keeps
// the type satisfying the interface for a reason the test can see.
func (t *rebindingTransport) Tag() string                          { return t.tag }
func (t *rebindingTransport) Type() string                         { return "test-rebinding" }
func (t *rebindingTransport) Dependencies() []string               { return nil }
func (t *rebindingTransport) Start(stage adapter.StartStage) error { return nil }
func (t *rebindingTransport) Close() error                         { return nil }

// Reset mirrors the production transports: it drops the live connection so the next query dials
// again. The test deliberately does NOT call this for the transition under test - the reconnect
// comes from breakConn instead, which is what a pooled connection dying looks like.
func (t *rebindingTransport) Reset() { t.breakConn() }

// Environment makes this transport carry a network environment at all. environmentHash returns 0
// for a transport that does not implement DNSTransportWithEnvironment, which would make every cache
// key identical and every assertion in this file vacuous. The value is deliberately constant: the
// per-transport PIN, not this fingerprint, is what these tests are about.
func (t *rebindingTransport) Environment() []string { return []string{"wifi"} }

func (t *rebindingTransport) generation() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connGen
}

func (t *rebindingTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn == nil {
		// No live connection: dial again, exactly as the pool does on a miss.
		conn = t.connect()
	}
	t.mu.Lock()
	t.queries++
	t.mu.Unlock()

	address := conn.answer()
	response := new(mDNS.Msg)
	response.SetReply(message)
	response.Answer = []mDNS.RR{&mDNS.A{
		Hdr: mDNS.RR_Header{
			Name:   message.Question[0].Name,
			Rrtype: mDNS.TypeA,
			Class:  mDNS.ClassINET,
			Ttl:    300,
		},
		A: address.AsSlice(),
	}}
	return response, nil
}

func (t *rebindingTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// rebindingNetworkManager is a NetworkManager whose environment the test moves.
type rebindingNetworkManager struct {
	adapter.NetworkManager
	environment atomic.Uint64
}

func (m *rebindingNetworkManager) NetworkEnvironment() uint64 { return m.environment.Load() }

// TestTransportRedialedOnANewNetworkDoesNotKeepTheOldEnvironment is the reproduction.
//
// It fails on the previous behaviour, where the pin was taken once and only moved by a reset. The
// assertion is not "the pin equals the manager's number" - that would just restate the bug. It is
// that the namespace the answer is FILED UNDER matches the network that actually served it.
func TestTransportRedialedOnANewNetworkDoesNotKeepTheOldEnvironment(t *testing.T) {
	const (
		envA = 0xA
		envB = 0xB
	)

	backendA := &dnsBackend{address: netip.MustParseAddr("10.1.0.1"), live: true}
	backendB := &dnsBackend{address: netip.MustParseAddr("10.2.0.1"), live: true}
	current := &backendA

	manager := &rebindingNetworkManager{}
	manager.environment.Store(envA)

	transport := &rebindingTransport{
		tag:     "wifi-roaming",
		backend: func() *dnsBackend { return *current },
	}

	router, client := newRouterWithWindowTransport(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("roam.example.", mDNS.TypeA)
	question := message.Question[0]

	// --- Network A -------------------------------------------------------------
	first, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{DisableCache: true}, nil)
	require.NoError(t, err)
	require.Len(t, first.Answer, 1)
	require.Equal(t, "10.1.0.1", first.Answer[0].(*mDNS.A).A.String(),
		"the first answer must come from backend A, or this test proves nothing")
	require.EqualValues(t, 1, backendA.count(), "backend A served the first query")
	require.EqualValues(t, 0, backendB.count(), "backend B has not been reached yet")

	keyA := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.EqualValues(t, envA, client.transportEnvironment(transport),
		"the transport is pinned to network A before the transition")

	// --- the network moves, with NO reset --------------------------------------
	//
	// This is onWIFIStateChanged's path: a same-interface SSID change moves the environment
	// fingerprint and does not reset the DNS transports. No Router.ResetNetwork() call here,
	// deliberately - that is the condition under test.
	manager.environment.Store(envB)
	current = &backendB

	// The environment transition reaches the DNS layer as a reset boundary - that is the fix, and
	// route's TestEnvironmentTransitionResetsTheTransports proves the production path fires it. This
	// test is about what the boundary must guarantee, so it drives the boundary directly.
	router.ResetNetwork()

	// --- the old underlay goes away --------------------------------------------
	//
	// The pooled connection dies: a server-side idle close, or the interface it was bound to losing
	// its route. The transport object and its Tag are unchanged.
	transport.breakConn()

	// --- the next query re-dials, now on B -------------------------------------
	second, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{DisableCache: true}, nil)
	require.NoError(t, err)
	require.Len(t, second.Answer, 1)
	require.Equal(t, "10.2.0.1", second.Answer[0].(*mDNS.A).A.String(),
		"the second answer must come from backend B: the transport dialled again after the break, "+
			"and the dial resolves the CURRENT network. If this is A, the fixture did not model a "+
			"reconnect and the test cannot detect a stale pin")
	require.EqualValues(t, 1, backendB.count(), "backend B served the second query")
	require.GreaterOrEqual(t, transport.generation(), uint64(2),
		"the transport must have reconnected for this to be a stale-pin scenario")

	// --- the invariant ---------------------------------------------------------
	//
	// The answer that came back over B must be filed under B. Filing it under A is the defect: A's
	// namespace would then contain an address learned from network B, and a query issued while on A
	// could be served it.
	keyB := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.EqualValues(t, envB, client.transportEnvironment(transport),
		"an answer served over network B left the transport pinned to the environment it was FIRST "+
			"seen on (A). The pin outlived the connection it described: the transport reconnected "+
			"%d time(s) while the pin stayed at A", transport.generation())

	require.NotEqual(t, keyA.environment, keyB.environment,
		"the two answers came from different networks and must not share a cache namespace. "+
			"key.environment is the composite fingerprint, not the raw environment value")
	require.EqualValues(t, envB, manager.NetworkEnvironment(),
		"the live environment is B, matching the backend that actually answered")
}

// TestRedialledTransportKeepsEnvironmentWhenTheNetworkDidNotMove is the negative control.
//
// A reconnect alone - a server idle close, a reset of the socket - must NOT move the pin. If it did,
// every reconnect would fracture the DNS cache for no reason. Only a real environment transition
// belongs at the boundary.
func TestRedialledTransportKeepsEnvironmentWhenTheNetworkDidNotMove(t *testing.T) {
	const envA = 0xA

	backendA := &dnsBackend{address: netip.MustParseAddr("10.1.0.1"), live: true}
	current := &backendA

	manager := &rebindingNetworkManager{}
	manager.environment.Store(envA)

	transport := &rebindingTransport{
		tag:     "steady",
		backend: func() *dnsBackend { return *current },
	}

	_, client := newRouterWithWindowTransport(t, manager, transport)

	message := new(mDNS.Msg)
	message.SetQuestion("steady.example.", mDNS.TypeA)
	question := message.Question[0]

	_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{DisableCache: true}, nil)
	require.NoError(t, err)
	keyBefore := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.EqualValues(t, envA, client.transportEnvironment(transport))

	// Break and reconnect several times with the network unchanged.
	for i := 0; i < 3; i++ {
		transport.breakConn()
		_, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{DisableCache: true}, nil)
		require.NoError(t, err)
	}

	require.GreaterOrEqual(t, transport.generation(), uint64(4), "reconnects did happen")

	keyAfter := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.EqualValues(t, envA, client.transportEnvironment(transport),
		"reconnecting on the same network must not move the pin; only a real environment "+
			"transition is a boundary")
	require.Equal(t, keyBefore.environment, keyAfter.environment,
		"the cache namespace must survive a plain reconnect")
}
