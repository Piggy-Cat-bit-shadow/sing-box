package dns

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Tests for network-generation isolation of the exact DNS cache.
//
// # The defect these pin
//
// A query captures its environment fingerprint when it is SENT. If nothing is known yet the
// fingerprint is 0. The response is stored later, and finishCacheKey accepted it whenever the
// captured value was 0:
//
//	if environment == key.environment || key.environment == 0 {
//	    key.environment = environment
//
// So a query sent before the network was known, whose response arrives AFTER a network change, is
// relabelled with the NEW network's fingerprint and stored in its cache - a stale answer from one
// network presented as a fresh answer about another.
//
// The reverse-mapping path already has a generation guard; the exact cache does not. Fixing one is
// not evidence about the other, which is why this is verified independently.

// environmentNetworkManager is a NetworkManager whose environment can be changed.
type environmentNetworkManager struct {
	adapter.NetworkManager
	environment atomic.Uint64
}

func (m *environmentNetworkManager) NetworkEnvironment() uint64 { return m.environment.Load() }

// environmentTransport is a DNS transport that participates in environment hashing.
type environmentTransport struct {
	adapter.DNSTransport
	tag         string
	environment []string
}

func (t *environmentTransport) Tag() string                          { return t.tag }
func (t *environmentTransport) Type() string                         { return "environment" }
func (t *environmentTransport) Environment() []string                { return t.environment }
func (t *environmentTransport) Start(stage adapter.StartStage) error { return nil }
func (t *environmentTransport) Close() error                         { return nil }

// newEnvironmentClient returns a client whose environment can be driven by the test.
//
// The network manager arrives through the context, which is how the client reads it in production.
func newEnvironmentClient(t *testing.T) (*Client, *environmentNetworkManager) {
	t.Helper()
	networkManager := &environmentNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	client := NewClient(ClientOptions{
		Context: ctx,
		Logger:  log.NewNOPFactory().NewLogger("dns-cache-test"),
	})
	// The network manager is read during Start, which is where production reads it.
	client.Start()
	return client, networkManager
}

// TestLateResponseFromUnknownEnvironmentIsNotRelabelled is the release blocker.
//
// A query sent while the environment is unknown must NOT have its response stored under whatever
// environment happens to be current when the response arrives.
func TestLateResponseFromUnknownEnvironmentIsNotRelabelled(t *testing.T) {
	client, networkManager := newEnvironmentClient(t)
	transport := &environmentTransport{tag: "env"}

	question := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	// The query was SENT before any environment was known.
	key := dnsCacheKey{
		Question:     question,
		transportTag: transport.Tag(),
		environment:  0,
	}

	// The network changes before the response is processed.
	networkManager.environment.Store(0xA1B2C3D4)

	finished, storable := client.finishCacheKey(transport, key)

	require.False(t, storable,
		"a response whose query captured an UNKNOWN environment must not be stored once the "+
			"environment is known. Doing so relabels an answer produced on the old network with the "+
			"new network's identity, so a later query on the new network is answered from a stale "+
			"cache entry that was never true there")

	require.EqualValues(t, 0, finished.environment,
		"and the key must not have been rewritten with the new environment")
}

// TestSameEnvironmentResponseIsStorable is the positive control.
//
// The guard must not disable caching for the ordinary case.
func TestSameEnvironmentResponseIsStorable(t *testing.T) {
	client, networkManager := newEnvironmentClient(t)
	transport := &environmentTransport{tag: "env"}
	networkManager.environment.Store(0x1234)

	question := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := dnsCacheKey{
		Question:     question,
		transportTag: transport.Tag(),
		environment:  networkManager.environment.Load(),
	}

	finished, storable := client.finishCacheKey(transport, key)
	require.True(t, storable, "an unchanged environment must still cache")
	require.EqualValues(t, 0x1234, finished.environment)
}
