package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// The four cells of the environment + generation model, asserted together.
//
// The two mechanisms answer different questions and neither is sufficient alone:
//
//	environment pin   WHICH network an answer describes   (namespacing)
//	generation        WHETHER it still belongs to now     (ownership)
//
// This file asserts all four combinations so the model can be read as a whole rather than inferred
// from separate tests, and so a change to one cannot silently break a cell the other was covering.

// matrixManager supplies both an environment and a reset epoch.
type matrixManager struct {
	adapter.NetworkManager
	environment atomic.Uint64
	generation  atomic.Uint64
}

func (m *matrixManager) NetworkEnvironment() uint64     { return m.environment.Load() }
func (m *matrixManager) NetworkResetGeneration() uint64 { return m.generation.Load() }

// cellMessage builds the query message for a cell.
func cellMessage(name string) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion(name, mDNS.TypeA)
	return message
}

// TestEnvironmentGenerationMatrix is Part C.
func TestEnvironmentGenerationMatrix(t *testing.T) {
	// --- Cell 1: env A, transport A, generation G1 -> stored under A ---
	t.Run("cell1 same environment is stored", func(t *testing.T) {
		manager := &matrixManager{}
		manager.environment.Store(0xA)

		transport := &windowTransport{tag: "cell1", environment: []string{"wifi"}, address: netip.MustParseAddr("10.0.0.1")}
		router, client := newRouterWithWindowTransport(t, manager, transport)

		// The client reads the ROUTER's generation, so the manager's counter is mirrored onto it.
		router.networkGeneration.Store(manager.generation.Load())
		client.networkGeneration = router.dnsGeneration

		require.EqualValues(t, 0xA, client.transportEnvironment(transport))

		message := new(mDNS.Msg)
		message.SetQuestion("cell1.example.", mDNS.TypeA)
		key := client.newCacheKey(transport, message.Question[0], message, adapter.DNSQueryOptions{})

		_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
		require.NoError(t, err)

		cached, _, _ := client.loadResponse(key)
		require.NotNil(t, cached, "an answer from the current network is stored")
	})

	// --- Cell 2: env B published, transport still A, generation G1 -> NOT stamped B ---
	t.Run("cell2 new environment is not stamped on the old transport", func(t *testing.T) {
		manager := &matrixManager{}
		manager.environment.Store(0xA)

		transport := &windowTransport{tag: "cell2", environment: []string{"wifi"}, address: netip.MustParseAddr("10.0.0.1")}
		_, client := newRouterWithWindowTransport(t, manager, transport)

		// The network the transport serves, captured before the environment moves.
		require.EqualValues(t, 0xA, client.transportEnvironment(transport))
		keyBefore := client.newCacheKey(transport,
			mDNS.Question{Name: "cell2.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET},
			cellMessage("cell2.example."), adapter.DNSQueryOptions{})

		// NetworkManager publishes the new environment before it resets the DNS router.
		manager.environment.Store(0xB)
		require.EqualValues(t, 0xB, manager.NetworkEnvironment(),
			"the live environment has moved, so a live read would now stamp B")

		keyAfter := client.newCacheKey(transport,
			mDNS.Question{Name: "cell2.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET},
			cellMessage("cell2.example."), adapter.DNSQueryOptions{})

		require.EqualValues(t, keyBefore.environment, keyAfter.environment,
			"the cache key moved to the new environment while the query still travels over the old "+
				"network's transport - the misattribution the pin exists to prevent")
		require.EqualValues(t, 0xA, client.transportEnvironment(transport))
	})

	// --- Cell 3: transport actually serving B, no reset -> must not keep stamping A ---
	t.Run("cell3 transport rebound to the new network is stamped with it", func(t *testing.T) {
		manager := &matrixManager{}
		manager.environment.Store(0xA)

		transport := &windowTransport{tag: "cell3", environment: []string{"wifi"}, address: netip.MustParseAddr("10.0.0.1")}
		router, client := newRouterWithWindowTransport(t, manager, transport)

		require.EqualValues(t, 0xA, client.transportEnvironment(transport))

		// The transport really is replaced - which is what a reset does - and the environment moves
		// with it. The pin must follow the transport's lifecycle, not the clock.
		manager.environment.Store(0xB)
		router.ResetNetwork()

		message := new(mDNS.Msg)
		message.SetQuestion("cell3.example.", mDNS.TypeA)
		key := client.newCacheKey(transport, message.Question[0], message, adapter.DNSQueryOptions{})

		require.EqualValues(t, 0xB, client.transportEnvironment(transport),
			"a transport that has been reset serves the new network and must be stamped with it. "+
				"If the pin never moved, every answer from the new network would be filed under the "+
				"old namespace")
		require.NotEqualValues(t, 0xA, key.environment)
	})

	// --- Cell 4: same environment, generation G1 -> G2 -> late G1 response not stored ---
	t.Run("cell4 late response across a reset is not stored", func(t *testing.T) {
		manager := &matrixManager{}
		manager.environment.Store(0xA)

		transport := &windowTransport{tag: "cell4", environment: []string{"wifi"}, address: netip.MustParseAddr("10.0.0.1")}
		router, client := newRouterWithWindowTransport(t, manager, transport)

		// A key and a capture taken before the reset, at the same environment.
		message := new(mDNS.Msg)
		message.SetQuestion("cell4.example.", mDNS.TypeA)
		key := client.newCacheKey(transport, message.Question[0], message, adapter.DNSQueryOptions{})

		operation := &exchangeOperation{cacheKey: key}
		client.captureGeneration(operation)

		// The reset advances the generation. The environment pin also moves, so the key is compared
		// against the pin the transport now carries.
		router.ResetNetwork()

		require.False(t, client.generationStillCurrent(operation),
			"a response captured before the reset must not be storable after it, even though the "+
				"environment is unchanged - this is exactly the case the fingerprint cannot see")
	})
}
