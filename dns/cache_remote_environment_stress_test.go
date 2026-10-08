package dns

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Long-run stability for the network-scoped DNS cache.
//
// The isolation between networks is only real if it holds for EVERY reset, not for
// the first one: a namespace that is computed once and then reused, a cache that
// quietly grows a new generation of goroutines per reset, or a stale entry that
// survives because its key stopped changing would all look correct in a single
// transition.
//
// These are count-based assertions (queries, goroutines, answers), not timings.
// ---------------------------------------------------------------------------

// waitForGoroutines waits for the goroutine count to settle back to a baseline.
func waitForGoroutines(t *testing.T, baseline int, tolerance int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline+tolerance {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: goroutines before=%d after=%d; work outlived the cycle", what, baseline, current)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRepeatedNetworkResetsKeepTheIsolationAndDoNotLeak drives the transition
// boundary a hundred times. Every iteration must resolve on ITS network, the cache
// must not answer from the previous one, and the goroutine count must come back.
func TestRepeatedNetworkResetsKeepTheIsolationAndDoNotLeak(t *testing.T) {
	manager := &windowNetworkManager{}
	manager.environment.Store(0xA)
	transport := newRemoteTransport("remote-doh", "10.1.0.1")
	router, client := newRouterWithWindowTransport(t, manager, transport)

	message := remoteQueryFor(t, "reset-cycle.example.")

	// Warm up so the first measurement is not the first-ever exchange.
	response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, transport.address, remoteResponseAddress(response))
	require.Equal(t, "10.1.0.1", transport.address.String())

	baseline := runtime.NumGoroutine()
	const cycles = 100
	for cycle := 0; cycle < cycles; cycle++ {
		address := fmt.Sprintf("10.%d.0.1", cycle%200+2)
		manager.environment.Store(uint64(0x1000 + cycle))
		transport.setAnswer(address, mDNS.RcodeSuccess)
		router.ResetNetwork()

		response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
		require.NoError(t, err, "cycle %d", cycle)
		require.Equal(t, address, remoteResponseAddress(response).String(),
			"cycle %d: the answer served on this network is not this network's answer", cycle)
	}
	waitForGoroutines(t, baseline, 4, fmt.Sprintf("%d network resets", cycles))
}

// TestRepeatedResetsWithinOneNetworkKeepTheNamespace pins the other side of the
// isolation: a reset that does not change the NETWORK must not throw the namespace
// away. The namespace is the network fingerprint, not the reset counter, which is
// what keeps a reset for an unrelated reason - a memory-pressure release, a
// transport restart - from turning into a DNS storm one lookup deep.
//
// A hundred reset-and-resolve cycles on one network must therefore cost exactly one
// upstream query, and must not grow the goroutine count.
func TestRepeatedResetsWithinOneNetworkKeepTheNamespace(t *testing.T) {
	manager := &windowNetworkManager{}
	manager.environment.Store(0xA)
	transport := newRemoteTransport("remote-doh", "10.1.0.1")
	router, client := newRouterWithWindowTransport(t, manager, transport)

	message := remoteQueryFor(t, "stable-network.example.")
	response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, "10.1.0.1", remoteResponseAddress(response).String())
	require.EqualValues(t, 1, transport.queries.Load())

	baseline := runtime.NumGoroutine()
	const cycles = 100
	for cycle := 0; cycle < cycles; cycle++ {
		// The same network: the environment does not move, so the reset re-pins every
		// transport to the value it already had.
		router.ResetNetwork()
		response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
		require.NoError(t, err, "cycle %d", cycle)
		require.Equal(t, "10.1.0.1", remoteResponseAddress(response).String(), "cycle %d", cycle)
	}
	require.EqualValues(t, 1, transport.queries.Load(),
		"%d resets within one network must not invalidate the namespace", cycles)
	waitForGoroutines(t, baseline, 4, fmt.Sprintf("%d same-network resets", cycles))
}
