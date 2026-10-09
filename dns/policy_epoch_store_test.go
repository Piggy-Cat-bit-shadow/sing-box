package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// TestTheStalePolicyAnswerIsDeliveredButNotRecorded pins the two halves of the fix separately, so a
// failure says WHICH half broke rather than only that the end-to-end answer was wrong.
//
// The contract, stated once:
//
//   - the caller that asked gets its answer. A DNS answer is a dated observation about a name, and the
//     exchange was legitimate; cancelling in-flight resolutions on a mode switch would turn a
//     controller click into failed lookups;
//   - the answer is NOT recorded, because the routing decision behind it no longer holds.
//
// It also asserts the epoch moved, because a guard that is never armed passes every other assertion in
// this file for the wrong reason - the first run of this test reported exactly that, with the client's
// PolicyGeneration left nil by its own harness.
func TestTheStalePolicyAnswerIsDeliveredButNotRecorded(t *testing.T) {
	harness := newModeSwitchHarness(t, "shared", true)
	client := harness.router.client.(*Client)

	require.NotNil(t, client.policyGeneration,
		"the client must be given a policy epoch, or the guard is inert and every other assertion here "+
			"would pass for the wrong reason")
	epochBefore := harness.router.policyEpoch()

	const name = "store-declined.example.org."
	message, metadata := modeTestMessage(name)

	firstCtx := adapter.WithContext(context.Background(), metadata)
	firstResult := make(chan netip.Addr, 1)
	go func() {
		response, err := harness.router.Exchange(firstCtx, message, adapter.DNSQueryOptions{})
		require.NoError(t, err)
		firstResult <- modeTestAddress(t, response, nil)
	}()

	select {
	case <-harness.transport.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the query never reached its transport, so nothing was in flight")
	}

	harness.manager.SetMode("Global")
	require.Greater(t, harness.router.policyEpoch(), epochBefore,
		"the mode switch must advance the policy epoch: SetMode's ClearCache is the only path that can")

	close(harness.transport.release)
	delivered := <-firstResult
	require.Equal(t, netip.MustParseAddr("192.0.2.10"), delivered,
		"the caller that asked must still receive its answer")

	// Half one: the answer was delivered.
	// Half two: it was not recorded.
	question := message.Question[0]
	key := client.newCacheKey(harness.transport, question, message, adapter.DNSQueryOptions{})
	_, loaded := client.cache.Get(key)
	require.False(t, loaded,
		"an answer captured under the previous policy epoch must not be stored: the server that "+
			"produced it is the one the switch moved away from")

	// The observable consequence: the new mode asks its OWN server instead of being served the retired
	// answer. The address changes before that query, so the answer it gets is unmistakably the new
	// policy's.
	harness.setAddress(netip.MustParseAddr("192.0.2.20"))
	secondCtx := adapter.WithContext(context.Background(), metadata)
	before := harness.transport.queryCount.Load()
	secondResponse, secondErr := harness.router.Exchange(secondCtx, message, adapter.DNSQueryOptions{})
	require.Greater(t, harness.transport.queryCount.Load(), before,
		"the new mode must ask its own server rather than read the retired entry")
	require.Equal(t, netip.MustParseAddr("192.0.2.20"), modeTestAddress(t, secondResponse, secondErr))

	// That answer belongs to the CURRENT policy epoch, so it IS recorded, and the next identical query
	// is served from it without asking the transport again. This is the positive control: the guard
	// rejects stale answers, not caching.
	thirdCtx := adapter.WithContext(context.Background(), metadata)
	beforeThird := harness.transport.queryCount.Load()
	thirdResponse, thirdErr := harness.router.Exchange(thirdCtx, message, adapter.DNSQueryOptions{})
	require.Equal(t, netip.MustParseAddr("192.0.2.20"), modeTestAddress(t, thirdResponse, thirdErr))
	require.Equal(t, beforeThird, harness.transport.queryCount.Load(),
		"an answer stored under the current policy epoch must still be served from the cache")
}
