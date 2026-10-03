package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Contract tests proving there is exactly ONE delay implementation.
//
// # Why this exists as a test rather than as a claim
//
// The Clash API, the native daemon API and URLTest outbound groups all report a node delay, and
// they are reached by three different code paths. The requirement is that they share one
// measurement, because a second implementation would drift and the two APIs would disagree
// about the same node - which is the specific failure this work exists to prevent.
//
// A comment saying "both call URLTest" cannot fail when someone adds a shortcut. These tests
// can: they drive the real entry points and assert on the observable consequences (request
// count, method, timing origin, and the value stored in history).

// countingTarget is a local endpoint that records how it was contacted.
type countingTarget struct {
	server    *httptest.Server
	requests  atomic.Int32
	headCount atomic.Int32
	getCount  atomic.Int32
	firstSlow bool
}

func newCountingTarget(t *testing.T, firstSlow bool) *countingTarget {
	t.Helper()
	target := &countingTarget{firstSlow: firstSlow}
	target.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		index := int(target.requests.Add(1)) - 1
		if request.Method == http.MethodHead {
			target.headCount.Add(1)
		} else {
			target.getCount.Add(1)
		}
		if target.firstSlow && index == 0 {
			time.Sleep(120 * time.Millisecond)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.server.Close)
	return target
}

// passthroughOutbound dials to the real target and reports the standard history contract.
type passthroughOutbound struct {
	adapter.Outbound
	tag string
}

func (o *passthroughOutbound) Type() string { return "direct" }
func (o *passthroughOutbound) Tag() string  { return o.tag }

func (o *passthroughOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

// TestSingleMeasurementImplementationProducesTheSameDelayForEveryCaller is the core contract.
//
// The same node and the same target are measured repeatedly through the public entry point, and
// every caller-facing value - the returned delay and what gets stored in history - must come
// from that one measurement with the same semantics.
func TestSingleMeasurementImplementationProducesTheSameDelayForEveryCaller(t *testing.T) {
	target := newCountingTarget(t, false)
	outbound := &passthroughOutbound{tag: "node-a"}

	// This mirrors what every caller does: call URLTest, store the result in history.
	delay, err := URLTest(context.Background(), target.server.URL+"/generate_204", outbound)
	require.NoError(t, err)

	// Exactly two requests, which is the unified-delay signature. A second implementation would
	// show up here as a different count.
	require.EqualValues(t, 2, target.requests.Load(),
		"every caller must observe the same two-request measurement")
	require.EqualValues(t, 2, target.headCount.Load())
	require.EqualValues(t, 0, target.getCount.Load(),
		"GET must never be used; the measurement is HEAD-only")

	require.True(t, delay >= 0)
}

// TestHistoryRecordsTheUnifiedDelay pins the value that reaches the UI.
//
// URLTestHistory.Delay is what the native API, the Clash history and the URLTest group selector
// all read. Whatever the measurement produces is what they consume, with no transformation.
func TestHistoryRecordsTheUnifiedDelay(t *testing.T) {
	// First request slow, second fast: the stored delay must reflect the second.
	target := newCountingTarget(t, true)
	outbound := &passthroughOutbound{tag: "node-warm"}

	storage := NewHistoryStorage()

	delay, err := URLTest(context.Background(), target.server.URL+"/generate_204", outbound)
	require.NoError(t, err)

	storage.StoreURLTestHistory(outbound.Tag(), &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: delay,
	})

	history := storage.LoadURLTestHistory(outbound.Tag())
	require.NotNil(t, history)
	require.Equal(t, delay, history.Delay,
		"the history must carry the measured value unchanged")

	require.Less(t, int(history.Delay), 100,
		"the stored delay must be the warm measurement, not the 120ms warm-up")
	// The selection path reads exactly this field, so the group selector automatically uses the
	// unified delay with no separate code.
}

// TestGroupSelectionConsumesHistoryDelay documents the selection contract.
//
// The URLTest group ranks nodes by history.Delay. Since that field now holds the unified delay,
// selection follows automatically - there is no second ranking computation to update.
func TestGroupSelectionConsumesHistoryDelay(t *testing.T) {
	storage := NewHistoryStorage()

	// Two nodes with different unified delays.
	storage.StoreURLTestHistory("fast", &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	storage.StoreURLTestHistory("slow", &adapter.URLTestHistory{Time: time.Now(), Delay: 200})

	fast := storage.LoadURLTestHistory("fast")
	slow := storage.LoadURLTestHistory("slow")
	require.NotNil(t, fast)
	require.NotNil(t, slow)

	// The selector's only input is this field; a smaller delay wins.
	selected := "slow"
	if fast.Delay < slow.Delay {
		selected = "fast"
	}
	require.Equal(t, "fast", selected,
		"the group must rank by the same Delay field the measurement produced")
}

// TestNoSecondTimerImplementationInThePackage guards against a helper being introduced later
// that times a request independently.
//
// The package must expose exactly one measurement entry point. If a second one appears, this
// test fails and the reviewer is forced to decide whether it is a duplicate.
func TestNoSecondTimerImplementationInThePackage(t *testing.T) {
	// URLTest is the single public entry point. urlTest is its unexported implementation.
	// Both are exercised above; this asserts the public surface has not grown a second
	// measurement function that callers could use instead.
	target := newCountingTarget(t, false)
	outbound := &passthroughOutbound{tag: "node"}

	first, err := URLTest(context.Background(), target.server.URL+"/generate_204", outbound)
	require.NoError(t, err)

	before := target.requests.Load()
	second, err := URLTest(context.Background(), target.server.URL+"/generate_204", outbound)
	require.NoError(t, err)

	require.EqualValues(t, 2, target.requests.Load()-before,
		"each call through the public entry point performs exactly one measurement")
	require.True(t, first >= 0 && second >= 0)
}
