package httpclient

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A network-bound http transport must not carry a verdict about the previous network.
//
// The mechanism: ManagedTransport.Reset swaps the epoch, and when the transport is cheap to rebuild
// the replacement is made immediately. The H3-broken memory lives INSIDE the inner transport, so a
// fresh instance is what clears it. This test pins that relationship: it is what stops a DoH
// transport's remembered H3 verdict from outliving the network it described.
//
// It is NOT the MASQUE mechanism. The MASQUE tunnel builds a transport/http.Client directly rather
// than going through common/httpclient, and its verdict is cleared by RestartSession/Suspend ->
// ResetConnections. An earlier version of this comment claimed otherwise.
//
// Invariant reference: docs/fork/runtime-lifecycle-phase1.5.md §17 (a new generation must not trust
// the old transport).
func TestManagedTransportResetReplacesTheInnerTransport(t *testing.T) {
	t.Parallel()
	var built atomic.Int64
	var closed atomic.Int64
	transport := &ManagedTransport{
		cheapRebuild: true,
		factory: func() (innerTransport, error) {
			built.Add(1)
			return &fakeInnerTransport{closed: &closed}, nil
		},
	}

	response, err := transport.RoundTrip(newTestRequest())
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.EqualValues(t, 1, built.Load(), "the first use builds one epoch")
	require.Zero(t, closed.Load())

	// A network change retires the epoch. Because the rebuild is cheap, the replacement exists
	// before the next request, so nothing waits on a dial inside a caller's request.
	transport.Reset()
	require.EqualValues(t, 1, closed.Load(), "the retired epoch is closed")
	require.Eventually(t, func() bool {
		// The rebuild happens under the rebuild lock; observe it by making another request.
		response, roundTripErr := transport.RoundTrip(newTestRequest())
		if roundTripErr != nil {
			return false
		}
		_ = response.Body.Close()
		return built.Load() >= 2
	}, 2*time.Second, 5*time.Millisecond)
	require.GreaterOrEqual(t, built.Load(), int64(2),
		"the request after a reset must use a NEW inner transport, so no verdict from the old network survives")
}

func TestManagedTransportUsesOneEpochWithoutReset(t *testing.T) {
	t.Parallel()
	var built atomic.Int64
	transport := &ManagedTransport{
		cheapRebuild: true,
		factory: func() (innerTransport, error) {
			built.Add(1)
			return &fakeInnerTransport{}, nil
		},
	}
	for index := 0; index < 3; index++ {
		response, err := transport.RoundTrip(newTestRequest())
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
	}
	require.EqualValues(t, 1, built.Load(),
		"without a reset the transport is reused; rebuilding per request would be a permanent cost")
}

// Close is a lifecycle event, not a network change: it must not rebuild anything.
func TestManagedTransportCloseDoesNotRebuild(t *testing.T) {
	t.Parallel()
	var built atomic.Int64
	transport := &ManagedTransport{
		cheapRebuild: true,
		factory: func() (innerTransport, error) {
			built.Add(1)
			return &fakeInnerTransport{}, nil
		},
	}
	response, err := transport.RoundTrip(newTestRequest())
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())

	require.NoError(t, transport.close())
	require.EqualValues(t, 1, built.Load())
	require.NoError(t, transport.close(), "Close is idempotent")
}

// Closing idle connections must not rebuild: a trim that caused a dial would not be a trim.
//
// The assertion that catches the real defect is the REQUEST AFTER the trim. An earlier version of
// this test only compared built.Load() across the CloseIdleConnections call itself, which the old
// implementation passed while still swapping the epoch to nil: the rebuild was lazy, so it landed
// on the next RoundTrip instead of inside the call. The next request then built a SECOND transport
// while a stream could still be live on the first, and every post-trim request dialed through a
// pool the trim had just emptied for no reason.
func TestManagedTransportCloseIdleConnectionsDoesNotRebuild(t *testing.T) {
	t.Parallel()
	var built atomic.Int64
	var idleClosed atomic.Int64
	transport := &ManagedTransport{
		cheapRebuild: true,
		factory: func() (innerTransport, error) {
			built.Add(1)
			return &fakeInnerTransport{idleClosed: &idleClosed}, nil
		},
	}
	response, err := transport.RoundTrip(newTestRequest())
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())

	before := built.Load()
	epochBefore := transport.epoch.Load()
	require.NotNil(t, epochBefore)
	transport.CloseIdleConnections()
	require.EqualValues(t, before, built.Load(),
		"releasing idle connections must not rebuild the transport")
	require.EqualValues(t, 1, idleClosed.Load())
	require.Same(t, epochBefore, transport.epoch.Load(),
		"the trim must keep the epoch: a nil epoch means the next request builds a second "+
			"transport beside any stream still running on the first")

	// The request after the trim is where a swap would surface.
	response, err = transport.RoundTrip(newTestRequest())
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.EqualValues(t, before, built.Load(),
		"the request after a trim must reuse the transport it trimmed; building one would "+
			"make the trim a reconnect trigger")
}

type fakeInnerTransport struct {
	closed     *atomic.Int64
	idleClosed *atomic.Int64
	once       sync.Once
}

func (f *fakeInnerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    request,
	}, nil
}

func (f *fakeInnerTransport) CloseIdleConnections() {
	if f.idleClosed != nil {
		f.idleClosed.Add(1)
	}
}

func (f *fakeInnerTransport) Close() error {
	f.once.Do(func() {
		if f.closed != nil {
			f.closed.Add(1)
		}
	})
	return nil
}

func newTestRequest() *http.Request {
	request, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	return request
}
