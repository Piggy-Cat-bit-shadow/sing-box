//go:build with_lx_command

package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestURLTestOutboundIsBoundedByItsContext proves a cancelled caller stops an
// in-flight URL test, which is the user-visible property: closing the proxy page
// must abort the dial rather than leave it running.
//
// # What this test does and does not pin
//
// It covers the PROPERTY, end to end: call the handler with a live context, cancel
// it mid-dial against a target that never answers, and require a prompt return with
// the failure reported in the payload.
//
// It does NOT, on its own, pin the MECHANISM. A mutation replacing `testCtx := ctx`
// with `context.Background()` was measured to STILL return in ~151ms with
// "context canceled", because cancellation also reaches the dial through the request
// context that the dialer threads down (common/urltest/urltest.go:102 passes ctx to
// detour.DialContext, and :137 to client.Do(req.WithContext(ctx))). So a regression
// in the handler's context plumbing is masked at this layer, and this test alone
// would not catch it.
//
// TestURLTestOutboundHandlerDerivesContextFromCall verifies the mechanism directly,
// at the level where the distinction is observable.
//
// # Why the target is a black-hole listener
//
// The dial must still be running when the cancel arrives. A loopback HTTP server
// answers in microseconds, so the test would race the machine. Instead the target is
// a TCP listener that accepts and then says nothing: the TCP connect succeeds, and
// urltest blocks in the HTTP exchange until either its own deadline or a cancel. The
// handler is then given a timeout far longer than the test's patience, so only the
// cancel can end it promptly.
func TestURLTestOutboundIsBoundedByItsContext(t *testing.T) {
	// A listener that accepts connections and never responds. Any bytes written by
	// the client are drained and discarded so the client's write cannot block and
	// mask the read.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "the black-hole listener must bind")
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Drain silently: the client is left waiting for a response.
				buffer := make([]byte, 1024)
				for {
					if _, readErr := conn.Read(buffer); readErr != nil {
						return
					}
				}
			}()
		}
	}()

	fixture := newLiveFixture(t)

	// The handler must be called with a live ctx, so the call is made in a goroutine
	// and cancelled from here.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		response *URLTestOutboundResponse
		err      error
		elapsed  time.Duration
	}
	result := make(chan outcome, 1)
	start := time.Now()
	go func() {
		// 60s: far longer than the test will wait, so the request timeout cannot be
		// what ends the call. Only the cancel can.
		response, callErr := fixture.harness.service.URLTestOutbound(ctx, &URLTestOutboundRequest{
			OutboundTag: "node-a",
			Link:        "http://" + listener.Addr().String() + "/",
			Timeout:     60000,
		})
		result <- outcome{response: response, err: callErr, elapsed: time.Since(start)}
	}()

	// Let the dial get underway, then cancel — this is the window a
	// context.Background() implementation would ignore.
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case got := <-result:
		require.Less(t, got.elapsed, 20*time.Second,
			"the handler must return promptly after the context is cancelled; a "+
				"60s-bounded call that runs to completion means the URL test was "+
				"parented to the SERVICE context instead of the one it was given, so "+
				"a user closing the proxy page could not abort the dial")
		// Variant B: the cancellation surfaces in the payload, with a nil gRPC error.
		require.NoError(t, got.err,
			"Variant B: even a cancellation is an application outcome carried in "+
				"the response payload, never a transport error")
		require.NotNil(t, got.response)
		require.NotEmpty(t, got.response.Error,
			"the payload must report the failure; an empty error with delay 0 would "+
				"read as a SUCCESSFUL 0 ms measurement of a node that never answered")
	case <-time.After(20 * time.Second):
		require.Fail(t, "the handler never returned after its context was cancelled; "+
			"the URL test outlived its caller, which is precisely the bug this "+
			"asserts against")
	}
}

// TestURLTestOutboundTimeoutIsChildOfCallContext pins the relationship between the
// caller's context and the request timeout: the timeout is layered ON TOP as a child
// deadline, so cancelling the caller still ends the call immediately.
//
// A request timeout must never REPLACE the call context, or a client would lose the
// ability to abort a long test by disconnecting.
func TestURLTestOutboundTimeoutIsChildOfCallContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 1024)
				for {
					if _, readErr := conn.Read(buffer); readErr != nil {
						return
					}
				}
			}()
		}
	}()

	fixture := newLiveFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		// A timeout an order of magnitude longer than the test's patience.
		_, _ = fixture.harness.service.URLTestOutbound(ctx, &URLTestOutboundRequest{
			OutboundTag: "node-a",
			Link:        "http://" + listener.Addr().String() + "/",
			Timeout:     60000,
		})
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case <-done:
		require.Less(t, time.Since(start), 20*time.Second,
			"the caller's cancellation must end the call even though the request "+
				"supplied a much longer timeout; if the timeout replaced the call "+
				"context, the client could not abort a long test by disconnecting")
	case <-time.After(20 * time.Second):
		require.Fail(t, "the request timeout overrode the caller's cancellation")
	}
}

// TestURLTestOutboundRequestTimeoutStillApplies is the complement: with no caller
// cancellation, the request's own timeout must bound the call.
func TestURLTestOutboundRequestTimeoutStillApplies(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 1024)
				for {
					if _, readErr := conn.Read(buffer); readErr != nil {
						return
					}
				}
			}()
		}
	}()

	fixture := newLiveFixture(t)

	// The caller never cancels; only the 300ms request timeout can end this. The
	// target never answers, so without a timeout the call would hang.
	start := time.Now()
	response, err := fixture.harness.service.URLTestOutbound(context.Background(), &URLTestOutboundRequest{
		OutboundTag: "node-a",
		Link:        "http://" + listener.Addr().String() + "/",
		Timeout:     300,
	})
	elapsed := time.Since(start)

	require.NoError(t, err, "Variant B: the timeout is an application outcome")
	require.NotNil(t, response)
	require.NotEmpty(t, response.Error,
		"a silent target must produce a timeout in the payload")
	require.Less(t, elapsed, 15*time.Second,
		"a 300ms request timeout must actually bound the call")
	require.Equal(t, codes.OK, status.Code(err))
}

// TestURLTestOutboundHandlerDerivesContextFromCall pins the MECHANISM the test above
// cannot: that the context handed to urltest.URLTest is derived from the CALL context.
//
// # Why a separate, narrower test
//
// TestURLTestOutboundIsBoundedByItsContext asserts the user-visible outcome — a
// cancelled caller aborts the dial — but cancellation reaches the dial through more
// than one path, so that test passes even if the handler drops the call context.
// That was measured, not assumed: mutating `testCtx := ctx` to
// `context.Background()` left the outcome unchanged (a prompt "context canceled"),
// because the dialer also threads the request context into DialContext and
// client.Do.
//
// This test closes that hole by exercising the derivation directly through
// urlTestContext, the same helper the handler calls: a context that is ALREADY DONE
// must make the derived test context done too, WITHOUT any dial taking place. An
// implementation that ignores the call context — using the service context or a
// fresh Background — derives a live test context and proceeds to dial.
//
// The assertion is on the derived context, so it is independent of network timing,
// of the dialer, and of the target's behaviour.
func TestURLTestOutboundHandlerDerivesContextFromCall(t *testing.T) {
	fixture := newLiveFixture(t)

	// A context that is already finished, with a cause we can look for.
	callContext, cancelCall := context.WithCancel(context.Background())
	cancelCall()

	// The REAL helper the handler calls, not a copy of it. A copy would let the
	// implementation drift away from what is asserted here.
	deriveTestContext := urlTestContext

	t.Run("no request timeout", func(t *testing.T) {
		derived, cancelDerived := deriveTestContext(callContext, 0)
		defer cancelDerived()

		require.Error(t, derived.Err(),
			"a test context derived from an already-cancelled call context must "+
				"itself be done; a live context here means the handler ignored the "+
				"call context and the dial would proceed after the caller gave up")
	})

	t.Run("request timeout is a child, not a replacement", func(t *testing.T) {
		// A long timeout must NOT clear the parent's cancellation. If the handler
		// built its context from Background and applied WithTimeout, the derived
		// context would be live for 60s despite the caller having cancelled.
		derived, cancelDerived := deriveTestContext(callContext, 60000)
		defer cancelDerived()

		require.Error(t, derived.Err(),
			"a 60s request timeout must not resurrect a cancelled call: the "+
				"deadline is layered ON TOP of the call context, never in place of "+
				"it, or a client could not abort a long test by disconnecting")
	})

	// And confirm the property through the real handler, so the derivation above is
	// not merely a description of code that does something else.
	t.Run("handler rejects a cancelled call context", func(t *testing.T) {
		start := time.Now()
		response, err := fixture.harness.service.URLTestOutbound(callContext, &URLTestOutboundRequest{
			OutboundTag: "node-a",
			Link:        fixture.testURL,
			Timeout:     60000,
		})
		require.Less(t, time.Since(start), 5*time.Second,
			"a cancelled call must not run for the full request timeout")
		require.NoError(t, err, "Variant B: reported in the payload")
		require.NotNil(t, response)
		require.NotEmpty(t, response.Error,
			"a cancelled call must report a failure; an empty error with delay 0 "+
				"would read as a successful 0 ms measurement")
	})
}
