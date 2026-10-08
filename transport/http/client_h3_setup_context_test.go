//go:build with_quic

package http

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// # C: the CONNECT response belongs to the SETUP context, and only to it
//
// A CONNECT is not a request whose response ends it; the 200 is where the tunnel begins. That
// makes the wait for the response a SETUP wait with two obligations that pull in opposite
// directions, and both are tested here:
//
//  1. before the 200, the setup context must bound the wait. A peer that completes the QUIC
//     handshake, keeps the connection alive and never answers must not be able to pin a dial (or
//     the client's setup lock) forever. A blackholed middlebox produces exactly this shape.
//
//  2. after the 200, the setup context must have NO authority left. Callers cancel their dial
//     context on return as a matter of course; if that cancellation were still wired to the
//     stream it would tear down a perfectly healthy tunnel the instant the dial succeeded. SPEC
//     072/077: a dial context governs setup only.
//
// These are two halves of one property -- the context's authority ends exactly at the handover --
// so a fix for either one that ignores the other is not a fix.

// TestH3ConnectResponseHonoursContext covers obligation 1.
//
// The server completes the handshake and accepts the CONNECT, then never answers. The setup
// context must end the wait, and doing so must not leave the setup lock occupied or the memoized
// connection in a half-built state: later dials have to be able to proceed immediately rather than
// queueing behind a peer that will never respond.
func TestH3ConnectResponseHonoursContext(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	entered := make(chan struct{}, 16)
	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		// The response is deliberately never written. The handler returns when the client
		// resets the stream -- which is what a cancelled setup does -- or at test teardown.
		select {
		case <-release:
		case <-request.Context().Done():
		}
	})
	client := dialerForTunnel(t, server.address)
	impl, isImpl := client.http3.(*http3ClientImpl)
	require.True(t, isImpl, "this test drives the production HTTP/3 implementation")

	const setupTimeout = 400 * time.Millisecond
	type outcome struct {
		elapsed time.Duration
		err     error
	}

	dial := func(destination string) chan outcome {
		done := make(chan outcome, 1)
		go func() {
			setupCtx, cancelSetup := context.WithTimeout(context.Background(), setupTimeout)
			defer cancelSetup()
			started := time.Now()
			_, dialErr := impl.DialContext(setupCtx, M.ParseSocksaddr(destination))
			done <- outcome{elapsed: time.Since(started), err: dialErr}
		}()
		return done
	}

	first := dial("target.example:443")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the CONNECT request")
	}

	// THE mutex assertion. The response wait must happen with the tunnel-build lock released;
	// otherwise every later dial queues behind a peer that never answers, which turns one broken
	// server into a client-wide stall.
	require.True(t, impl.access.TryLock(),
		"the tunnel-build mutex must not be occupied while the CONNECT response is awaited")
	impl.access.Unlock()
	_, live := impl.existingConn()
	require.True(t, live,
		"the handshake completed, so the connection must already be live and memoized while the response is awaited")

	// A later dial must be able to run its own setup now, not after the first one gives up.
	second := dial("other.example:443")

	for index, done := range []chan outcome{first, second} {
		select {
		case result := <-done:
			require.Error(t, result.err, "dial %d must fail when the CONNECT response never arrives", index)
			require.ErrorIs(t, result.err, context.DeadlineExceeded,
				"dial %d must report the setup context's own deadline, not hang", index)
			require.Less(t, result.elapsed, 3*time.Second,
				"dial %d took %s; the setup context must be what ends the wait", index, result.elapsed)
		case <-time.After(5 * time.Second):
			t.Fatalf("dial %d did not return; ReadResponse is not bounded by the setup context", index)
		}
	}

	// The cancellation path must release each stream exactly once. Two dials opened exactly two
	// streams on the one memoized connection: a retry, a leaked stream or a double release would
	// all show up as a count other than two.
	require.Equal(t, 2, server.streamCount(),
		"each cancelled setup must release exactly the one stream it opened")
	require.Equal(t, 1, server.connectionCount(),
		"and cancellation must never cause a second connection to be dialed")
}

// TestH3ConnectIPResponseHonoursContext is the same obligation on the path that matters in
// production: the CONNECT-IP tunnel, not the plain CONNECT dial.
//
// It is a separate test rather than a variant because the tunnel entry point is a different
// caller (OpenTunnelWithInfo -> openTunnel -> the HTTP/3 OpenTunnel) with its own error
// classification, and a future change that moved the response wait out of openConnectStream and
// into one of those wrappers would leave the dial-path test green.
func TestH3ConnectIPResponseHonoursContext(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	entered := make(chan struct{}, 16)
	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-request.Context().Done():
		}
	})
	client := dialerForTunnel(t, server.address)
	impl, isImpl := client.http3.(*http3ClientImpl)
	require.True(t, isImpl, "this test drives the production HTTP/3 implementation")

	setupCtx, cancelSetup := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancelSetup()

	done := make(chan error, 1)
	started := time.Now()
	go func() {
		stream, _, err := client.OpenTunnelWithInfo(setupCtx, "connect-ip", "/")
		if err == nil {
			_ = stream.Close()
		}
		done <- err
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the CONNECT-IP request")
	}

	// Same mutex property as the dial path: the response wait must not hold the tunnel-build lock,
	// or every later session restart queues behind a server that never answers.
	require.True(t, impl.access.TryLock(),
		"the tunnel-build mutex must not be occupied while the CONNECT-IP response is awaited")
	impl.access.Unlock()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded,
			"the CONNECT-IP response wait must end with the setup context's deadline")
		require.Less(t, time.Since(started), 3*time.Second,
			"the CONNECT-IP response wait must be bounded by the setup context")
	case <-time.After(5 * time.Second):
		t.Fatal("the CONNECT-IP response wait is not bounded by the setup context")
	}

	require.Equal(t, 1, server.streamCount(),
		"the cancelled CONNECT-IP setup must release exactly the one stream it opened")
	require.Equal(t, 1, server.connectionCount(),
		"and must not have dialed a second connection")
}

// TestDialContextCancellationAfterSuccessDoesNotKillTunnel covers obligation 2, and it is the
// SPEC 072/077 property: the context that governed setup must be dead the moment setup succeeds.
//
// The test writes real payload after cancelling the dial context, in both directions. Asserting
// only that the tunnel object is non-nil would pass against a stream that the cancellation had
// already reset, and the failure would then appear in production as a tunnel that dies the
// instant it is established -- exactly when the caller returns from DialContext.
func TestDialContextCancellationAfterSuccessDoesNotKillTunnel(t *testing.T) {
	t.Parallel()

	server := startEchoTunnelServer(t, nil)
	client := dialerForTunnel(t, server.address)

	dialCtx, cancelDial := context.WithCancel(context.Background())
	tunnel, err := client.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("target.example:443"))
	require.NoError(t, err, "the CONNECT must be accepted")

	// The caller is done with setup. From here the dial context has no authority over the stream.
	cancelDial()
	require.ErrorIs(t, dialCtx.Err(), context.Canceled,
		"the dial context must really be cancelled, or this test asserts nothing")

	const payload = "payload-after-dial-context-cancelled"
	_, err = tunnel.Write([]byte(payload))
	require.NoError(t, err,
		"the established tunnel must remain writable after its dial context is cancelled; "+
			"a stream still wired to that context is reset by the cancel")

	buffer := make([]byte, len(payload))
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(tunnel, buffer)
	require.NoError(t, err, "the established tunnel must remain readable after its dial context is cancelled")
	require.Equal(t, payload, string(buffer))

	// The success path must release the stream on Close without taking the connection with it:
	// the next CONNECT has to work on the SAME connection, or a tunnel Close would be a
	// connection Close in disguise.
	require.NoError(t, tunnel.Close())

	second, err := client.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("target.example:443"))
	require.NoError(t, err, "closing one tunnel must not close the connection the next one needs")
	defer second.Close()

	_, err = second.Write([]byte(payload))
	require.NoError(t, err)
	buffer = make([]byte, len(payload))
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(second, buffer)
	require.NoError(t, err, "the second tunnel must carry payload on the reused connection")
	require.Equal(t, payload, string(buffer))

	connections, tunnels := server.counts()
	require.Equal(t, 1, connections,
		"both tunnels must share one QUIC connection; a second connection means the first Close tore it down")
	require.Equal(t, 2, tunnels, "each CONNECT must open exactly one stream")
}
