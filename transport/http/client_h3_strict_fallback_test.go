package http

import (
	"context"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// P1-4: `disable_version_fallback` must be strict for EVERY way H3 can fail.
//
// # The defect
//
// The strict check sat inside `if !probeExpired`, so an H3 attempt that ran out of its own
// establishment window skipped it entirely and fell through to the HTTP/2 branch. Worse, the same
// path armed the H3-broken memory, so the NEXT dial saw H3 as unavailable and went straight to
// HTTP/2 as well. A configuration that said "do not fall back to another HTTP version" therefore
// fell back on both the current dial and every dial during the backoff period.
//
// This matters because the switch is a user-facing option on two config surfaces (the MASQUE
// client and the plain HTTP outbound), so "strict" has to mean strict.
//
// The order the code must follow:
//
//	caller/core context done   -> return that error (a local lifecycle event, not an H3 verdict)
//	H3 succeeded               -> return the connection
//	DisableVersionFallback     -> return the H3 error, and do NOT arm the broken memory
//	otherwise                  -> classify, remember, try HTTP/2

func newStrictH3Client(http3 http3Client) (*Client, *recordingDialer) {
	h1 := &recordingDialer{err: errTestNoConn}
	return &Client{http3: http3, http1Dialer: h1, disableVersionFallback: true}, h1
}

// The case that was broken: the window expires, so the probe error is a deadline rather than an
// ErrHTTP3Unavailable, and the old code fell through to HTTP/2.
func TestP14StrictNoFallbackOnAttemptWindowExpiry(t *testing.T) {
	previous := http3EstablishTimeout
	http3EstablishTimeout = 30 * time.Millisecond
	t.Cleanup(func() { http3EstablishTimeout = previous })

	h3 := &hangingHTTP3Client{}
	client, h1 := newStrictH3Client(h3)

	_, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
	require.Error(t, err, "a strict configuration must not return a connection when H3 did not come up")
	require.Zero(t, h1.calls,
		"strict means no HTTP/2 attempt at all, for every H3 failure mode including window expiry")
	require.Zero(t, client.http3Broken.Load(),
		"and the H3-broken memory must not be armed either: arming it makes the NEXT dial skip H3, which is a fallback too")
}

// An immediate refusal in strict mode: same rule, and this case already worked.
func TestP14StrictNoFallbackOnImmediateRefusal(t *testing.T) {
	h3 := &failingHTTP3Client{}
	client, h1 := newStrictH3Client(h3)

	_, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
	require.Error(t, err)
	require.Zero(t, h1.calls)
	require.Zero(t, client.http3Broken.Load())
}

// An ordinary error is returned unchanged, not converted into a fallback.
func TestP14StrictReturnsAnOrdinaryH3Error(t *testing.T) {
	h3 := &failingHTTP3Client{err: context.DeadlineExceeded}
	client, h1 := newStrictH3Client(h3)

	_, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
	require.Error(t, err)
	require.Zero(t, h1.calls)
}

// A caller that has left is not an H3 verdict, in either mode.
func TestP14CallerCancelNeverFallsBackInEitherMode(t *testing.T) {
	for _, strict := range []bool{true, false} {
		h3 := &hangingHTTP3Client{started: make(chan struct{}, 1)}
		h1 := &recordingDialer{err: errTestNoConn}
		client := &Client{http3: h3, http1Dialer: h1, disableVersionFallback: strict}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:443"))
			done <- err
		}()
		<-h3.started
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatal("the dial did not return after the caller cancelled")
		}
		require.Zero(t, h1.calls, "a cancelled caller must not trigger an HTTP/2 dial; nobody is waiting")
		require.Zero(t, client.http3Broken.Load(), "and it is not evidence about H3")
	}
}

// With fallback allowed, the window still makes HTTP/2 reachable - the fix must not break the
// feature the window was added for.
func TestP14FallbackStillReachableWhenNotStrict(t *testing.T) {
	previous := http3EstablishTimeout
	http3EstablishTimeout = 30 * time.Millisecond
	t.Cleanup(func() { http3EstablishTimeout = previous })

	h3 := &hangingHTTP3Client{}
	h1 := &recordingDialer{err: errTestNoConn}
	client := &Client{http3: h3, http1Dialer: h1}

	_, _ = client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
	require.Equal(t, 1, h1.calls, "a non-strict configuration must still fall back")
	require.True(t, client.http3Broken.Load() != 0, "and remember that H3 did not work")
}

// H3 succeeding must return the connection and try nothing else, in both modes.
func TestP14H3SuccessNeverFallsBack(t *testing.T) {
	for _, strict := range []bool{true, false} {
		h3 := &succeedingHTTP3Client{}
		h1 := &recordingDialer{err: errTestNoConn}
		client := &Client{http3: h3, http1Dialer: h1, disableVersionFallback: strict}

		conn, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.Zero(t, h1.calls)
		require.Zero(t, client.http3Broken.Load())
	}
}

// A generation reset (a network change) must clear a previously armed verdict, so H3 is retried on
// the new network instead of being skipped because of the old one.
func TestP14GenerationResetClearsTheH3Verdict(t *testing.T) {
	h3 := &failingHTTP3Client{}
	client := &Client{http3: h3, http1Dialer: &recordingDialer{err: errTestNoConn}}

	_, _ = client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
	require.True(t, client.http3Broken.Load() != 0, "the first dial arms the verdict")
	require.False(t, client.http3Available())

	client.ResetConnections()

	require.True(t, client.http3Available(),
		"a network change must re-enable H3, or a node that recovered on the new network stays on HTTP/2")
	require.Zero(t, client.http3Broken.Load())
	before := h3.calls
	_, _ = client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
	require.Equal(t, before+1, h3.calls, "and the next dial must actually try H3 again")
}

// succeedingHTTP3Client accepts every attempt, so the success path can be exercised.
type succeedingHTTP3Client struct {
	calls int
}

func (c *succeedingHTTP3Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	c.calls++
	return &stubConn{}, nil
}

func (c *succeedingHTTP3Client) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	return nil, ErrHTTP3Unavailable
}

func (c *succeedingHTTP3Client) ResetConnection() {}
func (c *succeedingHTTP3Client) Close() error     { return nil }
