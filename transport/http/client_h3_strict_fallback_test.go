//go:build with_quic

// Gated on with_quic because it drives the HTTP/3 client's strict-fallback path and shares the
// package's with_quic-gated test doubles (stubConn lives in stream_error_test.go). Without the
// constraint the untagged test build failed with `undefined: stubConn`, which made
// `go vet ./...` and `go test ./...` red in the configuration a reader gets by default. Its
// coverage is unchanged in every product profile: with_quic is in all of them.
package http

import (
	"context"
	"net"
	"net/url"
	"sync/atomic"
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

// A caller that walks away from a TUNNEL setup is the same local lifecycle event as a caller that
// walks away from a stream dial, and it must be treated the same way. The tunnel path is a
// separate branch (openTunnel) with its own classification, so covering only DialContext would
// leave the branch that actually carries user traffic unguarded.
//
// The failure this pins is real and asymmetric: marking H3 broken here would not merely report a
// wrong error, it would make every subsequent tunnel dial skip H3 during the backoff window --
// including the dial the user makes after reconnecting on a healthy network.
func TestP14CallerCancelDuringTunnelSetupIsNotAnH3Verdict(t *testing.T) {
	h3 := &hangingTunnelHTTP3Client{started: make(chan struct{}, 1)}
	h1 := &recordingDialer{err: errTestNoConn}
	client := &Client{http3: h3, http1Dialer: h1}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, _, err := client.openTunnel(ctx, tunnelRequest{
			protocol: "connect-ip",
			url:      &url.URL{Path: "/"},
		})
		done <- err
	}()
	<-h3.started
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel setup did not return after the caller cancelled")
	}
	require.Zero(t, h1.calls, "a cancelled caller must not trigger an HTTP/2 tunnel; nobody is waiting")
	require.Zero(t, client.http3Broken.Load(), "and it is not evidence about H3")
}

// A configuration that pins HTTP/2 must never reach HTTP/3 -- not on the first dial and not on a
// later one. The pin is expressed two ways on the config surface (an explicit version=2, and a
// resolved default of 2 when no version is given), and the property under test is stronger than
// "the H3 branch is skipped": no H3 client may even be CONSTRUCTED, because construction is what
// registers the broken-verdict bookkeeping and the connection memo in the first place.
//
// The test installs a recording factory rather than inspecting internals so that a future
// constructor that forgot the version check is caught at the point it runs, not inferred later
// from a dial outcome.
func TestP14PinnedHTTP2ConfigNeverConstructsOrUsesHTTP3(t *testing.T) {
	previousFactory := NewHTTP3Client
	t.Cleanup(func() { NewHTTP3Client = previousFactory })
	var constructed atomic.Int64
	NewHTTP3Client = func(options ClientOptions, authorization string) (http3Client, error) {
		constructed.Add(1)
		return &succeedingHTTP3Client{}, nil
	}

	client, err := NewClient(ClientOptions{Version: 2})
	require.NoError(t, err)
	require.Zero(t, constructed.Load(),
		"a version-2 client must not even construct an HTTP/3 client, because construction is where the fallback state is created")
	require.Nil(t, client.http3,
		"and the field the HTTP/3 branch keys on must stay nil, so no later dial can switch versions")

	// The same pin reached by inference rather than by an explicit number. A client with no
	// version configured resolves to HTTP/2 (ResolveVersion), and that resolution must be the
	// same fact as an explicit 2 rather than a second, weaker path.
	inferred, err := NewClient(ClientOptions{})
	require.NoError(t, err)
	require.Equal(t, 2, inferred.version, "an unconfigured version resolves to HTTP/2")
	require.Nil(t, inferred.http3,
		"the resolved pin must not construct an HTTP/3 client either")
	require.Zero(t, constructed.Load(),
		"neither pin may reach the HTTP/3 factory")

	h1 := &recordingDialer{err: errTestNoConn}
	client.http1Dialer = h1
	_, _ = client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
	require.Zero(t, constructed.Load(), "and no dial may construct one either")
	require.Equal(t, 1, h1.calls, "the dial must have gone to the pinned HTTP/2/HTTP1.1 path")
	require.Zero(t, client.http3Broken.Load(),
		"a pinned client has no H3 verdict to arm, and creating one would be the silent switch this test forbids")
}

// succeedingHTTP3Client accepts every attempt, so the success path can be exercised.
type succeedingHTTP3Client struct {
	calls int
}

// hangingTunnelHTTP3Client never answers a tunnel setup until its context ends, which is what a
// caller abandoning a blackholed CONNECT-IP setup looks like from the client's side.
type hangingTunnelHTTP3Client struct {
	started chan struct{}
}

func (c *hangingTunnelHTTP3Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return nil, ErrHTTP3Unavailable
}

func (c *hangingTunnelHTTP3Client) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *hangingTunnelHTTP3Client) ResetConnection() {}
func (c *hangingTunnelHTTP3Client) Close() error     { return nil }

func (c *succeedingHTTP3Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	c.calls++
	return &stubConn{}, nil
}

func (c *succeedingHTTP3Client) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	return nil, ErrHTTP3Unavailable
}

func (c *succeedingHTTP3Client) ResetConnection() {}
func (c *succeedingHTTP3Client) Close() error     { return nil }
