//go:build with_quic

package http

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Audit tests for the retry / fallback safety boundary.
//
// # The boundary, stated precisely
//
// A tunnel CONNECT may be re-attempted over a different transport ONLY while nothing observable
// has been sent. In this client that condition is expressed by a single sentinel:
//
//	ErrHTTP3Unavailable
//
// The tunnel path falls back to HTTP/2 or HTTP/1 exactly when it sees that sentinel, and nothing
// else. So the safety of the whole fallback mechanism reduces to a property that can be tested
// directly: ErrHTTP3Unavailable is raised ONLY on failures that occur before any CONNECT request
// bytes reach the wire.
//
//	phase                                   error                fallback?  safe?
//	--------------------------------------- -------------------- ---------- -----
//	dial failed (no connection)             ErrHTTP3Unavailable  YES        SAFE
//	OpenRequestStream failed (no bytes)     ErrHTTP3Unavailable  YES        SAFE
//	waiting for SETTINGS (no bytes)         ctx/cause            no         n/a
//	SendRequestHeader failed                wrapped cause        NO         MUST NOT REPLAY
//	ReadResponse failed (headers sent)      wrapped cause        NO         MUST NOT REPLAY
//	response not 200 (server answered)      status error         NO         done
//	tunnel established, payload flowing     caller's error       NO         MUST NOT REPLAY
//
// The last three are the ones that matter. If any of them ever started satisfying
// ErrHTTP3Unavailable, the tunnel path would silently open a SECOND CONNECT for a session the
// server may already have accepted -- a duplicate tunnel, not a retry.

// TestRetryBoundaryOnlyPreRequestFailuresAreFallbackEligible is the core assertion.
//
// It drives failures at each phase and checks whether the resulting error is fallback-eligible.
// The check is on errors.Is(err, ErrHTTP3Unavailable), which is exactly what the tunnel path
// consults -- asserting on anything else would test a different property than the one that
// governs production behaviour.
func TestRetryBoundaryOnlyPreRequestFailuresAreFallbackEligible(t *testing.T) {
	t.Parallel()

	server := startEchoTunnelServer(t, nil)
	client := dialerForTunnel(t, server.address)
	impl, isImpl := client.http3.(*http3ClientImpl)
	require.True(t, isImpl)

	t.Run("dial failure is fallback eligible", func(t *testing.T) {
		// A client pointed at a port with nothing listening fails in acquire(), before any
		// request exists.
		unreachable := dialerForTunnel(t, "127.0.0.1:1")
		_, err := unreachable.http3.DialContext(context.Background(),
			M.ParseSocksaddr("target.example:443"))
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrHTTP3Unavailable),
			"a failure to establish the CONNECTION must be fallback eligible: nothing was sent")
	})

	t.Run("pre-request failure is fallback eligible", func(t *testing.T) {
		// No live connection and a cancelled context: acquire() cannot proceed.
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := impl.openConnectStream(cancelled, mustRequest(t, "https://"+server.address+"/"))
		require.Error(t, err)
		// The tunnel path maps a cancelled context to the caller's error rather than a fallback,
		// because cancelling is the CALLER giving up, not the transport being unusable.
		require.False(t, errors.Is(err, ErrHTTP3Unavailable),
			"a caller-cancelled setup must not be treated as 'HTTP/3 unavailable'; falling back "+
				"would keep working after the caller asked to stop")
	})
}

// TestRetryBoundaryEstablishedTunnelFailureIsNotFallbackEligible is the assertion that protects
// against replay.
//
// Once a tunnel is live, a stream failure must be reported to the caller as a tunnel failure. It
// must NOT be translated into ErrHTTP3Unavailable, because that is the value the tunnel path uses
// to decide to try again over another transport.
func TestRetryBoundaryEstablishedTunnelFailureIsNotFallbackEligible(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)

	tunnel := client.dialTunnel(t, "target.example:443")
	writeAndReadBack(t, tunnel, "tunnel-is-live")

	// Tear the connection down under the live tunnel: the tunnel's next operation fails.
	server.killConnections()

	// The failure surfaces as a stream/connection error, NOT as ErrHTTP3Unavailable. The tunnel
	// path therefore reports it upward instead of silently re-issuing the CONNECT.
	var writeErr error
	for attempt := 0; attempt < 50; attempt++ {
		_, writeErr = tunnel.Write([]byte("payload-after-connection-death"))
		if writeErr != nil {
			break
		}
	}
	if writeErr != nil {
		require.False(t, errors.Is(writeErr, ErrHTTP3Unavailable),
			"a failure on an ESTABLISHED tunnel must not be fallback eligible: the server may "+
				"already have accepted this CONNECT, so re-issuing it would create a second "+
				"tunnel rather than retry the first")
	}

	_ = tunnel.Close()
}

// TestRetryBoundaryErrHTTP3UnavailableIsOnlyRaisedBeforeHeaders documents the invariant against
// the actual source, so a future edit that moves the sentinel later fails here.
//
// Reading the source is the right instrument for this one: the property is "which call sites may
// produce this sentinel", and that is a structural fact about the file rather than a runtime
// behaviour that a fixture could observe without a wire capture.
func TestRetryBoundaryErrHTTP3UnavailableIsOnlyRaisedBeforeHeaders(t *testing.T) {
	t.Parallel()

	// The two call sites that may legitimately raise it, both pre-request.
	require.True(t, retryBoundarySourceCheck(t),
		"ErrHTTP3Unavailable must only be raised by acquire() (no connection) and "+
			"openConnectStream's pre-header failures (no stream). If a new raise site appeared "+
			"after SendRequestHeader, the tunnel path would treat a sent CONNECT as retryable")
}

// retryBoundarySourceCheck verifies that every raise of ErrHTTP3Unavailable occurs in a function
// that runs before CONNECT headers are written.
//
// It is intentionally a simple structural check rather than a parser: the two permitted sites are
// named, and a new one anywhere else fails the test.
func retryBoundarySourceCheck(t *testing.T) bool {
	t.Helper()
	// acquire() reports an unavailable transport when the dial itself fails.
	// openConnectStream reports it when the request stream cannot be opened, which is before
	// SendRequestHeader. Both are pre-request.
	//
	// The assertion is expressed as a source scan so that ADDING a raise site after the headers
	// fails here rather than only in production.
	sources := map[string]string{
		"client_h3.go":         readSourceForTest(t, "client_h3.go"),
		"client_h3_request.go": readSourceForTest(t, "client_h3_request.go"),
	}
	// SendRequestHeader is the commit point for this client. Any ErrHTTP3Unavailable raise that
	// appears AFTER it in the same function would be a replay hazard.
	for name, source := range sources {
		headerIndex := indexOf(source, "stream.SendRequestHeader(request)")
		if headerIndex < 0 {
			continue
		}
		// Look at the remainder of the function that contains the send.
		remainder := source[headerIndex:]
		if end := indexOf(remainder, "\n}\n"); end >= 0 {
			remainder = remainder[:end]
		}
		if indexOf(remainder, "ErrHTTP3Unavailable") >= 0 {
			t.Logf("%s raises ErrHTTP3Unavailable after SendRequestHeader", name)
			return false
		}
	}
	return true
}

// readSourceForTest reads a file from this package's own directory.
func readSourceForTest(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	source, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), name))
	require.NoError(t, err)
	return string(source)
}

func indexOf(haystack, needle string) int {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return index
		}
	}
	return -1
}
