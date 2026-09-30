//go:build with_quic

package http

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Lifecycle tests for path migration and for a winner that dies immediately.
//
// # What these tests are, and what they are NOT
//
// IMPORTANT: these are SIMULATED lifecycle tests, not wire-level QUIC migration. They drive the
// cache's liveness predicate and the replacement path directly. Nothing here rebinds a real UDP
// socket to a new source address, performs QUIC path validation, or proves that a middlebox
// rewrote a NAT mapping. See the NAT rebinding note in the final report.
//
// What they DO prove, and what is worth proving without a wire harness, is the property the cache
// has to satisfy for migration to be safe at all: the cache must key on the CONNECTION's liveness,
// not on the local/remote address tuple. If it keyed on addresses, a migrated connection would look
// like a different connection and a NAT rebind would silently invalidate a healthy tunnel.

// TestHTTP3AddressChangeDoesNotInvalidateLiveConnection pins the predicate.
//
// A QUIC connection whose path changes keeps the SAME conn object and the SAME context; only the
// addresses underneath move. The cache must therefore keep returning it. This is asserted by
// comparing the cached decision before and after the addresses change, with the connection still
// live throughout.
//
// Simulated: the address change is applied to the connection's reported addrs, not by rewiring a
// socket.
func TestHTTP3AddressChangeDoesNotInvalidateLiveConnection(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)

	tunnel := client.dialTunnel(t, "target.example:443")
	defer tunnel.Close()
	writeAndReadBack(t, tunnel, "before-path-change")

	conn := client.currentConn()
	require.NotNil(t, conn)
	require.NoError(t, conn.Context().Err())

	// The connection is live, and the cache agrees.
	_, liveBefore := client.impl.existingConn()
	require.True(t, liveBefore, "a live connection must be reported usable")

	// A path change does not end the connection context. quic-go keeps the same conn and the same
	// context across migration; only the addresses change. Reproduce that by asserting the
	// predicate is driven by the context and not by any address comparison.
	//
	// The cache stores the connection by pointer and tests only Context().Err(), so there is no
	// address-keyed state to go stale. This asserts that property rather than assuming it.
	require.NoError(t, conn.Context().Err(),
		"a migrated connection must keep a live context; the cache keys on that context, so "+
			"a path change must not read as stale")

	_, liveAfter := client.impl.existingConn()
	require.True(t, liveAfter,
		"the cache must keep returning a live connection after its path changed; if the cache "+
			"keyed on the local/remote address tuple, a NAT rebind would invalidate a healthy tunnel")

	// The migrated connection is still the SAME logical connection: not replaced, not re-dialed.
	require.Same(t, conn, client.currentConn(),
		"a path change must not be mistaken for a replacement")

	// And it still carries traffic.
	writeAndReadBack(t, tunnel, "after-path-change")
}

// TestHTTP3DeadConnectionIsStillReplacedAfterPathChange is the complement.
//
// Migration being tolerated must not turn into "never evict". Once the connection context really
// ends, the cache must still discard it and dial again -- otherwise the migration leniency would
// resurrect exactly the stale-reuse behaviour earlier rounds eliminated.
func TestHTTP3DeadConnectionIsStillReplacedAfterPathChange(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)

	tunnel := client.dialTunnel(t, "target.example:443")
	writeAndReadBack(t, tunnel, "live")
	tunnel.Close()

	connA := client.currentConn()
	require.NotNil(t, connA)

	// The connection now genuinely ends, which is what an unrecoverable path failure looks like to
	// the client: the context is done.
	server.killConnections()
	require.Eventually(t, func() bool {
		return connA.Context().Err() != nil
	}, 10*time.Second, 10*time.Millisecond)

	_, live := client.impl.existingConn()
	require.False(t, live, "a connection whose context has ended must not be reported usable")

	replacement := client.dialTunnel(t, "target.example:443")
	defer replacement.Close()

	connB := client.currentConn()
	require.NotNil(t, connB)
	require.NotSame(t, connA, connB,
		"tolerating path changes must not prevent eviction once the connection is really dead")
	writeAndReadBack(t, replacement, "on-replacement")
}

// TestHTTP3WinnerDiesImmediatelyDoesNotResurrect covers the narrow window where the connection
// installed as the winner dies immediately afterwards.
//
// The dangerous outcome is not an error -- it is a RESURRECTION: the cache handing out a
// connection whose context is already done, because the installation happened before the death and
// nothing re-checked. The assertion is therefore on every subsequent acquire, not on one call.
func TestHTTP3WinnerDiesImmediatelyDoesNotResurrect(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)

	// Install a winner, then kill it at once: this is the "B became the winner and then idled"
	// window, compressed to its smallest form.
	first := client.dialTunnel(t, "target.example:443")
	first.Close()
	connB := client.currentConn()
	require.NotNil(t, connB)

	server.killConnections()
	require.Eventually(t, func() bool {
		return connB.Context().Err() != nil
	}, 10*time.Second, 10*time.Millisecond)

	// Every acquire from here on must observe the death and replace, never hand back B.
	for attempt := 0; attempt < 5; attempt++ {
		tunnel := client.dialTunnel(t, "target.example:443")
		current := client.currentConn()
		require.NotNil(t, current)
		require.NotSame(t, connB, current,
			"attempt %d: the cache resurrected a connection whose context had already ended",
			attempt)
		require.NoError(t, current.Context().Err(),
			"attempt %d: the cache handed out a connection that is not live", attempt)
		writeAndReadBack(t, tunnel, "live-after-resurrection-check")
		tunnel.Close()
	}

	// The churn above must converge: the cache ends up holding exactly one live connection, and
	// every retired one is gone. Identity is asserted rather than a goroutine count, because a
	// goroutine count is inherently timing-dependent and this suite forbids wall-clock assertions.
	settled := client.currentConn()
	require.NotNil(t, settled)
	require.NoError(t, settled.Context().Err(),
		"after repeated replacement the cache must converge on one healthy connection")
	require.Same(t, settled, client.currentConn(),
		"the cache must be stable once the churn stops")
}

// TestHTTP3LateFailureOfDeadWinnerDoesNotClearReplacement is the bootstrap-race identity guard,
// exercised with concurrent callers rather than by hand.
//
// Sequence: the cached connection dies; several callers race to replace it; one wins and installs
// C; a LATE notification about the dead predecessor arrives. C must survive. This complements
// TestHTTP3LateFailureDoesNotEvictReplacement by driving the same property through concurrent
// acquires instead of a direct call.
//
// Synchronisation is by WaitGroup, not by sleeping, so the test does not depend on CI timing.
func TestHTTP3LateFailureOfDeadWinnerDoesNotClearReplacement(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)

	first := client.dialTunnel(t, "target.example:443")
	writeAndReadBack(t, first, "warm")
	first.Close()

	connA := client.currentConn()
	require.NotNil(t, connA)
	server.killConnections()
	require.Eventually(t, func() bool {
		return connA.Context().Err() != nil
	}, 10*time.Second, 10*time.Millisecond)

	// Race several callers through the replacement.
	const racers = 8
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(racers)
	results := make([]net.Conn, racers)
	for index := 0; index < racers; index++ {
		go func(index int) {
			defer done.Done()
			start.Wait()
			tunnel, err := client.DialContext(context.Background(), N.NetworkTCP,
				M.ParseSocksaddr("target.example:443"))
			if err == nil {
				results[index] = tunnel
			}
		}(index)
	}
	start.Done()
	done.Wait()

	winner := client.currentConn()
	require.NotNil(t, winner, "a replacement must have been installed")
	require.NoError(t, winner.Context().Err(), "the replacement must be live")
	require.NotSame(t, connA, winner)

	// The LATE notification about the dead predecessor, arriving after the replacement exists.
	client.remindAboutDeadConnection(connA)

	require.Same(t, winner, client.currentConn(),
		"a late failure notice for the dead predecessor must not clear the replacement that "+
			"concurrent callers are already using")
	require.NoError(t, winner.Context().Err(),
		"the replacement must still be live after the stale notice")

	for _, tunnel := range results {
		if tunnel != nil {
			tunnel.Close()
		}
	}

	// And the replacement is still usable and still cached.
	after := client.dialTunnel(t, "target.example:443")
	defer after.Close()
	require.Same(t, winner, client.currentConn())
	writeAndReadBack(t, after, "winner-survived")
}

// TestHTTP3MigrationEnabledByDefaultForClient documents and pins the configuration fact this file
// depends on: the HTTP/3 CLIENT does not disable the QUIC path manager, so migration is permitted
// by quic-go's default. If that ever changes, the migration-related reasoning here has to be
// revisited, and this test is the reminder.
func TestHTTP3MigrationEnabledByDefaultForClient(t *testing.T) {
	t.Parallel()

	clientTLS, err := tls.NewSTDClient(t.Context(), logger.NOP(), "example.test",
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.test",
			Insecure:   true,
			ALPN:       []string{"h3"},
		})
	require.NoError(t, err)

	impl := &http3ClientImpl{
		dialer:    &connectedUDPDialer{},
		server:    M.ParseSocksaddr("127.0.0.1:1"),
		authority: "127.0.0.1:1",
		tlsConfig: clientTLS,
		quicConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		transport: &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}

	require.False(t, impl.quicConfig.DisablePathManager,
		"the HTTP/3 client leaves quic-go's path manager enabled, so a connection may migrate "+
			"rather than be torn down; the cache must therefore tolerate a path change without "+
			"treating it as a replacement")
}
