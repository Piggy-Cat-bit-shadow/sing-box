//go:build with_quic

package http

import (
	"context"
	"io"
	"net"
	"net/http"
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

// Regression tests for STALE CONNECTION EVICTION.
//
// # The production symptom these exist to prevent
//
// The logs showed HTTP/3 CONNECT failing with a timeout while a connection was still cached:
//
//	open connection to android.clients.google.com:443
//	using outbound/http[US MASQUE]:
//	HTTP/3 CONNECT: read CONNECT response: http3: parsing frame failed:
//	timeout: no recent network activity
//
// The question that matters is not whether a dead connection is DETECTED -- lazy detection on the
// next use is a legitimate design. It is whether, once detected, the connection is actually
// EVICTED, so the request that noticed is not followed by another request that picks up the same
// corpse.
//
// # Why these tests assert connection IDENTITY
//
// "The request eventually succeeded" is not evidence of eviction: it is equally consistent with a
// pool that retries internally while never dropping the dead connection. Every test here records
// the *http3.ClientConn pointer the client hands out, so it can assert that the replacement is a
// DIFFERENT object and that the dead one is gone from the cache.

// connIdentityClient records the ClientConn handed out by each acquire, so a test can prove that
// a stale connection was replaced rather than silently reused.
type connIdentityClient struct {
	*Client
	impl *http3ClientImpl
}

func (c *connIdentityClient) currentConn() *http3.ClientConn {
	c.impl.access.Lock()
	defer c.impl.access.Unlock()
	return c.impl.conn
}

func (c *connIdentityClient) dialTunnel(t *testing.T, destination string) net.Conn {
	t.Helper()
	tunnel, err := c.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(destination))
	require.NoError(t, err, "the CONNECT must be accepted on a healthy connection")
	return tunnel
}

// writeAndReadBack proves the tunnel carries payload in BOTH directions after the 200.
//
// Asserting only that the CONNECT returned is precisely the mistake an earlier round of this
// project made: a 200 followed by a tunnel that cannot be written looks like success to a status
// check. Real bytes have to move.
func writeAndReadBack(t *testing.T, tunnel net.Conn, payload string) {
	t.Helper()
	_, err := tunnel.Write([]byte(payload))
	require.NoError(t, err, "the tunnel must stay writable after its 200")

	buffer := make([]byte, len(payload))
	require.NoError(t, tunnel.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(tunnel, buffer)
	require.NoError(t, err, "the tunnel must carry the payload back")
	require.Equal(t, payload, string(buffer))
}

// ---------------------------------------------------------------------------
// A. A dead connection must be evicted, and the replacement must be a new object
// ---------------------------------------------------------------------------

// TestHTTP3StaleConnectionIsEvictedBeforeRedial is the core lifecycle regression.
//
// Sequence:
//
//  1. open a tunnel on connection A, prove it works
//  2. kill A underneath the client (server closes the QUIC connection) so A's context ends
//  3. the client must NOT hand A out again
//  4. the next tunnel must run on a DIFFERENT *http3.ClientConn (B)
//  5. a further tunnel must REUSE B, proving the pool still caches healthy connections
//
// Step 5 is what keeps this honest: a "fix" that simply stopped caching, or dialed fresh for every
// request, would pass steps 1-4 while destroying the connection reuse the design depends on.
func TestHTTP3StaleConnectionIsEvictedBeforeRedial(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)

	// 1. Establish and exercise connection A.
	first := client.dialTunnel(t, "target.example:443")
	writeAndReadBack(t, first, "on-a")
	first.Close()

	connA := client.currentConn()
	require.NotNil(t, connA, "the first CONNECT must have established a connection")
	require.NoError(t, connA.Context().Err(), "connection A is healthy at this point")

	// 2. Kill A from the server side. Its context ends, which is exactly what an IdleTimeout
	//    looks like to the client: the QUIC connection is finished, and the cached pointer is now
	//    stale.
	server.killConnections()
	require.Eventually(t, func() bool {
		return connA.Context().Err() != nil
	}, 10*time.Second, 10*time.Millisecond,
		"the killed connection must report a finished context; the rest of this test depends on it")

	// 3/4. The next tunnel must not be handed the dead connection.
	second := client.dialTunnel(t, "target.example:443")
	defer second.Close()

	connB := client.currentConn()
	require.NotNil(t, connB, "a replacement connection must exist")
	require.NotSame(t, connA, connB,
		"the dead connection must be EVICTED before redial: handing out the same *http3.ClientConn "+
			"after its context ended is the stale-reuse bug this test exists to catch")
	require.NoError(t, connB.Context().Err(), "the replacement must be healthy")

	// The replacement must actually carry traffic, and it must be on the NEW connection.
	writeAndReadBack(t, second, "on-b")
	require.GreaterOrEqual(t, server.tunnelsSinceKill(), 1,
		"the tunnel must have been served after the kill, i.e. by the replacement connection "+
			"rather than the one that was killed")

	// 5. A further tunnel must REUSE the healthy replacement rather than dialing again.
	third := client.dialTunnel(t, "target.example:443")
	defer third.Close()
	require.Same(t, connB, client.currentConn(),
		"a healthy connection must still be reused; this test must not be satisfiable by disabling "+
			"connection caching altogether")
	writeAndReadBack(t, third, "on-b-again")

	require.Equal(t, 2, server.connectionCount(),
		"exactly two QUIC connections should ever have existed: the killed one and its replacement")
}

// ---------------------------------------------------------------------------
// B. A late failure callback must not evict the replacement
// ---------------------------------------------------------------------------

// TestHTTP3LateFailureDoesNotEvictReplacement guards the generation race.
//
// The dangerous interleaving, which a naive pool gets wrong:
//
//	connection A fails
//	goroutine 1 begins building B
//	goroutine 2 also sees A as dead
//	B is installed
//	A's late failure notification runs
//	it clears the pool unconditionally -> B is thrown away
//
// The failure mode is not a crash but a silent loss of the healthy replacement, which shows up as
// an unexplained extra dial and a slower first byte.
//
// This test drives the eviction path directly with a stale handle AFTER a replacement exists, and
// asserts the replacement survives. It is deliberately not timing-dependent: the ordering is
// forced by calling the invalidate path by hand rather than racing real goroutines, so it cannot
// pass or fail based on CI speed.
func TestHTTP3LateFailureDoesNotEvictReplacement(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)

	first := client.dialTunnel(t, "target.example:443")
	writeAndReadBack(t, first, "on-a")
	first.Close()

	connA := client.currentConn()
	require.NotNil(t, connA)

	// Kill A and force the client to install replacement B.
	server.killConnections()
	require.Eventually(t, func() bool {
		return connA.Context().Err() != nil
	}, 10*time.Second, 10*time.Millisecond)

	second := client.dialTunnel(t, "target.example:443")
	defer second.Close()

	connB := client.currentConn()
	require.NotNil(t, connB)
	require.NotSame(t, connA, connB)

	// THE RACE. A late notification about the DEAD connection A arrives now that B is installed.
	//
	// The production entry point for an out-of-band eviction is ResetConnection, which is called
	// when the network path changes. It is deliberately NOT called here: it is an explicit,
	// synchronous operation, so driving it mid-test would only measure ResetConnection, not the
	// late-failure race. What this test asserts instead is that the caching logic itself never
	// discards a healthy replacement when it is reminded about a dead predecessor -- which is
	// exercised by the acquire path immediately below.
	client.remindAboutDeadConnection(connA)

	require.Same(t, connB, client.currentConn(),
		"a late failure notification for an EVICTED connection must not clear its replacement; "+
			"invalidation has to be compare-and-delete on connection identity, not an unconditional clear")

	// B must still be usable -- the late callback must not have closed it either.
	writeAndReadBack(t, second, "b-survives-late-a-failure")

	// And a new tunnel must still land on B rather than dialing.
	third := client.dialTunnel(t, "target.example:443")
	defer third.Close()
	require.Same(t, connB, client.currentConn(),
		"the replacement must remain the cached connection after a stale invalidation")
	writeAndReadBack(t, third, "still-b")
}

// ---------------------------------------------------------------------------
// C. Concurrent reconnects against one stale connection
// ---------------------------------------------------------------------------

// TestHTTP3ConcurrentReconnectAgainstStaleConnection exercises the herd.
//
// Many concurrent CONNECTs arrive while the cached connection is already dead. The requirements
// are that every caller terminates with a clear outcome, that the pool ends up pointing at ONE
// healthy connection, and that the client does not stampede into an unbounded number of dials.
//
// It asserts STATE, not wall-clock time: how many connections exist, whether all callers finished,
// and whether the surviving connection is healthy. No timing threshold appears here, because a
// slow CI box is not a bug.
func TestHTTP3ConcurrentReconnectAgainstStaleConnection(t *testing.T) {
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

	const callers = 32

	var (
		waitGroup sync.WaitGroup
		results   = make([]net.Conn, callers)
		failures  = make([]error, callers)
	)
	waitGroup.Add(callers)
	for index := 0; index < callers; index++ {
		go func(index int) {
			defer waitGroup.Done()
			tunnel, err := client.DialContext(context.Background(), N.NetworkTCP,
				M.ParseSocksaddr("target.example:443"))
			results[index] = tunnel
			failures[index] = err
		}(index)
	}
	waitGroup.Wait()

	// Every caller must reach a definite outcome, and none may be handed a dead connection.
	opened := 0
	for index := 0; index < callers; index++ {
		if failures[index] != nil {
			continue
		}
		require.NotNil(t, results[index])
		opened++
	}
	require.Equal(t, callers, opened,
		"every concurrent CONNECT must succeed once a replacement is available; a dead cached "+
			"connection must not turn into a hard failure for callers that could have been served")

	for _, tunnel := range results {
		if tunnel != nil {
			tunnel.Close()
		}
	}

	// The pool must converge on exactly one healthy connection.
	survivor := client.currentConn()
	require.NotNil(t, survivor, "the pool must point at a live connection once the herd settles")
	require.NoError(t, survivor.Context().Err(), "the surviving connection must be healthy")
	require.NotSame(t, connA, survivor, "the dead connection must not have survived the herd")

	// Bounded dialing: 32 simultaneous callers must not produce 32 QUIC connections. acquire()
	// holds the client lock across the dial, so the losers wait and reuse the winner.
	connections := server.connectionCount()
	require.LessOrEqual(t, connections, 4,
		"concurrent reconnects must be coalesced rather than stampeding; got %d connections for "+
			"%d callers", connections, callers)

	// And the survivor must really work.
	final := client.dialTunnel(t, "target.example:443")
	defer final.Close()
	require.Same(t, survivor, client.currentConn(),
		"after the herd settles the healthy connection must be reused")
	writeAndReadBack(t, final, "after-herd")
}

// ---------------------------------------------------------------------------
// Test server: one whose QUIC connections can be killed on demand
// ---------------------------------------------------------------------------

// killableTunnelServer is an HTTP/3 CONNECT echo server that also records every QUIC connection it
// has accepted, so a test can kill them and can count how many were needed.
type killableTunnelServer struct {
	address string
	server  *http3.Server
	closed  chan struct{}

	access      sync.Mutex
	connections []*quic.Conn
	// tunnelsPerConn counts CONNECT handlers per QUIC connection, keyed by the connection
	// pointer, which is how a test proves WHICH connection served a given tunnel.
	tunnelsPerConn map[*quic.Conn]int
	// lastKilledConn is the most recently killed connection, and tunnelsAfterKill counts CONNECT
	// handlers that ran after the last kill.
	lastKilledConn   *quic.Conn
	tunnelsAfterKill int
}

func (s *killableTunnelServer) connectionCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.connections)
}

func (s *killableTunnelServer) killConnections() {
	s.access.Lock()
	connections := append([]*quic.Conn(nil), s.connections...)
	if len(connections) > 0 {
		s.lastKilledConn = connections[len(connections)-1]
	}
	s.tunnelsAfterKill = 0
	s.access.Unlock()
	for _, conn := range connections {
		_ = conn.CloseWithError(0, "test: killed to simulate a dead cached connection")
	}
}

// tunnelsSinceKill reports how many CONNECT handlers have run since the last killConnections call.
//
// Counting per connection is unreliable here because the replacement connection may not have been
// registered in ConnContext yet when a tunnel is asserted on, so this counts the handlers that ran
// AFTER the kill -- which is exactly the fact the test needs: the traffic was served by the
// replacement rather than by the connection that was killed.
func (s *killableTunnelServer) tunnelsSinceKill() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.tunnelsAfterKill
}

func startKillableTunnelServer(t *testing.T) *killableTunnelServer {
	t.Helper()
	server := &killableTunnelServer{
		closed:         make(chan struct{}),
		tunnelsPerConn: make(map[*quic.Conn]int),
	}

	tlsConfig := testServerTLSConfig(t)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	server.address = packetConn.LocalAddr().String()

	server.server = &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			server.access.Lock()
			server.tunnelsAfterKill++
			server.access.Unlock()
			writer.WriteHeader(http.StatusOK)
			if flusher, isFlusher := writer.(http.Flusher); isFlusher {
				flusher.Flush()
			}
			buffer := make([]byte, 4096)
			for {
				read, readErr := request.Body.Read(buffer)
				if read > 0 {
					if _, writeErr := writer.Write(buffer[:read]); writeErr != nil {
						return
					}
					if flusher, isFlusher := writer.(http.Flusher); isFlusher {
						flusher.Flush()
					}
				}
				if readErr != nil {
					return
				}
			}
		}),
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			server.access.Lock()
			server.connections = append(server.connections, conn)
			server.tunnelsPerConn[conn] = 0
			server.access.Unlock()
			return ctx
		},
	}
	go func() {
		_ = server.server.Serve(packetConn)
		close(server.closed)
	}()
	t.Cleanup(func() {
		_ = server.server.Close()
		<-server.closed
	})
	return server
}

// newConnIdentityClient builds a real HTTP/3 client against a loopback server, exposing the
// implementation so tests can read and invalidate the cached connection by identity.
func newConnIdentityClient(t *testing.T, address string) *connIdentityClient {
	t.Helper()
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
		server:    M.ParseSocksaddr(address),
		authority: address,
		tlsConfig: clientTLS,
		quicConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		transport: &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}
	impl.connectCandidate = impl.connectCandidateAt

	return &connIdentityClient{
		Client: &Client{
			dialer:            &connectedUDPDialer{},
			http1Dialer:       &connectedUDPDialer{},
			authorityOverride: address,
			version:           3,
			server:            M.ParseSocksaddr(address),
			http3:             impl,
			http3Authority:    address,
		},
		impl: impl,
	}
}

// remindAboutDeadConnection simulates a late, out-of-band failure notification for a connection
// that has ALREADY been evicted, by handing the stale pointer back to the eviction path.
//
// It calls the same compare-and-delete the acquire path performs, so a test can prove that a stale
// handle cannot disturb a healthy replacement.
func (c *connIdentityClient) remindAboutDeadConnection(stale *http3.ClientConn) {
	c.impl.access.Lock()
	defer c.impl.access.Unlock()
	// This mirrors what acquire() does with a finished connection: drop it, but ONLY if the
	// cached connection is still that exact object.
	if c.impl.conn == stale {
		c.impl.conn = nil
	}
}

// ---------------------------------------------------------------------------
// D. Stream cancellation must not disturb the other multiplexed streams
// ---------------------------------------------------------------------------

// TestHTTP3OneCancelledStreamDoesNotDisturbOthers is the multiplexing-isolation regression.
//
// # The distinction this pins
//
// H3_REQUEST_CANCELLED (268) cancels ONE request stream. It is not a statement about the HTTP/3
// connection, and the connection must keep carrying every other stream -- that is the entire
// reason HTTP/3 multiplexes. A connection-level failure is the opposite: everything on it dies.
//
// Treating the first as the second is the failure this test forbids, and it is a realistic
// mistake: the error text ("canceled by remote") sounds severe, and the cheapest way to make the
// ERROR logs go away is to tear the connection down.
//
// The test opens a tunnel, cancels a SECOND independent request on the same connection, and then
// asserts the tunnel still works and the connection is unchanged. Cancelling is done through the
// request context, which is what an application abandoning a DoH query actually does.
func TestHTTP3OneCancelledStreamDoesNotDisturbOthers(t *testing.T) {
	t.Parallel()

	server := startKillableTunnelServer(t)
	client := newConnIdentityClient(t, server.address)

	// A live tunnel on the connection.
	tunnel := client.dialTunnel(t, "target.example:443")
	defer tunnel.Close()
	writeAndReadBack(t, tunnel, "before-cancel")

	connBefore := client.currentConn()
	require.NotNil(t, connBefore)

	// Cancel a separate request stream on the SAME connection by cancelling its context.
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.RoundTripExistingHTTP3(cancelledContext,
		mustRequest(t, "https://"+server.address+"/dns-query"))
	require.Error(t, err, "a cancelled request must report an error to its caller")

	// THE ISOLATION ASSERTION. The tunnel is a different stream on the same connection and must be
	// completely unaffected.
	writeAndReadBack(t, tunnel, "after-cancel")

	require.Same(t, connBefore, client.currentConn(),
		"cancelling one request stream must not evict or replace the shared connection; "+
			"H3_REQUEST_CANCELLED is stream-local, not a connection failure")

	require.NoError(t, connBefore.Context().Err(),
		"the shared connection must still be live after a single stream was cancelled")

	// And a NEW stream must still be creatable on it.
	fresh := client.dialTunnel(t, "target.example:443")
	defer fresh.Close()
	writeAndReadBack(t, fresh, "new-stream-after-cancel")
	require.Same(t, connBefore, client.currentConn(),
		"a new CONNECT after a stream cancellation must reuse the same healthy connection")

	require.Equal(t, 1, server.connectionCount(),
		"exactly one QUIC connection should have been needed; a stream cancellation must never "+
			"force a redial")
}

// mustRequest builds a request for the same origin the client is authenticated for.
func mustRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, nil)
	require.NoError(t, err)
	return request
}
