package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdTLS "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/quic-go"
	"github.com/stretchr/testify/require"
)

// Ownership tests for the QUIC handshake racer.
//
// # The property these exist to establish
//
// Every attempt that opens a socket and completes a handshake must end in exactly one of
// two states:
//
//	A. it is the single winner, handed to the caller
//	B. it was explicitly closed
//
// The dangerous third state is a SUCCESSFUL attempt whose result was published to a
// channel the caller has stopped reading. That attempt holds a QUIC connection and a UDP
// socket, its goroutine has already exited so nothing will ever clean up, and no error is
// reported anywhere. On a reconnect-heavy client it grows one socket per reconnect.
//
// # Why counting sockets is the right instrument
//
// runtime.NumGoroutine is a coarse signal: it cannot distinguish "one goroutine still
// winding down" from "one QUIC connection leaked", and it is noisy in a shared test
// binary. These tests instead wrap the DIALER, so every socket that is handed to the racer
// is tracked, and every Close on it is observed. The assertion is then exact:
//
//	live == 1   while the winner is held
//	live == 0   after the winner is closed
//
// A leaked loser shows up as live == 2, which no amount of timing can explain away.

// trackedConn wraps a net.Conn and reports its closure to a tracker exactly once.
type trackedConn struct {
	net.Conn
	tracker *connTracker
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.tracker.closed.Add(1) })
	return c.Conn.Close()
}

// connTracker counts sockets handed out and closed.
type connTracker struct {
	opened atomic64
	closed atomic64
}

// live reports how many tracked sockets are still open.
func (t *connTracker) live() int64 {
	return t.opened.Load() - t.closed.Load()
}

// trackingDialer hands out tracked sockets.
type trackingDialer struct {
	tracker *connTracker
	// base does the real dialing, so the QUIC handshake below is genuine.
	base N.Dialer
}

func (d *trackingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.base.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	d.tracker.opened.Add(1)
	return &trackedConn{Conn: conn, tracker: d.tracker}, nil
}

// ListenPacket completes the N.Dialer interface. The racer only dials.
func (d *trackingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.base.ListenPacket(ctx, destination)
}

// startQUICTestServer starts a real QUIC listener that completes handshakes, so a racer
// attempt can genuinely succeed.
//
// A fake that returned a "connection" would have to reimplement handshake completion,
// which is precisely the property under test, so a real server on loopback is used. The
// client config produced by racerTestTLSConfig resolves to a std *tls.Config, so a std
// server certificate is what it verifies against (and it is Insecure, so the certificate
// only has to exist, not be trusted).
func startQUICTestServer(t *testing.T) (host netip.Addr, port uint16) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "masque.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"masque.example"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	serverTLS := &stdTLS.Config{
		Certificates: []stdTLS.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	listener, err := quic.Listen(packetConn, serverTLS, &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		Allow0RTT:            true,
	})
	require.NoError(t, err)

	local := packetConn.LocalAddr().(*net.UDPAddr)
	host = netip.MustParseAddr("127.0.0.1")
	port = uint16(local.Port)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept(context.Background())
			if acceptErr != nil {
				return
			}
			// Keep the server side open so an abandoned client connection is not
			// closed out from under the test, which would hide a leak.
			go func() {
				<-conn.Context().Done()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return host, port
}

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

// TestRacerClosesLosingSuccessfulAttempts is the core ownership test.
//
// Two candidates both complete a handshake, so for a moment there are genuinely two
// successful attempts. Exactly one may become the winner; the other must be closed by the
// racer, not abandoned. The socket count makes that unambiguous.
func TestRacerClosesLosingSuccessfulAttempts(t *testing.T) {
	t.Parallel()

	// Both candidate addresses point at the SAME real server. That is what makes both
	// attempts succeed, which is the case the leak lives in: with distinct addresses one
	// of them would fail and take the (already correct) error path.
	host, port := startQUICTestServer(t)

	tracker := &connTracker{}
	dialer := &trackingDialer{
		tracker: tracker,
		base:    &netDialerShim{},
	}
	racer := newHandshakeRacer(20 * time.Millisecond)

	// Two "different" candidates that are really the same reachable server.
	first := host
	second := host

	rawConn, quicConn, err := racer.dial(context.Background(), testCandidateConnector(dialer, M.SocksaddrFrom(host, port), racerTestTLSConfig(t), &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
	}),
		[]netip.Addr{first, second}, false)
	require.NoError(t, err, "at least one attempt must win")
	require.NotNil(t, rawConn)
	require.NotNil(t, quicConn)

	// The racer must have closed every attempt that did not win BEFORE returning, so
	// only the winner is still open. A leaked loser would make this 2.
	require.EqualValues(t, 1, tracker.live(),
		"exactly one socket may remain open when the racer returns the winner; "+
			"any more means a successful losing attempt was abandoned rather than closed")

	// Closing the winner must bring the count to zero, which proves nothing else was
	// left behind holding a socket.
	_ = quicConn.CloseWithError(0, "")
	_ = rawConn.Close()
	require.Eventually(t, func() bool { return tracker.live() == 0 }, 2*time.Second, 10*time.Millisecond,
		"after the winner is closed, no tracked socket may remain open")
}

// netDialerShim is a plain UDP dialer.
type netDialerShim struct{}

func (d *netDialerShim) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(destination.Addr, destination.Port)))
}

// ListenPacket completes the N.Dialer interface. The racer never listens, so this is
// present only to satisfy the interface.
func (d *netDialerShim) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

// TestRacerDualSuccessStress repeats the dual-success race many times.
//
// Once could be luck: the loser might close for an unrelated reason on a single run. The
// loop makes a leak proportional to the number of races visible rather than occasional.
func TestRacerDualSuccessStress(t *testing.T) {
	t.Parallel()

	host, port := startQUICTestServer(t)

	const iterations = 60
	tracker := &connTracker{}
	dialer := &trackingDialer{tracker: tracker, base: &netDialerShim{}}

	for index := range iterations {
		racer := newHandshakeRacer(5 * time.Millisecond)
		rawConn, quicConn, err := racer.dial(context.Background(), testCandidateConnector(dialer, M.SocksaddrFrom(host, port), racerTestTLSConfig(t), &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
		}),
			[]netip.Addr{host, host}, false)
		require.NoError(t, err, "iteration %d must produce a winner", index)
		_ = quicConn.CloseWithError(0, "")
		_ = rawConn.Close()
	}

	require.Eventually(t, func() bool { return tracker.live() == 0 }, 5*time.Second, 20*time.Millisecond,
		"%d races must not leave a single socket open (live=%d)", iterations, tracker.live())
}

// TestRacerWinnerIsTheOnlyOpenConnectionWhenLosersAreSlow proves the loser is closed even
// when it succeeds LATER than the winner.
//
// A slow loser is the harder case: by the time its handshake completes the race is long
// over, and a naive implementation would publish its result to a channel nobody reads.
func TestRacerWinnerIsTheOnlyOpenConnectionWhenLosersAreSlow(t *testing.T) {
	t.Parallel()

	host, port := startQUICTestServer(t)

	tracker := &connTracker{}
	dialer := &trackingDialer{tracker: tracker, base: &netDialerShim{}}
	racer := newHandshakeRacer(1 * time.Millisecond)

	// Several candidates at one address: the first wins almost immediately and the
	// rest complete their handshakes afterwards, into a race that is already decided.
	rawConn, quicConn, err := racer.dial(context.Background(), testCandidateConnector(dialer, M.SocksaddrFrom(host, port), racerTestTLSConfig(t), &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
	}),
		[]netip.Addr{host, host, host, host}, false)
	require.NoError(t, err)

	// Give any late loser time to complete its handshake and be closed.
	time.Sleep(300 * time.Millisecond)
	require.EqualValues(t, 1, tracker.live(),
		"late-successful losers must be closed too, not published into an unread channel")

	_ = quicConn.CloseWithError(0, "")
	_ = rawConn.Close()
	require.Eventually(t, func() bool { return tracker.live() == 0 }, 2*time.Second, 10*time.Millisecond)
}

// TestRacerReturnsOnlyAfterLosersAreClosed pins the synchronous-cleanup requirement.
//
// The previous implementation started a goroutine to wait for losers and returned
// immediately, so a caller that inspected open sockets the instant the winner arrived
// would see the loser still open. This asserts the count is already correct at return.
func TestRacerReturnsOnlyAfterLosersAreClosed(t *testing.T) {
	t.Parallel()

	host, port := startQUICTestServer(t)

	tracker := &connTracker{}
	dialer := &trackingDialer{tracker: tracker, base: &netDialerShim{}}
	racer := newHandshakeRacer(1 * time.Millisecond)

	rawConn, quicConn, err := racer.dial(context.Background(), testCandidateConnector(dialer, M.SocksaddrFrom(host, port), racerTestTLSConfig(t), &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
	}),
		[]netip.Addr{host, host, host}, false)
	require.NoError(t, err)

	// NO sleep and no Eventually: the assertion is about the instant the call returned.
	// If cleanup were asynchronous this would be 2 or 3.
	require.EqualValues(t, 1, tracker.live(),
		"cleanup must be complete before dial returns, not merely started")

	_ = quicConn.CloseWithError(0, "")
	_ = rawConn.Close()
}

// ---------------------------------------------------------------------------
// Family interleave
// ---------------------------------------------------------------------------

// TestRacerAlternatesAddressFamilies is the Happy Eyeballs ordering test.
//
// With two IPv6 candidates and one IPv4, the second attempt must be the IPv4 one. Trying
// every address of the preferred family before touching the other family is not Happy
// Eyeballs: it gives a broken IPv6 network N fallback delays of silence before IPv4 is
// ever attempted, which is the exact scenario the mechanism exists to fix.
func TestRacerAlternatesAddressFamilies(t *testing.T) {
	t.Parallel()

	// Nothing matches this sentinel, so every attempt fails outright. A definite
	// failure is what makes the racer start the next candidate immediately rather than
	// waiting out the fallback timer, which is what lets the ordering be observed
	// quickly instead of in real time.
	dialer := &countingDialer{failExcept: "203.0.113.254"}
	racer := newHandshakeRacer(40 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	_, _, _ = racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil), []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.1"),
	}, true)

	attempts := dialer.attempts()
	require.GreaterOrEqual(t, len(attempts), 2, "the race must attempt more than one candidate")
	require.Equal(t, "2001:db8::1", attempts[0],
		"the preferred family's first address goes first")
	require.Equal(t, "192.0.2.1", attempts[1],
		"the SECOND attempt must be the other family, not the preferred family's second address: "+
			"otherwise a broken IPv6 network waits out every IPv6 fallback delay before IPv4 is tried")
}

// TestRacerAlternatesAddressFamiliesMirrored is the mirror, so the rule cannot pass by
// happening to prefer IPv4.
func TestRacerAlternatesAddressFamiliesMirrored(t *testing.T) {
	t.Parallel()

	// Nothing matches this sentinel, so every attempt fails outright. A definite
	// failure is what makes the racer start the next candidate immediately rather than
	// waiting out the fallback timer, which is what lets the ordering be observed
	// quickly instead of in real time.
	dialer := &countingDialer{failExcept: "203.0.113.254"}
	racer := newHandshakeRacer(40 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	_, _, _ = racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil), []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
	}, false)

	attempts := dialer.attempts()
	require.GreaterOrEqual(t, len(attempts), 2)
	require.Equal(t, "192.0.2.1", attempts[0])
	require.Equal(t, "2001:db8::1", attempts[1],
		"with IPv4 preferred, the second attempt must be IPv6")
}

// TestInterleaveCandidatesKeepsEveryAddress proves the interleave never drops a candidate.
//
// Reordering must not become filtering: a client that silently stopped trying the second
// address of the preferred family would trade a latency bug for a connectivity one.
func TestInterleaveCandidatesKeepsEveryAddress(t *testing.T) {
	t.Parallel()

	candidates := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("2001:db8::3"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
	}
	ordered := interleaveCandidates(candidates, true)

	require.Len(t, ordered, len(candidates), "every candidate must survive reordering")
	seen := make(map[netip.Addr]int)
	for _, address := range ordered {
		seen[address]++
	}
	for _, address := range candidates {
		require.Equal(t, 1, seen[address], "%s must appear exactly once", address)
	}

	// And the ordering must actually alternate.
	require.Equal(t, "2001:db8::1", ordered[0].String())
	require.Equal(t, "192.0.2.1", ordered[1].String())
	require.Equal(t, "2001:db8::2", ordered[2].String())
	require.Equal(t, "192.0.2.2", ordered[3].String())
	require.Equal(t, "2001:db8::3", ordered[4].String())
}

// TestInterleaveCandidatesSingleFamily is the degenerate case: with one family there is
// nothing to alternate with, and the resolver's order must be preserved exactly.
func TestInterleaveCandidatesSingleFamily(t *testing.T) {
	t.Parallel()

	only4 := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
	}
	ordered := interleaveCandidates(only4, true)
	require.Equal(t, only4, ordered,
		"a single-family list must keep its resolver order, with no preferred family to lead")
}

// atomic64 is a tiny alias so the tracker reads clearly.
type atomic64 = atomic.Int64
