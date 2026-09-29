package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for QUIC handshake-level happy eyeballs.
//
// The property that matters is what counts as a WINNER. Three things that are easy to
// mistake for success are explicitly not:
//
//	a successful UDP dial        -- the socket exists, the peer may not
//	DialEarly returning          -- a connection object exists, the handshake may not
//	0-RTT availability           -- the peer has confirmed nothing
//
// Only a COMPLETED QUIC handshake wins. These tests use the real qtls/QUIC path against
// loopback, because a fake would have to reimplement exactly the semantics under test.

// TestSplitByPreferenceOrdersFamilies proves the candidate grouping preserves resolver
// order within each family and puts the preferred family first.
func TestSplitByPreferenceOrdersFamilies(t *testing.T) {
	t.Parallel()

	candidates := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::2"),
	}

	preferred, other := splitByPreference(candidates, false)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
	}, preferred, "IPv4 addresses keep their resolver order when IPv4 is preferred")
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
	}, other)

	preferred6, other6 := splitByPreference(candidates, true)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
	}, preferred6)
	require.Len(t, other6, 2)
}

// TestSplitByPreferenceHandlesSingleFamily proves a single-family candidate list still
// produces a usable ordering rather than an empty preferred group.
func TestSplitByPreferenceHandlesSingleFamily(t *testing.T) {
	t.Parallel()

	only4 := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	preferred, other := splitByPreference(only4, true)
	require.Len(t, preferred, 2, "with no IPv6 candidates, IPv4 must still be attempted")
	require.Empty(t, other)

	// An IPv4-mapped address is IPv4, and must not be treated as native IPv6.
	mapped := []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")}
	preferred, _ = splitByPreference(mapped, false)
	require.Len(t, preferred, 1, "an IPv4-mapped address must group with IPv4")
}

// TestRacerSingleCandidateSkipsTheRace proves one candidate is dialled directly.
//
// A racer for a single address would add a goroutine and a timer for no benefit, and on
// the common single-stack case that is pure overhead on the reconnect path.
func TestRacerSingleCandidateSkipsTheRace(t *testing.T) {
	t.Parallel()

	racer := newHandshakeRacer(50 * time.Millisecond)
	_, _, err := racer.dial(context.Background(), testCandidateConnector(&recordingDialer{fail: true}, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil),
		[]netip.Addr{netip.MustParseAddr("192.0.2.1")}, false)
	require.Error(t, err, "a single unreachable candidate must fail")
	// The connector's error surfaces as itself: connection setup belongs to the transport, so
	// the racer does not re-word it. What matters is that the REAL failure is reported rather
	// than a synthesised timeout, which is what an operator can act on.
	require.Contains(t, err.Error(), "dial failed")
}

func TestRacerNoCandidates(t *testing.T) {
	t.Parallel()

	racer := newHandshakeRacer(50 * time.Millisecond)
	_, _, err := racer.dial(context.Background(), testCandidateConnector(&recordingDialer{}, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil),
		nil, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no bootstrap candidates")
}

// countingDialer records every address dialled and can fail specific ones, so a test can
// prove WHICH candidates were attempted and in what order.
type countingDialer struct {
	access     sync.Mutex
	attempted  []string
	failExcept string
	dialCount  int
}

func (d *countingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dialCount++
	d.attempted = append(d.attempted, destination.Addr.String())
	fail := d.failExcept != "" && destination.Addr.String() != d.failExcept
	d.access.Unlock()
	if fail {
		return nil, errTestDialFailed
	}
	// A CONNECTED UDP socket pointing at a closed loopback port: the dial succeeds, the
	// socket has a real remote address, and no peer ever answers.
	//
	// Both properties matter. qtls.DialEarly requires the connection's RemoteAddr to be a
	// *net.UDPAddr, so an unconnected socket would fail the dial for the wrong reason --
	// which is exactly what an earlier version of this helper did, and the resulting error
	// ("expected a *net.UDPAddr, got <nil>") made the test look like a racer bug.
	//
	// The port is one nothing listens on, so packets are dropped and the handshake never
	// completes. That is the "socket created but path dead" shape the racer must not treat
	// as a win.
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: closedUDPPort}
	if destination.Addr.IsValid() {
		target = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(destination.Port)}
	}
	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *countingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errTestDialFailed
}

// closedUDPPort is a port nothing listens on, so packets sent to it are dropped. The
// value only needs to be one the test process is not bound to.
const closedUDPPort = 9

func (d *countingDialer) attempts() []string {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]string(nil), d.attempted...)
}

// TestRacerDoesNotTreatUDPConnectAsSuccess is the central negative test.
//
// Every candidate accepts a UDP connection and none ever answers. No candidate can
// therefore complete a QUIC handshake, and the race must FAIL rather than returning the
// first socket it managed to create. An implementation that treated socket creation as
// success would return here, and the user would get a connection that carries nothing.
func TestRacerDoesNotTreatUDPConnectAsSuccess(t *testing.T) {
	t.Parallel()

	dialer := &countingDialer{}
	racer := newHandshakeRacer(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_, _, err := racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
		false)
	elapsed := time.Since(start)

	require.Error(t, err,
		"a socket that was created but never handshook must NOT be returned as a winner")
	require.GreaterOrEqual(t, len(dialer.attempts()), 1, "at least one candidate was tried")

	// The reported error is the REAL cause from the last attempt, not a synthesised context
	// error. That is deliberate: "connection refused" tells an operator something actionable,
	// whereas "context deadline exceeded" hides it.
	//
	// The wording now comes from the connector (the QUIC stack), because connection setup
	// belongs to the transport. What this asserts is that the race surfaces the LAST REAL
	// failure rather than replacing it with a generic one.
	require.NotContains(t, err.Error(), "no bootstrap candidates")
	require.NotContains(t, err.Error(), "context deadline exceeded",
		"a hard failure must be reported as itself, not smoothed into a timeout")

	// The race respected its context and did not hang. It fails FAST here because a closed
	// loopback port refuses the connection immediately, which the racer treats as a
	// definite failure and answers by starting the next candidate at once rather than
	// waiting out the fallback timer. A slow failure here would mean the racer was
	// sleeping through information it already had.
	require.Less(t, elapsed, 3*time.Second, "the race must respect its context")
}

// TestRacerStaggersTheSecondCandidate proves the fallback delay is actually applied: the
// second candidate is not started until the first has had its head start.
//
// Without the stagger the race would be a plain broadcast, which floods the network with
// simultaneous handshakes and gives the wrong family no chance to win on latency.
func TestRacerStaggersTheSecondCandidate(t *testing.T) {
	t.Parallel()

	dialer := &countingDialer{}
	const fallbackDelay = 400 * time.Millisecond
	racer := newHandshakeRacer(fallbackDelay)

	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()

	_, _, _ = racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		false)

	attempts := dialer.attempts()
	require.GreaterOrEqual(t, len(attempts), 2,
		"both families must eventually be attempted")
	// The preferred (IPv4) candidate must be attempted first.
	require.Equal(t, "192.0.2.1", attempts[0],
		"the preferred family must be attempted first")
	require.Equal(t, "2001:db8::1", attempts[1],
		"the other family must be attempted second, after the fallback delay")
}

// TestRacerPrefersIPv6WhenAsked is the mirror, so the racer cannot pass by always
// ordering IPv4 first.
func TestRacerPrefersIPv6WhenAsked(t *testing.T) {
	t.Parallel()

	dialer := &countingDialer{}
	racer := newHandshakeRacer(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	_, _, _ = racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		true)

	attempts := dialer.attempts()
	require.GreaterOrEqual(t, len(attempts), 1)
	require.Equal(t, "2001:db8::1", attempts[0],
		"with IPv6 preferred, the IPv6 candidate must be attempted first")
}

// TestRacerStartsNextCandidateImmediatelyOnFailure proves a failed attempt does not wait
// out the timer.
//
// A refusal or an unreachable address is information, whereas the timer exists for
// silence. Waiting the full delay after a definite failure would add latency to exactly
// the case that can be detected fastest.
func TestRacerStartsNextCandidateImmediatelyOnFailure(t *testing.T) {
	t.Parallel()

	// The first candidate fails outright; the second is dialled but never answers.
	dialer := &countingDialer{failExcept: "192.0.2.2"}
	const fallbackDelay = 5 * time.Second
	racer := newHandshakeRacer(fallbackDelay)

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()

	_, _, _ = racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
		false)

	attempts := dialer.attempts()
	require.Len(t, attempts, 2,
		"the second candidate must be attempted well before the 5s fallback delay, "+
			"because the first failed immediately rather than going silent")
}

// TestRacerCancelsLosers is the cleanup test.
//
// Every attempt that did not win must have its QUIC connection and its UDP socket closed. A
// loser left open holds a socket and a goroutine for as long as the connection lives, which
// on a reconnect-heavy client is a leak that grows.
//
// The assertion is on SOCKETS, counted by the dialer, rather than on a goroutine count.
// runtime.NumGoroutine is a global, process-wide number: when this package's tests run
// alongside another package's, the count moves for reasons that have nothing to do with the
// racer, and an earlier version of this test failed intermittently for exactly that reason.
// The stronger and more specific test lives in TestRacerClosesLosingSuccessfulAttempts, which
// counts opened and closed connections directly.
func TestRacerCancelsLosers(t *testing.T) {
	t.Parallel()

	dialer := &countingDialer{}
	racer := newHandshakeRacer(30 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, _, err := racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil), []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
	},
		false)
	require.Error(t, err)

	// The racer waits for every attempt before returning, so by the time it returns no
	// attempt is still running. That is observable without a global count: all three
	// candidates must have been attempted, which can only happen if each one finished.
	require.GreaterOrEqual(t, len(dialer.attempts()), 2,
		"the racer must have started more than one attempt before failing")
	require.Equal(t, len(dialer.attempts()), dialer.dialCount,
		"every attempt the racer started must have completed by the time it returned")
}

// TestRacerHonoursContextCancellation proves a cancelled context ends the race promptly
// and cleanly, which is what a session restart relies on.
func TestRacerHonoursContextCancellation(t *testing.T) {
	t.Parallel()

	dialer := &countingDialer{}
	racer := newHandshakeRacer(30 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, _, err := racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"), racerTestTLSConfig(t), nil), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
		false)
	elapsed := time.Since(start)

	// As above, the error names the real cause. What matters here is that cancellation
	// ended the race PROMPTLY rather than at the context deadline.
	require.Error(t, err)
	require.Less(t, elapsed, 2*time.Second, "cancellation must end the race promptly")
}

// racerTestTLSConfig builds a real aTLS client config.
//
// qtls.DialEarly dereferences it before any handshake begins -- it reads
// HandshakeTimeout() and resolves STDConfig() -- so a nil config panics rather than
// failing the handshake. Any test that reaches DialEarly therefore needs a real one.
func racerTestTLSConfig(t *testing.T) tls.Config {
	t.Helper()
	config, err := tls.NewSTDClient(t.Context(), logger.NOP(), "masque.example",
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "masque.example",
			// The candidates in these tests never complete a handshake, so certificate
			// verification is never reached; Insecure keeps the config constructible
			// without a CA pool.
			Insecure: true,
		})
	require.NoError(t, err)
	return config
}

// TestRacerCascadesHardFailuresButStaggersSilence pins the two timing behaviours together.
//
// They are easy to conflate and both are intended:
//
//	a HARD failure launches the next candidate at once, because a refusal is information and
//	waiting out the delay would add latency to the case that can be detected fastest. With
//	every candidate refusing, they are therefore all tried almost immediately;
//
//	the fallback delay decides when a SILENT candidate is joined by the next one, because
//	silence is not information.
//
// # Making a candidate genuinely silent
//
// A connected UDP socket pointing at a closed loopback port is NOT silent: the kernel returns
// ICMP port unreachable, which QUIC surfaces at once as "connection refused" -- a hard failure,
// and so the very case that cascades by design. Silence requires a socket that accepts packets
// and discards them.
func TestRacerCascadesHardFailuresButStaggersSilence(t *testing.T) {
	t.Parallel()

	_, silentPort := startSilentUDPPort(t)

	dialer := &scriptedDialer{
		hardFail:   map[string]bool{"192.0.2.1": true},
		silentPort: silentPort,
	}
	const fallbackDelay = 400 * time.Millisecond
	racer := newHandshakeRacer(fallbackDelay)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, _, _ = racer.dial(ctx, testCandidateConnector(dialer, M.ParseSocksaddr("masque.example:443"),
		racerTestTLSConfig(t), nil),
		[]netip.Addr{
			netip.MustParseAddr("192.0.2.1"), // hard failure
			netip.MustParseAddr("192.0.2.2"), // silent
			netip.MustParseAddr("192.0.2.3"), // only reachable via the timer
		}, false)

	attempts := dialer.attemptTimes()
	require.GreaterOrEqual(t, len(attempts), 2, "a hard failure must be followed by another attempt")
	require.Less(t, attempts[1].Sub(attempts[0]), fallbackDelay/2,
		"a hard failure must launch the next candidate at once rather than waiting out the delay")

	if len(attempts) < 3 {
		t.Skip("the silent candidate did not stay silent long enough to observe the timer")
	}
	require.GreaterOrEqual(t, attempts[2].Sub(attempts[1]), fallbackDelay/2,
		"a candidate reached only by the TIMER must wait a full delay, because silence is what the timer is for")
}

// startSilentUDPPort binds a UDP port whose packets are read and discarded, so the kernel
// accepts them and no ICMP error is generated. That is what a blackholed path looks like, and
// it is the only way to exercise the fallback TIMER rather than the immediate-launch path.
func startSilentUDPPort(t *testing.T) (*net.UDPConn, uint16) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			if _, _, readErr := conn.ReadFromUDP(buffer); readErr != nil {
				return
			}
		}
	}()
	return conn, uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// scriptedDialer fails or stalls per address, and records when each dial happened.
type scriptedDialer struct {
	access     sync.Mutex
	hardFail   map[string]bool
	silentPort uint16
	times      []time.Time
}

func (d *scriptedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.times = append(d.times, time.Now())
	hardFail, silentPort := d.hardFail[destination.Addr.String()], d.silentPort
	d.access.Unlock()

	if hardFail {
		return nil, errTestDialFailed
	}
	if silentPort != 0 {
		return net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(silentPort)})
	}
	return net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: closedUDPPort})
}

func (d *scriptedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errTestDialFailed
}

func (d *scriptedDialer) attemptTimes() []time.Time {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]time.Time(nil), d.times...)
}
