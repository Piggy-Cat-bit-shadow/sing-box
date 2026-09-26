package reference_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// A controllable UDP impairment relay: loss, duplication and reordering.
//
// The audit listed all three as NOT-TESTED, with the note that "the datagram paths are
// lossy by design and the capsule fallback is a reliable stream, but neither claim is
// tested". This relay makes them measurable.
//
// # Design constraints, and why they are what they are
//
//   - The impairment is applied to the DATAGRAM path only, after the QUIC handshake and
//     the MASQUE tunnel are established. Dropping handshake packets would make the test
//     flaky in a way that says nothing about the MASQUE data path, and a flaky test is
//     worse than no test.
//   - Every mode counts what it actually did. A test that asserts "the tunnel survived"
//     after a relay that dropped nothing is a false green, so a run whose counters are
//     zero FAILS rather than passing quietly.
//   - The relay sits BELOW QUIC, exactly like the NAT relay, so it is the transport that
//     is impaired rather than any sing-box code. This is the same division of labour the
//     migration tests use: quic-go owns transport behaviour, sing-box owns what it does
//     with the outcome.
//
// # What each mode can and cannot show
//
//	loss        a QUIC DATAGRAM is unreliable, so a dropped one is EXPECTED to be lost
//	            with no retransmission. The tunnel must stay alive.
//	duplicate   a duplicated QUIC packet is handled by QUIC's own duplicate detection.
//	            It must not be delivered twice to the application.
//	reorder     a reordered QUIC packet is buffered or discarded by QUIC's own
//	            reassembly. The tunnel must stay alive.
//
// NONE of these may kill the MASQUE tunnel or the HTTP/3 connection. That is the
// property under test, and it is a property of the whole stack rather than of one
// function.

// impairmentMode selects what the relay does to a packet.
type impairmentMode int

const (
	// impairmentNone forwards everything, so a test can establish a baseline.
	impairmentNone impairmentMode = iota
	// impairmentDropEveryNth drops one packet out of every N in the server->client
	// direction. The direction matters: the CLIENT's packets carry the requests, and
	// dropping a request would test client-side retry rather than the server's
	// robustness. Dropping replies is what proves the tunnel survives lost answers.
	impairmentDropEveryNth
	// impairmentDuplicateEveryNth sends one packet out of every N twice.
	impairmentDuplicateEveryNth
	// impairmentReorderPairs holds a packet and releases it AFTER the next one, so the
	// pair arrives swapped.
	impairmentReorderPairs
)

func (m impairmentMode) String() string {
	switch m {
	case impairmentNone:
		return "none"
	case impairmentDropEveryNth:
		return "drop-every-nth"
	case impairmentDuplicateEveryNth:
		return "duplicate-every-nth"
	case impairmentReorderPairs:
		return "reorder-pairs"
	default:
		return "unknown"
	}
}

// udpImpairmentRelay forwards UDP between a stable client-facing address and the server,
// applying one impairment to the server->client direction.
type udpImpairmentRelay struct {
	t *testing.T

	clientFacing *net.UDPConn
	upstream     *net.UDPConn

	access     sync.Mutex
	clientAddr *net.UDPAddr
	closed     bool

	// mode is read and written under modeAccess so a test can turn impairment on only
	// after the handshake has completed.
	modeAccess sync.Mutex
	mode       impairmentMode
	every      int64

	// Counters. They exist so a test can PROVE the relay did something: a green test
	// after a relay that never dropped a packet would be evidence of nothing.
	forwarded      atomic.Int64
	dropped        atomic.Int64
	duplicated     atomic.Int64
	reordered      atomic.Int64
	serverToClient atomic.Int64

	// pairHeld is the packet waiting to be released after the next one.
	pairHeld []byte
}

// startUDPImpairmentRelay starts the relay with no impairment applied.
//
// Impairment is enabled separately, so a test can complete the QUIC handshake and the
// MASQUE tunnel first. That ordering is the difference between a test of the data path
// and a test of handshake retransmission.
func startUDPImpairmentRelay(t *testing.T, serverAddress string) (*udpImpairmentRelay, string) {
	t.Helper()

	clientFacing, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	serverAddr, err := net.ResolveUDPAddr("udp", serverAddress)
	require.NoError(t, err)
	upstream, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)

	relay := &udpImpairmentRelay{
		t:            t,
		clientFacing: clientFacing,
		upstream:     upstream,
	}
	go relay.forwardClientToUpstream()
	go relay.forwardUpstreamToClient()

	t.Cleanup(relay.close)
	return relay, clientFacing.LocalAddr().String()
}

// enable turns on an impairment, applied to every nth packet in the server->client
// direction.
func (r *udpImpairmentRelay) enable(mode impairmentMode, every int) {
	require.Positive(r.t, every, "the impairment period must be positive")
	r.modeAccess.Lock()
	r.mode = mode
	r.every = int64(every)
	r.modeAccess.Unlock()
	r.t.Logf("impairment enabled: %s every %d server->client packets", mode, every)
}

// disable stops impairing, so a test can prove the tunnel recovers.
func (r *udpImpairmentRelay) disable() {
	r.modeAccess.Lock()
	previous := r.mode
	r.mode = impairmentNone
	r.modeAccess.Unlock()
	r.t.Logf("impairment disabled (was %s)", previous)
}

// currentMode reports the active impairment.
func (r *udpImpairmentRelay) currentMode() impairmentMode {
	r.modeAccess.Lock()
	defer r.modeAccess.Unlock()
	return r.mode
}

// counters reports what the relay actually did, so a test can assert the impairment was
// exercised rather than assuming it.
func (r *udpImpairmentRelay) counters() (forwarded, dropped, duplicated, reordered int64) {
	return r.forwarded.Load(), r.dropped.Load(), r.duplicated.Load(), r.reordered.Load()
}

// serverToClientCount reports how many packets came back from the server through the
// relay.
func (r *udpImpairmentRelay) serverToClientCount() int64 {
	return r.serverToClient.Load()
}

// requireExercised fails unless the relay actually applied its impairment at least once.
//
// This is the guard against the false green this whole file exists to avoid: a test that
// sets up loss and then passes because no packet was ever dropped proves nothing.
func (r *udpImpairmentRelay) requireExercised(t *testing.T, mode impairmentMode) {
	t.Helper()
	forwarded, dropped, duplicated, reordered := r.counters()
	switch mode {
	case impairmentDropEveryNth:
		require.Positive(t, dropped,
			"the relay dropped NOTHING, so this run says nothing about loss tolerance "+
				"(forwarded %d, server->client %d)", forwarded, r.serverToClientCount())
	case impairmentDuplicateEveryNth:
		require.Positive(t, duplicated,
			"the relay duplicated NOTHING, so this run says nothing about duplicate "+
				"tolerance (forwarded %d, server->client %d)", forwarded, r.serverToClientCount())
	case impairmentReorderPairs:
		require.Positive(t, reordered,
			"the relay reordered NOTHING, so this run says nothing about reordering "+
				"tolerance (forwarded %d, server->client %d)", forwarded, r.serverToClientCount())
	}
	t.Logf("impairment exercised: mode=%s forwarded=%d dropped=%d duplicated=%d reordered=%d",
		mode, forwarded, dropped, duplicated, reordered)
}

func (r *udpImpairmentRelay) forwardClientToUpstream() {
	buffer := make([]byte, 65535)
	for {
		n, from, err := r.clientFacing.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		r.access.Lock()
		if r.closed {
			r.access.Unlock()
			return
		}
		r.clientAddr = from
		upstream := r.upstream
		r.access.Unlock()

		if _, err := upstream.Write(buffer[:n]); err != nil {
			continue
		}
	}
}

func (r *udpImpairmentRelay) forwardUpstreamToClient() {
	buffer := make([]byte, 65535)
	for {
		n, err := r.upstream.Read(buffer)
		if err != nil {
			time.Sleep(2 * time.Millisecond)
			r.access.Lock()
			closed := r.closed
			r.access.Unlock()
			if closed {
				return
			}
			continue
		}
		r.serverToClient.Add(1)

		packet := append([]byte(nil), buffer[:n]...)
		r.access.Lock()
		clientAddr := r.clientAddr
		r.access.Unlock()
		if clientAddr == nil {
			continue
		}

		// The impairment is applied here, and only here: this is the server->client
		// direction, so the QUIC handshake (which is complete by the time a test enables
		// impairment) is never affected.
		r.modeAccess.Lock()
		mode := r.mode
		every := r.every
		index := r.serverToClient.Load()
		r.modeAccess.Unlock()

		switch {
		case mode == impairmentNone:
			r.writeToClient(clientAddr, packet)
		case mode == impairmentDropEveryNth && every > 0 && index%every == 0:
			r.dropped.Add(1)
		case mode == impairmentDuplicateEveryNth && every > 0 && index%every == 0:
			r.writeToClient(clientAddr, packet)
			r.writeToClient(clientAddr, packet)
			r.duplicated.Add(1)
		case mode == impairmentReorderPairs:
			r.access.Lock()
			held := r.pairHeld
			r.pairHeld = packet
			r.access.Unlock()
			if held != nil {
				// Send the NEW packet first, then the one that was held, so the pair
				// arrives swapped.
				r.writeToClient(clientAddr, packet)
				r.writeToClient(clientAddr, held)
				r.reordered.Add(1)
				r.access.Lock()
				r.pairHeld = nil
				r.access.Unlock()
			}
			// A held packet is not forwarded yet, which is the point; it is released when
			// the next one arrives.
		default:
			r.writeToClient(clientAddr, packet)
		}
	}
}

// writeToClient forwards one packet and counts it.
func (r *udpImpairmentRelay) writeToClient(clientAddr *net.UDPAddr, packet []byte) {
	if _, err := r.clientFacing.WriteToUDP(packet, clientAddr); err != nil {
		return
	}
	r.forwarded.Add(1)
}

func (r *udpImpairmentRelay) close() {
	r.access.Lock()
	if r.closed {
		r.access.Unlock()
		return
	}
	r.closed = true
	upstream := r.upstream
	r.access.Unlock()

	_ = r.clientFacing.Close()
	if upstream != nil {
		_ = upstream.Close()
	}
}

// ---------------------------------------------------------------------------
// The impairment tests
// ---------------------------------------------------------------------------

// impairmentScenario describes one mode and how a test should drive it.
type impairmentScenario struct {
	mode  impairmentMode
	every int
	// label names the subtest.
	label string
}

// TestReferenceConnectUDPTunnelSurvivesPacketImpairment is the main regression.
//
// For each impairment: establish a real CONNECT-UDP H3 tunnel, enable the impairment,
// send a burst of datagrams, then DISABLE the impairment and prove the tunnel still
// carries traffic. The last step is the assertion that matters, because a tunnel that is
// alive but permanently wedged would pass a weaker test.
//
// Loss is expected to lose data: a QUIC DATAGRAM is unreliable by design and RFC 9297
// gives it no retransmission. The test therefore does NOT require every packet to
// arrive. It requires the tunnel to survive, which is a different and more important
// property.
func TestReferenceConnectUDPTunnelSurvivesPacketImpairment(t *testing.T) {
	for _, scenario := range []impairmentScenario{
		{impairmentDropEveryNth, 4, "drop_every_4th"},
		{impairmentDuplicateEveryNth, 3, "duplicate_every_3rd"},
		{impairmentReorderPairs, 1, "reorder_pairs"},
	} {
		t.Run(scenario.label, func(t *testing.T) {
			server := startSingBoxMASQUEH3(t, "")
			t.Cleanup(server.stop)

			relay, dialAddress := startUDPImpairmentRelay(t, server.address())
			client := startRelayedConnectUDPClient(t, server, dialAddress)

			stream, _ := client.openTunnel(t, server.origin)

			// Baseline BEFORE any impairment, so the tunnel and the origin are both
			// proven working and the impairment is the only variable.
			require.Equal(t, "origin:pre-impairment",
				datagramEchoRoundTrip(t, stream, "pre-impairment"),
				"the tunnel must work before impairment begins")

			// Now impair, and drive enough traffic that the mode actually fires.
			relay.enable(scenario.mode, scenario.every)

			const burst = 40
			delivered := 0
			for index := range burst {
				payload := "impaired-" + itoaForReference(index)
				if err := stream.SendDatagram(append([]byte{0}, []byte(payload)...)); err != nil {
					// A send may fail while packets are being dropped; that is part of
					// what is being tolerated.
					continue
				}
				if _, ok := readContextZeroDatagram(t, stream, 1500*time.Millisecond); ok {
					delivered++
				}
			}

			// The impairment must actually have fired.
			relay.requireExercised(t, scenario.mode)

			// Stop impairing and prove the tunnel recovers. This is the real assertion:
			// "the connection object is still open" is not the same as "the tunnel still
			// carries traffic".
			relay.disable()

			recovered := false
			for attempt := range 12 {
				payload := "post-impairment-" + itoaForReference(attempt)
				if err := stream.SendDatagram(append([]byte{0}, []byte(payload)...)); err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				reply, ok := readContextZeroDatagram(t, stream, 2*time.Second)
				if ok && string(reply) == "origin:"+payload {
					recovered = true
					break
				}
			}
			require.True(t, recovered,
				"the CONNECT-UDP tunnel never recovered after %s was stopped. An "+
					"unreliable QUIC DATAGRAM may be lost, duplicated or reordered, but "+
					"none of those may leave the tunnel permanently unable to carry "+
					"traffic", scenario.mode)

			forwarded, dropped, duplicated, reordered := relay.counters()
			t.Logf("%s: delivered %d/%d during impairment, recovered after it stopped "+
				"(forwarded=%d dropped=%d duplicated=%d reordered=%d)",
				scenario.mode, delivered, burst, forwarded, dropped, duplicated, reordered)
		})
	}
}

// TestReferenceConnectUDPNewTunnelAfterImpairment proves the impairment did not damage
// the HTTP/3 CONNECTION, only individual datagrams.
//
// A connection that survives but can no longer open a new tunnel would pass the test
// above and still be broken for a real client that opens several tunnels.
func TestReferenceConnectUDPNewTunnelAfterImpairment(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	relay, dialAddress := startUDPImpairmentRelay(t, server.address())
	client := startRelayedConnectUDPClient(t, server, dialAddress)

	first, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:first", datagramEchoRoundTrip(t, first, "first"))

	relay.enable(impairmentDropEveryNth, 3)
	for index := range 30 {
		// Sends may fail while packets are being dropped; that is tolerated.
		if err := first.SendDatagram(append([]byte{0}, []byte("noise-"+itoaForReference(index))...)); err == nil {
			// Drain whatever arrives so the impairment counter advances, without
			// asserting on any individual packet.
			_, _ = readContextZeroDatagram(t, first, 300*time.Millisecond)
		}
	}
	relay.requireExercised(t, impairmentDropEveryNth)
	relay.disable()

	// A NEW tunnel on the same connection.
	second, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:second", datagramEchoRoundTrip(t, second, "second"),
		"a new CONNECT-UDP request must be openable after packet loss; the connection is "+
			"alive but no longer usable for new tunnels")

	// And the first tunnel must still work too.
	require.Equal(t, "origin:first-again", datagramEchoRoundTrip(t, first, "first-again"),
		"the pre-impairment tunnel must keep working alongside the new one")
}

// TestReferenceConnectUDPCapsuleStreamIsNotImpairedAtTheApplicationLayer is the
// counter-case that keeps the claim about the datagram path honest.
//
// The capsule fallback rides the RELIABLE QUIC stream. Packet loss below QUIC must be
// repaired by QUIC's own retransmission, so a capsule must NOT be lost at the
// application layer even while the relay is dropping packets. If this test ever showed
// loss, it would mean sing-box was treating the reliable path as lossy.
func TestReferenceConnectUDPCapsuleStreamSurvivesPacketLoss(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	relay, dialAddress := startUDPImpairmentRelay(t, server.address())

	// A capsule peer (datagrams OFF) through the impairing relay.
	client := startRelayedConnectUDPControlPeer(t, server, dialAddress, false)
	stream, _ := client.openTunnel(t, server.origin)

	require.NoError(t, writeDatagramCapsuleToStream(stream, []byte("pre-impairment")))
	require.Equal(t, "origin:pre-impairment",
		consumeCapsuleReply(t, stream, "pre-impairment"))

	// Loss is enabled, and the stream must still deliver EVERY payload.
	relay.enable(impairmentDropEveryNth, 4)

	const exchanges = 20
	for index := range exchanges {
		payload := "capsule-" + itoaForReference(index)
		require.NoError(t, writeDatagramCapsuleToStream(stream, []byte(payload)),
			"the capsule stream must remain writable under packet loss")

		reply, ok := capsuleReplyWithTimeout(t, stream, 20*time.Second)
		require.True(t, ok,
			"capsule %d never arrived. The capsule fallback rides the RELIABLE QUIC "+
				"stream, so packet loss must be repaired by QUIC's retransmission - losing "+
				"a capsule at the application layer would mean sing-box is treating the "+
				"reliable path as lossy", index)
		require.Equal(t, "origin:"+payload, string(reply),
			"capsule %d must be the reply to THIS request, so ordering was preserved", index)
	}

	relay.requireExercised(t, impairmentDropEveryNth)
	forwarded, dropped, _, _ := relay.counters()
	t.Logf("capsule stream carried all %d exchanges under %s (forwarded=%d dropped=%d)",
		exchanges, impairmentDropEveryNth, forwarded, dropped)
}

// TestReferenceConnectIPTunnelSurvivesPacketImpairment is the CONNECT-IP half.
func TestReferenceConnectIPTunnelSurvivesPacketImpairment(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	relay, dialAddress := startUDPImpairmentRelay(t, server.address())

	client := startRelayedConnectIPControlPeer(t, server, dialAddress)
	stream, response := client.openTunnel(t, server)
	defer response.Body.Close()

	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid())
	require.NotEmpty(t, routes)
	gateway := serverGatewayAddress(t)

	// Baseline.
	require.Equal(t, uint8(0),
		connectIPDatagramRoundTrip(t, stream, assigned, gateway, 0x8100, 1,
			[]byte{0x00}, "pre-impairment")[20],
		"the tunnel must work before impairment begins")

	// Loss is enabled and traffic is driven until the impairment has actually fired.
	//
	// The first version sent 20 packets back to back and then asserted the drop counter
	// was positive. It was zero: the CONNECT-IP replies are produced by the server's IP
	// stack, so a burst of requests does not produce a burst of replies on this
	// timescale, and only nine packets had crossed when the assertion ran. The guard was
	// right to fail - a run where nothing was dropped proves nothing - so the loop now
	// drives traffic until the relay reports it actually dropped something.
	relay.enable(impairmentDropEveryNth, 4)

	dropped := int64(0)
	for attempt := 0; attempt < 60 && dropped == 0; attempt++ {
		packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, 0x8200,
			uint16(attempt), []byte("impaired"))
		if err := stream.SendDatagram(append([]byte{0}, packet...)); err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// Consume whatever comes back so the exchange keeps moving.
		_, _ = readConnectIPDatagramWithTimeout(t, stream, 500*time.Millisecond)
		_, dropped, _, _ = relay.counters()
	}

	relay.requireExercised(t, impairmentDropEveryNth)
	relay.disable()

	// The tunnel must recover.
	recovered := false
	for attempt := range 12 {
		packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, 0x8300,
			uint16(attempt), []byte("recovered"))
		if err := stream.SendDatagram(append([]byte{0}, packet...)); err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		reply, ok := readConnectIPDatagramWithTimeout(t, stream, 2*time.Second)
		if ok && len(reply) > 20 && reply[20] == 0 {
			recovered = true
			break
		}
	}
	require.True(t, recovered,
		"the CONNECT-IP tunnel never recovered after packet loss stopped")
}

// capsuleReplyWithTimeout reads one capsule reply without failing on timeout.
func capsuleReplyWithTimeout(t *testing.T, stream interface{ Read([]byte) (int, error) }, timeout time.Duration) ([]byte, bool) {
	t.Helper()

	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		payload, err := readDatagramCapsule(stream)
		done <- result{payload, err}
	}()

	select {
	case received := <-done:
		if received.err != nil {
			return nil, false
		}
		return received.payload, true
	case <-time.After(timeout):
		return nil, false
	}
}

// consumeCapsuleReply reads one capsule reply and fails if nothing arrives.
func consumeCapsuleReply(t *testing.T, stream interface{ Read([]byte) (int, error) }, payload string) string {
	t.Helper()
	reply, ok := capsuleReplyWithTimeout(t, stream, 15*time.Second)
	require.True(t, ok, "a capsule reply must arrive for %q", payload)
	return string(reply)
}

// itoaForReference formats an int for a payload, so this file needs no strconv.
func itoaForReference(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [8]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

// startRelayedConnectUDPControlPeer dials the CONNECT-UDP inbound through the
// impairing relay, with configurable datagram support.
//
// The masque-go client cannot be pointed through a relay and cannot decline datagram
// support, so the impairment tests use the same controlled HTTP/3 peer the context-ID
// tests use, with the relay in front of it.
func startRelayedConnectUDPControlPeer(t *testing.T, server *singBoxServer, dialAddress string, enableDatagram bool) *connectUDPControlPeer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddrEarly(ctx, dialAddress, &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err)

	transport := &http3.Transport{EnableDatagrams: enableDatagram}
	peer := &connectUDPControlPeer{
		clientConn:     transport.NewClientConn(quicConn),
		transport:      transport,
		quicConn:       quicConn,
		enableDatagram: enableDatagram,
	}
	t.Cleanup(func() {
		peer.clientConn.CloseWithError(0, "")
		transport.Close()
		_ = quicConn.CloseWithError(0, "")
	})
	return peer
}

// startRelayedConnectIPControlPeer dials the CONNECT-IP endpoint through the impairing
// relay.
func startRelayedConnectIPControlPeer(t *testing.T, server *singBoxServer, dialAddress string) *connectIPControlPeer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddr(ctx, dialAddress, &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err)

	transport := &http3.Transport{EnableDatagrams: true}
	peer := &connectIPControlPeer{
		clientConn:     transport.NewClientConn(quicConn),
		transport:      transport,
		quicConn:       quicConn,
		enableDatagram: true,
	}
	t.Cleanup(func() {
		peer.clientConn.CloseWithError(0, "")
		transport.Close()
		_ = quicConn.CloseWithError(0, "")
	})
	return peer
}
