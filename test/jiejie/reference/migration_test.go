package reference_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// QUIC migration and NAT rebinding across MASQUE tunnels.
//
// Phase 2 changed the HTTP/3 listener from `DisablePathManager = true` back to
// quic-go's default (the path manager enabled), which is what both reference
// implementations get. That turned migration from a disabled feature into
// production runtime behaviour, and it had never been tested. These tests measure
// it.
//
// The mechanism is a UDP relay that changes its upstream socket underneath a live
// connection (see udp_nat_relay_test.go), which is what a NAT does when its mapping
// changes. Path validation itself is left entirely to quic-go: this harness does
// not synthesize PATH_CHALLENGE or PATH_RESPONSE, and sing-box does not implement
// them. What is asserted is the OUTCOME - that an established tunnel keeps working
// and that the identity the HTTP layer reports stays sane.
//
// Borrowed from vcarus/volto's tests/it_migration.rs, which is the reference for
// the test SEMANTICS: (1) an existing tunnel survives a client address change, and
// (2) a NEW tunnel can still be opened on the same connection afterwards. No Rust
// code was copied and no protocol behaviour was changed to match it.

// TestReferenceConnectUDPSurvivesNATRebinding is migration case 1.
//
// A tunnel is established and used, the client's observed source port changes, and
// the SAME tunnel must keep carrying traffic. A server that silently dropped the
// connection on a path change - which is what a disabled path manager amounts to -
// would fail here.
func TestReferenceConnectUDPSurvivesNATRebinding(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	origin := server.origin
	relay, dialAddress := startUDPNATRelay(t, server.address())

	client := startRelayedConnectUDPClient(t, server, dialAddress)
	// The QUIC connection identity must not change across the rebind. Capturing it
	// here lets the test prove that "the tunnel survived" was not achieved by
	// quietly reconnecting.
	connectionRef := client.quicConn
	localBefore := client.quicConn.LocalAddr().String()

	stream, _ := client.openTunnel(t, origin)

	before := datagramEchoRoundTrip(t, stream, "migration-before")
	require.Equal(t, "origin:migration-before", before,
		"the tunnel must work before the rebind, or the test has no baseline")

	rebind := relay.upstreamPortsSeen()
	relay.rebind()
	after := relay.upstreamPortsSeen()
	t.Logf("rebinding: upstream ports %v -> %v", rebind, after)

	// The server must observe a different source address, otherwise nothing was
	// migrated and the test would pass vacuously.
	require.NotEqual(t, rebind[len(rebind)-1], after[len(after)-1],
		"the relay must present a different source port after rebinding")

	// The SAME tunnel must keep working.
	//
	// MEASURED, and the reason this retries rather than asserting on one attempt:
	// the FIRST exchange after the rebind does not arrive. The client's packet
	// triggers path validation on the new path, and until it completes the server
	// has no validated path back, so that datagram is lost. Every subsequent
	// exchange succeeds.
	//
	// Retrying is not papering over a failure - it is what RFC 9000 section 9
	// describes. A migrating endpoint probes the new path and only then resumes;
	// a datagram sent during the probe is expected to be dropped. A test that sent
	// once would report "migration is broken" for correct behaviour, which is
	// exactly what the first version of this test did.
	//
	// What must NOT be tolerated is never recovering. The deadline below is the
	// real assertion: migration must complete within a bounded time, not
	// eventually-if-ever.
	survived := echoWithMigrationRecovery(t, stream, "migration-after")
	require.Equal(t, "origin:migration-after", survived,
		"RFC 9000 section 9: a validated path change must not disturb the "+
			"connection. The tunnel never resumed carrying traffic after the "+
			"client's source address changed, which means migration is not working "+
			"on this listener")

	// And it must be the same QUIC connection, not a replacement.
	require.Same(t, connectionRef, client.quicConn,
		"the QUIC connection object must be the one that was established before "+
			"the rebind")
	t.Logf("migration: same connection, local=%s, tunnel survived", localBefore)
}

// TestReferenceConnectUDPNewTunnelAfterRebinding is migration case 2, taken from
// Volto's second migration scenario.
//
// After a path change, a NEW tunnel on the same HTTP/3 connection must be
// openable. Surviving is not enough: a connection that is alive but refuses new
// requests would pass case 1 and still be broken for a real client that opens
// several tunnels.
func TestReferenceConnectUDPNewTunnelAfterRebinding(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	relay, dialAddress := startUDPNATRelay(t, server.address())
	client := startRelayedConnectUDPClient(t, server, dialAddress)

	firstStream, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:first", datagramEchoRoundTrip(t, firstStream, "first"))

	relay.rebind()

	// A second tunnel on the SAME connection, after the rebind.
	secondStream, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:second", datagramEchoRoundTrip(t, secondStream, "second"),
		"a new CONNECT-UDP request must be openable after a path change; the "+
			"connection is alive but no longer usable for new tunnels")

	// The first tunnel must ALSO still work, so the two are independent.
	require.Equal(t, "origin:first-again", datagramEchoRoundTrip(t, firstStream, "first-again"),
		"the pre-migration tunnel must keep working alongside the new one")
}

// TestReferenceUnvalidatedSpoofDoesNotChangeIdentity is the security case.
//
// An unrelated UDP socket sends traffic at the server while a legitimate
// connection is live. Nothing about that may change the legitimate connection's
// state: quic-go is responsible for path validation, and a packet from an
// unvalidated path must not be able to hijack the connection or reset its
// authenticated state.
//
// The spoofed traffic is deliberately opaque: this test does not parse QUIC, forge
// valid encrypted packets or replay captured ones. It does not need to. What it
// asserts is that opaque third-party traffic cannot disturb an established,
// authenticated tunnel - which is the property a proxy server must have against
// random noise on the internet.
func TestReferenceUnvalidatedSpoofDoesNotChangeIdentity(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	_, dialAddress := startUDPNATRelay(t, server.address())
	client := startRelayedConnectUDPClient(t, server, dialAddress)

	stream, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:before-spoof",
		datagramEchoRoundTrip(t, stream, "before-spoof"))

	// An unrelated socket, with no relationship to the connection.
	spoof, err := net.Dial("udp", server.address())
	require.NoError(t, err)
	defer spoof.Close()

	// Three shapes of noise: random bytes, bytes shaped like a long-header QUIC
	// packet, and a short burst. None should be interpretable, and all must be
	// ignorable.
	payloads := [][]byte{
		[]byte("this-is-not-a-quic-packet"),
		append([]byte{0xc0, 0x00, 0x00, 0x00, 0x01}, make([]byte, 1200)...),
		make([]byte, 64),
	}
	for index, payload := range payloads {
		for range 5 {
			_, writeErr := spoof.Write(payload)
			require.NoError(t, writeErr)
		}
		t.Logf("sent spoof burst %d (%d bytes x5)", index, len(payload))
	}

	time.Sleep(500 * time.Millisecond)

	// The legitimate tunnel must be entirely unaffected.
	require.Equal(t, "origin:after-spoof",
		datagramEchoRoundTrip(t, stream, "after-spoof"),
		"opaque traffic from an unrelated source disturbed an established, "+
			"authenticated tunnel. Unvalidated traffic must never replace the "+
			"identity of a validated path.")

	// And the connection must still accept new, separately authenticated tunnels.
	newStream, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:post-spoof-new",
		datagramEchoRoundTrip(t, newStream, "post-spoof-new"),
		"the connection must still be usable for new authenticated tunnels")
}

// The SOURCE-IDENTITY measurement lives in source_identity_test.go, and it moved
// because the version that used to be here was not evidence.
//
// This comment is kept so the history is not silently lost. The old
// TestReferenceSourceIdentityIsStableAcrossMigration said in its doc comment that it
// measured "what identity the SERVER layer reports ... taken from the server's own
// logs". It did not read the log and it did not read the source. What its body
// actually proved was that the relay's source port changed and that both tunnels
// still carried traffic - a real DATA-PATH property, and one that
// TestReferenceConnectUDPSurvivesNATRebinding already covers, but not the identity
// sing-box attached to the request.
//
// The audit recorded "source identity CLOSED" on that basis, which the test did not
// support. The replacement observes metadata.Source through the ROUTING LAYER, which
// is a real consumer of it: a `source_ip_cidr` rule routes to one of two named
// outbounds, and the outbound tag in the server's log is the routing decision. See
// source_identity_test.go for the fixture, the migration case and the load-bearing
// negative control.
//
// What is NOT claimed anywhere in this suite: quic-go's cryptographic path
// validation is quic-go's (RFC 9000 section 9), and no test here reimplements it or
// synthesizes PATH_CHALLENGE / PATH_RESPONSE. The OPAQUE SPOOF test above
// (TestReferenceUnvalidatedSpoofDoesNotChangeIdentity) shows only that opaque,
// unvalidated third-party traffic cannot disturb an established connection; it does
// not establish anything about QUIC's internal path state, and it is not presented
// as if it did.

// TestReferenceConnectIPSurvivesNATRebinding is migration case 3.
//
// The connect-ip-go client cannot be pointed through the relay without reaching
// into the reference package, which the task forbids, so this case uses a
// controlled HTTP/3 client built here. It proves the CONNECT-IP DATA path survives
// a rebind; the control-capsule handling is the same code the fallback tests
// exercise.
func TestReferenceConnectIPSurvivesNATRebinding(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	relay, dialAddress := startUDPNATRelay(t, server.address())

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddrEarly(ctx, dialAddress, &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err)
	defer quicConn.CloseWithError(0, "")

	transport := &http3.Transport{EnableDatagrams: true}
	defer transport.Close()
	clientConn := transport.NewClientConn(quicConn)
	defer clientConn.CloseWithError(0, "")

	stream, response := openConnectIPTunnel(t, clientConn, server)
	defer response.Body.Close()

	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid())
	require.NotEmpty(t, routes)
	t.Logf("connect-ip migration: assigned=%s routes=%d", assigned, len(routes))

	gateway := serverGatewayAddress(t)

	// One IP packet round trip before the rebind.
	replyBefore := connectIPPacketRoundTrip(t, stream, assigned, gateway, 0x2201, 1, "before")
	require.Equal(t, uint8(0), replyBefore[20], "the pre-migration packet must be answered")

	relay.rebind()

	// The same tunnel must carry a packet afterwards.
	//
	// As in the CONNECT-UDP case, the first packet on the new path is expected to
	// be lost while quic-go validates it, so this retries within a bounded window
	// rather than asserting on a single attempt. Never recovering still fails.
	replyAfter := connectIPPacketWithMigrationRecovery(t, stream, assigned, gateway, 0x2201, "after")
	require.NotEmpty(t, replyAfter,
		"a CONNECT-IP tunnel must survive a validated path change; no packet was "+
			"answered after the client's source address changed")
	require.Equal(t, uint8(0), replyAfter[20])
	require.Equal(t, []byte("after"), replyAfter[28:],
		"the post-migration reply must carry the post-migration payload")
}

// openConnectIPTunnel performs the CONNECT-IP extended CONNECT on a client
// connection.
func openConnectIPTunnel(t *testing.T, clientConn *http3.ClientConn, server *singBoxServer) (*http3.RequestStream, *http.Response) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	stream, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	template, err := url.Parse(server.connectIPURL())
	require.NoError(t, err)
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-ip",
		URL:    template,
		Host:   referenceTestTLSName,
		Header: http.Header{
			"Capsule-Protocol": []string{"?1"},
			"Authorization":    []string{basicAuthorization()},
		},
	}))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	return stream, response
}

// connectIPPacketRoundTrip writes one IP packet and reads one reply, over HTTP
// Datagrams with context ID 0.
func connectIPPacketRoundTrip(t *testing.T, stream *http3.RequestStream, assigned netip.Prefix, gateway netip.Addr, identifier uint16, sequence uint16, payload string) []byte {
	t.Helper()

	packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, identifier, sequence, []byte(payload))
	require.NoError(t, stream.SendDatagram(append([]byte{0}, packet...)))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type received struct {
		data []byte
		err  error
	}
	done := make(chan received, 1)
	go func() {
		data, err := stream.ReceiveDatagram(ctx)
		done <- received{data, err}
	}()

	select {
	case result := <-done:
		require.NoError(t, result.err, "the tunnel must deliver the reply")
		contextID, contextLength, ok := decodeVarint(result.data)
		require.True(t, ok)
		require.Equal(t, uint64(0), contextID)
		return result.data[contextLength:]
	case <-time.After(15 * time.Second):
		t.Fatal("no IP reply arrived within 15s")
		return nil
	}
}

// echoWithMigrationRecovery sends the payload repeatedly until the tunnel answers,
// within a bounded window.
//
// A migrating QUIC connection validates the new path before it resumes, so the
// datagrams sent during validation are dropped by design. This retries through
// that window and reports how many attempts it took, which makes the recovery
// latency visible in the test output rather than hidden.
//
// It fails if the tunnel never answers: recovery must be BOUNDED, not merely
// possible.
func echoWithMigrationRecovery(t *testing.T, stream *http3.RequestStream, payload string) string {
	t.Helper()

	const (
		attempts    = 12
		perAttempt  = 2 * time.Second
		totalBudget = 20 * time.Second
	)
	expectedBody := "origin:" + payload

	deadline := time.Now().Add(totalBudget)
	for attempt := 1; attempt <= attempts; attempt++ {
		if time.Now().After(deadline) {
			break
		}
		result := datagramEchoAttempt(t, stream, payload, perAttempt)
		if result == expectedBody {
			t.Logf("migration recovery: answered on attempt %d", attempt)
			return result
		}
	}
	t.Logf("migration recovery: no answer within %v", totalBudget)
	return ""
}

// datagramEchoAttempt is one non-fatal echo attempt with a short timeout.
func datagramEchoAttempt(t *testing.T, stream *http3.RequestStream, payload string, timeout time.Duration) string {
	t.Helper()

	// Sending can fail while the path is being validated; that is expected.
	if err := stream.SendDatagram(append([]byte{0}, []byte(payload)...)); err != nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type received struct {
		data []byte
		err  error
	}
	done := make(chan received, 1)
	go func() {
		data, err := stream.ReceiveDatagram(ctx)
		done <- received{data, err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			return ""
		}
		_, contextLength, ok := decodeVarint(result.data)
		if !ok {
			return ""
		}
		return string(result.data[contextLength:])
	case <-time.After(timeout):
		return ""
	}
}

// connectIPPacketWithMigrationRecovery sends one IP packet repeatedly until the
// tunnel answers, within a bounded window.
//
// Same reasoning as echoWithMigrationRecovery: path validation drops the packets
// sent while it runs, so recovery is expected to take more than one attempt. What
// is asserted is that recovery happens at all, within a bound.
func connectIPPacketWithMigrationRecovery(t *testing.T, stream *http3.RequestStream, assigned netip.Prefix, gateway netip.Addr, identifier uint16, payload string) []byte {
	t.Helper()

	const (
		attempts    = 12
		perAttempt  = 2 * time.Second
		totalBudget = 20 * time.Second
	)

	deadline := time.Now().Add(totalBudget)
	for attempt := 1; attempt <= attempts; attempt++ {
		if time.Now().After(deadline) {
			break
		}
		reply := connectIPPacketAttempt(t, stream, assigned, gateway, identifier, uint16(attempt), payload, perAttempt)
		if len(reply) > 0 {
			t.Logf("connect-ip migration recovery: answered on attempt %d", attempt)
			return reply
		}
	}
	t.Logf("connect-ip migration recovery: no answer within %v", totalBudget)
	return nil
}

// connectIPPacketAttempt is one non-fatal IP packet exchange.
func connectIPPacketAttempt(t *testing.T, stream *http3.RequestStream, assigned netip.Prefix, gateway netip.Addr, identifier uint16, sequence uint16, payload string, timeout time.Duration) []byte {
	t.Helper()

	packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, identifier, sequence, []byte(payload))
	if err := stream.SendDatagram(append([]byte{0}, packet...)); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type received struct {
		data []byte
		err  error
	}
	done := make(chan received, 1)
	go func() {
		data, err := stream.ReceiveDatagram(ctx)
		done <- received{data, err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			return nil
		}
		contextID, contextLength, ok := decodeVarint(result.data)
		if !ok || contextID != 0 {
			return nil
		}
		return result.data[contextLength:]
	case <-time.After(timeout):
		return nil
	}
}
