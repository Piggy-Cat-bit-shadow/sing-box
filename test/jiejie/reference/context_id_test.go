package reference_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Live HTTP Datagram CONTEXT ID behaviour.
//
// RFC 9297 gives every HTTP Datagram a varint Context ID, and this server carries
// exactly one context: 0. The audit recorded "DATAGRAM context IDs other than 0"
// as NOT-TESTED, because the framer and the zero-context path were covered by fuzzing
// and by the fallback tests while nothing drove a NONZERO context through a live
// tunnel.
//
// What matters is not that a nonzero context is understood - it is not, and RFC 9297
// does not require it to be - but that an unsupported context is dropped as an
// EXTENSION rather than being escalated into a session failure. Google QUICHE's
// ConnectUdpDatagramPayload parser is the reference for that split: a malformed
// context VARINT is a parse failure, while a well-formed but unknown context is
// "Unknown payload" and is discarded.
//
// So the property under test is:
//
//	a nonzero context is dropped;
//	the tunnel SURVIVES;
//	the very next context-0 datagram still works.
//
// The third clause is what makes this a real test. Dropping is trivially satisfiable
// by a server that has stopped reading; a server that survives must still carry
// traffic immediately afterwards, on the same stream, with no reconnect.

// contextIDProbe is one context ID to drive through a live tunnel, with the wire
// encoding spelled out so the test is not circular.
type contextIDProbe struct {
	name string
	id   uint64
	// encoded is the varint encoding of id, written by hand from RFC 9000 section 16
	// rather than produced by the implementation under test.
	encoded []byte
}

// contextIDProbes covers every varint WIDTH boundary, because the encoding length is
// what the receiver's decoder keys on and an off-by-one in the width is the failure
// mode a single-value test would miss.
//
// The values are chosen at both sides of every boundary:
//
//	1..63          one byte   (the largest one-byte value is 63)
//	64..16383      two bytes  (64 is the first two-byte value)
//	16384..2^30-1  four bytes (16384 is the first four-byte value)
//	2^30..2^62-1   eight bytes (2^30 is the first eight-byte value, 2^62-1 is the
//	                            largest legal QUIC varint)
var contextIDProbes = []contextIDProbe{
	{"one byte minimum", 1, []byte{0x01}},
	{"one byte 2", 2, []byte{0x02}},
	{"one byte maximum 63", 63, []byte{0x3f}},
	{"two byte minimum 64", 64, []byte{0x40, 0x40}},
	{"two byte 16383", 16383, []byte{0x7f, 0xff}},
	{"four byte minimum 16384", 16384, []byte{0x80, 0x00, 0x40, 0x00}},
	{"four byte maximum 2^30-1", 1<<30 - 1, []byte{0xbf, 0xff, 0xff, 0xff}},
	{"eight byte minimum 2^30", 1 << 30, []byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00}},
	{"eight byte maximum 2^62-1", 1<<62 - 1, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
}

// TestReferenceConnectUDPUnsupportedContextIDsAreDropped drives every probe through
// a real CONNECT-UDP tunnel and requires the tunnel to survive each one.
//
// The payload sent under the nonzero context is deliberately a VALID UDP payload that
// the origin would answer. That makes the test detect the opposite failure too: a
// server that ignored the context ID and forwarded the payload anyway would produce
// an echo, and the assertion that no echo arrives would fail.
func TestReferenceConnectUDPUnsupportedContextIDsAreDropped(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	client := startRelayedConnectUDPClient(t, server, server.address())
	stream, _ := client.openTunnel(t, server.origin)

	// The baseline: context 0 works before anything unusual happens.
	require.Equal(t, "origin:before-contexts",
		datagramEchoRoundTrip(t, stream, "before-contexts"),
		"the tunnel must work before the context probes, or a later failure cannot "+
			"be attributed")

	for _, probe := range contextIDProbes {
		t.Run(probe.name, func(t *testing.T) {
			// One datagram whose payload would be a valid echo request IF the server
			// ignored the context ID.
			require.NoError(t, stream.SendDatagram(
				append(append([]byte(nil), probe.encoded...), []byte("context-probe")...)),
				"the client must be able to SEND a nonzero context; the server's "+
					"handling of it is what is under test")

			// No answer may arrive for the unsupported context. A short deadline is
			// correct here: the assertion is that the server drops the datagram, and
			// the tunnel-survival check below is what proves the drop was not a stall.
			ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
			_, err := stream.ReceiveDatagram(ctx)
			cancel()
			require.Error(t, err,
				"context %d (%s) is not supported and must be DROPPED. An answer "+
					"means the server ignored the context ID and forwarded the payload "+
					"under the wrong context", probe.id, probe.name)

			// And the tunnel must still be alive: the very next context-0 datagram
			// must complete a round trip, on the same stream, with no reconnect.
			require.Equal(t, "origin:after-context-"+probe.name,
				datagramEchoRoundTrip(t, stream, "after-context-"+probe.name),
				"the tunnel did not survive an unsupported context %d (%s). RFC 9297 "+
					"requires an unknown context to be treated as an extension to "+
					"discard, NOT as a reason to tear down the session",
				probe.id, probe.name)
		})
	}
}

// TestReferenceConnectUDPMalformedContextVarintIsDropped is the other half of the
// QUICHE split: a MALFORMED context varint is a parse failure for that datagram.
//
// It must still not kill the tunnel, because a QUIC DATAGRAM is unreliable: RFC 9297
// has no way to signal an error back for one, so the only correct local action is to
// discard the datagram. The distinction from the datagram-CAPSULE case (which lives
// on a reliable stream and IS fatal) is drawn explicitly in
// TestReferenceConnectUDPDatagramCapsuleFramingIsFatal.
func TestReferenceConnectUDPMalformedContextVarintIsDropped(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	client := startRelayedConnectUDPClient(t, server, server.address())
	stream, _ := client.openTunnel(t, server.origin)

	require.Equal(t, "origin:baseline", datagramEchoRoundTrip(t, stream, "baseline"))

	// Every malformed shape: an empty datagram, and a datagram whose first byte
	// announces a varint WIDER than the bytes present.
	malformed := [][]byte{
		{},                 // no context ID at all
		{0x40},             // announces 2 bytes, has 1
		{0x80, 0x00},       // announces 4 bytes, has 2
		{0x80, 0x00, 0x00}, // announces 4 bytes, has 3
		{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // announces 8, has 7
	}
	for index, payload := range malformed {
		// A zero-length datagram may be rejected by the QUIC layer itself rather
		// than by the server; either way the tunnel must survive, which is asserted
		// below.
		_ = stream.SendDatagram(payload)
		t.Logf("sent malformed datagram %d (%d bytes)", index, len(payload))
	}

	// The tunnel must be entirely unaffected.
	require.Equal(t, "origin:after-malformed",
		datagramEchoRoundTrip(t, stream, "after-malformed"),
		"a malformed context varint in an unreliable QUIC DATAGRAM must be discarded "+
			"for that datagram only. RFC 9297 provides no error channel for a "+
			"datagram, so tearing down the session would be both unnecessary and "+
			"unreportable")
}

// TestReferenceConnectIPUnsupportedContextIDsAreDropped is the CONNECT-IP half.
//
// The session-level handling lives in transport/masque/session.go loopDatagram for
// CONNECT-IP, which is a DIFFERENT code path from the http inbound's
// http3PacketConn for CONNECT-UDP. A test of one says nothing about the other, so
// this drives the same probe matrix against a real masque-server endpoint.
//
// A CONTROLLED peer is used rather than connect-ip-go, and that is a limitation of
// the reference client rather than a preference: connect-ip-go's Conn always frames
// with context ID 0 and keeps its stream unexported, so there is no way to inject a
// nonzero context through its API. The controlled peer speaks the same protocol -
// extended CONNECT, then HTTP Datagrams with a context ID - and is built directly on
// quic-go's HTTP/3 API, so the wire shape under test is unchanged. The
// zero-context data path is separately proven with the real reference client by
// TestReferenceConnectIPDatagramFallbackDoesNotSendDatagrams.
func TestReferenceConnectIPUnsupportedContextIDsAreDropped(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	client := startDatagramCapableConnectIPClient(t, server)
	stream, response := client.openTunnel(t, server)
	defer response.Body.Close()

	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid(), "the server must assign an address")
	require.NotEmpty(t, routes)
	gateway := serverGatewayAddress(t)

	// The baseline: context 0 carries a real IP packet and gets an answer.
	baseline := connectIPDatagramRoundTrip(t, stream, assigned, gateway, 0x5100, 1,
		[]byte{0x00}, "baseline")
	require.Equal(t, uint8(0), baseline[20],
		"the tunnel must answer before the context probes")

	for _, probe := range contextIDProbes {
		t.Run(probe.name, func(t *testing.T) {
			// A VALID IP packet under an unsupported context: a server that ignored
			// the context ID would answer it.
			packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, 0x5200, 2,
				[]byte("ctx"))
			require.NoError(t, stream.SendDatagram(
				append(append([]byte(nil), probe.encoded...), packet...)))

			// It must be dropped.
			_, answered := readConnectIPDatagramWithTimeout(t, stream, 1200*time.Millisecond)
			require.False(t, answered,
				"context %d (%s) is not supported and must be DROPPED; an answer means "+
					"the server ignored the context ID and forwarded the packet under "+
					"the wrong context", probe.id, probe.name)

			// And the session must survive it.
			after := connectIPDatagramRoundTrip(t, stream, assigned, gateway, 0x5300, 3,
				[]byte{0x00}, "after-"+probe.name)
			require.Equal(t, uint8(0), after[20],
				"the CONNECT-IP session did not survive an unsupported context %d (%s); "+
					"an unknown HTTP Datagram context is an extension to discard, not a "+
					"session failure", probe.id, probe.name)
		})
	}
}

// connectIPDatagramRoundTrip sends one IP packet under a given context ID prefix and
// reads the reply, failing if nothing arrives.
func connectIPDatagramRoundTrip(t *testing.T, stream *http3.RequestStream, assigned netip.Prefix, gateway netip.Addr, identifier uint16, sequence uint16, contextPrefix []byte, payload string) []byte {
	t.Helper()

	packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, identifier, sequence,
		[]byte(payload))
	require.NoError(t, stream.SendDatagram(append(append([]byte(nil), contextPrefix...), packet...)))

	reply, ok := readConnectIPDatagramWithTimeout(t, stream, 15*time.Second)
	require.True(t, ok,
		"the tunnel must deliver a reply on context 0; no reply means the session did "+
			"not survive, which is the failure this test exists to distinguish from a "+
			"correctly dropped unsupported context")
	return reply
}

// readConnectIPDatagramWithTimeout reads one HTTP Datagram with a watchdog, reporting
// ok=false on timeout or on an unusable datagram rather than failing.
func readConnectIPDatagramWithTimeout(t *testing.T, stream *http3.RequestStream, timeout time.Duration) ([]byte, bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := stream.ReceiveDatagram(ctx)
		done <- result{data, err}
	}()

	select {
	case received := <-done:
		if received.err != nil {
			return nil, false
		}
		contextID, contextLength, valid := decodeVarint(received.data)
		if !valid || contextID != 0 {
			return nil, false
		}
		return received.data[contextLength:], true
	case <-time.After(timeout):
		return nil, false
	}
}

// startConnectUDPControlPeer dials the CONNECT-UDP inbound with a configurable
// datagram capability, so a test can reach either the datagram path or the capsule
// fallback on the SAME server shape.
//
// The reference masque-go client always negotiates datagrams and hides the request
// stream, so it cannot express "a peer that declined datagram support" or "a raw
// datagram with a chosen context ID". This peer is built directly on quic-go's HTTP/3
// API for exactly those two cases.
func startConnectUDPControlPeer(t *testing.T, server *singBoxServer, enableDatagram bool) *connectUDPControlPeer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddrEarly(ctx, server.address(), &tls.Config{
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

// connectUDPControlPeer is a CONNECT-UDP peer with configurable datagram support.
type connectUDPControlPeer struct {
	clientConn     *http3.ClientConn
	transport      *http3.Transport
	quicConn       *quic.Conn
	enableDatagram bool
}

// openTunnel performs the RFC 9298 CONNECT-UDP extended CONNECT.
func (c *connectUDPControlPeer) openTunnel(t *testing.T, target string) (*http3.RequestStream, *http.Response) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	request := connectUDPRequest(target)
	require.NoError(t, stream.SendRequestHeader(&request))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"the CONNECT-UDP request must be accepted; a rejection here would make every "+
			"assertion below meaningless")
	return stream, response
}
