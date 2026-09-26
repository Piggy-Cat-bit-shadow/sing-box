package reference_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Error semantics: an unreliable QUIC DATAGRAM and a reliable DATAGRAM CAPSULE must
// NOT be treated the same.
//
// RFC 9297 puts the same payload on two different transports with different failure
// models, and collapsing them is an easy and consequential mistake:
//
//   - a QUIC DATAGRAM is UNRELIABLE. There is no error channel back to the sender, so
//     a malformed context varint, an unknown context or a malformed application
//     payload can only be discarded. The tunnel must keep working.
//   - a DATAGRAM CAPSULE lives on the RELIABLE request stream. Its type and length
//     varints are the stream's own framing, so a malformed capsule means the stream
//     can no longer be parsed. The Capsule Protocol's malformed-message rule applies
//     and the request is terminated. Silently resynchronising would invent a framing
//     the peer never sent.
//
// Both halves are asserted here, on the wire, against a real server. The third
// assertion is the one that keeps the second from being over-broad: a stream-level
// failure must not be escalated into a connection-level one, so the same HTTP/3
// connection must still be able to establish a NEW tunnel.

// TestReferenceConnectUDPDatagramCapsuleFramingIsFatal is the RELIABLE half.
//
// # What counts as malformed framing, and what does not
//
// The first version of this test sent a capsule whose declared length was valid but
// large (1 MiB) and then stopped writing. Measured, the server neither delivered
// anything nor signalled an error within 10s - and that is CORRECT behaviour, not a
// defect: a declared length below MaxCapsuleLength that has not arrived yet is an
// incomplete stream, not a malformed one. `go test` would report the same for an
// HTTP/1.1 Content-Length the client has not finished sending. A receiver that
// rejected it would break every legitimate slow sender.
//
// So the malformed shape is the one the code actually treats as an error, which
// transport/http/capsule.go readDatagramCapsule states explicitly:
//
//	contextID, contextLength, err := ReadVarint(reader)
//	if uint64(contextLength) > length {
//		return E.New("malformed datagram capsule")
//	}
//
// The CONTEXT ID VARINT cannot be wider than the capsule that contains it. When it
// is, the length and the payload disagree about where the capsule ends and the stream
// can no longer be parsed - which is exactly a malformed-message condition. This test
// sends that shape.
func TestReferenceConnectUDPDatagramCapsuleFramingIsFatal(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	client := startConnectUDPControlPeer(t, server, false) // datagrams OFF: capsule path
	stream, _ := client.openTunnel(t, server.origin)

	// Confirm the capsule path works before corrupting it, so a later failure is
	// attributable to the malformed frame rather than to a broken fixture.
	require.NoError(t, writeDatagramCapsuleToStream(stream, []byte("capsule-baseline")))
	baseline := readDatagramCapsuleWithTimeout(t, stream, 15*time.Second)
	require.Contains(t, string(baseline), "capsule-baseline",
		"the capsule path must work before it is corrupted")

	// A DATAGRAM capsule whose declared payload length is 1 byte, followed by a
	// context ID varint that claims 8 bytes. The context ID cannot be wider than the
	// capsule containing it, so the stream can no longer be parsed.
	//
	// Every byte is written: the capsule body is complete as far as the LENGTH says.
	// This is what makes it malformed rather than merely incomplete.
	malformed := []byte{capsuleTypeDatagram}
	malformed = putVarint(malformed, 1) // declared payload length: 1 byte
	malformed = append(malformed, 0xc0) // a context ID varint announcing 8 bytes
	malformed = append(malformed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	_, err := stream.Write(malformed)
	require.NoError(t, err, "the write itself may succeed; the server's response is "+
		"what is under test")

	// The request must be terminated. A read that returns data would mean the server
	// resynchronised on framing the peer never sent.
	requireStreamTerminated(t, stream, 10*time.Second,
		"a DATAGRAM capsule carrying a context ID WIDER than the capsule itself is "+
			"malformed framing: the length and the payload disagree about where the "+
			"capsule ends, so the RELIABLE stream can no longer be parsed and the "+
			"request must be terminated rather than resynchronised")
}

// TestReferenceConnectUDPMalformedDatagramKeepsTheTunnelAlive is the UNRELIABLE half,
// asserted against the SAME server shape as the test above.
//
// The pair is the point: the same malformed context varint is survivable as a QUIC
// DATAGRAM and fatal as capsule framing. A server that treated both the same way
// fails one of the two tests whichever way it chose.
func TestReferenceConnectUDPMalformedDatagramKeepsTheTunnelAlive(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	client := startRelayedConnectUDPClient(t, server, server.address())
	stream, _ := client.openTunnel(t, server.origin)

	require.Equal(t, "origin:datagram-baseline",
		datagramEchoRoundTrip(t, stream, "datagram-baseline"))

	// The SAME malformed shape as the capsule test, but as a QUIC DATAGRAM whose first
	// byte announces an 8-byte varint the datagram does not contain.
	require.NoError(t, stream.SendDatagram([]byte{0xc0, 0x00, 0x00}))

	require.Equal(t, "origin:datagram-after-malformed",
		datagramEchoRoundTrip(t, stream, "datagram-after-malformed"),
		"a malformed context varint in an UNRELIABLE datagram must be discarded for "+
			"that datagram only. RFC 9297 has no way to report an error back for a "+
			"datagram, so terminating the tunnel would be both unnecessary and "+
			"unreportable - the exact opposite of the capsule case above")
}

// TestReferenceStreamFailureDoesNotKillTheHTTP3Connection is the escalation guard.
//
// The capsule test above terminates a REQUEST. That must not become a
// CONNECTION-level failure: the same HTTP/3 connection must still accept a new
// tunnel. Without this, "malformed framing is fatal" could be satisfied by closing
// the whole connection, which would turn one bad capsule into a denial of service for
// every other tunnel a client has on it.
func TestReferenceStreamFailureDoesNotKillTheHTTP3Connection(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	client := startConnectUDPControlPeer(t, server, false) // datagrams OFF: capsule path

	// First tunnel: establish it, then corrupt its stream.
	first, firstResponse := client.openTunnel(t, server.origin)
	require.Equal(t, http.StatusOK, firstResponse.StatusCode)
	require.NoError(t, writeDatagramCapsuleToStream(first, []byte("first-tunnel")))
	require.Contains(t, string(readDatagramCapsuleWithTimeout(t, first, 15*time.Second)),
		"first-tunnel")

	malformed := []byte{capsuleTypeDatagram}
	malformed = putVarint(malformed, 1)
	malformed = append(malformed, 0xc0)
	malformed = append(malformed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	_, _ = first.Write(malformed)
	requireStreamTerminated(t, first, 10*time.Second,
		"the first tunnel's framing must be rejected")

	// Second tunnel on the SAME connection. It must be established and must carry
	// traffic, which proves the first tunnel's failure was scoped to its own request.
	second, secondResponse := client.openTunnel(t, server.origin)
	require.Equal(t, http.StatusOK, secondResponse.StatusCode,
		"a malformed capsule on ONE request must not prevent a NEW tunnel on the same "+
			"HTTP/3 connection. Holding a client's whole connection hostage for one "+
			"bad stream would turn a stream-level error into a connection-level "+
			"denial of service")
	defer second.Close()

	require.NoError(t, writeDatagramCapsuleToStream(second, []byte("second-tunnel")))
	require.Contains(t, string(readDatagramCapsuleWithTimeout(t, second, 15*time.Second)),
		"second-tunnel",
		"the second tunnel must actually carry traffic, so \"the connection survived\" "+
			"means more than \"the stream opened\"")
}

// requireStreamTerminated asserts the request stream stops delivering data within a
// bounded window.
//
// Either shape of termination is accepted, and the distinction is deliberate:
//
//	io.EOF        a clean end of stream, which is what a server that closes the
//	              request without an error code produces;
//	any other err a reset or a cancellation, which is what the http3 error codes
//	              produce.
//
// Both mean the server STOPPED. The outcome that must not be accepted is a read that
// is still parked after the deadline: that would mean the server neither parsed the
// malformed frame nor failed on it, which is the resynchronisation hazard this test
// exists to rule out.
//
// The helper therefore watches the stream's own error signal rather than doing a bare
// read, which would hang.
func requireStreamTerminated(t *testing.T, stream *http3.RequestStream, timeout time.Duration, message string) {
	t.Helper()

	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 256)
		for {
			_, err := stream.Read(buffer)
			if err != nil {
				done <- err
				return
			}
		}
	}()

	select {
	case err := <-done:
		// Any error, EOF included, means the stream stopped delivering. The point is
		// that it TERMINATED, not which code it carried: an EOF and a reset are both
		// "the server refused to continue", and which one a given server sends is an
		// implementation detail of the HTTP/3 layer rather than a protocol difference.
		require.Error(t, err)
	case <-time.After(timeout):
		select {
		case err := <-done:
			require.Error(t, err)
		default:
			t.Fatalf("%s (the stream neither delivered data nor signalled an error "+
				"within %v)", message, timeout)
		}
	}
}
