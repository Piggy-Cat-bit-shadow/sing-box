package reference_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/stretchr/testify/require"
)

// CONNECT-IP over HTTP/3 to a peer that does NOT support HTTP Datagrams.
//
// This is the CONNECT-IP half of the RFC 9297 fallback, and it is a genuinely
// different code path from the CONNECT-UDP half:
//
//   - CONNECT-UDP on the http inbound is carried by
//     transport/http/capsule.go http3PacketConn.WritePacket;
//   - CONNECT-IP on the masque-server endpoint is carried by
//     transport/masque/session.go session.writePacket.
//
// Phase 2 proved the first and could not prove the second, because every client
// it had negotiated datagrams. The reference connect-ip-go client always enables
// them, so it can never exercise this. The peer here is therefore built directly
// on quic-go's HTTP/3 API with datagram support switched OFF, which is the only
// way to reach the fallback.
//
// Two things are asserted, and the second is the one that was suspected of being
// broken:
//
//  1. the payload travels as DATAGRAM capsules on the request stream, in both
//     directions;
//  2. the tunnel STAYS ALIVE while doing so.

// datagramDisabledConnectIPClient is an HTTP/3 peer whose datagram support is
// explicitly off.
type datagramDisabledConnectIPClient struct {
	clientConn *http3.ClientConn
	transport  *http3.Transport
	quicConn   *quic.Conn
}

// startDatagramDisabledConnectIPClient dials the CONNECT-IP endpoint without
// advertising SETTINGS_H3_DATAGRAM.
//
// The QUIC layer still enables datagrams, because that is a transport capability
// negotiated independently of the HTTP/3 setting that tells the peer whether the
// application may use them. What matters for the fallback is the HTTP/3 setting,
// and that is what `http3.Transport{EnableDatagrams: false}` controls.
func startDatagramDisabledConnectIPClient(t *testing.T, server *singBoxServer) *datagramDisabledConnectIPClient {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddr(ctx, server.address(), &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err)

	transport := &http3.Transport{EnableDatagrams: false}
	client := &datagramDisabledConnectIPClient{
		clientConn: transport.NewClientConn(quicConn),
		transport:  transport,
		quicConn:   quicConn,
	}
	t.Cleanup(func() {
		client.clientConn.CloseWithError(0, "")
		transport.Close()
		_ = quicConn.CloseWithError(0, "")
	})
	return client
}

// openTunnel performs the CONNECT-IP extended CONNECT and returns the request
// stream plus the response.
func (c *datagramDisabledConnectIPClient) openTunnel(t *testing.T, server *singBoxServer) (*http3.RequestStream, *http.Response) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	template, err := uritemplate.New(server.connectIPURL())
	require.NoError(t, err)
	requestURL, err := url.Parse(template.Raw())
	require.NoError(t, err)

	// The :protocol pseudo-header travels through Proto for HTTP/3; putting it in
	// the header map is rejected as an invalid header name.
	request := &http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-ip",
		URL:    requestURL,
		Host:   referenceTestTLSName,
		Header: http.Header{
			"Capsule-Protocol": []string{"?1"},
			"Authorization":    []string{basicAuthorization()},
		},
	}
	require.NoError(t, stream.SendRequestHeader(request))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"the CONNECT-IP extended CONNECT must be accepted")
	return stream, response
}

// TestReferenceConnectIPDatagramFallbackKeepsTheTunnelAlive is the end-to-end
// fallback proof for CONNECT-IP.
//
// The client cannot receive datagrams and says so. Everything must therefore
// travel as DATAGRAM capsules on the request stream, and the tunnel must survive
// the exchange.
//
// The failure this guards against is specific: transport/masque/session.go starts
// loopDatagram whenever the stream implements the DatagramStream interface, and
// HTTP3StreamFunc returns that implementation even when the peer disabled
// datagrams. loopDatagram then calls ReceiveDatagram, which cannot succeed on a
// connection where the extension was not negotiated, and its error handler calls
// s.cancel(err) - cancelling the WHOLE session. A tunnel that should simply fall
// back to capsules would be torn down instead.
func TestReferenceConnectIPDatagramFallbackKeepsTheTunnelAlive(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	client := startDatagramDisabledConnectIPClient(t, server)

	// Confirm the settings exchange before relying on it.
	//
	// NOTE ON DIRECTION, because getting it wrong here is easy and the first
	// version of this test did: ClientConn.Settings() returns the PEER's settings,
	// i.e. what the SERVER advertised, not what this client sent. The server
	// always advertises datagram support - that is its own capability and is
	// correct - so asserting !Settings().EnableDatagrams is asserting the wrong
	// thing entirely and fails against a correct server.
	//
	// What matters for this test is that THIS CLIENT did not offer datagram
	// support. That is a property of the client's configuration, so it is checked
	// there, and the server-side consequence is checked by the data path itself:
	// if the server thought datagrams were available it would answer with one,
	// and the capsule read below would time out.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	select {
	case <-client.clientConn.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("the client never received the server's HTTP/3 SETTINGS")
	}
	require.False(t, client.transport.EnableDatagrams,
		"this client must be configured with datagram support OFF, or the test "+
			"measures the datagram path instead of the fallback")
	require.True(t, client.clientConn.Settings().EnableDatagrams,
		"the SERVER must still advertise datagram support: it is the server's own "+
			"capability, independent of what this client offers")

	stream, response := client.openTunnel(t, server)
	defer response.Body.Close()

	// ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT travel as CAPSULES from the start,
	// because they are control capsules and never datagrams. Reading them proves
	// the capsule path is live before the data path is exercised.
	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid(),
		"the server must assign an address over the capsule path")
	require.NotEmpty(t, routes,
		"the server must advertise routes over the capsule path")

	t.Logf("connect-ip fallback: assigned=%s routes=%d datagrams=disabled",
		assigned, len(routes))

	// Now the data path. The payload is a complete IPv4 + ICMP echo request aimed
	// at the server's own gateway, which is the one destination guaranteed to
	// answer without any external dependency.
	gateway := serverGatewayAddress(t)
	const identifier = 0x7c31
	const sequence = 11
	payload := []byte("connect-ip-capsule-fallback")

	packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, identifier, sequence, payload)

	// Outbound: the client has no datagrams, so it writes a DATAGRAM capsule.
	require.NoError(t, writeDatagramCapsuleToStream(stream, packet),
		"the client must be able to send an IP packet as a capsule")

	// Inbound: the server must answer as a capsule too, because this peer cannot
	// receive datagrams.
	reply := readDatagramCapsuleWithTimeout(t, stream, 15*time.Second)
	require.NotEmpty(t, reply,
		"the server must fall back to a DATAGRAM capsule for a peer without "+
			"datagram support; without the fallback nothing arrives here")

	require.Equal(t, byte(4), reply[0]>>4, "the reply must be IPv4")
	require.Equal(t, byte(1), reply[9], "the reply must carry ICMP")
	icmp := reply[20:]
	require.Equal(t, uint8(0), icmp[0],
		"the reply must be an echo REPLY sourced from the gateway")
	require.Equal(t, gateway.As4(), [4]byte(reply[12:16]))
	require.Equal(t, assigned.Addr().As4(), [4]byte(reply[16:20]))

	// THE POINT: the tunnel must still be usable after all of that. A session
	// cancelled by a failed datagram receive would produce a closed stream here,
	// which is exactly the bug this test exists to catch.
	second := append([]byte(nil), payload...)
	second[0] = 'C'
	packet2 := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, identifier, sequence+1, second)
	require.NoError(t, writeDatagramCapsuleToStream(stream, packet2),
		"the tunnel must remain writable after a capsule exchange with no datagram "+
			"support; a failure here means the session was cancelled")

	reply2 := readDatagramCapsuleWithTimeout(t, stream, 15*time.Second)
	require.NotEmpty(t, reply2, "the tunnel must still deliver replies")
	require.Equal(t, uint16(sequence+1), uint16(reply2[26])<<8|uint16(reply2[27]),
		"the second reply must answer the second request, proving the tunnel "+
			"carried more than one exchange")
}

// TestReferenceConnectIPDatagramFallbackDoesNotSendDatagrams is the counter-case
// for the fallback above.
//
// The same endpoint, the same request, but a peer that DOES advertise datagram
// support. If the payload still arrived as a capsule the fallback above would be
// proving nothing about capability negotiation, so this pins that the server
// takes the datagram path when the peer offers it.
func TestReferenceConnectIPDatagramFallbackDoesNotSendDatagrams(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	// The reference client always advertises datagrams, which is exactly what
	// makes it the right peer for this half.
	conn := dialReferenceConnectIP(t, server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	assignments, err := conn.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	var assigned netip.Prefix
	for _, assignment := range assignments {
		if assignment.IPPrefix.IsValid() {
			assigned = assignment.IPPrefix
			break
		}
	}
	require.True(t, assigned.IsValid())

	gateway := serverGatewayAddress(t)
	request := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, 0x5150, 3, []byte("datagram-path"))
	icmpReply, err := conn.WritePacket(request)
	require.NoError(t, err)
	require.Empty(t, icmpReply, "the packet must be forwarded, not answered locally")

	reply := make([]byte, 1500)
	done := make(chan error, 1)
	go func() {
		_, readErr := conn.ReadPacket(reply)
		done <- readErr
	}()
	select {
	case readErr := <-done:
		require.NoError(t, readErr)
	case <-time.After(15 * time.Second):
		t.Fatal("a datagram-capable peer must receive its answer")
	}
	require.Equal(t, uint8(0), reply[20],
		"a datagram-capable peer must receive a normal echo reply over the "+
			"datagram path")
}
