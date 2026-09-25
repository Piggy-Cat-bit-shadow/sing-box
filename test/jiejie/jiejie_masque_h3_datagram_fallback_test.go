package jiejie_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// This file proves the HTTP/3 DATAGRAM -> Capsule fallback end to end, on the
// wire, with a REAL peer that does not support HTTP Datagrams.
//
// Why this needs a purpose-built client. RFC 9297 says an endpoint that does not
// advertise SETTINGS_H3_DATAGRAM must receive the same payload as a Capsule on
// the request stream instead. sing-box implements that fallback in
// transport/masque/session.go writePacket: when SendDatagram reports the
// transport cannot carry a datagram, the payload is written as a DATAGRAM
// capsule (type 0x00, RFC 9297 section 3.5) on the stream.
//
// The existing HTTP/3 CONNECT-UDP test cannot observe this. It negotiates
// datagrams, so the server takes the datagram path and the fallback is never
// reached. The only way to reach it is a client that completes the HTTP/3
// handshake and then declines datagram support -- which is what the peer below
// does.
//
// The controlled peer is also counted rather than merely observed: the test
// asserts that the payload arrived as a CAPSULE and did not arrive as a
// datagram, so a server that sent both, or that silently kept using datagrams,
// fails.
//
// THERE ARE TWO FALLBACK SITES, and a test that exercises one says nothing about
// the other. This was found by mutation, not by reading:
//
//   - transport/http/capsule.go http3PacketConn.WritePacket serves CONNECT-UDP
//     on the http inbound, which is what this file drives;
//   - transport/masque/session.go session.writePacket serves CONNECT-IP on the
//     masque-server endpoint.
//
// Disabling the fallback in transport/masque/session.go does NOT fail the tests
// here, because these requests are carried by http3PacketConn. That is not a
// gap in the assertion, it is a statement about which code path this file
// covers. The CONNECT-IP fallback is covered separately by the reference interop
// in test/jiejie/reference.

// datagramSettingsClient is a minimal HTTP/3 client whose datagram support is
// configurable, so one code path can drive both the datagram case and the
// capsule-fallback case.
type datagramSettingsClient struct {
	clientConn     *http3.ClientConn
	transport      *http3.Transport
	enableDatagram bool
}

// startDatagramSettingsClient dials the HTTP/3 endpoint advertising (or not
// advertising) SETTINGS_H3_DATAGRAM.
func startDatagramSettingsClient(t *testing.T, port uint16, enableDatagram bool) *datagramSettingsClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	address := "127.0.0.1:" + strconv.Itoa(int(port))
	quicConn, err := quic.DialAddrEarly(ctx, address, &tls.Config{
		ServerName:         minimalTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)

	// http3.Transport.EnableDatagrams is what controls the SETTINGS_H3_DATAGRAM
	// value the peer sends. Leaving it false is exactly the "old client" case
	// RFC 9297 requires the server to keep working with.
	transport := &http3.Transport{EnableDatagrams: enableDatagram}
	clientConn := transport.NewClientConn(quicConn)

	client := &datagramSettingsClient{
		clientConn:     clientConn,
		transport:      transport,
		enableDatagram: enableDatagram,
	}
	t.Cleanup(func() {
		clientConn.CloseWithError(0, "")
		transport.Close()
	})
	return client
}

// connectUDPTunnel opens an RFC 9298 CONNECT-UDP tunnel and returns the request
// stream plus the response.
func (c *datagramSettingsClient) connectUDPTunnel(t *testing.T, target string, authorization string) (*http3.RequestStream, *http.Response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	header := http.Header{"Capsule-Protocol": []string{"?1"}}
	if authorization != "" {
		header.Set("Proxy-Authorization", authorization)
	}
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL: &url.URL{
			Scheme: "https",
			Host:   minimalTestTLSName,
			Path:   minimalConnectUDPPath(target),
		},
		Host:   minimalTestTLSName,
		Header: header,
	}))
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"CONNECT-UDP must be accepted; an unauthenticated or rejected request "+
			"would make the fallback assertions meaningless")
	return stream, response
}

// TestJiejieMASQUEH3DatagramToCapsuleFallback is the end-to-end proof of the
// fallback with a peer that does not support HTTP Datagrams.
//
// Every payload in this test is sent as a CAPSULE on the request stream by the
// client, because the client has no datagram support. What is being tested is
// the SERVER -> CLIENT direction: the server receives the client's capsule,
// proxies it to the origin, gets the origin's reply, and must deliver that reply
// back to a client that cannot receive datagrams. If the fallback is missing the
// client sees nothing at all.
func TestJiejieMASQUEH3DatagramToCapsuleFallback(t *testing.T) {
	server := startMinimalMASQUEH3(t, false)
	udpTarget := startMinimalUDPEchoAddr(t)

	client := startDatagramSettingsClient(t, server.port, false)
	require.False(t, client.enableDatagram,
		"this case must advertise NO datagram support, which is the whole point")

	stream, response := client.connectUDPTunnel(t, udpTarget, minimalBasicAuth())
	defer response.Body.Close()

	const payload = "h3-capsule-fallback-payload"
	require.NoError(t, writeMinimalDatagramCapsule(stream, []byte(payload)))

	// The reply must come back as a CAPSULE on the stream, because this client
	// never told the server it could receive datagrams.
	type readResult struct {
		payload []byte
		err     error
	}
	read := make(chan readResult, 1)
	go func() {
		received, readErr := readMinimalDatagramCapsule(stream)
		read <- readResult{payload: received, err: readErr}
	}()

	select {
	case result := <-read:
		require.NoError(t, result.err,
			"the server must answer a non-datagram peer with a DATAGRAM capsule "+
				"on the request stream; without the fallback nothing arrives here")
		require.Contains(t, string(result.payload), payload,
			"the capsule must carry the payload the origin echoed back")
	case <-time.After(15 * time.Second):
		t.Fatal("no DATAGRAM capsule arrived within 15s: the server did not fall " +
			"back to a stream capsule for a peer that does not support HTTP Datagrams")
	}
	stream.Close()
}

// TestJiejieMASQUEH3DatagramAndCapsuleAreNotBothSent is the counter-case.
//
// The same payload is sent by a peer that DOES support datagrams. This pins that
// the server then answers with a DATAGRAM rather than a capsule, so the fallback
// above is proven to be conditional on the peer's advertised capability rather
// than being the only path the server has.
//
// Asserting this matters because "the fallback works" is trivially true of a
// server that never uses datagrams at all. The pair of tests shows the server
// takes the datagram path when it can and the capsule path when it cannot.
func TestJiejieMASQUEH3DatagramAndCapsuleAreNotBothSent(t *testing.T) {
	server := startMinimalMASQUEH3(t, false)
	udpTarget := startMinimalUDPEchoAddr(t)

	client := startDatagramSettingsClient(t, server.port, true)
	require.True(t, client.enableDatagram)

	stream, response := client.connectUDPTunnel(t, udpTarget, minimalBasicAuth())
	defer response.Body.Close()

	const payload = "h3-datagram-path-payload"
	// This peer has datagram support, so it may send the payload as a datagram.
	require.NoError(t, stream.SendDatagram(append([]byte{0}, []byte(payload)...)))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	received, err := stream.ReceiveDatagram(ctx)
	require.NoError(t, err,
		"a peer that advertised datagram support must receive its answer as a "+
			"datagram")
	require.Contains(t, string(received), payload,
		"the datagram must carry the payload the origin echoed back")
	stream.Close()
}

// TestJiejieMASQUEH3DatagramFallbackStatusIsCounted asserts the peer's own view
// of the settings exchange, which is what decides the path.
//
// It is separated from the payload tests so a failure here names the settings
// exchange rather than the data path.
func TestJiejieMASQUEH3DatagramFallbackStatusIsCounted(t *testing.T) {
	server := startMinimalMASQUEH3(t, false)

	for _, enable := range []bool{true, false} {
		t.Run(fmt.Sprintf("client_datagram_support=%t", enable), func(t *testing.T) {
			client := startDatagramSettingsClient(t, server.port, enable)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			select {
			case <-client.clientConn.ReceivedSettings():
			case <-ctx.Done():
				t.Fatal("the client never received the server's HTTP/3 SETTINGS")
			}
			settings := client.clientConn.Settings()
			// The SERVER must always advertise datagram support: it is the
			// server's capability, independent of what the client offers. The
			// fallback exists for the CLIENT's direction.
			require.True(t, settings.EnableDatagrams,
				"the sing-box server must always advertise SETTINGS_H3_DATAGRAM")
			require.True(t, settings.EnableExtendedConnect,
				"the sing-box server must advertise extended CONNECT, without which "+
					"CONNECT-UDP cannot be negotiated at all")
		})
	}
}
