//go:build with_quic

package main

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func dialHTTP3Proxy(t *testing.T, port uint16, enableDatagrams bool) *http3.ClientConn {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddrEarly(ctx, "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         "example.org",
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: enableDatagrams})
	require.NoError(t, err)
	transport := &http3.Transport{EnableDatagrams: enableDatagrams}
	clientConn := transport.NewClientConn(quicConn)
	t.Cleanup(func() {
		clientConn.CloseWithError(0, "")
		transport.Close()
	})
	return clientConn
}

func TestHTTPInboundHTTP3(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, []int{1, 2, 3}, nil)
	origin := newForwardOrigin(t)
	clientConn := dialHTTP3Proxy(t, serverPort, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: origin.host()},
		Host:   origin.host(),
		Header: http.Header{"Proxy-Authorization": []string{proxyAuthorization}},
	})
	require.NoError(t, err)
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_, err = stream.Write([]byte("GET /hello HTTP/1.1\r\nHost: " + origin.host() + "\r\n\r\n"))
	require.NoError(t, err)
	originResponse, err := http.ReadResponse(std_bufio.NewReader(stream), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(originResponse.Body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))
	stream.Close()

	forward, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	err = forward.SendRequestHeader(&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: origin.host(), Path: "/hello"},
		Host:   origin.host(),
		Header: http.Header{
			"Proxy-Authorization": []string{proxyAuthorization},
			"User-Agent":          nil,
		},
	})
	require.NoError(t, err)
	require.NoError(t, forward.Close())
	forwardResponse, err := forward.ReadResponse()
	require.NoError(t, err)
	body, err = io.ReadAll(forwardResponse.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, forwardResponse.StatusCode)
	require.Equal(t, "hello", string(body))
	forward.Close()

	rejected, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	err = rejected.SendRequestHeader(&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: origin.host(), Path: "/hello"},
		Host:   origin.host(),
		Header: http.Header{"Proxy-Authorization": []string{proxyAuthorization}},
	})
	require.NoError(t, err)
	require.NoError(t, rejected.Close())
	rejectedResponse, err := rejected.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rejectedResponse.StatusCode)
}

func openHTTP3ConnectUDP(t *testing.T, ctx context.Context, clientConn *http3.ClientConn, path string) *http3.RequestStream {
	stream, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.org",
			Path:   path,
		},
		Host: "example.org",
		Header: http.Header{
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{proxyAuthorization},
		},
	})
	require.NoError(t, err)
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	return stream
}

func TestHTTPInboundConnectUDPHTTP3(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, []int{1, 2, 3}, nil)
	echo := startUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientConn := dialHTTP3Proxy(t, serverPort, true)
	stream := openHTTP3ConnectUDP(t, ctx, clientConn, connectUDPPath(echo))
	for i := 0; i < 3; i++ {
		err := stream.SendDatagram(append([]byte{0}, []byte("ping")...))
		require.NoError(t, err)
		datagram, err := stream.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, append([]byte{0}, []byte("ping")...), datagram)
	}
	writeDatagramCapsule(t, stream, []byte("capsule"))
	datagram, err := stream.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, append([]byte{0}, []byte("capsule")...), datagram)
	err = stream.SendDatagram(append([]byte{0x40, 0x00}, []byte("varint")...))
	require.NoError(t, err)
	datagram, err = stream.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, append([]byte{0}, []byte("varint")...), datagram)
	stream.Close()

	capsuleConn := dialHTTP3Proxy(t, serverPort, false)
	capsuleStream := openHTTP3ConnectUDP(t, ctx, capsuleConn, connectUDPPath(echo))
	reader := std_bufio.NewReader(capsuleStream)
	for i := 0; i < 3; i++ {
		writeDatagramCapsule(t, capsuleStream, []byte("capsule"))
		require.Equal(t, "capsule", string(readDatagramCapsule(t, reader)))
	}
	capsuleStream.Close()
}

func startHTTP3OnlyInbound(t *testing.T, certPem string, keyPem string) {
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeHTTP,
				Options: &option.HTTPInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: serverPort,
					},
					Version: []int{3},
					Users:   []auth.User{{Username: "sekai", Password: "password"}},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							KeyPath:         keyPem,
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
}
