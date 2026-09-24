package main

import (
	std_bufio "bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

const proxyAuthorization = "Basic c2VrYWk6cGFzc3dvcmQ="

func startTLSHTTPInbound(t *testing.T, certPem string, keyPem string, versions []int, extraOutbounds []option.Outbound) {
	outbounds := append([]option.Outbound{{Type: C.TypeDirect}}, extraOutbounds...)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeHTTP,
				Options: &option.HTTPInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: serverPort,
					},
					Version: versions,
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
		Outbounds: outbounds,
	})
}

func dialHTTP2Proxy(t *testing.T, port uint16) *http2.ClientConn {
	tlsConn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         "example.org",
		InsecureSkipVerify: true,
		NextProtos:         []string{http2.NextProtoTLS},
	})
	require.NoError(t, err)
	require.Equal(t, http2.NextProtoTLS, tlsConn.ConnectionState().NegotiatedProtocol)
	clientConn, err := (&http2.Transport{}).NewClientConn(tlsConn)
	require.NoError(t, err)
	t.Cleanup(func() {
		clientConn.Close()
	})
	return clientConn
}

type http2Tunnel struct {
	writer   *io.PipeWriter
	response *http.Response
}

func openHTTP2Tunnel(t *testing.T, clientConn *http2.ClientConn, host string, authorization string) *http2Tunnel {
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: host},
		Host:   host,
		Header: make(http.Header),
		Body:   pipeReader,
	}
	if authorization != "" {
		request.Header.Set("Proxy-Authorization", authorization)
	}
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	return &http2Tunnel{writer: pipeWriter, response: response}
}

func (t *http2Tunnel) close() {
	t.writer.Close()
	t.response.Body.Close()
}

func TestHTTPInboundHTTP2(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, nil, nil)
	origin := newForwardOrigin(t)
	clientConn := dialHTTP2Proxy(t, serverPort)

	rejected := openHTTP2Tunnel(t, clientConn, origin.host(), "")
	require.Equal(t, http.StatusProxyAuthRequired, rejected.response.StatusCode)
	require.Contains(t, rejected.response.Header.Get("Proxy-Authenticate"), "Basic")
	rejected.close()

	first := openHTTP2Tunnel(t, clientConn, origin.host(), proxyAuthorization)
	require.Equal(t, http.StatusOK, first.response.StatusCode)
	second := openHTTP2Tunnel(t, clientConn, origin.host(), proxyAuthorization)
	require.Equal(t, http.StatusOK, second.response.StatusCode)
	for _, tunnel := range []*http2Tunnel{second, first} {
		_, err := tunnel.writer.Write([]byte("GET /hello HTTP/1.1\r\nHost: " + origin.host() + "\r\n\r\n"))
		require.NoError(t, err)
		response, err := http.ReadResponse(std_bufio.NewReader(tunnel.response.Body), nil)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, "hello", string(body))
		tunnel.close()
	}

	request, err := http.NewRequest(http.MethodGet, origin.url("/hello"), nil)
	require.NoError(t, err)
	request.Header.Set("User-Agent", "")
	request.Header.Set("Proxy-Authorization", proxyAuthorization)
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "hello", string(body))
	require.Equal(t, origin.host(), response.Header.Get("X-Host"))

	response, err = clientConn.RoundTrip(request)
	require.NoError(t, err)
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))
	require.Equal(t, int32(4), origin.connections.Load())
}

func TestHTTPForwardEarlyResponse(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, nil, nil)
	origin := startEarlyResponseOrigin(t)
	clientConn := dialHTTP2Proxy(t, serverPort)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+origin.String()+"/upload", io.LimitReader(rand.Reader, 4<<20))
	require.NoError(t, err)
	request.ContentLength = 4 << 20
	request.Header.Set("Proxy-Authorization", proxyAuthorization)
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "ok", string(body))
}

func TestHTTPInboundHTTP2Cleartext(t *testing.T) {
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeHTTP,
				Options: &option.HTTPInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: serverPort,
					},
					Version: []int{2},
					Users:   []auth.User{{Username: "sekai", Password: "password"}},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	origin := newForwardOrigin(t)
	http1Conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(serverPort)))
	require.NoError(t, err)
	defer http1Conn.Close()
	_, err = http1Conn.Write([]byte("CONNECT " + origin.host() + " HTTP/1.1\r\nHost: " + origin.host() + "\r\nProxy-Authorization: " + proxyAuthorization + "\r\n\r\n"))
	require.NoError(t, err)
	http1Response, err := http.ReadResponse(std_bufio.NewReader(http1Conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusHTTPVersionNotSupported, http1Response.StatusCode)
	require.True(t, http1Response.Close)

	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(serverPort)))
	require.NoError(t, err)
	clientConn, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(conn)
	require.NoError(t, err)
	defer clientConn.Close()
	tunnel := openHTTP2Tunnel(t, clientConn, origin.host(), proxyAuthorization)
	require.Equal(t, http.StatusOK, tunnel.response.StatusCode)
	_, err = tunnel.writer.Write([]byte("GET /hello HTTP/1.1\r\nHost: " + origin.host() + "\r\n\r\n"))
	require.NoError(t, err)
	response, err := http.ReadResponse(std_bufio.NewReader(tunnel.response.Body), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))
	tunnel.close()

	forwardRequest, err := http.NewRequest(http.MethodGet, origin.url("/hello"), nil)
	require.NoError(t, err)
	forwardRequest.Header.Set("Proxy-Authorization", proxyAuthorization)
	forwardResponse, err := clientConn.RoundTrip(forwardRequest)
	require.NoError(t, err)
	forwardResponse.Body.Close()
	require.Equal(t, http.StatusBadRequest, forwardResponse.StatusCode)
}

func startSwitchingProtocolsOrigin(t *testing.T) *net.TCPAddr {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, err := http.ReadRequest(std_bufio.NewReader(conn))
				if err != nil {
					return
				}
				conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

func TestHTTPForwardUnexpectedSwitchingProtocols(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, nil, nil)
	origin := startSwitchingProtocolsOrigin(t)
	clientConn := dialHTTP2Proxy(t, serverPort)
	request, err := http.NewRequest(http.MethodGet, "http://"+origin.String()+"/", nil)
	require.NoError(t, err)
	request.Header.Set("Proxy-Authorization", proxyAuthorization)
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, http.StatusBadGateway, response.StatusCode)
}

func startTruncatedChunkedOrigin(t *testing.T) *net.TCPAddr {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, err := http.ReadRequest(std_bufio.NewReader(conn))
				if err != nil {
					return
				}
				conn.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"))
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

func TestHTTPForwardHTTP2Responses(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, nil, nil)
	clientConn := dialHTTP2Proxy(t, serverPort)

	origin := newForwardOrigin(t)
	headRequest, err := http.NewRequest(http.MethodHead, origin.url("/hello"), nil)
	require.NoError(t, err)
	headRequest.Header.Set("User-Agent", "")
	headRequest.Header.Set("Proxy-Authorization", proxyAuthorization)
	headResponse, err := clientConn.RoundTrip(headRequest)
	require.NoError(t, err)
	headResponse.Body.Close()
	require.Equal(t, http.StatusOK, headResponse.StatusCode)
	require.Equal(t, int64(5), headResponse.ContentLength)

	trailerRequest, err := http.NewRequest(http.MethodGet, origin.url("/trailer"), nil)
	require.NoError(t, err)
	trailerRequest.Header.Set("Proxy-Authorization", proxyAuthorization)
	trailerResponse, err := clientConn.RoundTrip(trailerRequest)
	require.NoError(t, err)
	trailerBody, err := io.ReadAll(trailerResponse.Body)
	require.NoError(t, err)
	trailerResponse.Body.Close()
	require.Equal(t, "hello", string(trailerBody))
	require.Equal(t, "5d41402a", trailerResponse.Trailer.Get("X-Checksum"))

	streamRequest, err := http.NewRequest(http.MethodGet, origin.url("/stream"), nil)
	require.NoError(t, err)
	streamRequest.Header.Set("Proxy-Authorization", proxyAuthorization)
	startTime := time.Now()
	streamResponse, err := clientConn.RoundTrip(streamRequest)
	require.NoError(t, err)
	require.Less(t, time.Since(startTime), time.Second)
	streamBody, err := io.ReadAll(streamResponse.Body)
	streamResponse.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "late", string(streamBody))

	truncated := startTruncatedChunkedOrigin(t)
	request, err := http.NewRequest(http.MethodGet, "http://"+truncated.String()+"/", nil)
	require.NoError(t, err)
	request.Header.Set("Proxy-Authorization", proxyAuthorization)
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	_, err = io.ReadAll(response.Body)
	response.Body.Close()
	require.Error(t, err)
}
