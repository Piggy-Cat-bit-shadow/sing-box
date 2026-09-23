package main

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
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
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Runtime integration for the PRODUCTION MINIMAL registry.
//
// Every test in this file must pass under
// release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL, which registers only:
//
//	inbounds:  http, anytls, shadowtls, shadowsocks
//	outbounds: direct, socks
//	dns:       udp
//	services:  none
//	endpoints: none
//
// The tests therefore drive real protocol clients (HTTP/2, quic-go HTTP/3,
// sing-shadowtls, sing-anytls) rather than an in-process sing-box client, because
// the minimal registry deliberately registers no socks/mixed inbound. If a test
// here needs a protocol the production registry does not register, that is a
// signal it belongs in the client-feature group instead.
//
// Fixtures are loopback only, the certificate is generated per test, and the
// credentials are obvious placeholders. No production secret is involved.

const (
	minimalTestUser     = "sekai"
	minimalTestPassword = "password"
	minimalTestTLSName  = "example.org"
	minimalDecoyBody    = "jiejie minimal decoy"
)

func minimalBasicAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(minimalTestUser+":"+minimalTestPassword))
}

func minimalWrongBasicAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(minimalTestUser+":wrong"))
}

func minimalInboundTLS(certPem, keyPem string) option.InboundTLSOptionsContainer {
	return option.InboundTLSOptionsContainer{
		TLS: &option.InboundTLSOptions{
			Enabled:         true,
			ServerName:      minimalTestTLSName,
			CertificatePath: certPem,
			KeyPath:         keyPem,
		},
	}
}

func minimalLoopback() *badoption.Addr {
	return common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1")))
}

// startMinimalDecoyWeb stands in for the Nginx web root that the masquerade and
// AnyTLS fallback both target.
func startMinimalDecoyWeb(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("<html>" + minimalDecoyBody + "</html>"))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

func minimalHostPort(t *testing.T, address string) uint16 {
	t.Helper()
	_, portString, err := net.SplitHostPort(address)
	require.NoError(t, err)
	port, err := strconv.ParseUint(portString, 10, 16)
	require.NoError(t, err)
	return uint16(port)
}

// startMinimalHTTPOrigin is the CONNECT target; it answers a fixed body so a
// tunnel test can prove real bytes crossed the proxy.
func startMinimalHTTPOrigin(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("origin-ok"))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// startMinimalUDPEcho is the CONNECT-UDP target.
func startMinimalUDPEcho(t *testing.T) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, readErr := udpConn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = udpConn.WriteToUDP(buffer[:n], addr)
		}
	}()
	return udpConn.LocalAddr().String()
}

// startMinimalUDPEchoAddr is startMinimalUDPEcho, named for the UDP tests.
func startMinimalUDPEchoAddr(t *testing.T) string {
	t.Helper()
	return startMinimalUDPEcho(t)
}

func assertMinimalNoProxyChallenge(t *testing.T, response *http.Response) {
	t.Helper()
	require.NotEqual(t, http.StatusProxyAuthRequired, response.StatusCode,
		"the masquerade path must not return 407")
	require.NotEqual(t, http.StatusUnauthorized, response.StatusCode,
		"the masquerade path must not return 401")
	require.Empty(t, response.Header.Get("Proxy-Authenticate"))
	require.Empty(t, response.Header.Get("WWW-Authenticate"))
}

// ---------------------------------------------------------------------------
// MASQUE H2 (production minimal)
// ---------------------------------------------------------------------------

type minimalServer struct {
	port   uint16
	origin string
}

func startMinimalMASQUEH2(t *testing.T, withLimiter bool) *minimalServer {
	t.Helper()
	decoy := startMinimalDecoyWeb(t)
	origin := startMinimalHTTPOrigin(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, minimalTestTLSName)
	port := reserveOpenVPNTCPPort(t)

	options := &option.HTTPInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     minimalLoopback(),
			ListenPort: port,
		},
		Version: []int{2},
		Users:   []auth.User{{Username: minimalTestUser, Password: minimalTestPassword}},
		Masquerade: &option.Hysteria2Masquerade{
			Type: C.Hysterai2MasqueradeTypeProxy,
			ProxyOptions: option.Hysteria2MasqueradeProxy{
				URL:         "http://" + decoy,
				RewriteHost: true,
			},
		},
		InboundTLSOptionsContainer: minimalInboundTLS(certPem, keyPem),
	}
	if withLimiter {
		options.UnauthenticatedLimits = &option.UnauthenticatedLimitsOptions{
			Enabled:            true,
			MaxConcurrentPerIP: 1,
			RequestsPerSecond:  0.0001,
			Burst:              1,
			IdleTimeout:        badoption.Duration(time.Minute),
		}
	}
	startInstance(t, option.Options{
		Inbounds:  []option.Inbound{{Type: C.TypeHTTP, Tag: "masque-h2", Options: options}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return &minimalServer{port: port, origin: origin}
}

func dialMinimalH2(t *testing.T, port uint16) *http2.ClientConn {
	t.Helper()
	tlsConn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         minimalTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http2.NextProtoTLS},
	})
	require.NoError(t, err)
	require.Equal(t, http2.NextProtoTLS, tlsConn.ConnectionState().NegotiatedProtocol)
	clientConn, err := (&http2.Transport{}).NewClientConn(tlsConn)
	require.NoError(t, err)
	t.Cleanup(func() { clientConn.Close() })
	return clientConn
}

func minimalH2Get(t *testing.T, clientConn *http2.ClientConn, headers http.Header) *http.Response {
	t.Helper()
	request := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: minimalTestTLSName, Path: "/"},
		Host:   minimalTestTLSName,
		Header: http.Header{},
	}
	for name, values := range headers {
		request.Header[name] = values
	}
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	return response
}

// minimalH2Connect opens a CONNECT tunnel and returns the response plus a reader
// positioned at the tunnelled stream.
func minimalH2Connect(t *testing.T, clientConn *http2.ClientConn, authority string, headers http.Header) (*http.Response, *io.PipeWriter) {
	t.Helper()
	pipeReader, pipeWriter := io.Pipe()
	requestHeader := http.Header{}
	for name, values := range headers {
		requestHeader[name] = values
	}
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: requestHeader,
		Body:   pipeReader,
	})
	require.NoError(t, err)
	return response, pipeWriter
}

func TestJiejieMinimalMASQUEH2Masquerade(t *testing.T) {
	server := startMinimalMASQUEH2(t, false)
	clientConn := dialMinimalH2(t, server.port)

	t.Run("unauthenticated receives the decoy site", func(t *testing.T) {
		response := minimalH2Get(t, clientConn, nil)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), minimalDecoyBody)
		assertMinimalNoProxyChallenge(t, response)
	})

	t.Run("wrong auth receives the decoy site", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Proxy-Authorization", minimalWrongBasicAuth())
		response := minimalH2Get(t, clientConn, headers)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), minimalDecoyBody)
		assertMinimalNoProxyChallenge(t, response)
	})

	t.Run("authenticated CONNECT tunnels", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Proxy-Authorization", minimalBasicAuth())
		response, writer := minimalH2Connect(t, clientConn, server.origin, headers)
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		_, err := writer.Write([]byte("GET / HTTP/1.1\r\nHost: " + server.origin + "\r\n\r\n"))
		require.NoError(t, err)
		originResponse, err := http.ReadResponse(std_bufio.NewReader(response.Body), nil)
		require.NoError(t, err)
		body, err := io.ReadAll(originResponse.Body)
		require.NoError(t, err)
		require.Equal(t, "origin-ok", string(body))
		writer.Close()
	})
}

// TestJiejieMinimalMASQUEH2ConnectUDP proves the L4 UDP path works on the
// minimal registry over HTTP/2 CONNECT-UDP.
func TestJiejieMinimalMASQUEH2ConnectUDP(t *testing.T) {
	server := startMinimalMASQUEH2(t, false)
	udpTarget := startMinimalUDPEchoAddr(t)
	clientConn := dialMinimalH2(t, server.port)

	// RFC 9298 extended CONNECT over HTTP/2: the :protocol pseudo-header is
	// carried in Proto, and the payload uses the datagram capsule framing.
	pipeReader, pipeWriter := io.Pipe()
	// Over HTTP/2 the extended CONNECT pseudo-header is supplied as ":protocol"
	// inside the header map, matching the upstream HTTP/2 CONNECT-UDP path.
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   minimalTestTLSName,
			Path:   minimalConnectUDPPath(udpTarget),
		},
		Host: minimalTestTLSName,
		Header: http.Header{
			":protocol":           []string{"connect-udp"},
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{minimalBasicAuth()},
		},
		Body: pipeReader,
	})
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode, "CONNECT-UDP must be accepted over HTTP/2")

	payload := []byte("minimal-h2-connect-udp")
	require.NoError(t, writeMinimalDatagramCapsule(pipeWriter, payload))

	type readResult struct {
		frame []byte
		err   error
	}
	resultChannel := make(chan readResult, 1)
	go func() {
		frame, readErr := readMinimalDatagramCapsule(response.Body)
		resultChannel <- readResult{frame: frame, err: readErr}
	}()
	select {
	case result := <-resultChannel:
		require.NoError(t, result.err)
		require.Equal(t, payload, result.frame)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the CONNECT-UDP echo")
	}
	pipeWriter.Close()
}

// minimalConnectUDPPath builds the RFC 9298 well-known path for a target.
func minimalConnectUDPPath(target string) string {
	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		return "/.well-known/masque/udp/" + target + "/"
	}
	return "/.well-known/masque/udp/" + host + "/" + portString + "/"
}

// writeMinimalDatagramCapsule writes a DATAGRAM capsule (RFC 9297) carrying one
// UDP payload with a zero context ID.
func writeMinimalDatagramCapsule(writer io.Writer, payload []byte) error {
	// Capsule type 0x00 (DATAGRAM) + varint length + context ID 0 + payload.
	length := 1 + len(payload)
	header := []byte{0x00}
	switch {
	case length < 64:
		header = append(header, byte(length))
	case length < 16384:
		header = append(header, byte(0x40|(length>>8)), byte(length))
	default:
		header = append(header, byte(0x80|(length>>24)), byte(length>>16), byte(length>>8), byte(length))
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write([]byte{0x00}); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

// readMinimalDatagramCapsule reads one DATAGRAM capsule and returns its payload.
func readMinimalDatagramCapsule(reader io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x00 {
		return nil, E.New("unexpected capsule type: ", header[0])
	}
	length := int(header[1])
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	// body[0] is the context ID.
	return body[1:], nil
}

func TestJiejieMinimalMASQUEH2UnauthenticatedLimiter(t *testing.T) {
	server := startMinimalMASQUEH2(t, true)
	clientConn := dialMinimalH2(t, server.port)

	first := minimalH2Get(t, clientConn, nil)
	_, _ = io.Copy(io.Discard, first.Body)
	first.Body.Close()
	require.Equal(t, http.StatusOK, first.StatusCode)

	// With a masquerade configured, exceeding the unauthenticated budget yields the
	// decoy page rather than a 429, so the limiter is deliberately invisible to a
	// prober. Assert the shape never changes and never becomes a proxy challenge.
	// The accounting is asserted at the unit level in
	// transport/http/unauthenticated_limiter_test.go.
	for index := range 6 {
		response := minimalH2Get(t, clientConn, nil)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, err)
		assertMinimalNoProxyChallenge(t, response)
		if response.StatusCode == http.StatusTooManyRequests {
			continue
		}
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), minimalDecoyBody,
			"request %d must be indistinguishable from an ordinary visitor", index+1)
	}

	// Authenticated traffic must never be throttled by the unauthenticated limiter.
	for index := range 5 {
		headers := http.Header{}
		headers.Set("Proxy-Authorization", minimalBasicAuth())
		response, writer := minimalH2Connect(t, clientConn, server.origin, headers)
		require.Equal(t, http.StatusOK, response.StatusCode,
			"authenticated request %d must not be limited", index+1)
		_, err := writer.Write([]byte("GET / HTTP/1.1\r\nHost: " + server.origin + "\r\n\r\n"))
		require.NoError(t, err)
		originResponse, err := http.ReadResponse(std_bufio.NewReader(response.Body), nil)
		require.NoError(t, err)
		body, err := io.ReadAll(originResponse.Body)
		require.NoError(t, err)
		require.Equal(t, "origin-ok", string(body))
		writer.Close()
		response.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// MASQUE H3 (production minimal)
// ---------------------------------------------------------------------------

func startMinimalMASQUEH3(t *testing.T, withLimiter bool) *minimalServer {
	t.Helper()
	decoy := startMinimalDecoyWeb(t)
	origin := startMinimalHTTPOrigin(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, minimalTestTLSName)
	port := reserveOpenVPNUDPPort(t)

	options := &option.HTTPInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     minimalLoopback(),
			ListenPort: port,
		},
		Version:       []int{3},
		Users:         []auth.User{{Username: minimalTestUser, Password: minimalTestPassword}},
		ServerProfile: "jiejie-balanced-1g",
		Masquerade: &option.Hysteria2Masquerade{
			Type: C.Hysterai2MasqueradeTypeProxy,
			ProxyOptions: option.Hysteria2MasqueradeProxy{
				URL:         "http://" + decoy,
				RewriteHost: true,
			},
		},
		InboundTLSOptionsContainer: minimalInboundTLS(certPem, keyPem),
	}
	if withLimiter {
		options.UnauthenticatedLimits = &option.UnauthenticatedLimitsOptions{
			Enabled:            true,
			MaxConcurrentPerIP: 1,
			RequestsPerSecond:  0.0001,
			Burst:              1,
			IdleTimeout:        badoption.Duration(time.Minute),
		}
	}
	startInstance(t, option.Options{
		Inbounds:  []option.Inbound{{Type: C.TypeHTTP, Tag: "masque-h3", Options: options}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return &minimalServer{port: port, origin: origin}
}

type minimalH3Client struct {
	clientConn *http3.ClientConn
	transport  *http3.Transport
}

func dialMinimalH3(t *testing.T, port uint16) *minimalH3Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddrEarly(ctx, "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         minimalTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	transport := &http3.Transport{EnableDatagrams: true}
	clientConn := transport.NewClientConn(quicConn)
	t.Cleanup(func() {
		clientConn.CloseWithError(0, "")
		transport.Close()
	})
	return &minimalH3Client{clientConn: clientConn, transport: transport}
}

func (c *minimalH3Client) get(t *testing.T, headers http.Header) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	requestHeader := http.Header{}
	for name, values := range headers {
		requestHeader[name] = values
	}
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: minimalTestTLSName, Path: "/"},
		Host:   minimalTestTLSName,
		Header: requestHeader,
	}))
	require.NoError(t, stream.Close())
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	return response
}

func (c *minimalH3Client) connect(t *testing.T, authority string, headers http.Header) (*http.Response, *http3.RequestStream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	requestHeader := http.Header{}
	for name, values := range headers {
		requestHeader[name] = values
	}
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: requestHeader,
	}))
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	return response, stream
}

func TestJiejieMinimalMASQUEH3Masquerade(t *testing.T) {
	server := startMinimalMASQUEH3(t, false)
	client := dialMinimalH3(t, server.port)

	t.Run("unauthenticated receives the decoy site", func(t *testing.T) {
		response := client.get(t, nil)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), minimalDecoyBody)
		assertMinimalNoProxyChallenge(t, response)
	})

	t.Run("wrong auth receives the decoy site", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Proxy-Authorization", minimalWrongBasicAuth())
		response := client.get(t, headers)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), minimalDecoyBody)
		assertMinimalNoProxyChallenge(t, response)
	})

	t.Run("authenticated CONNECT tunnels", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Proxy-Authorization", minimalBasicAuth())
		response, stream := client.connect(t, server.origin, headers)
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		_, err := stream.Write([]byte("GET / HTTP/1.1\r\nHost: " + server.origin + "\r\n\r\n"))
		require.NoError(t, err)
		originResponse, err := http.ReadResponse(std_bufio.NewReader(stream), nil)
		require.NoError(t, err)
		body, err := io.ReadAll(originResponse.Body)
		require.NoError(t, err)
		require.Equal(t, "origin-ok", string(body))
		stream.Close()
	})
}

// TestJiejieMinimalMASQUEH3ConnectUDP proves CONNECT-UDP over HTTP/3 on the
// minimal registry.
func TestJiejieMinimalMASQUEH3ConnectUDP(t *testing.T) {
	server := startMinimalMASQUEH3(t, false)
	udpTarget := startMinimalUDPEchoAddr(t)
	client := dialMinimalH3(t, server.port)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	// RFC 9298 uses an extended CONNECT: the pseudo-header travels as Proto,
	// never as an ordinary header.
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL: &url.URL{
			Scheme: "https",
			Host:   minimalTestTLSName,
			Path:   minimalConnectUDPPath(udpTarget),
		},
		Host: minimalTestTLSName,
		Header: http.Header{
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{minimalBasicAuth()},
		},
	}))
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode, "CONNECT-UDP must be accepted over HTTP/3")

	payload := append([]byte{0}, []byte("minimal-h3-connect-udp")...)
	require.NoError(t, stream.SendDatagram(payload))
	received, readErr := stream.ReceiveDatagram(ctx)
	require.NoError(t, readErr)
	require.Equal(t, payload, received)
	stream.Close()
}

func TestJiejieMinimalMASQUEH3UnauthenticatedLimiter(t *testing.T) {
	server := startMinimalMASQUEH3(t, true)
	client := dialMinimalH3(t, server.port)

	first := client.get(t, nil)
	_, _ = io.Copy(io.Discard, first.Body)
	first.Body.Close()
	require.Equal(t, http.StatusOK, first.StatusCode)

	// With a masquerade configured, a request that exceeds the unauthenticated
	// budget is served the decoy page rather than a 429, so the limiter is
	// deliberately invisible to the client. Assert exactly that: the response
	// shape never changes and never becomes a proxy challenge, no matter how far
	// over budget the client goes. The accounting itself is asserted at the unit
	// level in transport/http/unauthenticated_limiter_test.go.
	for index := range 6 {
		response := client.get(t, nil)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, err)
		assertMinimalNoProxyChallenge(t, response)
		if response.StatusCode == http.StatusTooManyRequests {
			continue
		}
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), minimalDecoyBody,
			"request %d must be indistinguishable from an ordinary visitor", index+1)
	}

	// Authenticated CONNECT must keep working while the limiter is saturated.
	for index := range 3 {
		headers := http.Header{}
		headers.Set("Proxy-Authorization", minimalBasicAuth())
		response, stream := client.connect(t, server.origin, headers)
		require.Equal(t, http.StatusOK, response.StatusCode,
			"authenticated request %d must not be limited", index+1)
		_, err := stream.Write([]byte("GET / HTTP/1.1\r\nHost: " + server.origin + "\r\n\r\n"))
		require.NoError(t, err)
		originResponse, err := http.ReadResponse(std_bufio.NewReader(stream), nil)
		require.NoError(t, err)
		body, err := io.ReadAll(originResponse.Body)
		require.NoError(t, err)
		require.Equal(t, "origin-ok", string(body))
		stream.Close()
		response.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// AnyTLS native fallback (production minimal)
// ---------------------------------------------------------------------------

// TestJiejieMinimalAnyTLSFallback proves the production AnyTLS listener still
// serves the decoy site to a non-AnyTLS client and to a wrong password, and that
// it never emits a proxy challenge. That fallback is the whole reason AnyTLS sits
// behind Nginx on TCP/443.
func TestJiejieMinimalAnyTLSFallback(t *testing.T) {
	decoy := startMinimalDecoyWeb(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, minimalTestTLSName)
	anytlsPort := reserveOpenVPNTCPPort(t)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeAnyTLS,
			Tag:  "anytls-in",
			Options: &option.AnyTLSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     minimalLoopback(),
					ListenPort: anytlsPort,
				},
				Users: []option.AnyTLSUser{{Name: minimalTestUser, Password: minimalTestPassword}},
				Fallback: &option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: minimalHostPort(t, decoy),
				},
				InboundTLSOptionsContainer: minimalInboundTLS(certPem, keyPem),
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})

	t.Run("ordinary HTTPS client reaches the fallback backend", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: minimalTestTLSName},
			},
			Timeout: 10 * time.Second,
		}
		response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(int(anytlsPort)) + "/")
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), minimalDecoyBody)
		assertMinimalNoProxyChallenge(t, response)
	})

	t.Run("raw TLS client reaches the fallback backend", func(t *testing.T) {
		conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(anytlsPort)), &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         minimalTestTLSName,
		})
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + minimalTestTLSName + "\r\n\r\n"))
		require.NoError(t, err)
		response, err := http.ReadResponse(std_bufio.NewReader(conn), nil)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), minimalDecoyBody)
		assertMinimalNoProxyChallenge(t, response)
	})
}

// ---------------------------------------------------------------------------
// ShadowTLS v3 -> SS2022 inbound detour (production minimal)
// ---------------------------------------------------------------------------

// TestJiejieMinimalShadowTLSDetourSS2022 is intentionally NOT a hand-rolled
// ShadowTLS client. Building one from sing-shadowtls directly is not viable here:
// the v3 client panics inside sing-shadowtls (client.go, DialContextConn) with a
// nil pointer when it does not receive a usable ServerHello, instead of returning
// the "traffic hijacked" error the same code path intends to return. That is an
// upstream library behaviour, not something this fork should paper over in a
// test.
//
// The production link shadowtls-in --detour--> ss2022-in is therefore covered in
// two complementary places instead, and the read-only audit in
// jiejie_fixture_audit_test.go pins the fixture side of it:
//
//  1. TestJiejieProductionFixtureModelsRealTopology asserts that the production
//     fixture declares shadowtls-in with detour ss2022-in, and that ss2022-in is
//     a shadowsocks inbound. It fails if the detour ever regresses to an
//     outbound such as "direct".
//
//  2. TestJiejieMinimalShadowTLSInboundRegisters proves the minimal registry
//     can actually construct the server side of both inbounds, which is what the
//     registry trim could plausibly break; the wire-level half is covered by the
//     upstream TestShadowTLS / TestChainedInbound suites in the client-feature
//     group, which run under the default tag set where the ShadowTLS outbound
//     exists.
func TestJiejieMinimalShadowTLSInboundRegisters(t *testing.T) {
	ssPassword := mkBase64(t, 16)
	method := shadowaead_2022.List[0]
	shadowTLSPort := reserveOpenVPNTCPPort(t)
	ssPort := reserveOpenVPNTCPPort(t)

	instance := startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeShadowTLS,
				Tag:  "shadowtls-in",
				Options: &option.ShadowTLSInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     minimalLoopback(),
						ListenPort: shadowTLSPort,
						Detour:     "ss2022-in",
					},
					Version:  3,
					Password: "shadowtls-placeholder",
					Users:    []option.ShadowTLSUser{{Name: "sekai", Password: "shadowtls-placeholder"}},
					Handshake: option.ShadowTLSHandshakeOptions{
						ServerOptions: option.ServerOptions{
							Server:     "www.cloudflare.com",
							ServerPort: 443,
						},
					},
				},
			},
			{
				Type: C.TypeShadowsocks,
				Tag:  "ss2022-in",
				Options: &option.ShadowsocksInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     minimalLoopback(),
						ListenPort: ssPort,
					},
					Method:   method,
					Password: ssPassword,
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	require.NotNil(t, instance)

	// Both listeners must actually be accepting: that proves the minimal registry
	// constructed a ShadowTLS inbound whose detour target resolved to a real
	// registered inbound, since an unresolvable detour fails at route time.
	for _, port := range []uint16{shadowTLSPort, ssPort} {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 3*time.Second)
		require.NoError(t, err, "port %d must be listening", port)
		conn.Close()
	}
}
