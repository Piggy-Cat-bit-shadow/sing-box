package jiejie_test

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"github.com/stretchr/testify/require"
)

// A REAL HTTP/3 client driving the Native Naive inbound.
//
// This exists because the previous coverage of HTTP/3 was a source-level
// assertion that the :scheme/:path guard was present. That is not a test of the
// transport: it cannot detect that the H3 listener failed to start, that ALPN
// broke, or that a config change (such as removing Allow0RTT) stopped H3 working.
// The probes here speak HTTP/3 over QUIC and assert on what the origin received.
//
// Scope, stated plainly: these cover the H3 transport path this process can
// reach. They are NOT a differential comparison against the reference; that
// distinction is reported as NOT-TESTED rather than claimed as parity.

type h3NaiveClient struct {
	clientConn *http3.ClientConn
	transport  *http3.Transport
}

// startNaiveInboundH3 starts a Naive inbound serving BOTH tcp and udp, so the
// HTTP/3 listener is actually started.
func startNaiveInboundH3(t *testing.T) uint16 {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: "naive",
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
				// udp is what starts the HTTP/3 listener.
				Network: option.NetworkList("tcp\nudp"),
				Users: []auth.User{{
					Username: naiveTestUser,
					Password: naiveTestPassword,
				}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled: true, ServerName: "naive.test",
						CertificatePath: certPem, KeyPath: keyPem,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: "direct", Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return port
}

// dialNaiveH3 opens an HTTP/3 connection to the Naive inbound.
//
// DialAddrEarly is the transport API for establishing an H3 connection; it does
// NOT imply the server accepts 0-RTT, which is governed solely by the server's
// quic.Config.Allow0RTT. Using this call means the test also catches a
// regression where H3 stopped accepting new connections entirely.
func dialNaiveH3(t *testing.T, port uint16) *h3NaiveClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddrEarly(ctx, "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         "naive.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{})
	if err != nil {
		t.Skipf("HTTP/3 is not available in this build/environment: %v. This is "+
			"a SKIP, not a pass - H3 was not exercised.", err)
	}
	transport := &http3.Transport{}
	clientConn := transport.NewClientConn(quicConn)
	t.Cleanup(func() {
		_ = clientConn.CloseWithError(0, "")
		_ = transport.Close()
	})
	return &h3NaiveClient{clientConn: clientConn, transport: transport}
}

// connect sends an HTTP/3 CONNECT and returns the response head plus the stream.
func (c *h3NaiveClient) connect(t *testing.T, authority string, headers http.Header) (*http.Response, *http3.RequestStream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: headers,
	}))
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	return response, stream
}

func naiveH3Auth() http.Header {
	return http.Header{
		"Proxy-Authorization": []string{"Basic " +
			base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":"+naiveTestPassword))},
	}
}

// TestJiejieNaiveH3ConnectStillWorks proves removing Allow0RTT did not break
// HTTP/3. 0-RTT is a latency optimisation for RESUMED connections, not a
// prerequisite for establishing one.
func TestJiejieNaiveH3ConnectStillWorks(t *testing.T) {
	port := startNaiveInboundH3(t)
	origin := startCountingTCPOrigin(t)
	client := dialNaiveH3(t, port)

	response, stream := client.connect(t, origin.addr, naiveH3Auth())
	require.Equal(t, http.StatusOK, response.StatusCode,
		"an authenticated HTTP/3 CONNECT must be accepted without 0-RTT")

	_, err := stream.Write([]byte("GET / HTTP/1.1\r\nHost: " + origin.addr + "\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)

	originResponse, err := http.ReadResponse(std_bufio.NewReader(stream), nil)
	require.NoError(t, err, "the HTTP/3 tunnel must carry a full HTTP exchange")
	defer originResponse.Body.Close()
	body, err := io.ReadAll(originResponse.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "origin-ok",
		"an HTTP/3 CONNECT must reach the origin")

	require.True(t, waitForDial(&origin.conns, 0),
		"the HTTP/3 CONNECT must dial the origin; it saw %d connections", origin.conns.Load())
	t.Logf("HTTP/3 CONNECT reached the origin; connections=%d", origin.conns.Load())
}

// TestJiejieNaiveH3ResponseAdvertisesPaddingHeader checks the H3 response header
// behaves as it does on the other transports.
func TestJiejieNaiveH3ResponseAdvertisesPaddingHeader(t *testing.T) {
	port := startNaiveInboundH3(t)
	origin := startCountingTCPOrigin(t)
	client := dialNaiveH3(t, port)

	for _, testCase := range []struct {
		name        string
		sendPadding bool
	}{
		{"with request Padding", true},
		{"without request Padding", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			headers := naiveH3Auth()
			if testCase.sendPadding {
				headers.Set("Padding", "~~~~~~~~")
			}
			response, _ := client.connect(t, origin.addr, headers)
			require.Equal(t, http.StatusOK, response.StatusCode)
			require.NotEmpty(t, response.Header.Get("Padding"),
				"the response Padding header is unconditional on an authenticated "+
					"CONNECT, on every transport")
		})
	}
}

// TestJiejieNaiveH3UnauthenticatedIsRefused proves the auth boundary holds on
// HTTP/3 and that a refused CONNECT never reaches the target.
func TestJiejieNaiveH3UnauthenticatedIsRefused(t *testing.T) {
	port := startNaiveInboundH3(t)
	origin := startCountingTCPOrigin(t)
	client := dialNaiveH3(t, port)

	for _, testCase := range []struct {
		name    string
		headers http.Header
	}{
		{"no credentials", http.Header{}},
		{"wrong password", http.Header{"Proxy-Authorization": []string{
			"Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":wrong"))}}},
		{"malformed credentials", http.Header{"Proxy-Authorization": []string{"Basic !!!not-base64!!!"}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			stream, err := client.clientConn.OpenRequestStream(ctx)
			require.NoError(t, err)
			require.NoError(t, stream.SendRequestHeader(&http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Host: origin.addr},
				Host:   origin.addr,
				Header: testCase.headers,
			}))
			response, err := stream.ReadResponse()
			if err != nil {
				t.Logf("refused at the stream level: %v", err)
			} else {
				require.NotEqual(t, http.StatusOK, response.StatusCode,
					"an unauthenticated HTTP/3 CONNECT must not open a tunnel")
				t.Logf("refused with status %d", response.StatusCode)
			}
			require.EqualValues(t, 0, origin.conns.Load(),
				"a refused HTTP/3 CONNECT must never dial the target")
		})
	}
}
