package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// These tests exercise the Native Naive inbound directly over the wire.
//
// They deliberately use RAW HTTP/1.1 CONNECT and hand-built padding frames
// rather than the sing-box Naive outbound, because a test that only proves
// sing-box can talk to itself proves very little about protocol compatibility.
// Where the reference implementation (klzgrad/forwardproxy) defines a behaviour,
// these tests encode that behaviour: the padding frame layout, the fact that a
// CONNECT without a Padding header is a valid plain proxy request, and the fact
// that neither an unauthenticated nor a malformed CONNECT can ever open a
// tunnel.

const (
	naiveTestUser     = "naive-user"
	naiveTestPassword = "naive-password"
)

// naiveTestEnv holds one running Naive inbound plus the loopback backends it
// reaches.
type naiveTestEnv struct {
	port        uint16
	originAddr  string
	masqueraded bool
}

// requireFullNaiveRegistry skips the Naive tests when the build does not register
// the Naive inbound.
//
// The Naive inbound is deliberately NOT part of the jiejie_server_minimal
// production registry: that registry contains only the four inbounds this
// server actually runs. These tests therefore need the FULL registry, and without
// this guard they would fail with a confusing "outbound type not found: naive"
// that looks like a code defect instead of a build-tag mismatch.
func requireFullNaiveRegistry(t *testing.T) {
	t.Helper()
	if _, loaded := include.InboundRegistry().CreateOptions("naive"); !loaded {
		t.Skip("the naive inbound is not registered in this build " +
			"(jiejie_server_minimal); run the Naive tests WITHOUT that tag")
	}
}

// startNaiveInbound starts a Naive inbound with TLS, one user, and optionally a
// masquerade pointing at a decoy web backend.
func startNaiveInbound(t *testing.T, withMasquerade bool) *naiveTestEnv {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)

	env := &naiveTestEnv{
		port:        port,
		originAddr:  startOriginBackend(t),
		masqueraded: withMasquerade,
	}

	inboundOptions := &option.NaiveInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     minimalLoopback(),
			ListenPort: port,
		},
		Network: option.NetworkList("tcp"),
		Users: []auth.User{{
			Username: naiveTestUser,
			Password: naiveTestPassword,
		}},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:         true,
				ServerName:      "naive.test",
				CertificatePath: certPem,
				KeyPath:         keyPem,
			},
		},
	}
	if withMasquerade {
		decoyAddr := startNaiveDecoySite(t)
		inboundOptions.Masquerade = &option.Hysteria2Masquerade{
			Type: C.Hysterai2MasqueradeTypeProxy,
			ProxyOptions: option.Hysteria2MasqueradeProxy{
				URL:         "http://" + decoyAddr,
				RewriteHost: true,
			},
		}
	}

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type:    C.TypeNaive,
			Tag:     "naive-in",
			Options: inboundOptions,
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return env
}

// startNaiveDecoySite starts the fake website served to non-proxy traffic.
func startNaiveDecoySite(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.Header().Set("X-Decoy-Site", "naive-decoy")
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "<html><body>naive decoy page</body></html>")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// naiveTLSConn completes a TLS handshake with the inbound, offering ALPN so the
// HTTP/2 path is reachable the same way a real client reaches it.
func naiveTLSConn(t *testing.T, port uint16, nextProtos ...string) *tls.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	require.NoError(t, err)
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "naive.test",
		NextProtos:         nextProtos,
	})
	require.NoError(t, tlsConn.Handshake())
	t.Cleanup(func() { _ = tlsConn.Close() })
	require.NoError(t, tlsConn.SetDeadline(time.Now().Add(20*time.Second)))
	return tlsConn
}

// naiveBasicAuth builds the Proxy-Authorization value for the test user.
func naiveBasicAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":"+naiveTestPassword))
}

// naiveWriteConnect sends a CONNECT request and returns the parsed response, or
// an error when the server closed the connection instead of answering.
//
// The error case is NOT a bug: upstream rejectHTTP hijacks the connection, sets
// linger 0 and closes it, which makes the peer see a reset rather than a status
// line. Returning the error lets each test assert the refusal on its own terms.
func naiveWriteConnect(t *testing.T, conn net.Conn, authority string, headers map[string]string) (*http.Response, error) {
	t.Helper()
	var builder strings.Builder
	fmt.Fprintf(&builder, "CONNECT %s HTTP/1.1\r\n", authority)
	fmt.Fprintf(&builder, "Host: %s\r\n", authority)
	for name, value := range headers {
		fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
	}
	builder.WriteString("\r\n")
	_, err := io.WriteString(conn, builder.String())
	require.NoError(t, err)
	return http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
}

// naiveCloseResponse closes a CONNECT response without waiting for the tunnel to
// end.
//
// For a hijacked HTTP/1.1 tunnel the response body IS the tunnel, so
// Body.Close() blocks until the tunnel finishes or its deadline expires. Tests
// that only need to confirm the tunnel was established must close the underlying
// connection instead, otherwise every such test costs a full read deadline.
func naiveCloseResponse(conn net.Conn) {
	_ = conn.Close()
}

// naiveWriteConnectOK is naiveWriteConnect for the cases that must succeed.
func naiveWriteConnectOK(t *testing.T, conn net.Conn, authority string, headers map[string]string) *http.Response {
	t.Helper()
	response, err := naiveWriteConnect(t, conn, authority, headers)
	require.NoError(t, err, "the request must have been answered")
	return response
}

// naiveConnectRefused asserts that an unauthorised CONNECT did not open a tunnel.
//
// It accepts BOTH legitimate refusal shapes, because upstream's rejectHTTP sends
// no response at all:
//
//   - the connection is reset/closed, so reading a response returns an error; or
//   - a status line is returned and it is not 200.
//
// What it never accepts is a 200, which is the only outcome that would mean a
// tunnel was opened without authentication.
func naiveConnectRefused(t *testing.T, conn net.Conn, authority string, headers map[string]string) {
	t.Helper()
	response, err := naiveWriteConnect(t, conn, authority, headers)
	if err != nil {
		// Connection refused/reset by the server. This is the upstream shape.
		return
	}
	defer response.Body.Close()
	require.NotEqual(t, http.StatusOK, response.StatusCode,
		"an unauthorised CONNECT must never receive 200: that would mean a tunnel "+
			"was established without authentication")
}

// naivePaddingFrame encodes one Naive padding frame: 2-byte big-endian original
// size, 1-byte padding size, data, then that many zero bytes.
func naivePaddingFrame(data []byte, paddingSize int) []byte {
	frame := make([]byte, 0, 3+len(data)+paddingSize)
	frame = append(frame, byte(len(data)>>8), byte(len(data)))
	frame = append(frame, byte(paddingSize))
	frame = append(frame, data...)
	frame = append(frame, make([]byte, paddingSize)...)
	return frame
}

// naiveReadPaddingFrame decodes one Naive padding frame.
func naiveReadPaddingFrame(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	header := make([]byte, 3)
	_, err := io.ReadFull(reader, header)
	require.NoError(t, err)
	dataSize := int(header[0])<<8 | int(header[1])
	paddingSize := int(header[2])
	data := make([]byte, dataSize)
	_, err = io.ReadFull(reader, data)
	require.NoError(t, err)
	if paddingSize > 0 {
		_, err = io.ReadFull(reader, make([]byte, paddingSize))
		require.NoError(t, err)
	}
	return data
}

// ---------------------------------------------------------------------------
// A. TCP CONNECT and authentication
// ---------------------------------------------------------------------------

// TestJiejieNaiveTCPConnectWithPadding is the baseline happy path: an
// authenticated CONNECT with the Padding header opens a TCP tunnel and carries
// data in both directions through padding frames.
func TestJiejieNaiveTCPConnectWithPadding(t *testing.T) {
	env := startNaiveInbound(t, false)
	conn := naiveTLSConn(t, env.port)

	response := naiveWriteConnectOK(t, conn, env.originAddr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"an authenticated CONNECT carrying Padding must be accepted")
	require.NotEmpty(t, response.Header.Get("Padding"),
		"the response Padding header is sent for every authenticated CONNECT")

	// The tunnel is RAW even though the request carried Padding. The reference
	// ends its HTTP/1 CONNECT in serveHijack, which calls
	// dualStream(targetConn, clientConn, clientConn, false) - the padding flag is
	// a literal false. Padding applies to HTTP/2 and HTTP/3 only, so a client
	// that offers Padding over HTTP/1 still exchanges unframed bytes.
	//
	// Sending a Naive frame here would make the server read the client's first
	// data bytes as a frame header, which is precisely the desynchronisation the
	// previous behaviour caused.
	requestBytes := []byte("GET / HTTP/1.1\r\nHost: " + env.originAddr + "\r\nConnection: close\r\n\r\n")
	_, err := conn.Write(requestBytes)
	require.NoError(t, err)

	body, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Contains(t, string(body), "origin-ok",
		"data written through an HTTP/1 tunnel must reach the origin as RAW bytes")
}

// TestJiejieNaiveTCPConnectWithoutPadding is the compatibility case that the
// previous implementation got wrong.
//
// A CONNECT with correct credentials but NO Padding header is a valid plain HTTP
// proxy request. klzgrad/forwardproxy only enables padding frames when the client
// sent the header; it does not reject the request. Rejecting it broke ordinary
// HTTP CONNECT clients.
func TestJiejieNaiveTCPConnectWithoutPadding(t *testing.T) {
	env := startNaiveInbound(t, false)
	conn := naiveTLSConn(t, env.port)

	response := naiveWriteConnectOK(t, conn, env.originAddr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"an authenticated CONNECT without a Padding header is a plain proxy request "+
			"and must be accepted")

	// The response Padding header is INDEPENDENT of the request's, and the
	// reference sends it unconditionally: klzgrad/forwardproxy sets
	// w.Header().Set("Padding", ...) with no condition before WriteHeader(200),
	// and only passes `r.Header.Get("Padding") != ""` to dualStream to decide
	// whether payload FRAMING is enabled.
	//
	// An earlier version of this test asserted the header must be ABSENT here.
	// That assertion came from sing-box's own previous behaviour, not from the
	// reference, and it is what the differential harness flags as a divergence.
	require.NotEmpty(t, response.Header.Get("Padding"),
		"the response Padding header is sent for every authenticated CONNECT, "+
			"matching klzgrad/forwardproxy; it does not depend on the request header")

	// The header being present must NOT enable payload framing. This is the
	// half that protects ordinary HTTP CONNECT clients: a client that never
	// asked for padding must be able to write raw bytes even though the
	// response advertised a Padding header.
	//
	// Without padding there is no frame header: bytes pass straight through.
	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + env.originAddr + "\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	body, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Contains(t, string(body), "origin-ok",
		"a non-padded tunnel must still carry data to the origin")
}

// TestJiejieNaiveWrongPasswordRejected proves a wrong credential cannot open a
// tunnel, and that without a masquerade the upstream 407 challenge is preserved.
func TestJiejieNaiveWrongPasswordRejected(t *testing.T) {
	env := startNaiveInbound(t, false)
	conn := naiveTLSConn(t, env.port)

	wrongAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":wrong"))
	naiveConnectRefused(t, conn, env.originAddr, map[string]string{
		"Proxy-Authorization": wrongAuth,
		"Padding":             "~~~~~~~~",
	})
}

// TestJiejieNaiveNoAuthRejected proves a CONNECT with no credentials is refused.
func TestJiejieNaiveNoAuthRejected(t *testing.T) {
	env := startNaiveInbound(t, false)
	conn := naiveTLSConn(t, env.port)

	naiveConnectRefused(t, conn, env.originAddr, map[string]string{
		"Padding": "~~~~~~~~",
	})
}

// TestJiejieNaiveMultipleUsers proves a second user authenticates independently.
func TestJiejieNaiveMultipleUsers(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	originAddr := startOriginBackend(t)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
				Network:       option.NetworkList("tcp"),
				Users: []auth.User{
					{Username: "user-a", Password: "password-a"},
					{Username: "user-b", Password: "password-b"},
				},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled: true, ServerName: "naive.test",
						CertificatePath: certPem, KeyPath: keyPem,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})

	for _, user := range []struct{ name, password string }{
		{"user-a", "password-a"},
		{"user-b", "password-b"},
	} {
		t.Run(user.name, func(t *testing.T) {
			conn := naiveTLSConn(t, port)
			auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user.name+":"+user.password))
			response := naiveWriteConnectOK(t, conn, originAddr, map[string]string{
				"Proxy-Authorization": auth,
				"Padding":             "~~~~~~~~",
			})
			require.Equal(t, http.StatusOK, response.StatusCode,
				"each configured user must authenticate independently")
			naiveCloseResponse(conn)
		})
	}

	// And a cross-user credential must fail.
	t.Run("cross credential", func(t *testing.T) {
		conn := naiveTLSConn(t, port)
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user-a:password-b"))
		naiveConnectRefused(t, conn, originAddr, map[string]string{
			"Proxy-Authorization": auth,
			"Padding":             "~~~~~~~~",
		})
	})
}

// TestJiejieNaiveMalformedRequestsDoNotCrash feeds malformed input and checks the
// server keeps serving afterwards.
func TestJiejieNaiveMalformedRequestsDoNotCrash(t *testing.T) {
	requireFullNaiveRegistry(t)
	env := startNaiveInbound(t, false)

	malformed := []struct {
		name    string
		payload string
	}{
		{"garbage", "this is not http at all\r\n\r\n"},
		{"CONNECT no target", "CONNECT  HTTP/1.1\r\nHost: \r\n\r\n"},
		{"truncated headers", "CONNECT example.com:443 HTTP/1.1\r\nHost: exa"},
		{"bad authorization", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic !!!not-base64!!!\r\n\r\n"},
		{"empty basic auth", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic \r\n\r\n"},
	}
	for _, testCase := range malformed {
		t.Run(testCase.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 5*time.Second)
			require.NoError(t, err)
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
			if err = tlsConn.Handshake(); err != nil {
				// A handshake failure is acceptable input handling; the point is
				// that the server survives it.
				conn.Close()
				return
			}
			_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(tlsConn, testCase.payload)
			_, _ = io.ReadAll(tlsConn)
			tlsConn.Close()
		})
	}

	// The server must still serve a valid request after all of that.
	conn := naiveTLSConn(t, env.port)
	response := naiveWriteConnectOK(t, conn, env.originAddr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"the server must keep working after malformed input")
}

// TestJiejieNaiveConcurrentConnections proves several tunnels run at once.
func TestJiejieNaiveConcurrentConnections(t *testing.T) {
	env := startNaiveInbound(t, false)

	const concurrency = 8
	errs := make(chan error, concurrency)
	for range concurrency {
		go func() {
			errs <- func() error {
				conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 10*time.Second)
				if err != nil {
					return err
				}
				defer conn.Close()
				tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
				if err = tlsConn.Handshake(); err != nil {
					return err
				}
				_ = tlsConn.SetDeadline(time.Now().Add(20 * time.Second))

				var builder strings.Builder
				fmt.Fprintf(&builder, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", env.originAddr, env.originAddr)
				fmt.Fprintf(&builder, "Proxy-Authorization: %s\r\nPadding: ~~~~~~~~\r\n\r\n", naiveBasicAuth())
				if _, err = io.WriteString(tlsConn, builder.String()); err != nil {
					return err
				}
				response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodConnect})
				if err != nil {
					return err
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK {
					return fmt.Errorf("status %d", response.StatusCode)
				}
				// RAW, because HTTP/1 is a raw tunnel in the reference
				// (serveHijack -> dualStream(..., false)); the Padding header in
				// the request above does not enable framing here.
				payload := []byte("GET / HTTP/1.1\r\nHost: " + env.originAddr + "\r\nConnection: close\r\n\r\n")
				if _, err = tlsConn.Write(payload); err != nil {
					return err
				}
				body, err := io.ReadAll(tlsConn)
				if err != nil {
					return err
				}
				if !strings.Contains(string(body), "origin-ok") {
					return fmt.Errorf("origin body missing")
				}
				return nil
			}()
		}()
	}
	for range concurrency {
		require.NoError(t, <-errs, "every concurrent tunnel must complete")
	}
}

// ---------------------------------------------------------------------------
// HTTP/2 CONNECT helper
// ---------------------------------------------------------------------------

// TestJiejieNaiveHTTP2Connect exercises the HTTP/2 CONNECT path.
//
// go/1.25's golang.org/x/net/http2 no longer exposes the old NewStream API, so
// the HTTP/2 tunnel is driven through Transport.RoundTrip with an io.Pipe body:
// the pipe keeps the request body open, and the response body is the other half
// of the tunnel.
func TestJiejieNaiveHTTP2Connect(t *testing.T) {
	requireFullNaiveRegistry(t)
	env := startNaiveInbound(t, false)

	transport := &http2.Transport{}
	tlsConn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
	clientConn, err := transport.NewClientConn(tlsConn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })

	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() {
		_ = pipeWriter.Close()
		_ = pipeReader.Close()
	})

	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: env.originAddr},
		Host:   env.originAddr,
		Header: http.Header{
			"Proxy-Authorization": []string{naiveBasicAuth()},
			"Padding":             []string{"~~~~~~~~"},
		},
		Body: pipeReader,
	})
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"an authenticated HTTP/2 CONNECT must be accepted")

	// Write a padded request into the tunnel and decode the padded response.
	requestBytes := []byte("GET / HTTP/1.1\r\nHost: " + env.originAddr + "\r\nConnection: close\r\n\r\n")
	_, err = pipeWriter.Write(naivePaddingFrame(requestBytes, 5))
	require.NoError(t, err)

	body := naiveReadPaddingFrame(t, response.Body)
	require.Contains(t, string(body), "origin-ok",
		"the HTTP/2 tunnel must carry data through padding frames")
}
