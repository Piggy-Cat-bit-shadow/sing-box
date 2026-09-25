package jiejie_test

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// This file is the strict security verification for unauthorised CONNECT.
//
// Why it exists: the earlier masquerade tests proved only that the response BODY
// was the decoy page and did not contain the CONNECT target's content. That is
// necessary but not sufficient. A CONNECT carrying a 2xx has tunnel semantics, so
// what actually has to be proven is that no connection is ever made to the
// CONNECT target, no UDP session is ever created, and the client cannot then push
// TCP or UoT data through the request.
//
// Every test here therefore uses a RECORDING target that counts accepted TCP
// connections, UDP datagrams and forwarded bytes, and asserts those counters stay
// at zero for unauthorised requests.
//
// Reference behaviour, verified against klzgrad/forwardproxy ServeHTTP:
//
//	1. credentials are checked FIRST;
//	2. an unauthenticated CONNECT is passed to the next (Web) handler, which
//	   typically answers 200 with its own page;
//	3. the dial happens ONLY after authentication succeeds.
//
// So a 200 to an unauthorised CONNECT is the reference behaviour, not a defect.
// The defect would be dialing. These tests target that directly.

// recordingTarget is a TCP origin that counts connections and forwarded bytes.
type recordingTarget struct {
	address     string
	connections atomic.Int64
	bytes       atomic.Int64
}

// startRecordingTCPTarget starts a recording TCP origin that replies to any
// payload with a recognisable marker.
func startRecordingTCPTarget(t *testing.T) *recordingTarget {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	target := &recordingTarget{address: listener.Addr().String()}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			target.connections.Add(1)
			go func() {
				defer conn.Close()
				buffer := make([]byte, 4096)
				for {
					n, readErr := conn.Read(buffer)
					if n > 0 {
						target.bytes.Add(int64(n))
						_, _ = conn.Write([]byte("RECORDING-TARGET-CONTENT"))
					}
					if readErr != nil {
						return
					}
				}
			}()
		}
	}()
	return target
}

// recordingUDPTarget counts UDP datagrams received.
type recordingUDPTarget struct {
	address   string
	datagrams atomic.Int64
}

// startRecordingUDPTarget starts a recording UDP target that echoes.
func startRecordingUDPTarget(t *testing.T) *recordingUDPTarget {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	target := &recordingUDPTarget{address: conn.LocalAddr().String()}
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, addr, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			target.datagrams.Add(1)
			_, _ = conn.WriteToUDP(buffer[:n], addr)
		}
	}()
	return target
}

// securityEnv is a Naive inbound plus recording targets.
type securityEnv struct {
	port       uint16
	tcpTarget  *recordingTarget
	udpTarget  *recordingUDPTarget
	decoyHits  *int64
	decoyReply string
}

// startNaiveSecurityEnv starts a Naive inbound with a masquerade whose backend
// returns a configurable status, plus recording TCP and UDP targets that the
// CONNECT attempts will name.
func startNaiveSecurityEnv(t *testing.T, decoyStatus int) *securityEnv {
	t.Helper()
	requireFullNaiveRegistry(t)

	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)

	env := &securityEnv{
		port:       port,
		tcpTarget:  startRecordingTCPTarget(t),
		udpTarget:  startRecordingUDPTarget(t),
		decoyHits:  new(int64),
		decoyReply: "SECURITY-DECOY-PAGE",
	}

	decoyAddr := startSecurityDecoy(t, env, decoyStatus)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
				Network:       option.NetworkList("tcp"),
				Users: []auth.User{{
					Username: naiveTestUser,
					Password: naiveTestPassword,
				}},
				Masquerade: &option.Hysteria2Masquerade{
					Type: C.Hysterai2MasqueradeTypeProxy,
					ProxyOptions: option.Hysteria2MasqueradeProxy{
						URL:         "http://" + decoyAddr,
						RewriteHost: true,
					},
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
	return env
}

// startSecurityDecoy starts the masquerade backend with a chosen status code.
func startSecurityDecoy(t *testing.T, env *securityEnv, status int) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			atomic.AddInt64(env.decoyHits, 1)
			if value := request.Header.Get("Proxy-Authorization"); value != "" {
				writer.Header().Set("X-Leaked-Credential", value)
			}
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.WriteHeader(status)
			_, _ = io.WriteString(writer, "<html><body>"+env.decoyReply+"</body></html>")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// unauthorisedAttempts enumerates the request shapes that must never tunnel.
func unauthorisedAttempts(t *testing.T, env *securityEnv) []struct {
	name    string
	headers map[string]string
	target  string
} {
	t.Helper()
	wrongAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":wrong-password"))
	malformedAuth := "Basic !!!not-valid-base64!!!"
	emptyUser := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"))

	return []struct {
		name    string
		headers map[string]string
		target  string
	}{
		{"no credentials ipv4", map[string]string{"Padding": "~~~~~~~~"}, env.tcpTarget.address},
		{"wrong password ipv4", map[string]string{"Proxy-Authorization": wrongAuth, "Padding": "~~~~~~~~"}, env.tcpTarget.address},
		{"malformed authorization ipv4", map[string]string{"Proxy-Authorization": malformedAuth, "Padding": "~~~~~~~~"}, env.tcpTarget.address},
		{"empty username ipv4", map[string]string{"Proxy-Authorization": emptyUser, "Padding": "~~~~~~~~"}, env.tcpTarget.address},
		{"no credentials ipv6", map[string]string{"Padding": "~~~~~~~~"}, "[::1]:9"},
		{"no credentials domain", map[string]string{"Padding": "~~~~~~~~"}, "example.invalid:443"},
		{"no credentials uot magic", map[string]string{"Padding": "~~~~~~~~"}, uot.MagicAddress + ":0"},
		{"wrong password uot magic", map[string]string{"Proxy-Authorization": wrongAuth, "Padding": "~~~~~~~~"}, uot.MagicAddress + ":0"},
		{"no credentials legacy uot magic", map[string]string{"Padding": "~~~~~~~~"}, uot.LegacyMagicAddress + ":0"},
		{"no padding no credentials", map[string]string{}, env.tcpTarget.address},
		{"wrong padding value", map[string]string{"Padding": "zzz"}, env.tcpTarget.address},
		{"empty authority", map[string]string{"Padding": "~~~~~~~~"}, ""},
		{"garbage authority", map[string]string{"Padding": "~~~~~~~~"}, "!!!not-an-authority!!!"},
	}
}

// TestJiejieNaiveUnauthorisedConnectNeverDials is the central security test.
//
// It attempts every unauthorised CONNECT shape and asserts that the RECORDING
// TARGET observed zero connections and zero bytes afterwards. Status codes are
// logged for information only and are never used as the pass condition, because
// the reference deliberately serves unauthorised CONNECTs from the Web backend.
func TestJiejieNaiveUnauthorisedConnectNeverDials(t *testing.T) {
	env := startNaiveSecurityEnv(t, http.StatusOK)

	for _, attempt := range unauthorisedAttempts(t, env) {
		t.Run(attempt.name, func(t *testing.T) {
			before := env.tcpTarget.connections.Load()

			conn := naiveTLSConn(t, env.port)
			response, err := naiveWriteConnect(t, conn, attempt.target, attempt.headers)
			if err == nil {
				// Read the whole response, then try to USE the "tunnel".
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				t.Logf("status=%d body=%q", response.StatusCode, truncate(body, 60))
			} else {
				t.Logf("refused at transport level: %v", err)
			}

			// Push data at the connection regardless, in case a tunnel was opened.
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = io.WriteString(conn, "UNAUTHORISED-PAYLOAD\r\n")
			_, _ = io.ReadAll(conn)
			_ = conn.Close()

			time.Sleep(100 * time.Millisecond)

			after := env.tcpTarget.connections.Load()
			require.Equal(t, before, after,
				"an unauthorised CONNECT (%s) must NEVER open a connection to its target",
				attempt.name)
		})
	}

	require.Zero(t, env.tcpTarget.bytes.Load(),
		"no bytes may ever be forwarded to the target for unauthorised CONNECTs")
	require.Zero(t, env.udpTarget.datagrams.Load(),
		"no UDP datagram may ever reach the target for unauthorised CONNECTs")
}

// TestJiejieNaiveUnauthorisedUoTCannotSendDatagrams proves an unauthorised UoT
// CONNECT cannot smuggle UDP: the client must not be able to push UoT frames that
// reach the real UDP target.
func TestJiejieNaiveUnauthorisedUoTCannotSendDatagrams(t *testing.T) {
	env := startNaiveSecurityEnv(t, http.StatusOK)
	wrongAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":wrong-password"))

	for _, header := range []map[string]string{
		{"Padding": "~~~~~~~~"},
		{"Proxy-Authorization": wrongAuth, "Padding": "~~~~~~~~"},
	} {
		conn := naiveTLSConn(t, env.port)
		response, err := naiveWriteConnect(t, conn, uot.RequestDestination(uot.Version).String(), header)
		if err == nil {
			response.Body.Close()
		}

		// Now try to drive UoT: request header (v2) plus datagrams, in both
		// padded and unpadded shapes, in case one slips through.
		addressBytes := mustEncodeV2Addr(t, metadata.ParseSocksaddr(env.udpTarget.address))
		requestPayload := append([]byte{1}, addressBytes...)

		payload := []byte("UNAUTHORISED-UOT-DATAGRAM")
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len(payload)))
		datagram := append(length, payload...)

		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write(naivePaddingFrame(requestPayload, 0))
		_, _ = conn.Write(naivePaddingFrame(datagram, 0))
		_, _ = conn.Write(requestPayload)
		_, _ = conn.Write(datagram)
		_, _ = io.ReadAll(conn)
		_ = conn.Close()
	}

	time.Sleep(500 * time.Millisecond)
	require.Zero(t, env.udpTarget.datagrams.Load(),
		"an unauthorised UoT CONNECT must never deliver a datagram to a real UDP target")
}

// TestJiejieNaiveAuthorisedConnectStillDials is the control: the recording target
// MUST be reached when the credentials are correct. Without this, the test above
// could pass simply because nothing works at all.
func TestJiejieNaiveAuthorisedConnectStillDials(t *testing.T) {
	env := startNaiveSecurityEnv(t, http.StatusOK)

	conn := naiveTLSConn(t, env.port)
	response := naiveWriteConnectOK(t, conn, env.tcpTarget.address, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	require.Equal(t, http.StatusOK, response.StatusCode)

	// HTTP/1 tunnels are RAW even when the request carried Padding: the
	// reference ends serveHijack in dualStream(..., false). Sending a Naive
	// frame here would desynchronise the server from the client's first byte.
	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	// Read the first chunk rather than io.ReadAll: the recording target echoes
	// on every read and never closes its side, so ReadAll would block until the
	// connection deadline and report a timeout on an otherwise correct tunnel.
	body := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, readErr := conn.Read(body)
	require.NoError(t, readErr)
	require.Contains(t, string(body[:n]), "RECORDING-TARGET-CONTENT",
		"an AUTHORISED CONNECT must reach the recording target")

	require.Positive(t, env.tcpTarget.connections.Load(),
		"the control case must actually connect; otherwise the negative tests prove nothing")
}

// TestJiejieNaiveAuthorisedUoTStillDelivers is the UoT control case.
func TestJiejieNaiveAuthorisedUoTStillDelivers(t *testing.T) {
	env := startNaiveSecurityEnv(t, http.StatusOK)

	session := dialUoT(t, env.port, uot.Version, env.udpTarget.address, true)
	defer session.Close()

	payload := []byte("AUTHORISED-UOT")
	session.writeDatagram(t, uot.Version, env.udpTarget.address, payload)
	require.Equal(t, payload, session.readDatagram(t, uot.Version))
	require.Positive(t, env.udpTarget.datagrams.Load(),
		"the UoT control case must actually deliver; otherwise the negative test proves nothing")
}

// TestJiejieNaiveUnauthorisedConnectWhenDecoyReturns404 proves the security holds
// regardless of what the Web backend answers. A 404 backend must not become a
// tunnel either, and the status must not be mistaken for a security check.
func TestJiejieNaiveUnauthorisedConnectWhenDecoyReturns404(t *testing.T) {
	env := startNaiveSecurityEnv(t, http.StatusNotFound)

	for _, attempt := range unauthorisedAttempts(t, env) {
		t.Run(attempt.name, func(t *testing.T) {
			before := env.tcpTarget.connections.Load()
			conn := naiveTLSConn(t, env.port)
			response, err := naiveWriteConnect(t, conn, attempt.target, attempt.headers)
			if err == nil {
				response.Body.Close()
			}
			_ = conn.Close()
			time.Sleep(50 * time.Millisecond)
			require.Equal(t, before, env.tcpTarget.connections.Load(),
				"a 404 decoy must not change the security property (%s)", attempt.name)
		})
	}
	require.Zero(t, env.tcpTarget.bytes.Load())
}

// TestJiejieNaiveUnauthorisedConnectWhenDecoyIsDead proves a dead masquerade
// backend fails CLOSED: the proxy must not fall back to an unauthenticated tunnel.
func TestJiejieNaiveUnauthorisedConnectWhenDecoyIsDead(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	target := startRecordingTCPTarget(t)

	deadPort := reserveTCPPort(t)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
				Network:       option.NetworkList("tcp"),
				Users:         []auth.User{{Username: naiveTestUser, Password: naiveTestPassword}},
				Masquerade: &option.Hysteria2Masquerade{
					Type: C.Hysterai2MasqueradeTypeProxy,
					ProxyOptions: option.Hysteria2MasqueradeProxy{
						URL:         "http://127.0.0.1:" + strconv.Itoa(int(deadPort)),
						RewriteHost: true,
					},
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

	for _, attempt := range []map[string]string{
		{"Padding": "~~~~~~~~"},
		{"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("naive-user:nope")), "Padding": "~~~~~~~~"},
	} {
		conn := naiveTLSConn(t, port)
		response, err := naiveWriteConnect(t, conn, target.address, attempt)
		if err == nil {
			response.Body.Close()
		}
		_, _ = io.WriteString(conn, "PAYLOAD\r\n")
		_ = conn.Close()
	}

	time.Sleep(300 * time.Millisecond)
	require.Zero(t, target.connections.Load(),
		"a DEAD masquerade backend must fail closed, never fall back to an "+
			"unauthenticated tunnel")
	require.Zero(t, target.bytes.Load())
}

// TestJiejieNaiveUnauthorisedConnectDoesNotPoisonOtherStreams proves a rejected
// CONNECT on an HTTP/2 connection does not disturb other streams on the SAME
// connection, and does not leave the connection in an authenticated state.
func TestJiejieNaiveUnauthorisedConnectDoesNotPoisonOtherStreams(t *testing.T) {
	env := startNaiveSecurityEnv(t, http.StatusOK)

	// One HTTP/2 connection carrying several requests.
	conn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	require.NoError(t, err)
	defer clientConn.Close()

	// Several unauthorised CONNECTs over the same connection.
	wrongAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":wrong"))
	for range 3 {
		pipeReader, pipeWriter := io.Pipe()
		response, roundTripErr := clientConn.RoundTrip(&http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: env.tcpTarget.address},
			Host:   env.tcpTarget.address,
			Header: http.Header{
				"Proxy-Authorization": []string{wrongAuth},
				"Padding":             []string{"~~~~~~~~"},
			},
			Body: pipeReader,
		})
		if roundTripErr == nil {
			response.Body.Close()
		}
		_ = pipeWriter.Close()
	}

	time.Sleep(200 * time.Millisecond)
	require.Zero(t, env.tcpTarget.connections.Load(),
		"repeated unauthorised CONNECTs on one connection must never dial")

	// A correctly authenticated CONNECT on the SAME connection must still work,
	// proving the rejections did not corrupt connection state.
	pipeReader, pipeWriter := io.Pipe()
	defer pipeWriter.Close()
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: env.tcpTarget.address},
		Host:   env.tcpTarget.address,
		Header: http.Header{
			"Proxy-Authorization": []string{naiveBasicAuth()},
			"Padding":             []string{"~~~~~~~~"},
		},
		Body: pipeReader,
	})
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"a valid CONNECT on the same connection must still work after rejections")

	requestBytes := []byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	_, err = pipeWriter.Write(naivePaddingFrame(requestBytes, 0))
	require.NoError(t, err)
	body := naiveReadPaddingFrame(t, response.Body)
	require.Contains(t, string(body), "RECORDING-TARGET-CONTENT",
		"the authenticated stream must reach the target")
}

// TestJiejieNaiveMasqueradeCredentialsNeverReachBackend re-verifies the
// credential-leak property at the decoy itself, via the header the decoy echoes
// back when it sees one.
func TestJiejieNaiveMasqueradeCredentialsNeverReachBackend(t *testing.T) {
	env := startNaiveSecurityEnv(t, http.StatusOK)

	// A GET carrying credentials (so the request has a credential attached) and a
	// CONNECT carrying credentials, both unauthenticated routes.
	for _, request := range []struct {
		name    string
		method  string
		target  string
		headers map[string]string
	}{
		{"GET with credentials", http.MethodGet, "/", map[string]string{"Proxy-Authorization": naiveBasicAuth()}},
		{"CONNECT wrong credentials", http.MethodConnect, env.tcpTarget.address, map[string]string{
			"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("naive-user:nope")),
			"Padding":             "~~~~~~~~",
		}},
	} {
		t.Run(request.name, func(t *testing.T) {
			conn := naiveTLSConn(t, env.port)
			var raw string
			if request.method == http.MethodGet {
				raw = "GET / HTTP/1.1\r\nHost: naive.test\r\nProxy-Authorization: " +
					naiveBasicAuth() + "\r\nConnection: close\r\n\r\n"
			} else {
				raw = "CONNECT " + request.target + " HTTP/1.1\r\nHost: " + request.target +
					"\r\nProxy-Authorization: " + request.headers["Proxy-Authorization"] +
					"\r\nPadding: ~~~~~~~~\r\n\r\n"
			}
			_, err := io.WriteString(conn, raw)
			require.NoError(t, err)
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: request.method})
			if err != nil {
				return // closed instead of answered
			}
			defer response.Body.Close()
			require.Empty(t, response.Header.Get("X-Leaked-Credential"),
				"the Web backend must NEVER receive Proxy-Authorization")
		})
	}
}

// TestJiejieNaiveMasqueradeTargetIsFixed proves a client cannot redirect the
// reverse proxy with the CONNECT authority or Host header.
func TestJiejieNaiveMasqueradeTargetIsFixed(t *testing.T) {
	env := startNaiveSecurityEnv(t, http.StatusOK)
	attacker := startRecordingTCPTarget(t)

	conn := naiveTLSConn(t, env.port)
	// An unauthorised CONNECT naming the attacker's target, plus a spoofed Host.
	raw := "CONNECT " + attacker.address + " HTTP/1.1\r\nHost: " + attacker.address +
		"\r\nPadding: ~~~~~~~~\r\n\r\n"
	_, err := io.WriteString(conn, raw)
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err == nil {
		response.Body.Close()
	}
	_ = conn.Close()

	time.Sleep(200 * time.Millisecond)
	require.Zero(t, attacker.connections.Load(),
		"the masquerade target is fixed by configuration and must not be redirectable")
	require.Zero(t, env.tcpTarget.connections.Load())
}

// mustEncodeV2Addr encodes an address for a UoT v2 request header.
func mustEncodeV2Addr(t *testing.T, addr metadata.Socksaddr) []byte {
	t.Helper()
	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer, addr))
	return writer.data
}

func truncate(body []byte, limit int) string {
	text := string(body)
	if len(text) > limit {
		return text[:limit]
	}
	return text
}
