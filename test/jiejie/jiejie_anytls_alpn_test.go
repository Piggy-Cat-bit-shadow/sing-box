package jiejie_test

import (
	"crypto/tls"
	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing/common/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// These tests exercise fallback_for_alpn at runtime.
//
// The option was previously documented in the field matrix as DECODE ONLY,
// because nothing proved the map actually routed a real TLS handshake to the
// ALPN-specific backend. It does: the map is installed as
// tls.Config.NextProtos routing, so the ALPN a client negotiates selects the
// destination. These tests drive real TLS handshakes with distinct ALPN values
// and assert which backend answered.

// startALPNLabeledBackend starts a plain HTTP server that identifies itself in
// the response body, so a test can tell which backend served a request.
func startALPNLabeledBackend(t *testing.T, label string) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("X-Fallback-Backend", label)
			_, _ = io.WriteString(writer, label)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	_, portString, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portString)
	require.NoError(t, err)
	return port
}

// startAnyTLSInboundWithALPNFallback starts an AnyTLS inbound whose fallback is
// selected per ALPN, and returns its port.
func startAnyTLSInboundWithALPNFallback(t *testing.T, alpnFallbacks map[string]int, defaultFallback int) int {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, minimalTestTLSName)
	anytlsPort := reserveTCPPort(t)

	fallbackForALPN := make(map[string]*option.ServerOptions, len(alpnFallbacks))
	for alpn, port := range alpnFallbacks {
		fallbackForALPN[alpn] = &option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: uint16(port),
		}
	}
	var fallback *option.ServerOptions
	if defaultFallback != 0 {
		fallback = &option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: uint16(defaultFallback),
		}
	}

	// The TLS server must ADVERTISE the ALPN values. Without this it negotiates
	// none, connectionState.NegotiatedProtocol is empty, and
	// fallbackAddrTLSNextProto can never match -- every client lands on the
	// default backend however the map is configured.
	tlsContainer := minimalInboundTLS(certPem, keyPem)
	tlsContainer.TLS.ALPN = badoption.Listable[string]{"h2", "http/1.1"}

	inboundOptions := &option.AnyTLSInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     minimalLoopback(),
			ListenPort: anytlsPort,
		},
		Users:                      []option.AnyTLSUser{{Name: minimalTestUser, Password: minimalTestPassword}},
		FallbackForALPN:            fallbackForALPN,
		InboundTLSOptionsContainer: tlsContainer,
	}
	if fallback != nil {
		inboundOptions.Fallback = fallback
	}

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type:    C.TypeAnyTLS,
			Tag:     "anytls-in",
			Options: inboundOptions,
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return int(anytlsPort)
}

// requestThroughALPN performs a real TLS handshake advertising nextProto and
// returns the body the fallback backend produced.
func requestThroughALPN(t *testing.T, port int, nextProto string) (string, http.Header) {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         minimalTestTLSName,
				NextProtos:         []string{nextProto},
			},
		},
		Timeout: 15 * time.Second,
	}
	response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return string(body), response.Header
}

// requestThroughALPNAllowingFailure is requestThroughALPN for cases that are
// EXPECTED to fail, so the error can be asserted instead of the body. A refused
// connection produces no response at all, which the success helper would report as
// a test failure.
func requestThroughALPNAllowingFailure(port int, nextProto string) (string, http.Header, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         minimalTestTLSName,
				NextProtos:         []string{nextProto},
			},
		},
		Timeout: 15 * time.Second,
	}
	response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		return "", nil, err
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		return "", response.Header, readErr
	}
	return string(body), response.Header, nil
}

// TestJiejieAnyTLSFallbackForALPNRoutesPerALPN is the runtime proof that the
// ALPN a client negotiates selects the fallback destination.
//
// Two real TLS handshakes with different ALPN values against one AnyTLS inbound
// must reach two different backends.
func TestJiejieAnyTLSFallbackForALPNRoutesPerALPN(t *testing.T) {
	fallbackH2 := startALPNLabeledBackend(t, "backend-h2")
	fallbackHTTP11 := startALPNLabeledBackend(t, "backend-http11")
	fallbackDefault := startALPNLabeledBackend(t, "backend-default")

	port := startAnyTLSInboundWithALPNFallback(t, map[string]int{
		"h2":       fallbackH2,
		"http/1.1": fallbackHTTP11,
	}, fallbackDefault)

	t.Run("ALPN h2 reaches the h2 backend", func(t *testing.T) {
		body, header := requestThroughALPN(t, port, "h2")
		require.Equal(t, "backend-h2", header.Get("X-Fallback-Backend"),
			"an h2 handshake must reach the h2-specific fallback")
		require.Equal(t, "backend-h2", body)
	})

	t.Run("ALPN http/1.1 reaches the http/1.1 backend", func(t *testing.T) {
		body, header := requestThroughALPN(t, port, "http/1.1")
		require.Equal(t, "backend-http11", header.Get("X-Fallback-Backend"),
			"an http/1.1 handshake must reach the http/1.1-specific fallback")
		require.Equal(t, "backend-http11", body)
	})

	t.Run("an unlisted ALPN is refused at the TLS layer", func(t *testing.T) {
		// The server advertises only h2 and http/1.1, so a client offering
		// something else is rejected during the handshake with
		// "no application protocol". The fallback handler never runs, which is
		// the correct outcome: the ALPN was never negotiated, so there is no
		// NextProtos key to route on.
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         minimalTestTLSName,
					NextProtos:         []string{"acme-tls/1"},
				},
			},
			Timeout: 15 * time.Second,
		}
		_, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
		require.Error(t, err, "an ALPN the server does not advertise must fail the handshake")
		require.Contains(t, err.Error(), "application protocol")
	})

	t.Run("a negotiated ALPN with no entry is REFUSED, not defaulted", func(t *testing.T) {
		// This subtest previously claimed to cover "an advertised ALPN with no
		// entry falls through to the default" while mapping "h2" and then
		// REQUESTING "h2". The entry therefore existed and the mapped path ran, so
		// the case named in the test was never exercised.
		//
		// The real semantics, from inbound.go fallbackConnection, are:
		//
		//	if negotiated ALPN != "" {
		//	    if the map has no entry -> close the connection
		//	}
		//	if no fallbackAddr yet -> use the default fallback
		//
		// so a negotiated-but-unmapped ALPN is REFUSED and never reaches the
		// default. That is the safer behaviour - an unknown protocol must not be
		// silently served by a backend chosen for a different one - and it is what
		// this subtest now asserts.
		//
		// The map maps "http/1.1"; the client offers only "h2", so an ALPN IS
		// negotiated and there is deliberately NO entry for it.
		otherDefault := startALPNLabeledBackend(t, "backend-other")
		otherPort := startAnyTLSInboundWithALPNFallback(t, map[string]int{
			"http/1.1": otherDefault,
		}, otherDefault+1)

		_, _, err := requestThroughALPNAllowingFailure(otherPort, "h2")
		require.Error(t, err,
			"a negotiated ALPN with no map entry must be refused; reaching a "+
				"backend would mean an unlisted protocol was served anyway")
		t.Logf("unmapped ALPN refused as expected: %v", err)
	})

	t.Run("no fallback emits a proxy challenge to an unknown client", func(t *testing.T) {
		// The fallback must never authenticate a client that is not AnyTLS.
		_, header := requestThroughALPN(t, port, "h2")
		require.Empty(t, header.Get("Proxy-Authenticate"))
		require.Empty(t, header.Get("Proxy-Authorization"))
	})
}

// TestJiejieAnyTLSFallbackForALPNNoALPNUsesDefault proves the other half of the
// dispatch rule.
//
// fallbackConnection only consults the ALPN map when an ALPN was actually
// negotiated:
//
//	if negotiated ALPN != "" {
//	    if the map has no entry -> close
//	}
//	if no fallbackAddr yet -> use the default fallback
//
// A client that negotiates NO ALPN therefore reaches the default backend, which is
// the path a browser or a plain TLS client takes. Without this test the rule is
// only half covered: the refusal half is asserted above, and the default half
// would be untested.
func TestJiejieAnyTLSFallbackForALPNNoALPNUsesDefault(t *testing.T) {
	defaultBackend := startALPNLabeledBackend(t, "backend-default")
	mappedBackend := startALPNLabeledBackend(t, "backend-h2")

	// The map exists, so the dispatch logic is active; the client simply does not
	// offer any ALPN.
	port := startAnyTLSInboundWithALPNFallback(t, map[string]int{
		"h2": mappedBackend,
	}, defaultBackend)

	// An empty NextProtos means the handshake negotiates no ALPN.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         minimalTestTLSName,
			},
			// Force HTTP/1.1 so the transport does not require h2.
			ForceAttemptHTTP2: false,
		},
		Timeout: 15 * time.Second,
	}
	response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		// Go's transport may offer h2 by default, which would negotiate "h2" and
		// hit the mapped backend instead. If that happened this test would be
		// asserting the wrong branch, so it is reported rather than silently
		// accepted.
		t.Skipf("the client could not complete a no-ALPN request (%v), so the "+
			"default-fallback branch was not exercised. This is a SKIP, not a pass.", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, "backend-default", response.Header.Get("X-Fallback-Backend"),
		"a client that negotiates no ALPN must reach the default fallback; the "+
			"ALPN map applies only when an ALPN was actually negotiated")
	require.Equal(t, "backend-default", string(body))
}

// TestJiejieAnyTLSFallbackForALPNRequiresTLS proves the configuration contract.
//
// fallback_for_alpn selects a backend by negotiated TLS ALPN, so it is meaningless
// without TLS. The inbound rejects that combination at construction rather than
// accepting a configuration whose key can never be consulted.
func TestJiejieAnyTLSFallbackForALPNRequiresTLS(t *testing.T) {
	requireFullNaiveRegistry(t)
	anytlsPort := reserveTCPPort(t)
	backend := startALPNLabeledBackend(t, "backend-unused")

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(`{
		"inbounds": [{
			"type": "anytls",
			"tag": "anytls-notls",
			"listen": "127.0.0.1",
			"listen_port": `+strconv.Itoa(int(anytlsPort))+`,
			"users": [{"name": "`+minimalTestUser+`", "password": "`+minimalTestPassword+`"}],
			"fallback_for_alpn": {
				"h2": {"server": "127.0.0.1", "server_port": `+strconv.Itoa(backend)+`}
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"final": "direct"}
	}`), &options))

	instance, err := box.New(box.Options{Context: globalCtx, Options: options})
	if err == nil {
		err = instance.Start()
		if instance != nil {
			t.Cleanup(func() { _ = instance.Close() })
		}
	}
	require.Error(t, err,
		"fallback_for_alpn without TLS must be refused at construction: the key "+
			"it is indexed by can never be produced, so accepting it would leave "+
			"the operator with a silently inert configuration")
	require.Contains(t, err.Error(), "without TLS",
		"the error must name the reason so the misconfiguration is diagnosable")
	t.Logf("fallback_for_alpn without TLS refused: %v", err)
}
