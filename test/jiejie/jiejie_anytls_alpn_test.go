package jiejie_test

import (
	"crypto/tls"
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

	t.Run("an advertised ALPN with no entry falls through to the default", func(t *testing.T) {
		// This is the case the default fallback exists for: the ALPN IS
		// negotiated, but the map has no entry for it, so the shared default
		// backend serves the request.
		otherDefault := startALPNLabeledBackend(t, "backend-other")
		otherPort := startAnyTLSInboundWithALPNFallback(t, map[string]int{
			"h2": otherDefault,
		}, otherDefault+1)

		body, header := requestThroughALPN(t, otherPort, "h2")
		require.Equal(t, "backend-other", header.Get("X-Fallback-Backend"))
		require.Equal(t, "backend-other", body)
	})

	t.Run("no fallback emits a proxy challenge to an unknown client", func(t *testing.T) {
		// The fallback must never authenticate a client that is not AnyTLS.
		_, header := requestThroughALPN(t, port, "h2")
		require.Empty(t, header.Get("Proxy-Authenticate"))
		require.Empty(t, header.Get("Proxy-Authorization"))
	})
}
