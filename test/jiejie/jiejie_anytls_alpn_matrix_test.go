package jiejie_test

import (
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This file audits AnyTLS ALPN behaviour and PINS THE CURRENT PRODUCTION CHOICE.
//
// Production configures no ALPN on the AnyTLS inbound
// (release/jiejie-production-topology.json sets no `alpn`), so Go's TLS server
// negotiates no protocol at all. The question this audit answers is whether that
// hurts an ordinary HTTPS client -- i.e. whether a browser-shaped probe is served
// a normal web response -- and the answer, measured below, is that it does not.
//
// Measured behaviour with no ALPN configured, for every client-side offer:
//
//	client offers        negotiated    fallback response
//	["h2"]               ""            HTTP/1.1 200 OK
//	["http/1.1"]         ""            HTTP/1.1 200 OK
//	["h2","http/1.1"]    ""            HTTP/1.1 200 OK
//	(none)               ""            HTTP/1.1 200 OK
//
// So the fallback works identically in all four cases and the handshake succeeds
// in all four. This is why the production recommendation is left ALONE: pinning
// `alpn: ["http/1.1"]` or `["h2"]` on the AnyTLS inbound would change nothing
// observable for a fallback client (it already gets a working HTTP/1.1 web
// response), while risking legitimate AnyTLS clients that negotiate their own
// ALPN.
//
// In other words: there is no measured improvement available here, so there is
// no change. This test exists so that a future change has to confront the
// measurement rather than assert an improvement.

// anyTLSFallbackOutcome performs a real TLS handshake offering nextProtos and
// against the AnyTLS inbound, then sends a plain HTTP/1.1 request, and reports the
// negotiated protocol and the fallback's response head.
func anyTLSFallbackOutcome(t *testing.T, port int, nextProtos []string) (string, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         minimalTestTLSName,
		NextProtos:         nextProtos,
	})
	require.NoError(t, tlsConn.Handshake(),
		"an ordinary TLS client must complete a handshake through AnyTLS")

	_, err = io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: "+minimalTestTLSName+"\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	require.NoError(t, tlsConn.SetDeadline(time.Now().Add(15*time.Second)))
	body, err := io.ReadAll(tlsConn)
	require.NoError(t, err)

	return tlsConn.ConnectionState().NegotiatedProtocol, string(body)
}

// TestJiejieAnyTLSALPNMatrix pins the measured ALPN behaviour.
func TestJiejieAnyTLSALPNMatrix(t *testing.T) {
	port, _ := startAnyTLSInboundWithFallback(t)

	offers := []struct {
		name       string
		nextProtos []string
	}{
		{name: "h2", nextProtos: []string{"h2"}},
		{name: "http/1.1", nextProtos: []string{"http/1.1"}},
		{name: "h2 and http/1.1", nextProtos: []string{"h2", "http/1.1"}},
		{name: "no ALPN", nextProtos: nil},
	}
	for _, offer := range offers {
		t.Run(offer.name, func(t *testing.T) {
			negotiated, body := anyTLSFallbackOutcome(t, port, offer.nextProtos)

			// The measured fact: nothing is negotiated, because production
			// configures no ALPN. Asserted explicitly so that changing this is a
			// deliberate, visible decision.
			require.Empty(t, negotiated,
				"production configures no ALPN on the AnyTLS inbound, so nothing is negotiated")

			// The property that actually matters for probe resistance: the client
			// is served a normal web response by the fallback backend.
			require.True(t, strings.HasPrefix(body, "HTTP/1.1 200 OK"),
				"an ordinary HTTPS client offering %v must receive the fallback's normal "+
					"response, got %q", offer.nextProtos, firstLine(body))
			require.Contains(t, body, "X-Fallback-Backend: web-decoy",
				"the native fallback backend must have served the request")

			// And no proxy authentication surface.
			require.NotContains(t, body, "Proxy-Authenticate")
			require.NotContains(t, body, "WWW-Authenticate")
		})
	}
}

// firstLine trims a response to its first line for readable failure messages.
func firstLine(body string) string {
	if index := strings.IndexAny(body, "\r\n"); index >= 0 {
		return body[:index]
	}
	if len(body) > 80 {
		return body[:80]
	}
	return body
}
