package http

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A client must not be able to choose the source address the server records and
// routes on.
//
// badhttp.ForwardedSource takes the first valid X-Forwarded-For entry and uses it
// as the source, so a client that sends the header could select which
// source_ip_cidr rules apply to it, which address appears in the logs, and which
// bucket the unauthenticated limiter charges. The value it produces -
// metadata.Source - drives all three.
//
// Neither deployment has anything to validate the header against: the MASQUE
// HTTP/2 inbound sits behind Nginx Stream, which forwards at layer 4 and does not
// add it, and the HTTP/3 inbound terminates QUIC directly on public UDP/443. The
// transport peer is therefore the only trustworthy value.
//
// These tests assert metadata.Source at the point it is handed to the connection
// handler, which is exactly where the router would read it.

// sourceRecordingHandler captures the source address of an accepted tunnel.
type sourceRecordingHandler struct {
	sources chan M.Socksaddr
}

func newSourceRecordingHandler() *sourceRecordingHandler {
	return &sourceRecordingHandler{sources: make(chan M.Socksaddr, 8)}
}

func (h *sourceRecordingHandler) NewConnectionEx(_ context.Context, conn net.Conn, source M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	select {
	case h.sources <- source:
	default:
	}
	_ = conn.Close()
	onClose(nil)
}

func (h *sourceRecordingHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, source M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	select {
	case h.sources <- source:
	default:
	}
	_ = conn.Close()
	onClose(nil)
}

// h2SourceForRequest drives one authenticated H2 CONNECT through the real handler
// and reports the source the connection handler received.
func h2SourceForRequest(t *testing.T, headers map[string]string) (M.Socksaddr, bool) {
	t.Helper()

	handler := newSourceRecordingHandler()
	server := &Server{
		logger:         testLogger(),
		authenticator:  auth.NewAuthenticator([]auth.User{{Username: "user", Password: "pass"}}),
		maxHeaderBytes: 1 << 20,
	}
	// source is the transport peer, as it is in production: resolved from the QUIC
	// peer on H3, otherwise from request.RemoteAddr. handler is the connection
	// handler the tunnel is delivered to.
	h2Handler := &httpHandler{
		server:  server,
		handler: handler,
		source:  M.ParseSocksaddr("198.51.100.7:5000"),
	}

	request := httptest.NewRequest(http.MethodConnect, "http://203.0.113.77:8080", nil)
	request.Header.Set("Proxy-Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("user:pass")))
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	recorder := httptest.NewRecorder()
	h2Handler.ServeHTTP(recorder, request)

	select {
	case source := <-handler.sources:
		return source, true
	default:
		return M.Socksaddr{}, false
	}
}

// TestForwardedHeaderCannotSpoofTunnelSource is the core regression: every shape
// of the header a client could send is ignored.
func TestForwardedHeaderCannotSpoofTunnelSource(t *testing.T) {
	const realPeer = "198.51.100.7"

	for _, testCase := range []struct {
		name    string
		headers map[string]string
	}{
		{"single X-Forwarded-For", map[string]string{"X-Forwarded-For": "203.0.113.99"}},
		{"multiple X-Forwarded-For entries", map[string]string{
			"X-Forwarded-For": "203.0.113.98, 203.0.113.99",
		}},
		{"malformed X-Forwarded-For with a valid tail", map[string]string{
			"X-Forwarded-For": "not-an-address, 203.0.113.97",
		}},
		{"Forwarded (RFC 7239)", map[string]string{"Forwarded": "for=203.0.113.96"}},
		{"X-Real-IP", map[string]string{"X-Real-IP": "203.0.113.95"}},
		{"every forwarded header at once", map[string]string{
			"X-Forwarded-For": "203.0.113.94",
			"Forwarded":       "for=203.0.113.93",
			"X-Real-IP":       "203.0.113.92",
			"X-Client-IP":     "203.0.113.91",
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			source, recorded := h2SourceForRequest(t, testCase.headers)
			require.True(t, recorded,
				"the tunnel must have reached the connection handler, otherwise "+
					"nothing about the source was tested")
			require.Equal(t, realPeer, source.Addr.String(),
				"the source must be the transport peer, never a client-supplied "+
					"forwarded header: it feeds source_ip_cidr rules, the limiter, "+
					"the logs and the audit trail")
		})
	}
}

// TestForwardedSourceHelperIsNotUsedByDefault pins the helper boundary itself.
//
// PeerAddress is what the server uses; ForwardedSource still trusts the header
// and is kept only for a future explicit trusted-proxy decision. Asserting the
// difference here means a change that quietly puts ForwardedSource back on the
// default path fails a test rather than a security review.
func TestForwardedSourceHelperIsNotUsedByDefault(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	request.RemoteAddr = "198.51.100.7:5000"
	request.Header.Set("X-Forwarded-For", "203.0.113.99")

	require.Equal(t, "198.51.100.7",
		badhttp.PeerAddress(request).Addr.String(),
		"PeerAddress must return the transport peer and ignore the header")

	// ForwardedSource is retained and still reads the header; that is why it must
	// not be on the default path. Exercising it here is the point of the test, so
	// the deprecation warning is expected.
	//nolint:staticcheck // deliberately asserting the deprecated helper's behaviour
	require.Equal(t, "203.0.113.99",
		badhttp.ForwardedSource(request, M.ParseSocksaddr(request.RemoteAddr).Unwrap()).Addr.String(),
		"ForwardedSource is documented as untrusted; this asserts the documented "+
			"behaviour so callers cannot mistake it for the safe default")
}

// TestSourceAddressIgnoresForwardedHeader covers the older helper, which the Naive
// inbound previously used. It must now behave like PeerAddress.
func TestSourceAddressIgnoresForwardedHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	request.RemoteAddr = "198.51.100.7:5000"
	request.Header.Set("X-Forwarded-For", "203.0.113.99")

	require.Equal(t, "198.51.100.7", badhttp.SourceAddress(request).Addr.String(),
		"SourceAddress must return the transport peer; a client must not be able "+
			"to choose it")
}

// TestIPv6ForwardedHeaderCannotSpoofSource covers the IPv6 form, which takes a
// different parse path in the helper.
func TestIPv6ForwardedHeaderCannotSpoofSource(t *testing.T) {
	source, recorded := h2SourceForRequest(t, map[string]string{
		"X-Forwarded-For": "2001:db8::1",
	})
	require.True(t, recorded)
	require.Equal(t, "198.51.100.7", source.Addr.String(),
		"an IPv6 forwarded header must not replace the transport peer either")
}

var _ = adapter.InboundContext{}
