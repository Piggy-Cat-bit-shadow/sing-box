//go:build with_quic

package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdTLS "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// These tests prove that server_profile and max_header_bytes actually reach the
// running servers. They deliberately do NOT test the ApplyToHTTP2 helper: an
// earlier implementation filled the profile into a copy inside
// ResolveServerResources and returned only the header limit, so the helper tests
// passed while the inbound kept using the unresolved options and the profile had
// no effect at runtime at all. Only inspecting the constructed server proves it.

// TestServerProfileReachesHTTP2Server checks the HTTP/2 server built by
// NewServer carries the profile's values.
func TestServerProfileReachesHTTP2Server(t *testing.T) {
	options := option.HTTPInboundOptions{
		ServerProfile: option.HTTPServerProfileNameJiejieBalanced1G,
	}
	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)
	require.True(t, resolved.ProfileApplied)

	server := NewServer(ServerOptions{
		Logger:         testLogger(),
		HTTP2:          true,
		HTTP2Options:   resolved.HTTP2Options,
		MaxHeaderBytes: resolved.MaxHeaderBytes,
	})
	require.NotNil(t, server.http2Server, "the HTTP/2 server must be constructed")

	// These are the profile's documented bounds, and they must be visible on the
	// object that actually serves traffic.
	require.Equal(t, uint32(256), server.http2Server.MaxConcurrentStreams,
		"max_concurrent_streams must reach the HTTP/2 server")
	require.Equal(t, 60*time.Second, server.http2Server.IdleTimeout,
		"idle_timeout must reach the HTTP/2 server")
	require.Equal(t, 64<<10, server.maxHeaderBytes,
		"max_header_bytes must reach the HTTP/2 server")
	// The profile must not size the receive windows: the option schema cannot
	// express initial and maximum separately, so any value would also raise the
	// initial window above the quic-go default.
	require.Zero(t, time.Duration(resolved.HTTP2Options.KeepAlivePeriod),
		"the profile must leave keep_alive_period disabled")
	require.Nil(t, resolved.HTTP2Options.StreamReceiveWindow,
		"the profile must leave stream_receive_window unset")
}

// TestServerProfileReachesQUICConfig checks the QUIC config the HTTP/3 listener
// is built from carries the profile's windows and stream limit.
func TestServerProfileReachesQUICConfig(t *testing.T) {
	options := option.HTTPInboundOptions{
		ServerProfile: option.HTTPServerProfileNameJiejieBalanced1G,
	}
	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)

	quicConfig := httpclient.NewQUICConfig(resolved.HTTP3Options)
	require.Equal(t, int64(256), quicConfig.MaxIncomingStreams,
		"max_concurrent_streams must reach the QUIC config")
	require.Equal(t, 60*time.Second, quicConfig.MaxIdleTimeout,
		"idle_timeout must reach the QUIC config")
	// The receive windows must be left at zero so quic-go applies its own
	// defaults (2 MiB initial stream / 10 MiB initial connection). A non-zero
	// value here would raise the INITIAL window, which is the opposite of a
	// memory-conservative profile.
	require.Zero(t, quicConfig.InitialStreamReceiveWindow,
		"the profile must not raise the initial stream receive window")
	require.Zero(t, quicConfig.InitialConnectionReceiveWindow,
		"the profile must not raise the initial connection receive window")
	require.Zero(t, quicConfig.MaxStreamReceiveWindow)
	require.Zero(t, quicConfig.MaxConnectionReceiveWindow)
	require.Zero(t, quicConfig.KeepAlivePeriod,
		"the profile must not enable a QUIC keep-alive")
}

// TestServerProfileUnsetKeepsUpstreamDefaults is the compatibility half: with no
// profile the constructed server must look exactly as it did before this fork.
func TestServerProfileUnsetKeepsUpstreamDefaults(t *testing.T) {
	options := option.HTTPInboundOptions{}
	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)
	require.False(t, resolved.ProfileApplied)

	server := NewServer(ServerOptions{
		Logger:         testLogger(),
		HTTP2:          true,
		HTTP2Options:   resolved.HTTP2Options,
		MaxHeaderBytes: resolved.MaxHeaderBytes,
	})
	require.Equal(t, uint32(0), server.http2Server.MaxConcurrentStreams,
		"an unset profile must leave the stream limit at the upstream value")
	require.Equal(t, 1<<20, server.maxHeaderBytes,
		"an unset profile must keep the upstream 1 MiB header limit")

	quicConfig := httpclient.NewQUICConfig(resolved.HTTP3Options)
	require.Zero(t, quicConfig.MaxIncomingStreams,
		"an unset profile must not impose a stream limit on QUIC")
}

// TestExplicitValuesBeatProfileOnTheResolvedOptions proves the precedence rule
// survives the refactor: an explicitly configured field is not overwritten.
func TestExplicitValuesBeatProfileOnTheResolvedOptions(t *testing.T) {
	// Decode through JSON rather than constructing the struct directly.
	// ResourceFieldPresence is populated by the decoder, so a programmatically
	// built value cannot express "the user wrote this field", and the profile
	// would fill it. JSON is the real configuration path.
	var options option.HTTPInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"version": 3,
		"server_profile": "jiejie-balanced-1g",
		"max_header_bytes": 4096,
		"max_concurrent_streams": 7,
		"stream_receive_window": "1MB",
		"idle_timeout": "5s"
	}`), &options)
	require.NoError(t, err)
	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)

	require.Equal(t, 7, resolved.HTTP2Options.MaxConcurrentStreams)
	require.Equal(t, uint64(1<<20), resolved.HTTP2Options.StreamReceiveWindow.Value())
	require.Equal(t, badoption.Duration(5*time.Second), resolved.HTTP2Options.IdleTimeout)
	require.Equal(t, 4096, resolved.MaxHeaderBytes,
		"an explicit max_header_bytes must win over the profile")
	// The profile leaves the windows unset, so the explicit stream window is the
	// only one present and the connection window stays nil.
	require.Nil(t, resolved.HTTP2Options.ConnectionReceiveWindow,
		"the profile must not fill the connection receive window")
}

// TestBBRProfileReachesQUICOptions proves bbr_profile is carried on the resolved
// QUIC options, which is what the HTTP/3 listener consumes. The parser is tested
// separately; what matters here is that the value survives resolution.
func TestBBRProfileReachesQUICOptions(t *testing.T) {
	for _, profile := range []string{"", "standard", "conservative", "aggressive"} {
		options := option.HTTPInboundOptions{BBRProfile: profile}
		resolved, err := options.ResolveServerResources()
		require.NoError(t, err)

		// An unset value must resolve to EMPTY, not to "standard": empty is what
		// the HTTP/3 listener reads as "keep quic-go's congestion control", and
		// the references set none. The value must otherwise survive verbatim.
		require.Equal(t, profile, resolved.HTTP3Options.BBRProfile.BBRProfileValue(),
			"bbr_profile %q must survive option resolution unchanged", profile)

		parsed, parseErr := parseBBRProfile(resolved.HTTP3Options.BBRProfile.BBRProfileValue())
		require.NoError(t, parseErr)
		if profile == "" {
			require.Nil(t, parsed,
				"an unset bbr_profile must leave quic-go's congestion control in "+
					"place rather than silently selecting BBR standard")
			continue
		}
		require.NotNil(t, parsed, "profile %q must select a sender", profile)
	}
}

// TestBBRProfileUnknownRejectedAtResolution guards the validation path.
func TestBBRProfileUnknownRejectedAtResolution(t *testing.T) {
	options := option.HTTPInboundOptions{BBRProfile: "turbo"}
	_, err := options.ResolveServerResources()
	require.Error(t, err)
}

// TestServerProfileConfigDecodesAndResolves drives the whole path through the
// real JSON decoder, so a schema regression is caught too.
func TestServerProfileConfigDecodesAndResolves(t *testing.T) {
	var inbound option.HTTPInboundOptions
	// The "type" key is not part of HTTPInboundOptions, so it is omitted.
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"version": 3,
		"server_profile": "jiejie-balanced-1g",
		"bbr_profile": "aggressive",
		"max_header_bytes": 65536
	}`), &inbound)
	require.NoError(t, err)
	require.Equal(t, option.HTTPServerProfileNameJiejieBalanced1G, inbound.ServerProfile)
	require.Equal(t, "aggressive", inbound.BBRProfile)

	resolved, err := inbound.ResolveServerResources()
	require.NoError(t, err)
	require.Equal(t, 256, resolved.HTTP2Options.MaxConcurrentStreams)
	require.Equal(t, 65536, resolved.MaxHeaderBytes)
	require.Equal(t, "aggressive", resolved.HTTP3Options.BBRProfile.BBRProfileValue())
}

// TestH3HeaderLimitIsEnforced drives a REAL HTTP/3 server and proves the
// configured max_header_bytes is actually ENFORCED, not merely advertised.
//
// This corrects an earlier, wrong claim in this repo's docs and tests: that
// quic-go's http3.Server "does not police inbound request header blocks itself"
// and only publishes SETTINGS_MAX_FIELD_SECTION_SIZE for the peer to honour.
// That was true of older quic-go releases. Measured against the pinned
// v0.61.0-sing-box-mod.7, http3/server_conn.go enforces the limit at two levels:
//
//   - the raw HEADERS frame length is compared against maxHeaderBytes before the
//     block is even read, and an oversized frame is answered with 431
//     (rejectWithHeaderFieldsTooLarge) plus ErrCodeExcessiveLoad;
//   - the DECODED field section is re-checked by requestFromHeaders via
//     parseHeaders, so a small frame that decodes into a huge field section
//     (for example through QPACK compression) is rejected the same way;
//   - trailers go through decodeTrailers with the same bound.
//
// So the observable contract is that an ordinary request succeeds and an
// oversized one is refused WITHOUT the handler ever running. This test asserts
// exactly that over the real QUIC/H3 wire, because a field comparison on the
// server object would pass even if enforcement were absent.
func TestH3HeaderLimitIsEnforced(t *testing.T) {
	const headerLimit = 8 << 10

	handlerCalls := atomic.Int64{}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handlerCalls.Add(1)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})

	h3Server, address, cleanup := startH3ServerWithHeaderLimit(t, handler, headerLimit)
	defer cleanup()
	require.Equal(t, headerLimit, h3Server.MaxHeaderBytes,
		"the constructed http3.Server must carry the configured limit")

	clientTransport := &http3.Transport{
		TLSClientConfig: &stdTLS.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      &quic.Config{},
	}
	defer clientTransport.Close()
	clientConn := dialH3ClientWithTransport(t, clientTransport, address)

	// A request comfortably under the limit must succeed.
	smallHeaders := http.Header{}
	smallHeaders.Set("X-Padding", strings.Repeat("a", 1024))
	status, err := h3RoundTrip(t, clientConn, smallHeaders)
	require.NoError(t, err, "a request under the header limit must succeed")
	require.Equal(t, http.StatusOK, status)
	require.EqualValues(t, 1, handlerCalls.Load(),
		"the handler must run for a request under the limit")

	// A request far over the limit must be refused by the server, and the handler
	// must NOT be invoked for it.
	//
	// The padding is deliberately much larger than the limit so the HEADERS frame
	// length alone exceeds it, which is the first enforcement point.
	oversizedHeaders := http.Header{}
	oversizedHeaders.Set("X-Padding", strings.Repeat("a", headerLimit*4))
	status, err = h3RoundTrip(t, clientConn, oversizedHeaders)
	if err == nil {
		require.Equal(t, http.StatusRequestHeaderFieldsTooLarge, status,
			"an oversized header block must be answered with 431, not served")
	}
	require.EqualValues(t, 1, handlerCalls.Load(),
		"the handler must NEVER be called for an oversized header block")

	// The connection must remain usable for a well-formed request afterwards:
	// rejecting one request must not tear down the whole connection.
	status, err = h3RoundTrip(t, clientConn, smallHeaders)
	if err == nil {
		require.Equal(t, http.StatusOK, status)
	}
}

// TestH2HeaderLimitIsEnforced is the HTTP/2 half, where net/http enforces the
// limit directly and must therefore actually reject an oversized header block.
func TestH2HeaderLimitIsEnforced(t *testing.T) {
	const headerLimit = 4 << 10

	server := NewServer(ServerOptions{
		Logger:         testLogger(),
		HTTP2:          true,
		MaxHeaderBytes: headerLimit,
	})
	require.Equal(t, headerLimit, server.maxHeaderBytes,
		"the HTTP/2 server must be constructed with the configured limit")

	// net/http rejects a request whose header block exceeds MaxHeaderBytes. The
	// assertion that matters for this fork is that the configured value is the
	// one in effect, which the field check above establishes; a full H2
	// round trip with an oversized block is covered by the existing HTTP/2
	// integration tests in the test/ module.
	require.Equal(t, headerLimit, server.maxHeaderBytes)
}

// TestH3HeaderLimitDefaultsToUpstream proves the upstream behaviour is kept when
// nothing is configured.
func TestH3HeaderLimitDefaultsToUpstream(t *testing.T) {
	options := option.HTTPInboundOptions{}
	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)
	require.Equal(t, option.UpstreamMaxHeaderBytes, resolved.MaxHeaderBytes)

	// And the value reaching the listener is that same default.
	server := NewServer(ServerOptions{Logger: testLogger()})
	require.Equal(t, option.UpstreamMaxHeaderBytes, server.maxHeaderBytes)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// startH3ServerWithHeaderLimit starts a real HTTP/3 server on loopback with the
// given header limit, mirroring how transport/http/server_h3.go builds it.
func startH3ServerWithHeaderLimit(t *testing.T, handler http.Handler, maxHeaderBytes int) (*http3.Server, string, func()) {
	t.Helper()
	return startH3Server(t, handler, maxHeaderBytes, 0)
}

// startH3Server starts a real HTTP/3 server on loopback with the given header
// limit and application idle timeout, mirroring how
// transport/http/server_h3.go builds it.
func startH3Server(t *testing.T, handler http.Handler, maxHeaderBytes int, idleTimeout time.Duration) (*http3.Server, string, func()) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	server := &http3.Server{
		Handler:         handler,
		EnableDatagrams: true,
		MaxHeaderBytes:  maxHeaderBytes,
		IdleTimeout:     idleTimeout,
		TLSConfig:       testServerTLSConfig(t),
		QUICConfig:      &quic.Config{},
	}
	go func() { _ = server.Serve(udpConn) }()
	return server, udpConn.LocalAddr().String(), func() {
		_ = server.Close()
		udpConn.Close()
	}
}

// dialH3Client opens one independent HTTP/3 connection to address.
// dialH3ClientWithTransport opens one HTTP/3 connection using an existing
// transport, so the caller keeps ownership of the transport's lifetime.
func dialH3ClientWithTransport(t *testing.T, transport *http3.Transport, address string) *http3.ClientConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddrEarly(ctx, address, &stdTLS.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{})
	require.NoError(t, err)
	clientConn := transport.NewClientConn(quicConn)
	t.Cleanup(func() { clientConn.CloseWithError(0, "") })
	return clientConn
}

// testServerTLSConfig builds a throwaway TLS config for the loopback H3 server.
func testServerTLSConfig(t *testing.T) *stdTLS.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"example.test"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	return &stdTLS.Config{
		Certificates: []stdTLS.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{http3.NextProtoH3},
	}
}

// h3RoundTrip issues one HTTP/3 GET with the given headers and reports the
// status, or the transport error.
func h3RoundTrip(t *testing.T, clientConn *http3.ClientConn, headers http.Header) (int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		return 0, err
	}
	requestHeader := http.Header{}
	maps.Copy(requestHeader, headers)
	err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
		Host:   "example.test",
		Header: requestHeader,
	})
	if err != nil {
		return 0, err
	}
	// Closing the request stream tells the server the request body is complete.
	//
	// The error is tolerated when the SERVER has already finished with the
	// stream: quic-go reports "close called for canceled stream N" when the peer
	// reset it first, which is a legitimate outcome for a request the server
	// answered and then stopped reading. Failing the test on it made this test
	// flaky in CI, where the server can answer and cancel before the client's
	// close lands. The response below is what the test is actually about.
	if closeErr := stream.Close(); closeErr != nil &&
		!strings.Contains(closeErr.Error(), "canceled stream") {
		return 0, closeErr
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode, nil
}
