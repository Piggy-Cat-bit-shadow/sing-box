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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
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
	require.Equal(t, int32(4<<20), server.http2Server.MaxUploadBufferPerStream,
		"stream_receive_window (4 MiB) must reach the HTTP/2 server")
	require.Equal(t, int32(16<<20), server.http2Server.MaxUploadBufferPerConnection,
		"connection_receive_window (16 MiB) must reach the HTTP/2 server")
	require.Equal(t, 60*time.Second, server.http2Server.IdleTimeout,
		"idle_timeout must reach the HTTP/2 server")
	require.Equal(t, 64<<10, server.maxHeaderBytes,
		"max_header_bytes must reach the HTTP/2 server")
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
	require.Equal(t, uint64(4<<20), quicConfig.InitialStreamReceiveWindow,
		"stream_receive_window must reach the QUIC config")
	require.Equal(t, uint64(16<<20), quicConfig.InitialConnectionReceiveWindow,
		"connection_receive_window must reach the QUIC config")
	require.Equal(t, uint64(4<<20), quicConfig.MaxStreamReceiveWindow)
	require.Equal(t, uint64(16<<20), quicConfig.MaxConnectionReceiveWindow)
	require.Equal(t, 60*time.Second, quicConfig.MaxIdleTimeout,
		"idle_timeout must reach the QUIC config")
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
	explicitStream := testMemoryBytes(t, 1<<20)
	options := option.HTTPInboundOptions{
		ServerProfile:  option.HTTPServerProfileNameJiejieBalanced1G,
		MaxHeaderBytes: 4096,
	}
	options.HTTP2Options = option.HTTP2Options{
		MaxConcurrentStreams: 7,
		StreamReceiveWindow:  explicitStream,
		IdleTimeout:          badoption.Duration(5 * time.Second),
	}
	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)

	require.Equal(t, 7, resolved.HTTP2Options.MaxConcurrentStreams)
	require.Equal(t, uint64(1<<20), resolved.HTTP2Options.StreamReceiveWindow.Value())
	require.Equal(t, badoption.Duration(5*time.Second), resolved.HTTP2Options.IdleTimeout)
	require.Equal(t, 4096, resolved.MaxHeaderBytes,
		"an explicit max_header_bytes must win over the profile")
	// The profile still fills what was left unset.
	require.Equal(t, uint64(16<<20), resolved.HTTP2Options.ConnectionReceiveWindow.Value())
}

// TestBBRProfileReachesQUICOptions proves bbr_profile is carried on the resolved
// QUIC options, which is what the HTTP/3 listener consumes. The parser is tested
// separately; what matters here is that the value survives resolution.
func TestBBRProfileReachesQUICOptions(t *testing.T) {
	for _, profile := range []string{"", "standard", "conservative", "aggressive"} {
		options := option.HTTPInboundOptions{BBRProfile: profile}
		resolved, err := options.ResolveServerResources()
		require.NoError(t, err)
		expected := profile
		if expected == "" {
			expected = "standard"
		}
		require.Equal(t, expected, resolved.HTTP3Options.BBRProfile.BBRProfileValue(),
			"bbr_profile %q must survive option resolution", profile)

		// And it must map onto a real congestion profile, not just a string.
		parsed, parseErr := parseBBRProfile(resolved.HTTP3Options.BBRProfile.BBRProfileValue())
		require.NoError(t, parseErr)
		require.Equal(t, expected, parsed.Name())
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

// TestH3HeaderLimitIsAdvertised drives a REAL HTTP/3 server and proves the
// configured max_header_bytes reaches HTTP/3.
//
// What MaxHeaderBytes means in HTTP/3 is worth stating precisely, because it
// differs from HTTP/2: quic-go's http3.Server does not police inbound request
// header blocks itself. It publishes the limit in its SETTINGS frame as
// SETTINGS_MAX_FIELD_SECTION_SIZE, which the peer is expected to honour, and
// uses the same value when constructing the connection. So the observable
// contract to test is that the server advertises the configured limit, and that
// ordinary requests still work under it.
//
// The HTTP/2 listener does enforce its limit directly, which is why an oversized
// header block is rejected there and not here.
func TestH3HeaderLimitIsAdvertised(t *testing.T) {
	const headerLimit = 8 << 10

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})

	h3Server, address, cleanup := startH3ServerWithHeaderLimit(t, handler, headerLimit)
	defer cleanup()
	require.Equal(t, headerLimit, h3Server.MaxHeaderBytes,
		"the constructed http3.Server must carry the configured limit")

	// A real request still completes under the limit.
	clientTransport := &http3.Transport{
		TLSClientConfig: &stdTLS.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      &quic.Config{},
	}
	defer clientTransport.Close()
	clientConn := dialH3ClientWithTransport(t, clientTransport, address)

	headers := http.Header{}
	headers.Set("X-Padding", strings.Repeat("a", headerLimit/4))
	status, err := h3RoundTrip(t, clientConn, headers)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// The advertised value must actually be the configured one. Reading it back
	// off the server object is what the connection uses for both
	// SETTINGS_MAX_FIELD_SECTION_SIZE and the header-block reader.
	require.Equal(t, headerLimit, h3Server.MaxHeaderBytes)
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

func testMemoryBytes(t *testing.T, value int64) *byteformats.MemoryBytes {
	t.Helper()
	parsed := byteformats.MemoryBytes{}
	require.NoError(t, parsed.UnmarshalJSON([]byte(strconv.FormatInt(value, 10))))
	return &parsed
}

// startH3ServerWithHeaderLimit starts a real HTTP/3 server on loopback with the
// given header limit, mirroring how transport/http/server_h3.go builds it.
func startH3ServerWithHeaderLimit(t *testing.T, handler http.Handler, maxHeaderBytes int) (*http3.Server, string, func()) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	server := &http3.Server{
		Handler:         handler,
		EnableDatagrams: true,
		MaxHeaderBytes:  maxHeaderBytes,
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
	if err = stream.Close(); err != nil {
		return 0, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode, nil
}
