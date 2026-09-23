package option

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestHTTPServerProfileUnknownNameRejected(t *testing.T) {
	if _, _, err := NewHTTPServerProfile("nope"); err == nil {
		t.Fatal("an unknown server_profile must be rejected")
	}
}

func TestHTTPServerProfileUnsetIsNoop(t *testing.T) {
	profile, applied, err := NewHTTPServerProfile("")
	if err != nil {
		t.Fatalf("an unset profile must be valid: %v", err)
	}
	if applied {
		t.Fatal("an unset profile must not be reported as applied")
	}
	if profile.MaxHeaderBytes != 0 || profile.MaxConcurrentStreams != 0 {
		t.Fatalf("an unset profile must be the zero value, got %+v", profile)
	}
	// Applying the zero profile must change nothing.
	http2 := HTTP2Options{}
	quic := QUICOptions{}
	profile.ApplyToHTTP2(&http2)
	profile.ApplyToQUIC(&quic)
	if http2 != (HTTP2Options{}) || quic != (QUICOptions{}) {
		t.Fatalf("a zero profile must not modify options: %+v %+v", http2, quic)
	}
}

func TestHTTPServerProfileJiejieBalanced1GValues(t *testing.T) {
	profile, applied, err := NewHTTPServerProfile(HTTPServerProfileNameJiejieBalanced1G)
	if err != nil {
		t.Fatalf("the jiejie profile must resolve: %v", err)
	}
	if !applied {
		t.Fatal("the jiejie profile must be reported as applied")
	}
	// These are the documented, deterministic resource bounds.
	if profile.MaxHeaderBytes != 64<<10 {
		t.Fatalf("max header bytes must be 64 KiB, got %d", profile.MaxHeaderBytes)
	}
	if profile.MaxConcurrentStreams != 256 {
		t.Fatalf("max concurrent streams must be 256, got %d", profile.MaxConcurrentStreams)
	}
	if profile.StreamReceiveWindow != 4<<20 {
		t.Fatalf("stream receive window must be 4 MiB, got %d", profile.StreamReceiveWindow)
	}
	if profile.ConnectionReceiveWindow != 16<<20 {
		t.Fatalf("connection receive window must be 16 MiB, got %d", profile.ConnectionReceiveWindow)
	}
	if profile.IdleTimeout != 60*time.Second {
		t.Fatalf("idle timeout must be 60s, got %v", profile.IdleTimeout)
	}
	if profile.KeepAlivePeriod <= 0 || profile.KeepAlivePeriod > 60*time.Second {
		t.Fatalf("keep alive period must be a moderate positive value, got %v", profile.KeepAlivePeriod)
	}
}

func TestHTTPServerProfileFillsUnsetFields(t *testing.T) {
	profile, _, err := NewHTTPServerProfile(HTTPServerProfileNameJiejieBalanced1G)
	if err != nil {
		t.Fatalf("resolve profile: %v", err)
	}
	http2 := HTTP2Options{}
	profile.ApplyToHTTP2(&http2)

	if http2.MaxConcurrentStreams != 256 {
		t.Fatalf("max concurrent streams not applied: %d", http2.MaxConcurrentStreams)
	}
	if http2.StreamReceiveWindow.Value() != 4<<20 {
		t.Fatalf("stream receive window not applied: %d", http2.StreamReceiveWindow.Value())
	}
	if http2.ConnectionReceiveWindow.Value() != 16<<20 {
		t.Fatalf("connection receive window not applied: %d", http2.ConnectionReceiveWindow.Value())
	}
	if time.Duration(http2.IdleTimeout) != 60*time.Second {
		t.Fatalf("idle timeout not applied: %v", time.Duration(http2.IdleTimeout))
	}
	if time.Duration(http2.KeepAlivePeriod) == 0 {
		t.Fatal("keep alive period not applied")
	}
}

// TestHTTPServerProfileExplicitValuesWin is the compatibility rule: an
// explicitly configured field is never overwritten by the profile.
func TestHTTPServerProfileExplicitValuesWin(t *testing.T) {
	profile, _, err := NewHTTPServerProfile(HTTPServerProfileNameJiejieBalanced1G)
	if err != nil {
		t.Fatalf("resolve profile: %v", err)
	}
	explicitStream := memoryBytesValue(1 << 20)
	explicitConnection := memoryBytesValue(2 << 20)
	http2 := HTTP2Options{
		MaxConcurrentStreams:    7,
		StreamReceiveWindow:     explicitStream,
		ConnectionReceiveWindow: explicitConnection,
		IdleTimeout:             badoption.Duration(5 * time.Second),
		KeepAlivePeriod:         badoption.Duration(3 * time.Second),
	}
	profile.ApplyToHTTP2(&http2)

	if http2.MaxConcurrentStreams != 7 {
		t.Fatalf("explicit max_concurrent_streams must win, got %d", http2.MaxConcurrentStreams)
	}
	if http2.StreamReceiveWindow.Value() != 1<<20 {
		t.Fatalf("explicit stream_receive_window must win, got %d", http2.StreamReceiveWindow.Value())
	}
	if http2.ConnectionReceiveWindow.Value() != 2<<20 {
		t.Fatalf("explicit connection_receive_window must win, got %d", http2.ConnectionReceiveWindow.Value())
	}
	if time.Duration(http2.IdleTimeout) != 5*time.Second {
		t.Fatalf("explicit idle_timeout must win, got %v", time.Duration(http2.IdleTimeout))
	}
	if time.Duration(http2.KeepAlivePeriod) != 3*time.Second {
		t.Fatalf("explicit keep_alive_period must win, got %v", time.Duration(http2.KeepAlivePeriod))
	}
}

func TestHTTPServerProfilePartialExplicitKeepsProfileForRest(t *testing.T) {
	profile, _, err := NewHTTPServerProfile(HTTPServerProfileNameJiejieBalanced1G)
	if err != nil {
		t.Fatalf("resolve profile: %v", err)
	}
	http2 := HTTP2Options{MaxConcurrentStreams: 12}
	profile.ApplyToHTTP2(&http2)

	if http2.MaxConcurrentStreams != 12 {
		t.Fatalf("explicit field must win, got %d", http2.MaxConcurrentStreams)
	}
	// Everything else still comes from the profile.
	if http2.StreamReceiveWindow.Value() != 4<<20 {
		t.Fatalf("unset field must still take the profile value, got %d", http2.StreamReceiveWindow.Value())
	}
	if time.Duration(http2.IdleTimeout) != 60*time.Second {
		t.Fatalf("unset idle_timeout must take the profile value, got %v", time.Duration(http2.IdleTimeout))
	}
}

func TestHTTPServerProfileMaxHeaderBytesFallback(t *testing.T) {
	profile, _, err := NewHTTPServerProfile(HTTPServerProfileNameJiejieBalanced1G)
	if err != nil {
		t.Fatalf("resolve profile: %v", err)
	}
	const upstreamDefault = 1 << 20
	if got := profile.MaxHeaderBytesValue(upstreamDefault); got != 64<<10 {
		t.Fatalf("profile must supply its header limit, got %d", got)
	}
	// A zero profile keeps the upstream default.
	var zero HTTPServerProfile
	if got := zero.MaxHeaderBytesValue(upstreamDefault); got != upstreamDefault {
		t.Fatalf("an unset profile must keep the upstream default, got %d", got)
	}
}

// TestHTTPInboundServerProfileDoesNotMutateExplicitFields drives the option
// through its public resolver, which is what the inbound actually calls.
func TestHTTPInboundServerProfileResolution(t *testing.T) {
	options := HTTPInboundOptions{
		ServerProfile: HTTPServerProfileNameJiejieBalanced1G,
	}
	resolved, err := options.ResolveServerResources()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !resolved.ProfileApplied {
		t.Fatal("the profile must be reported as applied")
	}
	// MaxHeaderBytes now always reports the EFFECTIVE limit: the profile value.
	if resolved.MaxHeaderBytes != 64<<10 {
		t.Fatalf("the profile's 64 KiB header limit must be reported, got %d", resolved.MaxHeaderBytes)
	}
	// And the effective option sets must carry the profile too, not just the
	// header limit. This is the regression guard for the bug where the profile
	// filled a copy that the caller never used.
	if resolved.HTTP2Options.MaxConcurrentStreams != 256 {
		t.Fatalf("the effective HTTP/2 options must carry the profile, got %d streams",
			resolved.HTTP2Options.MaxConcurrentStreams)
	}
	if resolved.HTTP3Options.BBRProfile.BBRProfileValue() != "standard" {
		t.Fatalf("the effective QUIC options must carry the BBR profile, got %q",
			resolved.HTTP3Options.BBRProfile.BBRProfileValue())
	}
}

func TestHTTPInboundServerProfileUnknownFails(t *testing.T) {
	options := HTTPInboundOptions{ServerProfile: "does-not-exist"}
	if _, err := options.ResolveServerResources(); err == nil {
		t.Fatal("an unknown server_profile must fail configuration loading")
	}
}

func TestHTTPInboundNoProfileKeepsUpstream(t *testing.T) {
	options := HTTPInboundOptions{}
	resolved, err := options.ResolveServerResources()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.ProfileApplied {
		t.Fatal("an unset profile must not be applied")
	}
	if resolved.MaxHeaderBytes != UpstreamMaxHeaderBytes {
		t.Fatalf("with no profile the upstream %d header default must apply, got %d",
			UpstreamMaxHeaderBytes, resolved.MaxHeaderBytes)
	}
	if resolved.HTTP2Options.MaxConcurrentStreams != 0 {
		t.Fatalf("with no profile the HTTP/2 options must be untouched, got %d streams",
			resolved.HTTP2Options.MaxConcurrentStreams)
	}
}

// TestHTTP3PoolValidatedAtDecodeTime ensures `sing-box check` rejects an
// invalid pool instead of failing later when the transport is constructed.
func TestHTTP3PoolValidatedAtDecodeTime(t *testing.T) {
	decode := func(config string) error {
		var options HTTPOutboundOptions
		return json.UnmarshalContext(context.Background(), []byte(config), &options)
	}
	invalid := []string{
		`{"server":"1.2.3.4","server_port":443,"version":3,"username":"a","password":"b","http3_connection_pool":{"size":64},"tls":{"enabled":true,"server_name":"x.test"}}`,
		`{"server":"1.2.3.4","server_port":443,"version":3,"username":"a","password":"b","http3_connection_pool":{"size":2,"strategy":"adaptive"},"tls":{"enabled":true,"server_name":"x.test"}}`,
		`{"server":"1.2.3.4","server_port":443,"version":3,"username":"a","password":"b","http3_connection_pool":{"size":-1},"tls":{"enabled":true,"server_name":"x.test"}}`,
	}
	for _, config := range invalid {
		if err := decode(config); err == nil {
			t.Fatalf("an invalid pool must be rejected at decode time: %s", config)
		}
	}

	valid := []string{
		`{"server":"1.2.3.4","server_port":443,"version":3,"username":"a","password":"b","tls":{"enabled":true,"server_name":"x.test"}}`,
		`{"server":"1.2.3.4","server_port":443,"version":3,"username":"a","password":"b","http3_connection_pool":{"size":1},"tls":{"enabled":true,"server_name":"x.test"}}`,
		`{"server":"1.2.3.4","server_port":443,"version":3,"username":"a","password":"b","http3_connection_pool":{"size":2,"strategy":"round_robin"},"tls":{"enabled":true,"server_name":"x.test"}}`,
		// An absent pool must keep decoding, i.e. upstream compatibility.
		`{"server":"1.2.3.4","server_port":443,"version":2,"username":"a","password":"b","tls":{"enabled":true,"server_name":"x.test"}}`,
	}
	for _, config := range valid {
		if err := decode(config); err != nil {
			t.Fatalf("a valid pool must decode: %v (%s)", err, config)
		}
	}
}
