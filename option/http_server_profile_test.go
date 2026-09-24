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
	// The profile must NOT set receive windows. The schema cannot express initial
	// and maximum separately, so any value here would also raise the initial
	// window above the quic-go default, which is not memory-conservative.
	if profile.StreamReceiveWindow != 0 {
		t.Fatalf("the profile must not override stream_receive_window, got %d", profile.StreamReceiveWindow)
	}
	if profile.ConnectionReceiveWindow != 0 {
		t.Fatalf("the profile must not override connection_receive_window, got %d", profile.ConnectionReceiveWindow)
	}
	if profile.KeepAlivePeriod != 0 {
		t.Fatalf("the profile must not enable a keep-alive, got %v", profile.KeepAlivePeriod)
	}
	if profile.IdleTimeout != 60*time.Second {
		t.Fatalf("idle timeout must be 60s, got %v", profile.IdleTimeout)
	}
	if profile.KeepAlivePeriod != 0 {
		t.Fatalf("keep alive must stay disabled (0), got %v", profile.KeepAlivePeriod)
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
	if http2.StreamReceiveWindow != nil {
		t.Fatalf("the profile must leave the stream receive window unset, got %d",
			http2.StreamReceiveWindow.Value())
	}
	if time.Duration(http2.IdleTimeout) != 60*time.Second {
		t.Fatalf("idle timeout not applied: %v", time.Duration(http2.IdleTimeout))
	}
	if time.Duration(http2.KeepAlivePeriod) != 0 {
		t.Fatalf("the profile must leave keep_alive_period unset, got %v", time.Duration(http2.KeepAlivePeriod))
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
	if http2.StreamReceiveWindow != nil {
		t.Fatal("an unset stream receive window must stay unset under the profile")
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

// TestJiejieProfileDoesNotRaiseQUICWindows is the regression for the profile
// over-reaching.
//
// quic-go's defaults are 2 MiB initial stream / 6 MiB max stream and 10 MiB
// initial connection / 15 MiB max connection, with keep-alive disabled.
// common/httpclient.NewQUICConfig applies one configured value to BOTH the
// initial and the maximum window, so a profile that sets a receive window raises
// the initial window as a side effect. The profile must therefore leave the
// windows alone entirely.
func TestJiejieProfileDoesNotRaiseQUICWindows(t *testing.T) {
	profile, applied, err := NewHTTPServerProfile(HTTPServerProfileNameJiejieBalanced1G)
	if err != nil || !applied {
		t.Fatalf("profile must resolve: %v", err)
	}

	options := HTTP2Options{}
	profile.ApplyToHTTP2(&options)

	if options.StreamReceiveWindow != nil {
		t.Fatalf("stream_receive_window must stay unset so quic-go keeps its 2 MiB default, got %d",
			options.StreamReceiveWindow.Value())
	}
	if options.ConnectionReceiveWindow != nil {
		t.Fatalf("connection_receive_window must stay unset so quic-go keeps its 10 MiB default, got %d",
			options.ConnectionReceiveWindow.Value())
	}
	if options.KeepAlivePeriod != 0 {
		t.Fatalf("keep_alive_period must stay 0 (disabled, the quic-go default), got %v",
			time.Duration(options.KeepAlivePeriod))
	}

	// The parts the profile legitimately sets must still be applied.
	if options.MaxConcurrentStreams != 256 {
		t.Fatalf("max_concurrent_streams must still be applied, got %d", options.MaxConcurrentStreams)
	}
	if time.Duration(options.IdleTimeout) != 60*time.Second {
		t.Fatalf("idle_timeout must still be applied, got %v", time.Duration(options.IdleTimeout))
	}
}

// TestProfileDoesNotOverrideExplicitZero is the regression for the "explicit
// fields always win" contract.
//
// max_concurrent_streams, idle_timeout, keep_alive_period and max_header_bytes are
// plain values, so an explicit 0 and an omitted key both decode to 0. Without
// presence tracking the profile cannot tell them apart and silently overwrites the
// explicit zero. keep_alive_period: 0 means "disable keep-alive", which is the
// opposite of what the profile sets, so getting this wrong is a behaviour change
// the user did not ask for.
func TestProfileDoesNotOverrideExplicitZero(t *testing.T) {
	testCases := []struct {
		name          string
		config        string
		checkResolved func(t *testing.T, resolved ServerResourceOptions)
	}{
		{
			name:   "explicit keep_alive_period 0 survives the profile",
			config: `{"version":3,"server_profile":"jiejie-balanced-1g","keep_alive_period":"0s"}`,
			checkResolved: func(t *testing.T, resolved ServerResourceOptions) {
				if resolved.HTTP2Options.KeepAlivePeriod != 0 {
					t.Fatalf("keep_alive_period: 0 must stay 0, got %v",
						time.Duration(resolved.HTTP2Options.KeepAlivePeriod))
				}
			},
		},
		{
			name:   "explicit max_concurrent_streams 0 survives the profile",
			config: `{"version":3,"server_profile":"jiejie-balanced-1g","max_concurrent_streams":0}`,
			checkResolved: func(t *testing.T, resolved ServerResourceOptions) {
				if resolved.HTTP2Options.MaxConcurrentStreams != 0 {
					t.Fatalf("max_concurrent_streams: 0 must stay 0, got %d",
						resolved.HTTP2Options.MaxConcurrentStreams)
				}
			},
		},
		{
			name:   "explicit idle_timeout 0 survives the profile",
			config: `{"version":3,"server_profile":"jiejie-balanced-1g","idle_timeout":"0s"}`,
			checkResolved: func(t *testing.T, resolved ServerResourceOptions) {
				if resolved.HTTP2Options.IdleTimeout != 0 {
					t.Fatalf("idle_timeout: 0 must stay 0, got %v",
						time.Duration(resolved.HTTP2Options.IdleTimeout))
				}
			},
		},
		{
			name:   "absent fields still take the profile",
			config: `{"version":3,"server_profile":"jiejie-balanced-1g"}`,
			checkResolved: func(t *testing.T, resolved ServerResourceOptions) {
				if time.Duration(resolved.HTTP2Options.IdleTimeout) != 60*time.Second {
					t.Fatalf("an absent idle_timeout must take the profile's 60s, got %v",
						time.Duration(resolved.HTTP2Options.IdleTimeout))
				}
				if resolved.HTTP2Options.MaxConcurrentStreams != 256 {
					t.Fatalf("an absent max_concurrent_streams must take the profile's 256, got %d",
						resolved.HTTP2Options.MaxConcurrentStreams)
				}
			},
		},
		{
			name:   "explicit non-zero still wins",
			config: `{"version":3,"server_profile":"jiejie-balanced-1g","max_concurrent_streams":7,"idle_timeout":"5s"}`,
			checkResolved: func(t *testing.T, resolved ServerResourceOptions) {
				if resolved.HTTP2Options.MaxConcurrentStreams != 7 {
					t.Fatalf("explicit 7 must win, got %d", resolved.HTTP2Options.MaxConcurrentStreams)
				}
				if time.Duration(resolved.HTTP2Options.IdleTimeout) != 5*time.Second {
					t.Fatalf("explicit 5s must win, got %v", time.Duration(resolved.HTTP2Options.IdleTimeout))
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var inbound HTTPInboundOptions
			err := json.UnmarshalContext(context.Background(), []byte(testCase.config), &inbound)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			resolved, err := inbound.ResolveServerResources()
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			testCase.checkResolved(t, resolved)
		})
	}
}

// TestProfilePresenceTrackingIsPopulated covers the presence set itself.
func TestProfilePresenceTrackingIsPopulated(t *testing.T) {
	var inbound HTTPInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"version": 3,
		"keep_alive_period": "0s",
		"max_header_bytes": 8192
	}`), &inbound)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !inbound.Present.KeepAlivePeriod {
		t.Fatal("an explicit keep_alive_period must be recorded as present")
	}
	if !inbound.Present.MaxHeaderBytes {
		t.Fatal("an explicit max_header_bytes must be recorded as present")
	}
	if inbound.Present.IdleTimeout {
		t.Fatal("an absent idle_timeout must NOT be recorded as present")
	}
	if inbound.Present.MaxConcurrentStreams {
		t.Fatal("an absent max_concurrent_streams must NOT be recorded as present")
	}

	// An explicit max_header_bytes wins over the profile.
	inbound.ServerProfile = HTTPServerProfileNameJiejieBalanced1G
	resolved, err := inbound.ResolveServerResources()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.MaxHeaderBytes != 8192 {
		t.Fatalf("an explicit max_header_bytes must win over the profile's 64 KiB, got %d",
			resolved.MaxHeaderBytes)
	}
}
