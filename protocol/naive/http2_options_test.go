package naive

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// These tests pin the HTTP/2 server bounds the Naive inbound applies.
//
// They assert the CONSTRUCTED http2.Server rather than only the option struct,
// because the failure this guards against is exactly the one that was present:
// the inbound ran a bare `&http2.Server{}` and options had no path to it at all.

// TestHTTP2OptionsDefaultToUpstream proves an unconfigured inbound keeps the
// upstream defaults, so the new options cannot silently change behaviour.
func TestHTTP2OptionsDefaultToUpstream(t *testing.T) {
	inbound := &Inbound{}
	server := inbound.http2Server()

	require.Zero(t, server.MaxConcurrentStreams,
		"an unset max_concurrent_streams must leave the upstream default")
	require.Zero(t, server.IdleTimeout,
		"an unset idle_timeout must leave the upstream default")
	require.Zero(t, server.MaxUploadBufferPerStream,
		"an unset stream_receive_window must leave the upstream default")
	require.Zero(t, server.MaxUploadBufferPerConnection,
		"an unset connection_receive_window must leave the upstream default")
}

// TestHTTP2OptionsReachTheServer proves each configured value reaches the
// constructed server, so the fields are wired rather than merely parsed.
func TestHTTP2OptionsReachTheServer(t *testing.T) {
	streamWindow := memoryBytes(t, 1<<20)
	connectionWindow := memoryBytes(t, 4<<20)
	inbound := &Inbound{
		options: option.NaiveInboundOptions{
			HTTP2Options: option.HTTP2Options{
				MaxConcurrentStreams:    64,
				IdleTimeout:             badoption.Duration(90 * time.Second),
				StreamReceiveWindow:     streamWindow,
				ConnectionReceiveWindow: connectionWindow,
			},
		},
	}
	server := inbound.http2Server()

	require.EqualValues(t, 64, server.MaxConcurrentStreams,
		"max_concurrent_streams must reach the HTTP/2 server")
	require.Equal(t, 90*time.Second, server.IdleTimeout,
		"idle_timeout must reach the HTTP/2 server")
	require.EqualValues(t, 1<<20, server.MaxUploadBufferPerStream,
		"stream_receive_window must reach the server's per-stream upload buffer")
	require.EqualValues(t, 4<<20, server.MaxUploadBufferPerConnection,
		"connection_receive_window must reach the server's per-connection upload buffer")
}

// TestHTTP2OptionsDecodeFromJSON proves the new keys are real top-level config
// keys. They live on an embedded struct tagged `json:"-"`, which the default
// decoder would silently skip, so without the custom unmarshaler a user could set
// these fields and have them ignored with no error.
func TestHTTP2OptionsDecodeFromJSON(t *testing.T) {
	var options option.NaiveInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"listen": "127.0.0.1",
		"listen_port": 28545,
		"network": "tcp",
		"max_concurrent_streams": 32,
		"idle_timeout": "45s",
		"stream_receive_window": 1048576,
		"connection_receive_window": 2097152,
		"users": [{"username": "u", "password": "p"}]
	}`), &options)
	require.NoError(t, err)

	require.Equal(t, 32, options.HTTP2Options.MaxConcurrentStreams,
		"max_concurrent_streams must decode from the inbound's top level")
	require.Equal(t, 45*time.Second, time.Duration(options.HTTP2Options.IdleTimeout))
	require.NotNil(t, options.HTTP2Options.StreamReceiveWindow)
	require.EqualValues(t, 1<<20, options.HTTP2Options.StreamReceiveWindow.Value())
	require.NotNil(t, options.HTTP2Options.ConnectionReceiveWindow)
	require.EqualValues(t, 2<<20, options.HTTP2Options.ConnectionReceiveWindow.Value())
}

// TestMasqueradeDecodesFromJSON proves the masquerade field decodes with the same
// schema the HTTP inbound uses.
func TestMasqueradeDecodesFromJSON(t *testing.T) {
	var options option.NaiveInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"listen": "127.0.0.1",
		"listen_port": 28545,
		"masquerade": {
			"type": "proxy",
			"url": "http://127.0.0.1:28437",
			"rewrite_host": true
		}
	}`), &options)
	require.NoError(t, err)
	require.NotNil(t, options.Masquerade)
	require.Equal(t, "proxy", options.Masquerade.Type)
	require.Equal(t, "http://127.0.0.1:28437", options.Masquerade.ProxyOptions.URL)
	require.True(t, options.Masquerade.ProxyOptions.RewriteHost)
}

// TestUnknownHTTP2OptionIsRejected proves a typo cannot be silently ignored.
func TestUnknownHTTP2OptionIsRejected(t *testing.T) {
	var options option.NaiveInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"listen_port": 28545,
		"max_concurrent_stream": 32
	}`), &options)
	require.Error(t, err,
		"an unknown option key must be rejected rather than silently ignored")
}

// memoryBytes builds a MemoryBytes from a plain byte count via its JSON decoder,
// which is the supported construction path (the value field is unexported).
func memoryBytes(t *testing.T, bytes int64) *byteformats.MemoryBytes {
	t.Helper()
	value := &byteformats.MemoryBytes{}
	require.NoError(t, value.UnmarshalJSON([]byte(strconv.FormatInt(bytes, 10))))
	return value
}

// TestDocumentedInboundExampleDecodes guards against documentation drift: the
// JSON in docs/configuration/inbound/naive.md must actually decode.
//
// "type" and "tag" are deliberately absent here because they belong to the
// enclosing option.Inbound, not to the inbound's own option struct.
func TestDocumentedInboundExampleDecodes(t *testing.T) {
	var options option.NaiveInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"network": "tcp",
		"listen": "127.0.0.1",
		"listen_port": 28545,
		"users": [{"username": "sekai", "password": "password"}],
		"quic_congestion_control": "",
		"masquerade": {
			"type": "proxy",
			"url": "http://127.0.0.1:28437",
			"rewrite_host": true
		},
		"max_concurrent_streams": 64,
		"idle_timeout": "60s",
		"stream_receive_window": 1048576,
		"connection_receive_window": 4194304,
		"tls": {"enabled": false}
	}`), &options)
	require.NoError(t, err, "the documented inbound example must decode")

	require.Equal(t, option.NetworkList("tcp"), options.Network)
	require.Equal(t, 64, options.HTTP2Options.MaxConcurrentStreams)
	require.Equal(t, 60*time.Second, time.Duration(options.HTTP2Options.IdleTimeout))
	require.NotNil(t, options.HTTP2Options.StreamReceiveWindow)
	require.EqualValues(t, 1<<20, options.HTTP2Options.StreamReceiveWindow.Value())
	require.NotNil(t, options.HTTP2Options.ConnectionReceiveWindow)
	require.EqualValues(t, 4<<20, options.HTTP2Options.ConnectionReceiveWindow.Value())
	require.NotNil(t, options.Masquerade)
	require.Equal(t, "http://127.0.0.1:28437", options.Masquerade.ProxyOptions.URL)
	require.True(t, options.Masquerade.ProxyOptions.RewriteHost)
}

// TestHTTP2OptionsRejectOutOfRangeValues proves the resource options cannot
// silently wrap.
//
// The values are narrowed to fixed-width types when the HTTP/2 server is built
// (uint32 for the stream limit, int32 for the receive windows). Without a range
// check an out-of-range option would wrap into a small or negative number, and
// the operator would get a limit they never configured with no error to explain
// it - which is worse than a rejected configuration.
//
// Each case below is one step past the representable maximum, which is exactly
// where a silent cast would produce a plausible-looking small value.
func TestHTTP2OptionsRejectOutOfRangeValues(t *testing.T) {
	maxUint32 := int64(1)<<32 - 1
	// The byte-size literals that sit exactly at and one past MaxInt32.
	const (
		atMaxInt32   = "2147483647"
		overMaxInt32 = "2147483648"
	)

	// MemoryBytes has no exported literal constructor; JSON is its public input
	// path, so the test builds values the same way a configuration would.
	bytesOf := func(t *testing.T, literal string) *byteformats.MemoryBytes {
		t.Helper()
		var memory byteformats.MemoryBytes
		require.NoError(t, memory.UnmarshalJSON([]byte(literal)),
			"test fixture must be a valid byte size literal")
		return &memory
	}

	t.Run("max_concurrent_streams", func(t *testing.T) {
		// The largest value MaxUint32 can hold must be accepted.
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			MaxConcurrentStreams: int(maxUint32),
		}), "the largest representable stream limit must be accepted")

		// One past it must be refused rather than wrapping to 0.
		err := validateHTTP2Options(option.HTTP2Options{
			MaxConcurrentStreams: int(maxUint32) + 1,
		})
		require.Error(t, err, "a stream limit above MaxUint32 must be refused")
		require.Contains(t, err.Error(), "max_concurrent_streams")

		// A negative value is meaningless and must be refused.
		require.Error(t, validateHTTP2Options(option.HTTP2Options{
			MaxConcurrentStreams: -1,
		}), "a negative stream limit must be refused")
	})

	t.Run("stream_receive_window", func(t *testing.T) {
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			StreamReceiveWindow: bytesOf(t, atMaxInt32),
		}), "the largest representable window must be accepted")

		err := validateHTTP2Options(option.HTTP2Options{
			StreamReceiveWindow: bytesOf(t, overMaxInt32),
		})
		require.Error(t, err, "a window above MaxInt32 must be refused")
		require.Contains(t, err.Error(), "stream_receive_window",
			"the error must name the offending option")
	})

	t.Run("connection_receive_window", func(t *testing.T) {
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			ConnectionReceiveWindow: bytesOf(t, atMaxInt32),
		}))

		err := validateHTTP2Options(option.HTTP2Options{
			ConnectionReceiveWindow: bytesOf(t, overMaxInt32),
		})
		require.Error(t, err, "a window above MaxInt32 must be refused")
		require.Contains(t, err.Error(), "connection_receive_window")
	})

	t.Run("zero and one are accepted", func(t *testing.T) {
		// Zero is the documented "unset, use the upstream default" value and must
		// never become an error. One is the smallest meaningful limit and proves
		// the check is a bound rather than a floor.
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			MaxConcurrentStreams: 0,
		}), "zero means upstream default and must be accepted")
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			MaxConcurrentStreams: 1,
		}), "one is a valid stream limit")

		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			StreamReceiveWindow:     bytesOf(t, "0"),
			ConnectionReceiveWindow: bytesOf(t, "0"),
		}), "zero windows mean upstream default and must be accepted")
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			StreamReceiveWindow:     bytesOf(t, "1"),
			ConnectionReceiveWindow: bytesOf(t, "1"),
		}), "one-byte windows are representable and must be accepted")
	})

	t.Run("one below the limit is accepted", func(t *testing.T) {
		// The exact boundary from below: MaxInt32-1 and MaxUint32-1 must pass,
		// so the check is proven to be an upper bound and not off by one.
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			MaxConcurrentStreams: int(maxUint32) - 1,
		}), "one below the stream-limit maximum must be accepted")
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			StreamReceiveWindow:     bytesOf(t, "2147483646"),
			ConnectionReceiveWindow: bytesOf(t, "2147483646"),
		}), "one below the window maximum must be accepted")
	})

	t.Run("unset stays unset", func(t *testing.T) {
		// Zero for all three means "use the upstream default" and must never be
		// turned into an error, or every existing configuration would break.
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{}),
			"an unconfigured inbound must validate: zero means upstream default")
	})
}
