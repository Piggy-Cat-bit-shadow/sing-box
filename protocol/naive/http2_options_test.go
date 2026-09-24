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
