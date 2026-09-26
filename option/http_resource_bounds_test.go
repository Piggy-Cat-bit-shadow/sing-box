package option

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// Option values that are narrowed to fixed-width types downstream must be range
// checked, or they wrap or clamp silently.
//
// Every case here corresponds to a real conversion in the HTTP/MASQUE data path:
//
//	MaxConcurrentStreams -> uint32   (MaxUint32)
//	StreamReceiveWindow  -> int32    (MaxInt32)
//	ConnectionReceiveWindow -> int32 (MaxInt32)
//	InitialPacketSize    -> uint16   (MaxUint16)
//
// The receive windows need extra care: MemoryBytes.UnmarshalJSON parses a bare
// number into an int64 and stores it as uint64, so "-1" becomes
// 18446744073709551615 and the sign is gone before sing-box sees it. The old
// downstream min(v, MaxInt32) then turned that into about 2 GiB.

// memoryBytesFrom parses a byte-size literal the way a configuration would.
func memoryBytesFrom(t *testing.T, literal string) *byteformats.MemoryBytes {
	t.Helper()
	var memory byteformats.MemoryBytes
	require.NoError(t, memory.UnmarshalJSON([]byte(literal)),
		"test fixture %q must be a valid byte-size literal", literal)
	return &memory
}

func resolveWith(t *testing.T, http2 HTTP2Options, quic QUICOptions) error {
	t.Helper()
	options := HTTPInboundOptions{}
	options.HTTP2Options = http2
	options.HTTP3Options = quic
	_, err := options.ResolveServerResources()
	return err
}

// TestHTTP2StreamLimitBounds covers 0, 1, MaxUint32 and MaxUint32+1.
func TestHTTP2StreamLimitBounds(t *testing.T) {
	t.Run("0 and 1 are accepted", func(t *testing.T) {
		require.NoError(t, resolveWith(t, HTTP2Options{MaxConcurrentStreams: 0}, QUICOptions{}))
		require.NoError(t, resolveWith(t, HTTP2Options{MaxConcurrentStreams: 1}, QUICOptions{}))
	})

	t.Run("MaxUint32 is accepted", func(t *testing.T) {
		require.NoError(t, resolveWith(t,
			HTTP2Options{MaxConcurrentStreams: int(^uint32(0))}, QUICOptions{}),
			"the largest representable stream limit must be accepted")
	})

	t.Run("MaxUint32+1 is rejected", func(t *testing.T) {
		err := resolveWith(t,
			HTTP2Options{MaxConcurrentStreams: int(^uint32(0)) + 1}, QUICOptions{})
		require.Error(t, err, "a stream limit above MaxUint32 must be refused rather than wrap")
		require.Contains(t, err.Error(), "max_concurrent_streams")
	})

	t.Run("negative is rejected", func(t *testing.T) {
		err := resolveWith(t, HTTP2Options{MaxConcurrentStreams: -1}, QUICOptions{})
		require.Error(t, err, "a negative stream limit is meaningless and must be refused")
		require.Contains(t, err.Error(), "max_concurrent_streams")
	})
}

// TestHTTP2ReceiveWindowBounds covers both windows at the boundary, and the
// negative value that parses into a huge unsigned number.
func TestHTTP2ReceiveWindowBounds(t *testing.T) {
	for _, window := range []struct {
		name string
		set  func(*HTTP2Options, *byteformats.MemoryBytes)
	}{
		{"stream_receive_window", func(o *HTTP2Options, v *byteformats.MemoryBytes) {
			o.StreamReceiveWindow = v
		}},
		{"connection_receive_window", func(o *HTTP2Options, v *byteformats.MemoryBytes) {
			o.ConnectionReceiveWindow = v
		}},
	} {
		t.Run(window.name+" at MaxInt32 is accepted", func(t *testing.T) {
			var http2 HTTP2Options
			window.set(&http2, memoryBytesFrom(t, "2147483647"))
			require.NoError(t, resolveWith(t, http2, QUICOptions{}))
		})

		t.Run(window.name+" above MaxInt32 is rejected", func(t *testing.T) {
			var http2 HTTP2Options
			window.set(&http2, memoryBytesFrom(t, "2147483648"))
			err := resolveWith(t, http2, QUICOptions{})
			require.Error(t, err, "a window above MaxInt32 must be refused rather than clamp")
			require.Contains(t, err.Error(), window.name)
		})

		t.Run(window.name+" negative is rejected", func(t *testing.T) {
			// This is the case the task called out. "-1" parses SUCCESSFULLY into
			// uint64 max, so the rejection has to come from the upper bound, and
			// the error has to be produced rather than a ~2 GiB window.
			var http2 HTTP2Options
			window.set(&http2, memoryBytesFrom(t, "-1"))
			err := resolveWith(t, http2, QUICOptions{})
			require.Error(t, err,
				"a negative window parses to a huge unsigned number and must be "+
					"refused; clamping it to about 2 GiB is exactly the silent "+
					"misbehaviour this guards against")
			require.Contains(t, err.Error(), window.name)
		})
	}
}

// TestInitialPacketSizeBounds covers the uint16 narrowing.
func TestInitialPacketSizeBounds(t *testing.T) {
	t.Run("0 means unset", func(t *testing.T) {
		require.NoError(t, resolveWith(t, HTTP2Options{}, QUICOptions{InitialPacketSize: 0}))
	})

	t.Run("a normal value is accepted", func(t *testing.T) {
		require.NoError(t, resolveWith(t, HTTP2Options{}, QUICOptions{InitialPacketSize: 1200}))
	})

	t.Run("MaxUint16 is accepted", func(t *testing.T) {
		require.NoError(t, resolveWith(t, HTTP2Options{}, QUICOptions{InitialPacketSize: 65535}))
	})

	t.Run("above MaxUint16 is rejected", func(t *testing.T) {
		// 70000 would WRAP to 4464 in a uint16 cast, silently producing a packet
		// size nobody asked for.
		err := resolveWith(t, HTTP2Options{}, QUICOptions{InitialPacketSize: 70000})
		require.Error(t, err, "70000 must be refused rather than wrap to 4464")
		require.Contains(t, err.Error(), "initial_packet_size")
	})

	t.Run("negative is rejected", func(t *testing.T) {
		err := resolveWith(t, HTTP2Options{}, QUICOptions{InitialPacketSize: -1})
		require.Error(t, err)
		require.Contains(t, err.Error(), "initial_packet_size")
	})
}

// TestNegativeDurationsAreRejected proves an explicit negative duration is a
// mistake rather than a request for the default.
func TestNegativeDurationsAreRejected(t *testing.T) {
	for _, testCase := range []struct {
		name string
		set  func(*HTTP2Options)
	}{
		{"idle_timeout", func(o *HTTP2Options) { o.IdleTimeout = badoption.Duration(-1) }},
		{"keep_alive_period", func(o *HTTP2Options) { o.KeepAlivePeriod = badoption.Duration(-1) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var http2 HTTP2Options
			testCase.set(&http2)
			err := resolveWith(t, http2, QUICOptions{})
			require.Error(t, err, "an explicit negative duration must be refused")
			require.Contains(t, err.Error(), testCase.name)
		})
	}

	t.Run("zero still means unset", func(t *testing.T) {
		require.NoError(t, resolveWith(t, HTTP2Options{
			IdleTimeout:     badoption.Duration(0),
			KeepAlivePeriod: badoption.Duration(0),
		}, QUICOptions{}))
	})
}

// TestMaxHeaderBytesContract pins the documented rule.
//
//	absent                 -> profile, then the upstream default
//	explicit positive      -> used as given
//	explicit non-positive  -> configuration error
//
// The previous code replaced a non-positive explicit value with the default,
// which contradicted the contract that an explicit value always wins: the
// operator wrote something invalid and silently received a different limit.
func TestMaxHeaderBytesContract(t *testing.T) {
	t.Run("absent falls back to the upstream default", func(t *testing.T) {
		resolved, err := HTTPInboundOptions{}.ResolveServerResources()
		require.NoError(t, err)
		require.Equal(t, UpstreamMaxHeaderBytes, resolved.MaxHeaderBytes)
	})

	t.Run("an explicit positive value is used", func(t *testing.T) {
		options := decodeInboundOptions(t, `{"max_header_bytes": 32768}`)
		resolved, err := options.ResolveServerResources()
		require.NoError(t, err)
		require.Equal(t, 32768, resolved.MaxHeaderBytes,
			"an explicit value must be used as given")
	})

	t.Run("a negative value is an error", func(t *testing.T) {
		// A NEGATIVE value is refused. Zero is NOT an error: with the profile
		// mechanism removed, an unset and an explicit 0 both mean "use the upstream
		// default", which is the same convention every other numeric resource field
		// in this option set uses.
		options := decodeInboundOptions(t, `{"max_header_bytes": -1}`)
		_, err := options.ResolveServerResources()
		require.Error(t, err,
			"an explicit negative max_header_bytes must be refused rather than "+
				"silently replaced with the default")
		require.Contains(t, err.Error(), "max_header_bytes")
	})

	t.Run("zero means unset and resolves to the upstream default", func(t *testing.T) {
		options := decodeInboundOptions(t, `{"max_header_bytes": 0}`)
		resolved, err := options.ResolveServerResources()
		require.NoError(t, err)
		require.Equal(t, UpstreamMaxHeaderBytes, resolved.MaxHeaderBytes)
	})
}

// decodeInboundOptions parses an HTTP inbound option literal through the real
// decoder, so presence tracking behaves as it does for a configuration file.
func decodeInboundOptions(t *testing.T, literal string) HTTPInboundOptions {
	t.Helper()
	var options HTTPInboundOptions
	require.NoError(t, options.UnmarshalJSONContext(context.Background(), []byte(literal)),
		"test fixture %s must decode", literal)
	return options
}
