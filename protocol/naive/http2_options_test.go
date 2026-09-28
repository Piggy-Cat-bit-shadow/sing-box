package naive

import (
	"context"
	"math"
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

		// The two windows have DIFFERENT lower bounds, because x/net/http2 applies
		// different floors to them. A one-byte STREAM window is genuinely legal
		// (MaxUploadBufferPerStream accepts [1, MaxInt32]); a one-byte CONNECTION
		// window is not (MaxUploadBufferPerConnection accepts
		// [65535, MaxInt32]) and would be silently replaced with 1 MiB.
		//
		// A previous revision of this test asserted that a one-byte window is legal
		// for BOTH, which encoded the very assumption that made the connection
		// window bug invisible.
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			StreamReceiveWindow: bytesOf(t, "1"),
		}), "a one-byte stream window is within x/net's range and must be accepted")
		require.Error(t, validateHTTP2Options(option.HTTP2Options{
			ConnectionReceiveWindow: bytesOf(t, "1"),
		}), "a one-byte connection window is below x/net's floor and must be rejected")
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

	t.Run("just above the connection floor is accepted", func(t *testing.T) {
		// The connection window's lower boundary, from above. The floor itself and
		// one above it must both pass, so the floor cannot be off by one.
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			ConnectionReceiveWindow: bytesOf(t, "65535"),
		}), "the connection window floor itself must be accepted")
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{
			ConnectionReceiveWindow: bytesOf(t, "65536"),
		}), "one above the connection window floor must be accepted")
	})

	t.Run("unset stays unset", func(t *testing.T) {
		// Zero for all three means "use the upstream default" and must never be
		// turned into an error, or every existing configuration would break.
		require.NoError(t, validateHTTP2Options(option.HTTP2Options{}),
			"an unconfigured inbound must validate: zero means upstream default")
	})
}

// productionStreamReceiveWindow / productionConnectionReceiveWindow are the
// values release/jiejie-production-topology.json pins for the naive inbound.
//
// They are repeated here as literals on purpose. The production fixture is a
// configuration file, and this package cannot import it without turning a
// deployment artifact into a test dependency; the fixture-side test
// (TestJiejieProductionNaiveFlowControlWindows in test/jiejie) reads the file and
// checks it against the same numbers. Duplicating the constant is what makes the
// two sides able to disagree loudly instead of both drifting together.
const (
	productionStreamReceiveWindow     = 8 * 1024 * 1024
	productionConnectionReceiveWindow = 32 * 1024 * 1024
)

// TestProductionReceiveWindowsReachTheServer proves the exact production
// configuration produces the intended http2.Server bounds.
//
// The window options are the one part of this change that has no visible effect
// when it is wrong: an inbound built with a mistyped window still serves traffic,
// it just stops granting upload credit early and quietly caps bulk throughput.
// So the assertion walks the whole chain the operator's JSON takes - decode, then
// validate, then construct - and checks the constructed server, not the parsed
// option, because the option is not what carries the data.
func TestProductionReceiveWindowsReachTheServer(t *testing.T) {
	// The literal a user or the fixture would actually write.
	var options option.NaiveInboundOptions
	err := json.UnmarshalContext(context.Background(), []byte(`{
		"network": "tcp",
		"listen": "127.0.0.1",
		"listen_port": 28438,
		"stream_receive_window": 8388608,
		"connection_receive_window": 33554432,
		"users": [{"username": "example", "password": "example"}]
	}`), &options)
	require.NoError(t, err, "the production window configuration must decode")

	require.NotNil(t, options.HTTP2Options.StreamReceiveWindow,
		"stream_receive_window must be parsed rather than dropped")
	require.NotNil(t, options.HTTP2Options.ConnectionReceiveWindow,
		"connection_receive_window must be parsed rather than dropped")
	require.EqualValues(t, productionStreamReceiveWindow,
		options.HTTP2Options.StreamReceiveWindow.Value(),
		"the decoded stream window must be 8 MiB")
	require.EqualValues(t, productionConnectionReceiveWindow,
		options.HTTP2Options.ConnectionReceiveWindow.Value(),
		"the decoded connection window must be 32 MiB")

	// The inbound refuses out-of-range values at construction, so a production
	// configuration that decoded but failed validation would be rejected at
	// startup instead of silently running unbounded.
	require.NoError(t, validateHTTP2Options(options.HTTP2Options),
		"the production window values must survive validation")

	inbound := &Inbound{options: options}
	server := inbound.http2Server()

	require.EqualValues(t, productionStreamReceiveWindow, server.MaxUploadBufferPerStream,
		"8 MiB must reach the HTTP/2 server's per-stream upload buffer")
	require.EqualValues(t, productionConnectionReceiveWindow, server.MaxUploadBufferPerConnection,
		"32 MiB must reach the HTTP/2 server's per-connection upload buffer")

	// A connection window below the stream window would make the stream window
	// unreachable: one stream could never spend the credit its own window
	// advertises, so the larger value would be decorative.
	require.GreaterOrEqual(t, server.MaxUploadBufferPerConnection, server.MaxUploadBufferPerStream,
		"the connection window must not be smaller than the stream window")

	// The production tuning is flow control only. It must not smuggle in a
	// stream-count or timeout change that the task did not ask for.
	require.Zero(t, server.MaxConcurrentStreams,
		"the production fixture must not pin max_concurrent_streams")
	require.Zero(t, server.IdleTimeout,
		"the production fixture must not pin idle_timeout")
}

// TestProductionReceiveWindowsExceedUpstreamDefaults records WHY the production
// values are worth pinning: they must actually be larger than what x/net/http2
// would have used, otherwise the tuning is a no-op that looks like a fix.
func TestProductionReceiveWindowsExceedUpstreamDefaults(t *testing.T) {
	// Both defaults are 1 MiB. Read from the pinned x/net/http2 source rather
	// than assumed: setConfigDefaults() in http2/config.go substitutes 1<<20 for
	// BOTH MaxUploadBufferPerStream and MaxUploadBufferPerConnection when the
	// server is left at zero (the connection case is clamped to a floor of the
	// protocol's 65535-byte initial window, which 1<<20 clears comfortably).
	//
	// The per-stream default matters most here. It is what the server advertises
	// as SETTINGS_INITIAL_WINDOW_SIZE, and therefore the hard ceiling on how much
	// unacknowledged request body a client may have in flight on ONE stream. At
	// 1 MiB that ceiling is what caps a single bulk upload through the tunnel.
	const upstreamServerDefault = 1 << 20

	require.Greater(t, int64(productionStreamReceiveWindow), int64(upstreamServerDefault),
		"the production stream window must exceed the upstream 1 MiB default, "+
			"otherwise pinning it changes nothing")
	require.Greater(t, int64(productionConnectionReceiveWindow), int64(upstreamServerDefault),
		"the production connection window must exceed the upstream 1 MiB default, "+
			"otherwise pinning it changes nothing")

	// The connection window must be a real multiple of the stream window, not
	// merely larger: it has to fund several concurrent streams at the raised
	// per-stream size, which is the whole point of raising both together.
	require.GreaterOrEqual(t, int64(productionConnectionReceiveWindow),
		int64(productionStreamReceiveWindow)*4,
		"the connection window must fund at least 4 streams at the production stream window")

	// A bulk tunnel needs the stream window to cover many frames: one
	// maximum-size padded Naive frame is 64 KiB, so 8 MiB is 128 frames of
	// credit in flight rather than the 16 the default allows.
	const paddedFrameSize = 65536
	require.GreaterOrEqual(t, int64(productionStreamReceiveWindow)/paddedFrameSize, int64(128),
		"the stream window should hold at least 128 maximum-size padded frames")
}

// memoryBytesOf parses a byte-size literal into the option type, so the tests below
// state their boundary values as the strings an operator would actually write.
func memoryBytesOf(t *testing.T, literal string) *byteformats.MemoryBytes {
	t.Helper()
	var value byteformats.MemoryBytes
	require.NoError(t, value.UnmarshalJSON([]byte(literal)),
		"parse memory literal %q", literal)
	return &value
}

// TestHTTP2WindowBoundsMatchXNet pins this fork's window validation to the bounds
// golang.org/x/net/http2 actually enforces.
//
// # Why this test exists
//
// x/net does not report an out-of-range upload buffer. It substitutes a default:
//
//	func setDefault[T](v *T, minval, maxval, defval T) {
//		if *v < minval || *v > maxval {
//			*v = defval
//		}
//	}
//
//	MaxUploadBufferPerConnection: [initialWindowSize, MaxInt32] -> default 1<<20
//	MaxUploadBufferPerStream:     [1,               MaxInt32] -> default 1<<20
//
// The two floors differ, so a single shared rule is wrong for one of them. Before
// this fix the validator only checked `<= MaxInt32`, which accepted a
// connection_receive_window of 1, 32768 or 65534 - every one of which x/net quietly
// threw away and replaced with 1 MiB. The operator's configuration was therefore not
// the configuration in effect, with no error anywhere.
//
// This test states the ranges as data so a dependency bump that changes them fails
// here, next to the module version, instead of silently drifting.
func TestHTTP2WindowBoundsMatchXNet(t *testing.T) {
	// The module version these bounds were derived from:
	//
	//	golang.org/x/net v0.57.0 http2/config.go setConfigDefaults
	//
	// RFC 7540 section 6.9.2 fixes the initial window at 65535, which is the
	// connection floor. The stream floor of 1 is x/net's own choice.
	const (
		xNetVersion       = "v0.57.0"
		connectionFloor   = 65535
		streamFloor       = 1
		xNetDefaultWindow = 1 << 20
	)

	require.Equal(t, connectionFloor, http2InitialWindowSize,
		"http2InitialWindowSize must stay at the RFC 7540 initial window size, which "+
			"is the floor x/net/http2 applies to MaxUploadBufferPerConnection "+
			"(x/net %s)", xNetVersion)
	require.Equal(t, uint64(xNetDefaultWindow), uint64(1<<20),
		"the x/net default this fork must not silently fall back to")

	// The floor the fork enforces must equal the floor x/net enforces. If a future
	// x/net lowered its connection floor, this fork would start rejecting
	// configurations the library would honour.
	var accepted option.HTTP2Options
	for _, value := range []uint64{connectionFloor} {
		accepted = option.HTTP2Options{
			ConnectionReceiveWindow: memoryBytesOf(t, strconv.FormatUint(value, 10)),
		}
		require.NoError(t, validateHTTP2Options(accepted),
			"connection_receive_window=%d is x/net's own floor and must be accepted", value)
	}

	// And the stream floor must stay permissive, because x/net accepts it.
	require.NoError(t, validateHTTP2Options(option.HTTP2Options{
		StreamReceiveWindow: memoryBytesOf(t, strconv.Itoa(streamFloor)),
	}), "stream_receive_window=%d is within x/net's range and must stay accepted",
		streamFloor)
}

// TestConnectionReceiveWindowBelowXNetFloorIsRejected is the regression test for the
// silent-substitution bug.
//
// Each rejected value below is one x/net would have silently replaced with 1 MiB:
// the operator would set 32768, the server would use 1048576, and nothing in the
// configuration path would mention it.
func TestConnectionReceiveWindowBelowXNetFloorIsRejected(t *testing.T) {
	for _, value := range []string{"1", "2", "32768", "65534"} {
		value := value
		t.Run("connection_receive_window="+value, func(t *testing.T) {
			err := validateHTTP2Options(option.HTTP2Options{
				ConnectionReceiveWindow: memoryBytesOf(t, value),
			})
			require.Error(t, err,
				"connection_receive_window=%s is below the HTTP/2 initial window, so "+
					"x/net/http2 would silently substitute 1 MiB and the configured "+
					"value would not be in effect", value)
			require.Contains(t, err.Error(), "connection_receive_window")
			// The message must name the floor so an operator can fix the config
			// without reading the HTTP/2 library.
			require.Contains(t, err.Error(), "65535",
				"the error must state the minimum accepted value")
		})
	}
}

// TestConnectionReceiveWindowAtBoundaries proves the exact boundary behaves: the
// floor is accepted and one below it is not, so the comparison cannot be off by one.
func TestConnectionReceiveWindowAtBoundaries(t *testing.T) {
	require.NoError(t, validateHTTP2Options(option.HTTP2Options{
		ConnectionReceiveWindow: memoryBytesOf(t, "65535"),
	}), "the floor itself must be accepted")

	require.Error(t, validateHTTP2Options(option.HTTP2Options{
		ConnectionReceiveWindow: memoryBytesOf(t, "65534"),
	}), "one below the floor must be rejected")

	require.NoError(t, validateHTTP2Options(option.HTTP2Options{
		ConnectionReceiveWindow: memoryBytesOf(t, strconv.Itoa(math.MaxInt32)),
	}), "MaxInt32 is x/net's upper bound and must be accepted")

	require.Error(t, validateHTTP2Options(option.HTTP2Options{
		ConnectionReceiveWindow: memoryBytesOf(t, strconv.FormatInt(math.MaxInt32+1, 10)),
	}), "one above MaxInt32 must be rejected")
}

// TestStreamReceiveWindowKeepsItsOwnLowerBound proves the connection window's floor
// was NOT copied onto the stream window.
//
// x/net accepts MaxUploadBufferPerStream = 1, so rejecting it here would refuse a
// legal configuration. Sharing one validation rule between the two windows is the
// mistake this guards against.
func TestStreamReceiveWindowKeepsItsOwnLowerBound(t *testing.T) {
	for _, value := range []string{"1", "65534", "65535"} {
		value := value
		t.Run("stream_receive_window="+value, func(t *testing.T) {
			require.NoError(t, validateHTTP2Options(option.HTTP2Options{
				StreamReceiveWindow: memoryBytesOf(t, value),
			}), "stream_receive_window=%s is within x/net's [1, MaxInt32] range for "+
				"MaxUploadBufferPerStream and must stay accepted", value)
		})
	}

	require.Error(t, validateHTTP2Options(option.HTTP2Options{
		StreamReceiveWindow: memoryBytesOf(t, strconv.FormatInt(math.MaxInt32+1, 10)),
	}), "the stream window still cannot exceed MaxInt32")
}

// TestZeroWindowMeansUnset proves an explicit 0 is treated as unset for both windows,
// so a zero cannot trip the new lower bound.
func TestZeroWindowMeansUnset(t *testing.T) {
	// An omitted field leaves the pointer nil, which is how "unset" reaches the
	// validator. `"0B"` is the explicit zero an operator can also write.
	for _, testCase := range []struct {
		name  string
		value *byteformats.MemoryBytes
	}{
		{"omitted", nil},
		{"explicit 0", memoryBytesOf(t, "0")},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			require.NoError(t, validateHTTP2Options(option.HTTP2Options{
				ConnectionReceiveWindow: testCase.value,
				StreamReceiveWindow:     testCase.value,
			}), "an unset or zero window must not be read as below the floor")
		})
	}

	inbound := &Inbound{}
	inbound.options.HTTP2Options.ConnectionReceiveWindow = memoryBytesOf(t, "0")
	inbound.options.HTTP2Options.StreamReceiveWindow = memoryBytesOf(t, "0")
	server := inbound.http2Server()
	require.Zero(t, server.MaxUploadBufferPerConnection,
		"an unset connection window must stay unset so x/net applies its own default")
	require.Zero(t, server.MaxUploadBufferPerStream,
		"an unset stream window must stay unset so x/net applies its own default")
}

// TestConnectionReceiveWindowReachesServer proves an ACCEPTED value is the value the
// server actually receives, which is the property the bug violated.
func TestConnectionReceiveWindowReachesServer(t *testing.T) {
	inbound := &Inbound{}
	inbound.options.HTTP2Options.ConnectionReceiveWindow = memoryBytesOf(t, "65535")
	require.NoError(t, validateHTTP2Options(inbound.options.HTTP2Options))

	server := inbound.http2Server()
	require.EqualValues(t, 65535, server.MaxUploadBufferPerConnection,
		"the accepted value must reach the HTTP/2 server unchanged; if the validator "+
			"and the server disagreed, x/net would silently replace it at runtime")
}
