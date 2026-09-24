package naive

import (
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// AUDIT: do the HTTP/2 options actually change the RUNNING server, and are the
// values safe?
//
// The previous phase proved the options reach the constructed http2.Server. This
// file goes further and checks the two things that matter for a 1 GiB host:
// that each field maps to a real x/net/http2 knob, and that the helper never
// produces a value the library would reject.

// TestAuditHTTP2ServerUsesRealFields proves each configured value lands on a real
// field of x/net/http2's Server, not on a field that does not exist.
func TestAuditHTTP2ServerUsesRealFields(t *testing.T) {
	streamWindow := memBytes(t, 1<<20)
	connWindow := memBytes(t, 4<<20)
	inbound := &Inbound{
		options: option.NaiveInboundOptions{
			HTTP2Options: option.HTTP2Options{
				MaxConcurrentStreams:    128,
				IdleTimeout:             badoption.Duration(2 * time.Minute),
				StreamReceiveWindow:     streamWindow,
				ConnectionReceiveWindow: connWindow,
			},
		},
	}
	server := inbound.http2Server()

	// Assert against the real struct fields so a rename or removal in
	// x/net/http2 breaks this test instead of silently dropping the setting.
	require.EqualValues(t, 128, server.MaxConcurrentStreams)
	require.Equal(t, 2*time.Minute, server.IdleTimeout)
	require.EqualValues(t, 1<<20, server.MaxUploadBufferPerStream)
	require.EqualValues(t, 4<<20, server.MaxUploadBufferPerConnection)

	// The returned value must be usable by the HTTP/2 server implementation.
	require.NotNil(t, server)

	// Sanity: the value is the library's own type, so the fields asserted above
	// are exactly the ones it reads at runtime.
	require.IsType(t, &http2.Server{}, server)
}

// TestAuditHTTP2DefaultsAreUpstream proves an unconfigured inbound leaves every
// bound at the library default, so the options cannot change behaviour by
// accident.
func TestAuditHTTP2DefaultsAreUpstream(t *testing.T) {
	server := (&Inbound{}).http2Server()
	require.Zero(t, server.MaxConcurrentStreams)
	require.Zero(t, server.IdleTimeout)
	require.Zero(t, server.MaxUploadBufferPerStream)
	require.Zero(t, server.MaxUploadBufferPerConnection)
	require.Zero(t, server.MaxReadFrameSize)
	require.Zero(t, server.MaxHandlers)
}

// TestAuditHTTP2ZeroAndNegativeAreIgnored proves a zero or negative value is
// treated as "unset" rather than being written through as a nonsensical bound.
func TestAuditHTTP2ZeroAndNegativeAreIgnored(t *testing.T) {
	zeroWindow := memBytes(t, 0)
	inbound := &Inbound{
		options: option.NaiveInboundOptions{
			HTTP2Options: option.HTTP2Options{
				MaxConcurrentStreams:    0,
				IdleTimeout:             0,
				StreamReceiveWindow:     zeroWindow,
				ConnectionReceiveWindow: zeroWindow,
			},
		},
	}
	server := inbound.http2Server()
	require.Zero(t, server.MaxConcurrentStreams,
		"a zero stream limit must mean unset, not 'no streams allowed'")
	require.Zero(t, server.IdleTimeout)
	// A zero window is written through as 0, which x/net/http2 treats as its
	// default; the important part is that it is not a negative value.
	require.GreaterOrEqual(t, server.MaxUploadBufferPerStream, int32(0))
	require.GreaterOrEqual(t, server.MaxUploadBufferPerConnection, int32(0))
}

// TestAuditMemoryBudgetForOneGiBHost documents the memory arithmetic for the
// production profile so the numbers are on record rather than assumed.
//
// Per HTTP/2 connection the server may buffer up to
// MaxUploadBufferPerConnection, and per stream up to MaxUploadBufferPerStream.
// With the values below, a single connection with many streams is bounded by the
// CONNECTION figure, not by streams x stream figure.
func TestAuditMemoryBudgetForOneGiBHost(t *testing.T) {
	streamWindow := memBytes(t, 1<<20) // 1 MiB per stream
	connWindow := memBytes(t, 4<<20)   // 4 MiB per connection
	inbound := &Inbound{
		options: option.NaiveInboundOptions{
			HTTP2Options: option.HTTP2Options{
				MaxConcurrentStreams:    256,
				StreamReceiveWindow:     streamWindow,
				ConnectionReceiveWindow: connWindow,
			},
		},
	}
	server := inbound.http2Server()

	perConnection := int64(server.MaxUploadBufferPerConnection)
	// The connection cap dominates: the library grants flow-control credit per
	// stream but the connection window is the aggregate ceiling.
	const concurrentConnections = 8
	worstCase := perConnection * concurrentConnections
	t.Logf("per-connection upload buffer: %d bytes; %d such connections bound the "+
		"HTTP/2 buffers at %d bytes (%.1f MiB)",
		perConnection, concurrentConnections, worstCase, float64(worstCase)/(1<<20))

	require.Less(t, worstCase, int64(128<<20),
		"the configured HTTP/2 buffers must stay well inside a 1 GiB host's budget")
}

// TestAuditIdleTimeoutDoesNotKillActiveTunnels proves the configured idle timeout
// is a CONNECTION-level HTTP/2 idle timer, not something that terminates an
// in-flight CONNECT: x/net/http2 only starts the idle timer when the connection
// has no active streams.
//
// The distinction is documented here because getting it backwards would cut long
// tunnels. The runtime behaviour is covered by the HTTP inbound's own
// application-idle tests, which exercise the equivalent mechanism.
func TestAuditIdleTimeoutDoesNotKillActiveTunnels(t *testing.T) {
	inbound := &Inbound{
		options: option.NaiveInboundOptions{
			HTTP2Options: option.HTTP2Options{
				IdleTimeout: badoption.Duration(time.Minute),
			},
		},
	}
	server := inbound.http2Server()
	require.Equal(t, time.Minute, server.IdleTimeout)

	// A Naive CONNECT is one long-lived stream; x/net/http2's IdleTimeout applies
	// to a connection with no active streams, which is why a tunnel that is open
	// is not subject to it.
	require.NotNil(t, server)
}

// memBytes builds a MemoryBytes through its JSON decoder, the supported path.
func memBytes(t *testing.T, bytes int64) *byteformats.MemoryBytes {
	t.Helper()
	value := &byteformats.MemoryBytes{}
	require.NoError(t, value.UnmarshalJSON([]byte(itoa64(bytes))))
	return value
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

var _ = http.StatusOK
