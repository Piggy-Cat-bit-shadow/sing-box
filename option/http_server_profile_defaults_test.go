package option

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This file pins the profile against the ACTUAL defaults of the pinned quic-go,
// read out of its source rather than assumed from documentation.
//
// Measured from quic-go v0.61.0-sing-box-mod.7 internal/protocol/params.go and
// config.go:
//
//	DefaultInitialMaxStreamData                  2 MiB
//	DefaultInitialMaxData                        1.5 * 2 MiB
//	DefaultMaxReceiveStreamFlowControlWindow     6 MiB
//	DefaultMaxReceiveConnectionFlowControlWindow 15 MiB
//	DefaultMaxIncomingStreams                    100
//	KeepAlivePeriod                              0 (disabled)
//
// and config.go resolves a zero field to those values, so leaving a field unset
// means "library default" rather than "unlimited".

const (
	measuredQuicDefaultInitialStreamData = 2 << 20
	measuredQuicDefaultMaxStreamWindow   = 6 << 20
	measuredQuicDefaultMaxConnWindow     = 15 << 20
	measuredQuicDefaultMaxIncomingStream = 100
)

// TestJiejieProfileLeavesReceiveWindowsToTheLibrary is the memory-safety guard.
//
// common/httpclient.NewQUICConfig assigns a configured stream_receive_window to
// BOTH InitialStreamReceiveWindow and MaxStreamReceiveWindow. A profile value
// would therefore RAISE the initial window above the library default, which is
// the opposite of a memory-conservative profile on a ~1 GiB host. The correct
// behaviour is to leave both unset and let the library manage them.
func TestJiejieProfileLeavesReceiveWindowsToTheLibrary(t *testing.T) {
	profile := httpserverProfiles[HTTPServerProfileNameJiejieBalanced1G]
	require.Zero(t, profile.StreamReceiveWindow,
		"a stream receive window here would raise the initial window above the library default of %d bytes",
		measuredQuicDefaultInitialStreamData)
	require.Zero(t, profile.ConnectionReceiveWindow,
		"a connection receive window here would raise the initial window above the library default")
	require.Zero(t, profile.KeepAlivePeriod,
		"keep-alive must stay disabled: pinging idle connections keeps their state alive on a 1 GiB host")
}

// TestJiejieProfileStreamLimitIsConservativeForTheMASQUEPath documents the one
// place the profile genuinely tightens a limit, and against WHICH baseline.
//
// This is subtle enough that it is worth stating exactly, because comparing
// against the wrong baseline gives the wrong answer:
//
//   - quic-go's own zero-value default is 100 incoming streams;
//   - but the MASQUE HTTP/3 listener in transport/http/server_h3.go replaces a
//     zero with 1<<60, i.e. effectively unlimited, because an L4 proxy tunnel
//     server must not cap concurrent CONNECT streams at 100;
//   - so on the path that actually ships, profile 256 LOWERS the limit from
//     effectively unlimited to a bounded 256.
//
// Against the raw library default the profile would look like a 2.5x increase.
// Against the effective MASQUE baseline it is a reduction. The test asserts the
// latter, which is the behaviour that reaches production, and it records the
// former so a reader is not misled.
func TestJiejieProfileStreamLimitIsConservativeForTheMASQUEPath(t *testing.T) {
	const masqueEffectiveUnlimited = 1 << 60
	profile := httpserverProfiles[HTTPServerProfileNameJiejieBalanced1G]
	require.Equal(t, 256, profile.MaxConcurrentStreams)
	require.Less(t, int64(profile.MaxConcurrentStreams), int64(masqueEffectiveUnlimited),
		"the profile must lower the MASQUE stream limit from effectively unlimited")
	require.Greater(t, profile.MaxConcurrentStreams, measuredQuicDefaultMaxIncomingStream,
		"documented: 256 IS above quic-go's raw zero-value default of %d; the relevant baseline for the MASQUE listener is the 1<<60 replacement in server_h3.go",
		measuredQuicDefaultMaxIncomingStream)
}

// TestJiejieProfileResolvesOntoTheInboundOptions proves the profile reaches the
// EFFECTIVE option set rather than only the profile map.
//
// A value receiver here is exactly the bug this fork fixed once already: the
// profile was applied to a copy, so the runtime object never saw it.
func TestJiejieProfileResolvesOntoTheInboundOptions(t *testing.T) {
	options := &HTTPInboundOptions{
		ServerProfile: HTTPServerProfileNameJiejieBalanced1G,
	}
	resolved, err := options.ResolveServerResources()
	require.NoError(t, err)
	require.Equal(t, 64<<10, resolved.MaxHeaderBytes,
		"max_header_bytes must reach the resolved options")
	require.Equal(t, 256, resolved.HTTP3Options.HTTP2Options.MaxConcurrentStreams,
		"max_concurrent_streams must reach the resolved QUIC options")
	require.Equal(t, 60*time.Second, time.Duration(resolved.HTTP3Options.HTTP2Options.IdleTimeout),
		"idle_timeout must reach the resolved QUIC options")
	require.Zero(t, resolved.HTTP3Options.HTTP2Options.StreamReceiveWindow,
		"the receive window must stay unset")

	// With no profile the resolved values must remain the upstream defaults.
	plain := &HTTPInboundOptions{}
	plainResolved, err := plain.ResolveServerResources()
	require.NoError(t, err)
	require.Zero(t, plainResolved.HTTP3Options.HTTP2Options.MaxConcurrentStreams,
		"without a profile the stream limit must stay unset, so server_h3.go can apply its 1<<60 default")
}

// TestJiejieProfileExplicitZeroWins proves an explicitly written zero is not
// overwritten by the profile.
//
// These fields are plain values, not pointers, so an explicit
// `keep_alive_period: 0` and an omitted key both decode to 0. The documented
// contract is that explicit fields always win, so the presence set must be
// consulted rather than the value.
func TestJiejieProfileExplicitZeroWins(t *testing.T) {
	profile := httpserverProfiles[HTTPServerProfileNameJiejieBalanced1G]
	target := HTTP2Options{}
	presence := ResourceFieldPresence{
		MaxConcurrentStreams: true,
		IdleTimeout:          true,
	}
	profile.ApplyToHTTP2WithPresence(&target, presence)
	require.Zero(t, target.MaxConcurrentStreams,
		"an explicit max_concurrent_streams of 0 must not be replaced by the profile")
	require.Zero(t, target.IdleTimeout,
		"an explicit idle_timeout of 0 must not be replaced by the profile")
}
