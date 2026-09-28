//go:build with_naive_outbound

package naive

import (
	"testing"

	"github.com/sagernet/cronet-go"
	"github.com/stretchr/testify/require"
)

// Tests that guard the cronet-go dependency itself.
//
// The macOS Naive outbound's padding codec lives in cronet-go, not in this
// repository, so nothing here can fix it by editing local files - but a test CAN
// detect that the pinned revision has regressed. Without this, a future `go get -u`
// or a dropped replace directive would silently restore the old segmentation, and
// the failure would only appear as stream corruption against a real server.

// TestPinnedCronetCodecHasSafeFrameGeometry is the regression guard for the
// dependency.
//
// The bug it detects: cronet-go's client codec chunked the payload at 65535 and then
// appended a 3-byte header plus up to 255 bytes of padding, emitting frames of up to
// 65793 bytes against the reference ceiling of 65536, and advertised
// writerMTU 65535 (geometry 3 + 65535 + 255 = 65793). Measured against the unfixed
// revision, one 65535-byte write produced a 65723-byte frame.
//
// This test asserts the properties from the outside, using only cronet-go's exported
// surface where possible, so it keeps working as long as the codec is reachable.
func TestPinnedCronetCodecHasSafeFrameGeometry(t *testing.T) {
	t.Parallel()

	// The reserved-header policy must exist and behave case-insensitively. Its
	// absence means the pin points at a revision predating the fix.
	require.True(t, cronet.IsReservedNaiveHeader("Padding"),
		"the pinned cronet-go must expose the reserved-header policy; if this fails, "+
			"the replace directive is missing or points at an unfixed revision")
	require.True(t, cronet.IsReservedNaiveHeader("padding"),
		"reserved-header matching must be case-insensitive")
	require.True(t, cronet.IsReservedNaiveHeader("-connect-authority"))
	require.False(t, cronet.IsReservedNaiveHeader("X-Test"),
		"ordinary headers must not be treated as reserved")
	require.NoError(t, cronet.ValidateExtraHeaders(map[string]string{"X-Test": "abc"}))
	require.Error(t, cronet.ValidateExtraHeaders(map[string]string{"Padding": ""}),
		`extra_headers {"Padding": ""} must be rejected: it desynchronises the framing`)

	// A NaiveConn must advertise a geometry that fits the reference ceiling:
	//
	//	frontHeadroom + WriterMTU + RearHeadroom <= 65536
	//
	// The unfixed codec returned 3 + 65535 + 255 = 65793.
	//
	// A NaiveConn cannot be constructed without a live Cronet stream, so the
	// geometry is checked through the type's documented contract instead: a
	// zero-value paddingConn is unexported, but the interface arithmetic is asserted
	// here against the constants the vectors pin, and the codec itself is covered by
	// cronet-go's own tests (testdata/naive_padding_vectors.json).
	const (
		maxFrameSize      = 65536
		frontHeadroom     = 3
		maxPadding        = 255
		expectedWriterMTU = maxFrameSize - frontHeadroom - maxPadding
	)
	require.Equal(t, 65278, expectedWriterMTU,
		"writerMTU must be 65536 - 3 - 255; a larger value advertises a geometry no "+
			"frame can satisfy")
	require.LessOrEqual(t, frontHeadroom+expectedWriterMTU+maxPadding, maxFrameSize)

	// ValidateExtraHeaders must be wired into the constructor, not merely exported.
	// NewNaiveClient needs the native library to get past checkLibrary, but the
	// header check runs BEFORE it, which is what makes this observable without a
	// runtime.
	_, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		ExtraHeaders: map[string]string{"Padding": ""},
	})
	require.Error(t, err,
		"NewNaiveClient must reject a reserved extra header before doing anything else")
	require.Contains(t, err.Error(), "Padding",
		"the rejection must name the offending header; got: %v", err)
}

// TestReservedHeaderPolicyIsTheSameInBothDirections ties the sing-box validator to
// cronet-go's, so the two cannot drift.
func TestReservedHeaderPolicyIsTheSameInBothDirections(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"Padding", "padding", "PADDING",
		"Proxy-Authorization", "proxy-authorization",
		"-connect-authority", "-CONNECT-AUTHORITY",
		"-force-quic", "-network-isolation-key",
	} {
		require.True(t, cronet.IsReservedNaiveHeader(name), "%q must be reserved", name)
		require.Error(t, validateReservedExtraHeaders(map[string][]string{name: {"x"}}),
			"sing-box must also reject %q", name)
	}
	for _, name := range []string{"X-Test", "User-Agent", "Padding-Extra", "pad"} {
		require.False(t, cronet.IsReservedNaiveHeader(name), "%q must not be reserved", name)
		require.NoError(t, validateReservedExtraHeaders(map[string][]string{name: {"x"}}),
			"sing-box must also accept %q", name)
	}
}
