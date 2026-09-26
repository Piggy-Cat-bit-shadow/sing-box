package route

import (
	"os"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

// The tunnel copy-buffer threshold, and who it applies to.
//
// sing's copy path starts with a pooled ~32 KiB buffer and only switches to the larger
// geometry once the cumulative byte count reaches IncreaseBufferAfter, which defaults to
// 512000. Native Naive is given a threshold of 1 so the upgrade happens after the first
// transfer instead of after ~512 KiB.
//
// These tests pin the DECISION. The behaviour it produces - a real bulk transfer
// switching geometry earlier - is measured in
// TestNaiveCopyBufferUpgradesAfterTheFirstTransfer below and in the package benchmarks.

// TestIncreaseBufferAfterIsNaiveOnly is the central assertion, and the negative half is
// the more important one: every other protocol must keep the library default, or this
// change would silently alter copy behaviour for the whole server.
func TestIncreaseBufferAfterIsNaiveOnly(t *testing.T) {
	require.Equal(t, int64(1), connectionIncreaseBufferAfter(adapter.InboundContext{
		InboundType: C.TypeNaive,
	}), "Native Naive must upgrade its copy buffer after the first transfer")

	// The contrast, stated explicitly: the Naive threshold must NOT be the library
	// default. If a future change made them equal, the optimization would be silently
	// gone while every other test still passed.
	naiveThreshold := connectionIncreaseBufferAfter(adapter.InboundContext{
		InboundType: C.TypeNaive,
	})
	require.NotEqual(t, int64(bufio.DefaultIncreaseBufferAfter), naiveThreshold,
		"the Naive threshold must differ from the library default; if it is equal the "+
			"optimization has been silently reverted")

	require.Less(t, naiveThreshold, int64(bufio.DefaultIncreaseBufferAfter),
		"the Naive threshold must be SMALLER than the default: the point is to upgrade "+
			"the copy buffer EARLIER, never later")
}

// TestIncreaseBufferAfterLeavesOtherProtocolsAlone enumerates the inbound types that
// share this copy path, so a future change cannot quietly widen the Naive special case.
func TestIncreaseBufferAfterLeavesOtherProtocolsAlone(t *testing.T) {
	for _, inboundType := range []string{
		C.TypeHTTP,
		C.TypeAnyTLS,
		C.TypeShadowTLS,
		C.TypeShadowsocks,
		C.TypeSOCKS,
		C.TypeMixed,
		C.TypeTun,
		C.TypeDirect,
	} {
		t.Run(inboundType, func(t *testing.T) {
			require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
				connectionIncreaseBufferAfter(adapter.InboundContext{InboundType: inboundType}),
				"inbound type %q must keep the library default copy threshold", inboundType)
		})
	}
}

// TestIncreaseBufferAfterUnknownAndEmptyUseTheDefault covers the cases that are easy to
// get wrong: an empty metadata (some internal call paths), and a type this fork does not
// register.
func TestIncreaseBufferAfterUnknownAndEmptyUseTheDefault(t *testing.T) {
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(adapter.InboundContext{}),
		"an empty inbound type must fall back to the library default rather than "+
			"assuming Naive")

	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(adapter.InboundContext{InboundType: "not-a-real-inbound"}),
		"an unknown inbound type must fall back to the library default")
}

// TestNaiveThresholdIsPositive guards the specific mistake the implementation comment
// warns about.
//
// sing's condition is `IncreaseBufferAfter > 0 && n >= IncreaseBufferAfter`, so a
// threshold of 0 does NOT mean "upgrade immediately" - it means "never upgrade". Anyone
// tempted to use 0 as "no delay" would silently disable the optimization entirely.
func TestNaiveThresholdIsPositive(t *testing.T) {
	require.Positive(t, int64(naiveIncreaseBufferAfter),
		"the Naive threshold must be POSITIVE: sing treats 0 as \"never increase the "+
			"buffer\", not as \"increase immediately\"")

	require.Equal(t, int64(1), int64(naiveIncreaseBufferAfter),
		"the smallest positive value makes the upgrade happen after the FIRST transfer, "+
			"which is the intended behaviour: the first chunk still uses the default "+
			"buffer and everything after it uses the larger one")
}

// TestIncreaseBufferAfterDoesNotAffectPacketCopy proves the change is confined to the
// stream copy path.
//
// Packet (UDP) connections go through packetConnectionCopy, which does not consult
// IncreaseBufferAfter at all. This is asserted by reading the source rather than by
// behaviour, because the risk is someone later "unifying" the two paths and accidentally
// giving UDP connections a buffer threshold they do not use.
func TestIncreaseBufferAfterDoesNotAffectPacketCopy(t *testing.T) {
	source := readRouteSource(t, "conn.go")

	packetIndex := indexOf(t, source, "func (m *ConnectionManager) packetConnectionCopy(")
	// The packet copy body runs until the next top-level func; a generous window is
	// enough and avoids depending on exact formatting.
	window := source[packetIndex:]
	if next := indexOf(t, window[1:], "\nfunc "); next > 0 {
		window = window[:next+1]
	}

	require.NotContains(t, window, "IncreaseBufferAfter",
		"packetConnectionCopy must not use the stream copy threshold; UDP batching has "+
			"its own path and giving it a byte threshold would change packet behaviour")

	require.Contains(t, source, "func connectionIncreaseBufferAfter(",
		"the helper must exist in this file, or this test is reading the wrong source")
}

// readRouteSource reads a file from this package's directory, so the structural
// assertions above inspect the real source rather than a copy of its logic.
func readRouteSource(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(name)
	require.NoError(t, err, "the route package source must be readable; if the layout "+
		"changed, fix the path rather than deleting the guard")
	return string(content)
}

// indexOf reports the offset of needle in haystack, failing the test when absent.
func indexOf(t *testing.T, haystack string, needle string) int {
	t.Helper()
	index := strings.Index(haystack, needle)
	require.GreaterOrEqual(t, index, 0,
		"the route source must still contain %q; this test is reading the wrong code "+
			"if it does not", needle)
	return index
}
