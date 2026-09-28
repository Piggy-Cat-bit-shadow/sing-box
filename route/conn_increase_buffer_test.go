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
	}, nil), "Native Naive must upgrade its copy buffer after the first transfer")

	// The contrast, stated explicitly: the Naive threshold must NOT be the library
	// default. If a future change made them equal, the optimization would be silently
	// gone while every other test still passed.
	naiveThreshold := connectionIncreaseBufferAfter(adapter.InboundContext{
		InboundType: C.TypeNaive,
	}, nil)
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
				connectionIncreaseBufferAfter(adapter.InboundContext{InboundType: inboundType}, nil),
				"inbound type %q must keep the library default copy threshold", inboundType)
		})
	}
}

// TestIncreaseBufferAfterUnknownAndEmptyUseTheDefault covers the cases that are easy to
// get wrong: an empty metadata (some internal call paths), and a type this fork does not
// register.
func TestIncreaseBufferAfterUnknownAndEmptyUseTheDefault(t *testing.T) {
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(adapter.InboundContext{}, nil),
		"an empty inbound type must fall back to the library default rather than "+
			"assuming Naive")

	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(adapter.InboundContext{InboundType: "not-a-real-inbound"}, nil),
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

// --- Outbound capability tuning (chained SOCKS hop) -------------------------
//
// The threshold can now also be requested by the SELECTED OUTBOUND through
// adapter.ConnectionCopyTuner, which is how a chained residential SOCKS hop opts in
// without this file hardcoding a tag or a username.
//
// A tag was rejected as the key: it is operator-chosen configuration, so keying on one
// would make copy behaviour depend on a naming choice. The capability means only an
// outbound that explicitly asked for it is affected.

// tunerOutbound is a minimal Outbound that reports a copy-tuning preference.
type tunerOutbound struct {
	adapter.Outbound
	early bool
}

func (t tunerOutbound) EarlyConnectionBufferGrowth() bool { return t.early }

// nonTunerOutbound implements Outbound WITHOUT the capability.
type nonTunerOutbound struct {
	adapter.Outbound
}

// TestOutboundCopyTunerOptsIn proves an outbound that implements the capability and
// returns true gets the early threshold.
func TestOutboundCopyTunerOptsIn(t *testing.T) {
	metadata := adapter.InboundContext{InboundType: C.TypeAnyTLS}
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(metadata, nil),
		"without a tuning outbound the default must apply")

	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter),
		connectionIncreaseBufferAfter(metadata, tunerOutbound{early: true}),
		"an opted-in outbound must get the early threshold")
}

// TestOutboundCopyTunerOptsOut is the negative half, and the more important one:
// implementing the capability while reporting false must NOT change behaviour. This is
// what keeps an ordinary SOCKS outbound - which implements the capability but leaves
// the option off - at the library default.
func TestOutboundCopyTunerOptsOut(t *testing.T) {
	metadata := adapter.InboundContext{InboundType: C.TypeAnyTLS}
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(metadata, tunerOutbound{early: false}),
		"a SOCKS outbound with the option off must keep the library default")
}

// TestOutboundWithoutCapabilityUsesDefault covers an outbound that does not implement
// the capability at all.
func TestOutboundWithoutCapabilityUsesDefault(t *testing.T) {
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(
			adapter.InboundContext{InboundType: C.TypeAnyTLS}, nonTunerOutbound{}),
		"an outbound without the capability must keep the library default")
}

// TestNaiveStillWinsOverOutboundTuning pins the precedence: the Naive inbound rule is
// checked first and is unchanged by this feature, so the existing Native Naive
// optimization cannot regress because a SOCKS outbound was selected behind it.
func TestNaiveStillWinsOverOutboundTuning(t *testing.T) {
	require.Equal(t, int64(1),
		connectionIncreaseBufferAfter(
			adapter.InboundContext{InboundType: C.TypeNaive}, tunerOutbound{early: false}),
		"Native Naive must keep its early growth even when the outbound does not opt in")

	require.Equal(t, int64(1),
		connectionIncreaseBufferAfter(
			adapter.InboundContext{InboundType: C.TypeNaive}, tunerOutbound{early: true}),
		"and when it does")
}

// TestGroupResolvesToTheSelectedMember is requirement: a route through a
// selector/urltest must tune according to the MEMBER that served the connection, not
// according to the group.
//
// The route layer passes the dialer that was actually selected, so this asserts the
// property at the point the decision is made: whatever `this` is, its capability is
// what counts. A group that reports false while its selected member reports true must
// therefore yield the early threshold, which is what the pair of assertions shows.
func TestGroupResolvesToTheSelectedMember(t *testing.T) {
	metadata := adapter.InboundContext{InboundType: C.TypeAnyTLS}

	group := nonTunerOutbound{}          // the group itself: no tuning
	member := tunerOutbound{early: true} // the member that served the connection

	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(metadata, group),
		"the group itself must not enable tuning")

	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter),
		connectionIncreaseBufferAfter(metadata, member),
		"the SELECTED member's opt-in must be honoured; the route layer passes the "+
			"member, so a group cannot mask it")

	// The inverse: a member that declines must not inherit tuning from anywhere.
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(metadata, tunerOutbound{early: false}),
		"a member that declines must keep the default")
}

// TestEarlyThresholdIsPositive reuses the reasoning from the Naive test: sing's
// condition is `IncreaseBufferAfter > 0 && n >= IncreaseBufferAfter`, so a non-positive
// value means "never grow" rather than "grow immediately".
func TestEarlyThresholdIsPositive(t *testing.T) {
	require.Positive(t, earlyConnectionBufferIncreaseAfter,
		"a non-positive threshold would disable growth entirely")
}
