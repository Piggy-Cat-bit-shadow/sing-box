package route

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

// The tunnel copy-buffer threshold, and WHICH COPY it applies to.
//
// sing's copy path starts with a pooled ~32 KiB buffer and only switches to the larger
// geometry once the cumulative byte count reaches IncreaseBufferAfter, which defaults to
// 512000.
//
// The threshold is resolved PER DIRECTION, because the reason to grow early belongs to
// the writer the copy feeds:
//
//	upload   : conn -> remoteConn, destination is the OUTBOUND's writer
//	download : remoteConn -> conn, destination is the INBOUND's writer
//
// Native Naive's padded writer (WriterMTU 65278, 3 + 65278 + 255 = 65536) is the
// DOWNLOAD destination. It opts in through adapter.CopyBufferGrowthTuner; the upload
// destination is an ordinary TCP or SOCKS writer that does not, so it keeps the default.
//
// A previous revision asked "is this connection's inbound Naive?" and applied one answer
// to both directions, which gave the upload copy Naive's threshold with no padding
// geometry to match.

// fakeTunedConn is a net.Conn whose writer reports a copy-growth preference.
type fakeTunedConn struct {
	net.Conn
	early bool
}

func (c fakeTunedConn) EarlyCopyBufferGrowth() bool { return c.early }

// untunedConn implements net.Conn WITHOUT the capability: an ordinary TCP or SOCKS
// writer.
type untunedConn struct {
	net.Conn
}

// TestCopyGrowthIsRequestedByTheNaiveWriter proves the capability on the Naive writer is
// what enables early growth, not the inbound type.
func TestCopyGrowthIsRequestedByTheNaiveWriter(t *testing.T) {
	naiveWriter := fakeTunedConn{early: true}

	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter),
		connectionIncreaseBufferAfter(nil, naiveWriter, nil),
		"a destination writer that opts in must get the early threshold")

	// The contrast that matters: the same inbound type with an ordinary destination
	// writer must NOT get the early threshold. This is the bug that was fixed.
	ordinaryWriter := untunedConn{}
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(nil, ordinaryWriter, nil),
		"an ordinary writer must keep the library default even when the other end of "+
			"the connection is a Native Naive inbound; there is no padding geometry here "+
			"for a larger buffer to match")
}

// TestCopyGrowthIsIndependentOfInboundType is the direction-aware property stated as an
// absence: the inbound type cannot influence the decision, because the decision no
// longer has access to it.
func TestCopyGrowthIsIndependentOfInboundType(t *testing.T) {
	// The helper takes no metadata at all. This is asserted structurally as well as by
	// use, so a future change cannot reintroduce the inbound-type check without
	// deliberately changing the signature this test compiles against.
	source := readRouteSource(t, "conn.go")

	require.Contains(t, source, "func connectionIncreaseBufferAfter(dialer N.Dialer, destination net.Conn, source net.Conn) int64",
		"the helper must take the DESTINATION writer; that is what makes the decision "+
			"direction-aware")

	require.NotContains(t, source, "metadata.InboundType == C.TypeNaive",
		"the copy threshold must not be derived from the inbound type; doing so applies "+
			"one direction's writer tuning to the other direction")

	require.NotContains(t, source, "naiveIncreaseBufferAfter",
		"the inbound-type-based Naive threshold must be gone, not merely unused")
}

// TestNaiveWriterOptsInAndOrdinaryWritersDoNot exercises the two directions of one
// connection through the same helper the route layer calls.
func TestNaiveWriterOptsInAndOrdinaryWritersDoNot(t *testing.T) {
	naiveInboundWriter := fakeTunedConn{early: true} // download destination
	ordinaryOutboundWriter := untunedConn{}          // upload destination

	download := connectionIncreaseBufferAfter(nil, naiveInboundWriter, nil)
	upload := connectionIncreaseBufferAfter(nil, ordinaryOutboundWriter, nil)

	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter), download,
		"the download copy feeds the padded writer, so it must grow early")
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter), upload,
		"the upload copy feeds an ordinary writer, so it must keep the default")

	require.NotEqual(t, download, upload,
		"the two directions must NOT resolve to the same threshold; resolving them "+
			"together was the bug")
}

// TestWriterOptingOutIsHonoured proves implementing the capability and returning false
// does not change behaviour, so a writer can advertise the interface conditionally.
func TestWriterOptingOutIsHonoured(t *testing.T) {
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(nil, fakeTunedConn{early: false}, nil),
		"a writer that implements the capability but declines must keep the default")
}

// --- Outbound capability tuning (chained SOCKS hop) -------------------------
//
// An outbound may also opt in through adapter.ConnectionCopyTuner, which is how a
// chained residential SOCKS hop requests early growth without this file hardcoding a tag
// or a username.
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
// returns true gets the early threshold when the destination writer does not ask for it
// itself.
func TestOutboundCopyTunerOptsIn(t *testing.T) {
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(nil, untunedConn{}, nil),
		"without a tuning outbound the default must apply")

	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter),
		connectionIncreaseBufferAfter(tunerOutbound{early: true}, untunedConn{}, nil),
		"an opted-in outbound must get the early threshold")
}

// TestOutboundCopyTunerOptsOut is the negative half, and the more important one:
// implementing the capability while reporting false must NOT change behaviour. This is
// what keeps an ordinary SOCKS outbound - which implements the capability but leaves the
// option off - at the library default.
func TestOutboundCopyTunerOptsOut(t *testing.T) {
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(tunerOutbound{early: false}, untunedConn{}, nil),
		"a SOCKS outbound with the option off must keep the library default")
}

// TestOutboundWithoutCapabilityUsesDefault covers an outbound that does not implement the
// capability at all.
func TestOutboundWithoutCapabilityUsesDefault(t *testing.T) {
	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(nonTunerOutbound{}, untunedConn{}, nil),
		"an outbound without the capability must keep the library default")
}

// TestDestinationWriterWinsOverOutboundTuning pins the precedence.
//
// The destination writer describes the writer actually in hand, so its opt-in is the
// more specific statement and is checked first. The outbound capability remains a
// fallback for the direction whose destination is the outbound's own writer.
func TestDestinationWriterWinsOverOutboundTuning(t *testing.T) {
	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter),
		connectionIncreaseBufferAfter(
			tunerOutbound{early: false}, fakeTunedConn{early: true}, nil),
		"the destination writer's opt-in must be honoured even when the outbound "+
			"declines; a SOCKS hop behind a Naive writer must not disable Naive's own "+
			"download optimization")

	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter),
		connectionIncreaseBufferAfter(
			tunerOutbound{early: true}, fakeTunedConn{early: true}, nil),
		"and when both opt in")
}

// TestGroupResolvesToTheSelectedMember: a route through a selector/urltest must tune
// according to the MEMBER that served the connection, not according to the group.
//
// The route layer passes the dialer that was actually selected, so this asserts the
// property at the point the decision is made: whatever the dialer is, its capability is
// what counts.
func TestGroupResolvesToTheSelectedMember(t *testing.T) {
	group := nonTunerOutbound{}          // the group itself: no tuning
	member := tunerOutbound{early: true} // the member that served the connection

	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(group, untunedConn{}, nil),
		"the group itself must not enable tuning")

	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter),
		connectionIncreaseBufferAfter(member, untunedConn{}, nil),
		"the SELECTED member's opt-in must be honoured; the route layer passes the "+
			"member, so a group cannot mask it")

	require.Equal(t, int64(bufio.DefaultIncreaseBufferAfter),
		connectionIncreaseBufferAfter(tunerOutbound{early: false}, untunedConn{}, nil),
		"a member that declines must keep the default")
}

// TestEarlyThresholdIsPositive guards the specific mistake the implementation comment
// warns about.
//
// sing's condition is `IncreaseBufferAfter > 0 && n >= IncreaseBufferAfter`, so a
// threshold of 0 does NOT mean "upgrade immediately" - it means "never upgrade". Anyone
// tempted to use 0 as "no delay" would silently disable the optimization entirely.
func TestEarlyThresholdIsPositive(t *testing.T) {
	require.Positive(t, earlyConnectionBufferIncreaseAfter,
		"a non-positive threshold would disable growth entirely")

	require.Equal(t, int64(1), int64(earlyConnectionBufferIncreaseAfter),
		"the smallest positive value makes the upgrade happen after the FIRST transfer, "+
			"which is the intended behaviour: the first chunk still uses the default "+
			"buffer and everything after it uses the larger one")

	require.Less(t, int64(earlyConnectionBufferIncreaseAfter),
		int64(bufio.DefaultIncreaseBufferAfter),
		"early growth must be EARLIER than the default, never later")
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

// TestBothDirectionsResolveSeparately is the structural half of the direction-aware
// change: the route layer must call the helper once per direction rather than computing a
// single value and reusing it.
//
// A behavioural test cannot see this, because the two directions are goroutines racing on
// a live connection. Reading the call site is the reliable way to pin it.
func TestBothDirectionsResolveSeparately(t *testing.T) {
	source := readRouteSource(t, "conn.go")

	index := indexOf(t, source, "func (m *ConnectionManager) NewConnection(")
	window := source[index:]
	if next := indexOf(t, window[1:], "\nfunc "); next > 0 {
		window = window[:next+1]
	}

	// The upload copy: destination is remoteConn (the outbound's writer).
	require.Contains(t, window, "connectionIncreaseBufferAfter(this, conn, remoteConn)",
		"the upload direction must resolve its threshold from the OUTBOUND-side "+
			"destination writer")

	// The download copy: destination is conn (the inbound's writer).
	require.Contains(t, window, "connectionIncreaseBufferAfter(this, remoteConn, conn)",
		"the download direction must resolve its threshold from the INBOUND-side "+
			"destination writer")

	// And the two results must reach their own copy call, not a shared variable.
	require.Contains(t, window, "m.connectionCopy(ctx, conn, remoteConn, false, uploadIncreaseBufferAfter",
		"the upload copy must use the upload threshold")
	require.Contains(t, window, "m.connectionCopy(ctx, remoteConn, conn, true, downloadIncreaseBufferAfter",
		"the download copy must use the download threshold")
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

// TestNaiveWriterKeepsItsThresholdAcrossTransfers pins that the Naive DOWNLOAD
// optimization was preserved rather than deleted.
//
// # Scope of this assertion
//
// This is the MECHANISM half: it proves the threshold the route layer hands to the copy
// loop for the Naive writer is the early one, and that the value is strictly earlier than
// the library default. It does NOT claim a throughput improvement - the copy loop's
// internal buffer geometry is not observable from here, and "fewer handovers" is not
// "more Mbps". Any throughput number must come from a real transfer against a real
// server, which is recorded separately as NOT TESTED where applicable.
func TestNaiveWriterKeepsItsThresholdAcrossTransfers(t *testing.T) {
	naiveDownloadWriter := fakeTunedConn{early: true}

	threshold := connectionIncreaseBufferAfter(nil, naiveDownloadWriter, nil)

	require.Equal(t, int64(earlyConnectionBufferIncreaseAfter), threshold,
		"the Naive download writer must receive the early threshold; if this changed to "+
			"the library default, the download optimization was silently removed rather "+
			"than narrowed")

	require.Equal(t, int64(1), threshold,
		"the early threshold is 1: the first chunk uses the current default buffer and "+
			"every chunk after it uses the larger geometry")

	require.Less(t, threshold, int64(bufio.DefaultIncreaseBufferAfter),
		"early growth must be strictly EARLIER than the default, never later")

	// The value that actually reaches the copy loop must be positive, because sing
	// treats a non-positive threshold as "never grow".
	require.Positive(t, threshold,
		"a non-positive threshold would disable buffer growth entirely, which is the "+
			"opposite of the intent")

	// And the upload copy of the same conceptual connection must differ, which is the
	// narrowing this change performed.
	uploadThreshold := connectionIncreaseBufferAfter(nil, untunedConn{}, nil)
	require.NotEqual(t, threshold, uploadThreshold,
		"the upload copy must not inherit the download writer's threshold")
}

// TestCopyGrowthDecisionIsCheapToEvaluate documents that the resolution runs once per
// direction per connection, not per byte.
func TestCopyGrowthDecisionIsCheapToEvaluate(t *testing.T) {
	// Two interface assertions and an unwrap. Asserted structurally: the helper must not
	// contain a loop or a cache lookup, because it is called on the connection path.
	source := readRouteSource(t, "conn.go")

	index := indexOf(t, source, "func connectionIncreaseBufferAfter(")
	window := source[index:]
	if next := indexOf(t, window[1:], "\nfunc "); next > 0 {
		window = window[:next+1]
	}

	require.NotContains(t, window, "for ",
		"the threshold resolution must not loop")
	require.NotContains(t, window, "sync.",
		"the threshold resolution must not take a lock; it runs on the connection path")

	// A time bound as a smoke signal: if this ever becomes expensive, this fails long
	// before it shows up as a throughput regression.
	start := time.Now()
	for range 10000 {
		connectionIncreaseBufferAfter(tunerOutbound{early: true}, fakeTunedConn{early: true}, nil)
	}
	require.Less(t, time.Since(start), time.Second,
		"resolving the threshold 10000 times must be effectively free")
}
