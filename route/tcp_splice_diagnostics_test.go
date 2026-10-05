package route

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// TCP splice diagnostics.
//
// # What these tests can and cannot reach, and why that is stated rather than hidden
//
// The stream decision reads a live TUN stream through a `*tun.GoConn`. That type is a struct
// with unexported fields whose only constructor is inside sing-tun's Go engine, so no test
// outside that module can produce one. The consequences are specific:
//
//   - reachable here, and driven end to end through NewConnection: the caller's skip, and a
//     source that is not a TUN stream (the normal answer for a proxied flow);
//   - reachable here through the real classifier: every target-side rejection, because the
//     classifier takes wrappers and the wrappers are interfaces;
//   - NOT reachable here: success, splice_rejected, source_reader_writer_mismatch and
//     cached_write_failed, because all four are only decided after a live GoConn exists.
//
// The unreachable four are read on a device instead, which is what the diagnostics are for.
// What is verified here is that they have a name, that they cannot be confused with each
// other or with a success, and that the one-write-per-flow invariant holds - so a device
// report can be trusted to mean what it says.

// tcpSpliceTestDialer hands NewConnection the remote side of a pipe.
type tcpSpliceTestDialer struct {
	remote net.Conn
}

func (d *tcpSpliceTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.remote, nil
}

func (d *tcpSpliceTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, io.ErrClosedPipe
}

func newTCPDiagnosticsManager() *ConnectionManager {
	return &ConnectionManager{logger: log.NewNOPFactory().NewLogger("tcp-splice-test")}
}

// driveConnection runs one connection through the real manager and returns the peer ends so
// the caller can move bytes.
func driveConnection(t *testing.T, metadata adapter.InboundContext) (*ConnectionManager, net.Conn, net.Conn) {
	t.Helper()
	manager := newTCPDiagnosticsManager()
	inbound, inboundPeer := net.Pipe()
	remote, remotePeer := net.Pipe()
	t.Cleanup(func() {
		_ = inboundPeer.Close()
		_ = remotePeer.Close()
		_ = manager.Close()
	})
	if !metadata.Destination.IsValid() {
		metadata.Destination = M.ParseSocksaddrHostPort("example.com", 443)
	}
	manager.NewConnection(context.Background(), &tcpSpliceTestDialer{remote: remote}, inbound, metadata, nil)
	return manager, inboundPeer, remotePeer
}

// TestTCPSpliceDiagnostics_ProxiedStreamIsSourceNotGoConn is the normal case for a flow that
// is proxied in userspace: the client side is not a TUN stream, so no handover is possible.
//
// It also proves the fallback still works with the instrumentation in place: the bytes have to
// arrive, which they only do if the generic copy path ran. A diagnostic that recorded "not
// spliced" while breaking the copy would be worse than none.
func TestTCPSpliceDiagnostics_ProxiedStreamIsSourceNotGoConn(t *testing.T) {
	manager, inboundPeer, remotePeer := driveConnection(t, adapter.InboundContext{})

	payload := []byte("through the copy path")
	writeErr := make(chan error, 1)
	go func() {
		_, err := inboundPeer.Write(payload)
		writeErr <- err
	}()

	require.NoError(t, remotePeer.SetReadDeadline(time.Now().Add(5*time.Second)))
	received := make([]byte, len(payload))
	_, err := io.ReadFull(remotePeer, received)
	require.NoError(t, err, "the generic copy path must still forward data")
	require.Equal(t, payload, received)
	require.NoError(t, <-writeErr)

	snapshot := manager.TCPSpliceDiagnostics()
	require.Equal(t, uint64(1), snapshot.Attempts)
	require.Equal(t, uint64(0), snapshot.Successes)
	require.Equal(t, map[string]uint64{"source_not_go_conn": 1}, snapshot.Reasons)

	// The two transports count separately, or a TCP flow would move the UDP ratio.
	require.Equal(t, uint64(0), manager.SpliceDiagnostics().Attempts)
}

// TestTCPSpliceDiagnostics_SkippedForTLSRewrite covers the one outcome the caller records,
// because spliceConnection is not called at all when the stream has to be rewritten.
func TestTCPSpliceDiagnostics_SkippedForTLSRewrite(t *testing.T) {
	manager, inboundPeer, _ := driveConnection(t, adapter.InboundContext{TLSFragment: true})

	// The connection is live - the copy path owns it - so closing the client end is enough to
	// finish the flow; no assertion on byte flow is made here because the fragmentation wrapper
	// deliberately delays the first write, which is its own behaviour and not this test's.
	_ = inboundPeer.Close()

	snapshot := manager.TCPSpliceDiagnostics()
	require.Equal(t, uint64(1), snapshot.Attempts)
	require.Equal(t, uint64(0), snapshot.Successes)
	require.Equal(t, map[string]uint64{"skipped_for_tls_rewrite": 1}, snapshot.Reasons)
	require.Equal(t, uint64(0), manager.SpliceDiagnostics().Attempts, "a skip must not move the packet path")
}

// TestTCPSpliceTargetReasonsAreRecordable drives the real classifier with wrapper fakes and
// records what it returns, which is what the stream path does. It proves that every
// target-side rejection the classifier can produce has a distinct name in the stream
// snapshot - the part of the vocabulary that is not reachable through a live TUN stream still
// being checked against the code that produces it.
func TestTCPSpliceTargetReasonsAreRecordable(t *testing.T) {
	_, pipeConn := net.Pipe()
	defer pipeConn.Close()

	for _, testCase := range []struct {
		name   string
		target any
		reason string
	}{
		{
			name:   "plain connection",
			target: pipeConn,
			reason: "target_not_replaceable",
		},
		{
			name:   "replaceable but no upstream",
			target: &replaceableWithoutUpstream{Conn: pipeConn},
			reason: "target_no_upstream",
		},
		{
			name:   "upstream reader and writer differ",
			target: &mismatchedUpstream{Conn: pipeConn, reader: pipeConn, writer: &replaceableWithoutUpstream{Conn: pipeConn}},
			reason: "target_upstream_mismatch",
		},
		{
			name:   "asymmetric counters",
			target: &asymmetricCounter{Conn: pipeConn},
			reason: "target_counter_mismatch",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, reason, ok := unwrapSpliceTargetWithReason(testCase.target, false)
			require.False(t, ok, "the fake target must be rejected")
			require.Equal(t, testCase.reason, reason.String())

			manager := newTCPDiagnosticsManager()
			manager.tcpSpliceDiagnostics.recordOutcome(tcpSpliceTargetReason(reason))
			snapshot := manager.TCPSpliceDiagnostics()
			require.Equal(t, uint64(1), snapshot.Attempts)
			require.Equal(t, map[string]uint64{testCase.reason: 1}, snapshot.Reasons)
		})
	}
}

// TestTCPSpliceDiagnostics_InvariantAndFormat pins the accounting rule and the one-line
// report a device run reads.
func TestTCPSpliceDiagnostics_InvariantAndFormat(t *testing.T) {
	manager := newTCPDiagnosticsManager()
	manager.tcpSpliceDiagnostics.recordOutcome(spliceReasonSuccess)
	manager.tcpSpliceDiagnostics.recordOutcome(spliceReasonSuccess)
	manager.tcpSpliceDiagnostics.recordOutcome(spliceReasonSkippedForTLSRewrite)
	manager.tcpSpliceDiagnostics.recordOutcome(spliceReasonSourceNotGoConn)
	manager.tcpSpliceDiagnostics.recordOutcome(spliceReasonSourceNotGoConn)
	manager.tcpSpliceDiagnostics.recordOutcome(spliceReasonSpliceRejected)
	manager.tcpSpliceDiagnostics.recordOutcome(spliceReasonTargetNotReplaceable)
	// Out of range is ignored rather than corrupting a neighbouring bucket.
	manager.tcpSpliceDiagnostics.recordOutcome(spliceReason(200))

	snapshot := manager.TCPSpliceDiagnostics()
	require.Equal(t, uint64(7), snapshot.Attempts)
	require.Equal(t, uint64(2), snapshot.Successes)

	// Attempts == Successes + sum(Reasons), which is what makes a device report add up.
	var failureTotal uint64
	for _, count := range snapshot.Reasons {
		failureTotal += count
	}
	require.Equal(t, snapshot.Attempts, snapshot.Successes+failureTotal)

	// Success is reported separately and never as a reason, or every spliced flow would be
	// counted twice.
	require.NotContains(t, snapshot.Reasons, "success")

	summary := snapshot.TCPSpliceSummary()
	require.True(t, strings.HasPrefix(summary, "TCP splice diagnostics: attempts=7 successes=2 ratio=0.286"), summary)
	require.Contains(t, summary, "skipped_for_tls_rewrite=1")
	require.Contains(t, summary, "source_not_go_conn=2")
	require.Contains(t, summary, "splice_rejected=1")
	require.Contains(t, summary, "target_not_replaceable=1")
	require.NotContains(t, summary, "success=")

	// The packet path keeps its own prefix and its own counters.
	manager.spliceDiagnostics.recordOutcome(spliceReasonSuccess)
	require.True(t, strings.HasPrefix(manager.SpliceDiagnostics().SpliceSummary(), "UDP splice diagnostics: attempts=1"))
	require.Contains(t, manager.SpliceDiagnostics().SpliceSummary(), "ratio=1.000")
}

// TestTCPSpliceDiagnostics_ReasonsAreDistinctAndNamed guards the report's vocabulary: two
// outcomes that share a name would make a device log ambiguous, and an outcome without a name
// would print as "unknown".
func TestTCPSpliceDiagnostics_ReasonsAreDistinctAndNamed(t *testing.T) {
	names := make(map[string]spliceReason, spliceReasonCount)
	for i := 0; i < spliceReasonCount; i++ {
		reason := spliceReason(i)
		name := reason.String()
		require.NotEqual(t, "unknown", name, "reason %d has no name", i)
		if previous, exists := names[name]; exists {
			t.Fatalf("reasons %d and %d share the name %q", previous, i, name)
		}
		names[name] = reason
	}
	require.Equal(t, spliceReasonCount, len(names))

	// The three stream-only outcomes exist under their documented names, so a device report
	// naming one is understood by whoever reads it.
	require.Equal(t, "skipped_for_tls_rewrite", spliceReasonSkippedForTLSRewrite.String())
	require.Equal(t, "source_not_go_conn", spliceReasonSourceNotGoConn.String())
	require.Equal(t, "cached_write_failed", spliceReasonCachedWriteFailed.String())

	// The target-side vocabulary is shared with the packet path rather than mirrored, so a
	// target rejection reads the same in both reports.
	require.Equal(t, spliceReasonTargetNotReplaceable.String(), tcpSpliceTargetReason(spliceReasonTargetNotReplaceable).String())
}

// TestTCPSpliceDiagnostics_FallbackKeepsCountersAndOwnership is the regression for the
// instrumentation's cost: with the diagnostics recording a rejection, the generic copy path
// must still move bytes in both directions and close when the stream ends.
func TestTCPSpliceDiagnostics_FallbackKeepsCountersAndOwnership(t *testing.T) {
	manager, inboundPeer, remotePeer := driveConnection(t, adapter.InboundContext{})

	// Upstream direction.
	go func() { _, _ = inboundPeer.Write([]byte("up")) }()
	require.NoError(t, remotePeer.SetReadDeadline(time.Now().Add(5*time.Second)))
	upstream := make([]byte, 2)
	_, err := io.ReadFull(remotePeer, upstream)
	require.NoError(t, err)
	require.Equal(t, "up", string(upstream))

	// Downstream direction.
	go func() { _, _ = remotePeer.Write([]byte("dn")) }()
	require.NoError(t, inboundPeer.SetReadDeadline(time.Now().Add(5*time.Second)))
	downstream := make([]byte, 2)
	_, err = io.ReadFull(inboundPeer, downstream)
	require.NoError(t, err)
	require.Equal(t, "dn", string(downstream))

	require.Equal(t, uint64(1), manager.TCPSpliceDiagnostics().Attempts, "one connection, one outcome")

	// Closing one side finishes the tracked connection rather than leaking it.
	_ = remotePeer.Close()
	require.Eventually(t, func() bool {
		return manager.Count() == 0
	}, 5*time.Second, 10*time.Millisecond, "the tracked connection must be released")
}

// --- wrapper fakes for the target classifier -------------------------------------------

// replaceableWithoutUpstream is replaceable in both directions but exposes no upstream, which
// is exactly the shape the classifier reports as having nowhere left to walk.
type replaceableWithoutUpstream struct {
	net.Conn
}

func (c *replaceableWithoutUpstream) ReaderReplaceable() bool { return true }
func (c *replaceableWithoutUpstream) WriterReplaceable() bool { return true }

// mismatchedUpstream offers an upstream reader and a different upstream writer.
type mismatchedUpstream struct {
	net.Conn
	reader net.Conn
	writer net.Conn
}

func (c *mismatchedUpstream) ReaderReplaceable() bool { return true }
func (c *mismatchedUpstream) WriterReplaceable() bool { return true }
func (c *mismatchedUpstream) UpstreamReader() any     { return c.reader }
func (c *mismatchedUpstream) UpstreamWriter() any     { return c.writer }

// asymmetricCounter unwraps as a reader but not as a writer.
type asymmetricCounter struct {
	net.Conn
}

func (c *asymmetricCounter) UnwrapReader() (io.Reader, []N.CountFunc) { return c.Conn, nil }

// The fakes must be the shapes the walk tests for, and must not accidentally be more: a
// mismatchedUpstream that also satisfied common.WithUpstream would be followed as a single
// upstream and the mismatch branch this fake exists to exercise would never run.
var (
	_ N.ReaderWithUpstream = (*replaceableWithoutUpstream)(nil)
	_ N.WriterWithUpstream = (*replaceableWithoutUpstream)(nil)
	_ N.WithUpstreamReader = (*mismatchedUpstream)(nil)
	_ N.WithUpstreamWriter = (*mismatchedUpstream)(nil)
	_ N.ReadCounter        = (*asymmetricCounter)(nil)
)
