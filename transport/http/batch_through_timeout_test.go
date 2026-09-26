package http

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The timeout wrappers PRESERVE the batch capabilities.
//
// # The chain this pins
//
//	http3PacketConn            offers connected batch read + write
//	  -> canceler.NewPacketConn
//	     -> TimerPacketConn      (the socket cannot take a read deadline)
//	     -> TimeoutPacketConn    (the socket can)
//	  -> CreateConnectedPacketBatchReadWaiter / ...Writer
//	  -> bufio.CopyPacket selects the batch path
//
// route/conn.go wraps every CONNECT-UDP connection in canceler.NewPacketConn for the UDP
// idle timeout. Before the sing fix that wrap silently dropped both batch capabilities,
// so the batching implemented on the tunnel was unreachable in production: the tunnel
// kept working, one packet at a time, and nothing failed.
//
// # This replaces a negative test
//
// The previous file asserted the DROP, deliberately, so that the dependency gap stayed
// visible instead of being a stale comment. It did its job: it failed the moment the
// wrappers started forwarding, and its failure message said what to do next. It is
// replaced rather than deleted so the capability is now pinned in the positive
// direction - if a future change makes the wrapper swallow the batch path again, these
// tests fail instead of the tunnel quietly slowing down.
//
// # Why the wrapper-specific tests live elsewhere
//
// The detailed wrapper behaviour (both branches, activity accounting, ownership,
// timeouts) is tested in sing itself, next to the code, where the fixtures can drive the
// real implementations. This file is the sing-box-side integration point: that the
// capability really survives the specific wrapping that route/conn.go performs, on the
// specific connection type CONNECT-UDP uses.

// TestTimeoutWrapperKeepsHTTP3BatchCapabilitiesThroughTheRealWrapper is the end-to-end
// capability check for the connection CONNECT-UDP actually carries.
//
// It uses the real http3PacketConn rather than a test double, because the point is that
// THIS connection type keeps its batching after the timeout wrapper that production
// applies to it.
func TestTimeoutWrapperKeepsHTTP3BatchCapabilitiesThroughTheRealWrapper(t *testing.T) {
	inner := newHTTP3PacketConn(&datagramFeedingStream{}, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer inner.Close()

	// Precondition: the bare connection offers both capabilities, so anything observed
	// below is attributable to the wrapper rather than to the connection.
	_, bareRead := bufio.CreateConnectedPacketBatchReadWaiter(inner)
	_, bareWrite := bufio.CreateConnectedPacketBatchWriter(inner)
	require.True(t, bareRead, "precondition: the bare connection offers batch read")
	require.True(t, bareWrite, "precondition: the bare connection offers batch write")

	// The in-memory fixture cannot take a read deadline, which is the branch the real
	// HTTP/3 connection also takes: TimerPacketConn.
	_, wrapped := canceler.NewPacketConn(context.Background(), inner, 30*time.Second)
	_, isTimer := wrapped.(*canceler.TimerPacketConn)
	require.True(t, isTimer,
		"the HTTP/3 packet connection cannot set a read deadline, so it must take the "+
			"TimerPacketConn branch; got %T", wrapped)

	readWaiter, wrappedRead := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
	require.True(t, wrappedRead,
		"the batch read capability must survive the idle-timeout wrapper. Without it a "+
			"CONNECT-UDP tunnel falls back to one packet at a time on the production "+
			"path, which is the regression this test exists to prevent")
	require.NotNil(t, readWaiter, "a creator reporting true must return a usable waiter")

	writeWriter, wrappedWrite := bufio.CreateConnectedPacketBatchWriter(wrapped)
	require.True(t, wrappedWrite,
		"the batch write capability must survive the idle-timeout wrapper")
	require.NotNil(t, writeWriter)

	// The waiter must be usable, not merely present: initialize it, which is what the
	// copy path does before waiting.
	needCopy := readWaiter.InitializeReadWaiter(N.ReadWaitOptions{
		FrontHeadroom: inner.FrontHeadroom(),
		BatchSize:     defaultBatchSize,
	})
	require.False(t, needCopy,
		"the HTTP/3 batch waiter hands over queued buffers directly, so it must not ask "+
			"the copy path to allocate and copy")
}

// TestTimeoutWrapperKeepsBatchCapabilitiesForBothBranches covers the branch selection
// explicitly.
//
// canceler.NewPacketConn picks its implementation from whether the connection accepts a
// read deadline, and the two branches are different code. The HTTP/3 connection takes the
// timer branch, but a plain UDP socket takes the timeout branch, and both are used by
// CONNECT-UDP depending on how the target is reached - so both are asserted here as well
// as in sing.
func TestTimeoutWrapperKeepsBatchCapabilitiesForBothBranches(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		deadlineErr error
	}{
		{"timer-branch", errDeadlineUnsupported},
		{"timeout-branch", nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			inner := newBatchCapablePacketConn(testCase.deadlineErr)
			defer inner.Close()

			_, wrapped := canceler.NewPacketConn(context.Background(), inner, 30*time.Second)

			readWaiter, readOK := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
			require.True(t, readOK,
				"batch read must survive the wrapper on this branch")
			require.NotNil(t, readWaiter)

			writeWriter, writeOK := bufio.CreateConnectedPacketBatchWriter(wrapped)
			require.True(t, writeOK,
				"batch write must survive the wrapper on this branch")
			require.NotNil(t, writeWriter)

			// The capability must be usable through the wrapper, so a batch is
			// round-tripped rather than only requested.
			readWaiter.InitializeReadWaiter(N.ReadWaitOptions{
				FrontHeadroom: 3,
				RearHeadroom:  255,
				MTU:           1500,
				BatchSize:     8,
			})
			for index := range 4 {
				packet := newTestPacket(byte(index))
				inner.packets <- packet
			}
			buffers, destination, err := readWaiter.WaitReadConnectedPackets()
			require.NoError(t, err)
			require.Len(t, buffers, 4)
			require.Equal(t, inner.destination, destination)
			releaseTestBuffers(buffers)

			writeBuffers := []*buf.Buffer{newTestPacket(1), newTestPacket(2)}
			require.NoError(t, writeWriter.WriteConnectedPacketBatch(writeBuffers))
			require.Equal(t, 1, inner.forwardedBatchWrites,
				"the batch must reach the inner connection as one batch")
		})
	}
}

// errDeadlineUnsupported stands in for the error a connection that cannot take a read
// deadline reports. It selects the TimerPacketConn branch, which is the branch the real
// HTTP/3 packet connection takes - that connection reports os.ErrInvalid, and any
// non-nil error chooses the same path.
var errDeadlineUnsupported = os.ErrInvalid

// newTestPacket builds a one-byte packet carrying the marker, so order is assertable.
func newTestPacket(marker byte) *buf.Buffer {
	packet := buf.NewSize(1)
	packet.Write([]byte{marker})
	return packet
}

// releaseTestBuffers returns a batch to the pool. The batch path hands ownership to the
// caller, so a test that never releases would leak - which the pool detects.
func releaseTestBuffers(buffers []*buf.Buffer) {
	buf.ReleaseMulti(buffers)
}

// Compile-time guard: the batch options helper must keep matching the interface the copy
// path initializes waiters with.
var _ N.ReadWaitOptions = N.ReadWaitOptions{}
