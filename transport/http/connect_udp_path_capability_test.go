package http

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Where batching can be cut off along the production CONNECT-UDP path.
//
// # The path, from route/conn.go
//
//	client side                        target side
//	 http3PacketConn                    remotePacketConn
//	   -> canceler.NewPacketConn          -> NAT wrappers (only when the
//	      (when udpTimeout > 0)              destination was remapped)
//
//	upload   : CopyPacket(destination = NAT-wrapped target, source = timeout-wrapped client)
//	download : CopyPacket(destination = timeout-wrapped client, source = NAT-wrapped target)
//
// So the TIMEOUT WRAPPER behaves as a WRITER on upload and as a READER on download,
// while the NAT wrappers behave as a WRITER and a READER in the opposite directions. A
// fix that only handled one side would leave half the traffic unbatchable, which is why
// this file measures each wrapper in each role instead of asserting one aggregate claim.
//
// # What was measured
//
// Every wrapper on the production path forwards BOTH connected batch capabilities:
//
//	timeout wrapper (TimerPacketConn / TimeoutPacketConn)  read + write
//	unidirectionalNATPacketConn                            read + write
//	bidirectionalNATPacketConn                             read + write
//	destinationNATPacketConn                               read + write
//
// The NAT wrappers forward batch read through nat_wait.go and batch write through nat.go,
// which is why they are asserted in BOTH roles below rather than only as writers. An
// earlier reading of this only checked nat.go and wrongly concluded the download
// direction was blocked; the test is what caught that, which is the reason both roles are
// pinned here instead of documented in prose.
//
// So both directions of a CONNECT-UDP tunnel can batch after the timeout fix, and no
// additional wrapper blocker was found.

// TestConnectUDPSideWrappersForwardBatchWrite proves every wrapper that can appear on a
// WRITE side of the production path forwards the connected batch write capability.
//
// A failure here means upload batching is cut off, which is the direction that carries
// the client's own traffic.
func TestConnectUDPSideWrappersForwardBatchWrite(t *testing.T) {
	destination := M.ParseSocksaddr("198.18.0.1:443")
	originDestination := M.ParseSocksaddr("198.18.0.2:443")

	inner := newBatchCapablePacketConn(errDeadlineUnsupported)
	defer inner.Close()

	// The timeout wrapper is the WRITER on the upload direction only if the client is
	// the destination; more importantly it is a writer on the download direction, so it
	// is asserted in the writer role here.
	_, timeoutWrapped := newTimeoutWrappedForTest(t, inner)

	// Every NAT wrapper construction route/conn.go can take.
	natWrappers := map[string]N.PacketWriter{
		"unidirectional-nat": bufio.NewUnidirectionalNATPacketConn(
			bufio.NewPacketConn(newBatchCapablePacketConn(errDeadlineUnsupported)), destination, originDestination),
		"bidirectional-nat": bufio.NewNATPacketConn(
			bufio.NewPacketConn(newBatchCapablePacketConn(errDeadlineUnsupported)), destination, originDestination),
		"destination-nat": bufio.NewDestinationNATPacketConn(
			bufio.NewPacketConn(newBatchCapablePacketConn(errDeadlineUnsupported)), destination, originDestination),
	}

	for name, writer := range natWrappers {
		t.Run(name, func(t *testing.T) {
			_, ok := bufio.CreateConnectedPacketBatchWriter(writer)
			require.True(t, ok,
				"%s must forward the connected batch WRITE capability, or the upload "+
					"direction falls back to one packet at a time", name)
		})
	}

	t.Run("timeout-wrapper", func(t *testing.T) {
		_, ok := bufio.CreateConnectedPacketBatchWriter(timeoutWrapped)
		require.True(t, ok,
			"the timeout wrapper must forward the connected batch WRITE capability")
	})
}

// TestConnectUDPClientSideReadWaiterForwardsBatchRead proves the READ side of the client
// connection forwards batch read, which is what the upload direction depends on.
func TestConnectUDPClientSideReadWaiterForwardsBatchRead(t *testing.T) {
	inner := newBatchCapablePacketConn(errDeadlineUnsupported)
	defer inner.Close()

	_, wrapped := newTimeoutWrappedForTest(t, inner)

	_, ok := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
	require.True(t, ok,
		"the timeout wrapper must forward the connected batch READ capability, or the "+
			"upload direction falls back to one packet at a time")
}

// TestConnectUDPNATWrappersForwardBothBatchCapabilities proves the NAT wrappers are not
// a second blocker.
//
// They are checked in both roles because they appear on both sides of the data path: as
// the WRITER of the upload direction and as the READER of the download direction. A
// wrapper that forwarded only one would leave half the traffic unbatchable, which is
// exactly the mistake this test exists to catch - and it did catch one: the batch READ
// forwarding lives in nat_wait.go, a different file from the batch WRITE forwarding in
// nat.go, so a check that looked at only one file reported the wrong answer.
func TestConnectUDPNATWrappersForwardBothBatchCapabilities(t *testing.T) {
	destination := M.ParseSocksaddr("198.18.0.1:443")
	originDestination := M.ParseSocksaddr("198.18.0.2:443")

	newReaders := map[string]func() N.PacketConn{
		"unidirectional-nat": func() N.PacketConn {
			return bufio.NewUnidirectionalNATPacketConn(
				bufio.NewPacketConn(newBatchCapablePacketConn(errDeadlineUnsupported)),
				destination, originDestination)
		},
		"bidirectional-nat": func() N.PacketConn {
			return bufio.NewNATPacketConn(
				bufio.NewPacketConn(newBatchCapablePacketConn(errDeadlineUnsupported)),
				destination, originDestination)
		},
		"destination-nat": func() N.PacketConn {
			return bufio.NewDestinationNATPacketConn(
				bufio.NewPacketConn(newBatchCapablePacketConn(errDeadlineUnsupported)),
				destination, originDestination)
		},
	}

	for name, build := range newReaders {
		t.Run(name, func(t *testing.T) {
			conn := build()
			defer conn.Close()

			_, readOK := bufio.CreateConnectedPacketBatchReadWaiter(conn)
			require.True(t, readOK,
				"%s must forward the connected batch READ capability, or the download "+
					"direction (target -> client) falls back to one packet at a time", name)

			_, writeOK := bufio.CreateConnectedPacketBatchWriter(conn)
			require.True(t, writeOK,
				"%s must forward the connected batch WRITE capability, or the upload "+
					"direction falls back to one packet at a time", name)
		})
	}
}

// TestConnectUDPUploadDirectionBatchesFully proves the direction that IS fixed end to end.
//
// Upload is: the timeout-wrapped CLIENT connection is the source, and the NAT-wrapped
// target is the destination. Both sides forward what that direction needs - batch read
// on the source and batch write on the destination - so bufio.CopyPacket must select the
// batch path.
func TestConnectUDPUploadDirectionBatchesFully(t *testing.T) {
	const totalPackets = 8

	// Source: the client connection behind the timeout wrapper.
	source := newInstrumentedBatchSource(totalPackets, 4)
	defer source.Close()
	for index := range totalPackets {
		source.push([]byte{byte(index), 0xAB})
	}
	_, wrappedSource := newTimeoutWrappedForTest(t, source)

	// Destination: the NAT-wrapped target.
	destination := newInstrumentedBatchDestination()
	defer destination.Close()
	natDestination := bufio.NewNATPacketConn(
		bufio.NewPacketConn(destination),
		M.ParseSocksaddr("198.18.0.1:443"),
		M.ParseSocksaddr("198.18.0.2:443"),
	)

	// Both capability halves the upload direction needs must be present.
	_, readOK := bufio.CreateConnectedPacketBatchReadWaiter(wrappedSource)
	require.True(t, readOK, "the upload source must offer batch read")
	_, writeOK := bufio.CreateConnectedPacketBatchWriter(natDestination)
	require.True(t, writeOK, "the upload destination must offer batch write")

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = bufioCopyPacketForTest(natDestination, wrappedSource)
	}()

	require.Eventually(t, func() bool {
		_, _, payloads := destination.counters()
		return len(payloads) >= totalPackets
	}, 10*time.Second, 10*time.Millisecond,
		"every packet must be delivered through the upload direction")

	batches, singleWrites, _ := destination.counters()
	require.Greater(t, batches, 0,
		"the upload direction must use the batch path: its source offers batch read and "+
			"its destination offers batch write")
	require.Equal(t, 0, singleWrites,
		"the upload direction must not fall back to one packet per call")
	t.Logf("upload direction batches fully: %d batches, %d single writes", batches, singleWrites)

	<-done
}

// newTimeoutWrappedForTest puts a connection through the same idle-timeout wrapper that
// route/conn.go applies, with a timeout that keeps the wrapper in place for the whole
// test.
func newTimeoutWrappedForTest(t *testing.T, conn N.PacketConn) (context.Context, N.PacketConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return canceler.NewPacketConn(ctx, conn, 30*time.Second)
}

// bufioCopyPacketForTest runs the real copy function, so the selection logic under test is
// the shipped one rather than a reimplementation.
func bufioCopyPacketForTest(destination N.PacketWriter, source N.PacketReader) (int64, error) {
	return bufio.CopyPacket(destination, source)
}
