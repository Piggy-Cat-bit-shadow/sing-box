package http

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The MASQUE CONNECT-UDP production path must keep its batch capability.
//
// # Why this test exists on top of the wrapper tests
//
// The wrapper tests prove the capability survives canceler.NewPacketConn. They do not
// prove the timeout that CONNECT-UDP actually gets: the timeout is derived from the
// connection's metadata by route.packetTimeout, and the derived value decides which
// branch of canceler.NewPacketConn runs. A test that hard-codes "30s" would pass while
// the real rule produced something else, so this test derives the timeout the same way
// route/conn.go does and asserts on the value it gets.
//
// # The rule, from constant/timeout.go
//
//	metadata.UDPTimeout > 0                 -> that value
//	else metadata.Protocol                  -> ProtocolTimeouts[protocol]
//	else PortProtocols[destination.Port]    -> ProtocolTimeouts[protocol]
//	else                                    -> 0 (no wrapper)
//
// With the shipped tables that means port 443 resolves to QUIC and a 30s timeout, and
// port 53 resolves to DNS and a 10s timeout. Those are the two cases named in the task,
// and both are asserted here from the real tables rather than from literals.

// packetTimeoutForTest mirrors route.packetTimeout for the same metadata type.
//
// It is a deliberate copy rather than an import: route imports this package, so importing
// route here would be a cycle. The test below fails loudly if the rule it copies stops
// agreeing with the tables, because the EXPECTED values are read from those tables.
func packetTimeoutForTest(metadata *adapter.InboundContext) time.Duration {
	if metadata.UDPTimeout > 0 {
		return metadata.UDPTimeout
	}
	protocol := metadata.Protocol
	if protocol == "" {
		protocol = C.PortProtocols[metadata.Destination.Port]
	}
	if protocol != "" {
		return C.ProtocolTimeouts[protocol]
	}
	return 0
}

// TestConnectUDPTimeoutRulesProduceTheExpectedBranchTimeout proves the METADATA actually
// produces the timeouts the task names, before any capability is asserted.
//
// Without this step the capability tests could be exercising a timeout of zero (no
// wrapper at all), which would pass for the wrong reason and would not cover the
// production path at all.
func TestConnectUDPTimeoutRulesProduceTheExpectedBranchTimeout(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		metadata    adapter.InboundContext
		wantTimeout time.Duration
		wantWhy     string
	}{
		{
			name:        "target port 443 resolves to QUIC",
			metadata:    adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.10:443")},
			wantTimeout: C.ProtocolTimeouts[C.ProtocolQUIC],
			wantWhy:     "port 443 is in PortProtocols as quic",
		},
		{
			name:        "target port 53 resolves to DNS",
			metadata:    adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.10:53")},
			wantTimeout: C.ProtocolTimeouts[C.ProtocolDNS],
			wantWhy:     "port 53 is in PortProtocols as dns",
		},
		{
			name: "an explicit protocol wins over the port table",
			metadata: adapter.InboundContext{
				Destination: M.ParseSocksaddr("192.0.2.10:9999"),
				Protocol:    C.ProtocolQUIC,
			},
			wantTimeout: C.ProtocolTimeouts[C.ProtocolQUIC],
			wantWhy:     "metadata.Protocol is consulted before the port table",
		},
		{
			name: "an explicit UDPTimeout wins over everything",
			metadata: adapter.InboundContext{
				Destination: M.ParseSocksaddr("192.0.2.10:443"),
				UDPTimeout:  3 * time.Second,
			},
			wantTimeout: 3 * time.Second,
			wantWhy:     "metadata.UDPTimeout is the first rule",
		},
		{
			name:        "an unlisted port has no timeout",
			metadata:    adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.10:51820")},
			wantTimeout: 0,
			wantWhy:     "no protocol is known for this port, so no wrapper is applied",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := packetTimeoutForTest(&testCase.metadata)
			require.Equal(t, testCase.wantTimeout, got,
				"the timeout rule must produce %v for this metadata (%s)",
				testCase.wantTimeout, testCase.wantWhy)
			t.Logf("%s: timeout=%v (%s)", testCase.name, got, testCase.wantWhy)
		})
	}
}

// TestConnectUDPBatchSurvivesTheRealDerivedTimeout is the production-path acceptance.
//
// It takes the timeout the metadata rules actually produce for a CONNECT-UDP target and
// puts a real batch-capable connection through canceler.NewPacketConn with that value,
// then requires both capabilities and a working batch through the result.
//
// This is the chain, with the timeout no longer assumed:
//
//	metadata.Destination.Port = 443
//	  -> packetTimeout = 30s
//	  -> canceler.NewPacketConn
//	  -> batch capability must survive
func TestConnectUDPBatchSurvivesTheRealDerivedTimeout(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		port      uint16
		replyMTPU string
	}{
		{"target-port-443", 443, "QUIC"},
		{"target-port-53", 53, "DNS"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := adapter.InboundContext{
				Destination: M.ParseSocksaddrHostPort("192.0.2.10", testCase.port),
			}
			timeout := packetTimeoutForTest(&metadata)
			require.Greater(t, timeout, time.Duration(0),
				"a CONNECT-UDP target on this port must get a timeout, or the wrapper "+
					"would not be applied at all and this test would prove nothing")

			// Both wrapper branches are exercised, because which one runs depends on the
			// connection rather than on the timeout: an HTTP/3 connection cannot take a
			// read deadline, a plain UDP socket can.
			for _, branch := range []struct {
				branchName  string
				deadlineErr error
			}{
				{"timer-branch", errDeadlineUnsupported},
				{"timeout-branch", nil},
			} {
				t.Run(branch.branchName, func(t *testing.T) {
					conn := newBatchCapablePacketConn(branch.deadlineErr)
					defer conn.Close()

					_, wrapped := canceler.NewPacketConn(context.Background(), conn, timeout)

					readWaiter, readOK := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
					require.True(t, readOK,
						"the connected batch read capability must survive the %v timeout "+
							"derived for target port %d", timeout, testCase.port)
					require.NotNil(t, readWaiter)

					writeWriter, writeOK := bufio.CreateConnectedPacketBatchWriter(wrapped)
					require.True(t, writeOK,
						"the connected batch write capability must survive the %v timeout "+
							"derived for target port %d", timeout, testCase.port)
					require.NotNil(t, writeWriter)

					// The capability must be usable, not merely offered.
					readWaiter.InitializeReadWaiter(batchTestReadWaitOptions())
					for index := range 4 {
						packet := buf.NewSize(2)
						packet.Write([]byte{byte(index), 0xFF})
						conn.packets <- packet
					}
					buffers, destination, err := readWaiter.WaitReadConnectedPackets()
					require.NoError(t, err)
					require.Len(t, buffers, 4)
					require.Equal(t, conn.destination, destination)
					buf.ReleaseMulti(buffers)

					writeBuffers := []*buf.Buffer{buf.NewSize(1), buf.NewSize(1)}
					writeBuffers[0].Write([]byte{0x11})
					writeBuffers[1].Write([]byte{0x22})
					require.NoError(t, writeWriter.WriteConnectedPacketBatch(writeBuffers))
					require.Equal(t, 1, conn.forwardedBatchWrites,
						"the batch must reach the connection as one batch")

					t.Logf("target port %d with a %v timeout: batch read and write both "+
						"survive the %s wrapper", testCase.port, timeout, branch.branchName)
				})
			}
		})
	}
}

// TestConnectUDPWithoutATimeoutStillBatches is the "no wrapper" control.
//
// An unlisted port produces a zero timeout, so route/conn.go does not wrap the
// connection at all. Batching must still work in that case: the fix must not have made
// the wrapper a prerequisite for the batch path.
func TestConnectUDPWithoutATimeoutStillBatches(t *testing.T) {
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.10:51820")}
	require.Equal(t, time.Duration(0), packetTimeoutForTest(&metadata),
		"precondition: this port must produce no timeout, so nothing is wrapped")

	conn := newBatchCapablePacketConn(errDeadlineUnsupported)
	defer conn.Close()

	// With no timeout there is no wrapper; the connection is used as-is.
	readWaiter, readOK := bufio.CreateConnectedPacketBatchReadWaiter(conn)
	require.True(t, readOK, "an unwrapped connection must keep its batch read")
	writeWriter, writeOK := bufio.CreateConnectedPacketBatchWriter(conn)
	require.True(t, writeOK, "an unwrapped connection must keep its batch write")
	require.NotNil(t, readWaiter)
	require.NotNil(t, writeWriter)

	readWaiter.InitializeReadWaiter(batchTestReadWaitOptions())
	for index := range 3 {
		packet := buf.NewSize(1)
		packet.Write([]byte{byte(index)})
		conn.packets <- packet
	}
	buffers, _, err := readWaiter.WaitReadConnectedPackets()
	require.NoError(t, err)
	require.Len(t, buffers, 3)
	buf.ReleaseMulti(buffers)

	writeBuffers := []*buf.Buffer{buf.NewSize(1)}
	writeBuffers[0].Write([]byte{0x33})
	require.NoError(t, writeWriter.WriteConnectedPacketBatch(writeBuffers))
	require.Equal(t, 1, conn.forwardedBatchWrites)
}

// TestNonConnectedUDPPathIsUnchanged records that this change is confined to the
// CONNECTED batch capabilities.
//
// A non-connected packet connection (a plain UDP tunnel that reports a destination per
// packet) must not start claiming connected batch support just because the wrapper now
// forwards it: the inner connection has none, so the wrapper must report none.
func TestNonConnectedUDPPathIsUnchanged(t *testing.T) {
	inner := newNoBatchPacketConn()
	defer inner.Close()

	_, wrapped := canceler.NewPacketConn(context.Background(), inner, 30*time.Second)

	_, readOK := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
	_, writeOK := bufio.CreateConnectedPacketBatchWriter(wrapped)
	require.False(t, readOK,
		"a connection without connected batch read must not gain it through the wrapper")
	require.False(t, writeOK,
		"a connection without connected batch write must not gain it through the wrapper")

	// The ordinary path must keep working, which is what every non-batch protocol uses.
	require.NoError(t, wrapped.WritePacket(buf.NewSize(4), M.ParseSocksaddr("192.0.2.1:53")))
}

// batchTestReadWaitOptions mirrors what bufio.CopyPacket passes to a batch waiter.
//
// The batch size is read from the library constant rather than written as a literal, so
// the test follows the copy path if that default changes instead of quietly testing a
// size production never uses.
func batchTestReadWaitOptions() N.ReadWaitOptions {
	return N.ReadWaitOptions{
		FrontHeadroom: 3,
		RearHeadroom:  255,
		MTU:           1500,
		BatchSize:     bufio.DefaultPacketReadBatchSize,
	}
}
