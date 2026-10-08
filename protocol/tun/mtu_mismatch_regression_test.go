package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// MTU-mismatch coverage for the in-process Go TUN stack.
//
// # The failure this pins
//
// The stack terminates the device's TCP connections, so it is the one that advertises an MSS. If
// that value came from anywhere but the tunnel's own MTU - for example from the peer's SYN, or from
// a compiled-in default - a peer that claims jumbo frames would be told it may send 9000-byte
// segments into a 1280-byte tunnel. The resulting behaviour is not a clean error: the segments
// arrive, the tunnel's own fragmentation drops them or the far end never reassembles them, and the
// connection stalls with no error to attribute. Clamping the advertised value to the configured MTU
// is what makes a mismatch between the two ends degradable instead of fatal.
//
// # Why the harness
//
// Same MemoryTun link as blackhole_connect_regression_test.go: the real engine, a real TCP state
// machine, and the SYN-ACK observed as an actual frame on the wire. The handler reads from the
// accepted connection because that is what keeps the engine's transmit loop turning in this
// configuration; a handler that returns immediately leaves the SYN-ACK queued, which would make the
// test flaky rather than wrong.

// mtuMismatchHandler accepts every TCP flow and drains it so the engine keeps transmitting. It
// records nothing itself: the assertions are about the frames the stack emits.
type mtuMismatchHandler struct {
	accepted atomic.Int64
}

func (h *mtuMismatchHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (h *mtuMismatchHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

func (h *mtuMismatchHandler) NewConnectionEx(_ context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	h.accepted.Add(1)
	go func() {
		buffer := make([]byte, 16)
		_, _ = conn.Read(buffer)
	}()
}

func (h *mtuMismatchHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

// mtuSYN builds a device-side IPv4 SYN that advertises the given MSS, so a test can control what
// the far end claims independently of the tunnel's MTU.
func mtuSYN(sourcePort uint16, destinationPort uint16, advertisedMSS uint16) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+4)
	source := netip.MustParseAddr("198.18.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(packet[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    sourcePort,
		DstPort:    destinationPort,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize + 4,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	options := tcp[header.TCPMinimumSize : header.TCPMinimumSize+4]
	options[0] = header.TCPOptionMSS
	options[1] = 4
	binary.BigEndian.PutUint16(options[2:4], advertisedMSS)
	tcp.SetChecksum(^tcp.CalculateChecksum(header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(tcp.DataOffset()),
	)))
	return packet
}

// mtuStackFixture returns a started Go stack on a MemoryTun and a channel of every frame the stack
// emits, so a test can wait for the SYN-ACK instead of sleeping for it.
type mtuStackFixture struct {
	device *tun.MemoryTun
	stack  tun.Stack
	access sync.Mutex
	frames [][]byte
}

func newMTUStackFixture(t *testing.T, mtu uint32) *mtuStackFixture {
	t.Helper()
	fixture := &mtuStackFixture{}
	handler := &mtuMismatchHandler{}
	fixture.device = tun.NewMemoryTun(tun.MemoryTunOptions{
		MTU: int(mtu),
		Outbound: func(packets []*buf.Buffer) {
			fixture.access.Lock()
			for _, packet := range packets {
				frame := make([]byte, packet.Len())
				copy(frame, packet.Bytes())
				fixture.frames = append(fixture.frames, frame)
			}
			fixture.access.Unlock()
			buf.ReleaseMulti(packets)
		},
	})
	stack, err := tun.NewStack("go", tun.StackOptions{
		Context: context.Background(),
		Tun:     fixture.device,
		TunOptions: tun.Options{
			MTU:          mtu,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
			Logger:       logger.NOP(),
		},
		Handler:     handler,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	fixture.stack = stack
	t.Cleanup(func() {
		_ = stack.Close()
		_ = fixture.device.Close()
	})
	return fixture
}

// waitForSYNACK returns the latest TCP frame with SYN set, waiting for the engine's transmit loop
// rather than assuming it runs within any particular sleep.
func (f *mtuStackFixture) waitForSYNACK(t *testing.T) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.access.Lock()
		var found []byte
		for _, frame := range f.frames {
			if len(frame) < header.IPv4MinimumSize+header.TCPMinimumSize {
				continue
			}
			tcp := header.TCP(frame[header.IPv4MinimumSize:])
			if tcp.Flags()&header.TCPFlagSyn != 0 && tcp.Flags()&header.TCPFlagAck != 0 {
				found = frame
			}
		}
		f.access.Unlock()
		if found != nil {
			return found
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the stack never emitted a SYN-ACK")
	return nil
}

func synACKMSS(t *testing.T, frame []byte) uint16 {
	t.Helper()
	tcp := header.TCP(frame[header.IPv4MinimumSize:])
	dataOffset := int(tcp.DataOffset())
	require.GreaterOrEqual(t, dataOffset, header.TCPMinimumSize)
	require.LessOrEqual(t, dataOffset, len(tcp))
	options := header.ParseSynOptions(tcp[header.TCPMinimumSize:dataOffset], true)
	return options.MSS
}

// TestGoStackAdvertisedMSSIsClampedToTheTunnelMTU is the mismatch regression.
//
// The peer advertises an MSS far larger than any tunnel in the table. Whatever it claims, the value
// the stack advertises back must be derived from the tunnel MTU and must leave room for the IPv4
// and TCP headers, because that is the largest segment the tunnel can actually carry.
func TestGoStackAdvertisedMSSIsClampedToTheTunnelMTU(t *testing.T) {
	for _, mtu := range []uint32{1500, 1280, 900} {
		t.Run(fmt.Sprintf("mtu-%d", mtu), func(t *testing.T) {
			fixture := newMTUStackFixture(t, mtu)

			written, err := fixture.device.WritePackets([][]byte{mtuSYN(46000, 80, 9000)})
			require.NoError(t, err)
			require.Equal(t, 1, written)

			frame := fixture.waitForSYNACK(t)
			require.LessOrEqual(t, len(frame), int(mtu),
				"the stack emitted a frame larger than the tunnel MTU")
			expected := mtu - header.IPv4MinimumSize - header.TCPMinimumSize
			require.EqualValues(t, expected, synACKMSS(t, frame),
				"the advertised MSS must follow the tunnel MTU, not the peer's claim")
		})
	}
}

// TestGoStackAdvertisedMSSIsIndependentOfAPeerClaimBelowTheTunnelMTU is the other half of the
// mismatch: a peer that under-claims must not lower what this stack says it can receive.
//
// The two directions are separate values. Folding the peer's number into the advertised one would
// silently cap the download path at whatever the far end happened to announce for its own receive
// side, which is a different question.
func TestGoStackAdvertisedMSSIsIndependentOfAPeerClaimBelowTheTunnelMTU(t *testing.T) {
	const mtu = 1500
	fixture := newMTUStackFixture(t, mtu)

	written, err := fixture.device.WritePackets([][]byte{mtuSYN(46001, 443, 536)})
	require.NoError(t, err)
	require.Equal(t, 1, written)

	frame := fixture.waitForSYNACK(t)
	require.EqualValues(t, mtu-header.IPv4MinimumSize-header.TCPMinimumSize, synACKMSS(t, frame),
		"a peer's conservative MSS must not lower the value this stack advertises")
}
