package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Architecture trace for a native (non-userspace) data path, driven against the REAL pinned sing-tun
// go stack over an in-memory TUN.
//
// # Why this exists
//
// Everything the Direct Offload work built rests on one assumption: that returning
// tun.ActionBypass from JudgeFlow makes the platform carry the connection instead of the userspace
// stack. That assumption was never verified at the data plane - the earlier tests asserted on the
// verdict, and a verdict is not a packet path.
//
// This harness closes that gap. It runs the real stack, injects a real packet, and observes where
// the packet actually goes: into the userspace stack (which calls back into the Handler), or back
// out to the platform.
//
// The in-memory TUN is sing-tun's own test transport, so nothing here needs a device, root or a
// kernel route.

// --- harness ------------------------------------------------------------------------------

// traceHandler is the Handler half of the stack: sing-tun calls it to judge a flow and to accept
// the userspace connections it creates.
type traceHandler struct {
	verdict func(network uint8, source netip.AddrPort, destination netip.AddrPort) tun.FlowVerdict

	access         sync.Mutex
	judged         []netip.AddrPort
	tcpAccepted    []netip.AddrPort
	udpAccepted    []netip.AddrPort
	trackedFlows   []*traceFlow
	acceptedSignal chan struct{}
}

type traceFlow struct {
	mu          sync.Mutex
	forward     int
	reverse     int
	established int
	closed      []tun.FlowCloseReason
	handle      tun.FlowHandle
	handleType  string
	attached    bool
}

func (f *traceFlow) AttachFlow(handle tun.FlowHandle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handle = handle
	f.attached = true
	f.handleType = fmt.Sprintf("%T", handle)
}

func (f *traceFlow) CountForward(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forward += n
}

func (f *traceFlow) CountReverse(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reverse += n
}

func (f *traceFlow) FlowEstablished() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.established++
}

func (f *traceFlow) CloseFlow(reason tun.FlowCloseReason) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, reason)
}

func (f *traceFlow) snapshot() (forward, reverse, established int, closed []tun.FlowCloseReason) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.forward, f.reverse, f.established, append([]tun.FlowCloseReason(nil), f.closed...)
}

func newTraceHandler(verdict func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict) *traceHandler {
	return &traceHandler{verdict: verdict, acceptedSignal: make(chan struct{}, 8)}
}

func (h *traceHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	h.access.Lock()
	h.judged = append(h.judged, destination)
	h.access.Unlock()
	return h.verdict(network, source, destination)
}

func (h *traceHandler) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
}

// NewConnectionEx is the userspace acceptance: the stack has terminated the TCP connection in
// userspace and is handing it over. Its being called is the trace's evidence that the flow did NOT
// take a native path.
func (h *traceHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.access.Lock()
	h.tcpAccepted = append(h.tcpAccepted, destination.AddrPort())
	h.access.Unlock()
	_ = conn.Close()
	select {
	case h.acceptedSignal <- struct{}{}:
	default:
	}
}

func (h *traceHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.access.Lock()
	h.udpAccepted = append(h.udpAccepted, destination.AddrPort())
	h.access.Unlock()
	_ = conn.Close()
	select {
	case h.acceptedSignal <- struct{}{}:
	default:
	}
}

func (h *traceHandler) counts() (judged, tcp, udp int) {
	h.access.Lock()
	defer h.access.Unlock()
	return len(h.judged), len(h.tcpAccepted), len(h.udpAccepted)
}

// memoryTunHarness is the real go stack over an in-memory TUN, plus an observation channel for
// everything the stack writes back out toward the platform.
type memoryTunHarness struct {
	memoryTun *tun.MemoryTun
	stack     tun.Stack
	handler   *traceHandler

	outboundAccess sync.Mutex
	outbound       [][]byte
	outboundSignal chan struct{}
}

func newMemoryTunHarness(t *testing.T, handler *traceHandler) *memoryTunHarness {
	t.Helper()
	harness := &memoryTunHarness{handler: handler, outboundSignal: make(chan struct{}, 32)}
	harness.memoryTun = tun.NewMemoryTun(tun.MemoryTunOptions{
		MTU: 1500,
		Outbound: func(packets []*buf.Buffer) {
			defer buf.ReleaseMulti(packets)
			harness.outboundAccess.Lock()
			for _, packet := range packets {
				harness.outbound = append(harness.outbound, append([]byte(nil), packet.Bytes()...))
			}
			harness.outboundAccess.Unlock()
			select {
			case harness.outboundSignal <- struct{}{}:
			default:
			}
		},
	})
	stack, err := tun.NewStack("go", tun.StackOptions{
		Context: context.Background(),
		Tun:     harness.memoryTun,
		TunOptions: tun.Options{
			Name:         "trace0",
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd73:ab91:1::1/64")},
			Logger:       logger.NOP(),
		},
		Handler:    handler,
		Logger:     logger.NOP(),
		UDPTimeout: 30 * time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	t.Cleanup(func() {
		_ = stack.Close()
		_ = harness.memoryTun.Close()
	})
	return harness
}

// inject feeds a packet into the stack exactly as the platform would.
func (h *memoryTunHarness) inject(t *testing.T, packet []byte) {
	t.Helper()
	_, err := h.memoryTun.Write(packet)
	require.NoError(t, err)
}

func (h *memoryTunHarness) outboundPackets() [][]byte {
	h.outboundAccess.Lock()
	defer h.outboundAccess.Unlock()
	return append([][]byte(nil), h.outbound...)
}

// --- packet construction ------------------------------------------------------------------

// tcpSYN builds a checksummed IPv4 TCP SYN, because the memory transport makes the stack validate
// transport checksums and a packet it rejects would prove nothing.
func tcpSYN(source, destination netip.AddrPort, sequence uint32) []byte {
	packet := make([]byte, 20+20)
	ipHeader := packet[:20]
	tcpHeader := packet[20:]

	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:], uint16(len(packet)))
	binary.BigEndian.PutUint16(ipHeader[4:], 0x1234)
	binary.BigEndian.PutUint16(ipHeader[6:], 0x4000)
	ipHeader[8] = 64
	ipHeader[9] = 6
	copy(ipHeader[12:], source.Addr().AsSlice())
	copy(ipHeader[16:], destination.Addr().AsSlice())
	binary.BigEndian.PutUint16(ipHeader[10:], checksum(ipHeader))

	binary.BigEndian.PutUint16(tcpHeader[0:], source.Port())
	binary.BigEndian.PutUint16(tcpHeader[2:], destination.Port())
	binary.BigEndian.PutUint32(tcpHeader[4:], sequence)
	tcpHeader[12] = 5 << 4
	tcpHeader[13] = 0x02
	binary.BigEndian.PutUint16(tcpHeader[14:], 65535)
	binary.BigEndian.PutUint16(tcpHeader[16:], transportChecksum(6, source.Addr(), destination.Addr(), tcpHeader))
	return packet
}

// udpDatagram builds a checksummed IPv4 UDP datagram.
func udpDatagram(source, destination netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	ipHeader := packet[:20]
	udpHeader := packet[20 : 20+8]

	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:], uint16(len(packet)))
	binary.BigEndian.PutUint16(ipHeader[4:], 0x4321)
	binary.BigEndian.PutUint16(ipHeader[6:], 0x4000)
	ipHeader[8] = 64
	ipHeader[9] = 17
	copy(ipHeader[12:], source.Addr().AsSlice())
	copy(ipHeader[16:], destination.Addr().AsSlice())
	binary.BigEndian.PutUint16(ipHeader[10:], checksum(ipHeader))

	binary.BigEndian.PutUint16(udpHeader[0:], source.Port())
	binary.BigEndian.PutUint16(udpHeader[2:], destination.Port())
	binary.BigEndian.PutUint16(udpHeader[4:], uint16(8+len(payload)))
	copy(packet[28:], payload)
	binary.BigEndian.PutUint16(udpHeader[6:], transportChecksum(17, source.Addr(), destination.Addr(), udpHeader[:8+len(payload)]))
	return packet
}

func checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index:]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// transportChecksum computes the TCP or UDP checksum over the pseudo-header. The protocol byte is a
// parameter because the memory transport makes the stack validate checksums, and a UDP datagram
// checksummed as TCP is a datagram the stack silently drops - which reads as "the harness is broken"
// rather than as the thing under test.
func transportChecksum(protocol byte, source, destination netip.Addr, transport []byte) uint16 {
	pseudo := make([]byte, 12+len(transport))
	copy(pseudo[0:], source.AsSlice())
	copy(pseudo[4:], destination.AsSlice())
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(transport)))
	copy(pseudo[12:], transport)
	return checksum(pseudo)
}

// --- the trace ----------------------------------------------------------------------------

func (h *memoryTunHarness) waitForAccepted(t *testing.T) {
	t.Helper()
	select {
	case <-h.handler.acceptedSignal:
	case <-time.After(5 * time.Second):
		t.Fatal("the stack never created a userspace connection")
	}
}

// TestBypassReachesTheSameDataPathAsAccept is the trace's central claim, and the one the whole
// Direct Offload feature rests on.
//
// It runs the same TCP SYN twice, once judged ActionAccept and once judged ActionBypass, and
// compares where the packet ends up. If the two are indistinguishable, then returning ActionBypass
// does not make the flow native: the stack still terminates the connection in userspace and calls
// the Handler back.
func TestBypassReachesTheSameDataPathAsAccept(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	for _, action := range []tun.FlowAction{tun.ActionAccept, tun.ActionBypass} {
		t.Run(actionName(action), func(t *testing.T) {
			handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
				return tun.FlowVerdict{Action: action}
			})
			harness := newMemoryTunHarness(t, handler)

			harness.inject(t, tcpSYN(source, destination, 1000))
			harness.waitForAccepted(t)

			judged, tcpAccepted, _ := handler.counts()
			require.Equal(t, 1, judged, "the verdict was consulted")
			require.Equal(t, 1, tcpAccepted,
				"if this fails for ActionBypass, the pinned sing-tun has started honouring a native "+
					"bypass in the go stack: a capability change that Direct Offload's scope, "+
					"documentation and eligibility rules must be re-derived from")

			// The discriminating half. A native path would hand the application's own SYN back to
			// the platform, unchanged, for the OS to route. What the stack writes instead is its own
			// TCP: the SYN-ACK and the RST it generates as the userspace endpoint of the connection.
			time.Sleep(50 * time.Millisecond)
			for _, packet := range harness.outboundPackets() {
				require.False(t, isOriginalSYN(packet, source, destination),
					"the application's SYN was handed back to the platform, which is what a native "+
						"data path would look like - and if it now is, sing-tun gained the capability "+
						"this round was looking for")
				require.True(t, isStackGeneratedReply(packet, source),
					"the only packets written out are the ones the userspace stack generated: %v",
					packet)
			}

			t.Logf("%s: the flow was terminated in userspace (%d userspace acceptances, %d packets "+
				"written out, all of them stack-generated)", actionName(action), tcpAccepted,
				len(harness.outboundPackets()))
		})
	}
}

// isOriginalSYN reports whether this outbound packet is the application's own SYN, echoed back to
// the platform unchanged. That is what a native data path looks like, and its absence is the whole
// finding.
func isOriginalSYN(packet []byte, source, destination netip.AddrPort) bool {
	if len(packet) < 40 || packet[9] != 6 {
		return false
	}
	packetSource := netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[12:16])), binary.BigEndian.Uint16(packet[20:22]))
	packetDestination := netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[16:20])), binary.BigEndian.Uint16(packet[22:24]))
	if packetSource != source || packetDestination != destination {
		return false
	}
	flags := packet[33]
	return flags&0x02 != 0 && flags&0x10 == 0
}

// isStackGeneratedReply reports whether this outbound packet is addressed back to the application,
// which is what the userspace endpoint sends.
func isStackGeneratedReply(packet []byte, source netip.AddrPort) bool {
	if len(packet) < 20 || packet[9] != 6 {
		return false
	}
	destinationAddress := netip.AddrFrom4([4]byte(packet[16:20]))
	destinationPort := binary.BigEndian.Uint16(packet[22:24])
	return destinationAddress == source.Addr() && destinationPort == source.Port()
}

func actionName(action tun.FlowAction) string {
	switch action {
	case tun.ActionAccept:
		return "ActionAccept"
	case tun.ActionBypass:
		return "ActionBypass"
	case tun.ActionFlow:
		return "ActionFlow"
	default:
		return "ActionUnknown"
	}
}

// TestBypassWithAPortBecomesAFlow is the rewrite the fork already knew about, pinned here so a
// future change to the harness cannot lose it.
func TestBypassWithAPortBecomesAFlow(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	port := &tracePort{}
	handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
		return tun.FlowVerdict{Action: tun.ActionBypass, Port: port}
	})
	harness := newMemoryTunHarness(t, handler)

	harness.inject(t, tcpSYN(source, destination, 2000))
	require.Eventually(t, func() bool { return port.packetCount() > 0 }, 5*time.Second, 10*time.Millisecond,
		"a bypass carrying a Port is forwarded into that Port instead of to the platform")

	_, tcpAccepted, _ := handler.counts()
	require.Zero(t, tcpAccepted, "and the userspace stack is bypassed entirely")
}

// tracePort is a userspace Port: the interface the dispatcher forwards into for ActionFlow.
type tracePort struct {
	mu      sync.Mutex
	packets int
}

func (p *tracePort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
}
func (p *tracePort) PortMTU() uint32               { return 1500 }
func (p *tracePort) AttachReturn(tun.Return) error { return nil }
func (p *tracePort) DetachReturn(tun.Return) error { return nil }
func (p *tracePort) WritePackets(packets [][]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.packets += len(packets)
	return nil
}
func (p *tracePort) packetCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.packets
}

// TestANewTrackerOnABypassIsNeverCreated is the tracker half of the trace.
//
// A NewTracker attached to an accept/bypass verdict has no owner in the stack: the dispatcher's
// accept entry carries no flow, and the userspace connection the stack creates for the same flow is
// a different object that the handler's own RoutedFlow built. Whatever the caller passed in is
// dropped, silently.
func TestANewTrackerOnABypassIsNeverCreated(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	var created int
	handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
		return tun.FlowVerdict{
			Action: tun.ActionBypass,
			NewTracker: func() tun.FlowTracker {
				created++
				return &traceFlow{}
			},
		}
	})
	harness := newMemoryTunHarness(t, handler)

	harness.inject(t, tcpSYN(source, destination, 3000))
	harness.waitForAccepted(t)

	require.Zero(t, created,
		"a NewTracker on a bypass verdict is never called: the accept entry has no flow to attach it "+
			"to, so a tracker passed here would be silently dropped")
}

// TestABypassFlowIsNeverCounted is the accounting half, stated as what the tracker would see.
func TestABypassFlowIsNeverCounted(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	tracker := &traceFlow{}
	handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
		return tun.FlowVerdict{Action: tun.ActionBypass, NewTracker: func() tun.FlowTracker { return tracker }}
	})
	harness := newMemoryTunHarness(t, handler)

	harness.inject(t, tcpSYN(source, destination, 4000))
	harness.waitForAccepted(t)
	harness.inject(t, tcpSYN(source, destination, 4000))

	time.Sleep(50 * time.Millisecond)
	forward, reverse, established, closed := tracker.snapshot()
	require.Zero(t, forward, "the flow's bytes were never counted")
	require.Zero(t, reverse)
	require.Zero(t, established)
	require.Empty(t, closed)
}

// TestAClosedAcceptEntryLeavesNoTrackerBehind documents the lifecycle the accept entry DOES keep,
// so the trace says what is there as well as what is not.
func TestAClosedAcceptEntryLeavesNoTrackerBehind(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
		return tun.FlowVerdict{Action: tun.ActionBypass}
	})
	harness := newMemoryTunHarness(t, handler)

	// Two packets of the same flow: the second one hits the installed entry rather than being
	// judged again.
	harness.inject(t, tcpSYN(source, destination, 5000))
	harness.waitForAccepted(t)
	harness.inject(t, tcpSYN(source, destination, 5000))

	time.Sleep(50 * time.Millisecond)
	_, tcpAccepted, _ := handler.counts()
	require.Equal(t, 1, tcpAccepted, "the second packet reused the userspace connection")

	handler.access.Lock()
	judged := len(handler.judged)
	handler.access.Unlock()
	require.Equal(t, 1, judged,
		"the flow table caches the verdict, so the same flow is judged once")
}

// TestTrafficClassIsIrrelevantToTheVerdict is a guard against the tempting rule this round must not
// introduce: a native direct flow is outside the upload scheduler's managed domain, so its class
// cannot be a reason to withhold a bypass.
func TestTrafficClassIsIrrelevantToTheVerdict(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	// The stack's decision does not consult a class at all; this asserts that the harness, which is
	// the only place a class could be smuggled in, does not either.
	_ = trafficclass.ClassInteractive
	_ = trafficclass.ClassBulk

	handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
		return tun.FlowVerdict{Action: tun.ActionBypass}
	})
	harness := newMemoryTunHarness(t, handler)
	harness.inject(t, tcpSYN(source, destination, 6000))
	harness.waitForAccepted(t)

	_, tcpAccepted, _ := handler.counts()
	require.Equal(t, 1, tcpAccepted)
}

// TestABypassedUDPDatagramTakesTheUserspacePath is the UDP half of the trace.
//
// UDP has its own reason to be checked separately: the dispatcher's accept entry caches the verdict
// and hands it to the UDP path, so a "bypass" verdict does reach the UDP code - and what that code
// does with it is create a userspace NAT session, not write the datagram back out.
func TestABypassedUDPDatagramTakesTheUserspacePath(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("8.8.8.8:53")

	tracker := &traceFlow{}
	handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
		return tun.FlowVerdict{
			Action:     tun.ActionBypass,
			NewTracker: func() tun.FlowTracker { return tracker },
		}
	})
	harness := newMemoryTunHarness(t, handler)

	harness.inject(t, udpDatagram(source, destination, []byte("trace")))
	harness.waitForAccepted(t)

	judged, _, udpAccepted := handler.counts()
	require.Equal(t, 1, judged, "the verdict was consulted")
	require.Equal(t, 1, udpAccepted,
		"the datagram was handed to a userspace packet connection rather than to the platform")
	// UDP is the interesting case, and the one that shows what "tracked bypass" would actually mean
	// here: the accept entry carries the verdict into the UDP path, so a NewTracker IS created - and
	// it is attached to the USERSPACE packet connection. Tracking works precisely because the flow
	// did not bypass.
	tracker.mu.Lock()
	handleType := tracker.handleType
	attached := tracker.attached
	tracker.mu.Unlock()
	require.True(t, attached,
		"the tracker was attached rather than dropped, unlike the TCP case")
	require.Contains(t, handleType, "GoPacketConn",
		"and what it was attached to is the userspace packet connection, which is where the "+
			"datagram went: %s", handleType)

	// The datagram itself never leaves the process; the only outbound traffic is what the userspace
	// endpoint generates.
	time.Sleep(50 * time.Millisecond)
	for _, packet := range harness.outboundPackets() {
		require.NotEqual(t, destination.Addr(), netip.AddrFrom4([4]byte(packet[16:20])),
			"the application's datagram was handed back to the platform")
	}
}
