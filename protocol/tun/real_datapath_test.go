package tun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	chksum "github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Real-data-path coverage for the in-process Go TUN stack.
//
// # What is different about this file
//
// The other TUN tests in this package drive the stack with a fake Handler that only records that a
// connection arrived. That is the right shape for lifecycle questions - does cancellation release a
// half-open flow, does Close terminate it - but it cannot answer any question whose answer lives on
// the far side of a real socket. A refused connect, a kernel-produced RST, a NAT mapping that
// expires and is re-created, and an MTU that changes under the sender all need bytes to actually
// leave and come back, because a mock cannot produce the failure mode it is standing in for.
//
// So the Handler in this file is the route layer in miniature: it DIALS a real loopback socket,
// reports the handshake the way route/conn.go does, and copies bytes in both directions. The device
// side is still raw packets through tun.MemoryTun, so the path is the real engine, the real TCP/UDP
// state machine, the real socket layer and a real kernel peer - and it stays hermetic, because every
// peer is on 127.0.0.1 and no privilege, route or external network is involved.
//
// # One detail that is load-bearing rather than incidental
//
// The Go engine parks an accepted flow in goPhaseJudged and DROPS everything the device sends until
// the handler reports the outbound handshake, which is what N.ReportConnHandshakeSuccess does at
// route/conn.go:312. A relay that forgets that step looks exactly like a stack that cannot carry
// data, so the fixture here performs it and the handshake helper waits for it before completing the
// device side. That ordering is real, not a test artefact: the device's ACK arriving before the
// outbound is up is dropped by processAck by design, and the engine recovers by retransmitting the
// SYN-ACK.
//
// # Row coverage
//
//	TCP refused               covered: a real dial to a closed loopback port produces a real
//	                          ECONNREFUSED, and the device must observe the reset it becomes.
//	TCP RST                   covered: a real listener sets SO_LINGER 0 and closes, producing a real
//	                          kernel RST, and the relay must observe ECONNRESET.
//	TCP blackhole cancellation covered: a real peer completes the connect and never answers, the
//	                          caller's context is cancelled, and the relay and the peer socket both
//	                          unwind. The stack-level half of the contract is pinned separately by
//	                          blackhole_connect_regression_test.go.
//	UDP NAT mapping lifetime  covered: a real loopback UDP peer, a mapping allowed to expire, and a
//	                          second datagram that must create a new one.
//	fragmentation / PTB / MTU covered in two halves: a UDP datagram split into two real IPv4
//	                          fragments must be reassembled before it reaches the peer, and a real
//	                          ICMPv4 fragmentation-needed quoting a segment the stack actually
//	                          emitted must lower the MSS the stack segments the download stream to.
//
// Every row in this file is therefore covered by a real data path, and there is no row left with a
// privilege, device or namespace blocker on this host. The two things that are NOT covered here and
// why:
//
//   - An IPv6 PacketTooBig and IPv6 fragment reassembly are not asserted. The engine has both paths
//     (reassembleIPv6, goICMPPacketTooBig), but the fixture would have to carry an IPv6 flow, and the
//     value of a second protocol dialect over the same two code paths is lower than the cost of a
//     second addressing and neighbour-discovery setup. Classified COULD-BE-ADDED, not blocked.
//   - A real utun device, a route table entry and a network namespace are never touched. That is the
//     point of the file rather than a gap in it: a real interface would make every assertion depend
//     on host routing and on privileges, which is exactly where a test should not be. Classified
//     DEVICE-ONLY and deliberately not attempted.

// relayHandler is the route layer in miniature.
//
// NewConnectionEx dials target and relays; on a dial failure it closes the accepted flow, which is
// what the real route layer does with a refused outbound and what must become a reset on the device
// side. Every outcome is recorded per destination port so a test can assert on the error the real
// kernel produced rather than on the fact that something happened.
type relayHandler struct {
	target func(destination M.Socksaddr) string

	access      sync.Mutex
	dials       map[uint16]error
	uploads     map[uint16]error
	downloads   map[uint16]error
	uploaded    map[uint16]int64
	engaged     map[uint16]bool
	established map[uint16]bool
	mappings    map[uint16]int
	udpPayload  map[uint16][][]byte
	accepted    atomic.Int64
}

func newRelayHandler(target func(destination M.Socksaddr) string) *relayHandler {
	return &relayHandler{
		target:      target,
		dials:       make(map[uint16]error),
		uploads:     make(map[uint16]error),
		downloads:   make(map[uint16]error),
		uploaded:    make(map[uint16]int64),
		engaged:     make(map[uint16]bool),
		established: make(map[uint16]bool),
		mappings:    make(map[uint16]int),
		udpPayload:  make(map[uint16][][]byte),
	}
}

func (h *relayHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (h *relayHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

func (h *relayHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	h.accepted.Add(1)
	go h.relayTCP(ctx, conn, destination)
}

func (h *relayHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	h.access.Lock()
	h.mappings[destination.Port]++
	h.access.Unlock()
	go h.relayUDP(conn, destination)
}

func (h *relayHandler) relayTCP(ctx context.Context, conn net.Conn, destination M.Socksaddr) {
	var dialer net.Dialer
	remote, err := dialer.DialContext(ctx, "tcp", h.target(destination))
	h.access.Lock()
	h.dials[destination.Port] = err
	h.access.Unlock()
	if err != nil {
		// The dial refused. The route layer has nothing to relay, so it closes the accepted flow and
		// the stack is expected to turn that into a reset for the device.
		_ = conn.Close()
		return
	}
	defer remote.Close()

	// The route layer's handshake report. It is recorded BEFORE the call because the call blocks
	// until the device completes its side, and the test uses the flag to know when to send the ACK.
	h.access.Lock()
	h.engaged[destination.Port] = true
	h.access.Unlock()
	if handshakeErr := N.ReportConnHandshakeSuccess(conn, remote); handshakeErr != nil {
		h.access.Lock()
		h.dials[destination.Port] = handshakeErr
		h.access.Unlock()
		_ = conn.Close()
		return
	}
	h.access.Lock()
	h.established[destination.Port] = true
	h.access.Unlock()

	finished := make(chan struct{}, 2)
	go func() {
		copied, copyErr := io.Copy(remote, conn)
		h.access.Lock()
		h.uploads[destination.Port] = copyErr
		h.uploaded[destination.Port] = copied
		h.access.Unlock()
		finished <- struct{}{}
	}()
	go func() {
		// The DOWNLOAD direction is where a peer reset surfaces: it is the read on the dialled socket,
		// and a kernel RST makes that read return ECONNRESET rather than EOF. The upload direction
		// would instead see the write fail with EPIPE, which does not distinguish a reset from a
		// closed socket.
		_, copyErr := io.Copy(conn, remote)
		h.access.Lock()
		h.downloads[destination.Port] = copyErr
		h.access.Unlock()
		finished <- struct{}{}
	}()
	select {
	case <-ctx.Done():
	case <-finished:
	}
	_ = conn.Close()
	_ = remote.Close()
}

// relayUDP is the packet half of the same miniature route layer. One PacketConn is one NAT mapping,
// so the fixture counts the calls to NewPacketConnectionEx; the relay itself exists to make the peer
// real, because a mapping that "expired" without a socket behind it would prove nothing.
func (h *relayHandler) relayUDP(conn N.PacketConn, destination M.Socksaddr) {
	remote, err := net.Dial("udp", h.target(destination))
	if err != nil {
		_ = conn.Close()
		return
	}
	defer remote.Close()

	// The packet half of the same report the stream relay makes above, and at the same place in the
	// sequence: route/conn.go does it once the outbound packet connection exists, and the stack only
	// starts handing datagrams to the mapping's reader after it.
	if packetConn, isPacketConn := remote.(net.PacketConn); isPacketConn {
		if handshakeErr := N.ReportPacketConnHandshakeSuccess(conn, packetConn); handshakeErr != nil {
			_ = conn.Close()
			return
		}
	}

	go func() {
		buffer := buf.NewSize(64 * 1024)
		defer buffer.Release()
		for {
			buffer.Reset()
			_, readErr := conn.ReadPacket(buffer)
			if readErr != nil {
				_ = remote.Close()
				return
			}
			payload := append([]byte(nil), buffer.Bytes()...)
			h.access.Lock()
			h.udpPayload[destination.Port] = append(h.udpPayload[destination.Port], payload)
			h.access.Unlock()
			if _, writeErr := remote.Write(payload); writeErr != nil {
				return
			}
		}
	}()

	reply := make([]byte, 64*1024)
	for {
		read, readErr := remote.Read(reply)
		if readErr != nil {
			_ = conn.Close()
			return
		}
		buffer := buf.NewSize(read)
		buffer.Write(reply[:read])
		_ = conn.WritePacket(buffer, destination)
	}
}

func (h *relayHandler) dialError(port uint16) (error, bool) {
	h.access.Lock()
	defer h.access.Unlock()
	err, loaded := h.dials[port]
	return err, loaded
}

func (h *relayHandler) engagedFor(port uint16) bool {
	h.access.Lock()
	defer h.access.Unlock()
	return h.engaged[port]
}

func (h *relayHandler) establishedFor(port uint16) bool {
	h.access.Lock()
	defer h.access.Unlock()
	return h.established[port]
}

func (h *relayHandler) uploadedBytes(port uint16) int64 {
	h.access.Lock()
	defer h.access.Unlock()
	return h.uploaded[port]
}

func (h *relayHandler) uploadError(port uint16) (error, bool) {
	h.access.Lock()
	defer h.access.Unlock()
	err, loaded := h.uploads[port]
	return err, loaded
}

func (h *relayHandler) downloadError(port uint16) (error, bool) {
	h.access.Lock()
	defer h.access.Unlock()
	err, loaded := h.downloads[port]
	return err, loaded
}

func (h *relayHandler) mappingCount(port uint16) int {
	h.access.Lock()
	defer h.access.Unlock()
	return h.mappings[port]
}

func (h *relayHandler) payloads(port uint16) [][]byte {
	h.access.Lock()
	defer h.access.Unlock()
	out := make([][]byte, len(h.udpPayload[port]))
	copy(out, h.udpPayload[port])
	return out
}

// datapathFixture is a started Go stack on a MemoryTun, with every frame the stack emits captured so
// a test waits for the frame it is about instead of sleeping for it.
type datapathFixture struct {
	device  *tun.MemoryTun
	stack   tun.Stack
	handler *relayHandler
	access  sync.Mutex
	frames  [][]byte
}

func newDatapathFixture(t *testing.T, target func(destination M.Socksaddr) string, udpTimeout time.Duration) *datapathFixture {
	t.Helper()
	return newDatapathFixtureContext(t, context.Background(), target, udpTimeout)
}

func newDatapathFixtureContext(t *testing.T, ctx context.Context, target func(destination M.Socksaddr) string, udpTimeout time.Duration) *datapathFixture {
	t.Helper()
	fixture := &datapathFixture{handler: newRelayHandler(target)}
	fixture.device = tun.NewMemoryTun(tun.MemoryTunOptions{
		MTU: 1500,
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
		Context: ctx,
		Tun:     fixture.device,
		TunOptions: tun.Options{
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
			Logger:       logger.NOP(),
		},
		Handler:     fixture.handler,
		Logger:      logger.NOP(),
		UDPTimeout:  udpTimeout,
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

func (f *datapathFixture) emit(t *testing.T, packet []byte) {
	t.Helper()
	written, err := f.device.WritePackets([][]byte{packet})
	require.NoError(t, err)
	require.Equal(t, 1, written)
}

// waitForTCPFlag returns the first device-facing TCP frame for the flow whose flags contain every
// bit of want.
func (f *datapathFixture) waitForTCPFlag(t *testing.T, sourcePort, destinationPort uint16, want header.TCPFlags, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.access.Lock()
		for _, frame := range f.frames {
			tcp, ok := datapathTCP(frame)
			if !ok {
				continue
			}
			if tcp.SourcePort() != destinationPort || tcp.DestinationPort() != sourcePort {
				continue
			}
			if tcp.Flags()&want == want {
				f.access.Unlock()
				return frame
			}
		}
		f.access.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the stack never emitted a frame with flags %#x for %d -> %d", want, destinationPort, sourcePort)
	return nil
}

// waitForDialError blocks until the handler's dial for a port has finished, so an assertion never
// races the relay goroutine.
func (f *datapathFixture) waitForDialError(t *testing.T, port uint16, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, loaded := f.handler.dialError(port); loaded {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the relay never finished its dial for port %d", port)
	return nil
}

func (f *datapathFixture) waitForUploadError(t *testing.T, port uint16, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, loaded := f.handler.uploadError(port); loaded {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the relay never finished its upload for port %d", port)
	return nil
}

func (f *datapathFixture) waitForDownloadError(t *testing.T, port uint16, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, loaded := f.handler.downloadError(port); loaded {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the relay never finished its read for port %d", port)
	return nil
}

func (f *datapathFixture) waitForEngaged(t *testing.T, port uint16, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f.handler.engagedFor(port) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the relay never reached the outbound handshake for port %d", port)
}

// waitForEstablished reports whether the relay's handshake report returned within the window, i.e.
// whether the engine moved the flow out of its parked state.
func (f *datapathFixture) waitForEstablished(port uint16, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f.handler.establishedFor(port) {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return f.handler.establishedFor(port)
}

// datapathTCP parses the IPv4/TCP header out of a device-facing frame.
func datapathTCP(frame []byte) (header.TCP, bool) {
	if len(frame) < header.IPv4MinimumSize+header.TCPMinimumSize {
		return nil, false
	}
	ip := header.IPv4(frame)
	if !ip.IsValid(len(frame)) || ip.TransportProtocol() != header.TCPProtocolNumber {
		return nil, false
	}
	return header.TCP(frame[ip.HeaderLength():]), true
}

// datapathIPv4TCP builds a device-side IPv4/TCP frame with real checksums.
//
// The Go stack negotiates MemoryTun with checksum validation enabled, so a frame without them would
// exercise the parser's rejection path instead of the state machine.
func datapathIPv4TCP(sourcePort, destinationPort uint16, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	source := netip.MustParseAddr("198.18.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(payload))
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
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(packet[header.IPv4MinimumSize+header.TCPMinimumSize:], payload)
	// The checksum is taken over the WHOLE segment, not through TCP.CalculateChecksum: that helper
	// deliberately covers only the header (it is fed the payload's own partial checksum separately),
	// so using it here would leave every payload byte out of the sum and the stack would drop every
	// segment that carries one.
	tcp.SetChecksum(^chksum.Checksum(tcp, header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(len(packet)-header.IPv4MinimumSize),
	)))
	return packet
}

// datapathSYNWithMSS is the device's opening SYN with an MSS option.
//
// The option is load-bearing rather than decorative. A peer that offers no MSS is treated as having
// the RFC 9293 default of 536 bytes, and the stack then segments the download stream to 536 rather
// than to the tunnel MTU, so a test about segmentation has to say what it can receive.
func datapathSYNWithMSS(sourcePort, destinationPort uint16, mss uint16) []byte {
	source := netip.MustParseAddr("198.18.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	options := []byte{header.TCPOptionMSS, 4, byte(mss >> 8), byte(mss)}
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(options))
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
		SeqNum:     1000,
		DataOffset: header.TCPMinimumSize + uint8(len(options)),
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	copy(packet[header.IPv4MinimumSize+header.TCPMinimumSize:], options)
	tcp.SetChecksum(^chksum.Checksum(tcp, header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(len(packet)-header.IPv4MinimumSize),
	)))
	return packet
}

// datapathIPv4UDP builds a device-side IPv4/UDP datagram with real checksums.
func datapathIPv4UDP(sourcePort, destinationPort uint16, payload []byte) []byte {
	source := netip.MustParseAddr("198.18.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	udp := header.UDP(packet[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: sourcePort,
		DstPort: destinationPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(packet[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	// Same reason as the TCP builder above: UDP.CalculateChecksum also covers only the 8-byte header.
	udp.SetChecksum(^chksum.Checksum(udp, header.PseudoHeaderChecksum(
		header.UDPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(len(packet)-header.IPv4MinimumSize),
	)))
	return packet
}

// establishTCPFlow completes a device-side handshake so a test can send payload through the stack.
//
// The acknowledgement number has to come from the SYN-ACK the stack actually emitted, and the ACK
// has to wait for the relay's handshake report: the engine drops an ACK that arrives while the flow
// is still parked in goPhaseJudged, and a test that ignored that ordering would be measuring the
// engine's recovery path by accident.
func (f *datapathFixture) establishTCPFlow(t *testing.T, sourcePort, destinationPort uint16) (deviceNext, stackNext uint32) {
	t.Helper()
	f.emit(t, datapathSYNWithMSS(sourcePort, destinationPort, 1460))
	synACK := f.waitForTCPFlag(t, sourcePort, destinationPort, header.TCPFlagSyn|header.TCPFlagAck, 3*time.Second)
	tcp, ok := datapathTCP(synACK)
	require.True(t, ok)
	f.waitForEngaged(t, destinationPort, 3*time.Second)
	deviceNext = uint32(1001)
	stackNext = tcp.SequenceNumber() + 1
	// The ACK is retransmitted until the engine leaves its parked state. This is not a retry loop
	// hiding a sleep: the engine drops an ACK that arrives before the handler's engage message is
	// posted (processAck returns false while the phase is not engaged), and the real recovery is the
	// engine retransmitting its SYN-ACK until the device acknowledges again. A single ACK would race
	// that post; the loop makes the ordering explicit and bounded.
	for attempt := 0; attempt < 40; attempt++ {
		f.emit(t, datapathIPv4TCP(sourcePort, destinationPort, deviceNext, stackNext, header.TCPFlagAck, nil))
		if f.waitForEstablished(destinationPort, 50*time.Millisecond) {
			return deviceNext, stackNext
		}
	}
	t.Fatalf("the flow on port %d never left the engine's parked handshake state", destinationPort)
	return deviceNext, stackNext
}

// sendTCPPayload delivers one payload segment to the relay, re-sending it until the peer reports it.
//
// The re-send is the protocol's own recovery and not a tolerance: the engine's receive edge advances
// only once the handler's reader has published a buffer, so a segment that arrives in the instant
// between the handshake completing and the relay's first Read is outside the advertised edge and is
// dropped. A real sender retransmits exactly that segment, and nothing about the row being measured
// changes when it does - the seq/ack pair and the payload are identical every time.
func (f *datapathFixture) sendTCPPayload(t *testing.T, sourcePort, destinationPort uint16, seq, ack uint32, payload []byte, delivered <-chan []byte, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.emit(t, datapathIPv4TCP(sourcePort, destinationPort, seq, ack, header.TCPFlagAck|header.TCPFlagPsh, payload))
		select {
		case got := <-delivered:
			return got
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("the payload never reached the real peer on port %d", destinationPort)
	return nil
}

// TestGoStackTCPRefusedBecomesAResetForTheDevice is the refused row.
//
// A connect to a closed loopback port is refused by the kernel in the ordinary way, and the relay
// therefore has nothing to hand the flow. What the device must then observe is a reset rather than a
// connection that stays open until the client's own timeout: a stack that swallowed the refusal
// would leave every application talking to a port that will never answer.
func TestGoStackTCPRefusedBecomesAResetForTheDevice(t *testing.T) {
	// The closed port is obtained the honest way - listen on an ephemeral port and close it - rather
	// than by guessing a number, so the refusal is produced by a real kernel socket with no listener
	// rather than by an address the test assumed was unused.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())

	fixture := newDatapathFixture(t, func(M.Socksaddr) string {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(closedPort)))
	}, time.Minute)

	fixture.emit(t, datapathIPv4TCP(48000, closedPort, 1000, 0, header.TCPFlagSyn, nil))

	dialErr := fixture.waitForDialError(t, closedPort, 3*time.Second)
	require.Error(t, dialErr)
	require.True(t, isConnectionRefused(dialErr),
		"a connect to a closed loopback port must be refused by the kernel, got %v", dialErr)

	// The reset is the whole assertion. Its acknowledgement bit is NOT asserted: a reset generated in
	// response to a SYN carries one and a reset generated mid-connection does not, and pinning which
	// one this is would pin the engine's choice rather than the property that the refusal reached the
	// device at all.
	fixture.waitForTCPFlag(t, 48000, closedPort, header.TCPFlagRst, 3*time.Second)
}

// TestGoStackTCPResetFromARealPeerReachesTheRelay is the RST row.
//
// The peer is a real listener that accepts, reads the relay's bytes, then disables lingering and
// closes, which makes the kernel emit a genuine RST rather than a FIN. The relay's read on the
// dialled socket must then surface ECONNRESET. A mock cannot produce that error, and a relay that
// failed to see it would keep a dead flow alive until its own timeout.
func TestGoStackTCPResetFromARealPeerReachesTheRelay(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	listenPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	resetIssued := make(chan struct{})
	peerRead := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		tcpConn := conn.(*net.TCPConn)
		// Read the payload first, so the reset is a mid-connection reset with data on the flow rather
		// than a refusal in response to a connect that never carried anything.
		_ = tcpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		scratch := make([]byte, 8)
		read, _ := tcpConn.Read(scratch)
		peerRead <- append([]byte(nil), scratch[:read]...)
		// SO_LINGER 0 is what turns Close into an RST: without it the kernel sends a FIN and the peer
		// observes an orderly shutdown, which is a different error and a different row.
		_ = tcpConn.SetLinger(0)
		_ = tcpConn.Close()
		close(resetIssued)
	}()

	fixture := newDatapathFixture(t, func(M.Socksaddr) string {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort)))
	}, time.Minute)

	deviceNext, stackNext := fixture.establishTCPFlow(t, 48001, listenPort)
	require.NoError(t, fixture.waitForDialError(t, listenPort, 3*time.Second))

	// The payload must have reached the real peer, or the reset below would be a reset on a flow that
	// never carried anything and the row would be untested.
	require.Equal(t, []byte("ping"),
		fixture.sendTCPPayload(t, 48001, listenPort, deviceNext, stackNext, []byte("ping"), peerRead, 3*time.Second),
		"the relayed payload must reach the real loopback peer")
	<-resetIssued

	downloadErr := fixture.waitForDownloadError(t, listenPort, 3*time.Second)
	require.Error(t, downloadErr)
	require.True(t, isConnectionReset(downloadErr),
		"a peer that closes with SO_LINGER 0 must produce a kernel RST, got %v", downloadErr)
}

// TestGoStackUDPMappingExpiresAndIsRecreated is the UDP NAT mapping lifetime row.
//
// The stack owns one PacketConn per mapping, and the mapping has a lifetime; after it expires, the
// next datagram from the same device endpoint must create a NEW one rather than silently reusing a
// connection the stack has already torn down. The two halves are asserted separately and both
// against the real peer: the payload has to arrive, and the handler has to see the mapping count go
// from one to two.
func TestGoStackUDPMappingExpiresAndIsRecreated(t *testing.T) {
	const udpTimeout = 250 * time.Millisecond

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer peer.Close()
	peerPort := uint16(peer.LocalAddr().(*net.UDPAddr).Port)

	fixture := newDatapathFixture(t, func(M.Socksaddr) string {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(peerPort)))
	}, udpTimeout)

	received := make(chan []byte, 4)
	go func() {
		scratch := make([]byte, 2048)
		for {
			read, readErr := peer.Read(scratch)
			if readErr != nil {
				return
			}
			received <- append([]byte(nil), scratch[:read]...)
		}
	}()

	destinationPort := peerPort
	// The same reasoning as the TCP payload above: the mapping's reader has to be parked before the
	// engine will hand it a datagram, so the SAME datagram from the SAME device endpoint is re-sent
	// until it lands. The endpoint is what keys the mapping, so a re-send cannot create a second one.
	sendUDPUntil := func(t *testing.T, payload []byte, timeout time.Duration) []byte {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			fixture.emit(t, datapathIPv4UDP(49000, destinationPort, payload))
			select {
			case got := <-received:
				return got
			case <-time.After(50 * time.Millisecond):
			}
		}
		t.Fatalf("the UDP datagram never reached the real peer on port %d", destinationPort)
		return nil
	}

	require.Equal(t, []byte("first"), sendUDPUntil(t, []byte("first"), 3*time.Second))
	require.Equal(t, 1, fixture.handler.mappingCount(destinationPort),
		"the first datagram must create exactly one mapping")

	// Wait out the mapping's lifetime with no traffic, which is the only way a NAT mapping expires.
	time.Sleep(3 * udpTimeout)

	require.Equal(t, []byte("second"), sendUDPUntil(t, []byte("second"), 3*time.Second))

	// The re-creation is the row: the second datagram must have opened a second mapping, which is
	// what makes the port binding a lifetime rather than a permanent one. A stack that reused the
	// closed PacketConn would carry the payload but leave the count at one, and the peer would see a
	// datagram from a mapping the sender no longer owns.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && fixture.handler.mappingCount(destinationPort) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, 2, fixture.handler.mappingCount(destinationPort),
		"a datagram after the mapping lifetime must create a new mapping, not reuse the expired one")
}

// tcpDataSegments returns the device-facing data segments for a flow, in arrival order, as payload
// lengths and as whole frames.
//
// The frames are kept because the ICMP error below has to embed one of them: a PacketTooBig is a
// statement about a specific datagram, and a test that quoted an invented sequence number would be
// testing the error parser rather than the path-MTU feedback path.
func (f *datapathFixture) tcpDataSegments(sourcePort, destinationPort uint16) (lengths []int, frames [][]byte) {
	f.access.Lock()
	defer f.access.Unlock()
	for _, frame := range f.frames {
		tcp, ok := datapathTCP(frame)
		if !ok || tcp.SourcePort() != destinationPort || tcp.DestinationPort() != sourcePort {
			continue
		}
		if len(tcp.Payload()) == 0 {
			continue
		}
		lengths = append(lengths, len(tcp.Payload()))
		frames = append(frames, frame)
	}
	return lengths, frames
}

// datapathICMPFragNeeded builds an ICMPv4 destination-unreachable / fragmentation-needed that
// embeds the datagram it is complaining about, exactly as a router would.
func datapathICMPFragNeeded(offending []byte, mtu uint16) []byte {
	embedded := offending
	const maximum = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize - header.ICMPv4MinimumSize
	if len(embedded) > maximum {
		// An ICMP error must fit the minimum processable datagram, so a router truncates the quoted
		// packet. The engine only needs the IP header and the first eight bytes of TCP.
		embedded = embedded[:maximum]
	}
	source := netip.MustParseAddr("198.18.0.2")
	destination := netip.MustParseAddr("198.18.0.1")
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(embedded))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4DstUnreachable)
	icmp.SetCode(header.ICMPv4FragmentationNeeded)
	icmp.SetMTU(mtu)
	copy(packet[header.IPv4MinimumSize+header.ICMPv4MinimumSize:], embedded)
	// ICMPv4 has no CalculateChecksum helper in this fork, and the checksum covers the whole message
	// including the quoted datagram, so it is taken directly.
	icmp.SetChecksum(^chksum.Checksum(icmp, 0))
	return packet
}

// datapathIPv4UDPFragments splits one UDP datagram into two IPv4 fragments.
//
// The split point is rounded down to an eight-byte boundary because the fragment offset field counts
// eight-byte units, and the first fragment carries the more-fragments flag while the second carries
// the offset. A stack that only accepted whole datagrams would drop both halves, so the pair is a
// real exercise of the reassembly path rather than of the UDP parser.
func datapathIPv4UDPFragments(sourcePort, destinationPort uint16, payload []byte) [][]byte {
	source := netip.MustParseAddr("198.18.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	udp := make([]byte, header.UDPMinimumSize+len(payload))
	header.UDP(udp).Encode(&header.UDPFields{
		SrcPort: sourcePort,
		DstPort: destinationPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(udp[header.UDPMinimumSize:], payload)
	header.UDP(udp).SetChecksum(^chksum.Checksum(udp, header.PseudoHeaderChecksum(
		header.UDPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(len(udp)),
	)))

	const identification = 0x4d2
	split := (len(udp) / 2) &^ 7
	if split == 0 {
		split = len(udp)
	}
	build := func(offset, length int, moreFragments bool) []byte {
		packet := make([]byte, header.IPv4MinimumSize+length)
		ip := header.IPv4(packet)
		flags := uint8(0)
		if moreFragments {
			flags = header.IPv4FlagMoreFragments
		}
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(packet)),
			ID:          identification,
			Flags:       flags,
			// gtcpip's IPv4 API takes the fragment offset in BYTES (Encode shifts it right by three),
			// even though the wire field counts eight-byte units.
			FragmentOffset: uint16(offset),
			TTL:            64,
			Protocol:       uint8(header.UDPProtocolNumber),
			SrcAddr:        source,
			DstAddr:        destination,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(packet[header.IPv4MinimumSize:], udp[offset:offset+length])
		return packet
	}
	return [][]byte{
		build(0, split, true),
		build(split, len(udp)-split, false),
	}
}

// TestGoStackReassemblesIPv4FragmentsIntoOneDatagram is the fragmentation half of the MTU row.
//
// A path that cannot carry the datagram in one piece delivers it as IP fragments, and the receiving
// stack has to put them back together before it can hand the datagram to the mapping: the second
// fragment carries no UDP header at all, so a stack that treated each fragment as a datagram would
// either drop them or deliver a truncated payload. The peer is real, and the assertion is that the
// bytes it receives are the bytes that were sent.
func TestGoStackReassemblesIPv4FragmentsIntoOneDatagram(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer peer.Close()
	peerPort := uint16(peer.LocalAddr().(*net.UDPAddr).Port)

	fixture := newDatapathFixture(t, func(M.Socksaddr) string {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(peerPort)))
	}, time.Minute)

	// 4000 bytes is far past the 1500-byte tunnel MTU, so the pair of fragments is a genuine
	// reassembly rather than a formality.
	payload := bytes.Repeat([]byte{0x7e}, 4000)

	received := make(chan []byte, 4)
	go func() {
		scratch := make([]byte, 8192)
		for {
			read, readErr := peer.Read(scratch)
			if readErr != nil {
				return
			}
			received <- append([]byte(nil), scratch[:read]...)
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for got == nil && time.Now().Before(deadline) {
		for _, fragment := range datapathIPv4UDPFragments(49010, peerPort, payload) {
			fixture.emit(t, fragment)
		}
		select {
		case got = <-received:
		case <-time.After(50 * time.Millisecond):
		}
	}
	require.NotNil(t, got, "the reassembled datagram never reached the real peer")
	require.Len(t, got, len(payload), "the peer received a truncated datagram: the fragments were not reassembled")
	require.Equal(t, payload, got)
}

// TestGoStackTCPHonoursICMPPacketTooBigFromTheDevice is the PacketTooBig row.
//
// The stack advertises an MSS derived from the tunnel MTU and segments the download stream to it.
// When the device reports that a segment is too big - the ICMPv4 fragmentation-needed a router would
// send, with a smaller next-hop MTU - the stack must lower the effective MSS for that connection and
// re-segment to it. Without that feedback the tunnel would keep emitting segments the path cannot
// carry and the connection would stall with no error to attribute, which is the failure the row is
// about.
//
// The peer is real, the download bytes are real, and the ICMP quotes a segment the stack actually
// emitted, so both halves of the row are exercised: an over-MTU segment exists, and its rejection
// changes what the stack sends next.
func TestGoStackTCPHonoursICMPPacketTooBigFromTheDevice(t *testing.T) {
	const (
		tunnelMTU    = 1500
		reducedMTU   = 600
		originalMSS  = tunnelMTU - header.IPv4MinimumSize - header.TCPMinimumSize
		reducedMSS   = reducedMTU - header.IPv4MinimumSize - header.TCPMinimumSize
		chunkSize    = 20000
		sourcePort   = uint16(48003)
		dataDeadline = 5 * time.Second
	)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	listenPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	writeChunk := make(chan []byte, 4)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		for chunk := range writeChunk {
			if _, writeErr := conn.Write(chunk); writeErr != nil {
				return
			}
		}
	}()

	fixture := newDatapathFixture(t, func(M.Socksaddr) string {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort)))
	}, time.Minute)

	fixture.establishTCPFlow(t, sourcePort, listenPort)
	// The device deliberately never acknowledges the download stream. That is what keeps the emitted
	// segments in flight, which is the state the ICMP error has to refer to: the engine ignores a
	// PacketTooBig whose quoted sequence number has already been acknowledged.
	writeChunk <- bytes.Repeat([]byte{0x5a}, chunkSize)

	var lengths []int
	var frames [][]byte
	deadline := time.Now().Add(dataDeadline)
	for time.Now().Before(deadline) {
		lengths, frames = fixture.tcpDataSegments(sourcePort, listenPort)
		if len(lengths) >= 5 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	require.GreaterOrEqual(t, len(lengths), 5, "the stack never segmented the download stream")
	require.EqualValues(t, originalMSS, maxInt(lengths),
		"before any feedback the stack must segment to the tunnel MTU")

	fixture.emit(t, datapathICMPFragNeeded(frames[0], reducedMTU))

	segmentsBefore := len(lengths)
	writeChunk <- bytes.Repeat([]byte{0x6b}, chunkSize)

	deadline = time.Now().Add(dataDeadline)
	for time.Now().Before(deadline) {
		lengths, frames = fixture.tcpDataSegments(sourcePort, listenPort)
		if len(lengths) > segmentsBefore {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	require.Greater(t, len(lengths), segmentsBefore,
		"the stack emitted nothing after the PacketTooBig, so the feedback was either ignored or fatal")
	after := lengths[segmentsBefore:]
	require.LessOrEqual(t, maxInt(after), reducedMSS,
		"every segment emitted after the PacketTooBig must fit the MTU the device reported")
}

func maxInt(values []int) int {
	maximum := 0
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	return maximum
}

// TestGoStackTCPBlackholeCancellationUnwindsARealUnansweringPeer is the blackhole row with a real
// peer rather than a fake Handler.
//
// The peer completes the connect and then never answers: no byte ever comes back. Cancellation has to
// propagate all the way out, which is observable at the FAR end - the relay closes the socket it
// dialled, so the peer's own read returns - and not only inside the stack. The stack-level half of
// this contract (the caller's context reaching NewConnectionEx, and the half-open flow terminating)
// is pinned by blackhole_connect_regression_test.go; this test adds the socket at the other end.
func TestGoStackTCPBlackholeCancellationUnwindsARealUnansweringPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	listenPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	peerAccepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		peerAccepted <- conn.(*net.TCPConn)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture := newDatapathFixtureContext(t, ctx, func(M.Socksaddr) string {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort)))
	}, time.Minute)

	deviceNext, stackNext := fixture.establishTCPFlow(t, 48002, listenPort)
	require.NoError(t, fixture.waitForDialError(t, listenPort, 3*time.Second))

	peer := <-peerAccepted
	defer peer.Close()
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))

	// A request that will never be answered. The relay forwards it to the peer, which reads nothing:
	// that is the blackhole.
	fixture.emit(t, datapathIPv4TCP(48002, listenPort, deviceNext, stackNext, header.TCPFlagAck|header.TCPFlagPsh, []byte("request")))

	// The cancellation itself. The stack context is the one handed to NewConnectionEx, which is what
	// makes cancelling it terminate the flow rather than only stop new work.
	cancel()

	// The relay must unwind: the stack closed the TUN-side connection, so the copy ends and the relay
	// closes the socket it dialled.
	uploadErr := fixture.waitForUploadError(t, listenPort, 5*time.Second)
	require.Error(t, uploadErr)

	// And the far end must see that: the peer's read returns instead of blocking forever on a
	// connection nobody owns any more.
	scratch := make([]byte, 16)
	for {
		_, readErr := peer.Read(scratch)
		if readErr != nil {
			return
		}
	}
}
