package e2e

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	chksum "github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ===========================================================================
// What this file covers, and the one thing it does NOT
// ===========================================================================
//
// The tun path is: device -> real Go TCP/IP stack -> handler -> route -> DNS -> outbound -> remote.
//
// This file drives the FIRST three hops with real packets: a tun.MemoryTun device, the in-process
// Go stack from the pinned sing-tun, real IPv4/TCP and IPv4/UDP frames with real checksums, and a
// real loopback peer at the far end. Everything from the handler down is the real product: the
// live router of a started box, its rules, its DNS router, its cached answers, and its outbounds.
//
// The handler itself is a stand-in for protocol/tun.Inbound's delegation, and that is the one piece
// of production code this file does not execute. It reproduces that delegation line for line -
// metadata.Inbound/InboundType/Source/Destination, the canonicalised destination, the DNS-protocol
// marking, then router.RouteConnectionEx / RoutePacketConnectionEx / HijackDNSPacket - because the
// real Inbound cannot be constructed without opening a device.
//
// The distinction matters enough to state plainly: a defect INSIDE protocol/tun.Inbound's
// delegation would not be caught here. A defect in the stack, the router, the rules, the DNS
// router, the outbounds, or the seam between them would be. The device half - a real utun, a
// route table entry, a network namespace - needs root and is not attempted: DEVICE-ONLY, and
// therefore UNVERIFIED by this file.

// tunStackHandler is the faithful stand-in described above.
type tunStackHandler struct {
	router      adapter.Router
	tag         string
	dnsAddress  netip.Addr
	dnsPort     uint16
	logger      *testLogger
	connections sync.WaitGroup
}

func (h *tunStackHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, _ []byte) tun.FlowVerdict {
	// The production rule this reproduces: a configured DNS address is hijacked on every port
	// (protocol/tun/inbound.go, JudgeFlow). The address is taken from the configuration the same
	// way the inbound takes it from its own options.
	if destination.Addr().Unmap() == h.dnsAddress {
		if network == uint8(header.UDPProtocolNumber) {
			return tun.FlowVerdict{Action: tun.ActionHijackDNS}
		}
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (h *tunStackHandler) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	metadata := adapter.InboundContext{
		Inbound:     h.tag,
		InboundType: C.TypeTun,
		Network:     N.NetworkUDP,
		Source:      source,
		Destination: destination,
		Protocol:    C.ProtocolDNS,
	}
	h.logger.logf("tun: inbound DNS packet from %s to %s", source, destination)
	h.router.HijackDNSPacket(context.Background(), payload, writer, metadata)
}

func (h *tunStackHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.connections.Add(1)
	defer h.connections.Done()
	metadata := adapter.InboundContext{
		Inbound:     h.tag,
		InboundType: C.TypeTun,
		Source:      source,
		Destination: canonicalSocksaddrForTun(destination),
	}
	h.logger.logf("tun: inbound connection from %s to %s", source, destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *tunStackHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.connections.Add(1)
	defer h.connections.Done()
	metadata := adapter.InboundContext{
		Inbound:     h.tag,
		InboundType: C.TypeTun,
		Source:      source,
		Destination: canonicalSocksaddrForTun(destination),
	}
	h.logger.logf("tun: inbound packet connection from %s to %s", source, destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// canonicalSocksaddrForTun is protocol/tun's canonicalSocksaddr: a v4-mapped address is an IPv4
// address written in sixteen bytes, and every policy comparison downstream is written against the
// four-byte form.
func canonicalSocksaddrForTun(address M.Socksaddr) M.Socksaddr {
	if address.Addr.Is4In6() {
		return M.Socksaddr{Addr: address.Addr.Unmap(), Fqdn: address.Fqdn, Port: address.Port}
	}
	return address
}

// testLogger is a minimal log sink that records the delegation's own messages so a failing scenario
// can show what reached the handler.
type testLogger struct {
	mu      sync.Mutex
	entries []string
}

func (l *testLogger) logf(format string, args ...any) {
	l.mu.Lock()
	l.entries = append(l.entries, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *testLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.entries, "\n")
}

// ===========================================================================
// The device and the stack
// ===========================================================================

type tunFixture struct {
	t       *testing.T
	device  *tun.MemoryTun
	stack   tun.Stack
	handler *tunStackHandler
	access  sync.Mutex
	frames  [][]byte
	// frameSignal is raised on every device-facing frame so a test waits on an observation.
	frameSignal chan struct{}
}

const (
	tunDeviceAddress  = "198.18.0.2"
	tunStackAddress   = "198.18.0.1/30"
	tunProxiedAddress = "10.9.9.9"
	tunDirectAddress  = "10.9.9.10"
	tunUDPAddress     = "10.9.9.11"
	tunRefusedAddress = "10.9.9.12"
	tunDNSAddress     = "10.9.9.53"
)

func newTunFixture(t *testing.T, running *chain, dnsAddress netip.Addr, dnsPort uint16) *tunFixture {
	t.Helper()
	fixture := &tunFixture{t: t, frameSignal: make(chan struct{}, 1)}
	fixture.handler = &tunStackHandler{
		router:     running.router(),
		tag:        "tun-in",
		dnsAddress: dnsAddress,
		dnsPort:    dnsPort,
		logger:     &testLogger{},
	}
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
			select {
			case fixture.frameSignal <- struct{}{}:
			default:
			}
		},
	})
	stack, err := tun.NewStack("go", tun.StackOptions{
		Context: context.Background(),
		Tun:     fixture.device,
		TunOptions: tun.Options{
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix(tunStackAddress)},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
			Logger:       logger.NOP(),
		},
		Handler:     fixture.handler,
		Logger:      logger.NOP(),
		UDPTimeout:  30 * time.Second,
		ICMPTimeout: time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	fixture.stack = stack
	t.Cleanup(func() {
		_ = stack.Close()
		_ = fixture.device.Close()
		// The handler's delegations must all have returned: a route decision that outlives the
		// stack is a connection the product still owns after the tunnel is gone.
		done := make(chan struct{})
		go func() {
			fixture.handler.connections.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("a handler delegation was still running 10s after the stack closed\n%s", fixture.handler.logger)
		}
	})
	return fixture
}

func (f *tunFixture) emit(t *testing.T, packet []byte) {
	t.Helper()
	written, err := f.device.WritePackets([][]byte{packet})
	require.NoError(t, err)
	require.Equal(t, 1, written)
}

// ===========================================================================
// Frame construction, parsing and waiting
// ===========================================================================

// tcpFrame builds a device-side IPv4/TCP frame with real checksums.
//
// The Go stack negotiates MemoryTun with checksum validation enabled: a frame without them would
// exercise the parser's rejection path rather than the state machine.
func tcpFrame(source netip.Addr, sourcePort uint16, destination netip.Addr, destinationPort uint16, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
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
	// The checksum covers the whole segment: TCP.CalculateChecksum covers only the header.
	tcp.SetChecksum(^chksum.Checksum(tcp, header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(len(packet)-header.IPv4MinimumSize),
	)))
	return packet
}

// synFrame is the device's opening SYN, with an MSS option.
//
// The option is load-bearing: a peer that offers no MSS is treated as having the RFC 9293 default
// of 536 bytes, and the stack would then segment its download to 536 rather than to the MTU.
func synFrame(source netip.Addr, sourcePort uint16, destination netip.Addr, destinationPort uint16, seq uint32, mss uint16) []byte {
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
		SeqNum:     seq,
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

// udpFrame builds a device-side IPv4/UDP datagram with real checksums.
func udpFrame(source netip.Addr, sourcePort uint16, destination netip.Addr, destinationPort uint16, payload []byte) []byte {
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
	// The checksum must cover the whole datagram: UDP.CalculateChecksum covers only the 8-byte
	// header, so using it here would leave every payload byte out of the sum and the stack would
	// drop every datagram that carries one.
	udp.SetChecksum(^chksum.Checksum(udp, header.PseudoHeaderChecksum(
		header.UDPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(len(packet)-header.IPv4MinimumSize),
	)))
	return packet
}

// parseFrame pulls the IPv4 header and the transport header out of a device-facing frame.
func parseFrame(frame []byte) (header.IPv4, []byte, bool) {
	if len(frame) < header.IPv4MinimumSize {
		return nil, nil, false
	}
	ip := header.IPv4(frame)
	if !ip.IsValid(len(frame)) {
		return nil, nil, false
	}
	return ip, frame[ip.HeaderLength():], true
}

// waitForTCPPayload waits for a device-facing TCP segment for one flow that carries a payload, and
// returns it with the segment's headers.
func (f *tunFixture) waitForTCPPayload(t *testing.T, sourcePort, destinationPort uint16, timeout time.Duration) (header.TCP, []byte) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		f.access.Lock()
		for _, frame := range f.frames {
			ip, transport, ok := parseFrame(frame)
			if !ok || ip.TransportProtocol() != header.TCPProtocolNumber {
				continue
			}
			tcp := header.TCP(transport)
			if tcp.SourcePort() != destinationPort || tcp.DestinationPort() != sourcePort {
				continue
			}
			payload := transport[tcp.DataOffset():]
			if len(payload) == 0 {
				continue
			}
			f.access.Unlock()
			return tcp, append([]byte(nil), payload...)
		}
		f.access.Unlock()
		if time.Now().After(deadline) {
			f.dump(t)
			t.Fatalf("the stack never emitted a TCP payload for %d -> %d", sourcePort, destinationPort)
		}
		select {
		case <-f.frameSignal:
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func (f *tunFixture) waitForTCPFlag(t *testing.T, sourcePort, destinationPort uint16, want header.TCPFlags, timeout time.Duration) header.TCP {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		f.access.Lock()
		for _, frame := range f.frames {
			ip, transport, ok := parseFrame(frame)
			if !ok || ip.TransportProtocol() != header.TCPProtocolNumber || len(transport) < header.TCPMinimumSize {
				continue
			}
			tcp := header.TCP(transport)
			if tcp.SourcePort() != destinationPort || tcp.DestinationPort() != sourcePort {
				continue
			}
			if tcp.Flags()&want == want {
				f.access.Unlock()
				return tcp
			}
		}
		f.access.Unlock()
		if time.Now().After(deadline) {
			f.dump(t)
			t.Fatalf("the stack never emitted flags %s for %d -> %d", want, sourcePort, destinationPort)
		}
		select {
		case <-f.frameSignal:
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// waitForUDPPayload waits for a device-facing UDP datagram for one flow.
func (f *tunFixture) waitForUDPPayload(t *testing.T, sourcePort, destinationPort uint16, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		f.access.Lock()
		for _, frame := range f.frames {
			ip, transport, ok := parseFrame(frame)
			if !ok || ip.TransportProtocol() != header.UDPProtocolNumber || len(transport) < header.UDPMinimumSize {
				continue
			}
			udp := header.UDP(transport)
			if udp.SourcePort() != destinationPort || udp.DestinationPort() != sourcePort {
				continue
			}
			payload := transport[header.UDPMinimumSize:]
			f.access.Unlock()
			return append([]byte(nil), payload...)
		}
		f.access.Unlock()
		if time.Now().After(deadline) {
			f.dump(t)
			t.Fatalf("the stack never emitted a UDP payload for %d -> %d", sourcePort, destinationPort)
		}
		select {
		case <-f.frameSignal:
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// tcpOverTun performs a real handshake over the device and returns the connection's sequence
// numbers, so a test can send and receive payload without reimplementing TCP.
type tcpOverTun struct {
	fixture         *tunFixture
	sourcePort      uint16
	destination     netip.Addr
	destinationPort uint16
	nextSeq         uint32
	nextAck         uint32
}

func (f *tunFixture) dialTCP(t *testing.T, connection *tcpOverTun, timeout time.Duration) {
	t.Helper()
	connection.fixture = f
	connection.nextSeq = 1000
	f.emit(t, synFrame(netip.MustParseAddr(tunDeviceAddress), connection.sourcePort,
		connection.destination, connection.destinationPort, connection.nextSeq, 1400))
	synAck := f.waitForTCPFlag(t, connection.sourcePort, connection.destinationPort, header.TCPFlagSyn|header.TCPFlagAck, timeout)
	connection.nextAck = synAck.SequenceNumber() + 1
	connection.nextSeq++
	f.emit(t, tcpFrame(netip.MustParseAddr(tunDeviceAddress), connection.sourcePort,
		connection.destination, connection.destinationPort, connection.nextSeq, connection.nextAck, header.TCPFlagAck, nil))
}

func (c *tcpOverTun) write(t *testing.T, payload string) {
	t.Helper()
	c.fixture.emit(t, tcpFrame(netip.MustParseAddr(tunDeviceAddress), c.sourcePort,
		c.destination, c.destinationPort, c.nextSeq, c.nextAck, header.TCPFlagAck|header.TCPFlagPsh, []byte(payload)))
	c.nextSeq += uint32(len(payload))
}

// expectEcho waits for a payload segment and acknowledges it, which is what keeps the stack's send
// window open for the next round.
func (c *tcpOverTun) expectEcho(t *testing.T, expected string, timeout time.Duration) {
	t.Helper()
	segment, payload := c.fixture.waitForTCPPayload(t, c.sourcePort, c.destinationPort, timeout)
	require.Equal(t, expected, string(payload))
	c.nextAck = segment.SequenceNumber() + uint32(len(payload))
	c.fixture.emit(t, tcpFrame(netip.MustParseAddr(tunDeviceAddress), c.sourcePort,
		c.destination, c.destinationPort, c.nextSeq, c.nextAck, header.TCPFlagAck, nil))
}

// dump prints every frame the device has seen, so a failure says what the stack actually answered
// rather than only that something was missing.
func (f *tunFixture) dump(t *testing.T) {
	t.Helper()
	f.access.Lock()
	defer f.access.Unlock()
	var builder strings.Builder
	for index, frame := range f.frames {
		ip, transport, ok := parseFrame(frame)
		if !ok {
			fmt.Fprintf(&builder, "  frame %d: unparseable (%d bytes)\n", index, len(frame))
			continue
		}
		switch ip.TransportProtocol() {
		case header.TCPProtocolNumber:
			if len(transport) < header.TCPMinimumSize {
				fmt.Fprintf(&builder, "  frame %d: short TCP\n", index)
				continue
			}
			tcp := header.TCP(transport)
			fmt.Fprintf(&builder, "  frame %d: TCP %s:%d -> %s:%d flags=%s seq=%d ack=%d payload=%d\n", index,
				ip.SourceAddress(), tcp.SourcePort(), ip.DestinationAddress(), tcp.DestinationPort(),
				tcp.Flags(), tcp.SequenceNumber(), tcp.AckNumber(), len(transport[tcp.DataOffset():]))
		case header.UDPProtocolNumber:
			if len(transport) < header.UDPMinimumSize {
				fmt.Fprintf(&builder, "  frame %d: short UDP\n", index)
				continue
			}
			udp := header.UDP(transport)
			fmt.Fprintf(&builder, "  frame %d: UDP %s:%d -> %s:%d payload=%d\n", index,
				ip.SourceAddress(), udp.SourcePort(), ip.DestinationAddress(), udp.DestinationPort(), len(transport[header.UDPMinimumSize:]))
		default:
			fmt.Fprintf(&builder, "  frame %d: protocol %d\n", index, ip.TransportProtocol())
		}
	}
	t.Logf("device-facing frames (%d):\n%s\nroute delegation log:\n%s", len(f.frames), builder.String(), f.handler.logger)
}

// ===========================================================================
// The configuration
// ===========================================================================

const tunChainConfig = `{
  "log": {"level": "%s"},
  "dns": {
    "servers": [
      {"tag": "local", "type": "udp", "server": "127.0.0.1", "server_port": %d},
      {"tag": "fakeip", "type": "fakeip", "inet4_range": "198.19.0.0/15"}
    ],
    "rules": [
      {"domain": ["fake-tun.test"], "server": "fakeip"}
    ],
    "final": "local",
    "strategy": "ipv4_only",
    "reverse_mapping": true
  },
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": %d}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "remote", "server": "127.0.0.1", "server_port": %d, "version": "5"}
  ],
  "route": {
    "rules": [
      {"domain": ["fake-tun.test"], "action": "route", "outbound": "remote"},
      {"ip_cidr": ["10.9.9.9/32"], "port": [%d], "action": "route", "outbound": "remote"},
      {"ip_cidr": ["10.9.9.10/32"], "port": [%d], "action": "route", "outbound": "direct", "override_address": "127.0.0.1"},
      {"ip_cidr": ["10.9.9.11/32"], "port": [%d], "action": "route", "outbound": "direct", "override_address": "127.0.0.1"},
      {"ip_cidr": ["10.9.9.12/32"], "action": "route", "outbound": "direct", "override_address": "127.0.0.1", "override_port": %d}
    ],
    "final": "direct"
  }
}`

// The device-side destinations. They are deliberately NOT loopback: the Go engine drops any frame
// whose destination is not global unicast (goEngine.dropNonUnicast), which is correct - a real
// tunnel never carries 127.0.0.0/8 - and the route rules below rewrite these to the loopback peers
// with override_address, which is how a real deployment reaches a local service.

// TestTunChain drives real packets through the real Go stack into the live route layer.
func TestTunChain(t *testing.T) {
	directEcho := startEchoServer(t, "tcp", "127.0.0.1:0")
	proxiedEcho := startEchoServer(t, "tcp", "127.0.0.1:0")
	udpEcho := startUDPEchoServer(t, "udp", "127.0.0.1:0")
	sink := startSocksSink(t, "127.0.0.1:0")
	sink.backendOverride = map[string]string{"fake-tun.test": proxiedEcho.listener.Addr().String()}
	dnsLocal := startDNSResponder(t, "local", map[string]netip.Addr{
		"direct-tun.test": netip.MustParseAddr("127.0.0.1"),
	})
	proxiedPort := uint16(proxiedEcho.listener.Addr().(*net.TCPAddr).Port)
	directPort := uint16(directEcho.listener.Addr().(*net.TCPAddr).Port)
	udpPort := uint16(udpEcho.conn.LocalAddr().(*net.UDPAddr).Port)
	closedPort := freePort(t)
	config := fmt.Sprintf(tunChainConfig, chainLogLevel, dnsLocal.port(), freePort(t),
		uint16(sink.listener.Addr().(*net.TCPAddr).Port), proxiedPort, directPort, udpPort, closedPort)
	running := startChain(t, config)
	// The address the device asks for is the hijack trigger; the port is not part of the rule, to
	// match protocol/tun's "hijack a configured DNS address on every port".
	fixture := newTunFixture(t, running, netip.MustParseAddr(tunDNSAddress), 53)
	sink.backendOverride["10.9.9.9:"+fmt.Sprint(proxiedPort)] = "127.0.0.1:" + fmt.Sprint(proxiedPort)
	sink.backendOverride["fake-tun.test:"+fmt.Sprint(proxiedPort)] = "127.0.0.1:" + fmt.Sprint(proxiedPort)

	// -------------------------------------------------------------------
	// TCP through the tunnel, selected by a rule onto a real outbound.
	// -------------------------------------------------------------------
	t.Run("tcp_routed_to_outbound", func(t *testing.T) {
		connection := &tcpOverTun{sourcePort: 40001, destination: netip.MustParseAddr(tunProxiedAddress), destinationPort: proxiedPort}
		fixture.dialTCP(t, connection, 10*time.Second)
		connection.write(t, "tun-tcp-proxied")
		connection.expectEcho(t, "tun-tcp-proxied", 10*time.Second)
		request := sink.waitForHost(t, tunProxiedAddress, 10*time.Second)
		require.Equal(t, proxiedPort, request.Port)
		flows := running.tracker.waitForFlows(t, 1, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "tcp", flow.Network)
		require.Equal(t, "tun-in", flow.Inbound)
		require.Equal(t, "tun", flow.InboundType)
		require.Equal(t, tunProxiedAddress+":"+fmt.Sprint(proxiedPort), flow.Destination)
		require.Equal(t, "remote", flow.RouteOutbound)
		require.Equal(t, []string{"remote"}, flow.OutboundChain)
		require.Contains(t, flow.RouteRule, tunProxiedAddress+"/32")
	})

	// -------------------------------------------------------------------
	// The same tunnel, a destination the final outbound carries.
	// -------------------------------------------------------------------
	t.Run("tcp_direct_final_outbound", func(t *testing.T) {
		before := len(sink.seen())
		connection := &tcpOverTun{sourcePort: 40002, destination: netip.MustParseAddr(tunDirectAddress), destinationPort: directPort}
		fixture.dialTCP(t, connection, 10*time.Second)
		connection.write(t, "tun-tcp-direct")
		connection.expectEcho(t, "tun-tcp-direct", 10*time.Second)
		require.Greater(t, directEcho.accepts.Load(), int64(0))
		require.Equal(t, before, len(sink.seen()), "a direct flow must not reach the remote outbound")
		flows := running.tracker.waitForFlows(t, 2, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "direct", flow.RouteOutbound)
		require.Contains(t, flow.RouteRule, tunDirectAddress+"/32")
		// The override rewrites the flow's destination - for TCP and for UDP alike - and the
		// address the device asked for is preserved in OriginDestination.
		require.Equal(t, "127.0.0.1:"+fmt.Sprint(directPort), flow.Destination)
		require.Equal(t, tunDirectAddress+":"+fmt.Sprint(directPort), flow.RouteOriginalDestination,
			"the address the device asked for is preserved for the flow's consumers")
	})

	// -------------------------------------------------------------------
	// UDP through the tunnel: one NAT mapping, a real datagram peer, and
	// the reply written back through the device.
	// -------------------------------------------------------------------
	t.Run("udp_through_device", func(t *testing.T) {
		fixture.emit(t, udpFrame(netip.MustParseAddr(tunDeviceAddress), 40003, netip.MustParseAddr(tunUDPAddress), udpPort, []byte("tun-udp")))
		reply := fixture.waitForUDPPayload(t, 40003, udpPort, 10*time.Second)
		require.Equal(t, "tun-udp", string(reply))
		require.Greater(t, udpEcho.packets.Load(), int64(0))
		flows := running.tracker.waitForFlows(t, 3, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "udp", flow.Network)
		require.Equal(t, "tun", flow.InboundType)
		// The UDP and TCP overrides land in different places, and the difference is measured
		// rather than assumed: a TCP override is applied by the outbound and the flow keeps the
		// destination the device asked for, while a UDP flow's destination IS the rewritten one,
		// because the packet connection is keyed by destination.
		require.Equal(t, "127.0.0.1:"+fmt.Sprint(udpPort), flow.Destination)
		require.Equal(t, "direct", flow.RouteOutbound)
	})

	// -------------------------------------------------------------------
	// DNS through the device: the query is hijacked, answered by the real
	// responder, and the answer is written back to the device.
	// -------------------------------------------------------------------
	t.Run("dns_through_device", func(t *testing.T) {
		query := dnsQueryPayload(0x4242, "direct-tun.test", 1)
		fixture.emit(t, udpFrame(netip.MustParseAddr(tunDeviceAddress), 40004, netip.MustParseAddr(tunDNSAddress), 53, query))
		reply := fixture.waitForUDPPayload(t, 40004, 53, 10*time.Second)
		require.Equal(t, netip.MustParseAddr("127.0.0.1"), readDNSAddress(t, reply))
		require.Contains(t, dnsLocal.asked(), "direct-tun.test/1")
	})

	// -------------------------------------------------------------------
	// FakeIP across the whole chain: the answer is a placeholder, and the
	// TCP flow to that placeholder must be routed as the DOMAIN.
	// -------------------------------------------------------------------
	t.Run("fakeip_over_device", func(t *testing.T) {
		query := dnsQueryPayload(0x4243, "fake-tun.test", 1)
		fixture.emit(t, udpFrame(netip.MustParseAddr(tunDeviceAddress), 40005, netip.MustParseAddr(tunDNSAddress), 53, query))
		reply := fixture.waitForUDPPayload(t, 40005, 53, 10*time.Second)
		fakeAddress := readDNSAddress(t, reply)
		require.True(t, netip.MustParsePrefix("198.19.0.0/15").Contains(fakeAddress),
			"the fake address must come from the configured range, got %s", fakeAddress)
		connection := &tcpOverTun{sourcePort: 40006, destination: fakeAddress, destinationPort: proxiedPort}
		fixture.dialTCP(t, connection, 10*time.Second)
		connection.write(t, "tun-fakeip")
		connection.expectEcho(t, "tun-fakeip", 10*time.Second)
		request := sink.waitForHost(t, "fake-tun.test", 10*time.Second)
		require.Equal(t, "fake-tun.test", request.Host,
			"a flow to a fake address must be forwarded as the mapped domain")
		flows := running.tracker.waitForFlows(t, 4, 10*time.Second)
		flow := flows[len(flows)-1]
		require.True(t, flow.FakeIP)
		require.Equal(t, fakeAddress.String()+":"+fmt.Sprint(proxiedPort), flow.OriginDestination)
		require.Equal(t, "fake-tun.test:"+fmt.Sprint(proxiedPort), flow.Destination)
		require.Equal(t, "remote", flow.RouteOutbound)
	})

	// -------------------------------------------------------------------
	// A destination with nothing listening must produce a real reset on
	// the device, through the whole chain rather than from a mock.
	// -------------------------------------------------------------------
	t.Run("tcp_refused_produces_reset", func(t *testing.T) {
		connection := &tcpOverTun{sourcePort: 40007, destination: netip.MustParseAddr(tunRefusedAddress), destinationPort: closedPort}
		fixture.emit(t, synFrame(netip.MustParseAddr(tunDeviceAddress), connection.sourcePort,
			connection.destination, connection.destinationPort, 1000, 1400))
		// A real ECONNREFUSED from the loopback peer must become a real reset on the device; what
		// must not happen is a silent SYN that leaves the flow half-open forever.
		segment := fixture.waitForTCPFlag(t, 40007, closedPort, header.TCPFlagRst, 10*time.Second)
		require.NotZero(t, segment.Flags()&header.TCPFlagRst)
	})
}
