package masque

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Packet Too Big must be delivered to the peer whose tunnel produced it, and to no other.
//
// # Why this is a security-relevant test and not just a correctness one
//
// The endpoint serves several peers from one Server. A Packet Too Big is generated because
// a packet the endpoint was SENDING could not fit in one peer's QUIC connection, so the
// error belongs to that peer alone.
//
// The delivery path used to look up the session from the ERROR's destination address, which
// is derived from the quoted packet's source. For an endpoint-generated packet that source
// is the endpoint itself, so the lookup matched nothing and the error was handed to the
// local device instead of into any tunnel. The fix addresses the error to the peer that
// owns the session and queues it on that same session.
//
// That fix is what this test pins. If delivery were ever re-derived by lookup, a packet too
// big on one peer's tunnel could be reported into ANOTHER peer's tunnel - one user's network
// conditions leaking into another user's session - which is why the assertion is on
// cross-session isolation and not merely on "an error was delivered".

// recordingSession is a sessionHandler that records what reached it.
//
// handlePacketTooBig is reached through session.writePacket when the QUIC connection
// reports a datagram that does not fit. The serverSession.handlePacketTooBig path builds an
// ICMP error and QUEUES it, so the tests below assert on the queued reply and on WHICH
// session received it - the recording handler is the instrument for the writePacket path
// and for proving the other session's handler saw nothing.
type recordingSession struct {
	// packets are the buffers passed to handlePacket.
	packets []*buf.Buffer
	// tooBig are the buffers passed to handlePacketTooBig.
	tooBig []*buf.Buffer
	// mtus are the MTU values reported alongside them.
	mtus []int
}

func (h *recordingSession) handleAddressAssign([]AssignedAddress) error   { return nil }
func (h *recordingSession) handleAddressRequest([]AssignedAddress) error  { return nil }
func (h *recordingSession) handleRouteAdvertisement([]AddressRange) error { return nil }

func (h *recordingSession) handlePacket(buffer *buf.Buffer) {
	h.packets = append(h.packets, buffer)
}

func (h *recordingSession) handlePacketTooBig(buffer *buf.Buffer, mtu int) {
	h.tooBig = append(h.tooBig, buffer)
	h.mtus = append(h.mtus, mtu)
}

// queuedReplies drains a session's send queue, releasing each buffer after inspecting it.
//
// The queue is the observable effect of handlePacketTooBig, because that method builds the
// ICMP error and hands it to queuePacket rather than invoking the handler directly.
func queuedReplies(session *serverSession) [][]byte {
	var replies [][]byte
	for {
		select {
		case queued := <-session.sendQueue:
			replies = append(replies, append([]byte(nil), queued.Bytes()...))
			queued.Release()
		default:
			return replies
		}
	}
}

// newServerSessionForTest builds a serverSession with the given assigned addresses and a
// queued send queue, so queuePacket has somewhere to put a reply.
func newServerSessionForTest(t *testing.T, server *Server, addresses []netip.Addr) (*serverSession, *recordingSession) {
	t.Helper()
	handler := &recordingSession{}
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(net.ErrClosed) })
	current := &serverSession{
		session: &session{
			ctx:       ctx,
			cancel:    cancel,
			handler:   handler,
			sendQueue: make(chan *buf.Buffer, 8),
		},
		server:    server,
		ctx:       ctx,
		addresses: addresses,
	}
	return current, handler
}

// newServerForTest builds the minimum Server a serverSession needs for delivery.
func newServerForTest(t *testing.T) *Server {
	t.Helper()
	return &Server{
		logger:       logger.NOP(),
		inet4Address: netip.MustParseAddr("198.18.0.1"),
		inet6Address: netip.MustParseAddr("2001:db8::1"),
	}
}

// buildIPv4PacketForTest builds a valid IPv4 packet so buildICMPErrorTo accepts it.
func buildIPv4PacketForTest(t *testing.T, source, destination netip.Addr, payloadLength int) []byte {
	t.Helper()
	total := header.IPv4MinimumSize + payloadLength
	packet := make([]byte, total)
	packet[0] = 0x45
	packet[2] = byte(total >> 8)
	packet[3] = byte(total)
	packet[8] = 64
	packet[9] = 17 // UDP
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	ipHeader := header.IPv4(packet)
	ipHeader.SetChecksum(0)
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	return packet
}

// TestPacketTooBigIsDeliveredOnlyToTheOwningSession is the isolation assertion.
func TestPacketTooBigIsDeliveredOnlyToTheOwningSession(t *testing.T) {
	server := newServerForTest(t)

	gateway := netip.MustParseAddr("198.18.0.1")
	peerA := netip.MustParseAddr("198.18.0.2")
	peerB := netip.MustParseAddr("198.18.0.3")

	sessionA, _ := newServerSessionForTest(t, server, []netip.Addr{peerA})
	sessionB, handlerB := newServerSessionForTest(t, server, []netip.Addr{peerB})

	// Register both sessions so a lookup-based implementation would have something to
	// find. Without this the test could pass merely because lookup finds nothing at all,
	// which is not the property being asserted.
	server.access.Lock()
	server.addresses = map[netip.Addr]*serverSession{
		peerA: sessionA,
		peerB: sessionB,
	}
	server.access.Unlock()

	// The oversized packet is one the endpoint was SENDING to peer A, so its source is the
	// gateway - the exact shape that used to be misrouted.
	oversized := buildIPv4PacketForTest(t, gateway, peerA, 1400)

	const advertisedMTU = 1311

	sessionA.handlePacketTooBig(buf.As(oversized), advertisedMTU)

	// The owning session must have exactly one queued reply, and it must be correctly
	// addressed.
	repliesA := queuedReplies(sessionA)
	require.Len(t, repliesA, 1,
		"the owning session must receive exactly one Packet Too Big for its own tunnel")

	packet := repliesA[0]
	require.Equal(t, uint8(4), packet[0]>>4, "the reply must be IPv4")
	require.Equal(t, uint8(3), packet[20], "the reply must be an ICMP Destination Unreachable")
	require.Equal(t, uint8(4), packet[21], "the code must be 4 (Fragmentation Needed)")
	require.Equal(t, gateway.As4(), [4]byte(packet[12:16]),
		"the error must be sourced from the endpoint's gateway")
	require.Equal(t, peerA.As4(), [4]byte(packet[16:20]),
		"the error must be addressed to the OWNING peer, not to the endpoint and not to "+
			"another peer")
	require.Equal(t, uint16(advertisedMTU), uint16(packet[26])<<8|uint16(packet[27]),
		"the advertised MTU must be carried through unchanged")

	// And the OTHER session must have been handed nothing. This is the isolation
	// property: one peer's network conditions must never be reported into another peer's
	// session.
	require.Empty(t, queuedReplies(sessionB),
		"a Packet Too Big for one peer must never be queued on another peer's session; "+
			"that would leak one user's network conditions into another session")
	require.Empty(t, handlerB.tooBig,
		"the other peer's handler must not be invoked either")
	require.Empty(t, handlerB.packets)
}

// TestPacketTooBigIsNotBroadcastToEverySession is the direct cross-user assertion.
//
// The isolation test above uses two peers. This one uses several and requires that exactly
// one session - the owner - receives the error, so an implementation that queued the reply
// on every registered session would fail rather than pass by coincidence.
func TestPacketTooBigIsNotBroadcastToEverySession(t *testing.T) {
	server := newServerForTest(t)
	gateway := netip.MustParseAddr("198.18.0.1")

	type peer struct {
		address netip.Addr
		session *serverSession
		handler *recordingSession
	}

	peers := make([]peer, 0, 4)
	server.access.Lock()
	server.addresses = make(map[netip.Addr]*serverSession, 4)
	server.access.Unlock()

	for index := range 4 {
		address := netip.AddrFrom4([4]byte{198, 18, 0, byte(2 + index)})
		session, handler := newServerSessionForTest(t, server, []netip.Addr{address})
		server.access.Lock()
		server.addresses[address] = session
		server.access.Unlock()
		peers = append(peers, peer{address: address, session: session, handler: handler})
	}

	// The oversized packet belongs to the SECOND peer.
	owner := peers[1]
	oversized := buildIPv4PacketForTest(t, gateway, owner.address, 1400)
	owner.session.handlePacketTooBig(buf.As(oversized), 1311)

	totalDelivered := 0
	for index, current := range peers {
		replies := queuedReplies(current.session)
		totalDelivered += len(replies)
		if current.address == owner.address {
			require.Len(t, replies, 1,
				"the owning peer must receive the error")
			continue
		}
		require.Empty(t, replies,
			"peer %d (%s) must not receive a Packet Too Big generated for %s",
			index, current.address, owner.address)
	}

	require.Equal(t, 1, totalDelivered,
		"exactly one session must receive the error; a broadcast would reach every peer "+
			"and leak one user's conditions into the others")
}

// TestPacketTooBigWithoutAnAssignedAddressIsDropped proves the degenerate case is handled.
//
// With no assigned address in the packet's family there is no peer to inform, and the
// buffer must be released rather than delivered to the local device handler - an error
// addressed to nobody would be attributed to the local stack.
func TestPacketTooBigWithoutAnAssignedAddressIsDropped(t *testing.T) {
	server := newServerForTest(t)
	gateway := netip.MustParseAddr("198.18.0.1")
	destination := netip.MustParseAddr("198.18.0.2")

	// A session with NO addresses assigned.
	session, handler := newServerSessionForTest(t, server, nil)

	oversized := buildIPv4PacketForTest(t, gateway, destination, 1400)

	require.NotPanics(t, func() {
		session.handlePacketTooBig(buf.As(oversized), 1311)
	}, "a session with no assignment must not panic")

	require.Empty(t, handler.tooBig,
		"no error may be generated when there is no peer to address it to")
	require.Empty(t, queuedReplies(session),
		"nothing may be queued when there is no peer to address it to")
}

// TestPacketTooBigAddressingFollowsThePacketFamily proves the address family is respected.
//
// An IPv4 oversized packet must produce an IPv4 error addressed to the peer's IPv4 address,
// and likewise for IPv6. With both families assigned, using the wrong one would address the
// error to an address the peer does not have on that tunnel.
func TestPacketTooBigAddressingFollowsThePacketFamily(t *testing.T) {
	server := newServerForTest(t)
	gateway4 := server.inet4Address
	peer4 := netip.MustParseAddr("198.18.0.2")
	peer6 := netip.MustParseAddr("2001:db8::2")

	// Both families assigned, IPv4 first, so a naive "first address" implementation would
	// pick IPv4 even for an IPv6 packet.
	session, _ := newServerSessionForTest(t, server, []netip.Addr{peer4, peer6})

	oversized6 := make([]byte, header.IPv6MinimumSize+8)
	oversized6[0] = 0x60
	oversized6[4] = 0
	oversized6[5] = 8
	oversized6[6] = 17
	oversized6[7] = 64
	copy(oversized6[8:24], gateway4.AsSlice())
	// An IPv6 destination, written directly since inet4Address is what the endpoint sources
	// from for IPv6 through inet6Address.
	copy(oversized6[24:40], server.inet6Address.AsSlice())

	session.handlePacketTooBig(buf.As(oversized6), 1280)

	replies := queuedReplies(session)
	require.Len(t, replies, 1, "the IPv6 packet must produce exactly one error")

	packet := replies[0]
	require.Equal(t, uint8(6), packet[0]>>4,
		"an IPv6 oversized packet must produce an IPv6 error, not an IPv4 one")
	require.Equal(t, uint8(58), packet[6],
		"the IPv6 error must declare ICMPv6 as its next header")
	// The destination must be the peer's IPv6 address, not its IPv4 one.
	require.Equal(t, peer6.As16(), [16]byte(packet[24:40]),
		"the IPv6 error must be addressed to the peer's IPv6 address")
}

// Compile-time reference so the test's use of Socksaddr stays meaningful if the fixtures
// change.
var _ = M.Socksaddr{}
