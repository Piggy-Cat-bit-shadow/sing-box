package masque

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
)

// Cross-session ownership and route policy.
//
// session_isolation_test.go pins the base ownership rules (an assigned address
// wins over an advertisement, the server keeps its own address, releasing a
// session does not steal a recycled address). What it does NOT cover is the pair of
// questions this file answers:
//
//  1. Can a peer's ROUTE_ADVERTISEMENT override something it must never override --
//     the server's own gateway address, or another client's assigned address? The
//     existing tests set a route over a range nobody owns; they never put an
//     advertisement in direct conflict with a SPECIFIC client address or with the
//     gateway, and never mix protocol 0 with a protocol-specific route.
//
//  2. Does the answer hold on the DATA path, not only in lookup()? A routing table
//     that answers correctly while the forwarding code does something else is not a
//     policy, and the source check in handlePacket is where source forgery is
//     actually stopped.
//
// So the wire-level tests below drive real IP packets through the real handlers,
// because that check is invisible to a test that only calls lookup().

// ---------------------------------------------------------------------------
// Wire-level fixtures.
// ---------------------------------------------------------------------------

// ownershipTestPrefix is the tunnel network. The server's own address is the
// prefix address, 198.18.0.1, which is the value the gateway guard compares
// against.
const ownershipTestPrefix = "198.18.0.1/24"

// buildOwnershipIPv4Packet assembles a minimal IPv4 packet.
//
// The header checksum is left zero deliberately: the code under test reads only the
// addresses, the protocol and the TTL, and filling the checksum in would make this
// fixture silently depend on the checksum helper rather than on the packet shape.
func buildOwnershipIPv4Packet(source netip.Addr, destination netip.Addr, protocol uint8, ttl uint8) []byte {
	packet := make([]byte, header.IPv4MinimumSize)
	packet[0] = 0x45 // version 4, IHL 5
	packet[2] = byte(header.IPv4MinimumSize >> 8)
	packet[3] = byte(header.IPv4MinimumSize)
	packet[6] = 0 // flags and fragment offset: not fragmented
	packet[8] = ttl
	packet[9] = protocol
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	return packet
}

// buildOwnershipIPv6Packet assembles a minimal IPv6 packet.
func buildOwnershipIPv6Packet(source netip.Addr, destination netip.Addr, protocol uint8, hopLimit uint8) []byte {
	packet := make([]byte, header.IPv6MinimumSize)
	packet[0] = 0x60 // version 6
	packet[6] = protocol
	packet[7] = hopLimit
	sourceBytes := source.As16()
	destinationBytes := destination.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	return packet
}

// tunnelSession builds a serverSession the way a REAL tunnel establishment does.
//
// noopSession (from session_isolation_test.go) is enough for the ownership maps, but
// it leaves TWO fields empty that production always fills, and both of them sit on
// the forwarding path this file exercises:
//
//   - advertisedRoutes, which NewTunnelRequest derives from the server's advertised
//     routes intersected with the client's address families. It is the EGRESS policy:
//     session.accepts() consults it, so a session without it is a session that
//     refuses everything, and every packet is answered with "no route" instead of
//     being forwarded.
//   - handler, which is the server (a serverSession is its own sessionHandler).
//
// Both omissions make the session fail CLOSED, which is why the first version of the
// tests in this file recorded "a forged packet reached the device": the session had
// no egress policy at all and the packet was dropped back into the device path. A
// fixture that cannot forward anything cannot show that forwarding is policed, so
// the fields are filled here and the tests assert on a session that WOULD forward.
func tunnelSession(t *testing.T, server *Server, addresses []netip.Addr, peerRoutes []AddressRange) *serverSession {
	t.Helper()
	// An outbound queue is required, not cosmetic: a session writes its replies through it,
	// and a session built without one looks like an implementation that "rejected the packet
	// without telling anyone" when in fact nothing was ever wired up to receive the reply.
	// The queue's handler captures what the session sends so a test can inspect it.
	current := &serverSession{
		session:          newSession(context.Background(), discardStream{}, nil, func() int { return PacketHeadroom }),
		server:           server,
		ctx:              context.Background(),
		addresses:        addresses,
		peerRoutes:       peerRoutes,
		advertisedRoutes: advertisedRoutesFor(server, addresses, 0),
	}
	// The fixture keeps production wiring: a serverSession IS its own sessionHandler. What
	// is captured instead is the QUEUE's delivery, because that is where a reply actually
	// goes out.
	current.handler = current
	current.queue = newTestOutboundQueue(func(packetBuffers []*buf.Buffer) {
		recordDelivery(current, packetBuffers)
	})
	if len(current.advertisedRoutes) == 0 {
		t.Fatalf("the fixture produced no egress routes for %v", addresses)
	}
	return current
}

// advertisedRoutesFor mirrors the route construction in NewTunnelRequest: the
// server's advertised routes intersected with the families the session holds.
func advertisedRoutesFor(server *Server, addresses []netip.Addr, protocol uint8) []AddressRange {
	ranges := server.advertiseRoutes.Ranges()
	advertised := make([]AddressRange, 0, len(ranges))
	for _, ipRange := range ranges {
		for _, address := range addresses {
			if ipRange.From().BitLen() != address.BitLen() {
				continue
			}
			advertised = append(advertised, AddressRange{
				Start:    ipRange.From(),
				End:      ipRange.To(),
				Protocol: protocol,
			})
			break
		}
	}
	return advertised
}

// ownedPacketBuffer copies a raw packet into a MANAGED buffer.
//
// buf.As is not usable on this path: it returns an UNMANAGED buffer, and the
// forwarding path copies the packet into a fresh buffer rather than taking the
// argument, so an unmanaged argument silently contributes nothing to the leak
// accounting the resource tests rely on. It also makes packet content indistinguishable
// from a released buffer, because Release on an unmanaged buffer is a no-op that
// leaves the bytes in place.
func ownedPacketBuffer(packet []byte) *buf.Buffer {
	buffer := buf.NewSize(len(packet))
	buffer.Write(packet)
	return buffer
}

// ownershipProbeHandler is both a sessionHandler and a ServerHandler, so one value
// can observe what a session delivers AND what the device path receives.
//
// Device deliveries are counted and RELEASED: the server hands the device path
// buffers it no longer owns, and a test that dropped them would leak in a way the
// leak assertions in the resource test would then blame on something else.
type ownershipProbeHandler struct {
	device int
}

func (h *ownershipProbeHandler) handleAddressAssign([]AssignedAddress) error   { return nil }
func (h *ownershipProbeHandler) handleAddressRequest([]AssignedAddress) error  { return nil }
func (h *ownershipProbeHandler) handleRouteAdvertisement([]AddressRange) error { return nil }
func (h *ownershipProbeHandler) handlePacket(buffer *buf.Buffer)               { buffer.Release() }
func (h *ownershipProbeHandler) handlePacketTooBig(buffer *buf.Buffer, mtu int) {
	buffer.Release()
}

func (h *ownershipProbeHandler) FrontHeadroom() int { return PacketHeadroom }

func (h *ownershipProbeHandler) NewOutboundQueue(handler func(packetBuffers []*buf.Buffer)) *tun.OutboundQueue {
	return newTestOutboundQueue(nil)
}

func (h *ownershipProbeHandler) WriteInboundBuffers(buffers []*buf.Buffer) error {
	h.device += len(buffers)
	for _, buffer := range buffers {
		buffer.Release()
	}
	return nil
}

// queuedObservation is what a test can learn about a packet a session queued.
type queuedObservation struct {
	protocol uint8
	ttl      uint8
	source   netip.Addr
	dest     netip.Addr
}

// drainQueuedPackets records what each packet a session queued says about itself, then
// releases the buffers. The values are measured BEFORE the release, because Release
// recycles the buffer.
func drainQueuedPackets(t *testing.T, current *serverSession) []queuedObservation {
	t.Helper()
	return drainQueuedPacketsUntil(t, current, 0)
}

// drainQueuedPacketsUntil is drainQueuedPackets for a caller that KNOWS a delivery is
// coming.
//
// expected is how many packets the caller expects the session's queue to deliver. The
// queue delivers through its handler loop, which runs after the code that queued the
// packet returns, so an immediate drain races it and observes nothing. Waiting for the
// expected delivery observes the same packet through the same production queue; a caller
// that expects nothing (expected == 0) still returns immediately, so negative assertions
// are not slowed down or turned into timeouts.
func drainQueuedPacketsUntil(t *testing.T, current *serverSession, expected int) []queuedObservation {
	t.Helper()
	var observations []queuedObservation
	for {
		packet := current.takeQueuedUntil(func(queued int) bool {
			return len(observations)+queued < expected
		})
		if packet == nil {
			return observations
		}
		{
			observation := queuedObservation{}
			if source, destination, protocol, valid := packetAddresses(packet.Bytes()); valid {
				observation.source = source
				observation.dest = destination
				observation.protocol = protocol
				switch header.IPVersion(packet.Bytes()) {
				case header.IPv4Version:
					observation.ttl = header.IPv4(packet.Bytes()).TTL()
				case header.IPv6Version:
					observation.ttl = header.IPv6(packet.Bytes()).HopLimit()
				}
			}
			observations = append(observations, observation)
			packet.Release()
		}
	}
}

// takeQueued returns the next packet a session queued, or nil when nothing is pending.
//
// The queue delivers through its handler, so the fixture records what arrived and this
// pops from that record. A session that has not been run() never drains its own queue, so a
// test that wants to observe a DELIVERED packet takes it here.
func (s *serverSession) takeQueued() *buf.Buffer {
	return s.takeQueuedUntil(nil)
}

// takeQueuedUntil is takeQueued with a settle predicate, used to observe a reply that the
// production path queues asynchronously.
//
// tun.OutboundQueue.WriteBuffers only ENQUEUES the buffer: a handler-loop goroutine calls
// the delivery handler afterwards. Production does not care, because that loop runs for as
// long as the session does, but a test that queues a reply and reads it immediately races
// the loop and observes nothing. Waiting for the expected reply observes the same
// DELIVERED packet through the same production queue without weakening any assertion.
//
// pending reports whether the caller still expects more packets. A predicate rather than a
// fixed count, so a test asserting EMPTINESS returns immediately instead of paying a
// timeout, while a test asserting a reply waits for that reply to actually arrive.
func (s *serverSession) takeQueuedUntil(pending func(queued int) bool) *buf.Buffer {
	if pending != nil {
		deadline := time.Now().Add(settleTimeout)
		for pending(s.queuedCount()) && time.Now().Before(deadline) {
			time.Sleep(settleInterval)
		}
	}
	value, loaded := queuedDeliveries.Load(s)
	if !loaded {
		return nil
	}
	recorder := value.(*deliveryRecorder)
	recorder.access.Lock()
	defer recorder.access.Unlock()
	if len(recorder.queued) == 0 {
		return nil
	}
	packet := recorder.queued[0]
	recorder.queued = recorder.queued[1:]
	return packet
}

// queuedCount returns how many packets the session's queue has delivered so far.
func (s *serverSession) queuedCount() int {
	value, loaded := queuedDeliveries.Load(s)
	if !loaded {
		return 0
	}
	recorder := value.(*deliveryRecorder)
	recorder.access.Lock()
	defer recorder.access.Unlock()
	return len(recorder.queued)
}

// settleTimeout bounds how long a test waits for the queue's handler loop to deliver, and
// settleInterval is the polling step. The loop delivers as soon as it is scheduled, so this
// is a generous upper bound rather than a sleep the tests rely on for correctness.
const (
	settleTimeout  = 2 * time.Second
	settleInterval = 200 * time.Microsecond
)

// queuedDeliveries records what each session's outbound queue delivered.
//
// The capture lives here rather than on serverSession so the production struct and the
// production wiring (a serverSession is its own sessionHandler) are both untouched: what a
// test observes is the QUEUE's delivery, which is where a reply actually leaves the session.
var queuedDeliveries sync.Map

func recordDelivery(session *serverSession, buffers []*buf.Buffer) {
	value, _ := queuedDeliveries.LoadOrStore(session, &deliveryRecorder{})
	recorder := value.(*deliveryRecorder)
	recorder.access.Lock()
	recorder.queued = append(recorder.queued, buffers...)
	recorder.access.Unlock()
}

type deliveryRecorder struct {
	access sync.Mutex
	queued []*buf.Buffer
}

// otherAddress returns whichever of first/second is not the given address.
func otherAddress(given netip.Addr, first netip.Addr, second netip.Addr) netip.Addr {
	if given == first {
		return second
	}
	return first
}

// requireQueuedPacketLike fails unless the session queued at least one packet, and
// returns the observations it drained.
//
// The wait is bounded and the queue is the observable: handlePacket queues its
// reply synchronously, so an empty queue is a bug rather than a timing artefact.
// Polling only keeps the assertion independent of exactly where the queueing
// happens relative to the call.
func requireQueuedPacketLike(t *testing.T, current *serverSession, why string) []queuedObservation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if observations := drainQueuedPackets(t, current); len(observations) > 0 {
			return observations
		}
		if time.Now().After(deadline) {
			t.Fatalf("the session queued no reply, expected %s", why)
		}
		time.Sleep(time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Area 1: ownership and route policy.
// ---------------------------------------------------------------------------

// TestTunnelIngressRejectsAForgedSource is the "A forges B" case at the boundary
// where it is actually enforced.
//
// Client A is assigned 198.18.0.2 and client B is assigned 198.18.0.3. A sends an
// inner packet whose SOURCE is B's address, over its OWN tunnel: serverSession.handlePacket
// is the handler a session's capsule loop calls, so this is the real ingress path.
// Three things must hold:
//
//   - the packet is never written to the device as if it came from B, which is what
//     makes it spoofing rather than a routing mistake;
//   - the sender receives an ICMP error, so a policy rejection is distinguishable
//     from packet loss;
//   - the error goes back to the FORGING session, not to the session whose address
//     was stolen.
//
// The legitimate direction is asserted in the same table: a one-directional
// assertion would also pass against an implementation that dropped everything.
//
// WHY THIS IS NOT TESTED VIA Server.WritePacketBuffers: that method is the
// device->tunnel direction and it does NOT apply a source-ownership check at all --
// see TestDeviceIngressSourcePolicyIsNotEnforced for the measurement. Asserting a
// forgery rejection there would assert behaviour that does not exist, and weakening
// it to "the packet is delivered somewhere" would assert the opposite of what the
// test is for. So the forgery case is pinned where the guard lives.
func TestTunnelIngressRejectsAForgedSource(t *testing.T) {
	addressA := netip.MustParseAddr("198.18.0.2")
	addressB := netip.MustParseAddr("198.18.0.3")
	destination := netip.MustParseAddr("203.0.113.9")

	for _, testCase := range []struct {
		name string
		// assigned is what the server actually gave the sending session.
		assigned netip.Addr
		// forged is the source the packet claims.
		forged netip.Addr
		// allowed is whether the packet is legitimate.
		allowed bool
	}{
		{
			name:     "A claiming B's address",
			assigned: addressA,
			forged:   addressB,
			allowed:  false,
		},
		{
			name:     "B claiming A's address",
			assigned: addressB,
			forged:   addressA,
			allowed:  false,
		},
		{
			name:     "A claiming the server's own gateway address",
			assigned: addressA,
			forged:   netip.MustParseAddr("198.18.0.1"),
			allowed:  false,
		},
		{
			name:     "A claiming an address nobody holds",
			assigned: addressA,
			forged:   netip.MustParseAddr("198.18.0.99"),
			allowed:  false,
		},
		{
			name:     "A claiming its own address",
			assigned: addressA,
			forged:   addressA,
			allowed:  true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := newTestServer(t, ServerOptions{
				Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
			})
			probe := &ownershipProbeHandler{}
			server.handler = probe

			sender := tunnelSession(t, server, []netip.Addr{testCase.assigned}, nil)
			other := tunnelSession(t, server, []netip.Addr{
				otherAddress(testCase.assigned, addressA, addressB),
			}, nil)
			registerSession(server, sender)
			registerSession(server, other)
			defer server.releaseSession(sender)
			defer server.releaseSession(other)

			// The packet arrives from the peer over its own tunnel.
			sender.handlePacket(ownedPacketBuffer(buildOwnershipIPv4Packet(
				testCase.forged, destination, uint8(header.TCPProtocolNumber), 64)))

			if testCase.allowed {
				if probe.device != 1 {
					t.Fatalf("a packet whose source is the session's OWN assigned "+
						"address was not delivered to the device (deliveries=%d): a "+
						"legitimate packet is being dropped", probe.device)
				}
				if queued := drainQueuedPackets(t, sender); len(queued) != 0 {
					t.Fatalf("a legitimate packet produced %d queued replies", len(queued))
				}
				return
			}

			if probe.device != 0 {
				t.Fatalf("a packet with a FORGED source (%s) was written to the device "+
					"%d time(s): one client's traffic is being presented as another's",
					testCase.forged, probe.device)
			}

			// The rejection must be observable to the forger, and it must be an
			// ICMP error rather than an arbitrary reply.
			replies := requireQueuedPacketLike(t, sender,
				"an ICMP error for the packet that failed the source policy")
			if replies[0].protocol != uint8(header.ICMPv4ProtocolNumber) {
				t.Fatalf("the reply to a source-policy rejection carries protocol %d, "+
					"want ICMP (%d)", replies[0].protocol,
					uint8(header.ICMPv4ProtocolNumber))
			}
			if queued := drainQueuedPackets(t, other); len(queued) != 0 {
				t.Fatalf("the error for a packet forged by one client was queued to the "+
					"OTHER client (%d replies): the answer must go to the sender", len(queued))
			}
		})
	}
}

// TestDeviceIngressSourcePolicyIsNotEnforced RECORDS a measured gap rather than
// asserting a guarantee.
//
// Server.WritePacketBuffers is the device->tunnel direction. It decides where a
// packet goes from its DESTINATION and the receiving session's advertised routes
// (session.accepts), and it never asks whether the packet's SOURCE belongs to anyone.
// Measured: a packet whose source is another client's assigned address, or an address
// nobody holds at all, is delivered into a tunnel exactly like a legitimate one.
//
// This is recorded rather than fixed, and recorded rather than silently omitted,
// because the two directions are easy to confuse: the ingress direction (a peer
// sending INTO the server) DOES enforce it in serverSession.handlePacket, and the
// suite covers that in TestTunnelIngressRejectsAForgedSource. A reader who saw only
// the ingress test would reasonably assume the egress direction is symmetric.
//
// WHY THIS MAY BE DEFENSIBLE, and why this test does not declare a bug outright: the
// device path receives packets from the TUN device, which is the host's own routing
// stack. A source address on that path was chosen by the host, not by a remote peer,
// and the kernel already refuses to route packets whose source does not belong to the
// host. The exposed surface is therefore a host-local process, not a remote client.
// The test pins CURRENT behaviour so a future change is deliberate, and fails loudly
// if it changes in either direction with the comment left stale.
func TestDeviceIngressSourcePolicyIsNotEnforced(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
	})
	probe := &ownershipProbeHandler{}
	server.handler = probe

	addressB := netip.MustParseAddr("198.18.0.3")
	// B advertises the range this test sends into, so the ROUTING half of the
	// decision is unambiguous and only the SOURCE policy is under observation.
	b := tunnelSession(t, server, []netip.Addr{addressB}, []AddressRange{{
		Start:    netip.MustParseAddr("203.0.113.0"),
		End:      netip.MustParseAddr("203.0.113.255"),
		Protocol: 0,
	}})
	registerSession(server, b)
	defer server.releaseSession(b)

	destination := netip.MustParseAddr("203.0.113.9")

	// The observation is what happens to the packet, and there are exactly three
	// possible outcomes: it is handed to the device, it is queued into a tunnel, or
	// it is answered with an ICMP error. Counting all three is what makes this a
	// measurement rather than an assumption about which branch is taken.
	for _, testCase := range []struct {
		name   string
		source netip.Addr
		// note explains what the current value means.
		note string
	}{
		{
			name:   "source is the receiving session's own address",
			source: addressB,
			note:   "the legitimate case, and the control for the two below",
		},
		{
			name:   "source is another client's assigned address",
			source: netip.MustParseAddr("198.18.0.4"),
			note: "measured: forwarded into the tunnel, so no source check is applied " +
				"on this path",
		},
		{
			name:   "source is an address nobody holds",
			source: netip.MustParseAddr("198.18.0.99"),
			note:   "measured: an unowned source is likewise forwarded, not rejected",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			before := probe.device
			server.WritePacketBuffers([]*buf.Buffer{
				ownedPacketBuffer(buildOwnershipIPv4Packet(testCase.source, destination,
					uint8(header.TCPProtocolNumber), 64)),
			}, false)
			deviceDeliveries := probe.device - before
			// The routing decision puts the packet on the session's queue, which delivers
			// through its handler loop after this call returns, so wait for the expected
			// delivery rather than racing it.
			//
			// This is drained ONCE. An earlier version drained the queue twice, once for
			// "tunnel" and once for "replies"; the first drain consumed the only packet,
			// so the second always reported zero and the two counters could not be
			// compared. There is one observation here: what the session received.
			queued := drainQueuedPacketsUntil(t, b, 1)
			tunnelDeliveries := len(queued)
			replies := 0

			t.Logf("source %s -> device %d, tunnel %d, replies %d (%s)",
				testCase.source, deviceDeliveries, tunnelDeliveries, replies, testCase.note)

			if tunnelDeliveries != 1 {
				t.Fatalf("a packet with source %s and destination %s was handed to the "+
					"tunnel %d time(s), want 1: the destination IS routed to this session, "+
					"so this test is meant to observe what the SOURCE policy does to a "+
					"packet that already has a valid destination. device=%d replies=%d",
					testCase.source, destination, tunnelDeliveries, deviceDeliveries, replies)
			}
			// The point of the test: the tunnel took it whatever the source was.
			// If this ever starts failing, a source check has been ADDED to the
			// device->tunnel direction, and the comment above must be rewritten.
			if deviceDeliveries != 0 {
				t.Fatalf("the packet was BOTH queued into a tunnel and written to the "+
					"device (%d): it must take exactly one path", deviceDeliveries)
			}
		})
	}
}

// TestPeerAdvertisementCannotClaimTheGateways covers BOTH IP families for the
// gateway guard, asserted through lookup() and Contains().
//
// The server's own address is kept out of the advertisement scan by an explicit
// comparison, and the two families reach it differently: the IPv4 gateway is the
// prefix address the pool also reserves, while the IPv6 gateway is only ever
// compared as inet6Address. A client advertising its tunnel network -- the obvious
// thing to advertise -- must not be handed traffic for either.
func TestPeerAdvertisementCannotClaimTheGateways(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		prefix     string
		gateway    string
		assigned   string
		advertised AddressRange
		unowned    string
	}{
		{
			name:       "IPv4 gateway",
			prefix:     ownershipTestPrefix,
			gateway:    "198.18.0.1",
			assigned:   "198.18.0.2",
			advertised: mustRange(t, "198.18.0.0", "198.18.0.255", 0),
			unowned:    "198.18.0.9",
		},
		{
			name:       "IPv6 gateway",
			prefix:     "2001:db8::1/120",
			gateway:    "2001:db8::1",
			assigned:   "2001:db8::2",
			advertised: mustRange(t, "2001:db8::", "2001:db8::ff", 0),
			unowned:    "2001:db8::9",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			gateway := netip.MustParseAddr(testCase.gateway)
			server := newTestServer(t, ServerOptions{
				Address: []netip.Prefix{netip.MustParsePrefix(testCase.prefix)},
			})

			client := tunnelSession(t, server, []netip.Addr{netip.MustParseAddr(testCase.assigned)},
				[]AddressRange{testCase.advertised})
			registerSession(server, client)
			defer server.releaseSession(client)

			if got := server.lookup(gateway, 0); got != nil {
				t.Fatalf("the gateway %s was claimed by a peer advertisement (%p): the "+
					"server's own tunnel address must stay with the server", gateway, got)
			}
			if server.Contains(gateway) {
				t.Fatalf("Contains reported the gateway %s as tunnel-owned, so "+
					"`preferred_by` would route the server's own traffic into a tunnel "+
					"that then refuses it", gateway)
			}
			// Control: an ordinary address in the same network must still be
			// claimable, or the guard above would also pass against an
			// advertisement that does nothing at all.
			if got := server.lookup(netip.MustParseAddr(testCase.unowned), 0); got != client {
				t.Fatalf("an address covered by the advertisement was not routed to the "+
					"advertising session (%p): the gateway guard must not disable routing",
					got)
			}
		})
	}
}

// TestAssignedAddressSurvivesAnAdvertisedOverlapCapsule goes through the real
// control path instead of assembling serverSession state by hand.
//
// A peer sends an actual ROUTE_ADVERTISEMENT capsule whose ranges cover both the
// server's gateway and another client's assigned address. Two distinct behaviours
// are pinned:
//
//   - the overlapping capsule is REJECTED by parseRoutes, so it never reaches the
//     routing table at all (the composition of the parser bound with the ownership
//     rule, which no existing test asserts end to end);
//   - a well-formed capsule that still covers both protected addresses IS accepted,
//     and the routing table must still refuse to hand over either of them.
func TestAssignedAddressSurvivesAnAdvertisedOverlapCapsule(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
	})

	gateway := netip.MustParseAddr("198.18.0.1")
	otherClientsAddress := netip.MustParseAddr("198.18.0.7")

	owner := tunnelSession(t, server, []netip.Addr{otherClientsAddress}, nil)
	registerSession(server, owner)
	defer server.releaseSession(owner)

	advertiser := tunnelSession(t, server, []netip.Addr{netip.MustParseAddr("198.18.0.6")}, nil)
	registerSession(server, advertiser)
	defer server.releaseSession(advertiser)

	// The capsule a hostile peer would send: one range at protocol 0 covering the
	// tunnel network, plus a protocol 6 range covering the gateway on its own. The
	// pair overlaps, so parseRoutes rejects the whole capsule and nothing from it
	// can be applied - not the wide range and not the narrow one.
	capsulePayload := routeCapsulePayload([]AddressRange{
		mustRange(t, "198.18.0.0", "198.18.0.255", 0),
		mustRange(t, "198.18.0.1", "198.18.0.1", 6),
	})
	if _, err := parseRoutes(capsulePayload); err == nil {
		t.Fatal("the capsule this test relies on being rejected was accepted by " +
			"parseRoutes, so the test no longer covers the rejection path that keeps " +
			"the routing table clean")
	}
	// And the session's handler is never reached with it, so the table is untouched.
	if got := server.lookup(otherClientsAddress, 6); got != owner {
		t.Fatalf("before any advertisement, the assigned address already routes "+
			"elsewhere (%p vs %p)", got, owner)
	}

	// A well-formed advertisement that still covers both protected addresses: the
	// parser accepts it (one range, so nothing overlaps within it), and the routing
	// table must still refuse to hand over either address.
	if err := advertiser.handleRouteAdvertisement([]AddressRange{
		mustRange(t, "198.18.0.0", "198.18.0.255", 0),
	}); err != nil {
		t.Fatalf("applying a well-formed advertisement failed: %v", err)
	}
	defer advertiser.handleRouteAdvertisement(nil)

	if got := server.lookup(gateway, 0); got != nil {
		t.Fatalf("the server's gateway %s was claimed by a peer advertisement (%p)",
			gateway, got)
	}
	if got := server.lookup(otherClientsAddress, 0); got != owner {
		t.Fatalf("another client's assigned address %s was claimed by a peer "+
			"advertisement (%p vs %p)", otherClientsAddress, got, owner)
	}
	// Control: the advertisement must still work for addresses nobody owns.
	if got := server.lookup(netip.MustParseAddr("198.18.0.200"), 0); got != advertiser {
		t.Fatalf("a genuinely unowned address covered by the advertisement was not "+
			"routed to the advertiser (%p)", got)
	}
}

// TestAdvertisedOverlapTable covers the two-route overlap shapes at the routing
// table level, over BOTH IP families.
//
// This is the half the parser cannot express. parseRoutes rejects overlapping
// ranges WITHIN one capsule, but handleRouteAdvertisement simply REPLACES
// s.peerRoutes with the last capsule it received. So the question of what an
// overlap would do if one ever reached the table has to be answered by the table
// itself, and the answer must not depend on the order the ranges appear in.
func TestAdvertisedOverlapTable(t *testing.T) {
	assigned := netip.MustParseAddr("198.18.0.9")
	v6Assigned := netip.MustParseAddr("2001:db8::9")

	for _, testCase := range []struct {
		name string
		// routes are the peer's advertised ranges, in the order they would be
		// parsed from the wire.
		routes []AddressRange
		// claimed must stay with the assigned session whatever order is used.
		claimed netip.Addr
		// protocol is the protocol of the traffic being classified.
		protocol uint8
	}{
		{
			name: "IPv4 protocol 0 first, then the same range at protocol 6",
			routes: []AddressRange{
				mustRange(t, "198.18.0.0", "198.18.0.255", 0),
				mustRange(t, "198.18.0.0", "198.18.0.255", 6),
			},
			claimed:  assigned,
			protocol: 6,
		},
		{
			name: "IPv4 protocol 6 first, then the same range at protocol 0",
			routes: []AddressRange{
				mustRange(t, "198.18.0.0", "198.18.0.255", 6),
				mustRange(t, "198.18.0.0", "198.18.0.255", 0),
			},
			claimed:  assigned,
			protocol: 17,
		},
		{
			name: "IPv6 protocol 0 first, then the same range at protocol 17",
			routes: []AddressRange{
				mustRange(t, "2001:db8::", "2001:db8::ffff", 0),
				mustRange(t, "2001:db8::", "2001:db8::ffff", 17),
			},
			claimed:  v6Assigned,
			protocol: 17,
		},
		{
			name: "IPv6 protocol 17 first, then the same range at protocol 0",
			routes: []AddressRange{
				mustRange(t, "2001:db8::", "2001:db8::ffff", 17),
				mustRange(t, "2001:db8::", "2001:db8::ffff", 0),
			},
			claimed:  v6Assigned,
			protocol: 6,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := newTestServer(t, ServerOptions{
				Address: []netip.Prefix{
					netip.MustParsePrefix(ownershipTestPrefix),
					netip.MustParsePrefix("2001:db8::1/120"),
				},
			})

			owner := tunnelSession(t, server, []netip.Addr{assigned, v6Assigned}, nil)
			registerSession(server, owner)
			defer server.releaseSession(owner)

			advertiser := tunnelSession(t, server, []netip.Addr{
				netip.MustParseAddr("198.18.0.10"),
				netip.MustParseAddr("2001:db8::a"),
			}, testCase.routes)
			registerSession(server, advertiser)
			defer server.releaseSession(advertiser)

			if got := server.lookup(testCase.claimed, testCase.protocol); got != owner {
				t.Fatalf("with the advertised ranges in this order an address ASSIGNED "+
					"to one session was claimed by another session's advertisement "+
					"(%p vs %p): the ownership decision depends on route ordering, so a "+
					"peer can pick the winner by reordering its advertisement",
					got, owner)
			}
			if !server.Contains(testCase.claimed) {
				t.Fatalf("%s is assigned to a live session and must be reported as owned",
					testCase.claimed)
			}
		})
	}
}

// TestProtocolZeroAdvertisementCarriesEveryProtocol is the protocol-0 case.
//
// Protocol 0 means ALL protocols, so a single protocol-0 advertisement must carry
// TCP, UDP and ICMP. The negative half - that a protocol-specific route carries
// only its own protocol - is asserted in the same table, so an implementation that
// matched everything regardless of protocol could not pass it.
func TestProtocolZeroAdvertisementCarriesEveryProtocol(t *testing.T) {
	destination := netip.MustParseAddr("203.0.113.9")

	for _, testCase := range []struct {
		name string
		// advertisedProtocol is what the peer put on the wire.
		advertisedProtocol uint8
		// matchProtocols must reach the advertising session.
		matchProtocols []uint8
		// nonMatchProtocols must NOT reach it.
		nonMatchProtocols []uint8
	}{
		{
			name:               "protocol 0 matches every protocol",
			advertisedProtocol: 0,
			matchProtocols: []uint8{
				uint8(header.TCPProtocolNumber),
				uint8(header.UDPProtocolNumber),
				uint8(header.ICMPv4ProtocolNumber),
			},
		},
		{
			name:               "protocol 6 matches TCP and the control protocols",
			advertisedProtocol: 6,
			matchProtocols: []uint8{
				uint8(header.TCPProtocolNumber),
				// isControlProtocol short-circuits RoutesContain, so ICMP is
				// always admitted. That is deliberate - ICMP errors have to be
				// able to reach any tunnel - and is recorded here as MEASURED
				// behaviour rather than left to be rediscovered.
				uint8(header.ICMPv4ProtocolNumber),
			},
			nonMatchProtocols: []uint8{uint8(header.UDPProtocolNumber)},
		},
		{
			name:               "protocol 17 matches UDP and the control protocols",
			advertisedProtocol: 17,
			matchProtocols: []uint8{
				uint8(header.UDPProtocolNumber),
				uint8(header.ICMPv6ProtocolNumber),
			},
			nonMatchProtocols: []uint8{uint8(header.TCPProtocolNumber)},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := newTestServer(t, ServerOptions{
				Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
			})

			current := tunnelSession(t, server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, []AddressRange{{
				Start:    netip.MustParseAddr("203.0.113.0"),
				End:      netip.MustParseAddr("203.0.113.255"),
				Protocol: testCase.advertisedProtocol,
			}})
			registerSession(server, current)
			defer server.releaseSession(current)

			for _, protocol := range testCase.matchProtocols {
				if got := server.lookup(destination, protocol); got != current {
					t.Fatalf("an advertisement at protocol %d must carry protocol %d, "+
						"but lookup returned %p", testCase.advertisedProtocol, protocol, got)
				}
			}
			for _, protocol := range testCase.nonMatchProtocols {
				if got := server.lookup(destination, protocol); got != nil {
					t.Fatalf("an advertisement at protocol %d must NOT carry protocol %d, "+
						"but lookup returned %p", testCase.advertisedProtocol, protocol, got)
				}
			}
		})
	}
}

// TestPeerAdvertisementWithMixedFamiliesKeepsOwnership covers both families in one
// advertisement.
//
// A peer may advertise ranges of both families, and RFC 9484 orders them by version.
// The ownership maps are keyed by a single netip.Addr, so the family a range is in
// must not change which address it can claim.
func TestPeerAdvertisementWithMixedFamiliesKeepsOwnership(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{
			netip.MustParsePrefix(ownershipTestPrefix),
			netip.MustParsePrefix("2001:db8::1/120"),
		},
	})

	v4Assigned := netip.MustParseAddr("198.18.0.11")
	v6Assigned := netip.MustParseAddr("2001:db8::11")
	owner := tunnelSession(t, server, []netip.Addr{v4Assigned, v6Assigned}, nil)
	registerSession(server, owner)
	defer server.releaseSession(owner)

	advertiser := tunnelSession(t, server, []netip.Addr{
		netip.MustParseAddr("198.18.0.12"),
		netip.MustParseAddr("2001:db8::12"),
	}, []AddressRange{
		mustRange(t, "198.18.0.0", "198.18.0.255", 0),
		mustRange(t, "2001:db8::", "2001:db8::ffff", 0),
	})
	registerSession(server, advertiser)
	defer server.releaseSession(advertiser)

	for _, address := range []netip.Addr{v4Assigned, v6Assigned} {
		if got := server.lookup(address, 0); got != owner {
			t.Fatalf("assigned address %s was claimed by a mixed-family peer "+
				"advertisement (%p vs %p)", address, got, owner)
		}
	}
	for _, address := range []netip.Addr{
		netip.MustParseAddr("198.18.0.200"),
		netip.MustParseAddr("2001:db8::200"),
	} {
		if got := server.lookup(address, 0); got != advertiser {
			t.Fatalf("unowned address %s covered by the advertisement was not routed to "+
				"the advertiser (%p)", address, got)
		}
	}
}

// TestTunnelIngressSourcePolicyForIPv6 is the IPv6 half of the ingress source check.
//
// The ingress guard has to work per family, and nothing else in the suite drives an
// IPv6 packet through serverSession.handlePacket. The gateway's address is the case
// worth pinning: only the server can be its source, so a client that sends it is
// forging by construction, and the guard must not be reading a family-specific field
// it never populated.
func TestTunnelIngressSourcePolicyForIPv6(t *testing.T) {
	gateway := netip.MustParseAddr("2001:db8::1")
	assigned := netip.MustParseAddr("2001:db8::2")
	// The destination must be OUTSIDE the tunnel prefix. Inside it, handlePacket
	// relays the packet back into a tunnel (address unreachable / another session)
	// and the device path is never reached, which would make the legitimate case
	// below assert the wrong branch.
	destination := netip.MustParseAddr("2001:db8:1::9")

	for _, testCase := range []struct {
		name    string
		source  netip.Addr
		allowed bool
	}{
		{name: "the gateway's own address", source: gateway, allowed: false},
		{name: "an address nobody holds", source: netip.MustParseAddr("2001:db8::99"), allowed: false},
		{name: "the session's assigned address", source: assigned, allowed: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := newTestServer(t, ServerOptions{
				Address: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/120")},
			})
			probe := &ownershipProbeHandler{}
			server.handler = probe

			current := tunnelSession(t, server, []netip.Addr{assigned}, nil)
			registerSession(server, current)
			defer server.releaseSession(current)

			current.handlePacket(ownedPacketBuffer(buildOwnershipIPv6Packet(testCase.source,
				destination, uint8(header.UDPProtocolNumber), 64)))

			if testCase.allowed {
				if probe.device != 1 {
					t.Fatalf("a legitimate IPv6 packet from the session's own address did "+
						"not reach the device (deliveries=%d)", probe.device)
				}
				if queued := drainQueuedPackets(t, current); len(queued) != 0 {
					t.Fatalf("a legitimate IPv6 packet produced %d queued replies",
						len(queued))
				}
				return
			}

			if probe.device != 0 {
				t.Fatalf("an IPv6 packet whose source is %s was written to the device: the "+
					"source policy is not applied to IPv6 on the ingress path",
					testCase.source)
			}
			replies := requireQueuedPacketLike(t, current,
				"an ICMP error for the IPv6 packet that failed the source policy")
			if replies[0].protocol != uint8(header.ICMPv6ProtocolNumber) {
				t.Fatalf("the reply to an IPv6 source-policy rejection carries protocol %d, "+
					"want ICMPv6 (%d)", replies[0].protocol,
					uint8(header.ICMPv6ProtocolNumber))
			}
		})
	}
}

// TestTheOwnershipScanIsLinearOverAdvertisedRanges keeps the large-input case
// consistent with TestRouteAdvertisementValidationIsLinear.
//
// lookup() and Contains() scan a session's advertised ranges on EVERY packet, so a
// quadratic scan there is a per-packet cost rather than a one-off. The fixture is the
// worst case for such a scan: many NON-overlapping ranges plus a lookup for an
// address that is in none of them, so the whole list is walked every time and no
// early match shortens the work.
//
// This is a REGRESSION GUARD, not a reproduction: the scan is slices.ContainsFunc
// today and this test passes. It exists because "the parser is linear" and "the
// lookup is linear" are two different claims, and only the first one was pinned.
func TestTheOwnershipScanIsLinearOverAdvertisedRanges(t *testing.T) {
	// The parser's own bound is the natural fixture size: a peer cannot exceed it,
	// so a larger list would measure state production can never reach.
	const rangeCount = maxRoutesPerCapsule
	routes := make([]AddressRange, 0, rangeCount)
	for index := range rangeCount {
		address := netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
		routes = append(routes, AddressRange{Start: address, End: address, Protocol: 0})
	}

	miss := netip.MustParseAddr("203.0.113.1")
	const lookups = 20000

	measure := func(t *testing.T, advertised []AddressRange) time.Duration {
		t.Helper()
		server := newTestServer(t, ServerOptions{
			Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
		})
		current := tunnelSession(t, server, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, advertised)
		registerSession(server, current)
		defer server.releaseSession(current)

		start := time.Now()
		for range lookups {
			if got := server.lookup(miss, 0); got != nil {
				t.Fatalf("lookup returned %p for an address outside every advertised range",
					got)
			}
		}
		return time.Since(start)
	}

	wide := measure(t, routes)
	// The same code path with a trivial list, so the comparison is between two
	// measurements of the same machine rather than against an absolute number that
	// the hardware decides.
	narrow := measure(t, routes[:1])

	t.Logf("%d lookups over %d advertised ranges took %v; over 1 range, %v",
		lookups, rangeCount, wide, narrow)

	// The assertion is a RATIO between two measurements on the same machine, not an
	// absolute wall-clock bound.
	//
	// That distinction was measured, not chosen for elegance: the first version used an
	// absolute 5s ceiling, which passes normally (1.46s) and FAILS under `go test -race`
	// (24.1s) because race instrumentation inflates every memory access. The test would
	// then have reported "the ownership scan is not linear" for a scan that is linear,
	// and the only way to keep an absolute bound honest would be to raise it until it
	// stopped detecting anything.
	//
	// A ratio cancels both the machine's speed and the instrumentation overhead. A
	// QUADRATIC scan is not a constant factor slower: 8192 ranges against 1 is roughly
	// 8192x the work, so it separates from a linear scan by orders of magnitude no matter
	// how slow the machine or the instrumentation is.
	//
	// The bound is stated in terms of what LINEAR actually costs, which was MEASURED
	// rather than assumed.
	//
	// A linear scan over N ranges costs about N times the work of a scan over 1, so the
	// expected ratio is ~N = 8192. Measured under -race: 1659x, comfortably UNDER the
	// linear expectation because the fixed per-lookup cost (map access, mutex, the
	// comparison against the server's own address) dominates at the small end.
	//
	// The first version of this bound was 100x, derived from a guess about what "linear"
	// should look like, and it failed on correct code at 1659x. The check now fails only
	// when the ratio EXCEEDS the linear expectation by a wide margin, which is the
	// signature of a quadratic scan: 8192 ranges quadratic is ~8192x the range TESTS, so
	// the ratio would land in the millions rather than the thousands.
	//
	// The margin (4x the linear expectation) keeps it robust on a loaded, virtualised
	// runner while still being orders of magnitude below quadratic behaviour.
	if narrow <= 0 {
		t.Fatalf("the baseline measurement is not positive (%v), so no ratio can be "+
			"formed", narrow)
	}
	ratio := float64(wide) / float64(narrow)
	linearExpectation := float64(rangeCount)
	bound := 4 * linearExpectation
	t.Logf("linearity ratio: %d ranges / 1 range = %.1fx (linear expectation %.0fx, "+
		"bound %.0fx)", rangeCount, ratio, linearExpectation, bound)
	if ratio > bound {
		t.Fatalf("%d lookups over %d advertised ranges took %v versus %v over 1 range, "+
			"a ratio of %.0fx. A linear scan over %d ranges costs about %dx the work; a "+
			"ratio near that means it is linear, and a ratio in the thousands means the "+
			"scan went quadratic. The ownership lookup must stay linear in the number of "+
			"advertised ranges",
			lookups, rangeCount, wide, narrow, ratio, rangeCount, rangeCount)
	}
}
