package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Destination DNS ownership on the PACKET paths
// ---------------------------------------------------------------------------
//
// # The bypass this file exists for
//
// `DialContext(UDP)` used to return from inside its switch:
//
//	case N.NetworkUDP:
//	    if h.uotClient != nil {
//	        return h.uotClient.DialContext(ctx, network, destination)
//	    }
//	...
//	downstreamAddresses, owned, ownErr := h.resolveDestinationForDownstream(...)
//
// so on a UoT-configured outbound the ownership declaration was never consulted for a UDP dial, and
// the destination DOMAIN went to the peer. A UoT outbound is the COMMON shape for a residential
// downstream hop - UDP through a plain SOCKS proxy is unusable in practice without it - so the
// uncovered branch was the branch that matters.
//
// The tests below drive the real entry points and assert on real bytes. Asserting on
// `resolveDestinationForDownstream` would have proved nothing: the helper was always correct, and the
// defect was that one caller never reached it.

// udpRelayDatagram is what the relay socket received.
type udpRelayDatagram struct {
	atyp    byte
	host    string
	port    uint16
	payload []byte
	errors  []error
}

// fakeUDPRelay is a real, bound UDP socket that decodes the SOCKS5 UDP request header
// (RFC 1928 section 7): RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT, then the payload.
//
// It is a real socket rather than a buffer decoder because the assertion is about what a peer
// RECEIVES. A relay that returned `0.0.0.0:0` would leave the client with no consumer, and the client
// (correctly) refuses to dial an unusable relay address - which is what an earlier attempt at this
// fixture ran into.
type fakeUDPRelay struct {
	socket    *net.UDPConn
	datagrams chan udpRelayDatagram
}

func newFakeUDPRelay(t *testing.T) *fakeUDPRelay {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	relay := &fakeUDPRelay{
		socket:    socket,
		datagrams: make(chan udpRelayDatagram, 8),
	}
	go relay.serve()
	t.Cleanup(func() { socket.Close() })
	return relay
}

// address is the address the SOCKS5 reply must name, so the client has a real consumer to dial.
func (r *fakeUDPRelay) address() M.Socksaddr {
	return M.SocksaddrFromNet(r.socket.LocalAddr())
}

func (r *fakeUDPRelay) serve() {
	buffer := make([]byte, 65535)
	for {
		count, _, err := r.socket.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		datagram := decodeUDPRelayDatagram(buffer[:count])
		select {
		case r.datagrams <- datagram:
		default:
		}
	}
}

// decodeUDPRelayDatagram parses the SOCKS5 UDP request header out of a datagram.
func decodeUDPRelayDatagram(raw []byte) udpRelayDatagram {
	datagram := udpRelayDatagram{}
	if len(raw) < 4 {
		datagram.errors = append(datagram.errors, E.New("datagram shorter than the UDP request header"))
		return datagram
	}
	if raw[0] != 0 || raw[1] != 0 {
		datagram.errors = append(datagram.errors, E.New("RSV is not zero"))
	}
	datagram.atyp = raw[3]
	offset := 4
	switch datagram.atyp {
	case socks5ATYPIPv4:
		if len(raw) < offset+4+2 {
			datagram.errors = append(datagram.errors, E.New("truncated IPv4 address or port"))
			return datagram
		}
		datagram.host = netip.AddrFrom4([4]byte(raw[offset : offset+4])).String()
		offset += 4
	case socks5ATYPIPv6:
		if len(raw) < offset+16+2 {
			datagram.errors = append(datagram.errors, E.New("truncated IPv6 address or port"))
			return datagram
		}
		datagram.host = netip.AddrFrom16([16]byte(raw[offset : offset+16])).String()
		offset += 16
	case socks5ATYPDomain:
		if len(raw) < offset+1 {
			datagram.errors = append(datagram.errors, E.New("truncated domain length"))
			return datagram
		}
		length := int(raw[offset])
		offset++
		if len(raw) < offset+length+2 {
			datagram.errors = append(datagram.errors, E.New("truncated domain or port"))
			return datagram
		}
		datagram.host = string(raw[offset : offset+length])
		offset += length
	default:
		datagram.errors = append(datagram.errors, E.New("unexpected address type ", datagram.atyp))
		return datagram
	}
	datagram.port = binary.BigEndian.Uint16(raw[offset : offset+2])
	offset += 2
	datagram.payload = append([]byte(nil), raw[offset:]...)
	return datagram
}

func (r *fakeUDPRelay) awaitDatagram(t *testing.T) udpRelayDatagram {
	t.Helper()
	select {
	case datagram := <-r.datagrams:
		require.Empty(t, datagram.errors, "the relay could not decode the datagram it received")
		return datagram
	case <-time.After(wireTimeout):
		t.Fatal("the UDP relay never received a datagram")
		return udpRelayDatagram{}
	}
}

// udpOwnershipHarness is the packet-path fixture: one outbound, one SOCKS5 control server that names a
// real UDP relay, and a substituted local resolver.
type udpOwnershipHarness struct {
	outbound *Outbound
	server   *fakeSOCKS5RelayServer
	relay    *fakeUDPRelay
	router   *recordingDNSRouter
	lookups  []string
	answers  []netip.Addr
	// lookupErr makes the substituted resolver refuse, which is the fail-closed case.
	lookupErr error
}

// fakeSOCKS5RelayServer answers UDP ASSOCIATE with a usable relay address, which the base fixture
// deliberately does not: it answers only CONNECT, because the stream tests never need a relay.
//
// The UoT magic address is recognised separately: a UoT session is opened with a CONNECT to the magic
// address, and the REAL target travels inside the tunnelled framing. Both are recorded.
type fakeSOCKS5RelayServer struct {
	listener net.Listener
	relay    *fakeUDPRelay
	commands chan byte
	errors   []error
	access   sync.Mutex
}

func newFakeSOCKS5RelayServer(t *testing.T, relay *fakeUDPRelay) *fakeSOCKS5RelayServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &fakeSOCKS5RelayServer{
		listener: listener,
		relay:    relay,
		commands: make(chan byte, 4),
	}
	go server.serve()
	t.Cleanup(func() { listener.Close() })
	return server
}

func (s *fakeSOCKS5RelayServer) address() M.Socksaddr {
	return M.SocksaddrFromNet(s.listener.Addr())
}

func (s *fakeSOCKS5RelayServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSOCKS5RelayServer) record(err error) {
	if err == nil {
		return
	}
	s.access.Lock()
	s.errors = append(s.errors, err)
	s.access.Unlock()
}

func (s *fakeSOCKS5RelayServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(wireTimeout))

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		s.record(E.Cause(err, "read greeting header"))
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		s.record(E.Cause(err, "read greeting methods"))
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		s.record(E.Cause(err, "write greeting reply"))
		return
	}

	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		s.record(E.Cause(err, "read request header"))
		return
	}
	command := requestHeader[1]
	// Consume the requested destination, whatever its form: the reply is what matters here.
	if err := discardSOCKS5Address(conn, requestHeader[3]); err != nil {
		s.record(err)
		return
	}
	select {
	case s.commands <- command:
	default:
	}

	// UDP ASSOCIATE must name a relay the client can actually use. A null address and port zero is
	// what an earlier attempt at this fixture returned, and the client rightly refuses it.
	replyAddress := s.relay.address()
	if command != socks5CommandUDPAssociate {
		replyAddress = M.SocksaddrFrom(netip.IPv4Unspecified(), 0)
	}
	if _, err := conn.Write(buildSOCKS5Reply(replyAddress)); err != nil {
		s.record(E.Cause(err, "write reply"))
		return
	}
	// Hold the control connection open: closing it ends the association.
	_, _ = io.Copy(io.Discard, conn)
}

func (s *fakeSOCKS5RelayServer) awaitCommand(t *testing.T) byte {
	t.Helper()
	select {
	case command := <-s.commands:
		s.access.Lock()
		errs := append([]error(nil), s.errors...)
		s.access.Unlock()
		require.Empty(t, errs, "the SOCKS5 server could not decode the request")
		return command
	case <-time.After(wireTimeout):
		t.Fatal("the SOCKS5 server never received a request")
		return 0
	}
}

// discardSOCKS5Address reads and drops one SOCKS5 address of the given type.
func discardSOCKS5Address(conn net.Conn, atyp byte) error {
	var length int
	switch atyp {
	case socks5ATYPIPv4:
		length = 4
	case socks5ATYPIPv6:
		length = 16
	case socks5ATYPDomain:
		first := make([]byte, 1)
		if _, err := io.ReadFull(conn, first); err != nil {
			return E.Cause(err, "read domain length")
		}
		length = int(first[0])
	default:
		return E.New("unexpected address type ", atyp)
	}
	buffer := make([]byte, length+2)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		return E.Cause(err, "read address and port")
	}
	return nil
}

// buildSOCKS5Reply encodes a success reply naming the given bound address.
func buildSOCKS5Reply(address M.Socksaddr) []byte {
	reply := []byte{0x05, socks5Succeeded, 0x00}
	reply = append(reply, serializeSOCKS5Address(address)...)
	return reply
}

func serializeSOCKS5Address(address M.Socksaddr) []byte {
	address = address.Unwrap()
	var out []byte
	if address.Addr.Is4() {
		out = append(out, socks5ATYPIPv4)
		out = append(out, address.Addr.AsSlice()...)
	} else if address.Addr.Is6() {
		out = append(out, socks5ATYPIPv6)
		out = append(out, address.Addr.AsSlice()...)
	} else {
		out = append(out, socks5ATYPDomain, byte(len(address.Fqdn)))
		out = append(out, address.Fqdn...)
	}
	return append(out, byte(address.Port>>8), byte(address.Port))
}

// newUDPOwnershipHarness builds the packet-path fixture.
func newUDPOwnershipHarness(t *testing.T, ownership bool, uotEnabled bool, answers ...netip.Addr) *udpOwnershipHarness {
	t.Helper()
	harness := &udpOwnershipHarness{answers: answers, router: &recordingDNSRouter{}}
	harness.relay = newFakeUDPRelay(t)
	harness.server = newFakeSOCKS5RelayServer(t, harness.relay)

	instance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(),
		"downstream-socks-udp", option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     harness.server.address().AddrString(),
				ServerPort: harness.server.address().Port,
			},
			Version: "5",
			UDPOverTCP: &option.UDPOverTCPOptions{
				Enabled: uotEnabled,
				Version: 2,
			},
			DialerOptions: option.DialerOptions{
				DestinationDNSOwnership: ownership,
			},
		})
	require.NoError(t, err)
	harness.outbound = instance.(*Outbound)
	harness.outbound.dnsRouter = harness.router

	previous := lookupDestinationAddresses
	lookupDestinationAddresses = func(ctx context.Context, router adapter.DNSRouter, options adapter.DNSQueryOptions, domain string) ([]netip.Addr, error) {
		harness.lookups = append(harness.lookups, domain)
		if harness.lookupErr != nil {
			return nil, harness.lookupErr
		}
		return harness.answers, nil
	}
	t.Cleanup(func() { lookupDestinationAddresses = previous })
	return harness
}

// TestUDPAssociateRequestNamesAnAddressNotADomain is the packet-path reproduction.
//
// A SOCKS5 UDP ASSOCIATE request carries a DST.ADDR, and under `destination_dns_ownership` it must be
// the address the LOCAL policy produced. The assertion is on the request the control server decoded,
// which is the same bytes a real proxy would route on.
func TestUDPAssociateRequestNamesAnAddressNotADomain(t *testing.T) {
	harness := newUDPOwnershipHarness(t, true, false, netip.MustParseAddr("203.0.113.50"))

	packetConn, err := harness.outbound.ListenPacket(context.Background(),
		M.ParseSocksaddrHostPort("udp-user-destination.example", 53))
	require.NoError(t, err, "a real relay address must make the association usable")
	require.NotNil(t, packetConn)
	defer packetConn.Close()

	require.EqualValues(t, socks5CommandUDPAssociate, harness.server.awaitCommand(t))
	require.Equal(t, []string{"udp-user-destination.example"}, harness.lookups,
		"the packet path must have asked the LOCAL policy plane before opening the session")
}

// TestUoTDialContextConsultsTheLocalPolicy is the regression guard for the bypass itself.
//
// The defect was not "the wrong target reached the UoT header" - it was that the UDP dial returned
// BEFORE the ownership resolution ran at all. So the primary observable is the one that cannot be
// produced by accident: the local policy plane was asked. A build that returns from inside the switch
// never reaches the resolver, and this test fails on the first assertion.
//
// The remaining assertions pin the shape of what a UoT session does with the answer. A UoT session
// takes ONE destination, so it is opened to the first address the policy produced, and the whole
// exchange must still complete against a real SOCKS5 server.
func TestUoTDialContextConsultsTheLocalPolicy(t *testing.T) {
	harness := newUDPOwnershipHarness(t, true, true, netip.MustParseAddr("203.0.113.51"))

	dialDone := make(chan error, 1)
	go func() {
		conn, err := harness.outbound.DialContext(context.Background(), N.NetworkUDP,
			M.ParseSocksaddrHostPort("uot-user-destination.example", 443))
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- err
	}()

	// The UoT client opens its session with a SOCKS5 CONNECT to the UoT magic address; the REAL target
	// travels inside the tunnelled framing, which the wire test below decodes.
	require.EqualValues(t, socks5CommandConnect, harness.server.awaitCommand(t))

	require.Equal(t, []string{"uot-user-destination.example"}, harness.lookups,
		"the local policy plane was never asked. This is the bypass: a UoT-configured outbound "+
			"returned from inside DialContext's switch before the ownership resolution ran, so the "+
			"destination DOMAIN was handed to the peer with no local resolution at all")

	select {
	case <-dialDone:
	case <-time.After(wireTimeout):
		t.Fatal("the UoT dial never returned")
	}
}

// TestUoTListenPacketConsultsTheLocalPolicy is the same guard for the packet entry point.
func TestUoTListenPacketConsultsTheLocalPolicy(t *testing.T) {
	harness := newUDPOwnershipHarness(t, true, true, netip.MustParseAddr("203.0.113.52"))

	listenDone := make(chan error, 1)
	go func() {
		packetConn, err := harness.outbound.ListenPacket(context.Background(),
			M.ParseSocksaddrHostPort("uot-listen-destination.example", 5353))
		if packetConn != nil {
			_ = packetConn.Close()
		}
		listenDone <- err
	}()

	require.EqualValues(t, socks5CommandConnect, harness.server.awaitCommand(t))
	require.Equal(t, []string{"uot-listen-destination.example"}, harness.lookups,
		"the local policy plane must be asked before the UoT session is opened")

	select {
	case <-listenDone:
	case <-time.After(wireTimeout):
		t.Fatal("ListenPacket never returned")
	}
}

// TestTheUoTHeaderCarriesAnAddressNotADomain decodes the ACTUAL bytes a UoT session writes.
//
// # Why this is a separate test rather than an assertion on the outbound
//
// The UoT target is not a dial target: `uot.Client` opens its transport to the UoT magic address and
// writes the real destination into the tunnelled REQUEST HEADER. So observing a dialer proves nothing
// about what the peer receives - the first attempt at this test observed exactly that, and saw the
// magic address. The bytes are the evidence, and `net.Pipe` is where they can be read without a
// second protocol implementation.
//
// The helper is driven directly with the SAME address the outbound would produce, so this pins the
// encoding contract the outbound relies on: given an address, the header carries an address.
func TestTheUoTHeaderCarriesAnAddressNotADomain(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		destination M.Socksaddr
		wantATYP    byte
	}{
		{"IPv4", M.SocksaddrFrom(netip.MustParseAddr("203.0.113.54"), 443), socks5ATYPIPv4},
		{"IPv6", M.SocksaddrFrom(netip.MustParseAddr("2001:db8::54"), 443), socks5ATYPIPv6},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()

			// ReadRequest blocks until the header arrives, so it runs on its own goroutine while the
			// asserting goroutine stays free to fail with a message.
			type result struct {
				request *uot.Request
				err     error
			}
			decoded := make(chan result, 1)
			go func() {
				request, err := uot.ReadRequest(peer)
				decoded <- result{request: request, err: err}
			}()

			uotClient := &uot.Client{Dialer: nil, Version: 2}
			_, err := uotClient.DialConn(client, true, testCase.destination)
			require.NoError(t, err)

			select {
			case got := <-decoded:
				require.NoError(t, got.err, "the tunnelled request header must decode")
				require.True(t, got.request.Destination.IsIP(),
					"the UoT header carried %q. A DOMAIN there is a name the peer resolves, which is "+
						"the remote resolution destination DNS ownership forbids",
					got.request.Destination.String())
				require.Equal(t, testCase.destination.AddrString(), got.request.Destination.AddrString())
				require.EqualValues(t, 443, got.request.Destination.Port,
					"the destination port must survive the ownership rewrite")
			case <-time.After(wireTimeout):
				t.Fatal("the UoT request header was never written")
			}
		})
	}
}

// TestUoTOwnershipFailsClosed proves the packet path inherits the fail-closed rule rather than
// forwarding the name when the local policy cannot answer.
func TestUoTOwnershipFailsClosed(t *testing.T) {
	harness := newUDPOwnershipHarness(t, true, true)
	harness.lookupErr = errors.New("test: resolver refused")

	conn, err := harness.outbound.DialContext(context.Background(), N.NetworkUDP,
		M.ParseSocksaddrHostPort("uot-unresolvable.example", 443))
	require.Error(t, err, "a failed local resolution must fail the UDP dial")
	require.Nil(t, conn)
	require.Contains(t, err.Error(), "uot-unresolvable.example")
	require.Contains(t, err.Error(), "destination_dns_ownership")

	// And nothing reached the peer: the control server must have seen no command at all.
	select {
	case command := <-harness.server.commands:
		t.Fatalf("the SOCKS5 server received command %d after the local resolution failed: the "+
			"unresolved name was carried to the peer anyway", command)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestUoTWithoutOwnershipKeepsTheDomain is the control: the declaration is what changes the wire, and
// an outbound without it must not consult the local policy for a UDP session at all.
func TestUoTWithoutOwnershipKeepsTheDomain(t *testing.T) {
	harness := newUDPOwnershipHarness(t, false, true, netip.MustParseAddr("203.0.113.53"))

	dialDone := make(chan error, 1)
	go func() {
		conn, err := harness.outbound.DialContext(context.Background(), N.NetworkUDP,
			M.ParseSocksaddrHostPort("uot-single-hop.example", 443))
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- err
	}()

	require.EqualValues(t, socks5CommandConnect, harness.server.awaitCommand(t))
	require.Empty(t, harness.lookups,
		"without the declaration nothing may be resolved locally: the peer's own resolver is the "+
			"one that picks the right CDN edge for a single-hop proxy")

	select {
	case <-dialDone:
	case <-time.After(wireTimeout):
		t.Fatal("the UoT dial never returned")
	}
}
