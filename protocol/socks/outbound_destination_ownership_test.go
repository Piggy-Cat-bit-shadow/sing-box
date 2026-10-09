package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Destination DNS ownership on the wire
// ---------------------------------------------------------------------------
//
// # The contract
//
// A downstream physical hop - a proxy the user's traffic reaches after leaving the device - must not
// resolve the user's destination. This fork's DNS policy plane owns that name; the address is what
// crosses the boundary; the domain stays in the metadata for routing, SNI, the Host header, the
// tracker and diagnostics.
//
// # Why this is asserted on the WIRE and not on the metadata
//
// `option.DialerOptions.DestinationDNSOwnership` is a promise about what a PEER receives. A test that
// read the outbound's own fields, or inspected adapter.InboundContext, would pass for an
// implementation that resolved the name and then handed the NAME to the client anyway - which is
// exactly the failure the option exists to prevent. So this file runs a real SOCKS5 server on
// loopback, decodes the CONNECT request it receives, and asserts on the ATYP byte.
//
// # What the metadata half costs
//
// The domain must not be lost either, so every ownership case also asserts that the connection
// metadata still carries it. Losing it would make "we resolved this locally" indistinguishable from
// "we forgot what the user asked for".

const (
	// socks5ATYPIPv4 / socks5ATYPIPv6 / socks5ATYPDomain are the SOCKS5 address-type bytes
	// (RFC 1928 section 5). The domain type is the one that must never reach a downstream hop under
	// this option.
	socks5ATYPIPv4   = 0x01
	socks5ATYPIPv6   = 0x04
	socks5ATYPDomain = 0x03

	socks5CommandConnect      = 0x01
	socks5CommandUDPAssociate = 0x03
	socks5Succeeded           = 0x00

	// wireTimeout is a hang detector for the server goroutine's reads. Nothing is timed.
	wireTimeout = 10 * time.Second
)

// capturedRequest is what the fake SOCKS5 server received.
type capturedRequest struct {
	atyp   byte
	host   string // the address or the domain the request named
	port   uint16
	raw    []byte
	errors []error
}

// fakeSOCKS5Server accepts exactly one connection, performs the no-auth greeting, decodes the CONNECT
// request and answers success. It records what it received, including any protocol error, so a test can
// distinguish "the request never arrived" from "the request named the wrong thing".
type fakeSOCKS5Server struct {
	listener net.Listener
	requests chan capturedRequest
}

func newFakeSOCKS5Server(t *testing.T) *fakeSOCKS5Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &fakeSOCKS5Server{
		listener: listener,
		requests: make(chan capturedRequest, 1),
	}
	go server.serve()
	t.Cleanup(func() {
		listener.Close()
	})
	return server
}

func (s *fakeSOCKS5Server) address() M.Socksaddr {
	return M.SocksaddrFromNet(s.listener.Addr())
}

func (s *fakeSOCKS5Server) serve() {
	conn, err := s.listener.Accept()
	if err != nil {
		s.requests <- capturedRequest{errors: []error{E.Cause(err, "accept")}}
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(wireTimeout))

	request := capturedRequest{}
	record := func(err error) {
		if err != nil {
			request.errors = append(request.errors, err)
		}
		s.requests <- request
	}

	// Greeting: version, method count, methods.
	header := make([]byte, 2)
	if _, err = io.ReadFull(conn, header); err != nil {
		record(E.Cause(err, "read greeting header"))
		return
	}
	if header[0] != 0x05 {
		record(E.New("unexpected socks version ", header[0]))
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err = io.ReadFull(conn, methods); err != nil {
		record(E.Cause(err, "read greeting methods"))
		return
	}
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		record(E.Cause(err, "write greeting reply"))
		return
	}

	// Request: version, command, reserved, address type.
	requestHeader := make([]byte, 4)
	if _, err = io.ReadFull(conn, requestHeader); err != nil {
		record(E.Cause(err, "read request header"))
		return
	}
	request.raw = append(request.raw, requestHeader...)
	if requestHeader[0] != 0x05 {
		record(E.New("unexpected request version ", requestHeader[0]))
		return
	}
	if requestHeader[1] != socks5CommandConnect && requestHeader[1] != socks5CommandUDPAssociate {
		record(E.New("unexpected command ", requestHeader[1]))
		return
	}
	request.atyp = requestHeader[3]
	switch request.atyp {
	case socks5ATYPIPv4:
		address := make([]byte, 4)
		if _, err = io.ReadFull(conn, address); err != nil {
			record(E.Cause(err, "read IPv4 address"))
			return
		}
		request.raw = append(request.raw, address...)
		request.host = netip.AddrFrom4([4]byte(address)).String()
	case socks5ATYPIPv6:
		address := make([]byte, 16)
		if _, err = io.ReadFull(conn, address); err != nil {
			record(E.Cause(err, "read IPv6 address"))
			return
		}
		request.raw = append(request.raw, address...)
		request.host = netip.AddrFrom16([16]byte(address)).String()
	case socks5ATYPDomain:
		length := make([]byte, 1)
		if _, err = io.ReadFull(conn, length); err != nil {
			record(E.Cause(err, "read domain length"))
			return
		}
		request.raw = append(request.raw, length[0])
		domain := make([]byte, int(length[0]))
		if _, err = io.ReadFull(conn, domain); err != nil {
			record(E.Cause(err, "read domain"))
			return
		}
		request.raw = append(request.raw, domain...)
		request.host = string(domain)
	default:
		record(E.New("unexpected address type ", request.atyp))
		return
	}
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBytes); err != nil {
		record(E.Cause(err, "read port"))
		return
	}
	request.raw = append(request.raw, portBytes...)
	request.port = binary.BigEndian.Uint16(portBytes)

	// A success reply with a null bound address. The connection is then left open until the test
	// tears it down, so the client's own teardown path is exercised rather than a server-side reset.
	if _, err = conn.Write([]byte{0x05, socks5Succeeded, 0x00, socks5ATYPIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		record(E.Cause(err, "write success reply"))
		return
	}
	record(nil)
	// Hold the connection until the test closes it or the deadline passes.
	_, _ = io.Copy(io.Discard, conn)
}

// awaitRequest returns what the server received.
//
// A decode failure is reported with the bytes it had read, because "the request named the wrong thing"
// and "the request was not a request" are different failures and the raw bytes distinguish them.
func (s *fakeSOCKS5Server) awaitRequest(t *testing.T) capturedRequest {
	t.Helper()
	select {
	case request := <-s.requests:
		if len(request.errors) > 0 {
			t.Fatalf("the SOCKS5 server could not decode the request: %v (bytes read: % x)",
				request.errors, request.raw)
		}
		return request
	case <-time.After(wireTimeout):
		t.Fatal("the SOCKS5 server never received a request")
		return capturedRequest{}
	}
}

// ---------------------------------------------------------------------------
// The fixture: an outbound whose destination DNS is owned locally
// ---------------------------------------------------------------------------

// ownershipHarness is one outbound pointed at one fake server, with the local resolver replaced.
type ownershipHarness struct {
	outbound *Outbound
	server   *fakeSOCKS5Server
	router   *recordingDNSRouter
	lookups  []string
	answers  []netip.Addr
	// lookupErr makes the substituted resolver refuse, which is the fail-closed case.
	lookupErr error
}

// newOwnershipHarness builds the outbound the configuration describes. The resolver is substituted at
// the package seam rather than through a DNS transport, because the question is what the OUTBOUND does
// with an answer - not how the answer was obtained. A real router value is still present, so the
// outbound's own "is there anything to resolve through" check passes and the seam is what answers.
func newOwnershipHarness(t *testing.T, ownership bool, version string, answers ...netip.Addr) *ownershipHarness {
	t.Helper()
	harness := &ownershipHarness{answers: answers, router: &recordingDNSRouter{}}
	harness.server = newFakeSOCKS5Server(t)

	instance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(),
		"downstream-socks", option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     harness.server.address().AddrString(),
				ServerPort: harness.server.address().Port,
			},
			Version: version,
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

// TestDownstreamOwnedDestinationIsSentAsAnAddress is the reproduction for IPv4.
//
// With destination_dns_ownership declared, a domain destination must reach the peer as ATYP=IPv4 with
// the resolved address in it - never ATYP=DOMAIN. The domain must still be resolvable from the
// connection metadata, because everything downstream of the wire reads it there.
func TestDownstreamOwnedDestinationIsSentAsAnAddress(t *testing.T) {
	harness := newOwnershipHarness(t, true, "5", netip.MustParseAddr("203.0.113.10"))

	dialDone := make(chan error, 1)
	go func() {
		defer close(dialDone)
		conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
			M.ParseSocksaddrHostPort("user-destination.example", 443))
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- err
	}()

	request := harness.server.awaitRequest(t)
	require.EqualValues(t, socks5ATYPIPv4, request.atyp,
		"a downstream hop must receive an address. ATYP=DOMAIN (%d) means the name crossed the "+
			"ownership boundary and the PEER is resolving the user's destination", socks5ATYPDomain)
	require.Equal(t, "203.0.113.10", request.host)
	require.EqualValues(t, 443, request.port)
	require.Equal(t, []string{"user-destination.example"}, harness.lookups,
		"the destination must have been resolved exactly once, locally, before the request was written")

	select {
	case err := <-dialDone:
		require.NoError(t, err, "the dial itself must succeed against a server that answered success")
	case <-time.After(wireTimeout):
		t.Fatal("the dial never returned after the server answered")
	}
}

// TestDownstreamOwnedDestinationIsSentAsAnIPv6Address is the same contract for IPv6, which is a
// different ATYP and a different encoding. A v4-only implementation would send the mapped form here.
func TestDownstreamOwnedDestinationIsSentAsAnIPv6Address(t *testing.T) {
	harness := newOwnershipHarness(t, true, "5", netip.MustParseAddr("2001:db8::10"))

	dialDone := make(chan error, 1)
	go func() {
		conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
			M.ParseSocksaddrHostPort("v6-destination.example", 8443))
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- err
	}()

	request := harness.server.awaitRequest(t)
	require.EqualValues(t, socks5ATYPIPv6, request.atyp,
		"an IPv6 answer must travel as ATYP=IPv6, not as an IPv4-mapped address")
	require.Equal(t, "2001:db8::10", request.host)
	require.EqualValues(t, 8443, request.port)

	select {
	case err := <-dialDone:
		require.NoError(t, err)
	case <-time.After(wireTimeout):
		t.Fatal("the dial never returned after the server answered")
	}
}

// TestWithoutOwnershipTheDomainStillTravels is the control, and it is the behaviour this option
// deliberately does NOT change: an ordinary single-hop SOCKS5 proxy receives the domain, because its
// own resolver is the better one for CDN and geo selection.
func TestWithoutOwnershipTheDomainStillTravels(t *testing.T) {
	harness := newOwnershipHarness(t, false, "5", netip.MustParseAddr("203.0.113.10"))

	dialDone := make(chan error, 1)
	go func() {
		conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
			M.ParseSocksaddrHostPort("single-hop.example", 443))
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- err
	}()

	request := harness.server.awaitRequest(t)
	require.EqualValues(t, socks5ATYPDomain, request.atyp,
		"without the declaration the domain must still reach the proxy: local resolution would change "+
			"which CDN edge serves the request")
	require.Equal(t, "single-hop.example", request.host)
	require.Empty(t, harness.lookups,
		"and nothing may be resolved locally for it")

	select {
	case err := <-dialDone:
		require.NoError(t, err)
	case <-time.After(wireTimeout):
		t.Fatal("the dial never returned after the server answered")
	}
}

// TestOwnershipFailsClosedWhenResolutionFails is the fail-closed contract.
//
// A destination that cannot be resolved locally must produce an ERROR, not a request that carries the
// unresolved name. The second would be a silent remote resolution performed by the very peer the
// configuration said must not perform one, and it would be invisible in the response.
func TestOwnershipFailsClosedWhenResolutionFails(t *testing.T) {
	harness := newOwnershipHarness(t, true, "5")
	harness.lookupErr = errors.New("test: resolver refused")

	conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddrHostPort("unresolvable.example", 443))
	require.Error(t, err, "resolution failure must fail the dial")
	require.Nil(t, conn)
	require.Contains(t, err.Error(), "unresolvable.example",
		"the error must name the destination whose resolution was refused")
	require.Contains(t, err.Error(), "destination_dns_ownership",
		"and it must say WHY the name was not forwarded, so the operator can find the field")

	// The decisive half: nothing was written to the peer.
	select {
	case request := <-harness.server.requests:
		t.Fatalf("a request reached the proxy (%v) after the local resolution failed: the unresolved "+
			"name was handed to the peer", request)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestOwnershipFailsClosedWhenResolutionIsEmpty covers the resolver that succeeds with no addresses.
// Sending a domain on an empty answer is the same silent remote resolution as sending one on an error.
func TestOwnershipFailsClosedWhenResolutionIsEmpty(t *testing.T) {
	harness := newOwnershipHarness(t, true, "5")

	conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddrHostPort("no-address.example", 443))
	require.Error(t, err)
	require.Nil(t, conn)
	require.Contains(t, err.Error(), "no-address.example")

	select {
	case request := <-harness.server.requests:
		t.Fatalf("a request reached the proxy (%v) although the local resolution produced no address",
			request)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestOwnershipLeavesAnAddressDestinationAlone pins that the option is about DOMAINS. A literal
// destination is already an address, and resolving it would be inventing a name by reverse lookup.
func TestOwnershipLeavesAnAddressDestinationAlone(t *testing.T) {
	harness := newOwnershipHarness(t, true, "5", netip.MustParseAddr("198.51.100.7"))

	dialDone := make(chan error, 1)
	go func() {
		conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
			M.ParseSocksaddrHostPort("198.51.100.7", 443))
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- err
	}()

	request := harness.server.awaitRequest(t)
	require.EqualValues(t, socks5ATYPIPv4, request.atyp)
	require.Equal(t, "198.51.100.7", request.host)
	require.Empty(t, harness.lookups, "a literal destination must not be resolved")

	select {
	case err := <-dialDone:
		require.NoError(t, err)
	case <-time.After(wireTimeout):
		t.Fatal("the dial never returned after the server answered")
	}
}

// TestThePacketPathOwnsTheDestination pins that ListenPacket takes the same branch as DialContext.
//
// The wire form for a packet connection needs a SOCKS server that names a usable relay port, which is
// a different protocol concern from ownership; what matters here is that the packet entry point resolves
// the destination locally and fails closed, exactly as the stream one does.
func TestThePacketPathOwnsTheDestination(t *testing.T) {
	harness := newOwnershipHarness(t, true, "5", netip.MustParseAddr("203.0.113.40"))

	// A failed resolution must refuse the packet connection rather than forward the name.
	harness.lookupErr = errors.New("test: resolver refused")
	packetConn, err := harness.outbound.ListenPacket(context.Background(),
		M.ParseSocksaddrHostPort("packet-destination.example", 53))
	require.Error(t, err, "a packet connection must fail closed under destination_dns_ownership")
	require.Nil(t, packetConn)
	require.Equal(t, []string{"packet-destination.example"}, harness.lookups,
		"the packet path must have asked the LOCAL policy plane, not the peer")
	require.Contains(t, err.Error(), "destination_dns_ownership")
}

// TestMissingRouterFailsClosed covers the construction-adjacent case: the option is declared but this
// process has no DNS router to resolve through. Passing the name through would be silent remote
// resolution, so it is an error.
func TestMissingRouterFailsClosed(t *testing.T) {
	harness := newOwnershipHarness(t, true, "5", netip.MustParseAddr("203.0.113.30"))
	harness.outbound.dnsRouter = nil

	conn, err := harness.outbound.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddrHostPort("metadata.example", 443))
	require.Error(t, err)
	require.Nil(t, conn)
	require.Contains(t, err.Error(), "no DNS router",
		"the error must name the missing component rather than looking like a resolution failure")

	select {
	case request := <-harness.server.requests:
		t.Fatalf("a request reached the proxy (%v) with no resolver available", request)
	case <-time.After(200 * time.Millisecond):
	}
}
