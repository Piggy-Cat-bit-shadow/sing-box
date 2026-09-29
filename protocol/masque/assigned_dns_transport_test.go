package masque

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// Tests for the endpoint-local assigned DNS transport.
//
// # The property that matters most
//
// This transport exists to keep server-assigned DNS queries INSIDE the tunnel. The
// failure mode that would defeat its purpose is a fallback to a host socket: a
// resolver the server named would then be reached in cleartext from the host
// interface, which draft-ietf-masque-connect-ip-dns-06 §5 explicitly warns about.
//
// So the central tests are negative: with no assignment, with an unreachable
// assignment, and with a failing tunnel, the transport must FAIL rather than resolve.

// recordingDialer counts dials and can be made to fail, so a test can prove whether the
// transport attempted the tunnel at all -- and in particular that it never attempted
// anything else.
//
// A successful dial returns a connection to a REAL loopback UDP socket that answers with
// the canned response. Using an actual socket rather than an in-memory pipe matters:
// net.Pipe is synchronous, so a single Read would block until a matching write, which
// does not exercise the same read semantics the transport uses in production.
type recordingDialer struct {
	dials   int
	fail    bool
	network string
	last    M.Socksaddr
	answer  []byte
}

func (d *recordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials++
	d.network = network
	d.last = destination
	if d.fail {
		return nil, errTestDialFailed
	}
	return dialTestUDPEcho(d.answer)
}

// dialTestUDPEcho starts a loopback UDP socket that replies to the first datagram with
// answer, and returns a connected socket pointing at it.
func dialTestUDPEcho(answer []byte) (net.Conn, error) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	go func() {
		buffer := make([]byte, 65535)
		_, remote, readErr := server.ReadFromUDP(buffer)
		if readErr != nil {
			_ = server.Close()
			return
		}
		if len(answer) > 0 {
			_, _ = server.WriteToUDP(answer, remote)
		}
		_ = server.Close()
	}()
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (d *recordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errTestDialFailed
}

func testAssignedTransport(dialer N.Dialer) *assignedDNSTransport {
	return newAssignedDNSTransport(logger.NOP(), dialer, "assigned-dns-test")
}

func testConfiguration() masque.DNSConfiguration {
	return masque.DNSConfiguration{
		Nameservers: []masque.DNSNameserver{{
			ServicePriority:          1,
			IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.53")},
			AuthenticationDomainName: "",
		}},
	}
}

// TestAssignedTransportFailsClosedWithNoAssignment is the primary leak test.
//
// With nothing assigned, a query must fail AND must not dial anything. An
// implementation that fell back to a host resolver would resolve successfully here,
// which is precisely the leak this guards against.
func TestAssignedTransportFailsClosedWithNoAssignment(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{}
	transport := testAssignedTransport(dialer)

	message := new(mDNS.Msg)
	message.SetQuestion("example.test.", mDNS.TypeA)

	_, err := transport.Exchange(context.Background(), message)
	require.Error(t, err, "a query with no assignment must fail, not resolve")
	require.Equal(t, 0, dialer.dials,
		"no assignment means no dial at all; a dial here would be an escape")
	require.Contains(t, err.Error(), "no MASQUE DNS assignment")
}

// TestAssignedTransportClearedAssignmentFailsClosed proves a WITHDRAWN assignment is
// not silently replaced by anything else.
func TestAssignedTransportClearedAssignmentFailsClosed(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{fail: true}
	transport := testAssignedTransport(dialer)
	transport.apply(oneConfiguration(testConfiguration()), nil)
	require.True(t, transport.active())

	transport.clear()
	require.False(t, transport.active(), "a cleared assignment must not be active")

	message := new(mDNS.Msg)
	message.SetQuestion("example.test.", mDNS.TypeA)
	_, err := transport.Exchange(context.Background(), message)
	require.Error(t, err, "a withdrawn assignment must fail closed")
}

// TestAssignedTransportSendsThroughTheTunnel proves the happy path uses the device
// dialer over UDP, not a host socket.
func TestAssignedTransportSendsThroughTheTunnel(t *testing.T) {
	t.Parallel()

	response := buildDNSResponse(t, "example.test.", netip.MustParseAddr("203.0.113.7"))
	dialer := &recordingDialer{answer: response}
	transport := testAssignedTransport(dialer)
	transport.apply(oneConfiguration(testConfiguration()), nil)

	message := new(mDNS.Msg)
	message.SetQuestion("example.test.", mDNS.TypeA)
	message.Id = 1

	reply, err := transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.NotNil(t, reply)
	require.Len(t, reply.Answer, 1)

	require.Equal(t, 1, dialer.dials, "exactly one dial, through the tunnel")
	require.Equal(t, N.NetworkUDP, dialer.network, "DNS must go over UDP to the tunnel")
	require.Equal(t, "192.0.2.53", dialer.last.Addr.String(),
		"the dial must target the ASSIGNED nameserver")
	require.EqualValues(t, 53, dialer.last.Port, "the default DNS port applies")
}

// TestAssignedTransportHonoursPortServiceParameter covers the SVCB "port" parameter,
// which the draft defines for nameservers reachable on a non-standard port.
func TestAssignedTransportHonoursPortServiceParameter(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{answer: buildDNSResponse(t, "example.test.", netip.MustParseAddr("203.0.113.7"))}
	transport := testAssignedTransport(dialer)

	configuration := testConfiguration()
	configuration.Nameservers[0].ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamKey(3): {0x14, 0x51}, // port 5201
	}
	transport.apply(oneConfiguration(configuration), nil)

	message := new(mDNS.Msg)
	message.SetQuestion("example.test.", mDNS.TypeA)
	_, err := transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.EqualValues(t, 5201, dialer.last.Port,
		"the SVCB port parameter must override the default")
}

// TestAssignedTransportFailsWhenTunnelFails is the tunnel-down case: the query must
// fail rather than escape.
func TestAssignedTransportFailsWhenTunnelFails(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{fail: true}
	transport := testAssignedTransport(dialer)
	transport.apply(oneConfiguration(testConfiguration()), nil)

	message := new(mDNS.Msg)
	message.SetQuestion("example.test.", mDNS.TypeA)
	_, err := transport.Exchange(context.Background(), message)
	require.Error(t, err, "a broken tunnel must fail the query, not leak it")

	// It dialled the tunnel (and only the tunnel) before failing.
	require.Positive(t, dialer.dials, "the tunnel must have been attempted")
	require.Equal(t, N.NetworkUDP, dialer.network,
		"the only dial attempted must be through the device")
}

// TestAssignedTransportEnvironmentIsolatesCache is the cache-isolation test.
//
// The DNS cache keys on Environment. Two different assignments must never share a key,
// or a response resolved by a nameserver the server has since replaced could be served
// from cache -- wrong, and a privacy problem given that the assignment exists to make a
// PARTICULAR resolver answer.
func TestAssignedTransportEnvironmentIsolatesCache(t *testing.T) {
	t.Parallel()

	transport := testAssignedTransport(&recordingDialer{})

	// The identity is never empty, and deliberately so: it carries a generation even
	// when nothing is assigned, which gives the cleared state its own cache bucket.
	// Collapsing to empty would let entries cached while an assignment WAS active
	// become reachable again after it was withdrawn -- the stale-resolver bug this
	// whole mechanism exists to prevent.
	clearedIdentity := transport.Environment()
	require.NotEmpty(t, clearedIdentity)

	transport.apply(oneConfiguration(testConfiguration()), nil)
	first := transport.Environment()
	require.NotEmpty(t, first)
	require.NotEqual(t, clearedIdentity, first,
		"the first assignment must not share the cleared state's cache identity")

	// The same assignment applied again must still advance the generation, so a
	// re-sent capsule invalidates cached answers.
	transport.apply(oneConfiguration(testConfiguration()), nil)
	second := transport.Environment()
	require.NotEqual(t, first, second,
		"re-applying an assignment must change the environment, or stale cache entries "+
			"would survive a server re-send")

	// A different nameserver must produce a different environment.
	configuration := testConfiguration()
	configuration.Nameservers[0].IPv4Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.99")}
	transport.apply(oneConfiguration(configuration), nil)
	third := transport.Environment()
	require.NotEqual(t, second, third,
		"a different nameserver must produce a different cache identity")
	require.Contains(t, third, "cfg0.ns=192.0.2.99")

	// Clearing must ALSO change it, so entries resolved by the withdrawn resolver are
	// not reused. This is the case that would silently serve answers from a resolver
	// the server has stopped advertising.
	transport.clear()
	fourth := transport.Environment()
	require.NotEqual(t, third, fourth,
		"clearing must change the cache identity so entries from the withdrawn "+
			"resolver cannot be served")
	require.NotEqual(t, clearedIdentity, fourth,
		"a clear after an assignment must not return to the original identity either")
}

// TestAssignedTransportEnvironmentIncludesResolverIdentity proves the environment
// carries the authentication domain and dohpath, which are part of what makes one
// resolver different from another.
func TestAssignedTransportEnvironmentIncludesResolverIdentity(t *testing.T) {
	t.Parallel()

	transport := testAssignedTransport(&recordingDialer{})
	configuration := testConfiguration()
	configuration.Nameservers[0].AuthenticationDomainName = "resolver.example."
	configuration.Nameservers[0].ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamALPN:   {0x02, 'h', '2'},
		dnsmessage.SVCParamKey(9): []byte("/dns-query{?dns}"),
	}
	transport.apply(oneConfiguration(configuration), nil)

	environment := transport.Environment()
	require.Contains(t, environment, "cfg0.auth=resolver.example.")
	require.Contains(t, environment, "cfg0.dohpath=/dns-query{?dns}")
}

// ---------------------------------------------------------------------------
// Route reachability
// ---------------------------------------------------------------------------

// TestAssignedNameserverMustBeReachableThroughRoutes is the route-validation test.
//
// A nameserver outside the advertised routes would be routed by the ordinary routing
// table rather than through the tunnel. Accepting it is the cleartext leak, so it must
// be refused.
func TestAssignedNameserverMustBeReachableThroughRoutes(t *testing.T) {
	t.Parallel()

	routes := []masque.AddressRange{
		rangeFor(t, "10.0.0.0/8"),
		rangeFor(t, "2001:db8::/32"),
	}

	require.True(t, isReachableThroughRoutes(netip.MustParseAddr("10.1.2.3"), routes),
		"an address inside an advertised route must be accepted")
	require.True(t, isReachableThroughRoutes(netip.MustParseAddr("2001:db8::53"), routes),
		"an address inside an advertised IPv6 route must be accepted")

	require.False(t, isReachableThroughRoutes(netip.MustParseAddr("8.8.8.8"), routes),
		"a public resolver outside the routes must be refused")
	require.False(t, isReachableThroughRoutes(netip.MustParseAddr("192.0.2.53"), routes),
		"any address outside the advertised routes must be refused")
}

// TestNoAdvertisedRoutesMeansNothingIsReachable enforces the draft's ordering rule from
// the receiving side.
//
// §5 requires that DNS_ASSIGN not be sent before ROUTE_ADVERTISEMENT, because a
// resolver outside the tunnel breaks the privacy properties. Rather than trusting the
// peer to respect that order, an assignment received with no routes in force is treated
// as unreachable, so the client falls back to its own DNS rules instead of installing a
// resolver it cannot route.
func TestNoAdvertisedRoutesMeansNothingIsReachable(t *testing.T) {
	t.Parallel()

	require.False(t, isReachableThroughRoutes(netip.MustParseAddr("10.0.0.1"), nil),
		"with no routes in force, nothing may be treated as reachable through the tunnel")
	require.False(t, isReachableThroughRoutes(netip.MustParseAddr("8.8.8.8"), []masque.AddressRange{}))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func rangeFor(t *testing.T, prefix string) masque.AddressRange {
	t.Helper()
	ranges, err := masque.RangesFromPrefixes([]netip.Prefix{netip.MustParsePrefix(prefix)}, 0)
	require.NoError(t, err)
	require.Len(t, ranges, 1)
	return ranges[0]
}

var errTestDialFailed = E.New("test: dial failed")

// buildDNSResponse constructs a minimal A-record response for the given name.
func buildDNSResponse(t *testing.T, name string, address netip.Addr) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response: true,
		RCode:    dnsmessage.RCodeSuccess,
	})
	require.NoError(t, builder.StartQuestions())
	dnsName, err := dnsmessage.NewName(name)
	require.NoError(t, err)
	require.NoError(t, builder.Question(dnsmessage.Question{
		Name:  dnsName,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}))
	require.NoError(t, builder.StartAnswers())
	require.NoError(t, builder.AResource(
		dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		dnsmessage.AResource{A: address.As4()},
	))
	message, err := builder.Finish()
	require.NoError(t, err)
	return message
}
