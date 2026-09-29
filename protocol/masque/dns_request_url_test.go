package masque

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// TestDohRequestURLDoesNotDoubleEscapeThePath is a regression test for a quiet, hard-to-diagnose
// fault in the DoH request path.
//
// # The fault
//
// A dohpath is a URI Template whose expansion is already a valid ":path". A server advertising
//
//	"/dns-query"   and   "/%E4%B8%AD/dns-query"
//
// means exactly those bytes, including the percent-encoded ones.
//
// Building the request URL with url.URL{Path: requestPath} marks that string as DECODED, so
// url.String() escapes it a second time and every '%' becomes "%25":
//
//	/dns%2Dquery  ->  /dns%252Dquery
//	/%E4%B8%AD     ->  /%25E4%25B8%25AD
//
// # Why this is worse than an obvious failure
//
// The request still goes to the right ORIGIN, so the connection, the TLS handshake and the
// same-origin check all succeed. Only the RESOURCE is wrong. The server answers 404 or, worse,
// serves a different document, and the operator sees a DNS failure with nothing pointing at the
// path. A tunnelled resolver failing this way would be attributed to the tunnel, the server or the
// network long before anyone suspected the template expansion.
//
// # What is asserted
//
// Not the exact string -- that would just restate the implementation. The property is that the
// request path survives the round trip through URL construction and parsing UNCHANGED: whatever
// the server advertised is what goes on the wire, byte for byte.
func TestDohRequestURLDoesNotDoubleEscapeThePath(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name        string
		requestPath string
		reason      string
	}{
		{name: "plain path", requestPath: "/dns-query",
			reason: "nothing to escape, so nothing may change"},
		{name: "percent-encoded hyphen", requestPath: "/dns%2Dquery",
			reason: "%2D must stay %2D; re-escaping makes it %252D"},
		{name: "percent-encoded space", requestPath: "/dns%20query",
			reason: "%20 must stay %20"},
		{name: "UTF-8 path", requestPath: "/%E4%B8%AD/dns-query",
			reason: "a multi-byte path must not have every octet re-escaped"},
		{name: "already-escaped slash", requestPath: "/dns%2Fquery",
			reason: "%2F is a literal slash inside a segment, which is NOT the same resource as /dns/query"},
		{name: "nested segments", requestPath: "/a/b/c",
			reason: "ordinary separators pass through untouched"},
		{name: "encoded percent", requestPath: "/dns%25query",
			reason: "%25 denotes a literal percent sign and must survive exactly once"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			raw, err := buildDoHRequestURL("doh.example:443", testCase.requestPath)
			require.NoError(t, err, testCase.reason)

			parsed, err := url.Parse(raw)
			require.NoError(t, err)
			require.Equal(t, testCase.requestPath, parsed.EscapedPath(),
				"the wire path must be byte-identical to what the server advertised: %s",
				testCase.reason)
		})
	}
}

// TestDohRequestURLKeepsTheOriginAndScheme asserts the parts that were never in question, so a
// future change that fixed escaping by breaking the authority is caught here rather than by a DNS
// timeout.
func TestDohRequestURLKeepsTheOriginAndScheme(t *testing.T) {
	t.Parallel()

	raw, err := buildDoHRequestURL("doh.example:8443", "/dns-query")
	require.NoError(t, err)

	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, "https", parsed.Scheme,
		"RFC 8484 DoH is HTTPS; a plaintext scheme would be a downgrade")
	require.Equal(t, "doh.example:8443", parsed.Host,
		"the port must be preserved, since it is part of the origin the connection was verified for")
	require.Empty(t, parsed.RawQuery,
		"RFC 8484 POST carries the query in the body, so the URL must not gain a query string")
	require.Empty(t, parsed.Fragment, "a fragment is never sent to the server")
}

// TestDohRequestURLRejectsMalformedEncoding proves a template that cannot be a valid ":path" is
// reported instead of being copied verbatim.
//
// Passing an unescapable path through would put a malformed request line on the wire, which a
// server may answer with a protocol error far from its cause. The template is the server's own
// advertisement, so refusing it is an accurate statement about the advertisement rather than a
// guess about intent.
//
// Note what is deliberately NOT in this list: `/%E4%B8`. That is well-formed percent-encoding which
// merely happens to decode to a truncated UTF-8 sequence, so url.PathUnescape accepts it --
// correctly, because percent-encoding validity and UTF-8 validity are independent questions. The
// UTF-8 check belongs to template validation (ExpandDohPathForPost), which rejects it before a URL
// is ever constructed.
func TestDohRequestURLRejectsMalformedEncoding(t *testing.T) {
	t.Parallel()

	for _, requestPath := range []string{
		"/dns%ZZ", // not hexadecimal
		"/dns%2",  // truncated escape
		"/dns%",   // escape with no digits at all
		"/dns%G0", // not hexadecimal in the first digit
	} {
		_, err := buildDoHRequestURL("doh.example:443", requestPath)
		require.Error(t, err, "malformed percent-encoding %q must be refused", requestPath)
	}
}

// ---------------------------------------------------------------------------
// ROUTE_ADVERTISEMENT protocol enforcement
// ---------------------------------------------------------------------------

// TestAssignedResolverDialerRefusesUnadvertisedTCP proves the truncated-answer retry cannot escape
// the protocol set the server advertised.
//
// # The flow this guards
//
// The native UDP transport retries a truncated DNS answer over TCP, dialing through whatever dialer
// it was handed. ROUTE_ADVERTISEMENT can route an address for UDP only, so handing that transport
// the raw device dialer would put TCP traffic in the tunnel for an address the server never said it
// routes. The server drops it, and the caller sees a timeout indistinguishable from packet loss.
//
// The check is therefore made before the dial, so the refusal names its reason.
func TestAssignedResolverDialerRefusesUnadvertisedTCP(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("2001:db8::53")
	underlying := &dialCountingDialer{}

	// The server advertised a route permitting UDP alone.
	resolver := dnsResolverSnapshot{
		plain: &compiledPlain{
			udpAddresses: []netip.Addr{address},
			tcpAddresses: nil,
		},
	}
	dialer := newAssignedResolverDialer(underlying, resolver, address)

	_, err := dialer.DialContext(context.Background(), N.NetworkTCP,
		M.SocksaddrFrom(address, 53))
	require.Error(t, err, "TCP was not advertised, so the retry must be refused")
	require.Contains(t, err.Error(), "not advertised as reachable over TCP")
	require.Contains(t, err.Error(), address.String(),
		"the refusal must name the address it applies to")

	require.Equal(t, 0, underlying.dialCount(),
		"the underlying dialer must never be reached, or the traffic is already in the tunnel")
}

// TestAssignedResolverDialerPermitsAdvertisedTCP is the complement: a route that DOES permit TCP
// must not be blocked, or the retry that RFC 1035 requires could never happen.
func TestAssignedResolverDialerPermitsAdvertisedTCP(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("2001:db8::53")
	underlying := &dialCountingDialer{}

	resolver := dnsResolverSnapshot{
		plain: &compiledPlain{
			udpAddresses: []netip.Addr{address},
			tcpAddresses: []netip.Addr{address},
		},
	}
	dialer := newAssignedResolverDialer(underlying, resolver, address)

	// The dial itself is expected to fail (nothing is listening); what matters is that it was
	// ATTEMPTED rather than refused.
	_, _ = dialer.DialContext(context.Background(), N.NetworkTCP, M.SocksaddrFrom(address, 53))
	require.Equal(t, 1, underlying.dialCount(),
		"an advertised TCP address must reach the underlying dialer")
}

// TestAssignedResolverDialerAlwaysPermitsUDP asserts UDP is never gated by this wrapper.
//
// The wrapper exists to constrain the TCP retry. UDP reachability was already established when the
// address was selected for the attempt, so gating it again would add a refusal path that can never
// legitimately fire -- and if it did fire it would break plain DNS entirely.
func TestAssignedResolverDialerAlwaysPermitsUDP(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("2001:db8::53")
	underlying := &dialCountingDialer{}

	// Deliberately advertise NO TCP, so the only reason UDP could pass is that it is not gated.
	resolver := dnsResolverSnapshot{
		plain: &compiledPlain{udpAddresses: []netip.Addr{address}},
	}
	dialer := newAssignedResolverDialer(underlying, resolver, address)

	_, _ = dialer.DialContext(context.Background(), N.NetworkUDP, M.SocksaddrFrom(address, 53))
	require.Equal(t, 1, underlying.dialCount(), "UDP must never be refused by this wrapper")
}

// TestAssignedResolverDialerScopesThePermissionToItsOwnAddress proves the permission is per-address
// rather than per-resolver.
//
// A nameserver may list several addresses with different route coverage. A dialer built for an
// address whose TCP is unadvertised must not inherit permission from a SIBLING address that has it,
// because the retry would then go to the wrong one.
func TestAssignedResolverDialerScopesThePermissionToItsOwnAddress(t *testing.T) {
	t.Parallel()

	udpOnly := netip.MustParseAddr("2001:db8::1")
	bothProtocols := netip.MustParseAddr("2001:db8::2")
	underlying := &dialCountingDialer{}

	resolver := dnsResolverSnapshot{
		plain: &compiledPlain{
			udpAddresses: []netip.Addr{udpOnly, bothProtocols},
			// Only the SECOND address is routable over TCP.
			tcpAddresses: []netip.Addr{bothProtocols},
		},
	}

	udpOnlyDialer := newAssignedResolverDialer(underlying, resolver, udpOnly)
	_, err := udpOnlyDialer.DialContext(context.Background(), N.NetworkTCP,
		M.SocksaddrFrom(udpOnly, 53))
	require.Error(t, err,
		"a sibling address's TCP permission must not leak to an address that lacks it")
	require.Equal(t, 0, underlying.dialCount())

	permittedDialer := newAssignedResolverDialer(underlying, resolver, bothProtocols)
	_, _ = permittedDialer.DialContext(context.Background(), N.NetworkTCP,
		M.SocksaddrFrom(bothProtocols, 53))
	require.Equal(t, 1, underlying.dialCount())
}

// dialCountingDialer records how many times it was reached, so a test can distinguish "refused
// before dialing" from "dialed and failed".
type dialCountingDialer struct {
	access sync.Mutex
	dials  int
}

func (d *dialCountingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dials++
	d.access.Unlock()
	return nil, E.New("test: dial reached the underlying dialer")
}

func (d *dialCountingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("test: not implemented")
}

func (d *dialCountingDialer) dialCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.dials
}

// TestDoHRequestURLSlashSlashDoesNotChangeTheOrigin guards a property that LOOKS like a
// malformed-path bug but is not one.
//
// A template such as "/{dns}/%00" expands to "//%00", and url.Parse rejects that as a standalone
// reference, because a leading "//" introduces an AUTHORITY component. In a full request URL the
// origin is already fixed and the same string is an ordinary path -- so refusing such a template
// would demand a rule the protocol does not have, and fuzzing flagged exactly this shape before the
// distinction was made.
//
// What actually matters is the security property: a path beginning with "//" must not be able to
// relocate the request to another host. That is asserted here directly, because "the path is odd"
// and "the request went somewhere else" are very different outcomes.
func TestDoHRequestURLSlashSlashDoesNotChangeTheOrigin(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		path   string
		reason string
	}{
		{path: "//%00", reason: "the expansion of /{dns}/%00"},
		{path: "//evil.test/dns-query", reason: "an explicit host-looking path"},
		{path: "//user:pass@evil.test/x", reason: "userinfo must not relocate the request"},
		{path: "///evil.test/x", reason: "three slashes"},
		{path: "//evil.test:8443/x", reason: "a path naming both host and port"},
	} {
		requestURL, err := buildDoHRequestURL("doh.example:443", testCase.path)
		require.NoError(t, err, testCase.reason)

		parsed, err := url.Parse(requestURL)
		require.NoError(t, err, testCase.reason)
		require.Equal(t, "doh.example:443", parsed.Host,
			"the DoH request must stay on the origin the connection was verified for: %s", testCase.reason)
		require.Equal(t, testCase.path, parsed.EscapedPath(),
			"and the path must still be carried verbatim: %s", testCase.reason)
	}
}
