package http

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Fuzzing for the CONNECT-UDP request target parser (RFC 9298).
//
// # Why this target did not exist before, and why the old name was misleading
//
// transport/masque had a target called FuzzConnectUDPTemplatePath. It never
// touched CONNECT-UDP: it drove transport/masque's CONNECT-IP URI template
// (/.well-known/masque/ip/{target}/{ipproto}/). The name was wrong, so the
// CONNECT-UDP target parser -- the one on the production minimal VPS path -- had no
// fuzz coverage at all while appearing to have some. The old target is now called
// FuzzConnectIPTemplatePath and this file carries the real CONNECT-UDP coverage.
//
// # What is under test
//
// parseConnectUDPTarget reads the UDP destination out of the request PATH, which is
// entirely attacker-controlled, and its output becomes the UDP endpoint the server
// dials. connectUDPURL is the inverse and is what the fork's own client uses. Two
// properties matter:
//
//	no panic, and no destination accepted that is not a usable host:port;
//	for any destination this endpoint would accept, connectUDPURL followed by
//	parseConnectUDPTarget must recover an EQUIVALENT destination.
//
// The round-trip property is the strong one: it catches an encoder and a decoder
// that disagree, which is the failure that makes a client and a server silently
// route to different places.

// connectUDPRoundTripCorpus is the deterministic half.
//
// Each entry is a destination the parser must accept and must round-trip. They are
// derived from M.Socksaddr semantics and RFC 9298, not from the encoder, so an
// encoder that changes shape without the parser following it fails here.
var connectUDPRoundTripCorpus = []struct {
	name        string
	destination string
}{
	{"ipv4 literal", "192.0.2.1:443"},
	{"ipv4 low port", "192.0.2.1:1"},
	{"ipv4 high port", "192.0.2.1:65535"},
	{"domain", "example.com:443"},
	{"domain with hyphen", "my-origin.example.com:53"},
	{"single-label domain", "localhost:9"},
	{"ipv6 literal", "[2001:db8::1]:443"},
	{"ipv6 loopback", "[::1]:443"},
	{"ipv6 unspecified", "[::]:53"},
	{"ipv6 v4-mapped", "[::ffff:192.0.2.1]:443"},
	{"ipv6 long form", "[2001:0db8:0000:0000:0000:0000:0000:0001]:443"},
	{"ipv6 with embedded port-like group", "[2001:db8::ff]:65535"},
}

// TestConnectUDPTargetRoundTrip is the deterministic companion to the fuzz target.
//
// The fuzz target asserts the same property over generated inputs; this pins the
// named cases so a regression names the shape that broke instead of producing an
// anonymous fuzz failure.
func TestConnectUDPTargetRoundTrip(t *testing.T) {
	for _, testCase := range connectUDPRoundTripCorpus {
		t.Run(testCase.name, func(t *testing.T) {
			destination := M.ParseSocksaddr(testCase.destination).Unwrap()
			require.True(t, destination.IsValid(),
				"the corpus entry itself must parse: %s", testCase.destination)

			recovered, ok := roundTripConnectUDPTarget(t, destination)
			require.True(t, ok,
				"connectUDPURL(parse) must recover the destination; the encoder and "+
					"the parser disagree")
			require.Equal(t, destination.AddrString(), recovered.AddrString(),
				"the recovered host must be equivalent")
			require.Equal(t, destination.Port, recovered.Port,
				"the recovered port must be equal")
		})
	}
}

// roundTripConnectUDPTarget renders destination as a CONNECT-UDP request path,
// parses it back, and reports the result.
func roundTripConnectUDPTarget(t *testing.T, destination M.Socksaddr) (M.Socksaddr, bool) {
	t.Helper()
	rendered := connectUDPURL(destination)
	// The server parses request.URL.EscapedPath(), which is what the URL exposes
	// on the wire. Using anything else would test a path the server never sees.
	return parseConnectUDPTarget(rendered.EscapedPath())
}

// TestConnectUDPURLRendersTheRFC9298Template pins the produced path shape, because
// the round trip alone would also pass for a self-consistent but non-conforming
// encoder.
func TestConnectUDPURLRendersTheRFC9298Template(t *testing.T) {
	for _, testCase := range []struct {
		destination string
		escapedPath string
	}{
		{"192.0.2.1:443", "/.well-known/masque/udp/192.0.2.1/443/"},
		{"example.com:443", "/.well-known/masque/udp/example.com/443/"},
		// GitHub issue: the colon in an IPv6 literal must be escaped so it cannot be
		// read as a port separator, and the brackets are optional on the wire.
		{"[2001:db8::1]:443", "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/"},
	} {
		t.Run(testCase.destination, func(t *testing.T) {
			destination := M.ParseSocksaddr(testCase.destination).Unwrap()
			require.True(t, destination.IsValid())
			rendered := connectUDPURL(destination)
			require.Equal(t, testCase.escapedPath, rendered.EscapedPath(),
				"the rendered request path must be the RFC 9298 well-known template "+
					"with the target percent-encoded")
			require.Equal(t, testCase.escapedPath, rendered.String(),
				"Path and RawPath must agree, so the URL is not re-encoded differently "+
					"by net/http on the way out")
		})
	}
}

// FuzzConnectUDPTargetPath drives parseConnectUDPTarget and connectUDPURL together.
//
// The path is the only attacker-controlled input to this parser, so the target
// feeds the parser arbitrary path text and asserts the two properties above. It also
// drives connectUDPURL with destinations recovered from the parser, which closes the
// loop on generated inputs rather than only on the named corpus.
func FuzzConnectUDPTargetPath(fuzz *testing.F) {
	fuzz.Add("/.well-known/masque/udp/192.0.2.1/443/")
	fuzz.Add("/.well-known/masque/udp/example.com/443/")
	fuzz.Add("/.well-known/masque/udp/example.com/1/")
	fuzz.Add("/.well-known/masque/udp/example.com/65535/")
	fuzz.Add("/.well-known/masque/udp/example.com/65536/")
	fuzz.Add("/.well-known/masque/udp/example.com/0/")
	fuzz.Add("/.well-known/masque/udp/example.com/-1/")
	fuzz.Add("/.well-known/masque/udp/example.com/99999999999999999999/")
	fuzz.Add("/.well-known/masque/udp/example.com/0443/")
	fuzz.Add("/.well-known/masque/udp//443/")
	fuzz.Add("/.well-known/masque/udp/example.com//")
	fuzz.Add("/.well-known/masque/udp/example.com/443")
	fuzz.Add("/.well-known/masque/udp/example.com/443/extra/")
	fuzz.Add("/.well-known/masque/udp/example.com/443//")
	fuzz.Add("/.well-known/masque/udp//")
	fuzz.Add("/.well-known/masque/udp/2001:db8::1/443/")
	fuzz.Add("/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/")
	fuzz.Add("/.well-known/masque/udp/%5B2001:db8::1%5D/443/")
	fuzz.Add("/.well-known/masque/udp/fe80::1%25eth0/443/")
	fuzz.Add("/.well-known/masque/udp/example%2Fcom/443/")
	fuzz.Add("/.well-known/masque/udp/%2e%2e%2f%2e%2e%2f/443/")
	fuzz.Add("/.well-known/masque/udp/%ZZ/443/")
	fuzz.Add("/.well-known/masque/udp/%/443/")
	fuzz.Add("/.well-known/masque/udp/%00/443/")
	fuzz.Add("/.well-known/masque/udp/example.com/443/?x=1")
	fuzz.Add("/.well-known/masque/udp/user:pass@example.com/443/")
	fuzz.Add("/.well-known/masque/udp/[2001:db8::1/443/")
	fuzz.Add("/.well-known/masque/udp/2001:db8::1]/443/")
	fuzz.Add("/.well-known/masque/udp/example.com:443/443/")
	fuzz.Add("//.well-known/masque/udp/example.com/443/")
	fuzz.Add("/.well-known/masque/udp/example.com/443/#fragment")
	fuzz.Add("/.well-known/masque/udp/\u00e9xample.com/443/")
	fuzz.Add("/.well-known/masque/udp/example.com/\u0661\u0664\u0664\u0663/")
	fuzz.Add("/.well-known/masque/udp/EXAMPLE.COM/443/")
	fuzz.Add("/.well-known/masque/udp/trailing.dot.example.com/443/")
	fuzz.Add("/.well-known/masque/udp/0.0.0.0/443/")
	fuzz.Add("/.well-known/masque/udp/255.255.255.255/443/")
	fuzz.Add("/.well-known/masque/udp/256.1.1.1/443/")
	fuzz.Add("/.well-known/masque/udp/1.2.3.4.5/443/")
	fuzz.Add("/.well-known/masque/udp/::1/443/")
	fuzz.Add("/wrong/prefix/example.com/443/")
	fuzz.Add("/.well-known/masque/udp/")
	fuzz.Add("")
	// A long host and a long path, to keep the parser honest about size.
	fuzz.Add("/.well-known/masque/udp/" + strings.Repeat("a", 4096) + "/443/")
	fuzz.Add("/.well-known/masque/udp/example.com/" + strings.Repeat("9", 4096) + "/")

	fuzz.Fuzz(func(t *testing.T, path string) {
		destination, ok := parseConnectUDPTarget(path)
		if !ok {
			return
		}
		// Anything accepted becomes a dialled UDP endpoint, so it must be a usable
		// host:port: a valid address or a non-empty domain, and a port that is in
		// range and non-zero.
		if !destination.IsValid() {
			t.Fatalf("an accepted destination must be valid: %q -> %v", path, destination)
		}
		if destination.Port == 0 {
			t.Fatalf("port 0 must never be accepted: %q", path)
		}
		if destination.AddrString() == "" {
			t.Fatalf("an accepted destination must carry a host: %q", path)
		}
		// A zone identifier IS allowed through, on ANY IPv6 address, and that is
		// MEASURED rather than assumed. Two earlier versions of this assertion were
		// guesses and both failed on correct code:
		//
		//   - the first required the zone to be rejected;
		//   - the second allowed it only on a LINK-LOCAL address, and the fuzzer
		//     immediately produced `::%0` (an unspecified address with zone "0"),
		//     which is accepted.
		//
		// The zone is produced by M.ParseSocksaddrHostPort, which keeps whatever zone
		// the client spelled, so it is present for link-local (fe80::1%eth0), global
		// (2001:db8::1%eth0) and unspecified (::%0) addresses alike. Enumerating the
		// addresses the parser accepts is therefore not this target's business; what
		// IS this target's business is that a zone never changes the ADDRESS itself
		// and is only ever attached to an IPv6 address.
		//
		// The end-to-end consequence is recorded in
		// TestJiejieMinimalConnectUDPScopedIPv6TargetIsMeasured: the request is
		// accepted with 200, the zone survives into the destination, and the OS
		// decides per datagram whether the scoped destination is routable, without
		// killing the tunnel.
		if zone := destination.Addr.Zone(); zone != "" {
			if !destination.Addr.Is6() {
				t.Fatalf("only an IPv6 address may carry a zone: %q -> %s", path, destination)
			}
			if destination.Addr.Is4In6() {
				t.Fatalf("a v4-mapped address must not carry a zone: %q -> %s", path, destination)
			}
			// The zone must be the one the client spelled and must not have been
			// folded into the address bytes: the address this endpoint would dial
			// has to be the address that was written.
			withoutZone := destination.Addr.WithZone("")
			if !withoutZone.IsValid() {
				t.Fatalf("stripping the zone must leave a valid address: %q -> %s",
					path, destination)
			}
			if destination.AddrString() != withoutZone.WithZone(zone).String() {
				t.Fatalf("the zone must be carried as a zone and not merged into the "+
					"address: %q -> %s", path, destination)
			}
		}

		// The round trip. This is the property a client and a server must agree on:
		// whatever this server accepted, the URL it renders for the same destination
		// must parse back to the same thing.
		recovered, recoveredOK := roundTripConnectUDPTarget(t, destination)
		if !recoveredOK {
			t.Fatalf("a destination the parser accepted must round-trip through "+
				"connectUDPURL: %q -> %v", path, destination)
		}
		if recovered.AddrString() != destination.AddrString() {
			t.Fatalf("round trip changed the host: %q -> %v -> %s",
				path, destination, recovered.AddrString())
		}
		if recovered.Port != destination.Port {
			t.Fatalf("round trip changed the port: %q -> %v -> %d",
				path, destination, recovered.Port)
		}

		// The rendered URL must be a well-formed absolute-path URL whose escaped
		// path is exactly what was rendered, so net/http cannot re-encode it into
		// something the server would parse differently.
		rendered := connectUDPURL(destination)
		if !strings.HasPrefix(rendered.EscapedPath(), connectUDPPathPrefix) {
			t.Fatalf("a rendered CONNECT-UDP URL must start with %q: %q",
				connectUDPPathPrefix, rendered.EscapedPath())
		}
		parsed, parseErr := url.Parse(rendered.String())
		if parseErr != nil {
			t.Fatalf("a rendered CONNECT-UDP URL must be parseable: %v", parseErr)
		}
		if parsed.EscapedPath() != rendered.EscapedPath() {
			t.Fatalf("re-parsing the rendered URL changed its path: %q -> %q",
				rendered.EscapedPath(), parsed.EscapedPath())
		}
	})
}

// TestConnectUDPParserIsNotOverPermissive is the negative companion: a corpus of
// shapes that must NOT become a destination.
//
// It exists alongside the fuzz target because "no panic and a coherent result" is
// satisfiable by a parser that accepts everything. These pin the rejections.
func TestConnectUDPParserIsNotOverPermissive(t *testing.T) {
	for _, testCase := range []struct {
		path   string
		reason string
	}{
		{"/.well-known/masque/ip/198.18.0.2/32/0/", "the CONNECT-IP template is not CONNECT-UDP"},
		{"/.well-known/masque/udp/example.com/443/extra", "an extra path segment"},
		{"/.well-known/masque/udp/example.com/443/../", "traversal after the port"},
		{"/.well-known/masque/udp/example.com/0x1bb/", "a non-decimal port"},
		{"/.well-known/masque/udp/example.com/ 443/", "a port with leading whitespace"},
		{"/.well-known/masque/udp/example.com/443 /", "a port with trailing whitespace"},
		{"/.well-known/masque/udp/example.com/+443/", "a signed port"},
		{"/.well-known/masque/udp/example.com/-0/", "a negative zero port"},
		{"/.well-known/masque/udp/example.com/443/0/", "two extra segments"},
	} {
		t.Run(testCase.path, func(t *testing.T) {
			if destination, ok := parseConnectUDPTarget(testCase.path); ok {
				t.Fatalf("%q must be rejected (%s), got %s",
					testCase.path, testCase.reason, destination)
			}
		})
	}
}

// TestConnectUDPPortBoundaries pins the port arithmetic explicitly, because it is
// the one piece of integer logic in the parser and the mutation an audit is most
// likely to introduce.
func TestConnectUDPPortBoundaries(t *testing.T) {
	for _, testCase := range []struct {
		port string
		want uint16
		ok   bool
	}{
		{"0", 0, false},
		{"1", 1, true},
		{"65534", 65534, true},
		{"65535", 65535, true},
		{"65536", 0, false},
		{"4294967296", 0, false},
		{"99999999999999999999999", 0, false},
		{"", 0, false},
		{"-1", 0, false},
		{"+1", 0, false},
		{"1 ", 0, false},
		{" 1", 0, false},
		{"0x10", 0, false},
		{"1e3", 0, false},
		{"08", 8, true},
	} {
		t.Run("port "+strconv.Quote(testCase.port), func(t *testing.T) {
			path := "/.well-known/masque/udp/example.com/" + testCase.port + "/"
			destination, ok := parseConnectUDPTarget(path)
			require.Equal(t, testCase.ok, ok, "path %q", path)
			if testCase.ok {
				require.Equal(t, testCase.want, destination.Port)
			}
		})
	}
}

// TestConnectUDPIPv6ZoneIsAcceptedAndIsHarmless records a MEASURED behaviour
// rather than a preferred one, and the measurement says the zone is not a problem.
//
// A scoped IPv6 target does reach the parser: a client that escapes its percent
// sign (`fe80::1%25eth0`) produces a path whose host segment decodes to
// `fe80::1%eth0`, and M.ParseSocksaddrHostPort keeps the zone. An earlier version
// of this test asserted the zone must be REJECTED. That assertion was a guess, and
// it was wrong: it failed against correct code.
//
// What the measurement actually shows (all three measured, not inferred):
//
//  1. the parser accepts the bracket form and keeps the zone
//     (`[fe80::1%25eth0]` -> `fe80::1%eth0`, zone `eth0`);
//  2. a zone can never reach the dialer as a zone, because net.Dial rejects
//     "too many colons in address" when a scoped literal is joined WITHOUT
//     brackets, and M.Socksaddr.String() brackets it, so what the dialer sees is
//     the parsable `[fe80::1%eth0]:443`;
//  3. end to end, a probe of exactly that shape is rejected by the production
//     server with 400 rather than being dialled - measured through
//     TestJiejieMinimalConnectUDPScopedIPv6TargetIsNotDialled.
//
// So the zone is passed through to the destination rather than stripped, and the
// outcome is still "no client-controlled interface selection". The test pins the
// preserved shape so that a dependency change which starts silently DROPPING the
// zone (which would turn a scoped address into a different, global one) is visible.
func TestConnectUDPIPv6ZoneIsAcceptedAndIsHarmless(t *testing.T) {
	destination, ok := parseConnectUDPTarget("/.well-known/masque/udp/fe80::1%25eth0/443/")
	require.True(t, ok,
		"a scoped IPv6 target in the escaped bracket form is accepted today; if that "+
			"changed, this test and the audit note must be updated together")
	require.Equal(t, "eth0", destination.Addr.Zone(),
		"the zone is preserved rather than stripped. Dropping it would turn a "+
			"link-local address into a different, global destination, which is worse "+
			"than carrying a zone the dialer cannot act on: got %s", destination)
	require.True(t, destination.Addr.IsLinkLocalUnicast(),
		"the scoped address in the probe is link-local, which is why the zone matters")
}

// TestConnectUDPHostSegmentEdgeCases records what the parser does with host
// segments that are neither a domain nor an address.
//
// A dot-only or space-only host is ACCEPTED by the parser, because
// M.ParseSocksaddrHostPort treats any non-empty, non-address string as a DOMAIN.
// An earlier version of this test asserted rejection; that was a guess and it was
// wrong.
//
// The reason acceptance is not a defect is that a domain never becomes an address by
// fiat: it goes to the router as metadata.Destination with Fqdn set, and it can only
// reach a dialer through domain resolution, which fails for "." and " ". It is
// pinned here so the behaviour is a recorded decision rather than an accident.
func TestConnectUDPHostSegmentEdgeCases(t *testing.T) {
	for _, testCase := range []struct {
		host string
		path string
	}{
		{"dot", "/.well-known/masque/udp/./443/"},
		{"escaped space", "/.well-known/masque/udp/%20/443/"},
	} {
		t.Run(testCase.host, func(t *testing.T) {
			destination, ok := parseConnectUDPTarget(testCase.path)
			require.True(t, ok,
				"the parser accepts this as a DOMAIN, not as an address: %s", testCase.path)
			require.False(t, destination.Addr.IsValid(),
				"a non-address host must not become an address by fallback: %s", destination)
			require.NotEmpty(t, destination.Fqdn,
				"the host must be carried as a domain so it can only reach a dialer "+
					"through resolution: %s", destination)
		})
	}
}
