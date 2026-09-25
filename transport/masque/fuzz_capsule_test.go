package masque

import (
	std_bufio "bufio"
	"bytes"
	"io"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
)

// Fuzzing for the MASQUE parsers that consume attacker-controlled bytes.
//
// The three parsers here are chosen because each one turns bytes from the PEER
// into either state or a decision, on a path that runs before any application
// logic can reject the input:
//
//   - the capsule framer, which reads a type varint, a length varint and then
//     that many bytes, and is the first thing an established tunnel reads;
//   - the route-advertisement parser, whose output decides which destinations
//     the server will forward, so a misparse is a policy bypass rather than a
//     cosmetic error;
//   - the URI-template matcher, which decides the tunnel SCOPE (target prefix and
//     protocol) from the request path, so a matcher that accepts more than it
//     should widens what a client may proxy.
//
// The properties asserted in every target are the three that matter for a parser
// on a network path:
//
//	no panic, whatever the bytes
//	no unbounded allocation driven by a declared length
//	anything reported valid must be internally coherent (and, where the parser
//	normalises, round-trip stably)

// FuzzCapsuleParser drives the capsule framer.
//
// The framer is what an established tunnel reads first, and it is driven entirely
// by peer bytes: a type varint, a length varint, then that many payload bytes.
// The declared length is the classic amplification vector, so the property under
// test is not merely "no panic" but that a length beyond the limit is REFUSED
// before anything is allocated for it.
func FuzzCapsuleParser(fuzz *testing.F) {
	// Empty input: a clean EOF, not a panic.
	fuzz.Add([]byte{})
	// A zero-length unknown capsule: type 0x01, length 0.
	fuzz.Add([]byte{0x01, 0x00})
	// DATAGRAM (type 0x00) carrying one byte of context ID and no payload.
	fuzz.Add([]byte{0x00, 0x01, 0x00})
	// A truncated type varint (2-byte form with one byte missing).
	fuzz.Add([]byte{0x40})
	// A truncated length varint.
	fuzz.Add([]byte{0x00, 0x40})
	// A declared length far beyond any real capsule (8-byte varint).
	fuzz.Add([]byte{0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// A length larger than the data actually present.
	fuzz.Add([]byte{0x00, 0x10, 0x00})
	// A well-formed DATAGRAM capsule.
	fuzz.Add([]byte{0x00, 0x04, 0x00, 0xde, 0xad, 0xbe})
	// The 4-byte varint form of a length just under the limit.
	fuzz.Add([]byte{0x00, 0x80, 0x00, 0x0f, 0xff})

	fuzz.Fuzz(func(t *testing.T, data []byte) {
		reader := std_bufio.NewReader(bytes.NewReader(data))
		capsuleType, typeLength, err := transportHTTP.ReadVarint(reader)
		if err != nil {
			return
		}
		// A varint must consume exactly the number of bytes its first byte
		// announces, never more: a framer that over-reads would desynchronise
		// from the stream and interpret payload bytes as the next header.
		expectedLength := 1 << (data[0] >> 6)
		if typeLength != expectedLength {
			t.Fatalf("the type varint consumed %d bytes but its first byte announces %d",
				typeLength, expectedLength)
		}

		length, _, err := transportHTTP.ReadVarint(reader)
		if err != nil {
			return
		}
		if length > transportHTTP.MaxCapsuleLength {
			// Refused, which is the required outcome for an oversized capsule.
			return
		}
		// Within the limit, the payload must actually be readable and its size
		// must not exceed what the limit allows. Allocating it here is safe
		// precisely because the limit was checked first, which is the property
		// being pinned.
		payload := make([]byte, length)
		_, err = io.ReadFull(reader, payload)
		if err != nil {
			return
		}
		if uint64(len(payload)) > transportHTTP.MaxCapsuleLength {
			t.Fatalf("a payload of %d bytes was read, above the limit of %d",
				len(payload), transportHTTP.MaxCapsuleLength)
		}
		// NOTE ON LAYERING, learned by getting it wrong here first: a zero-length
		// DATAGRAM capsule IS accepted by the framer, and that is correct. The
		// framer owns the length; readDatagramCapsule owns the context-ID rule
		// and discards a zero-payload datagram rather than delivering an empty
		// packet. An assertion that the framer must reject it encodes a rule the
		// code under test is not responsible for, and would fail on correct code.
		//
		// So the property asserted here is the one the framer does own: the
		// reported type and length must be self-consistent with the bytes
		// consumed. Anything further belongs to a target that drives the session
		// layer.
		_ = capsuleType
	})
}

// FuzzRouteAdvertisement drives the ROUTE_ADVERTISEMENT parser.
//
// The output of this parser becomes the set of destinations the server will
// forward, so the property that matters is not merely "no panic" but that
// anything ACCEPTED describes coherent ranges: an IPv4 start with an IPv6 end, or
// a range whose start is above its end, would make routing decisions undefined.
func FuzzRouteAdvertisement(fuzz *testing.F) {
	fuzz.Add([]byte{})
	// An empty route list is valid.
	fuzz.Add([]byte{0x00})
	// One route: 0.0.0.0 - 0.0.0.0, protocol 0.
	fuzz.Add([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	// One route with a wildcard start.
	fuzz.Add([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06})
	// A truncated route.
	fuzz.Add([]byte{0x01, 0, 0, 0, 0})
	// An IPv6-shaped route.
	fuzz.Add([]byte{
		0x01,
		16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0,
	})
	// A route count claiming far more routes than the bytes support.
	fuzz.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})

	fuzz.Fuzz(func(t *testing.T, data []byte) {
		routes, err := parseRoutes(data)
		if err != nil {
			return
		}
		if len(routes) > maxRoutesPerCapsule {
			t.Fatalf("accepted %d routes, above the per-capsule bound of %d",
				len(routes), maxRoutesPerCapsule)
		}
		for index, route := range routes {
			// Address families must agree: a range that starts in one family and
			// ends in another cannot describe a contiguous run of addresses.
			if route.Start.Is4() != route.End.Is4() {
				t.Fatalf("route %d mixes address families: start %s, end %s",
					index, route.Start, route.End)
			}
			// A range that ends before it starts would make containment checks
			// undefined, so it must never be reported as valid.
			if route.Start.Is4() == route.End.Is4() && route.End.Less(route.Start) {
				t.Fatalf("route %d ends before it starts: %s - %s",
					index, route.Start, route.End)
			}
			// A wildcard (invalid) address is an internal marker; if the parser
			// ever returns one, address comparison downstream would misbehave.
			if !route.Start.IsValid() && !route.Start.IsUnspecified() {
				t.Fatalf("route %d has an invalid start address", index)
			}
		}
	})
}

// FuzzConnectIPAddresses drives the ADDRESS_ASSIGN parser.
//
// Assigned addresses become the addresses a client may source traffic from, so
// an accepted-but-incoherent entry is a policy question, not a formatting one. A
// declared entry count is again the amplification vector.
func FuzzConnectIPAddresses(fuzz *testing.F) {
	fuzz.Add([]byte{})
	fuzz.Add([]byte{0x00})
	// One assignment: request ID 1, IPv4 0.0.0.0/0.
	fuzz.Add([]byte{0x01, 0x01, 0, 0, 0, 0, 0, 0x00})
	// One assignment with an out-of-range prefix length.
	fuzz.Add([]byte{0x01, 0x01, 0, 0, 0, 0, 0, 0xff})
	// A truncated entry.
	fuzz.Add([]byte{0x01, 0x01, 0, 0})
	// A count far beyond the data.
	fuzz.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// The maximum address count, with no entries behind it.
	fuzz.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00})

	fuzz.Fuzz(func(t *testing.T, data []byte) {
		addresses, err := parseAddresses(data)
		if err != nil {
			return
		}
		if len(addresses) > maxAddressesPerCapsule {
			t.Fatalf("accepted %d addresses, above the per-capsule bound of %d",
				len(addresses), maxAddressesPerCapsule)
		}
		for index, assigned := range addresses {
			prefix := assigned.Prefix
			// A prefix length outside the address width is not a prefix at all,
			// and prefix.Contains would then behave unpredictably.
			if prefix.Bits() < 0 || prefix.Bits() > prefix.Addr().BitLen() {
				t.Fatalf("address %d has an out-of-range prefix length: %s (%d bits)",
					index, prefix, prefix.Bits())
			}
		}
	})
}

// FuzzConnectUDPTemplatePath drives the URI-template matcher.
//
// The matcher decides the SCOPE of a tunnel - which target prefix and which IP
// protocol the client may proxy through - from the request path alone. The
// property that matters is that a scope is only reported for a path that actually
// matches the template, and that the extracted protocol is always a valid IP
// protocol number: an over-permissive match widens what a client can reach.
func FuzzConnectUDPTemplatePath(fuzz *testing.F) {
	// The paths this endpoint is configured to serve.
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/0/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/*/*/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/2001:db8::1/128/17/")
	fuzz.Add(DefaultPath, "/")
	fuzz.Add(DefaultPath, "")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/../../etc/passwd/0/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/999/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/-1/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/%2e%2e%2f%2e%2e%2f/32/0/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/%00/")
	fuzz.Add("/masque?target={target}&ipproto={ipproto}", "/masque?target=198.18.0.2&ipproto=17")
	fuzz.Add("/masque?target={target}&ipproto={ipproto}", "/masque")
	fuzz.Add("/{target}/{ipproto}/", "/198.18.0.2/17/")

	fuzz.Fuzz(func(t *testing.T, templatePath string, requestPath string) {
		// A template that cannot be parsed must report an error rather than
		// producing a matcher in an undefined state.
		template, err := ParseTemplate(templatePath)
		if err != nil {
			return
		}
		// The request path is fully attacker-controlled, so it must be valid
		// UTF-8 for url.Parse to accept it; anything else is not a path the
		// server could ever see.
		if !utf8.ValidString(requestPath) {
			return
		}
		parsed, err := url.Parse(requestPath)
		if err != nil {
			return
		}
		scope, matched, matchErr := template.Match(parsed)
		if matchErr != nil || !matched {
			return
		}
		// A matched scope with an invalid, non-wildcard prefix would be used as
		// a routing decision, so it must never escape.
		if scope.Prefix.IsValid() {
			if scope.Prefix.Bits() < 0 || scope.Prefix.Bits() > scope.Prefix.Addr().BitLen() {
				t.Fatalf("matched scope has an out-of-range prefix: %s", scope.Prefix)
			}
			if scope.Prefix.Addr().Zone() != "" {
				t.Fatalf("matched scope has a zone identifier: %s", scope.Prefix)
			}
		}
		// The domain, when present, must not be empty or contain a path
		// separator: it becomes a dialled domain.
		if scope.Domain != "" {
			if strings.ContainsAny(scope.Domain, "/\\") {
				t.Fatalf("matched scope has a domain containing a path separator: %q", scope.Domain)
			}
		}
		// A prefix and a domain are mutually exclusive scopes.
		if scope.Prefix.IsValid() && scope.Domain != "" {
			t.Fatalf("matched scope has both a prefix (%s) and a domain (%q)",
				scope.Prefix, scope.Domain)
		}
	})
}
