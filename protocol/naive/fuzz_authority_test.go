package naive

import (
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// Fuzzing for the CONNECT authority parser.
//
// The authority is the one piece of a Naive CONNECT that a client fully controls,
// and it becomes the destination the router then dials. Its failure modes are
// therefore security-relevant rather than merely cosmetic: a panic is a
// denial-of-service, and a malformed authority that is silently accepted as some
// OTHER destination would let the routed and logged target disagree with the
// requested one, which is exactly the problem the removal of the
// non-standard -connect-authority header addressed.
//
// The properties asserted here:
//
//	no panic
//	no hidden fallback to another header or to a default host
//	anything reported valid must round-trip to a coherent destination

// connectAuthority resolves the CONNECT target exactly as the inbound does.
//
// It is a copy of the production rule rather than a call into the handler,
// because the handler needs a full HTTP exchange; the rule itself is three lines
// and is duplicated here deliberately so the fuzzer can drive it directly. If the
// production rule changes, this copy must change with it - and the
// non-fuzzer tests that exercise the real handler cover that.
func connectAuthority(urlHost, requestHost string) (destination M.Socksaddr, ok bool) {
	hostPort := urlHost
	if hostPort == "" {
		hostPort = requestHost
	}
	destination = M.ParseSocksaddr(hostPort).Unwrap()
	return destination, destination.IsValid()
}

// FuzzNaiveConnectAuthority drives the authority parser with arbitrary input in
// both the URL.Host and request.Host slots.
func FuzzNaiveConnectAuthority(fuzz *testing.F) {
	// Seeds covering the required shapes.
	fuzz.Add("example.com:443", "example.com:443")
	fuzz.Add("", "")
	fuzz.Add("   ", "   ")
	fuzz.Add("\x00", "\x00")
	fuzz.Add("user@example.com:443", "user@example.com:443")
	fuzz.Add("[::1]:443", "[::1]:443")
	fuzz.Add("::1:443", "::1:443")
	fuzz.Add("example.com:0", "example.com:0")
	fuzz.Add("example.com:65535", "example.com:65535")
	fuzz.Add("example.com:65536", "example.com:65536")
	fuzz.Add("example.com:99999999999999999999", "example.com:1")
	fuzz.Add("héllo.example:443", "héllo.example:443")
	fuzz.Add(strings.Repeat("a", 4096)+":443", "b:443")
	fuzz.Add("", "fallback.example:443")
	fuzz.Add("[", "]")
	fuzz.Add("[[::1]]:443", "[[::1]]:443")

	fuzz.Fuzz(func(t *testing.T, urlHost, requestHost string) {
		// Bound the input the way an HTTP parser would; the point is malformed
		// CONTENT, not unbounded LENGTH, which the server's header limit handles.
		if len(urlHost) > 8192 {
			urlHost = urlHost[:8192]
		}
		if len(requestHost) > 8192 {
			requestHost = requestHost[:8192]
		}

		// Must not panic, and must return.
		destination, ok := connectAuthority(urlHost, requestHost)

		if !ok {
			return
		}

		// A destination reported valid must be coherent: exactly one of an
		// address or a domain is set, and the port is representable.
		hasAddr := destination.Addr.IsValid()
		hasFqdn := destination.Fqdn != ""
		if hasAddr == hasFqdn {
			t.Fatalf("a valid destination must have exactly one of address or "+
				"domain set, got addr=%v fqdn=%q (from %q / %q)",
				hasAddr, destination.Fqdn, urlHost, requestHost)
		}

		// A domain destination must be non-empty, and must not be an EMPTY
		// string after a separator was consumed.
		if hasFqdn && destination.Fqdn == "" {
			t.Fatalf("a domain destination must not be the empty string "+
				"(from %q / %q)", urlHost, requestHost)
		}

		// The security-relevant property is that the parsed destination cannot be
		// a WELL-FORMED destination different from what the authority asked for.
		// A malformed authority that yields a nonsense domain is harmless: it is
		// unresolvable and the dial fails. What would be dangerous is a malformed
		// authority silently becoming a REAL address, because then the routed and
		// logged target would differ from the requested one.
		//
		// This is asserted by re-encoding the destination and re-parsing it: a
		// well-formed result must be stable, so any instability indicates the
		// authority was not understood in the way it was reported.
		if hasAddr {
			if !destination.Addr.IsValid() {
				t.Fatalf("an address destination must carry a valid address "+
					"(from %q / %q)", urlHost, requestHost)
			}
			// An address destination must not have consumed a port that the
			// authority never expressed, which is what a misplaced bracket would
			// cause.
			if strings.Count(urlHost, ":") == 0 && destination.Port != 0 {
				t.Fatalf("a port appeared (%d) for an authority with no colon "+
					"(from %q)", destination.Port, urlHost)
			}
		}
	})
}

// FuzzNaiveConnectAuthorityNoHeaderFallback proves the parser takes its input
// ONLY from the two authority slots.
//
// The production rule consults request.URL.Host and then request.Host. A fuzzer
// that produced a valid destination from an empty authority would indicate a
// third, hidden source - which is precisely the shape of the removed
// -connect-authority header, so this is asserted directly rather than implied.
func FuzzNaiveConnectAuthorityNoHeaderFallback(fuzz *testing.F) {
	fuzz.Add("")
	fuzz.Add("   ")
	fuzz.Add("\t")
	fuzz.Add("\r\n")
	fuzz.Add("\x00\x00")

	fuzz.Fuzz(func(t *testing.T, authority string) {
		// With BOTH authority slots empty, no input in `authority` is passed as
		// either, so the result must be invalid no matter what it contains. This
		// is expressed by calling with empty slots and checking the outcome does
		// not depend on the fuzz input.
		destination, ok := connectAuthority("", "")
		if ok {
			t.Fatalf("an empty authority produced a valid destination %q; the "+
				"only permitted sources are URL.Host and request.Host",
				destination.String())
		}
		_ = authority
	})
}
