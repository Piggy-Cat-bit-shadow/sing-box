package http

import (
	"testing"
)

// RFC 9298 CONNECT-UDP request path, as a corpus.
//
// The default URI template is
//
//	/.well-known/masque/udp/{target_host}/{target_port}/
//
// and it is the only one this server accepts; see the scope note in
// docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md for why arbitrary templates are not
// configurable here.
//
// The corpus pins the parser's decisions rather than asserting a preference, so a
// future change to any of them is visible in review.

func TestConnectUDPPathCorpus(t *testing.T) {
	accepted := []struct {
		path string
		want string
	}{
		{"/.well-known/masque/udp/192.0.2.1/443/", "192.0.2.1:443"},
		{"/.well-known/masque/udp/example.com/443/", "example.com:443"},
		// IPv6 in both the raw and the percent-encoded bracket form. RFC 9298
		// does not require the brackets, and clients differ, so both are accepted.
		{"/.well-known/masque/udp/2001:db8::1/443/", "[2001:db8::1]:443"},
		{"/.well-known/masque/udp/%5B2001:db8::1%5D/443/", "[2001:db8::1]:443"},
		// Port 1 and 65535 are the valid extremes.
		{"/.well-known/masque/udp/example.com/1/", "example.com:1"},
		{"/.well-known/masque/udp/example.com/65535/", "example.com:65535"},
		// A leading zero parses as decimal, matching net/url and Go's own port
		// handling.
		{"/.well-known/masque/udp/example.com/0443/", "example.com:443"},
		// A missing trailing slash is accepted: the reference's template matching
		// also tolerates it, and rejecting it would break clients that omit it.
		{"/.well-known/masque/udp/example.com/443", "example.com:443"},
	}

	for _, testCase := range accepted {
		t.Run("accept "+testCase.path, func(t *testing.T) {
			destination, ok := parseConnectUDPTarget(testCase.path)
			if !ok {
				t.Fatalf("%s must be accepted", testCase.path)
			}
			if destination.String() != testCase.want {
				t.Fatalf("got %s, want %s", destination, testCase.want)
			}
		})
	}

	rejected := []struct {
		path   string
		reason string
	}{
		{"/wrong/prefix/example.com/443/", "a path outside the template must not be treated as CONNECT-UDP"},
		{"/.well-known/masque/udp/example.com/0/", "port 0 is not a valid UDP destination"},
		{"/.well-known/masque/udp/example.com/65536/", "port above the 16-bit range"},
		{"/.well-known/masque/udp/example.com/-1/", "a negative port"},
		{"/.well-known/masque/udp/example.com/abc/", "a non-numeric port"},
		{"/.well-known/masque/udp//443/", "an empty host"},
		{"/.well-known/masque/udp/example.com//", "an empty port"},
		{"/.well-known/masque/udp/example.com/443/extra/", "an extra path segment"},
		{"/.well-known/masque/udp//", "no host and no port"},
		{"/.well-known/masque/udp/example.com/443//", "a doubled trailing slash"},
		{"/.well-known/masque/udp/%ZZ/443/", "an invalid percent escape"},
		{"/.well-known/masque/udp/%/443/", "a truncated percent escape"},
	}

	for _, testCase := range rejected {
		t.Run("reject "+testCase.path, func(t *testing.T) {
			if destination, ok := parseConnectUDPTarget(testCase.path); ok {
				t.Fatalf("%s must be rejected (%s), got %s",
					testCase.path, testCase.reason, destination)
			}
		})
	}
}

// TestConnectUDPPathEncodedSlashIsNotATraversal records a deliberate decision
// rather than a preferred behaviour.
//
// An encoded slash inside the host segment survives PathUnescape, so the parsed
// host contains "/". That cannot be a real hostname and the resulting destination
// fails at DNS, and it is NOT a traversal: the path is split into segments BEFORE
// unescaping, so the slash never becomes a separator. The behaviour is pinned so
// that a future change to it is a visible decision.
func TestConnectUDPPathEncodedSlashIsNotATraversal(t *testing.T) {
	destination, ok := parseConnectUDPTarget("/.well-known/masque/udp/example%2Fcom/443/")
	if !ok {
		t.Skip("the parser rejects an encoded slash in the host; nothing to record")
	}
	if destination.AddrString() != "example/com" {
		t.Fatalf("the encoded slash no longer decodes into the host (%s); if the "+
			"parser now rejects it, update this test to record the stricter choice",
			destination.AddrString())
	}
	t.Logf("an encoded slash decodes into the host (%s) and fails at DNS; it "+
		"cannot traverse because segments are split before unescaping",
		destination.AddrString())
}
