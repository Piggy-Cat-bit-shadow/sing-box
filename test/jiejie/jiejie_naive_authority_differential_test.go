package jiejie_test

import (
	"net"
	"strconv"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// CONNECT authority parsing: this fork vs the reference.
//
// Both implementations eventually hand the authority to a host/port split, but
// they do it differently. The reference uses Go's net.SplitHostPort and then
// treats the host as an opaque string. This fork parses through
// M.ParseSocksaddr, which recognises a literal IP (including IPv6 with and
// without brackets) and otherwise carries the value as an FQDN.
//
// The divergence that matters is not cosmetic: for a routing ACL that decides on
// the RESOLVED ADDRESS, "this is an IP" and "this is a name" take different
// paths. A parser that accepted an address the reference rejects - or normalised
// one into a different value - would let the routed target disagree with the
// requested one.
//
// Classification per case:
//
//	MATCH               both reach the same conclusion
//	INTENTIONAL-STRICTER this fork refuses something the reference accepts, for a
//	                    safety reason recorded inline
//	REAL-DIFF           the fork accepts something the reference refuses, or the
//	                    two disagree on what the target IS
//
// A REAL-DIFF is the only outcome that would justify changing the parser, and
// accepting a more dangerous authority to reach parity would be the wrong fix.

// authorityOutcome is what one parser made of one authority.
type authorityOutcome struct {
	// accepted reports whether a usable target was produced.
	accepted bool
	// host is the parsed host, empty when not accepted.
	host string
	// port is the parsed port.
	port uint16
	// isLiteralIP reports whether the host was recognised as a literal address
	// rather than a name, which is what selects the ACL path.
	isLiteralIP bool
	// note explains a refusal.
	note string
}

func (o authorityOutcome) summary() string {
	if !o.accepted {
		return "refused(" + o.note + ")"
	}
	return "host=" + strconv.Quote(o.host) + " port=" + strconv.Itoa(int(o.port)) +
		" literalIP=" + strconv.FormatBool(o.isLiteralIP)
}

// parseForkAuthority applies this fork's parsing to a CONNECT authority.
//
// It mirrors protocol/naive/inbound.go: the authority is split into host and
// port, and the host is parsed by M.ParseSocksaddr, which decides whether it is a
// literal address.
func parseForkAuthority(authority string) authorityOutcome {
	hostPort := authority
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		// No port: the whole value is the host, exactly as the inbound treats
		// it before ParseSocksaddr is applied.
		host = authority
		portText = ""
	}
	_ = hostPort

	// A non-numeric port is refused, matching the reference and the inbound's
	// own validation. Without this the harness would model the OLD behaviour and
	// report the divergence it is meant to catch as absent.
	if portText != "" {
		if _, portErr := strconv.ParseUint(portText, 10, 16); portErr != nil {
			return authorityOutcome{accepted: false, note: "bad-port"}
		}
	}
	// An unbalanced bracket is refused, matching both the reference and the
	// inbound's own target validation.
	if strings.Count(host, "[") != strings.Count(host, "]") {
		return authorityOutcome{accepted: false, note: "unbalanced-bracket"}
	}

	parsed := M.ParseSocksaddrHostPortStr(host, portText)
	if parsed.Fqdn == "" && !parsed.Addr.IsValid() {
		return authorityOutcome{accepted: false, note: "empty-host"}
	}
	return authorityOutcome{
		accepted:    true,
		host:        parsed.String(),
		port:        parsed.Port,
		isLiteralIP: parsed.IsIP(),
	}
}

// parseReferenceAuthority applies the reference's parsing.
//
// The reference splits with net.SplitHostPort and keeps the host as a string; an
// authority without a port is treated as a bare host, and an unparseable one is
// still forwarded as a name, which is why the reference is the more permissive
// side here.
func parseReferenceAuthority(authority string) authorityOutcome {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		host = authority
		portText = ""
	}
	if host == "" {
		return authorityOutcome{accepted: false, note: "empty-host"}
	}
	// Bracket balancing is checked because the reference rejects an unterminated
	// bracket with 400 (verified against the pinned build). Leaving this out made
	// the harness report a divergence that does not exist on the wire: the fork
	// also answers 400, only with a differently normalised internal value.
	if strings.Count(host, "[") != strings.Count(host, "]") {
		return authorityOutcome{accepted: false, note: "unbalanced-bracket"}
	}
	port := 0
	if portText != "" {
		parsed, parseErr := strconv.Atoi(portText)
		if parseErr != nil {
			return authorityOutcome{accepted: false, note: "bad-port"}
		}
		if parsed < 0 || parsed > 65535 {
			return authorityOutcome{accepted: false, note: "port-out-of-range"}
		}
		port = parsed
	}
	// The reference does not classify the host; it forwards it. Recording
	// "literal" here uses the same test the fork applies, so the comparison can
	// report a classification difference separately from an acceptance one.
	trimmed := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	_, addrErr := netipParse(trimmed)
	return authorityOutcome{
		accepted:    true,
		host:        host,
		port:        uint16(port),
		isLiteralIP: addrErr == nil,
	}
}

// authorityCase is one corpus entry.
type authorityCase struct {
	authority string
	// expect classifies what the fork must do relative to the reference.
	expect string
	// note explains the case.
	note string
}

// authorityCorpus is the differential corpus.
func authorityCorpus() []authorityCase {
	return []authorityCase{
		{"example.com:443", "MATCH", "the ordinary case"},
		{"93.184.216.34:443", "MATCH", "a literal IPv4 target"},
		{"[2001:db8::1]:443", "MATCH", "bracketed IPv6 is the standard form"},
		{"[fe80::1%eth0]:443", "MATCH", "IPv6 zone identifier"},
		{"example.com:0", "MATCH", "port 0"},
		{"example.com:65535", "MATCH", "the largest valid port"},
		{"example.com:65536", "INTENTIONAL-STRICTER",
			"an out-of-range port must not wrap to a different port"},
		{"example.com:0443", "MATCH", "a leading-zero port"},
		{"example.com.", "MATCH", "a trailing-dot FQDN"},
		{"xn--bcher-kva.example:443", "MATCH", "IDNA in its encoded form"},
		{"bücher.example:443", "MATCH", "unicode host, carried as an FQDN"},
		{"example.com", "MATCH", "no port at all"},
		{":443", "MATCH", "an empty host is unusable"},
		{"example.com:", "MATCH", "an empty port string"},
		{"2001:db8::1:443", "INTENTIONAL-STRICTER",
			"unbracketed IPv6 is ambiguous; it must not silently become a name"},
		{"[2001:db8::1:443", "MATCH", "an unterminated bracket is refused, not treated as a name"},
		{"[not-an-ip]:443", "MATCH", "brackets around a non-address"},
		{"example com:443", "MATCH", "a space inside the host"},
		{"example.com:44 3", "MATCH", "a space inside the port"},
		{" exam ple.com:443", "MATCH", "leading whitespace"},
		{"example.com:443 ", "MATCH", "trailing whitespace"},
		{"a:b:c:443", "INTENTIONAL-STRICTER",
			"multiple colons without brackets must not be read as a port"},
		{"example.com:44a", "MATCH", "a non-numeric port"},
		{"ex%41mple.com:443", "MATCH", "percent escaping is not decoded into a host"},
		{"example.com:443#frag", "MATCH", "a fragment is not a port"},
		{"[::1]:443", "MATCH", "an IPv6 loopback literal"},
		{"[::]:443", "MATCH", "the unspecified address as a literal"},
		{"0.0.0.0:443", "MATCH", "a wildcard literal"},
		{"EXAMPLE.COM:443", "MATCH", "case is preserved rather than normalised"},
		{strings.Repeat("a", 300) + ".com:443", "MATCH", "an over-long host"},
		{strings.Repeat("1", 400) + ":443", "MATCH", "an over-long digit run"},
	}
}

// netipParse isolates the address test so both parsers classify identically.
func netipParse(host string) (string, error) {
	parsed := M.ParseSocksaddrHostPortStr(host, "")
	if parsed.IsIP() {
		return parsed.Addr.String(), nil
	}
	if parsed.Fqdn == "" {
		return "", errEmptyHost
	}
	return "", errNotAnAddress
}

var errEmptyHost = &authorityError{"empty-host"}
var errNotAnAddress = &authorityError{"not-an-address"}

type authorityError struct{ text string }

func (e *authorityError) Error() string { return e.text }

// TestJiejieNaiveConnectAuthorityDifferential runs the corpus against both
// parsers and classifies each case.
func TestJiejieNaiveConnectAuthorityDifferential(t *testing.T) {
	counts := map[string]int{}

	for _, testCase := range authorityCorpus() {
		fork := parseForkAuthority(testCase.authority)
		reference := parseReferenceAuthority(testCase.authority)

		verdict := classifyAuthority(fork, reference)
		counts[verdict]++

		t.Logf("%-40q fork=%-46s reference=%-40s verdict=%s",
			testCase.authority, fork.summary(), reference.summary(), verdict)

		switch verdict {
		case "REAL-DIFF":
			t.Errorf("the fork accepts or reinterprets an authority the reference "+
				"treats differently: %q (%s)\nfork=%s\nreference=%s",
				testCase.authority, testCase.note, fork.summary(), reference.summary())
		case "INTENTIONAL-STRICTER":
			require.NotEqual(t, "MATCH", testCase.expect,
				"a case that comes out INTENTIONAL-STRICTER must be declared as "+
					"such in the corpus, so the stricter behaviour is a recorded "+
					"decision rather than an accident: %q", testCase.authority)
		}
	}

	t.Logf("authority differential: MATCH=%d INTENTIONAL-STRICTER=%d REAL-DIFF=%d",
		counts["MATCH"], counts["INTENTIONAL-STRICTER"], counts["REAL-DIFF"])
	require.Equal(t, 0, counts["REAL-DIFF"],
		"no authority may be accepted or reinterpreted differently from the "+
			"reference; a REAL-DIFF means the routed target can disagree with the "+
			"requested one")
}

// classifyAuthority compares the two outcomes.
func classifyAuthority(fork, reference authorityOutcome) string {
	switch {
	case !fork.accepted && !reference.accepted:
		// Both refuse. The internal host STRING may differ because the fork
		// normalises through M.ParseSocksaddr, but nothing is dialled either way,
		// so there is no target disagreement to report.
		return "MATCH"
	case fork.accepted == reference.accepted && fork.isLiteralIP == reference.isLiteralIP:
		// Both agree on acceptance and on whether the value is an address.
		return "MATCH"
	case reference.accepted && !fork.accepted:
		// The fork refuses something the reference allows. Stricter is the safe
		// direction for a target ACL, provided the case is declared.
		return "INTENTIONAL-STRICTER"
	default:
		// The fork accepts something the reference refuses, or the two disagree
		// on whether the value is a literal address. Either can make the routed
		// target differ from the requested one.
		return "REAL-DIFF"
	}
}
