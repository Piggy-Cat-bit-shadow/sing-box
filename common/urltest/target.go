package urltest

import (
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// DefaultURLTestURL is the target used when none is supplied.
//
// It is the only definition in the repository: callers that need the default reference this
// constant rather than repeating the string, so the default cannot drift between the Clash API,
// the native API and the URLTest group.
const DefaultURLTestURL = "https://www.gstatic.com/generate_204"

// NormalizeURLTestURL resolves a caller-supplied target into a canonical absolute URL.
//
// # Why this exists
//
// The target string is the identity of a measurement. Two spellings of the same endpoint must
// produce the same scope, and an unusable one must fail before anything is dialled - not after a
// connect to a host of "" on port 0, which is what parsing lazily inside the HTTP layer would do.
//
// # What it guarantees
//
//   - empty means the default, so "" and the explicit default are the same target
//   - only http and https are accepted; ftp, file, ws, ssh and anything unknown are rejected
//   - a hostname is required, and an explicit port must be a valid port number
//   - the fragment is dropped, because a fragment is never sent to the server and so cannot
//     describe a different measurement
//   - path and query are preserved exactly, because they do change what is requested
//
// MeasurementTarget separates the three things a URL test target is used for.
//
// They were previously one normalised string, which conflated decisions that should be independent:
//
//	RequestURL   what is actually fetched - must stay exactly as the user wrote it
//	ScopeURL     the identity a result is stored under - must be canonical
//	Destination  what is dialled - must be validated before any connection is attempted
//
// Keeping them together meant a canonicalisation applied for identity could silently rewrite the
// request (reordering a query string, rewriting the authority), and a malformed port was only
// discovered once net/http tried to dial. Separating them lets each be exactly as strict, or as
// permissive, as its own job requires.
type MeasurementTarget struct {
	// RequestURL is handed to http.NewRequest unchanged, apart from validation.
	RequestURL string
	// ScopeURL identifies the measurement. Equivalent spellings share one scope.
	ScopeURL string
	// Destination is the address to dial, already validated.
	Destination M.Socksaddr
}

// ParseMeasurementTarget resolves a configured link into its three uses.
func ParseMeasurementTarget(link string) (MeasurementTarget, error) {
	if link == "" {
		link = DefaultURLTestURL
	}

	parsed, err := url.Parse(link)
	if err != nil {
		return MeasurementTarget{}, E.Cause(err, "parse URL test target ", link)
	}

	// A scheme is required. Without one, `example.com/x` would parse as a path and the request
	// would have no transport at all - a failure that belongs here, not in net/http.
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https":
	case "":
		return MeasurementTarget{}, E.New("URL test target requires a scheme: ", link)
	default:
		// Rejecting the scheme is the whole point: a non-HTTP scheme cannot be measured by an
		// HTTP request, and passing it on would connect to a host that is not the target.
		return MeasurementTarget{}, E.New("unsupported URL test scheme ", parsed.Scheme, " in ", link)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return MeasurementTarget{}, E.New("URL test target requires a host: ", link)
	}

	// The port is validated and defaulted HERE, so an unusable target fails before a detour is
	// asked to dial it. The previous version only rejected an explicitly bad port and left the
	// default resolution to net/http.
	port := parsed.Port()
	var portNumber uint64
	if port != "" {
		portNumber, err = strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return MeasurementTarget{}, E.New("invalid URL test port ", port, " in ", link)
		}
	} else if scheme == "https" {
		portNumber = 443
	} else {
		portNumber = 80
	}

	// --- RequestURL: validate, but do not rewrite ---
	//
	// Only two changes are made, both because the fragment is never transmitted: it is dropped so
	// it cannot create a second scope, and the scheme is lowercased because a scheme is
	// case-insensitive by definition. The path, the query and its order, the authority and the
	// host spelling are all left exactly as the user wrote them, so the request that is sent is
	// the request that was configured.
	requestURL := *parsed
	requestURL.Fragment = ""
	requestURL.RawFragment = ""
	requestURL.Scheme = scheme

	// --- ScopeURL: canonical, for identity only ---
	scopeURL := requestURL
	scopeURL.Host = canonicalScopeHost(hostname, portNumber, port, scheme)
	// An omitted path and an explicit "/" are the same request target: HTTP requires the request
	// line to carry a path, so an empty one is sent as "/". Only the IDENTITY is normalised here;
	// RequestURL keeps exactly what was configured, and the transport adds the "/" itself.
	if scopeURL.Path == "" {
		scopeURL.Path = "/"
	}

	// The destination is built by the metadata parser, so a numeric literal becomes an IP
	// destination and a hostname becomes a domain.
	//
	// Assigning Fqdn directly - which is what this used to do - labelled every target a DOMAIN
	// whose text merely looked numeric. That is a different instruction on the wire: the proxy
	// protocols encode ATYP IPv4, IPv6 or DOMAIN, so a DOMAIN "1.1.1.1" asks the remote end to
	// resolve a literal the operator had already resolved, and an IPv6 literal has to survive as an
	// address rather than as a bracketed name.
	destination := M.ParseSocksaddrHostPort(hostname, uint16(portNumber))

	return MeasurementTarget{
		RequestURL:  requestURL.String(),
		ScopeURL:    scopeURL.String(),
		Destination: destination,
	}, nil
}

// canonicalScopeHost renders the authority as an identity rather than as a request target.
//
// It lowercases a DNS hostname, because a hostname is case-insensitive, and omits the default port,
// so "https://example.com:443/a" and "https://example.com/a" are one measurement. A non-default
// port is kept, because it is a different endpoint.
//
// IPv6 literals are re-bracketed, since the bracket is part of the authority syntax and not of the
// address.
func canonicalScopeHost(hostname string, portNumber uint64, explicitPort string, scheme string) string {
	host := hostname
	if address, addressErr := netip.ParseAddr(hostname); addressErr == nil {
		// An IP literal is canonicalised to its ADDRESS, not merely lowercased.
		//
		// One address has many legal spellings - `2001:0DB8:0:0::1` and `2001:db8::1` are the same
		// address - so keying the identity on the spelling splits one endpoint into several
		// scopes, and a group that measures more than one spelling sees half-histories. The
		// destination was already canonical; only the identity disagreed with it.
		host = address.String()
	} else {
		// A DNS name is case-insensitive.
		host = strings.ToLower(hostname)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	// A port equal to the scheme's default is omitted, whether it was written explicitly or not.
	//
	// Checking the VALUE rather than whether one was supplied is what makes "https://host:443/a"
	// and "https://host/a" one scope. Keying on explicitness instead would give the same endpoint
	// two identities, which is the split this canonicalisation exists to prevent.
	_ = explicitPort
	if portNumber == defaultPortForScheme(scheme) {
		return host
	}
	return host + ":" + strconv.FormatUint(portNumber, 10)
}

// defaultPortForScheme returns the port implied by a scheme.
func defaultPortForScheme(scheme string) uint64 {
	if scheme == "https" {
		return 443
	}
	return 80
}

// isIPLiteral reports whether host is an IP address rather than a DNS name.
func isIPLiteral(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	// A dotted-quad-only check is deliberately avoided; a name with digits and dots is still a
	// name, and lowercasing it is harmless either way.
	_, err := netip.ParseAddr(host)
	return err == nil
}

// NormalizeURLTestURL returns the canonical identity for a target.
//
// It is the scope accessor: a result is stored under this string. Callers that also need to make
// the request or dial the host should use ParseMeasurementTarget, so the canonicalisation here
// cannot leak into what is actually fetched.
func NormalizeURLTestURL(link string) (string, error) {
	target, err := ParseMeasurementTarget(link)
	if err != nil {
		return "", err
	}
	return target.ScopeURL, nil
}

// urlTestPort returns the port to dial for a normalised target.
func urlTestPort(normalized *url.URL) string {
	if port := normalized.Port(); port != "" {
		return port
	}
	switch normalized.Scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// StatusRange is an inclusive HTTP status range.
type StatusRange struct {
	Start uint16
	End   uint16
}

// ExpectedStatus is the set of HTTP status codes a measurement accepts.
//
// An empty set accepts anything, which the Canonical form reports as "*".
type ExpectedStatus []StatusRange

// maxExpectedStatusRanges bounds the parsed set, matching Mihomo.
//
// The bound exists because the value arrives from an HTTP query string: without it a caller could
// make the parser build an arbitrarily large set for a single delay request.
const maxExpectedStatusRanges = 28

// ParseExpectedStatus parses a Mihomo-compatible expected-status expression.
//
// Accepted syntax, where an empty value accepts anything:
//
//	*
//	204
//	200-299
//	200/204/301-399
//	200,204,301-399
//
// Three lenient cases are deliberate, because Mihomo's own parser accepts them and refusing one
// would reject a configuration that works there:
//
//	empty tokens are skipped     "204,", "204//200" and "[200-299]" are valid
//	brackets are trimmed
//	a reversed range is swapped  "299-200" means "200-299"
//
// A zero status is also accepted, since Mihomo's ParseUint takes it; it matches nothing a real
// server sends, which makes it harmless rather than useful.
//
// Rejected: a non-numeric token, a malformed range, and a bound beyond uint16. The last is a
// deliberate divergence - Mihomo parses through uint64 and truncates, so "65536" silently becomes 0
// there, which would give two different expressions the same identity.
func ParseExpectedStatus(value string) (ExpectedStatus, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "*" {
		return nil, nil
	}

	// Both separators are accepted, and a caller may mix them. The comma is normalised to a slash
	// first, exactly as Mihomo does, so the two spellings cannot diverge.
	normalised := strings.ReplaceAll(trimmed, ",", "/")
	fields := strings.Split(normalised, "/")

	// The cap is applied to the RAW field count, before empty tokens are skipped, which is how
	// Mihomo counts it.
	if len(fields) > maxExpectedStatusRanges {
		return nil, E.New("expected status has more than ", maxExpectedStatusRanges, " ranges: ", value)
	}

	expected := make(ExpectedStatus, 0, len(fields))
	for _, field := range fields {
		token := strings.TrimSpace(field)
		if token == "" {
			// Skipped, not refused: Mihomo accepts "204," and its equivalents, so a configuration
			// using a trailing separator must keep working.
			continue
		}

		startText, endText, isRange := strings.Cut(token, "-")
		start, err := parseStatusCode(startText)
		if err != nil {
			return nil, E.Cause(err, "invalid expected status: ", value)
		}
		end := start
		if isRange {
			end, err = parseStatusCode(endText)
			if err != nil {
				return nil, E.Cause(err, "invalid expected status: ", value)
			}
		}
		if start > end {
			// Unambiguous intent, normalised rather than refused - the same reading Mihomo uses.
			start, end = end, start
		}
		expected = append(expected, StatusRange{Start: start, End: end})
	}
	return expected, nil
}

// parseStatusCode parses one status code.
//
// Brackets and surrounding whitespace are trimmed, matching Mihomo's own parser, so "[200-299]" is
// accepted. A bound beyond uint16 is refused rather than truncated: Mihomo converts through uint64,
// which silently turns 65536 into 0 and would give two different expressions the same scope.
func parseStatusCode(text string) (uint16, error) {
	trimmed := strings.Trim(strings.TrimSpace(text), "[]")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return 0, E.New("empty status code")
	}
	number, err := strconv.ParseUint(trimmed, 10, 16)
	if err != nil {
		return 0, E.Cause(err, "status code ", trimmed)
	}
	return uint16(number), nil
}

// Match reports whether a status code is accepted.
//
// An empty ExpectedStatus accepts every status, which is what "no constraint" means.
func (e ExpectedStatus) Match(status int) bool {
	if len(e) == 0 {
		return true
	}
	if status < 0 || status > 0xFFFF {
		return false
	}
	code := uint16(status)
	for _, statusRange := range e {
		if code >= statusRange.Start && code <= statusRange.End {
			return true
		}
	}
	return false
}

// Canonical renders the set as a stable string suitable for use as a scope key.
//
// # Why this is a semantic canonical form and not a re-spelling
//
// The same accepted set can be written many ways: "200/204", "204/200", "200,204", "200-204",
// "200/201/202-204". The scope key is built from this string, so any two spellings that produce
// different output would become two scopes for one target - splitting a node's history and letting
// a group see only part of its own evidence.
//
// The ranges are therefore sorted, merged where they overlap or touch, and deduplicated, so the
// output depends only on the SET of accepted statuses. "200/201/202-204" and "200-204" both render
// as "200-204"; "204/200" and "200/204" both render as "200/204".
//
// Merging is stronger than Mihomo's own String(), which joins the input ranges as written. That is
// deliberate: Mihomo's output is a display string, while this one is an identity, and an identity
// has to be canonical or it is not an identity.
func (e ExpectedStatus) Canonical() string {
	if len(e) == 0 {
		return "*"
	}

	// Copy before sorting: Canonical must not reorder the caller's slice.
	ranges := make([]StatusRange, len(e))
	copy(ranges, e)

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Start != ranges[j].Start {
			return ranges[i].Start < ranges[j].Start
		}
		return ranges[i].End < ranges[j].End
	})

	merged := make([]StatusRange, 0, len(ranges))
	for _, current := range ranges {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		// Merge when the ranges overlap or are adjacent.
		//
		// The comparison is widened to uint32 so an End of 65535 does not overflow when the
		// adjacency check adds one.
		if uint32(current.Start) <= uint32(last.End)+1 {
			if current.End > last.End {
				last.End = current.End
			}
			continue
		}
		merged = append(merged, current)
	}

	var builder strings.Builder
	for index, statusRange := range merged {
		if index > 0 {
			builder.WriteByte('/')
		}
		if statusRange.Start == statusRange.End {
			builder.WriteString(strconv.FormatUint(uint64(statusRange.Start), 10))
			continue
		}
		builder.WriteString(strconv.FormatUint(uint64(statusRange.Start), 10))
		builder.WriteByte('-')
		builder.WriteString(strconv.FormatUint(uint64(statusRange.End), 10))
	}
	return builder.String()
}

// MeasurementScope identifies one measurement target.
//
// # Why the outbound tag alone is not enough
//
// A delay is a property of a (node, target) pair, not of a node. "Hong Kong to gstatic" and
// "Hong Kong to Cloudflare" are different measurements, and storing both under one key meant the
// second overwrote the first - so a URLTest group configured for one target would read, and make
// selection decisions from, a result measured against another.
//
// # Why Expected is part of the key
//
// The same URL under different status expectations is also a different measurement. A strict
// "must be 204" health check that fails says nothing about whether the node is reachable, so it
// must not be able to invalidate a result collected under "any status".
type MeasurementScope struct {
	// URL is the normalised target.
	URL string
	// Expected is the canonical accepted-status expression, or "*" for no constraint.
	Expected string
}

// NewMeasurementScope builds a scope from a raw target and expected-status expression.
func NewMeasurementScope(link string, expected ExpectedStatus) (MeasurementScope, error) {
	normalized, err := NormalizeURLTestURL(link)
	if err != nil {
		return MeasurementScope{}, err
	}
	return MeasurementScope{URL: normalized, Expected: expected.Canonical()}, nil
}

// IsZero reports whether the scope carries no target, which is what a zero value holds.
func (s MeasurementScope) IsZero() bool {
	return s.URL == "" && s.Expected == ""
}
