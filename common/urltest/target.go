package urltest

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
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
func NormalizeURLTestURL(link string) (string, error) {
	if link == "" {
		link = DefaultURLTestURL
	}

	parsed, err := url.Parse(link)
	if err != nil {
		return "", E.Cause(err, "parse URL test target ", link)
	}

	// A scheme is required. Without one, `example.com/x` would parse as a path and the request
	// would have no transport at all - a failure that belongs here, not in net/http.
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https":
	case "":
		return "", E.New("URL test target requires a scheme: ", link)
	default:
		// Rejecting the scheme is the whole point: a non-HTTP scheme cannot be measured by an
		// HTTP request, and passing it on would connect to a host that is not the target.
		return "", E.New("unsupported URL test scheme ", parsed.Scheme, " in ", link)
	}

	if parsed.Hostname() == "" {
		return "", E.New("URL test target requires a host: ", link)
	}
	if port := parsed.Port(); port != "" {
		number, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || number == 0 {
			return "", E.New("invalid URL test port ", port, " in ", link)
		}
	}

	// Drop the fragment: it is never transmitted, so it must not create a second scope for the
	// same request.
	parsed.Fragment = ""
	parsed.RawFragment = ""
	parsed.Scheme = scheme

	return parsed.String(), nil
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
// A reversed range is normalised rather than rejected ("299-200" means "200-299"), matching
// Mihomo, because the intent is unambiguous. Anything else - a non-numeric token, an empty
// element, a zero status, a value beyond uint16 - is an error.
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
