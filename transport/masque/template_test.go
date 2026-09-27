package masque

import (
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for CONNECT-IP template parsing and matching.
//
// # Why this file exists
//
// FuzzConnectIPTemplatePath found a real gap: a request path carrying a BACKSLASH
// in the target produced a Scope whose Domain contained that backslash, and the
// Domain becomes a dialled host. The matcher rejected ":" and "/" but not "\".
//
// Impact was assessed rather than assumed before writing the fix. A backslash
// domain is not a valid hostname, Go's resolver treats it as an unknown host and
// returns a blackhole address, and net.JoinHostPort does not reinterpret it - so it
// was a validation gap, not an exploitable traversal. It is closed because the
// invariant is worth holding on its own: a domain that cannot be a hostname should
// never reach the resolver.
//
// The fuzz target remains the broad check. These tests pin the specific behaviour
// so a regression fails immediately, in a normal `go test` run, without needing a
// fuzz campaign to rediscover it.

// TestTemplateRejectsPathSeparatorsInTargets pins the fix directly.
//
// Every one of these previously assigned a Domain containing a path separator. They
// must now be rejected as malformed targets, which surfaces as Match returning an
// error rather than a scope.
func TestTemplateRejectsPathSeparatorsInTargets(t *testing.T) {
	t.Parallel()

	// Both template forms that extract a target: the query form and the path form.
	templates := []string{
		"/masque?target={target}&ipproto={ipproto}",
		"/{target}/{ipproto}/",
		DefaultPath,
	}

	// Requests whose extracted target contains a separator. ":" and "/" were always
	// rejected; "\" is what the fuzzer found.
	requests := []string{
		"/masque?target=a\\b&ipproto=17",
		"/masque?target=\\&ipproto=17",
		"/masque?target=a/b&ipproto=17",
		"/masque?target=a:b&ipproto=17",
		"/a\\b/17/",
		"/\\/17/",
		"/a/b/17/",
		"/a:b/17/",
		"/.well-known/masque/ip/a\\b/32/0/",
		"/.well-known/masque/ip/a/b/32/0/",
	}

	for _, templatePath := range templates {
		template, err := ParseTemplate(templatePath)
		if err != nil {
			// A template that does not parse cannot be matched against; that is a
			// different assertion, and the fuzz target covers it.
			continue
		}
		for _, requestPath := range requests {
			parsed, parseErr := url.Parse(requestPath)
			require.NoError(t, parseErr, "the request path must parse: %s", requestPath)

			scope, matched, matchErr := template.Match(parsed)
			if !matched {
				// The template shape did not match this request at all, which is
				// fine - the property below only applies to a MATCHED scope.
				continue
			}
			require.Error(t, matchErr,
				"template %q request %q matched with target containing a path "+
					"separator and produced scope %+v; it must be rejected",
				templatePath, requestPath, scope)
			require.Empty(t, scope.Domain,
				"a rejected match must not carry a domain: %q", scope.Domain)
			require.False(t, scope.Prefix.IsValid(),
				"a rejected match must not carry a prefix: %v", scope.Prefix)
		}
	}
}

// TestTemplateAcceptsWellFormedTargets is the other direction.
//
// Without it, the rejection above could be satisfied by refusing every target, and
// the CONNECT-IP path would be silently broken.
func TestTemplateAcceptsWellFormedTargets(t *testing.T) {
	t.Parallel()

	ipTemplate, err := ParseTemplate(DefaultPath)
	require.NoError(t, err)

	// DefaultPath is "/.well-known/masque/ip/{target}/{ipproto}/", so the path
	// carries the target and the IP protocol number - not the four-segment form
	// that appears in some of the fuzz SEEDS, which deliberately exercise shapes
	// the template does not accept.
	scope, matched, matchErr := ipTemplate.Match(
		urlMustParse(t, "/.well-known/masque/ip/198.18.0.2/32/"))
	require.NoError(t, matchErr)
	require.True(t, matched, "a well-formed IP target must match %s", DefaultPath)
	require.Equal(t, netip.MustParsePrefix("198.18.0.2/32"), scope.Prefix)

	// A subnet target, which is the other accepted prefix form. The address must be
	// MASKED: "198.18.0.2/24" is rejected with "prefix has host bits set", which is
	// the parser being strict rather than a limitation.
	subnetScope, subnetMatched, subnetErr := ipTemplate.Match(
		urlMustParse(t, "/.well-known/masque/ip/198.18.0.0%2F24/17/"))
	require.NoError(t, subnetErr)
	require.True(t, subnetMatched, "a masked subnet target must match")
	require.Equal(t, netip.MustParsePrefix("198.18.0.0/24"), subnetScope.Prefix,
		"a percent-encoded subnet target must parse to the intended prefix")

	// A domain target via the query form must still work, since that is a supported
	// CONNECT-IP scope.
	domainTemplate, err := ParseTemplate("/masque?target={target}&ipproto={ipproto}")
	require.NoError(t, err)
	domainScope, domainMatched, domainErr := domainTemplate.Match(
		urlMustParse(t, "/masque?target=example.com&ipproto=17"))
	require.NoError(t, domainErr)
	require.True(t, domainMatched)
	require.Equal(t, "example.com", domainScope.Domain,
		"a plain domain must still be accepted as a scope")
	require.Equal(t, uint8(17), domainScope.Protocol)
}

// TestTemplateDomainNeverContainsASeparator is the invariant the fuzz target
// asserts, stated as its own property so the intent is readable.
//
// It walks a small set of adversarial request shapes and requires that ANY matched
// scope either carries a valid prefix or a domain free of ":" "/" and "\".
func TestTemplateDomainNeverContainsASeparator(t *testing.T) {
	t.Parallel()

	templates := []string{
		DefaultPath,
		"/masque?target={target}&ipproto={ipproto}",
		"/{target}/{ipproto}/",
	}
	adversarial := []string{
		"/masque?target=a\\b&ipproto=17",
		"/masque?target=\\\\&ipproto=17",
		"/masque?target=..%5c..%5cetc&ipproto=17",
		"/masque?target=example.com&ipproto=17",
		"/a\\b/17/",
		"/\\/17/",
		"/.well-known/masque/ip/198.18.0.2/32/0/",
		"/.well-known/masque/ip/example.com/0/17/",
	}

	for _, templatePath := range templates {
		template, err := ParseTemplate(templatePath)
		if err != nil {
			continue
		}
		for _, requestPath := range adversarial {
			parsed, parseErr := url.Parse(requestPath)
			if parseErr != nil {
				continue
			}
			scope, matched, matchErr := template.Match(parsed)
			if !matched || matchErr != nil {
				continue
			}
			if scope.Domain != "" {
				require.NotContains(t, scope.Domain, "/",
					"matched domain %q from %q contains a forward slash",
					scope.Domain, requestPath)
				require.NotContains(t, scope.Domain, "\\",
					"matched domain %q from %q contains a backslash",
					scope.Domain, requestPath)
				require.NotContains(t, scope.Domain, ":",
					"matched domain %q from %q contains a colon",
					scope.Domain, requestPath)
			}
			// A prefix and a domain are mutually exclusive scopes.
			require.False(t, scope.Prefix.IsValid() && scope.Domain != "",
				"matched scope has both a prefix (%v) and a domain (%q)",
				scope.Prefix, scope.Domain)
		}
	}
}

func urlMustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err, "parse %s", raw)
	return parsed
}
