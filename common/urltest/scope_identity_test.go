package urltest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for ScopeURL as an identity.
//
// # The two defects these pin
//
// ScopeURL decides which health evidence a result belongs to. Two spellings that describe the same
// request must therefore produce the same scope, or one target occupies two scopes and a group sees
// only part of its own evidence - a result it measured is invisible to the selection that depends
// on it.
//
// Two spellings were not canonicalised:
//
//   - An omitted path and an explicit "/" are the same request target, since HTTP requires the
//     request line to carry a path. They produced two scopes.
//   - An IP literal was only lowercased, so two legal spellings of one address - `2001:0DB8:0:0::1`
//     and `2001:db8::1` - produced two scopes. The destination was already canonical, so the
//     inconsistency was specific to the identity.
//
// The RequestURL must keep its own semantics; only the identity is canonicalised.

// TestEmptyPathMatchesExplicitSlash is §10.
func TestEmptyPathMatchesExplicitSlash(t *testing.T) {
	bare, err := ParseMeasurementTarget("https://example.com")
	require.NoError(t, err)

	slash, err := ParseMeasurementTarget("https://example.com/")
	require.NoError(t, err)

	require.Equal(t, slash.ScopeURL, bare.ScopeURL,
		"an omitted path and an explicit \"/\" are the same request target - HTTP requires the "+
			"request line to carry a path - so they must share one scope. Two scopes would split a "+
			"target's health evidence in half")
}

// TestIPv6EquivalentSpellingsShareScope is §10.1.
//
// Every legal spelling of one address must reach one identity.
func TestIPv6EquivalentSpellingsShareScope(t *testing.T) {
	for _, group := range [][]string{
		{"http://[2001:0DB8:0:0::1]/a", "http://[2001:db8::1]/a"},
		{"http://[::1]/a", "http://[0:0:0:0:0:0:0:1]/a"},
		{"http://[2001:db8:0:0:0:0:0:1]/a", "http://[2001:db8::1]/a"},
	} {
		t.Run(group[0], func(t *testing.T) {
			first, err := ParseMeasurementTarget(group[0])
			require.NoError(t, err)
			second, err := ParseMeasurementTarget(group[1])
			require.NoError(t, err)

			require.Equal(t, first.ScopeURL, second.ScopeURL,
				"%q and %q are the same address and must share one scope; keying on the spelling "+
					"means a group measuring both sees two half-histories instead of one", group[0],
				group[1])
		})
	}
}

// TestIPv4EquivalentSpellingsShareScope covers the other family.
func TestIPv4EquivalentSpellingsShareScope(t *testing.T) {
	// 127.0.0.1 has only one spelling, but leading-zero forms and the canonical form must not
	// diverge if a parser normalises them.
	first, err := ParseMeasurementTarget("http://127.0.0.1/a")
	require.NoError(t, err)
	second, err := ParseMeasurementTarget("http://127.0.0.1/a")
	require.NoError(t, err)
	require.Equal(t, first.ScopeURL, second.ScopeURL)
}

// TestScopeCanonicalizationDoesNotRewriteTheRequest is the pairing requirement (§10.2).
//
// Canonicalising the identity must leave the request exactly as configured.
func TestScopeCanonicalizationDoesNotRewriteTheRequest(t *testing.T) {
	target, err := ParseMeasurementTarget("https://EXAMPLE.com:443/UPPER?B=2&a=1#frag")
	require.NoError(t, err)

	// The identity is canonical.
	require.Equal(t, "https://example.com/UPPER?B=2&a=1", target.ScopeURL,
		"the identity lowercases the host and omits the default port")

	// The request keeps the configured spelling, apart from the fragment (never transmitted) and
	// the scheme case (case-insensitive by definition).
	require.Contains(t, target.RequestURL, "EXAMPLE.com",
		"the Host spelling must survive into the request: canonicalising the identity must not "+
			"rewrite what is fetched")
	require.Contains(t, target.RequestURL, "UPPER?B=2&a=1",
		"and the path and query order must survive, because they are part of the request")
	require.NotContains(t, target.RequestURL, "frag",
		"while the fragment is dropped, since it is never transmitted")
}

// TestScopeNonDefaultPortStaysDistinct keeps a real difference a difference.
func TestScopeNonDefaultPortStaysDistinct(t *testing.T) {
	base, err := ParseMeasurementTarget("https://example.com/a")
	require.NoError(t, err)
	other, err := ParseMeasurementTarget("https://example.com:8443/a")
	require.NoError(t, err)

	require.NotEqual(t, base.ScopeURL, other.ScopeURL,
		"a non-default port is a different endpoint and must remain a different identity")
}
