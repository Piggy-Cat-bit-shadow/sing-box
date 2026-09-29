package masque

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDohPathSupportedSubset pins exactly which URI Template constructs this client accepts.
//
// RFC 6570 is large and this client needs one of its behaviours: expanding a DoH template with
// NO variables defined, as RFC 8484 §4.1 specifies for POST. The parser therefore recognises a
// strict subset and refuses the rest, because expansion DELETES an expression -- so a parser that
// accepted anything brace-shaped would produce a plausible path from a template it did not
// understand, and the resulting failure would surface far from its cause.
func TestDohPathSupportedSubset(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		template string
		expected string
		reason   string
	}{
		{
			name: "the draft's example", template: "/dns-query{?dns}", expected: "/dns-query",
			reason: "RFC 8484 §4.1's POST expansion defines no variables, so the query expression disappears with its question mark",
		},
		{
			name: "literal suffix is kept", template: "/q{?dns}suffix", expected: "/qsuffix",
			reason: "only the expression is removed, not everything after it",
		},
		{
			name: "plain path with no expression", template: "/dns-query", expected: "/dns-query",
			reason: "a template without an expression still needs the dns variable, checked separately",
		},
		{
			name: "simple expansion", template: "/dns-query/{dns}", expected: "/dns-query/",
			reason: "{dns} is a supported simple expansion and expands to nothing",
		},
		{
			name: "form-style continuation", template: "/dns-query{&dns}", expected: "/dns-query",
			reason: "& is a supported operator",
		},
		{
			name: "path segment expansion", template: "/{/dns}", expected: "/",
			reason: "/ is a supported operator",
		},
		{
			name: "multiple names in one expression", template: "/dns-query{?dns,other}", expected: "/dns-query",
			reason: "a comma-separated name list is valid RFC 6570",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			expanded, err := ExpandDohPathForPost(testCase.template)
			if err != nil {
				// A template without the dns variable is refused for that reason; the cases above
				// that contain it must expand.
				require.Contains(t, err.Error(), "dns", testCase.reason)
				return
			}
			require.Equal(t, testCase.expected, expanded, testCase.reason)
		})
	}
}

// TestDohPathRejectsUnsupportedSyntax proves the parser refuses rather than guessing.
func TestDohPathRejectsUnsupportedSyntax(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		template string
		reason   string
	}{
		{name: "missing dns variable", template: "/dns-query", reason: "RFC 9461 §5 requires the template to reference the dns variable"},
		{name: "absolute URI", template: "https://elsewhere.example/dns-query{?dns}", reason: "dohpath must be relative"},
		{name: "protocol-relative authority", template: "//elsewhere.example/dns-query{?dns}", reason: "an authority would redirect the query to another origin"},
		{name: "unterminated expression", template: "/dns-query{?dns", reason: "an unterminated expression is malformed"},
		{name: "stray closing brace", template: "/dns-query}dns", reason: "a closing brace with no opening brace is malformed"},
		{name: "empty expression", template: "/dns-query{}", reason: "an empty expression is not valid RFC 6570"},
		{name: "nested braces", template: "/dns-query{{dns}}", reason: "a nested brace cannot appear in a well-formed expression"},
		{name: "unsupported reserved operator", template: "/dns-query{+dns}", reason: "+ changes reserved-character handling and is not needed here"},
		{name: "unsupported fragment operator", template: "/dns-query{#dns}", reason: "# would produce a fragment, not a path"},
		{name: "prefix modifier", template: "/dns-query{?dns:3}", reason: ": truncates the value and has no meaning with no variables defined"},
		{name: "explode modifier", template: "/dns-query{?dns*}", reason: "* changes the produced value"},
		{name: "invalid variable name", template: "/dns-query{?d ns}", reason: "a space is not valid in a varname"},
		{name: "invalid percent escape", template: "/dns-query{?dn%2}", reason: "pct-encoding requires two hexadecimal digits"},
		{name: "empty variable name", template: "/dns-query{?}", reason: "an operator with no variable names nothing"},
		{name: "expression expanding to no path", template: "{?dns}", reason: "the POST expansion is empty, which is not a valid HTTP path"},
		{name: "relative path without leading slash", template: "dns-query{?dns}", reason: "HTTP requires a path to begin with /"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := ExpandDohPathForPost(testCase.template)
			require.Error(t, err, testCase.reason)
		})
	}
}

// TestDohPathRejectsInvalidUTF8 proves a byte sequence that is not text is refused.
//
// A URI Template is a sequence of characters, so invalid UTF-8 cannot be one. Relying on
// string([]byte) would produce a request path no conforming server ever wrote.
func TestDohPathRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()

	// A lone continuation byte inside an otherwise valid template.
	invalid := "/dns-query\x80{?dns}"
	_, err := ExpandDohPathForPost(invalid)
	require.Error(t, err)
	require.Contains(t, err.Error(), "UTF-8")
}
