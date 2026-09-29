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

// TestDohPathVariableNameGrammar pins the RFC 6570 §2.3 varname production.
//
//	varname = varchar *( ["."] varchar )
//	varchar = ALPHA / DIGIT / "_" / pct-encoded
//
// The dot is a SEPARATOR between varchar components, not a member of varchar. An earlier
// implementation listed "." among the allowed characters, which accepted `.dns`, `dns.`,
// `dns..foo` and a lone "." -- names the grammar cannot produce. That matters because the parser's
// whole job is to refuse templates this client does not genuinely understand.
//
// This exercises the varname predicate directly rather than through ExpandDohPathForPost, because
// the two rules are separate: the grammar says what a name MAY look like, while expansion
// additionally requires the name to be exactly `dns`. Going through the outer function would
// conflate a grammar bug with the correct refusal of a well-formed but irrelevant name like `dns1`.
func TestDohPathVariableNameGrammar(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		varname string
		valid   bool
		reason  string
	}{
		{varname: "dns", valid: true},
		{varname: "_dns", valid: true},
		{varname: "dns1", valid: true},
		{varname: "DNS", valid: true},
		{varname: "a", valid: true},
		{varname: "_", valid: true},
		{varname: "a.b", valid: true,
			reason: "a dot between two non-empty components is what the grammar allows"},
		{varname: "a1.b2.c3", valid: true},
		{varname: "dn%73", valid: true,
			reason: "pct-encoded is a varchar in its own right"},
		{varname: "dn%2Es", valid: true,
			reason: "%2E is a literal dot inside one component, so no component is empty"},

		{varname: "", valid: false},
		{varname: ".dns", valid: false, reason: "the first component would be empty"},
		{varname: "dns.", valid: false, reason: "the last component would be empty"},
		{varname: "dns..query", valid: false, reason: "the middle component would be empty"},
		{varname: ".", valid: false, reason: "every component would be empty"},
		{varname: "..", valid: false},
		{varname: "a..b", valid: false},
		{varname: "dn%2", valid: false, reason: "a pct-escape needs two hexadecimal digits"},
		{varname: "dn%", valid: false},
		{varname: "dn%ZZ", valid: false},
		{varname: "d-ns", valid: false,
			reason: "varchar is ALPHA / DIGIT / _ / pct-encoded; a hyphen is none of them"},
		{varname: "d ns", valid: false},
		{varname: "d/ns", valid: false},
	} {
		t.Run(testCase.varname, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, testCase.valid, isValidTemplateVariableName(testCase.varname),
				"varname %q: %s", testCase.varname, testCase.reason)
		})
	}
}

// TestDohPathRejectsMalformedVariableNameThroughExpansion proves the grammar rule is genuinely
// reached from the public entry point, so the predicate above cannot pass while the parser
// quietly ignores it.
//
// Every template here names the `dns` variable, so the malformed name is the only reason to
// refuse it.
func TestDohPathRejectsMalformedVariableNameThroughExpansion(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		template string
		reason   string
	}{
		{name: "leading dot", template: "/dns-query{?.dns}", reason: "empty first component"},
		{name: "trailing dot", template: "/dns-query{?dns.}", reason: "empty last component"},
		{name: "doubled dot", template: "/dns-query{?dns..dns}", reason: "empty middle component"},
		{name: "bare dot", template: "/dns-query{?.}", reason: "no component at all"},
		{name: "hyphen", template: "/dns-query{?d-ns}", reason: "hyphen is not varchar"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := ExpandDohPathForPost(testCase.template)
			require.Error(t, err,
				"a malformed varname must be refused rather than silently expanded: %s",
				testCase.reason)
		})
	}
}

// TestDohPathVariableIsRecognisedThroughEveryOperator proves `dns` is found however the
// expression is written, since that name is what makes a template a DoH template at all.
func TestDohPathVariableIsRecognisedThroughEveryOperator(t *testing.T) {
	t.Parallel()

	for _, template := range []string{
		"/q{dns}",
		"/q{?dns}",
		"/q{&dns}",
		"/q{/dns}",
		"/q{;dns}",
		"/q{.dns}",
		"/q{?other,dns}",
		"/q{?dns,other}",
	} {
		expanded, err := ExpandDohPathForPost(template)
		require.NoError(t, err, "template %q names the dns variable", template)
		require.Equal(t, "/q", expanded,
			"a POST expansion with no variables defined deletes the expression entirely")
	}
}

// TestDohPathWithoutTheDnsVariableIsRefused is the complement.
//
// RFC 9461 §5 defines dohpath through the RFC 8484 template, whose only variable is `dns`. A
// template naming something else cannot be expanded for a DoH query, so accepting it would mean
// sending a request whose path has nothing to do with the query.
func TestDohPathWithoutTheDnsVariableIsRefused(t *testing.T) {
	t.Parallel()

	for _, template := range []string{
		"/dns-query",
		"/dns-query{?other}",
		"/dns-query{dnsquery}",
		"/dns-query{?dn}",
	} {
		_, err := ExpandDohPathForPost(template)
		require.Error(t, err, "template %q does not name the dns variable", template)
		require.Contains(t, err.Error(), "dns")
	}
}

// TestDohPathRejectsBytesThatCannotAppearInAPath covers a class of malformed advertisement that
// fuzzing found and that the earlier checks missed.
//
// # Why the existing checks did not catch these
//
// The parser already verified that the template is valid UTF-8, that every expression is well
// formed, and that the result begins with "/" and contains no "?" or "#". None of that constrains
// the LITERAL text between expressions, and that text becomes the request's ":path" verbatim:
//
//	"/\x01{dns}"  ->  "/\x01"   a raw control character
//	"/%{dns}"     ->  "/%"      a "%" that begins no valid escape
//	"/dns query{dns}" -> "/dns query"  a raw space
//
// Each of these was ACCEPTED, compiled into a resolver, and then failed on every query -- after the
// assignment had been reported usable. The failure surfaced as an unparseable request URL, far from
// the advertisement that caused it.
//
// # Why refusing is the right answer
//
// RFC 3986 §3.3 allows only pchar and "/" in a path; anything else must be percent-encoded. A path
// carrying a raw control character or space is not a ":path" at all, so the server sent something
// this client cannot use. Saying so at compile time is accurate; guessing an encoding would invent
// configuration the server never sent.
func TestDohPathRejectsBytesThatCannotAppearInAPath(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		template string
		reason   string
	}{
		{name: "lone percent", template: "/%{dns}",
			reason: `"%" must begin a two-digit escape`},
		{name: "percent then garbage", template: "/a%zz{dns}",
			reason: "zz is not hexadecimal"},
		{name: "truncated escape at end", template: "/a%2{dns}",
			reason: "only one hexadecimal digit"},
		{name: "trailing percent", template: "/100%{dns}",
			reason: "a trailing % begins no escape"},
		{name: "control character", template: "/\x01{dns}",
			reason: "RFC 3986 excludes control characters from a URI"},
		{name: "tab", template: "/a\tb{dns}", reason: "a tab is a control character"},
		{name: "newline", template: "/a\nb{dns}", reason: "a newline is a control character"},
		{name: "DEL", template: "/a\x7fb{dns}", reason: "DEL is excluded from a URI"},
		{name: "raw space", template: "/dns query{dns}",
			reason: "a space must be percent-encoded"},
		{name: "raw non-ASCII", template: "/\u4e2d{dns}",
			reason: "a non-ASCII byte must be percent-encoded"},
		{name: "raw double quote", template: "/a\"b{dns}",
			reason: `'"' is not a pchar and must be percent-encoded`},
		{name: "raw angle bracket", template: "/a<b{dns}",
			reason: `"<" is not a pchar`},
		{name: "raw backslash", template: "/a\\b{dns}",
			reason: `"\" is not a pchar`},
		{name: "raw caret", template: "/a^b{dns}", reason: `"^" is not a pchar`},
		{name: "raw pipe", template: "/a|b{dns}", reason: `"|" is not a pchar`},
		{name: "raw brace in text", template: "/a}b{dns}", reason: "a stray closing brace"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := ExpandDohPathForPost(testCase.template)
			require.Error(t, err,
				"an advertisement whose expansion is not a valid :path must be refused: %s",
				testCase.reason)
		})
	}
}

// TestDohPathAcceptsCorrectlyEncodedEquivalents is the other side of the same rule.
//
// The check must be on the ESCAPE, not on the character: every byte refused above has a legal
// percent-encoded form, and refusing that would break real advertisements. Without this test the
// rule above could be satisfied by rejecting "%" outright, which would make almost every template
// unusable.
func TestDohPathAcceptsCorrectlyEncodedEquivalents(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		template string
		expected string
		reason   string
	}{
		{template: "/dns%2Dquery{?dns}", expected: "/dns%2Dquery",
			reason: "%2D is a legal escape for a hyphen"},
		{template: "/dns%20query{?dns}", expected: "/dns%20query",
			reason: "an encoded space is legal"},
		{template: "/%E4%B8%AD{?dns}", expected: "/%E4%B8%AD",
			reason: "an encoded multi-byte character is legal"},
		{template: "/a%00b{?dns}", expected: "/a%00b",
			reason: "%00 is well-formed percent-encoding; whether the server wants a NUL is its business"},
		{template: "/100%25{?dns}", expected: "/100%25",
			reason: "%25 is a legal escape for a literal percent sign"},
		{template: "/a%2Fb{?dns}", expected: "/a%2Fb",
			reason: "%2F is a legal escape for a slash inside a segment"},
		{template: "/~user{?dns}", expected: "/~user", reason: "~ is unreserved"},
		{template: "/a!$&'()*+,;=:@b{?dns}", expected: "/a!$&'()*+,;=:@b",
			reason: "these are all pchar"},
		{template: "/a.b_c-d{?dns}", expected: "/a.b_c-d", reason: "unreserved characters"},
	} {
		t.Run(testCase.expected, func(t *testing.T) {
			t.Parallel()
			expanded, err := ExpandDohPathForPost(testCase.template)
			require.NoError(t, err, testCase.reason)
			require.Equal(t, testCase.expected, expanded, testCase.reason)
		})
	}
}
