package masque

import (
	"strings"
	"unicode/utf8"

	E "github.com/sagernet/sing/common/exceptions"
)

// dohpath expansion, per RFC 9461 §5 and RFC 8484 §4.1.
//
// # What the specifications actually require
//
// RFC 9461 §5 defines dohpath as a RELATIVE URI Template whose expansion yields the ":path"
// of a DoH request. RFC 8484 §4.1 fixes how it is expanded for each method:
//
//	"The URI Template defined in this document is processed without any variables when the
//	 HTTP method is POST. When the HTTP method is GET, the single variable "dns" is defined
//	 as the content of the DNS request ... encoded with base64url."
//
// This client uses POST exclusively, so expansion always happens with NO VARIABLES DEFINED.
// That has a consequence which is easy to get wrong: an expression that references an
// undefined variable expands to the EMPTY STRING, and the expression's own syntax
// (its leading "?" or "&", its operators) disappears with it.
//
//	dohpath              POST :path
//	/dns-query{?dns}  -> /dns-query
//	/q{?dns}suffix    -> /qsuffix
//	/dns-query        -> /dns-query
//	{?dns}            -> ""            (empty -> invalid, see below)
//
// # Why "truncate at the first {" was wrong
//
// The previous implementation cut the string at the first "{" and returned the prefix. That
// happens to give the right answer for the draft's example (`/dns-query{?dns}` ->
// `/dns-query`) and the WRONG answer for anything with a literal suffix: `/q{?dns}suffix`
// became `/q` instead of `/qsuffix`. It also accepted templates it should refuse, and it
// accepted a template with no `dns` variable at all, which RFC 9461 requires.
//
// # Why there is no invented default
//
// An earlier version substituted `/dns-query` for an empty or missing template, and prefixed
// a missing "/" . Both invent configuration the server did not send. If a server advertises
// an HTTP transport without a usable dohpath, the honest answer is that the resolver is
// incompatible -- not that we guessed a path and hoped. RFC 9461 makes dohpath mandatory
// alongside an HTTP ALPN for exactly this reason.

// dohPathVariable is the variable RFC 8484 defines for GET expansion. It is the only variable
// this protocol knows, and its presence is what makes a template a DoH template at all.
const dohPathVariable = "dns"

// expandDohPathForPost expands a dohpath URI Template for an RFC 8484 POST request.
//
// POST means no variables are defined, so every expression expands to the empty string. The
// work is therefore: validate the template, strip every expression, and check that what
// remains is a usable path.
func ExpandDohPathForPost(template string) (string, error) {
	if template == "" {
		return "", E.New("dohpath is empty")
	}
	// RFC 9461 §5 defines dohpath as a URI Template, and a URI Template is a sequence of
	// characters: invalid UTF-8 cannot be one. Checking explicitly is better than relying on
	// string([]byte) to produce something that merely looks like text, because the resulting
	// request path would be a byte sequence no conforming server wrote.
	if !utf8.ValidString(template) {
		return "", E.New("dohpath is not valid UTF-8")
	}
	if !DohPathIsRelative(template) {
		return "", E.New("dohpath must be a relative URI Template, got ", template)
	}
	if !templateReferencesDohPathVariable(template) {
		return "", E.New("dohpath must reference the \"", dohPathVariable,
			"\" variable, got ", template)
	}

	expanded, err := stripTemplateExpressions(template)
	if err != nil {
		return "", err
	}
	if expanded == "" {
		return "", E.New("dohpath ", template,
			" expands to an empty path for POST, which is not a valid HTTP path")
	}
	if !strings.HasPrefix(expanded, "/") {
		// RFC 9461 §5 requires the expansion to be a valid ":path", and HTTP requires a
		// path to begin with "/". A template like "dns-query{?dns}" expands to "dns-query",
		// which is not a path; inventing the leading slash would be guessing.
		return "", E.New("dohpath ", template,
			" expands to ", expanded, " for POST, which is not an absolute path")
	}
	if strings.ContainsAny(expanded, "?#") {
		// Those characters may only appear inside an expression, and every expression has
		// been removed by this point.
		return "", E.New("dohpath ", template, " expands to an invalid path ", expanded)
	}
	return expanded, nil
}

// templateReferencesDohPathVariable reports whether a template mentions the `dns` variable.
//
// The check is deliberately on the variable NAME inside an expression, not on the raw string:
// a literal `{dns}` in path text cannot occur (RFC 6570 reserves braces), so any occurrence of
// the name inside an expression counts, whether as `{dns}`, `{?dns}`, `{&dns}` or `{dns,other}`.
func templateReferencesDohPathVariable(template string) bool {
	for _, expression := range templateExpressions(template) {
		for _, name := range splitTemplateVariableNames(expression) {
			if name == dohPathVariable {
				return true
			}
		}
	}
	return false
}

// templateExpressions returns the text of each `{...}` expression in a template, without the
// braces. Unterminated expressions are skipped here and rejected by stripTemplateExpressions.
func templateExpressions(template string) []string {
	var expressions []string
	for index := 0; index < len(template); index++ {
		if template[index] != '{' {
			continue
		}
		end := strings.IndexByte(template[index:], '}')
		if end < 0 {
			break
		}
		expressions = append(expressions, template[index+1:index+end])
		index += end
	}
	return expressions
}

// splitTemplateVariableNames extracts the variable names from one expression body, dropping
// the operator and any explode/modifier prefixes.
func splitTemplateVariableNames(expression string) []string {
	// RFC 6570 §2.2: the first character may be an operator from "+#./;?&".
	if len(expression) > 0 && strings.IndexByte("+#./;?&", expression[0]) >= 0 {
		expression = expression[1:]
	}
	var names []string
	for _, item := range strings.Split(expression, ",") {
		// Strip the explode modifier and the prefix/length modifiers.
		if star := strings.IndexByte(item, '*'); star >= 0 {
			item = item[:star]
		}
		if colon := strings.IndexByte(item, ':'); colon >= 0 {
			item = item[:colon]
		}
		item = strings.TrimSpace(item)
		if item != "" {
			names = append(names, item)
		}
	}
	return names
}

// stripTemplateExpressions removes every expression from a template, which is what expansion
// with no variables defined does: each expression contributes the empty string.
//
// A literal `}` with no opening `{`, or an unterminated `{`, is a malformed template rather
// than something to pass through.
func stripTemplateExpressions(template string) (string, error) {
	var builder strings.Builder
	for index := 0; index < len(template); index++ {
		character := template[index]
		switch character {
		case '{':
			end := strings.IndexByte(template[index:], '}')
			if end < 0 {
				return "", E.New("dohpath has an unterminated expression: ", template)
			}
			expression := template[index+1 : index+end]
			if err := validateTemplateExpression(expression, template); err != nil {
				return "", err
			}
			// Valid, so the whole expression expands to nothing and is dropped.
			index += end
		case '}':
			return "", E.New("dohpath has a closing brace with no opening brace: ", template)
		default:
			builder.WriteByte(character)
		}
	}
	return builder.String(), nil
}

// validateTemplateExpression checks one expression against the supported subset.
//
// # The subset, stated rather than approximated
//
// RFC 6570 is large and this client needs exactly one of its behaviours: expanding a DoH template
// with NO variables defined, as RFC 8484 §4.1 specifies for POST. Rather than accept whatever
// looks brace-shaped, the parser recognises a strict subset and refuses the rest, so an
// advertisement it cannot interpret is reported instead of half-understood.
//
// Supported, because a DoH server legitimately uses them and they are unambiguous:
//
//	{dns}                  simple expansion
//	{?dns}                 form-style query expansion -- the draft's example
//	{&dns}                 form-style continuation
//	{/dns} {.dns} {;dns}   reserved-path and path-parameter expansions
//	{dns,other}            several names in one expression
//
// Refused:
//
//	{+dns} {#dns}          reserved-character handling, which changes the path if got wrong
//	{}                     an empty expression
//	{{dns}}                a nested brace
//	unterminated or stray braces
//	{dns:3} {dns*}         modifiers that alter the produced value
//	an invalid variable name
//
// # Why refusing beats guessing
//
// Expansion with no variables defined deletes the expression, so a parser that accepted anything
// brace-shaped would produce a plausible path from a template it did not understand. The result
// is a request to the right origin and the wrong resource, surfacing as a DNS failure far from
// its cause.
func validateTemplateExpression(expression string, template string) error {
	if expression == "" {
		return E.New("dohpath has an empty expression: ", template)
	}
	if strings.ContainsAny(expression, "{}") {
		return E.New("dohpath expression contains a brace: ", expression)
	}
	body := expression
	if strings.IndexByte("+#./;?&", body[0]) >= 0 {
		if body[0] == '+' || body[0] == '#' {
			return E.New("dohpath uses the unsupported operator ", string(body[0]), ": ", template)
		}
		body = body[1:]
	}
	if body == "" {
		return E.New("dohpath expression names no variable: ", expression)
	}
	for _, name := range strings.Split(body, ",") {
		if strings.ContainsAny(name, "*:") {
			return E.New("dohpath uses an unsupported modifier in expression ", expression)
		}
		if !isValidTemplateVariableName(name) {
			return E.New("dohpath has an invalid variable name ", name, " in expression ", expression)
		}
	}
	return nil
}

// isValidTemplateVariableName reports whether a name matches RFC 6570 section 2.3: a varname is
// a dot-separated sequence of varchar, where varchar is ALPHA / DIGIT / "_" / pct-encoded.
func isValidTemplateVariableName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '_', character == '.':
			continue
		case character == '%':
			if index+2 >= len(name) || !isHexDigit(name[index+1]) || !isHexDigit(name[index+2]) {
				return false
			}
			index += 2
		default:
			return false
		}
	}
	return true
}

// isHexDigit reports whether a byte is a hexadecimal digit.
func isHexDigit(character byte) bool {
	switch {
	case character >= '0' && character <= '9':
		return true
	case character >= 'a' && character <= 'f':
		return true
	case character >= 'A' && character <= 'F':
		return true
	default:
		return false
	}
}
