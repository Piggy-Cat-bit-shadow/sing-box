package urltest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Compatibility tests for the expected-status parser and canonical form.
//
// # What is being compared against
//
// The reference is Mihomo's own parser (common/utils/ranges.go and range.go), read from source
// rather than inferred. Three of its behaviours are load-bearing because configurations in the wild
// rely on them:
//
//	empty tokens are skipped     "204," parses as {204}
//	brackets are trimmed         "[200-299]" parses as {200-299}
//	reversed ranges are swapped  "299-200" means {200-299}
//
// A parser that refused any of those would reject a configuration Mihomo accepts.
//
// # One deliberate difference
//
// Mihomo parses each bound as uint64 and converts to uint16, so "65536" silently becomes 0. That is
// a truncation bug rather than a contract, and this parser rejects it instead. Accepting it would
// mean "65536" and "0" share a scope, which is worse than refusing an expression no sane
// configuration contains.

// TestExpectedStatusEmptyTokensAreSkipped is the "204," case.
func TestExpectedStatusEmptyTokensAreSkipped(t *testing.T) {
	for _, expression := range []string{"204,", "204/", ",204", "/204", "204,,200", "204//200"} {
		t.Run(expression, func(t *testing.T) {
			expected, err := ParseExpectedStatus(expression)
			require.NoError(t, err,
				"Mihomo skips empty tokens, so this expression is valid there and must be valid "+
					"here: refusing it would reject a configuration Mihomo accepts")
			require.NotEmpty(t, expected)
		})
	}

	// The empty tokens contribute nothing: "204," accepts exactly what "204" accepts.
	withSeparator, err := ParseExpectedStatus("204,")
	require.NoError(t, err)
	withoutSeparator, err := ParseExpectedStatus("204")
	require.NoError(t, err)
	require.Equal(t, withoutSeparator.Canonical(), withSeparator.Canonical())
}

// TestExpectedStatusBracketsAreTrimmed is the "[200-299]" case.
func TestExpectedStatusBracketsAreTrimmed(t *testing.T) {
	bracketed, err := ParseExpectedStatus("[200-299]")
	require.NoError(t, err,
		"Mihomo trims [ and ] around each bound, so this is a valid expression there and must be "+
			"valid here")

	plain, err := ParseExpectedStatus("200-299")
	require.NoError(t, err)
	require.Equal(t, plain.Canonical(), bracketed.Canonical(),
		"both spellings describe the same accepted set")

	for status := 200; status <= 299; status++ {
		require.True(t, bracketed.Match(status))
	}
	require.False(t, bracketed.Match(199))
	require.False(t, bracketed.Match(300))
}

// TestExpectedStatusMihomoShapes covers the forms a real configuration uses.
func TestExpectedStatusMihomoShapes(t *testing.T) {
	for _, testCase := range []struct {
		expression string
		accepts    []int
		rejects    []int
	}{
		{"*", []int{200, 204, 500}, nil},
		{"", []int{200, 500}, nil},
		{"204", []int{204}, []int{200, 205}},
		{"200-299", []int{200, 250, 299}, []int{199, 300}},
		{"200/204/401-429", []int{200, 204, 401, 429}, []int{201, 400, 430}},
		{"200,204,401-429", []int{200, 204, 401, 429}, []int{201, 400, 430}},
		{"299-200", []int{200, 250, 299}, []int{199, 300}},
		{"200,204,401-429,501-503", []int{200, 204, 401, 429, 501, 503}, []int{430, 500}},
	} {
		t.Run(testCase.expression, func(t *testing.T) {
			expected, err := ParseExpectedStatus(testCase.expression)
			require.NoError(t, err)
			for _, status := range testCase.accepts {
				require.True(t, expected.Match(status),
					"%q must accept %d", testCase.expression, status)
			}
			for _, status := range testCase.rejects {
				require.False(t, expected.Match(status),
					"%q must reject %d", testCase.expression, status)
			}
		})
	}
}

// TestExpectedStatusRangeLimit is the 28-range cap, counted as Mihomo counts it.
func TestExpectedStatusRangeLimit(t *testing.T) {
	expression := ""
	for index := 0; index < maxExpectedStatusRanges; index++ {
		if index > 0 {
			expression += "/"
		}
		expression += "200"
	}
	_, err := ParseExpectedStatus(expression)
	require.NoError(t, err, "exactly %d ranges is the documented maximum", maxExpectedStatusRanges)

	_, err = ParseExpectedStatus(expression + "/200")
	require.Error(t, err, "%d ranges exceeds the maximum", maxExpectedStatusRanges+1)
}

// TestExpectedStatusRejectsGenuinelyInvalid keeps the parser strict where Mihomo is strict.
func TestExpectedStatusRejectsGenuinelyInvalid(t *testing.T) {
	for _, expression := range []string{"abc", "200-abc", "200-299-400", "2oo", "-"} {
		_, err := ParseExpectedStatus(expression)
		require.Error(t, err, "%q is not a valid expression in any spelling", expression)
	}
}

// TestExpectedStatusRejectsOverflow documents the one deliberate divergence.
func TestExpectedStatusRejectsOverflow(t *testing.T) {
	// Mihomo parses as uint64 and truncates to uint16, so 65536 becomes 0. Replicating that would
	// make "65536" and "0" share a scope, so it is refused instead.
	_, err := ParseExpectedStatus("65536")
	require.Error(t, err,
		"a status beyond uint16 is refused rather than silently truncated; truncating would give "+
			"two different expressions the same scope")
}

// TestExpectedStatusCanonicalIsSemantic is §64(G).
//
// The scope key is built from the canonical form, so two spellings of the same accepted set must
// produce the same key. Otherwise one target would occupy two scopes and a group would see only
// part of its own evidence.
func TestExpectedStatusCanonicalIsSemantic(t *testing.T) {
	for _, group := range [][]string{
		{"200/204", "204/200", "200,204", "204,200", "200-200/204-204"},
		{"200/201/202-204", "200-204", "204-200", "200,201,202,203,204"},
		{"204/200/203-204/202/201", "200-204"},
		{"*", ""},
		{"204,", "204", "204/"},
		{"[200-299]", "200-299"},
	} {
		t.Run(group[0], func(t *testing.T) {
			var canonical string
			for index, expression := range group {
				expected, err := ParseExpectedStatus(expression)
				require.NoError(t, err, "%q must parse", expression)
				current := expected.Canonical()
				if index == 0 {
					canonical = current
					continue
				}
				require.Equal(t, canonical, current,
					"%q and %q describe the same accepted set, so they must produce the SAME scope "+
						"key; different keys would split one target's history into two", group[0],
					expression)
			}
		})
	}
}

// TestExpectedStatusCanonicalMergesAdjacent pins the merging rules.
func TestExpectedStatusCanonicalMergesAdjacent(t *testing.T) {
	for _, testCase := range []struct {
		expression string
		canonical  string
	}{
		{"200/201", "200-201"},         // adjacent
		{"200/202", "200/202"},         // a gap is preserved
		{"200-210/205-220", "200-220"}, // overlapping
		{"200/200", "200"},             // duplicate
		{"100/200/150-160", "100/150-160/200"},
		{"204", "204"},
		{"*", "*"},
	} {
		t.Run(testCase.expression, func(t *testing.T) {
			expected, err := ParseExpectedStatus(testCase.expression)
			require.NoError(t, err)
			require.Equal(t, testCase.canonical, expected.Canonical())
		})
	}
}

// TestExpectedStatusCanonicalDoesNotMutate guards the copy.
func TestExpectedStatusCanonicalDoesNotMutate(t *testing.T) {
	expected, err := ParseExpectedStatus("204/200")
	require.NoError(t, err)

	before := make([]StatusRange, len(expected))
	copy(before, expected)

	require.Equal(t, "200/204", expected.Canonical())

	require.Equal(t, before, []StatusRange(expected),
		"Canonical must not reorder the receiver; a scope key that mutates its input would make "+
			"the parsed value depend on whether it had been rendered")
}

// TestExpectedStatusCanonicalFullRange checks the merge boundary at the top of uint16.
func TestExpectedStatusCanonicalFullRange(t *testing.T) {
	expected, err := ParseExpectedStatus("65534/65535")
	require.NoError(t, err)
	require.Equal(t, "65534-65535", expected.Canonical(),
		"merging at the top of the range must not overflow when the adjacency check adds one")
}
