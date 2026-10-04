package trafficclass_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/sagernet/sing-box/common/trafficclass"

	"github.com/stretchr/testify/require"
)

func TestClassZeroValueIsDefault(t *testing.T) {
	// The runtime metadata is not initialised per flow, so the zero value has to mean
	// "unclassified" rather than something that needs a policy applied to it.
	var zero trafficclass.Class
	require.Equal(t, trafficclass.ClassDefault, zero)
	require.True(t, zero.IsDefault())
	require.False(t, zero.IsHighPriority())
	require.Equal(t, "default", zero.String())
}

func TestClassRoundTrip(t *testing.T) {
	for _, name := range []string{"default", "interactive", "bulk", "realtime"} {
		class, err := trafficclass.Parse(name)
		require.NoError(t, err, name)
		require.Equal(t, name, class.String(), "String and Parse must agree")
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	// Fail closed: a typo must not silently mean "default", because that would disable the
	// policy the operator asked for without telling them.
	for _, value := range []string{"Interactive", "INTERACTIVE", "high", "low", "ai", "true", "1"} {
		_, err := trafficclass.Parse(value)
		require.Error(t, err, "value %q must be rejected", value)
	}
}

func TestParseAcceptsEmptyAsDefault(t *testing.T) {
	class, err := trafficclass.Parse("")
	require.NoError(t, err)
	require.Equal(t, trafficclass.ClassDefault, class)
}

func TestHighPriorityLanes(t *testing.T) {
	require.True(t, trafficclass.ClassInteractive.IsHighPriority())
	require.True(t, trafficclass.ClassRealtime.IsHighPriority())
	require.False(t, trafficclass.ClassDefault.IsHighPriority())
	require.False(t, trafficclass.ClassBulk.IsHighPriority())
}

// TestMatchTagMatrix is the classification contract. Every entry is a real tag shape from this
// fork's configuration or a deliberate near-miss.
func TestMatchTagMatrix(t *testing.T) {
	matching := []string{
		"🤖 AI",
		"AI",
		"ai",
		"AI-US",
		"[AI]",
		"OpenAI",
		"OpenAI Residential",
		"ChatGPT",
		"Claude",
		"Claude-3",
		"Anthropic",
		"Gemini",
		"DeepSeek",
		"Grok",
		"Perplexity",
		"LLM",
		"ai-residential",
		"🇺🇸 AI 住宅",
		"人工智能",
		"人工智能专线",
	}
	for _, tag := range matching {
		require.True(t, trafficclass.MatchTag(tag), "tag %q must classify as AI", tag)
	}

	// The near-misses matter more than the matches. "NaiveProxy" is this fork's most common
	// outbound and the others are the substrings that make a naive Contains(lower, "ai") wrong.
	notMatching := []string{
		"NaiveProxy",
		"naive",
		"Naive",
		"mail",
		"gmail",
		"paid",
		"rail",
		"trail",
		"available",
		"availability",
		"Thailand",
		"Main",
		"main",
		"Direct",
		"Proxy",
		"",
		"🇺🇸 住宅 VLESS",
		"🇺🇸住宅 AnyTLS",
	}
	for _, tag := range notMatching {
		require.False(t, trafficclass.MatchTag(tag), "tag %q must NOT classify as AI", tag)
	}
}

// TestMatchTagIsWholeTokenForASCII pins the specific property that substring matching would break.
func TestMatchTagIsWholeTokenForASCII(t *testing.T) {
	// Every one of these contains the letters "ai" contiguously.
	for _, tag := range []string{"mail", "paid", "rail", "trail", "available", "availability", "Thailand", "Main", "NaiveProxy"} {
		lowered := strings.ToLower(tag)
		require.Contains(t, lowered, "ai", "%q is a substring case, which is the point", tag)
		require.False(t, trafficclass.MatchTag(tag),
			"%q contains \"ai\" as a substring but is not an AI token, so it must not classify", tag)
	}
}

// FuzzMatchTagAgreesWithTokenisation is the property that replaces hand-picked near-misses.
//
// For an arbitrary string, MatchTag must be true only when lowercasing and splitting on
// non-alphanumeric runes yields a reserved token. A substring implementation fails this as soon as
// the fuzzer places "ai" inside a longer word.
func FuzzMatchTagAgreesWithTokenisation(f *testing.F) {
	for _, seed := range []string{
		"AI", "NaiveProxy", "mail", "🤖 AI", "OpenAI Residential", "人工智能", "", "ai-x", "MAIN",
	} {
		f.Add(seed)
	}
	reserved := map[string]bool{
		"ai": true, "openai": true, "chatgpt": true, "claude": true, "anthropic": true,
		"gemini": true, "deepseek": true, "grok": true, "perplexity": true, "llm": true,
	}
	// The oracle is an independent restatement of the specification: split on the same boundary
	// rule (rune is not a letter and not a digit), then require a whole reserved token or the CJK
	// keyword. Asserting both directions means a substring implementation fails as soon as the
	// fuzzer puts "ai" inside a longer word, and a missed case fails just as loudly.
	f.Fuzz(func(t *testing.T, tag string) {
		expected := false
		for _, token := range strings.FieldsFunc(strings.ToLower(tag), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			if reserved[token] || strings.Contains(token, "人工智能") {
				expected = true
				break
			}
		}
		require.Equal(t, expected, trafficclass.MatchTag(tag),
			"tag %q: tokenisation says %v", tag, expected)
	})
}

// TestMatchTagDoesNotDependOnPositionOrCase pins that classification is a property of the whole
// tag rather than of where the keyword happens to sit.
func TestMatchTagDoesNotDependOnPositionOrCase(t *testing.T) {
	require.True(t, trafficclass.MatchTag("US Residential AI"))
	require.True(t, trafficclass.MatchTag("us residential ai"))
	require.True(t, trafficclass.MatchTag("Ai"))
	require.True(t, trafficclass.MatchTag("a I") == false, "a split token is not the token \"ai\"")
}
