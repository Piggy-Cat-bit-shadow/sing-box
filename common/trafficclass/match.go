package trafficclass

import (
	"strings"
	"unicode"
)

// AutoTagClass is the class an automatically recognised tag resolves to.
//
// AI business traffic is interactive: a person is waiting on the response. The matcher does not
// distinguish providers, because the policy is "someone is waiting", not "this is a particular
// vendor" - naming vendors in the enum would put business vocabulary into the data model.
const AutoTagClass = ClassInteractive

// autoTokens are matched as WHOLE tokens after lowercasing.
//
// Token matching rather than substring matching is the entire point. This fork's most common
// outbound is NaiveProxy, and "naive" does not contain "ai" - but the substring case is exactly
// what makes substring matching wrong: mail, paid, rail, trail, available, availability,
// Thailand and Main all contain "ai" and none of them is AI traffic. A substring match would
// silently reclassify an unrelated proxy or region group as interactive.
var autoTokens = map[string]struct{}{
	"ai":         {},
	"openai":     {},
	"chatgpt":    {},
	"claude":     {},
	"anthropic":  {},
	"gemini":     {},
	"deepseek":   {},
	"grok":       {},
	"perplexity": {},
	"llm":        {},
}

// cjkAutoKeyword is matched INSIDE a token rather than as a whole token.
//
// CJK text is written without word separators, so "人工智能" is a single token by the rule above
// and a whole-token match would also work for it. It is treated as a fragment anyway because the
// realistic tag is a phrase - "人工智能 专线" tokenises to "人工智能" and "专线", but a tag such
// as "🇺🇸人工智能住宅" is one token and must still match. The four-character sequence is specific
// enough that fragment matching does not create the false positives that motivated whole-token
// matching for the ASCII keywords.
const cjkAutoKeyword = "人工智能"

// MatchTag reports whether a logical outbound tag looks like AI business traffic.
//
// It runs on the flow-setup path only. Nothing here may be called per read, per write or per
// packet: the resolved class is carried on the flow metadata and the scheduler reads that.
func MatchTag(tag string) bool {
	if tag == "" {
		return false
	}
	// Unicode-aware lowering, so a tag in any script is compared in one form.
	lowered := strings.ToLower(tag)
	// A token boundary is any rune that is neither a letter nor a digit. Emoji, spaces, dashes,
	// brackets and path separators are all boundaries, which is what makes "🤖 AI", "AI-US"
	// and "[AI]" classify while "NaiveProxy" stays a single token.
	tokenStart := -1
	for index, r := range lowered {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if tokenStart < 0 {
				tokenStart = index
			}
			continue
		}
		if tokenStart >= 0 {
			if tokenMatches(lowered[tokenStart:index]) {
				return true
			}
			tokenStart = -1
		}
	}
	if tokenStart >= 0 {
		return tokenMatches(lowered[tokenStart:])
	}
	return false
}

func tokenMatches(token string) bool {
	if _, isAuto := autoTokens[token]; isAuto {
		return true
	}
	return strings.Contains(token, cjkAutoKeyword)
}
